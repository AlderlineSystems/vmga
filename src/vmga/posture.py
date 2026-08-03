"""Runtime enforcement posture checks for VMGA deployments."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .evidence_integrity import (
    EvidenceHMACConfig,
    load_segmented_events,
    retained_segment_paths,
    verify_integrity,
)


PASS = "pass"
WARN = "warn"
FAIL = "fail"
UNKNOWN = "unknown"


@dataclass
class PostureConfig:
    host: str = "127.0.0.1"
    backend: str = "fake"
    policy_path: str = "policies/draft_assist.yaml"
    state_db_path: str = ".vmga/state.sqlite3"
    ledger_path: str = ".vmga/evidence.jsonl"
    ledger_rotate_bytes: int = 0
    bearer_token_set: bool = False
    allow_unauthenticated: bool = False
    gog_binary: str = ""
    gog_home: Optional[str] = None
    approval_auth: str = "hmac"
    evidence_integrity: str = "append_only"
    agent_roots: List[str] = field(default_factory=list)
    direct_bypass_attested: bool = False
    direct_bypass_evidence: str = ""
    canary_registry_path: str = ""
    # One-way operative signal: True can only force direct_gmail_bypass FAIL.
    canary_trip_recorded: bool = False
    # Operative signal from the adapter's signature-mode readiness computation
    # (VMGAGmailAdapter.signature_readiness). Posture consumes it, never
    # recomputes it. None means the signal is unavailable (e.g. --local).
    signature_readiness: Optional[Dict[str, str]] = None


def _resolve(path: str | Path) -> Path:
    return Path(path).expanduser().resolve()


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _path_under_roots(path: str | Path, roots: Iterable[str | Path]) -> Optional[str]:
    resolved_path = _resolve(path)
    for root in roots:
        resolved_root = _resolve(root)
        if _is_relative_to(resolved_path, resolved_root):
            return str(resolved_root)
    return None


def _check(check_id: str, status: str, summary: str, *, detail: str = "") -> Dict[str, str]:
    payload = {"id": check_id, "status": status, "summary": summary}
    if detail:
        payload["detail"] = detail
    return payload


def _evidence_chain_result(config: PostureConfig) -> Dict[str, str]:
    """Run the existing evidence-chain verifier for posture.

    This is wiring only: key material comes from the environment via
    EvidenceHMACConfig, the expected head from the state DB, and the verdict
    from verify_integrity. Posture never reimplements the chain check. Any
    missing input is cannot_verify, never pass.
    """
    try:
        hmac_config = EvidenceHMACConfig.from_env()
    except ValueError as exc:
        return {"state": "cannot_verify", "reason": str(exc)}
    if hmac_config is None:
        return {"state": "cannot_verify", "reason": "missing_evidence_hmac_key"}
    try:
        from .sqlite_state import SQLiteStateStore

        checkpoint = SQLiteStateStore(config.state_db_path).load_evidence_head()
        events = load_segmented_events(config.ledger_path)
    except Exception as exc:  # noqa: BLE001 - any unreadable input fails closed to cannot_verify
        return {"state": "cannot_verify", "reason": f"unreadable_inputs: {exc}"}
    result = verify_integrity(
        events,
        checkpoint=checkpoint,
        keyring={hmac_config.key_id: hmac_config.key},
    )
    return {"state": result.state, "reason": result.reason}


def _state_canary_evidence(config: PostureConfig) -> tuple[bool, bool]:
    """Return (tripped, unreadable) for the durable canary state."""
    if not Path(config.state_db_path).expanduser().exists():
        return False, False
    try:
        from .sqlite_state import SQLiteStateStore

        return SQLiteStateStore(config.state_db_path).load_canary_trip_recorded(), False
    except Exception:
        return False, True


def _ledger_canary_evidence(config: PostureConfig) -> tuple[bool, bool]:
    """Return (tripped, unreadable) for retained canary evidence."""
    if not retained_segment_paths(config.ledger_path):
        return False, False
    try:
        return any(
            event.get("event_type") == "vmga_canary_tripped"
            for event in load_segmented_events(config.ledger_path)
        ), False
    except Exception:
        return False, True


def assess_posture(config: PostureConfig) -> Dict[str, Any]:
    """Return a conservative deployment posture report.

    This is a runtime self-check, not a formal sandbox proof. Facts that VMGA
    cannot observe locally remain ``unknown`` and never count toward hard-ready.
    """

    agent_roots = config.agent_roots
    checks: List[Dict[str, str]] = []

    geteuid = getattr(os, "geteuid", None)
    if callable(geteuid) and geteuid() == 0:
        checks.append(_check("process_privilege", WARN, "Broker process appears to be running as root; hard-boundary deployments should use a dedicated unprivileged runtime identity."))
    elif callable(geteuid):
        checks.append(_check("process_privilege", PASS, "Broker process is not running as root."))
    else:
        checks.append(_check("process_privilege", UNKNOWN, "Broker process privilege cannot be assessed on this platform."))

    if config.bearer_token_set:
        checks.append(_check("broker_auth", PASS, "Broker bearer authentication is configured."))
    elif config.allow_unauthenticated and config.host in {"127.0.0.1", "::1", "localhost"}:
        checks.append(_check("broker_auth", WARN, "Loopback unauthenticated mode is enabled for development."))
    else:
        checks.append(_check("broker_auth", FAIL, "Broker authentication is not configured."))

    if config.backend == "fake":
        checks.append(_check("mailbox_backend", WARN, "Fake backend is active; no live Gmail boundary is being enforced."))
    elif config.backend == "gogcli":
        binary_name = Path(config.gog_binary or "").name
        if binary_name == "gog-agent-safe":
            checks.append(_check("mailbox_backend", PASS, "gog-agent-safe backend is configured."))
        elif binary_name:
            checks.append(_check("mailbox_backend", WARN, "gogcli backend is configured without the gog-agent-safe wrapper.", detail=config.gog_binary))
        else:
            checks.append(_check("mailbox_backend", UNKNOWN, "gogcli backend binary could not be identified."))
    else:
        checks.append(_check("mailbox_backend", UNKNOWN, f"Unknown backend posture: {config.backend}"))

    if config.approval_auth == "signature":
        readiness = config.signature_readiness
        if readiness is not None and readiness.get("state") == "verified_intact":
            checks.append(_check(
                "approval_boundary", PASS,
                "Asymmetric approval mode is operative: active Ed25519 keyring loaded. Verify private-key isolation separately.",
                detail=readiness.get("reason", ""),
            ))
        else:
            checks.append(_check(
                "approval_boundary", WARN,
                "Signature mode declared but no keyring loaded; approval enforcement is not operative.",
                detail=(readiness or {}).get("reason", "signature_readiness_unavailable"),
            ))
    elif config.approval_auth == "hmac":
        checks.append(_check("approval_boundary", WARN, "HMAC approval is broker-forgeable; hard approval enforcement requires signature mode."))
    else:
        checks.append(_check("approval_boundary", UNKNOWN, f"Unknown approval mode: {config.approval_auth}"))

    if config.evidence_integrity in {"hmac_chain", "signed_checkpoint", "external_anchor"}:
        chain_result = _evidence_chain_result(config)
        chain_state = chain_result.get("state")
        chain_reason = chain_result.get("reason", "")
        if chain_state == "verified_intact":
            checks.append(_check(
                "evidence_integrity", PASS,
                f"Evidence integrity mode {config.evidence_integrity} is operative: chain verified intact against the expected-head checkpoint.",
                detail=chain_reason,
            ))
        elif chain_state == "verified_tampered":
            checks.append(_check(
                "evidence_integrity", FAIL,
                f"Evidence integrity mode {config.evidence_integrity} is declared but the ledger FAILED verification: {chain_reason}.",
                detail=chain_reason,
            ))
        else:
            checks.append(_check(
                "evidence_integrity", UNKNOWN,
                f"Evidence integrity mode {config.evidence_integrity} is declared but the chain cannot be verified from here: {chain_reason}.",
                detail=chain_reason,
            ))
    elif config.evidence_integrity == "append_only":
        checks.append(_check("evidence_integrity", WARN, "Evidence is append-only/advisory; integrity anchoring is not configured."))
    else:
        checks.append(_check("evidence_integrity", UNKNOWN, f"Unknown evidence integrity mode: {config.evidence_integrity}"))

    isolation_paths = [
        ("policy_path", config.policy_path, "Policy path"),
        ("state_path", config.state_db_path, "State DB path"),
        ("ledger_path", config.ledger_path, "Evidence ledger path"),
    ]
    if config.canary_registry_path:
        isolation_paths.append(("canary_registry_path", config.canary_registry_path, "Canary registry path"))
    for check_id, path_value, label in isolation_paths:
        if not agent_roots:
            checks.append(_check(check_id, UNKNOWN, f"{label} isolation cannot be assessed until operator supplies --agent-root.", detail=str(_resolve(path_value))))
            continue
        root = _path_under_roots(path_value, agent_roots)
        if root:
            checks.append(_check(check_id, WARN, f"{label} is under an agent/root workspace; hard-boundary claims require operator-owned paths.", detail=f"path={_resolve(path_value)} root={root}"))
        else:
            checks.append(_check(check_id, PASS, f"{label} is not under the configured agent root(s).", detail=str(_resolve(path_value))))

    if config.backend == "gogcli":
        if config.gog_home:
            root = _path_under_roots(config.gog_home, agent_roots)
            if root:
                checks.append(_check("gog_home", WARN, "gog home is under an agent/root workspace; OAuth material may be agent-readable.", detail=f"path={_resolve(config.gog_home)} root={root}"))
            else:
                checks.append(_check("gog_home", PASS, "gog home is not under the configured agent root(s).", detail=str(_resolve(config.gog_home))))
        else:
            checks.append(_check("gog_home", UNKNOWN, "gog home was not configured; credential isolation cannot be assessed."))

    if config.ledger_rotate_bytes > 0:
        checks.append(_check("evidence_rotation", PASS, "Evidence ledger rotation is configured.", detail=f"rotate_bytes={config.ledger_rotate_bytes}"))
    else:
        checks.append(_check("evidence_rotation", WARN, "Evidence ledger rotation is not configured."))

    state_trip, state_unreadable = _state_canary_evidence(config)
    ledger_trip, ledger_unreadable = _ledger_canary_evidence(config)
    if config.canary_trip_recorded or state_trip or ledger_trip:
        checks.append(_check(
            "direct_gmail_bypass",
            FAIL,
            "A VMGA canary trip was recorded; treat the deployment as a direct Gmail/Workspace bypass risk.",
        ))
    elif state_unreadable or ledger_unreadable:
        checks.append(_check(
            "direct_gmail_bypass",
            FAIL,
            "VMGA canary trip evidence is unreadable; fail closed rather than accepting direct-bypass attestation.",
        ))
    elif config.direct_bypass_attested and config.direct_bypass_evidence:
        checks.append(_check("direct_gmail_bypass", PASS, "Operator attests direct Gmail/Workspace bypass closure evidence exists.", detail=config.direct_bypass_evidence))
    else:
        checks.append(_check("direct_gmail_bypass", UNKNOWN, "VMGA cannot locally prove agents lack direct Gmail/Workspace access; supply explicit bypass-closure attestation and evidence before hard-enforcement claims. A quiet or unconfigured canary is not proof of isolation."))
    checks.append(_check("single_process_boundary", PASS, "Built-in broker is a single-process control plane; do not run multiple broker processes against one state DB for hard claims."))

    hard_blockers = [item for item in checks if item["status"] in {FAIL, WARN, UNKNOWN}]
    if not hard_blockers:
        mode = "hard_enforcement_ready"
    elif any(item["status"] == FAIL for item in hard_blockers):
        mode = "advisory"
    elif any(item["status"] == UNKNOWN for item in hard_blockers):
        mode = "cannot_determine"
    else:
        mode = "advisory"

    return {
        "schema_version": "0.1",
        "mode": mode,
        "hard_enforcement_ready": mode == "hard_enforcement_ready",
        "summary": _summary_for_mode(mode),
        "checks": checks,
    }


def _summary_for_mode(mode: str) -> str:
    if mode == "hard_enforcement_ready":
        return "Runtime posture checks found no local blockers to hard-enforcement claims."
    if mode == "cannot_determine":
        return "Runtime posture has unknowns; treat this deployment as advisory until resolved."
    return "Runtime posture is advisory; hard-enforcement preconditions are not met."


def print_posture_summary(report: Dict[str, Any]) -> str:
    return f"VMGA posture: {report['mode']} - {report['summary']}"

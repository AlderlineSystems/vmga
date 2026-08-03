"""Canary tripwire acceptance tests for direct-bypass detection."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vmga import CanaryMarker, SQLiteStateStore, VMGABroker, VMGAGmailAdapter, VMGAStateStore
from vmga.canary import canary_registry_agent_root, load_canary_registry
from vmga.cli import broker_main
from vmga.ledger import JSONLVMGALedger, LedgerVestaAdapter
from vmga.posture import PostureConfig, assess_posture


MARKER = "VMGA-CANARY-54-TEST"


class MemoryLedger:
    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    def append(self, event: dict[str, object]) -> None:
        self.events.append(event)


class MemoryVesta:
    def __init__(self) -> None:
        self.audit_ledger = MemoryLedger()


def _adapter(tmp_path: Path, registry: tuple[CanaryMarker, ...]) -> VMGAGmailAdapter:
    return VMGAGmailAdapter(
        vesta_adapter=MemoryVesta(),
        profile="canary_test",
        policy_rules={"allowed_actions": ["read"]},
        state_store=VMGAStateStore(str(tmp_path / "state")),
        approval_secret="test-secret",
        canary_registry=registry,
    )


def _direct_bypass_check(report: dict[str, object]) -> dict[str, str]:
    return next(
        check
        for check in report["checks"]  # type: ignore[index]
        if check["id"] == "direct_gmail_bypass"
    )


@pytest.mark.parametrize("surface", ["content", "justification", "parameters"])
def test_marker_on_each_proposal_surface_emits_one_critical_event_and_forces_fail(
    tmp_path: Path,
    surface: str,
) -> None:
    registry = (CanaryMarker("decoy-oauth-1", MARKER, "/operator/decoys/oauth.json"),)
    adapter = _adapter(tmp_path, registry)
    broker = VMGABroker(
        adapter,
        posture_config=PostureConfig(
            ledger_path=str(tmp_path / "not-used-by-memory-ledger.jsonl"),
            canary_registry_path="/operator/canaries.yaml",
        ),
    )
    surrounded = f"private-before {MARKER} private-after"
    payload: dict[str, object] = {
        "action": "read",
        "actor_id": "agent-1",
        "correlation_id": f"corr-{surface}",
    }
    if surface == "parameters":
        payload["parameters"] = {"metadata": {"operator_note": surrounded}}
    else:
        payload[surface] = surrounded

    proposal_result = broker.propose(payload)
    assert proposal_result["status"] == "ALLOW"  # Tripwire detects; it does not prevent.

    trip_events = [
        event for event in adapter.vesta.audit_ledger.events
        if event["event_type"] == "vmga_canary_tripped"
    ]
    assert len(trip_events) == 1
    assert trip_events[0] == {
        "event_type": "vmga_canary_tripped",
        "timestamp": trip_events[0]["timestamp"],
        "severity": "CRITICAL",
        "canary_id": "decoy-oauth-1",
        "where_observed": surface,
        "correlation_id": f"corr-{surface}",
        "vmga_profile": "canary_test",
    }
    serialized_event = json.dumps(trip_events[0], sort_keys=True)
    assert MARKER not in serialized_event
    assert "private-before" not in serialized_event
    assert "private-after" not in serialized_event

    report = broker.posture()
    assert _direct_bypass_check(report)["status"] == "fail"
    assert report["mode"] == "advisory"
    assert report["hard_enforcement_ready"] is False


def test_same_marker_on_multiple_surfaces_emits_once_per_proposal(tmp_path: Path) -> None:
    registry = (CanaryMarker("decoy-1", MARKER, "/operator/decoy"),)
    adapter = _adapter(tmp_path, registry)

    adapter.propose_action(
        "read",
        "agent-1",
        content=MARKER,
        justification=MARKER,
        parameters={"metadata": {"also": MARKER}, "correlation_id": "corr-one"},
    )

    trip_events = [
        event for event in adapter.vesta.audit_ledger.events
        if event["event_type"] == "vmga_canary_tripped"
    ]
    assert len(trip_events) == 1
    assert trip_events[0]["where_observed"] == "content"


def test_unconfigured_and_armed_but_quiet_canaries_remain_unknown(tmp_path: Path) -> None:
    unconfigured = assess_posture(PostureConfig(ledger_path=str(tmp_path / "missing.jsonl")))
    assert _direct_bypass_check(unconfigured)["status"] == "unknown"

    adapter = _adapter(
        tmp_path,
        (CanaryMarker("quiet-decoy", MARKER, "/operator/decoy"),),
    )
    broker = VMGABroker(
        adapter,
        posture_config=PostureConfig(
            ledger_path=str(tmp_path / "still-missing.jsonl"),
            canary_registry_path="/operator/canaries.yaml",
        ),
    )
    broker.propose({"action": "read", "actor_id": "agent-1", "content": "ordinary proposal"})
    quiet = broker.posture()
    assert _direct_bypass_check(quiet)["status"] == "unknown"
    assert quiet["hard_enforcement_ready"] is False


def test_trip_overrides_operator_attestation_and_can_never_produce_pass(tmp_path: Path) -> None:
    adapter = _adapter(
        tmp_path,
        (CanaryMarker("decoy-1", MARKER, "/operator/decoy"),),
    )
    broker = VMGABroker(
        adapter,
        posture_config=PostureConfig(
            ledger_path=str(tmp_path / "missing.jsonl"),
            direct_bypass_attested=True,
            direct_bypass_evidence="operator-evidence/no-direct-bypass.md",
        ),
    )
    broker.propose({"action": "read", "actor_id": "agent-1", "content": MARKER})

    report = broker.posture()
    assert _direct_bypass_check(report)["status"] == "fail"
    assert report["mode"] == "advisory"
    assert report["hard_enforcement_ready"] is False


def test_durable_one_way_trip_keeps_posture_failed_after_restart(tmp_path: Path) -> None:
    ledger_path = tmp_path / "evidence.jsonl"
    state_db = tmp_path / "state.sqlite3"
    adapter = VMGAGmailAdapter(
        vesta_adapter=LedgerVestaAdapter(JSONLVMGALedger(ledger_path)),
        profile="canary_test",
        policy_rules={"allowed_actions": ["read"]},
        state_store=SQLiteStateStore(state_db),
        approval_secret="test-secret",
        canary_registry=(CanaryMarker("decoy-1", MARKER, "/operator/decoy"),),
    )
    adapter.propose_action("read", "agent-1", content=MARKER)

    # Even pruning the local evidence file cannot turn the operator-state bit
    # back into UNKNOWN/PASS. There is deliberately no reset API for this bit.
    ledger_path.unlink()
    restarted_report = assess_posture(PostureConfig(
        ledger_path=str(ledger_path),
        state_db_path=str(state_db),
        direct_bypass_attested=True,
        direct_bypass_evidence="operator attestation",
    ))
    assert _direct_bypass_check(restarted_report)["status"] == "fail"
    assert restarted_report["hard_enforcement_ready"] is False


def test_registry_loads_from_dedicated_operator_config_and_rejects_agent_root(tmp_path: Path) -> None:
    operator_dir = tmp_path / "operator"
    operator_dir.mkdir()
    registry_path = operator_dir / "canaries.yaml"
    registry_path.write_text(
        "canaries:\n"
        "  - canary_id: fake-gog-1\n"
        f"    marker: {MARKER}\n"
        "    location_hint: /decoys/gog/config.json\n",
        encoding="utf-8",
    )

    registry = load_canary_registry(registry_path)
    assert registry == (
        CanaryMarker("fake-gog-1", MARKER, "/decoys/gog/config.json"),
    )
    assert canary_registry_agent_root(registry_path, [tmp_path / "agent"]) is None
    assert canary_registry_agent_root(registry_path, [tmp_path]) == str(tmp_path.resolve())


def test_broker_refuses_registry_under_configured_agent_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    registry_path = tmp_path / "agent" / "canaries.yaml"
    registry_path.parent.mkdir()
    registry_path.write_text("canaries: []\n", encoding="utf-8")
    monkeypatch.setenv("VMGA_APPROVAL_SECRET", "test-secret")

    result = broker_main([
        "--canary-registry", str(registry_path),
        "--agent-root", str(tmp_path / "agent"),
        "--allow-unauthenticated",
    ])

    assert result == 2
    assert "Refusing canary registry under configured agent root" in capsys.readouterr().err


def test_registry_rejects_empty_or_duplicate_markers(tmp_path: Path) -> None:
    registry_path = tmp_path / "bad.yaml"
    registry_path.write_text(
        "canaries:\n"
        "  - {canary_id: one, marker: SAME, location_hint: /one}\n"
        "  - {canary_id: two, marker: SAME, location_hint: /two}\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate canary marker"):
        load_canary_registry(registry_path)

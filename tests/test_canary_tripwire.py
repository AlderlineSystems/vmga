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


def test_marker_in_correlation_id_is_redacted_from_trip_event(tmp_path: Path) -> None:
    adapter = _adapter(
        tmp_path,
        (CanaryMarker("decoy-1", MARKER, "/operator/decoy"),),
    )

    adapter.propose_action(
        "read",
        "agent-1",
        content=MARKER,
        parameters={"correlation_id": MARKER},
    )

    event = next(event for event in adapter.vesta.audit_ledger.events if event["event_type"] == "vmga_canary_tripped")
    assert event["correlation_id"] == "[REDACTED]"
    assert MARKER not in json.dumps(event)


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


def test_broker_refuses_registry_under_symlink_alias_agent_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    agent_root = tmp_path / "agent"
    agent_root.mkdir()
    agent_root_alias = tmp_path / "agent-alias"
    agent_root_alias.symlink_to(agent_root, target_is_directory=True)
    registry_path = agent_root / "canaries.yaml"
    registry_path.write_text("canaries: []\n", encoding="utf-8")
    monkeypatch.setenv("VMGA_APPROVAL_SECRET", "test-secret")

    result = broker_main([
        "--canary-registry", str(registry_path),
        "--agent-root", str(agent_root_alias),
        "--allow-unauthenticated",
    ])

    assert result == 2
    assert "Refusing canary registry under configured agent root" in capsys.readouterr().err


def test_broker_refuses_registry_symlinked_from_agent_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    operator_registry = tmp_path / "operator" / "canaries.yaml"
    operator_registry.parent.mkdir()
    operator_registry.write_text("canaries: []\n", encoding="utf-8")
    registry_link = tmp_path / "agent" / "canaries.yaml"
    registry_link.parent.mkdir()
    registry_link.symlink_to(operator_registry)
    monkeypatch.setenv("VMGA_APPROVAL_SECRET", "test-secret")

    result = broker_main([
        "--canary-registry", str(registry_link),
        "--agent-root", str(tmp_path / "agent"),
        "--allow-unauthenticated",
    ])

    assert result == 2
    assert "Refusing canary registry under configured agent root" in capsys.readouterr().err


def test_broker_rejects_registry_symlink_outside_agent_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    operator_registry = tmp_path / "operator" / "canaries.yaml"
    operator_registry.parent.mkdir()
    operator_registry.write_text("canaries: []\n", encoding="utf-8")
    registry_link = tmp_path / "link" / "canaries.yaml"
    registry_link.parent.mkdir()
    registry_link.symlink_to(operator_registry)
    monkeypatch.setenv("VMGA_APPROVAL_SECRET", "test-secret")

    result = broker_main([
        "--canary-registry", str(registry_link),
        "--allow-unauthenticated",
    ])

    assert result == 2
    assert "must not contain symlinks" in capsys.readouterr().err


def test_posture_does_not_pass_symlinked_canary_path(
    tmp_path: Path,
) -> None:
    operator_registry = tmp_path / "operator" / "canaries.yaml"
    operator_registry.parent.mkdir()
    operator_registry.write_text("canaries: []\n", encoding="utf-8")
    agent_root = tmp_path / "agent"
    agent_root.mkdir()
    registry_link = agent_root / "canaries.yaml"
    registry_link.symlink_to(operator_registry)

    report = assess_posture(PostureConfig(
        canary_registry_path=str(registry_link),
        agent_roots=[str(agent_root)],
    ))

    check = next(item for item in report["checks"] if item["id"] == "canary_registry_path")
    assert check["status"] == "warn"


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


def test_registry_rejects_marker_in_canary_id(tmp_path: Path) -> None:
    registry_path = tmp_path / "bad-id.yaml"
    registry_path.write_text(
        "canaries:\n"
        f"  - {{canary_id: unsafe-{MARKER}, marker: {MARKER}, location_hint: /one}}\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="canary_id contains"):
        load_canary_registry(registry_path)


def test_canary_trip_event_write_failure_fails_closed(tmp_path: Path) -> None:
    class FailingLedger:
        def append(self, event: dict[str, object]) -> None:
            raise OSError("ledger unavailable")

    vesta = MemoryVesta()
    vesta.audit_ledger = FailingLedger()
    adapter = VMGAGmailAdapter(
        vesta_adapter=vesta,
        profile="canary_test",
        policy_rules={"allowed_actions": ["read"]},
        state_store=VMGAStateStore(str(tmp_path / "state")),
        approval_secret="test-secret",
        canary_registry=(CanaryMarker("decoy-1", MARKER, "/operator/decoy"),),
    )

    with pytest.raises(RuntimeError, match="durably recorded"):
        adapter.propose_action("read", "agent-1", content=MARKER)
    assert adapter.canary_trip_recorded is True


def test_canary_trip_state_write_failure_fails_closed(tmp_path: Path) -> None:
    class FailingStateStore(VMGAStateStore):
        def save_canary_trip_recorded(self) -> None:
            raise OSError("state unavailable")

    vesta = MemoryVesta()
    state_store = FailingStateStore(str(tmp_path / "state"))
    adapter = VMGAGmailAdapter(
        vesta_adapter=vesta,
        profile="canary_test",
        policy_rules={"allowed_actions": ["read"]},
        state_store=state_store,
        approval_secret="test-secret",
        canary_registry=(CanaryMarker("decoy-1", MARKER, "/operator/decoy"),),
    )

    with pytest.raises(RuntimeError, match="durably recorded"):
        adapter.propose_action("read", "agent-1", content=MARKER)
    assert len(vesta.audit_ledger.events) == 1
    assert adapter.canary_trip_recorded is True


@pytest.mark.parametrize("evidence", ["state", "ledger"])
def test_unreadable_canary_evidence_fails_closed_over_attestation(tmp_path: Path, evidence: str) -> None:
    state_db = tmp_path / "state.sqlite3"
    ledger_path = tmp_path / "evidence.jsonl"
    if evidence == "state":
        state_db.write_text("not sqlite", encoding="utf-8")
    else:
        ledger_path.write_text("not json\n", encoding="utf-8")

    report = assess_posture(PostureConfig(
        state_db_path=str(state_db),
        ledger_path=str(ledger_path),
        direct_bypass_attested=True,
        direct_bypass_evidence="operator attestation",
    ))

    assert _direct_bypass_check(report)["status"] == "fail"
    assert report["mode"] == "advisory"

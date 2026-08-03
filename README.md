# VMGA

Vesta Mail Governance Adapter (VMGA) is a control-plane governance boundary for
AI agents with Gmail access.

VMGA is not an agent, model wrapper, prompt filter, or UI product. It mediates
mailbox actions by requiring agents to submit structured Gmail proposals, then
enforcing policy, approval, execution binding, and evidence logging before any
mailbox side effect occurs.

## Current Status

This repository contains the standalone VMGA reference implementation extracted
from the Vesta Agent Runtime Governance work. The current code is
production-alpha control-plane software, not a complete hosted service.

Production enforcement requires deployment controls outside this package:

- Gmail credentials are not readable by the agent runtime.
- VMGA policy and approval verifier secrets are not writable by the agent.
- Gmail write-capable APIs are reachable only through the VMGA execution gate.
- Approval occurs out-of-band from the agent session.
- Evidence logs are retained somewhere the agent cannot rewrite.

Without those controls, VMGA should be described as advisory governance or a
reference control pattern, not hard isolation.

VMGA includes a runtime posture self-check (`/v1/posture` and
`vmga-operator posture`) to make that boundary visible at startup and during
operator review. Treat `advisory` or `cannot_determine` as the deployment's
actual posture until the missing evidence is resolved. The self-check is not a
formal sandbox proof: it reports what VMGA can observe from configuration and
operator-supplied attestations, and it deliberately fails toward unknown rather
than optimistic hard-ready claims.

VMGA also supports operator-owned non-secret canary markers on proposal
`content`, `justification`, and `parameters`. A recorded marker emits CRITICAL
redacted evidence and forces `direct_gmail_bypass` to `fail`/`advisory` through
a one-way state bit. This detects only markers that surface through VMGA; it
does not prevent bypass, observe filesystem reads, or make a quiet canary proof
of isolation. See [Canary tripwire](docs/canary_tripwire.md).

VMGA now has opt-in Ed25519 approval-signature mode
([approval signing design](docs/approval_signing_design.md)). The broker holds
public keys only, and hard approval-enforcement claims require the approver
private key to live outside both broker and agent authority domains. Residuals:
VMGA cannot detect an attacker who controls the approver private key, a
compromised operator signing device, or an operator intentionally signing a bad
approval. HMAC approval mode remains available for advisory and development use
and is broker-forgeable.

VMGA also supports opt-in tamper-evident evidence through a keyed HMAC chain
([evidence integrity design](docs/evidence_integrity_design.md)) when the
broker is started with `VMGA_EVIDENCE_HMAC_KEY` and
`VMGA_EVIDENCE_HMAC_KEY_ID`, and the expected-head checkpoint remains in
operator-owned state. Without those settings, evidence remains append-only
JSONL with advisory verification. The Tier-1 residual is plain: an actor who
can rewrite evidence and also read the HMAC key, or forge the expected-head
checkpoint, can rewrite the retained evidence chain.

### OpenClaw Integration Status

VMGA's core broker path does not depend on OpenClaw. The optional OpenClaw
integration currently pins OpenClaw `2026.6.9` as an external runtime and test
fixture. The OpenClaw integration's dev dependency audit is expected to be clean
at this version. Do not expose an OpenClaw-backed VMGA deployment to remote
ingress unless the deployment has current dependency-review evidence,
loopback/private-network binding, token or trusted-proxy auth, operator
allowlists, sandboxing, and direct-bypass evidence.

## What VMGA Governs

- Read, summarize, classify, and extract actions.
- Draft creation, sending, forwarding, archive/delete/label operations.
- Attachment download and release.
- Proposal hashing, approval binding, execution integrity, and lockdown.
- Action-tier cataloging with release-check drift protection in
  [docs/action_catalog.md](docs/action_catalog.md).
- Multi-turn pressure evidence through `vmga_pressure_signal` events for
  repeated denials, urgency or authority-language pressure, and proposal
  mutation attempts.
- Proposal-surface canary detection with one-way direct-bypass failure posture.

## Repository Layout

```text
src/vmga/          Python package
policies/          Example VMGA policy profiles
docs/              Specification, deployment, and readiness notes
tests/             Unit tests
```

## Key Docs

- [Release checklist](docs/release_checklist.md)
- [Deployment runbook](docs/deployment_runbook.md)
- [Action catalog](docs/action_catalog.md)
- [Evidence notes](docs/evidence.md)
- [Canary tripwire](docs/canary_tripwire.md)
- [Evidence integrity architecture](docs/evidence_integrity_design.md)
- [Approval signing architecture](docs/approval_signing_design.md)
- [Roadmap](docs/roadmap.md)
- [Hermes integration notes](docs/hermes_integration.md)
- [OpenClaw integration notes](docs/openclaw_integration.md)
- [Gmail backend options](docs/gmail_backend_options.md)
- [DSOVS readiness mapping](docs/dsovs_readiness.md)
- [Historical v0.2 spec](docs/vmga_spec_v0.2.md)

## Quickstart

```bash
python3 -m pip install -e ".[dev]"
pytest -q
```

Safe local playground, no Gmail account or OAuth credentials required:

```bash
python scripts/vmga_fixture_playground.py --force
```

The playground uses
[examples/fixtures/safe_mailbox.json](examples/fixtures/safe_mailbox.json) with
the fake Gmail backend and writes local artifacts under
`artifacts/vmga-fixture-playground/`. It uses a fixture-only in-memory approval
secret and no live keyring, OAuth token, broker token, gog config, or network
service.
Its terminal output includes deterministic `VMGA_PLAYGROUND` lines showing a
direct execution bypass denial, repeated-denial `vmga_pressure_signal` evidence,
proposal-mutation `vmga_pressure_signal` evidence, and a replay denial with
`vmga_approval_already_used`.

## Roadmap

VMGA's roadmap focuses on reducing operator friction while preserving the
approval, signing, evidence, and deployment-boundary constraints that make the
control meaningful. The near-term direction is operator experience without
boundary collapse: easier to run, without weakening what it enforces. See
[docs/roadmap.md](docs/roadmap.md) for direction and explicit anti-goals.

## Broker Mode

Run the local broker with the fake backend for offline development:

```bash
export VMGA_APPROVAL_SECRET="replace-with-a-local-dev-secret"
vmga-broker --backend fake --policy policies/draft_assist.yaml --allow-unauthenticated
```

For Ed25519 approval signatures, start the broker with public keys only:

```bash
vmga-broker --approval-auth signature --approval-public-keys /operator/keyring.json ...
```

The operator signs out of band with `vmga-approval-sign`. Private keys must not
be stored in the broker environment, state database, policy file, evidence
ledger, repository, or any agent-readable path.

For a gogcli-backed broker, point VMGA at the agent-safe wrapper and keep gog
OAuth config outside the agent-readable workspace:

```bash
export VMGA_APPROVAL_SECRET="replace-with-a-broker-secret"
export VMGA_BROKER_TOKEN="replace-with-a-broker-token"
export VMGA_EVIDENCE_HMAC_KEY="replace-with-an-operator-evidence-secret"
export VMGA_EVIDENCE_HMAC_KEY_ID="operator-2026-06"
vmga-broker \
  --backend gogcli \
  --gog-binary /opt/homebrew/bin/gog-agent-safe \
  --gog-home /path/outside/agent/workspace \
  --ledger-rotate-bytes 10485760
```

The gogcli backend starts with a narrow Gmail surface: search, read, and create
draft. It always enables `--gmail-no-send`, `--no-input`, and an exact command
allowlist. Gmail send remains denied by VMGA policy and by the backend.
SQLite state uses WAL mode and a busy timeout for concurrent broker callers.
Every broker proposal receives a correlation ID that is carried into evidence
events for request tracing.

Operators can arm canary detection with
`--canary-registry /path/outside/agent/canaries.yaml`. Keep that dedicated
registry and VMGA state outside agent-readable/writable roots, and supply
`--agent-root` so the broker can refuse a known registry placement under an
agent root. The repository ships no active marker. See
[Canary tripwire](docs/canary_tripwire.md) for the strict detect-not-prevent
boundary and registry schema.

Operator helpers:

```bash
vmga-operator --json posture
vmga-operator --state-db /path/outside/agent/state.sqlite3 list
vmga-operator --state-db /path/outside/agent/state.sqlite3 show <proposal-id>
vmga-approval-token <proposal-id> <proposal-hash> <approver-id>
vmga-operator approve <proposal-id> <approver-id> <approval-token>
vmga-operator execute <proposal-id> <proposal-hash> <approval-token>
vmga-verify-evidence /path/outside/agent/evidence.jsonl \
  --state-db /path/outside/agent/state.sqlite3 \
  --hmac-key operator-2026-06="$VMGA_EVIDENCE_HMAC_KEY"
```

The broker exposes `/v1/posture` and prints a startup posture summary. Treat any
`advisory` or `cannot_determine` posture as not hard-enforcement-ready; unknown
direct-bypass or credential-isolation checks must be resolved with operator
evidence before making hard-boundary claims. Path-isolation checks report
`unknown` unless the operator supplies the agent-readable root with
`--agent-root`; direct-bypass closure requires explicit operator attestation
with an evidence reference. For example:

```bash
vmga-operator --json posture --local \
  --agent-root /path/to/agent/workspace \
  --attest-no-direct-bypass \
  --direct-bypass-evidence docs/deployment-evidence/no-direct-gmail.md
```

Only use the attestation flags after collecting real evidence that the
mailbox-capable agent cannot reach direct Gmail, Workspace, browser, CLI, MCP,
cron, or plugin write paths outside VMGA.

For a real-account smoke test, run the broker first and then opt in explicitly:

```bash
python scripts/vmga_live_smoke.py \
  --live \
  --broker-url http://127.0.0.1:8765 \
  --safe-recipient operator@example.com
```

Add `--create-draft` only when a real Gmail draft is acceptable. The smoke test
talks to VMGA, not directly to gog or Gmail, and writes a redacted transcript
under `artifacts/`. Draft smoke tests include a `[VMGA-SMOKE]` subject/body tag
so the operator can search for and bulk-delete generated drafts.

## Design Influences

- The original VMGA reference implementation in Vesta Agent Runtime Governance.
- The VMGA v0.2 specification carried into
  [docs/vmga_spec_v0.2.md](docs/vmga_spec_v0.2.md).
- `orlyjamie/hardmail`, as prior art for a shell-free Hermes mail surface. VMGA
  borrows that ergonomics direction, not hardmail's self-gated approval model.
- OWASP DSOVS, as a release-readiness and evidence self-assessment lens. This
  does not imply OWASP certification or endorsement.
- OpenClaw's public gateway security, exposure, formal-model, and MITRE ATLAS
  threat-model docs, as deployment-boundary references for OpenClaw integrations.
- OpenClaw SecretRef, secrets audit, and trusted-proxy auth docs, as credential
  migration and gateway-auth references. SecretRefs are treated as plaintext
  residue reduction, not process isolation.
- OpenClaw approvals, sandbox, gateway protocol, `/tools/invoke`, and pairing
  docs, as runtime-boundary references. These controls complement VMGA but do
  not replace VMGA proposal-bound approval.
- OpenClaw sandboxing, OpenShell, tool policy/elevated, operator-scope, and
  secure-file-operation docs, as isolation and file-safety references. These are
  deployment controls, not proof that VMGA is enforced by themselves.
- Hermes security, Docker, Tool Gateway, credential-pool, gateway-internals,
  session-storage, CLI-extension, and tools-runtime docs, as Hermes deployment
  boundary references.
- Hermes plugin-build docs, as the reference shape for VMGA's Hermes
  integration package and tool handler contract.

## Non-Goals

VMGA does not claim prompt-injection prevention, DLP, host compromise
protection, browser/session isolation, compliance certification, or security of
Hermes/OpenClaw internals.

## License

VMGA is released under the MIT License. See `LICENSE`.

# VMGA Deployment Runbook

This runbook describes the minimum deployment posture needed before VMGA can be
described as a hard Gmail governance boundary.

## Required Preconditions

1. The agent process cannot read Gmail OAuth tokens, approval verifier secrets,
   VMGA policy files, or executor credentials.
2. The agent cannot call Gmail write-capable APIs outside VMGA.
3. Approval happens through a channel the agent cannot spoof or operate.
4. VMGA state and evidence paths are not writable by the agent.
5. Kinetic actions fail closed when policy, state, approval, or evidence writes
   are unavailable.

## Local Broker Operations

For a local production-adjacent setup, run VMGA as an operator-owned broker
process on loopback. Keep the broker environment file, policy file, SQLite
state, JSONL evidence, gog OAuth material, and keyring password outside the
agent-readable repository.

Minimum broker environment:

```text
VMGA_APPROVAL_SECRET=<operator-owned secret>
VMGA_BROKER_TOKEN=<operator-owned broker bearer token>
VMGA_EVIDENCE_HMAC_KEY=<operator-owned evidence HMAC secret>
VMGA_EVIDENCE_HMAC_KEY_ID=<stable evidence key id>
GOG_KEYRING_PASSWORD=<operator-owned keyring password>
VMGA_BROKER_URL=http://127.0.0.1:8765
```

Minimum broker command shape:

```bash
vmga-broker \
  --host 127.0.0.1 \
  --port 8765 \
  --backend gogcli \
  --gog-binary /opt/homebrew/bin/gog-agent-safe \
  --gog-home /path/outside/agent/gog-home \
  --policy /path/outside/agent/policy.yaml \
  --state-db /path/outside/agent/state.sqlite3 \
  --ledger /path/outside/agent/evidence.jsonl \
  --canary-registry /path/outside/agent/canaries.yaml \
  --agent-root /path/to/agent/workspace \
  --ledger-rotate-bytes 10485760 \
  --ledger-backups 5
```

The broker CLI refuses unauthenticated startup by default. Use
`--allow-unauthenticated` only for loopback-only fake-backend development, never
for live mailbox credentials or remote ingress. The built-in HTTP server does
not provide TLS; put it behind an authenticated local/private-network boundary
or an external TLS-terminating ingress when it is not loopback-only.

Use `launchd`, systemd, or another operator-owned supervisor for restart and log
capture. The supervisor wrapper should source secrets from the operator-owned
environment file and should not live in an agent-writable directory.

Health and recovery checks:

```bash
curl -fsS http://127.0.0.1:8765/health
curl -fsS http://127.0.0.1:8765/v1/posture
vmga-operator --json posture --local \
  --agent-root /path/to/agent/workspace
vmga-operator --state-db /path/outside/agent/state.sqlite3 list
vmga-verify-evidence /path/outside/agent/evidence.jsonl \
  --state-db /path/outside/agent/state.sqlite3 \
  --hmac-key "$VMGA_EVIDENCE_HMAC_KEY_ID=$VMGA_EVIDENCE_HMAC_KEY" \
  --json
```

`/v1/posture` is a runtime self-check, not a formal sandbox proof. It reports
whether VMGA can locally see hard-enforcement preconditions such as broker auth,
backend wrapper choice, obvious path placement, evidence rotation, approval
mode, and evidence-integrity mode. `unknown` never counts as hard-ready.
Path-isolation checks report `unknown` unless the operator supplies the
agent-readable roots with `--agent-root`. Direct Gmail/Workspace bypass closure
is not locally provable by VMGA; it becomes `pass` only when the operator
supplies `--attest-no-direct-bypass` and a `--direct-bypass-evidence` reference.
If the posture mode is `advisory` or `cannot_determine`, describe the
deployment that way until missing credential-isolation, direct-bypass, and
evidence-anchor proof is collected.

Use `--attest-no-direct-bypass` only after collecting evidence that the
mailbox-capable agent cannot reach direct Gmail, Workspace, browser, CLI, MCP,
cron, or plugin write paths outside VMGA. Include a durable reference with
`--direct-bypass-evidence`; do not use a bare attestation as a substitute for
reviewable deployment evidence.

### Canary tripwire

Operators may configure a dedicated canary registry with
`--canary-registry /path/outside/agent/canaries.yaml`; see
[Canary tripwire](canary_tripwire.md) for its schema. Keep the registry
operator-owned and non-writable by the agent, separate from policy and proposal
inputs. Supply every relevant `--agent-root`: broker startup refuses a registry
under a configured agent root, and posture reports registry placement, but this
path comparison is not a filesystem-permission proof.

VMGA scans only proposal `content`, `justification`, and `parameters`. A match
emits one payload-free `vmga_canary_tripped` CRITICAL event per matched canary
and durably records a one-way trip bit with no reset API in operator state. The
resulting `direct_gmail_bypass=fail` takes precedence over an attestation and
yields `advisory`. No configured marker, or an armed registry with no match,
leaves the check `unknown` unless
the existing explicit operator attestation plus evidence independently makes it
`pass`; canary state itself never makes a check pass or contributes to
hard-enforcement readiness.

This detects, but does not prevent, a marker returning through VMGA. VMGA does
not monitor file reads, syscalls, direct Gmail traffic, or silent credential use.
A quiet canary is not proof of isolation. An optional operator-hosted decoy auth
endpoint can alert on use of its fake credential, including a silent attempt;
VMGA neither hosts that endpoint nor currently ingests its beacon.

The posture self-check distinguishes declared modes from operative ones.
`signature` approval mode passes only when an approver keyring with at least
one active, parseable Ed25519 key is actually loaded; declared-but-unloaded
signature mode reports `warn` as non-operative. A chain evidence-integrity mode
passes only when the evidence HMAC key is configured, an expected-head
checkpoint exists, and the existing chain verifier returns `verified_intact`
over the current ledger; `verified_tampered` is `fail` (mode advisory) and
`cannot_verify` is `unknown` with the verifier's reason surfaced — for example,
`vmga-operator posture --local` without the evidence key honestly reports
`unknown` rather than guessing. Operative posture is still not proof of
deployment-boundary isolation: `signature` approval
mode verifies Ed25519 detached approvals with broker-held public keys only; it
supports hard approval-enforcement claims only when the approver private key is
isolated from both broker and agent authority domains. Residuals: private-key
compromise, operator signing-device compromise, and intentional operator
approval are outside VMGA's approval-signature boundary. HMAC approval mode
remains broker-forgeable and advisory/dev. Evidence integrity is active only
when both evidence HMAC environment variables are present and the expected-head
checkpoint is stored outside the agent-writable workspace. Without that anchor,
JSONL evidence remains advisory and `vmga-verify-evidence` reports
`cannot_verify`, never success.

If `/health` reports lockdown, inspect evidence first, then reset only through
an operator-controlled maintenance path. `reset_lockdown` is an in-process
maintenance API, not a public broker route; do not expose it to agents or remote
callers without separate operator authentication. If state or evidence writes
fail, preserve the failed files for diagnosis and restart only after
permissions, disk space, and policy paths are corrected.

SQLite state uses Write-Ahead Logging and a busy timeout so simultaneous broker
callers can read while another request writes. This is not a queue by itself;
high-volume batch callers should still serialize kinetic work at the agent or
operator layer.

VMGA uses at-most-once approval-consumption semantics for kinetic execution.
With `SQLiteStateStore`, an approval is transactionally marked `used` before the
backend side effect begins; concurrent broker processes against the same SQLite
database cannot both consume the same approval. If the broker or backend fails
after consumption but before the mailbox side effect completes, replay is denied
on restart. That can lose a draft/send attempt, but it fails safer than
replaying a mailbox side effect. Operators should inspect evidence and submit a
new proposal when a consumed execution fails.

The built-in broker still uses an in-process adapter lock for proposal,
approval, execution, and lockdown-reset mutations inside one process. For
hard-enforcement claims, multi-process deployments must use the SQLite state
store or another state backend with equivalent transactional consume before
execution semantics.

Each broker proposal receives a `correlation_id`. Supplying one in the request
preserves the caller's ID; otherwise the broker generates one. Proposal, state,
approval, and execution evidence events carry that ID so a single lifecycle can
be traced in the JSONL ledger.

The JSONL ledger supports size-based rotation through `--ledger-rotate-bytes`
and `--ledger-backups`. Operators can also use OS log rotation if compression or
central collection is required. Rotate before local disk pressure becomes a
mailbox availability risk.

When evidence HMAC mode is enabled, VMGA verifies the ordered retained segment
set from the oldest rotated backup through the active file. It checks per-record
MACs, sequence continuity, cross-file seams, the genesis anchor, and the
expected head. Deleting a retained rotated segment is reported as tampering.
History pruned beyond the retained backups is outside Tier 1 and needs an
external append-only or WORM sink if older history must remain verifiable.

Tier 1 does not protect against a compromised broker/operator context that can
both rewrite evidence and read the evidence HMAC key, or forge the checkpoint in
state. Keep the key, state DB, and ledger outside the agent authority domain and
record that placement in deployment evidence.

## Real-Account Smoke Test

Use `scripts/vmga_live_smoke.py` only after the broker is running and gog auth
has been configured in an operator-owned gog home. The smoke script calls the
broker, not gog directly.

**Live draft warning:** `--create-draft` creates a real Gmail draft. Use the
default `[VMGA-SMOKE]` tag or another unique subject/body marker, verify the
draft in Gmail, then search for that marker in Drafts and delete the generated
drafts before sharing evidence or tagging a release.

The smoke script uses a per-run actor for its intentional send-denial probe so
repeated smoke runs do not accumulate denial counts toward the broker lockdown
threshold for the main smoke actor.

Read/search and send-denial probe:

```bash
python scripts/vmga_live_smoke.py \
  --live \
  --broker-url http://127.0.0.1:8765 \
  --safe-recipient operator@example.com
```

Approved draft creation:

```bash
export VMGA_APPROVAL_SECRET=<operator-owned secret>
python scripts/vmga_live_smoke.py \
  --live \
  --create-draft \
  --broker-url http://127.0.0.1:8765 \
  --safe-recipient operator@example.com
```

Draft creation is a real Gmail side effect. The script expects `send` to remain
denied and writes a redacted transcript under `artifacts/`. Draft smoke tests
add a `[VMGA-SMOKE]` marker to the subject and body so generated drafts can be
searched and bulk-deleted later.

Redaction happens in memory before the transcript is written. Do not pipe raw
broker responses to temporary files before redaction.

## OpenClaw Deployments

For OpenClaw, VMGA assumes one trusted operator boundary per gateway. Use
separate gateways, OS users, hosts, VMs, or containers for materially different
trust boundaries. Shared routing labels and `sessionKey` values are context
selectors, not VMGA authorization boundaries.

Before exposing an OpenClaw-backed VMGA deployment, run:

```bash
openclaw config set gateway.mode local
openclaw doctor
openclaw security audit --deep
openclaw secrets audit --check
openclaw sandbox explain --json
openclaw approvals get --gateway --json
openclaw health
openclaw plugins inspect plugin.vmga
```

Record the audit output, accepted residual warnings, gateway config hash, VMGA
policy hash, plugin manifest hash, secrets audit output, and proof that non-VMGA
Gmail write paths are denied. If `openclaw secrets apply` or
`openclaw secrets reload` is part of the deployment, keep the plan and reload
result in release evidence. See `docs/openclaw_integration.md` for the detailed
OpenClaw checklist.

`plugin.vmga` being loaded is not sufficient. Gateway mode, token auth, command
owner, session storage, plugin status, sandbox posture, secrets posture, and
direct-bypass denial evidence must all be captured before calling OpenClaw
runtime wiring ready.

If sandbox configuration, OpenShell policy, SSH sandbox auth, Docker image,
backend, mode, or setup commands change, recreate the affected sandbox runtimes
with `openclaw sandbox recreate` before treating the new policy as active.
Capture the effective sandbox mode, backend, scope, workspace access, sandbox
tool policy, elevated gates, bind mounts, and OpenShell mode/policy where
applicable.

Sandboxing, tool policy, and elevated mode are separate controls. Sandboxing
decides where tools run, tool policy decides what is callable, and elevated mode
is an exec-only path outside the sandbox. A hard VMGA deployment should deny
elevated exec for mailbox-capable agents and prove `exec` cannot mutate Gmail
state outside VMGA.

Treat OpenClaw `/tools/invoke` as a gateway operator surface. A deployment must
prove that direct mailbox write tools cannot be invoked through it unless they
emit VMGA proposals and pass through VMGA execution.

OpenClaw exec approvals and node pairing are not substitutes for VMGA approval.
VMGA approval remains proposal-bound, non-replayable, and verified by VMGA before
any Gmail side effect.

SecretRefs are useful but do not isolate secrets from an agent that can read
files or execute commands in the same authority context. If plaintext
credentials, OAuth refresh material, copied configs, backups, generated model
catalogs, or unsupported credential classes remain readable by the agent,
describe the deployment as advisory.

OpenClaw fs-safe and secure file helpers are guardrails for trusted OpenClaw code
handling untrusted paths; they are not a sandbox. VMGA state, evidence, Gmail
credentials, browser profiles, Docker sockets, and OpenClaw config/auth material
must stay outside any agent-readable or sandbox-mounted path.

## Hermes Deployments

For Hermes, VMGA hard enforcement requires a shell-free VMGA mail tool surface
and credential isolation from the Hermes agent process. Hermes dangerous-command
approval, YOLO state, Docker isolation, MCP environment filtering, Tool Gateway
routing, and credential pools are useful controls, but none replaces VMGA's
proposal-bound Gmail approval.

Before exposing a Hermes-backed VMGA deployment, record:

- Effective `~/.hermes/config.yaml` and `~/.hermes/.env` hashes with secrets
  redacted.
- Gateway allowlists or DM pairing state proving only intended senders can
  trigger the mailbox-capable agent.
- `approvals.mode`, `approvals.cron_mode`, `HERMES_YOLO_MODE`, and permanent
  `command_allowlist` posture.
- Terminal backend and Docker/remote runtime settings, including mounted
  volumes, forwarded env vars, credential files, resource limits, and whether
  `/var/run/docker.sock` is mounted.
- Proof that native Hermes Gmail/Workspace tools, direct Workspace CLIs, MCP
  servers, hooks, plugins, cron jobs, and browser sessions cannot mutate Gmail
  outside VMGA.
- Location and permissions for `~/.hermes/state.db`, gateway logs, VMGA evidence,
  VMGA state, and VMGA credential material.

If Hermes can read Gmail OAuth tokens, Google client secrets, VMGA verifier
secrets, VMGA policy/evidence, or direct Workspace credentials, describe the
deployment as advisory.

## Advisory Mode

If VMGA runs in the same authority context as the agent, or if the agent can read
tokens and policy files, describe the deployment as advisory governance only.

## Evidence To Collect

- Service identity and filesystem permission output.
- Network egress rules showing direct Gmail write paths are unavailable to the
  agent.
- Policy file hash and deployment config hash.
- Broker health output and VMGA operator proposal listing.
- Runtime posture output, including supplied agent roots and any direct-bypass
  attestation evidence reference.
- `gog-agent-safe` version and gog auth health, redacted.
- Hermes plugin status and VMGA handler smoke output, redacted.
- OpenClaw doctor, plugin inspect, secrets audit, sandbox explain, and approvals
  output, redacted.
- Redacted live smoke transcript when a real account is tested.
- Sample ledger entries for allow, deny, review-required, approval, execution,
  lockdown, and reset.

## Approval Token Hardening

VMGA approval tokens are HMAC values bound to `proposal_id`, `proposal_hash`,
`approver_id`, and a short UTC time window. The default generated token window
is five minutes, with one previous-window grace for clock skew. Approval records
also persist a proposal binding hash and a used flag so tokens cannot be applied
to a different proposal or replayed after successful execution.

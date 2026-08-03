# VMGA Release Checklist

Use this checklist before tagging or publishing a VMGA release, and before
deploying VMGA with live mailbox credentials. The checklist has two lanes:
repo-verifiable gates that CI can run, and operator-evidence gates that must be
captured from the target deployment.

VMGA does not claim prompt-injection prevention, DLP, host compromise
protection, browser/session isolation, compliance certification, or security of
Hermes/OpenClaw internals. Release evidence should preserve that boundary.

## Automated Repo Gates

Run these commands from the repository root before opening a release PR or
tagging a release:

```bash
python -m compileall src tests scripts integrations
python -m pytest -q
python scripts/vmga_release_check.py --json
python scripts/vmga_fixture_playground.py --force
python -m pytest tests/test_fixture_playground.py -q
```

For OpenClaw integration changes, also run:

```bash
cd integrations/openclaw
npm test
npm run plugin:validate
```

`scripts/vmga_release_check.py` is the offline repo-verifiable release gate. It
currently checks:

- Required release files are present.
- Shipped policy YAML loads through VMGA policy parsing.
- `docs/action_catalog.md` matches the shipped `GmailAction` enum, action
  classes, default approval stance, and baseline-deny behavior.
- Public docs, examples, policies, and JSON fixtures avoid obvious secret
  patterns and public Gmail account leakage.
- Required claim-hygiene language exists for prompt-injection prevention, DLP,
  host compromise, browser/session isolation, compliance certification, and
  Hermes/OpenClaw internals.
- Merge-conflict markers are absent from source, docs, examples, policies, and
  release metadata.

CI runs the release check, test suite, compile checks, OpenClaw plugin
validation, and CodeQL. A passing CI run is required before merge, but it is not
deployment evidence by itself.

## Manual Operator Evidence

The following items depend on the target machine, mailbox, gateway, or operator
workflow. CI cannot prove them. Capture redacted command output, screenshots, or
operator notes in release evidence when a deployment claim depends on them.

- Review dependency, license, CodeQL, secret-scanning, Dependabot, and
  dependency-review status for the canonical repository.
- Verify `SECURITY.md` has a monitored reporting path and that private
  vulnerability reporting remains enabled for the public repository.
- Verify example policies use placeholder domains and strict defaults.
- Verify SQLite state uses WAL mode and a busy timeout in the deployed broker.
- Verify evidence rotation is configured through VMGA or host log rotation
  before live use.
- Verify broker correlation IDs appear on proposal, state, approval, execution,
  and pressure-signal evidence for at least one request lifecycle.
- If canaries are armed, verify the registry and one-way trip state are outside
  agent authority, a staging marker emits payload-free CRITICAL evidence, and
  quiet-canary posture remains unknown rather than pass.
- Verify redaction happens in memory before writing shareable smoke-test or
  release evidence.
- Verify live smoke drafts are tagged with `[VMGA-SMOKE]` or cleaned up before
  sharing evidence.
- Verify CI-safe mocks use the same broker request contract as the real broker.
- Verify gogcli rate-limit handling returns structured VMGA errors after
  bounded exponential backoff.

## Runtime Posture Gate

Run the posture self-check for any live deployment claim:

```bash
vmga-operator --json posture --local \
  --agent-root /path/to/agent/workspace \
  --attest-no-direct-bypass \
  --direct-bypass-evidence docs/deployment-evidence/no-direct-gmail.md
```

Retain the JSON output and the evidence reference supplied with
`--direct-bypass-evidence`. Treat `advisory` or `cannot_determine` as the actual
deployment posture until missing evidence is resolved.

Posture must not claim hard-ready from configuration strings alone:

- `hmac_chain` evidence must verify intact against the expected-head checkpoint.
- `signature` approval mode must load an active Ed25519 public keyring.
- Path-isolation checks must use explicit `--agent-root` values.
- Direct-bypass closure must be supported by operator evidence, not inference.

## v0.3.0 Gates

For v0.3.0 or later tags, verify these implemented records before making
hard-boundary claims:

- `docs/evidence_integrity_design.md`: HMAC-chain ledger verification,
  expected-head checkpointing, genesis anchoring, rotated-segment continuity,
  and fail-closed `cannot_verify` behavior.
- `docs/approval_signing_design.md`: Ed25519 detached approval signatures,
  broker-side proposal-hash recomputation, nonce replay denial, algorithm/key
  matching, and no silent HMAC fallback in signature mode.
- `docs/action_catalog.md`: checked tier catalog aligned with OpenClaw/Hermes
  tool surfaces.
- `docs/evidence.md`: `vmga_pressure_signal` evidence for repeated denials,
  urgency or authority pressure, and proposal mutation attempts.
- `scripts/vmga_fixture_playground.py`: local-only fixture demonstration of
  bypass denial, pressure evidence, tamper denial, and
  `vmga_approval_already_used`.

When verifying anchored evidence, supply the expected-head checkpoint or state
database and the required HMAC key material, for example:

```bash
python scripts/verify_vmga_evidence.py /path/outside/agent/evidence.jsonl \
  --state-db /path/outside/agent/state.sqlite3 \
  --hmac-key operator-2026-06="$VMGA_EVIDENCE_HMAC_KEY" \
  --json
```

An unanchored fixture ledger may pass sequence validation while returning
`cannot_verify` for integrity; do not treat that as hard tamper-evidence.

## OpenClaw Operator Evidence

Capture this when a release or deployment claims OpenClaw readiness:

```bash
openclaw doctor
openclaw plugins inspect plugin.vmga
openclaw security audit --deep
openclaw secrets audit --check
openclaw sandbox explain --json
openclaw approvals get --gateway --json
```

Also record the OpenClaw version under test and check current release notes for
security-relevant changes to HTTP tool gating, MCP redirect handling, plugin
install pinning, state-store migrations, service env planning, and release proof
behavior.

Verify:

- `/tools/invoke` cannot call non-VMGA Gmail/Workspace write paths.
- Sandbox mode, backend, scope, workspace access, sandbox tool policy, elevated
  gates, bind mounts, and OpenShell mode/policy cannot reach Gmail side effects
  outside VMGA.
- Elevated exec is disabled for mailbox-capable agents or documented as a
  break-glass exception with bypass evidence.
- Node pairing and node command policy do not expose mailbox side effects
  outside VMGA.
- VMGA state, evidence, Gmail credentials, browser profiles, Docker sockets,
  and OpenClaw config/auth material are not exposed through sandbox bind mounts
  or agent-readable paths.
- If OpenClaw SecretRefs are migrated, retain the redacted
  `openclaw secrets apply` plan and `openclaw secrets reload` result.
- If trusted-proxy auth is documented or enabled, verify the proxy
  authenticates users, is the only gateway path, strips or overwrites identity
  headers, and has an explicit `allowUsers` operator list for shared audiences.

## Hermes Operator Evidence

Capture this when a release or deployment claims Hermes readiness:

- `vmga-mail` is enabled and points at the VMGA broker.
- `VMGA_BROKER_URL` is configured; `VMGA_BROKER_TOKEN`, when used, is available
  only to the VMGA plugin process or operator wrapper.
- `--yolo`, `/yolo`, `HERMES_YOLO_MODE=1`, and `approvals.mode: off` are not
  part of mailbox-capable deployments.
- Hermes gateway allowlists or DM pairing restrict who can trigger VMGA mail
  tools.
- Hermes env passthrough, Docker forwarded env vars, credential-file mounts,
  MCP env config, hooks, plugins, cron jobs, and native Google Workspace tools
  do not expose Gmail writes outside VMGA.
- Hermes plugin examples use the standard plugin layout, declare only VMGA
  tools in `provides_tools`, return JSON strings from handlers, and avoid
  slash-command or hook dispatch to non-VMGA Gmail or terminal tools.
- Hermes `~/.hermes/state.db`, gateway logs, credential files, browser
  profiles, VMGA state, and VMGA evidence are treated as sensitive deployment
  artifacts.

## DSOVS Evidence

Record DSOVS self-assessment evidence in `docs/dsovs_readiness.md`. That file
is a readiness mapping and gap-analysis aid only; it is not OWASP
certification, endorsement, formal compliance evidence, or a complete DSOVS
assessment.

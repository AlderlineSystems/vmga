# VMGA Evidence Notes

VMGA release evidence should show what was tested, reviewed, and bounded for a
tagged release or live deployment without overstating VMGA's security boundary.

## What To Capture

- `python scripts/vmga_release_check.py`
- `pytest tests/test_release_checks.py -q`
- `python scripts/build_vmga_evidence.py --mode dry-run --force`
- `python scripts/build_vmga_evidence.py --mode release --include-local-tools`
- Policy load results for every shipped file in `policies/`
- A record of whether `schemas/` exists in the release bundle
- Secret-scan output for docs, examples, and integration example files when
  present
- Broker health output, VMGA operator proposal listing, gog auth health, Hermes
  plugin status, OpenClaw plugin status, and OpenClaw doctor/security outputs
  when a local deployment is being claimed
- Runtime posture output, including agent roots supplied to the check and any
  direct-bypass attestation evidence reference
- Any deployment-specific evidence required by `docs/deployment_runbook.md`
- Correlation IDs for proposal, state, approval, and execution events when a
  request lifecycle is being traced.
- `vmga_pressure_signal` events for multi-turn pressure patterns, including
  repeated denials, urgency or authority-language pressure, and proposal
  mutation attempts during execution.

## Claim Hygiene

The public docs must stay explicit about what VMGA is and is not. VMGA does not
claim prompt-injection prevention, DLP, host compromise protection,
browser/session isolation, compliance certification, or security of
Hermes/OpenClaw internals.

That language belongs in the README and supporting docs so reviewers can see the
boundary without cross-referencing hidden notes or oral context.

## Safe Publishing Rules

- Example configs should use `example.com`, `example.invalid`, or other clearly
  fake placeholders.
- Approval secrets and Gmail tokens should be referenced as external sources,
  never embedded in examples.
- Evidence bundles should be reproducible offline from the repository state and
  should not depend on live secrets.
- Live evidence should be redacted before sharing. Keep raw local transcripts in
  ignored artifact directories and commit only generic examples.
- Redact in memory before writing shareable evidence. Do not write raw OAuth
  tokens, mailbox content, or message payloads to temporary files as an
  intermediate step.

## Pressure Signals

VMGA emits `vmga_pressure_signal` evidence events when policy-visible behavior
shows escalation across a request lifecycle. These events are metadata-only:
they carry proposal ids, proposal hashes, action, actor, policy state, rule id,
denial counts, risk flags, correlation ids, and mutation hashes where relevant;
they do not carry raw message bodies or approval tokens.

Current pressure signal types:

- `repeated_denial_escalation`: the same actor receives repeated denials before
  or at lockdown.
- `urgency_or_authority_pressure`: urgency language from content-risk analysis
  or authority-language markers are present on a denied, locked down, or
  review-required proposal.
- `proposal_mutation_attempt`: execution is denied because the supplied
  proposal hash or persisted approval binding no longer matches the approved
  record.

These events do not create a separate policy engine. They make the existing
policy decision and integrity checks inspectable as multi-turn evidence.

## Canary Trip Evidence

Collect canary trip evidence according to the authoritative [Canary tripwire]
document. Retain the payload-free CRITICAL event and resulting posture output
when a deployment uses this control; do not copy the marker, location hint, or
surrounding proposal payload into shareable evidence. A canary trip is a
proposal-surface detection signal, not proof that VMGA prevented or observed a
silent direct Gmail path.

[Canary tripwire]: canary_tripwire.md

## Release Review

Use `scripts/vmga_release_check.py` as a preflight gate before tagging a
release. The script is intentionally conservative: missing required files or
obvious secret patterns are treated as errors, while a missing `schemas/`
directory is reported so the release reviewer can decide whether that is
expected for the current snapshot.

Use `scripts/build_vmga_evidence.py --mode release` to collect a redacted local
evidence skeleton. The command records hashes and broker health by default. Add
`--include-local-tools` only when the local Hermes/OpenClaw/gog command output is
intended to become part of the operator evidence bundle.

For the implemented Tier-1 evidence-integrity mode, see
`docs/evidence_integrity_design.md`. Evidence integrity is active only when the
broker is configured with an evidence HMAC key, key id, and expected-head
checkpoint held outside the agent authority domain. Without that anchor
material, VMGA evidence remains append-only JSONL with advisory verification.

For the implemented asymmetric approval-signature mode, see
`docs/approval_signing_design.md`. Signature mode is a hard approval-enforcement
candidate only when approver private keys are held outside the broker and agent
authority domains. HMAC approval remains available for advisory and development
use and is broker-forgeable on the approval axis.

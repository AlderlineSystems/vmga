# Changelog

All notable changes to VMGA will be documented here.

## Unreleased

### Security

- Added operator-owned proposal-surface canary detection. Registered non-secret
  markers in content, justification, or parameters emit payload-free CRITICAL
  evidence and durably force `direct_gmail_bypass` to fail/advisory through a
  one-way state bit. This detects but does not prevent bypass; quiet canaries
  remain unknown and never contribute to hard-enforcement readiness.

## [0.3.0] - 2026-06-11

### Security

- Added opt-in Ed25519 approval-signature mode with broker-held public keys,
  detached signature evidence, single-use approval nonces, and an external
  `vmga-approval-sign` helper. HMAC approval remains available for advisory and
  development use and is broker-forgeable because the broker holds the secret.
- Implemented opt-in Tier-1 evidence HMAC chaining with expected-head
  checkpoints, cross-file rotated-ledger verification, key rotation support,
  crash-after-append recovery, and separate CLI reporting for advisory event
  checks versus integrity state.
- Added SQLite transactional approval consumption for at-most-once kinetic
  execution across independent broker processes. Approvals are consumed before
  backend execution; failures after consumption are not replayable and require a
  new proposal.
- Added approval binding-mutation coverage for persisted record tampering,
  type-confused approval payloads, request bit-flips, stale HMAC windows, and
  signature payload mutation; malformed bindings now deny without executing the
  backend handler.

### Added

- Added the runtime enforcement posture self-check (`/v1/posture`,
  `vmga-operator posture`, and broker startup summaries) so operators can see
  when a deployment is advisory, cannot be determined, or hard-ready under
  explicit evidence.
- Added canonical implemented architecture records for tamper-evident evidence
  and asymmetric out-of-domain approval signatures.
- Added a checked action-tier catalog in `docs/action_catalog.md`; the release
  check asserts the catalog against live `GmailAction`, action classification,
  default approval posture, and baseline-deny behavior.
- Added first-class `vmga_pressure_signal` evidence for repeated denials,
  urgency or authority-language pressure, and proposal mutation attempts.
- Added a safe local fixture playground with fake mailbox data, deterministic
  terminal evidence logs, replay-denial output, and no Gmail/OAuth dependency.
- Added a public roadmap that frames operator-experience work around preserving
  VMGA's approval, signing, evidence, and deployment-boundary constraints.

### Changed

- Added README links to the main architecture, deployment, evidence,
  integration, and readiness docs for GitHub readers.
- Posture now checks that signature approval mode and chain evidence modes are
  operative, not merely declared: signature mode passes only with a loaded
  active Ed25519 keyring, and chain modes pass only when the existing chain
  verifier returns intact against the expected-head checkpoint. Tampered
  ledgers fail posture, and missing key/checkpoint reports unknown with the
  verifier's reason; declared-but-non-operative modes never count toward
  hard-ready.
- Tightened posture checks to avoid optimistic path-isolation results: agent
  roots must be supplied explicitly, and direct Gmail/Workspace bypass closure
  requires an evidence-referenced operator attestation.

### Fixed

- Reconciled v0.3.0 documentation so the approval-signing and evidence-integrity
  records describe implemented architecture, and the v0.2 spec points readers
  to the current signature and hash-chained ledger boundaries.

## v0.2.1 - 2026-06-10

### Security

- Serialized proposal, approval, execution, and lockdown-reset mutations behind
  an adapter state lock to prevent concurrent approval-token replay in the
  single-process broker.
- Made the fake Gmail backend honor the broker search contract (`max_results`)
  and added a regression test that exercises the broker against the shipped
  backend.
- Refused unauthenticated broker startup unless `--allow-unauthenticated` is
  set on a loopback host; non-loopback binds now require `VMGA_BROKER_TOKEN`.
- Switched broker bearer-token comparison to a constant-time check.
- Redacted and length-capped agent-supplied justification and reason text before
  it is written to evidence.
- Persisted lockdown reset so a cleared lockdown survives broker restart.
- Expired stale SQLite rate-limit state on load.
- Linked GitHub private vulnerability reporting in `SECURITY.md`.

### Documentation

- Reframed the v0.2 spec as a historical reference; clarified the standalone
  ledger is append-only JSONL, not hash-chained, and that credential isolation
  is a deployment precondition.
- Documented the built-in broker as a single-process control plane and noted
  multi-process hard enforcement needs transactional cross-process approval
  consumption.
- Documented `reset_lockdown` as an in-process operator maintenance API, not a
  public broker route.

### Maintenance

- Added npm Dependabot coverage for the OpenClaw integration and documented the
  upstream `hono` advisory handling.
- Switched the repository to GitHub default CodeQL setup.

## v0.2.0 - 2026-06-10

- Added the production-alpha VMGA broker scaffold for governed Gmail and
  Workspace actions.
- Added proposal, approval, policy, state, evidence, ledger, executor, and
  broker modules with compatibility exports for the original adapter.
- Added JSON schemas for VMGA proposals, approvals, and evidence records.
- Added broker endpoints for proposals, approvals, and executions, including
  legacy compatibility routes.
- Added fake Gmail and gogcli-backed backend paths with shell-free subprocess
  execution.
- Added VMGA CLI entry points for broker operation, evidence verification,
  release checks, and approval-token workflows.
- Added dry-run and release evidence generation with verifier support.
- Added Hermes integration manifests, schemas, tool handlers, and skill docs.
- Added OpenClaw plugin packaging, profile adapter, examples, and validation
  scripts.
- Hardened broker operations with SQLite WAL mode, correlation IDs, in-memory
  redaction, bounded approval tokens, evidence lifecycle guidance, strict mock
  schemas, live-smoke cleanup tagging, and Gmail rate-limit backoff.
- Added open-source readiness scaffolding for packaging, CI, security reporting,
  contribution guidance, release checklists, evidence docs, and DSOVS
  self-assessment.
- Added the MIT License.

## Earlier

- Started standalone VMGA repository extraction.
- Imported the v0.2 reference adapter, policies, specification, and tests.
- Hardened VMGA policy validation, denial error codes, and approval binding
  checks for production-alpha work.

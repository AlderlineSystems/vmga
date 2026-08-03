# DSOVS Readiness Mapping

VMGA uses the OWASP DevSecOps Verification Standard (DSOVS) as a
self-assessment lens for release and deployment readiness. This document maps
selected DSOVS-style control areas to VMGA evidence so reviewers can see what
exists, what is deployment-specific, and what must not be overclaimed.

This file is not OWASP certification, endorsement, formal compliance evidence,
or a complete DSOVS assessment. Control identifiers follow the DSOVS phase
naming used by the OWASP project, such as `DES-002` and `CODE-004`. Re-check
the upstream standard before using this mapping in an audit packet because
DSOVS evolves over time.

VMGA does not claim prompt-injection prevention, DLP, host compromise
protection, browser/session isolation, compliance certification, or security of
Hermes/OpenClaw internals.

## Control Mapping

| Area | VMGA Evidence | Operator Evidence |
| --- | --- | --- |
| `DES-002` Threat Modelling | README status boundaries; `docs/deployment_runbook.md`; `docs/evidence_integrity_design.md`; `docs/approval_signing_design.md`; `docs/hermes_integration.md`; `docs/openclaw_integration.md`. | Deployment-specific trust-boundary notes showing where Gmail credentials, approval keys, evidence paths, and broker state live relative to the agent. |
| `CODE-002` Hardcoded Secrets Detection | `scripts/vmga_release_check.py` scans docs, examples, policies, and JSON fixtures for obvious OAuth credentials, tokens, approval secrets, private keys, and public Gmail account leakage. Tests cover secret-like and public Gmail fixture failures. | Secret-scanning status for the canonical GitHub repository and any private deployment repos. |
| `CODE-004` Static Application Security Testing | CodeQL runs in GitHub Actions for the public repository. Release PRs should retain the green check history. | Any additional local, enterprise, or deployment SAST output used for release approval. |
| `CODE-005` Software Composition Analysis | Dependabot and CI-visible dependency updates are reviewed through PRs. The OpenClaw integration pins explicit runtime versions so SCA findings map to the audited package, not a floating `latest` range. | Current GitHub security tab, production and development npm audit results for OpenClaw integration installs, and any organization SCA reports. |
| `CODE-006` Software License Compliance | MIT license is present; release checklist requires license/dependency review. | License review output for any packaged distribution or downstream deployment bundle. |
| `CODE-009` Secure Dependency Management | Dependency updates are tracked through reviewable PRs and CI, not unreviewed local lockfile churn. | Review notes for dependency bumps accepted after the release branch is cut. |
| `REL-003` Secret Management | VMGA docs require Gmail tokens, Google OAuth material, approval verifier secrets, broker bearer tokens, evidence HMAC keys, and operator signing keys to remain outside the agent authority domain. Runtime posture checks flag missing or non-operative approval-signature and evidence-integrity modes. | Secret store, keyring, file-permission, and path-isolation evidence for the deployed broker, Hermes/OpenClaw runtime, gog home, state DB, and evidence ledger. |
| `REL-004` Secure Configuration | Example policies use strict defaults; `docs/action_catalog.md` is release-checked against the shipped enum and policy behavior; posture fails toward `advisory` or `cannot_determine` when roots, anchors, keyrings, or bypass evidence are missing. | Captured `vmga-operator --json posture --local` output with explicit `--agent-root` values and direct-bypass evidence references. |
| `REL-005` Security Policy Enforcement | Tests cover policy denies, lockdown, approval binding, Ed25519 signature denial paths, HMAC-chain verification, transactional approval consumption, and pressure-signal evidence. | Live smoke or staging evidence that the target broker denies direct bypasses, replays, malformed approvals, and non-approved kinetic actions. |
| `REL-008` Secure Release Management | `docs/release_checklist.md`; `CHANGELOG.md`; CI; release check; fixture playground; evidence verifier; no-tag-before-green workflow. | Release PR, CI run URLs, operator evidence bundle, and final tag notes. |
| `OPR-004` Application Security Logging | Evidence docs and tests cover JSONL evidence, correlation IDs, redaction, pressure signals, approval records, execution outcomes, and optional HMAC-chain verification. | Retention, rotation, central collection, expected-head checkpoint ownership, and redacted sample evidence from the target deployment. |
| `OPR-005` Vulnerability Disclosure | `SECURITY.md` provides the vulnerability-reporting path; release checklist requires confirming monitored reporting and private vulnerability reporting for the public repository. | Repository settings evidence showing reporting paths are enabled and monitored. |
| `TEST-005` Security Test Coverage | Unit, contract, integration, fixture-playground, posture, evidence-integrity, approval-signature, SQLite-consumption, fuzz/mutation, OpenClaw plugin, and release-check tests. | Any deployment-specific adversarial tests, tabletop results, or external review notes used for release approval. |

## Non-Applicable Or Bounded Areas

- VMGA is not a hosted SaaS, so cloud perimeter, tenant-management, uptime SLO,
  and production incident-response controls are deployment responsibilities.
- VMGA is not a browser sandbox or host-isolation product. It can report when
  browser/session isolation is outside its claim, but it does not provide that
  isolation by itself.
- VMGA is not a DLP product. It redacts evidence and governs declared mailbox
  actions; it does not inspect every possible exfiltration path on the host.
- VMGA is not a prompt-injection prevention system. It assumes hostile or
  confused agents can request unsafe actions and focuses on policy, approval,
  execution binding, posture, and evidence.
- OpenClaw and Hermes internals are external runtime surfaces. VMGA documents
  integration assumptions and bypass controls but does not certify those
  runtimes.

## Evidence To Collect

For each tagged release or deployment that claims hard VMGA enforcement, collect
or link:

- VMGA unit, contract, integration, OpenClaw plugin, fixture-playground, and
  release-check output.
- `scripts/vmga_release_check.py --json` output.
- CodeQL, secret-scanning, Dependabot, dependency-review, and license-review
  status where configured.
- Documentation review showing security claims are bounded by deployment
  preconditions.
- Sample redacted VMGA evidence ledger entries for allow, review-required, deny,
  approval, execution, replay denial, lockdown, reset, and pressure-signal
  paths.
- Evidence-integrity verification output, including expected-head checkpoint
  handling when `hmac_chain` is claimed.
- Approval-signature readiness output showing active public keys and denial for
  missing key, algorithm mismatch, invalid signature, expired signature, and
  nonce replay when `signature` approval mode is claimed.
- Runtime posture output for the deployment under review, with explicit
  agent-readable roots and any direct-bypass attestation evidence reference.
- Deployment-specific bypass evidence for Hermes, OpenClaw, gogcli, and any
  other mailbox-capable runtime surface being claimed.

## Gap Handling

Repo-verifiable gaps should be tracked as GitHub issues and closed by PRs with
tests or documentation that name the new evidence. Deployment-specific gaps
should be captured in the operator evidence bundle and, when they affect the
reference implementation or public docs, promoted to GitHub issues.

For the v0.3.0 release train, repo-level DSOVS/release-governance
paperwork was completed through:

- #9: DSOVS self-assessment pass.
- #10: Release checklist verification automation and manual-gate separation.

Current remaining DSOVS gaps are expected to be deployment-specific unless a
new issue is opened against the reference repo. Issue #54's proposal-surface
canary detection is implemented; its detect-not-prevent boundary and required
operator evidence are documented in `docs/canary_tripwire.md`.

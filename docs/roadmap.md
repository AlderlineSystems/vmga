# VMGA Roadmap

VMGA's roadmap focuses on reducing operator friction while preserving the
approval, signing, evidence, and deployment-boundary constraints that make the
control meaningful.

This document describes direction and boundaries, not a delivery commitment. It
is intentionally high-level and slow-changing. For the current state of work,
see the GitHub issues, milestones, and `CHANGELOG.md`; those are the living
record. This file exists to explain where VMGA is headed and, just as
importantly, where it will not go.

## Principle

Make the safe path easier to operate, while preserving the inconvenient parts
that are the security boundary.

Some friction in VMGA is load-bearing. A human approving out of band, a signing
key the broker never holds, evidence the agent cannot rewrite, and credentials
the agent cannot read are not rough edges to smooth away; they are the control.
Roadmap work reduces cognitive friction for operators. It does not reduce the
separation between an agent's reasoning and its authority.

## Direction: Operator Experience Without Boundary Collapse

VMGA is intended to become easier to run without weakening what it enforces.
Planned directions include:

- Single-file deployment configuration and a guided start path, so standing up a
  broker does not require assembling many flags by hand.
- A consolidated read-only status view covering broker health, deployment
  posture, pending proposals, and evidence state.
- Proposal review ergonomics: summaries, diffs, and risk flags rendered from
  the canonical proposal so an operator can review faster.
- A local operator console that acts only as a client of the VMGA broker.
- Documented patterns to help operators achieve credential isolation and
  hardened deployments.

These are directions, not shipped features, and not capabilities VMGA provides
on its own today. Credential isolation, in particular, remains a deployment
precondition that an operator establishes; VMGA does not provide it by itself.

## Boundary Rules For Operator Tooling

Any operator-experience work is constrained by these rules:

- A console or UI is a broker client only. It never becomes a second write path
  to Gmail, Workspace, state, or evidence.
- Proposal review is advisory presentation derived from the canonical proposal.
  The operator approves the actual proposal, not a rendering of it; what is
  shown must match what is signed.
- Signature mode keeps approver private keys outside both the console and the
  broker authority domain.
- Status and review surfaces are read-only; observing state and changing state
  stay separate.
- Operator tooling surfaces the deployment's posture plainly, so an advisory
  deployment is never mistaken for a hard-enforcement one.
- Any remote or mobile surface is operator-managed and is not part of VMGA's
  default hard-enforcement claims.

## Anti-Goals

VMGA will not:

- Claim prompt-injection prevention, DLP, host compromise protection,
  browser/session isolation, compliance certification, or security of
  Hermes/OpenClaw internals.
- Add auto-approval, "remember my approval," or approve-all-from-sender
  behavior.
- Hold approver signing keys in the broker.
- Add a second write path to mailbox side effects that bypasses VMGA.
- Present itself as a hosted service or imply a deployment is hard-enforcing
  when its preconditions are not met.

Convenience stops where authority separation begins.

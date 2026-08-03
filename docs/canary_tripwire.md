# Canary Tripwire

VMGA can detect an operator-planted, non-secret marker when that marker returns
through a broker proposal surface. This is a detection signal, not a bypass
prevention control.

## Boundary and Limits

The core tripwire scans only proposal `content`, `justification`, and
`parameters`. VMGA is not a filesystem, process, syscall, browser, or network
monitor. It does not observe a marker merely because an agent reads a decoy
file, and it cannot stop an agent from using a direct Gmail path.

A trip catches a confused or injected agent that brings the planted marker back
through VMGA. It does **not** catch a fully silent bypass in which an agent uses
a real credential directly against Gmail without proposing anything to VMGA.
A quiet, missing, or armed-but-untripped canary is absence of evidence, never
proof of isolation.

Consequently:

- A recorded trip forces `direct_gmail_bypass` to `fail` and posture to
  `advisory` through a durable, one-way state bit.
- A canary can never set that check to `pass` or contribute to
  `hard_enforcement_ready`.
- `pass` remains available only through the existing explicit operator
  no-bypass attestation with a reviewable evidence reference. A trip takes
  precedence over that attestation.
- VMGA makes no new claim of prompt-injection prevention, DLP, host-compromise
  protection, browser/session isolation, compliance certification, or security
  of Hermes/OpenClaw internals.

## Operator-Owned Registry

Start the broker with a dedicated YAML/JSON registry:

```yaml
canaries:
  - canary_id: <stable-operator-id>
    marker: <unique-non-secret-token>
    location_hint: <operator-description-of-decoy-placement>
```

```bash
vmga-broker \
  --canary-registry /path/outside/agent/canaries.yaml \
  --agent-root /path/to/agent/workspace \
  ...
```

The registry is separate from VMGA policy and proposal data. Keep it in an
operator-owned, agent-non-writable location. When `--agent-root` is supplied,
the broker refuses a registry path under that root, and posture reports registry
path isolation. Path checks are not a permissions proof: enforce ownership and
read/write permissions in the deployment supervisor and record them in operator
evidence. No active marker or reference registry is committed in this
repository.

Markers are unique non-secret tokens; do not use live credentials as markers.
`location_hint` helps the operator map a trip to a planted decoy but is not
written to trip evidence. A decoy containing the marker may be readable by the
agent for detection purposes, but the registry and one-way trip state must stay
outside agent authority.

## Evidence

Each matched registered canary emits at most one event per proposal:

```json
{
  "event_type": "vmga_canary_tripped",
  "severity": "CRITICAL",
  "canary_id": "<stable-operator-id>",
  "where_observed": "content|justification|parameters",
  "correlation_id": "<proposal-correlation-id>"
}
```

The event omits the marker, `location_hint`, and surrounding proposal payload.
Identifiers use the existing evidence redaction helper. Normal proposal evidence
continues to follow the redaction and retention rules in [Evidence
Notes](evidence.md).

The durable trip bit has no reset API. Retained trip evidence is also recognized
by posture after restart. Preserve the operator state database and evidence
ledger for investigation; do not clear either to make posture appear healthy.

## Optional Operator Decoy Beacon

An operator may point a fake credential at an operator-controlled decoy endpoint
that alerts on attempted authentication. This is the variant that can expose a
silent direct use of that decoy, because detection happens at the decoy endpoint
rather than on a VMGA proposal.

VMGA does not host a decoy endpoint and does not currently ingest beacon signals.
Deploy, authenticate, retain, and review beacon alerts as separate operator
evidence. A beacon does not prove prevention, and a quiet beacon is not proof of
isolation.

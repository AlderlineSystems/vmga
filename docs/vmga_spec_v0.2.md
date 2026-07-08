# Vesta Mail Governance Adapter (VMGA) v0.2
Alderline Systems
Classification: UNCLASSIFIED // TLP:WHITE  
Status: Reference Specification (TRL 4–5)  
Revised: 2026-04-14

> Historical reference specification. For the standalone `vmga` package's
> current implementation and deployment claim boundaries, see `README.md` and
> `docs/deployment_runbook.md`. The standalone ledger is append-only JSONL, not
> hash-chained, and credential isolation is a deployment precondition rather
> than something the package can enforce by itself.
>
> v0.3.0 extends this v0.2 boundary with implemented asymmetric Ed25519
> approval signatures and a keyed, hash-chained evidence ledger. See
> `docs/approval_signing_design.md` for out-of-domain approval signing and
> `docs/evidence_integrity_design.md` for Tier-1 evidence integrity. Do not stop
> at the v0.2 append-only JSONL / HMAC approval boundaries when reviewing the
> current codebase.

---

## 1. Purpose

VMGA is a **domain-specific governance extension** of the Vesta Agent Runtime Governance framework. It mediates all agent interaction with Gmail, adding email-specific policy enforcement while leveraging the core Vesta control plane for execution gating, audit logging, and circuit breaking.

Under the deployment preconditions in `docs/deployment_runbook.md`, VMGA is
designed so that:

- Untrusted email content does not become mailbox authority.
- Agents propose actions but cannot directly execute mailbox-modifying
  operations.
- Kinetic actions (send, draft, forward, etc.) pass through approval workflow.
- Gmail credentials are isolated from the agent runtime by deployment controls.
- Proposals, decisions, approvals, and executions are recorded as evidence.

---

## 2. Architecture

VMGA extends the Vesta governance stack:

```
[Untrusted Email Content]
          ↓
       [Agent]
          ↓
 [VMGA Gmail Adapter]  ←── Domain-specific policy + content analysis
          ↓
 [Vesta Core Governance]  ←── Tool allowlists, circuit breakers, ledger
          ↓
     [Gmail API]
          ↓
 [Vesta Audit Ledger]  ←── Append-only evidence
```

### 2.1 Integration Points

**With Hermes:**
- VMGA implements Hermes tool interface (`google-workspace` skill replacement)
- Credentials held by VMGA, not exposed to agent
- Tool calls route through `vmga.propose_action()` → Vesta execution gate

**With OpenClaw:**
- VMGA registers as plugin gate in OpenClaw gateway config
- Intercepts Gmail tool invocations at runtime boundary
- Produces Vesta-standard ledger entries

---

## 3. Core Invariants

> The agent may reason freely, but it may not act freely on the mailbox.

All Gmail side effects MUST pass through VMGA's separate control plane.

---

## 4. Action Classification

### 4.1 Non-Kinetic Actions (Informational)

No mailbox modification. Generally allowed with logging.

| Action | Description |
|--------|-------------|
| `read` | Retrieve message content |
| `summarize` | Generate summary of thread |
| `classify` | Categorize (invoice, spam, etc.) |
| `extract_entities` | Extract dates, names, amounts |
| `recommend_draft` | Suggest draft text (no creation) |

### 4.2 Kinetic Actions (State-Modifying)

Modify mailbox state. Require policy evaluation + potential approval.

| Action | Description |
|--------|-------------|
| `create_draft` | Create draft message |
| `send` | Send email |
| `forward` | Forward message |
| `archive` | Archive message |
| `delete` | Delete message |
| `apply_label` | Apply Gmail label |
| `download_attachment` | Download attachment |
| `mark_read` | Mark as read/unread |
| `move` | Move to folder |

---

## 5. Governance States

VMGA uses Vesta's four-state model with Gmail-specific criteria:

### 5.1 ALLOW

**Criteria:**
- Non-kinetic action class
- Risk score within tolerance
- No policy deny rules triggered

**Effect:** Execute without approval.

### 5.2 REVIEW_REQUIRED

**Criteria:**
- Kinetic action (default)
- External recipient detected
- High-risk content flags (payment, urgency, credentials)
- Draft creation with sensitive content

**Effect:** Queue for human approval. No execution until approval verified.

### 5.3 DENY

**Criteria:**
- Baseline deny category (financial, credentials, bulk operations)
- External domain restriction violated
- Action not in allowlist
- Proposal schema invalid

**Effect:** No execution. Log denial.

### 5.4 LOCKDOWN

**Criteria:**
- Repeated denied attempts
- Proposal hash mismatch (mutation detected)
- Approval spoofing attempt
- Bypass attempt detected

**Effect:** Suspend all kinetic mailbox actions. Require manual reset.

---

## 6. Content Risk Analysis

VMGA analyzes email content for risk flags:

| Flag | Trigger |
|------|---------|
| `payment_mention` | "invoice", "wire transfer", "payment" |
| `urgency_language` | "urgent", "immediate", "asap" |
| `credential_request` | "password", "login", "verify account" |
| `external_recipient` | Domain not in internal list |
| `unknown_sender` | Sender domain not recognized |
| `secrecy_instructions` | "confidential", "do not share" |
| `legal_threat` | "lawsuit", "legal action", "attorney" |

Risk flags inform policy decisions but do not by themselves deny actions—policy rules determine enforcement.

---

## 7. Proposal Contract

All Gmail actions MUST be submitted as structured proposals.

### 7.1 Required Fields

```json
{
  "proposal_id": "vmga_<hash>",
  "action": "create_draft",
  "actor_id": "agent_123",
  "thread_id": "thread_abc",
  "message_ids": ["msg_1", "msg_2"],
  "content": "Draft body text",
  "recipients": ["to@example.com"],
  "attachment_ids": [],
  "justification": "Responding to client inquiry",
  "requested_at": "2026-04-14T10:00:00Z"
}
```

### 7.2 Canonicalization

Proposals are serialized deterministically for hashing:
- JSON with sorted keys
- No whitespace variation
- Array elements sorted

### 7.3 Proposal Hash

SHA-256 of canonical JSON. Used for:
- Approval binding (approve exactly this proposal)
- Integrity verification (detect mutation)
- Evidence correlation

---

## 8. Approval Workflow

### 8.1 Out-of-Band Requirement

Approval MUST occur through channel agent cannot control:
- Webhook/API call from separate authenticated service
- Mobile push approval
- Separate admin console

Unacceptable: Terminal prompt in agent session, file-based approval readable by agent.

### 8.2 Approval Binding

Approval references exact proposal hash:

```json
{
  "proposal_id": "prop_abc",
  "proposal_hash": "sha256:def123...",
  "approver_id": "operator_1",
  "approved_at": "2026-04-14T10:05:00Z",
  "expires_at": "2026-04-14T11:05:00Z"
}
```

Execution gate verifies hash match before action.

### 8.3 One Approval, One Action

Approvals are single-use and time-bounded. No blanket approvals for action classes.

---

## 9. Profiles

### 9.1 Profile A: Observe Only

```yaml
profile: observe_only
allowed_actions: [read, summarize, classify, extract_entities, recommend_draft]
denied_actions: [create_draft, send, forward, archive, delete, apply_label, download_attachment]
```

**Use case:** Inbox triage, suspicious message review, scheduling extraction.

### 9.2 Profile B: Draft Assist

```yaml
profile: draft_assist
allowed_actions: [read, summarize, classify, extract_entities, recommend_draft, create_draft]
approval_required:
  create_draft: true
denied_actions: [send, forward, delete, download_attachment]
```

**Use case:** Reply preparation with human review before sending.

### 9.3 Profile C: Scoped Execution

```yaml
profile: scoped_execution
allowed_actions: [read, summarize, classify, draft_create, label_apply, archive]
label_allowlist: ["Priority", "Handled", "Waiting"]
auto_archive_rules:
  - sender_domain: "notifications.github.com"
    age_days: 7
```

**Use case:** Constrained productivity workflows with bounded autonomy.

---

## 10. Evidence Ledger

VMGA produces Vesta-standard audit ledger entries with Gmail-specific extensions:

```json
{
  "schema_version": "0.1",
  "event_type": "vmga_proposal_received",
  "timestamp": "2026-04-14T10:00:00Z",
  "proposal_id": "prop_abc123",
  "proposal_hash": "sha256:def456...",
  "session_id": "session_xyz",
  "actor_id": "agent_1",
  "action": "create_draft",
  "action_class": "kinetic",
  "vmga_profile": "draft_assist",
  "policy_state": "REVIEW_REQUIRED",
  "vesta_rule_id": "vmga_kinetic_approval_required",
  "risk_score": 2,
  "risk_flags": {
    "payment_mention": true,
    "external_recipient": true
  },
  "sender_domain": "client.com",
  "recipient_domains": ["company.com"],
  "attachment_count": 0,
  "previous_hash": "sha256:abc...",
  "integrity": "sha256:xyz..."
}
```

---

## 11. Implementation Structure

```
extensions/vmga/
├── README.md                      # This overview
├── vmga_adapter.py              # Core adapter implementation
├── policies/
│   ├── observe_only.yaml         # Profile A
│   ├── draft_assist.yaml         # Profile B
│   └── scoped_execution.yaml     # Profile C (template)
├── docs/
│   ├── vmga_spec_v0.2.md         # Full specification
│   ├── integration.md            # Hermes/OpenClaw setup
│   ├── threat_model.md           # Gmail-specific threats
│   └── deployment_runbook.md     # Bypass closure requirements
└── tests/
    └── test_vmga_adapter.py      # Unit tests
```

---

## 12. Limitations

- **Prompt injection:** VMGA does not prevent malicious content from reaching the agent for reasoning. It prevents that content from directly causing mailbox actions.
- **Host security:** VMGA assumes the underlying Vesta runtime provides process isolation. If the agent can access Gmail tokens outside VMGA, enforcement is bypassed.
- **Content analysis:** Risk flags are keyword-based heuristics, not NLP classification.
- **Approval UX:** No built-in approval console provided—integrators must build out-of-band approval channel.
- **No DLP:** VMGA is not a data loss prevention system.

---

## 13. Future Extensions

- Sender trust registry with reputation scoring
- Attachment sandbox/detonation workflow
- Hardware-backed approval (YubiKey, TouchID)
- Multi-mailbox federation
- Cryptographic ledger signing

---

**END OF SPECIFICATION**

"""VMGA (Vesta Mail Governance Adapter) — Gmail-specific governance extension.

This adapter wraps the core Vesta governance engine to provide email-domain-specific
policy enforcement: action classification, content risk analysis, and proposal integrity.

SECURITY NOTE: This is a reference implementation (TRL 4-5). For production use:
- Store state behind a boundary the agent cannot write to
- Use proper database with transactions instead of JSON files
- Enable strict approval_token verification (no dev mode)
- Ensure ledger failures trigger hard denies for kinetic actions
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import base64
import secrets
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_ssh_public_key

from .canary import CanaryMarker, find_canary_matches, validate_canary_registry
from .evidence_integrity import (
    EvidenceCheckpoint,
    EvidenceHMACConfig,
    add_integrity_metadata,
    canonical_json_line,
    load_segmented_events,
    recover_one_ahead,
)
from .models import ExecutionRequestEnvelope, PolicyDecision
from .redaction import redact_text


class ActionClass(Enum):
    """Gmail action classification per VMGA spec."""
    NON_KINETIC = auto()  # read, summarize, classify (no mailbox changes)
    KINETIC = auto()      # draft, send, forward, archive (modifies state)


class GmailAction(Enum):
    """Gmail-specific actions governed by VMGA."""
    # Non-kinetic
    READ = "read"
    SUMMARIZE = "summarize"
    CLASSIFY = "classify"
    EXTRACT_ENTITIES = "extract_entities"
    RECOMMEND_DRAFT = "recommend_draft"  # Returns text only, no creation

    # Kinetic
    CREATE_DRAFT = "create_draft"
    SEND = "send"
    FORWARD = "forward"
    ARCHIVE = "archive"
    DELETE = "delete"
    APPLY_LABEL = "apply_label"
    DOWNLOAD_ATTACHMENT = "download_attachment"
    MARK_READ = "mark_read"
    MOVE = "move"

    @classmethod
    def from_string(cls, action_str: str) -> Optional["GmailAction"]:
        """Parse action string to enum, returning None for invalid actions."""
        try:
            return cls(action_str.lower())
        except ValueError:
            return None


@dataclass(frozen=True)
class VMGAProposal:
    """Canonical proposal structure for Gmail actions.

    Immutable and deterministic for hash-based integrity checks.
    """
    proposal_id: str
    action: GmailAction
    actor_id: str
    thread_id: Optional[str] = None
    message_ids: List[str] = field(default_factory=list)
    content: Optional[str] = None  # Draft content, if applicable
    recipients: List[str] = field(default_factory=list)
    attachment_ids: List[str] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)
    justification: str = ""
    requested_at: str = ""

    def canonical_json(self) -> str:
        """Deterministic serialization for hashing."""
        data = {
            "proposal_id": self.proposal_id,
            "action": self.action.value,
            "actor_id": self.actor_id,
            "thread_id": self.thread_id,
            "message_ids": sorted(self.message_ids),
            "content": self.content,
            "recipients": sorted(self.recipients),
            "attachment_ids": sorted(self.attachment_ids),
            "parameters": self.parameters,
            "justification": self.justification,
            "requested_at": self.requested_at,
        }
        return json.dumps(data, sort_keys=True, separators=(',', ':'))

    def compute_hash(self) -> str:
        """SHA-256 hash of canonical serialization."""
        return f"sha256:{hashlib.sha256(self.canonical_json().encode()).hexdigest()}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "proposal_id": self.proposal_id,
            "action": self.action.value,
            "actor_id": self.actor_id,
            "thread_id": self.thread_id,
            "message_ids": self.message_ids,
            "content": self.content,
            "recipients": self.recipients,
            "attachment_ids": self.attachment_ids,
            "parameters": self.parameters,
            "justification": self.justification,
            "requested_at": self.requested_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VMGAProposal":
        """Create from dictionary (e.g., loaded from state store)."""
        return cls(
            proposal_id=data["proposal_id"],
            action=GmailAction(data["action"]),
            actor_id=data["actor_id"],
            thread_id=data.get("thread_id"),
            message_ids=data.get("message_ids", []),
            content=data.get("content"),
            recipients=data.get("recipients", []),
            attachment_ids=data.get("attachment_ids", []),
            parameters=data.get("parameters", {}),
            justification=data.get("justification", ""),
            requested_at=data.get("requested_at", ""),
        )


@dataclass
class ContentRisk:
    """Risk flags extracted from email content analysis."""
    payment_mention: bool = False
    urgency_language: bool = False
    credential_request: bool = False
    external_recipient: bool = False
    unknown_sender: bool = False
    suspicious_attachment: bool = False
    secrecy_instructions: bool = False
    legal_threat: bool = False
    mfa_recovery: bool = False
    bulk_operation: bool = False

    @property
    def score(self) -> int:
        return sum([
            self.payment_mention, self.urgency_language, self.credential_request,
            self.external_recipient, self.unknown_sender, self.suspicious_attachment,
            self.secrecy_instructions, self.legal_threat, self.mfa_recovery, self.bulk_operation,
        ])

    def to_dict(self) -> Dict[str, bool]:
        return {
            "payment_mention": self.payment_mention, "urgency_language": self.urgency_language,
            "credential_request": self.credential_request, "external_recipient": self.external_recipient,
            "unknown_sender": self.unknown_sender, "suspicious_attachment": self.suspicious_attachment,
            "secrecy_instructions": self.secrecy_instructions, "legal_threat": self.legal_threat,
            "mfa_recovery": self.mfa_recovery, "bulk_operation": self.bulk_operation,
        }


@dataclass
class ApprovalRecord:
    """Durable approval record."""
    proposal_id: str
    proposal_hash: str
    approver_id: str
    approved_at: str
    expires_at: str
    used: bool = False
    approval_token_hash: str = ""  # Hash of token (token itself never stored)
    actor_id: str = ""
    action: str = ""
    thread_id: Optional[str] = None
    message_ids: List[str] = field(default_factory=list)
    recipients: List[str] = field(default_factory=list)
    attachment_ids: List[str] = field(default_factory=list)
    content: Optional[str] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    binding_hash: str = ""
    approval_auth: str = "hmac"
    signature_payload: Optional[Dict[str, Any]] = None
    signature: str = ""
    key_id: str = ""
    signature_version: str = ""
    approval_nonce: str = ""

    @staticmethod
    def compute_binding_hash(
        proposal_id: str, proposal_hash: str, approver_id: str, actor_id: str,
        action: str, thread_id: Optional[str], message_ids: List[str],
        recipients: List[str], expires_at: str, attachment_ids: Optional[List[str]] = None,
        content: Optional[str] = None, parameters: Optional[Dict[str, Any]] = None,
    ) -> str:
        data = {
            "proposal_id": proposal_id,
            "proposal_hash": proposal_hash,
            "approver_id": approver_id,
            "actor_id": actor_id,
            "action": action,
            "thread_id": thread_id,
            "message_ids": sorted(message_ids),
            "recipients": sorted(recipients),
            "attachment_ids": sorted(attachment_ids or []),
            "content": content,
            "parameters": parameters or {},
            "expires_at": expires_at,
        }
        payload = json.dumps(data, sort_keys=True, separators=(',', ':'))
        return f"sha256:{hashlib.sha256(payload.encode()).hexdigest()}"

    @classmethod
    def from_proposal(
        cls, proposal: VMGAProposal, proposal_hash: str, approver_id: str,
        approved_at: str, expires_at: str, approval_token_hash: str,
    ) -> "ApprovalRecord":
        binding_hash = cls.compute_binding_hash(
            proposal_id=proposal.proposal_id,
            proposal_hash=proposal_hash,
            approver_id=approver_id,
            actor_id=proposal.actor_id,
            action=proposal.action.value,
            thread_id=proposal.thread_id,
            message_ids=proposal.message_ids,
            recipients=proposal.recipients,
            attachment_ids=proposal.attachment_ids,
            content=proposal.content,
            parameters=proposal.parameters,
            expires_at=expires_at,
        )
        return cls(
            proposal_id=proposal.proposal_id,
            proposal_hash=proposal_hash,
            approver_id=approver_id,
            approved_at=approved_at,
            expires_at=expires_at,
            used=False,
            approval_token_hash=approval_token_hash,
            actor_id=proposal.actor_id,
            action=proposal.action.value,
            thread_id=proposal.thread_id,
            message_ids=list(proposal.message_ids),
            recipients=list(proposal.recipients),
            attachment_ids=list(proposal.attachment_ids),
            content=proposal.content,
            parameters=dict(proposal.parameters),
            binding_hash=binding_hash,
        )

    def expected_binding_hash(self) -> str:
        return self.compute_binding_hash(
            proposal_id=self.proposal_id,
            proposal_hash=self.proposal_hash,
            approver_id=self.approver_id,
            actor_id=self.actor_id,
            action=self.action,
            thread_id=self.thread_id,
            message_ids=self.message_ids,
            recipients=self.recipients,
            attachment_ids=self.attachment_ids,
            content=self.content,
            parameters=self.parameters,
            expires_at=self.expires_at,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proposal_id": self.proposal_id, "proposal_hash": self.proposal_hash,
            "approver_id": self.approver_id, "approved_at": self.approved_at,
            "expires_at": self.expires_at, "used": self.used,
            "approval_token_hash": self.approval_token_hash,
            "actor_id": self.actor_id, "action": self.action,
            "thread_id": self.thread_id, "message_ids": self.message_ids,
            "recipients": self.recipients, "attachment_ids": self.attachment_ids,
            "content": self.content, "parameters": self.parameters,
            "binding_hash": self.binding_hash,
            "approval_auth": self.approval_auth,
            "signature_payload": self.signature_payload,
            "signature": self.signature,
            "key_id": self.key_id,
            "signature_version": self.signature_version,
            "approval_nonce": self.approval_nonce,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ApprovalRecord":
        return cls(
            proposal_id=data["proposal_id"], proposal_hash=data["proposal_hash"],
            approver_id=data["approver_id"], approved_at=data["approved_at"],
            expires_at=data["expires_at"], used=data.get("used", False),
            approval_token_hash=data.get("approval_token_hash", ""),
            actor_id=data.get("actor_id", ""), action=data.get("action", ""),
            thread_id=data.get("thread_id"), message_ids=data.get("message_ids", []),
            recipients=data.get("recipients", []), attachment_ids=data.get("attachment_ids", []),
            content=data.get("content"), parameters=data.get("parameters", {}),
            binding_hash=data.get("binding_hash", ""),
            approval_auth=data.get("approval_auth", "hmac"),
            signature_payload=data.get("signature_payload"),
            signature=data.get("signature", ""),
            key_id=data.get("key_id", ""),
            signature_version=data.get("signature_version", ""),
            approval_nonce=data.get("approval_nonce", ""),
        )

    def to_execution_payload(self) -> Dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "proposal_hash": self.proposal_hash,
            "action": self.action,
            "actor_id": self.actor_id,
            "thread_id": self.thread_id,
            "message_ids": list(self.message_ids),
            "recipients": list(self.recipients),
            "attachment_ids": list(self.attachment_ids),
            "content": self.content,
            "parameters": dict(self.parameters),
        }


class VMGAPolicy:
    """Gmail-specific policy evaluation layer."""

    TOP_LEVEL_KEYS = {
        "vmga_version", "profile", "description", "allowed_actions", "denied_actions",
        "kinetic_requires_approval", "approval_required", "content_analysis",
        "high_risk_indicators", "domain_policy", "approval_workflow",
        "lockdown_threshold", "baseline_denies", "draft_policy", "label_allowlist",
        "ledger_required_for_kinetic", "proposal_ttl_seconds", "internal_domains",
        "external_domain_deny", "log_external_senders", "content_analysis_enabled",
        "enforce_risk_threshold", "max_risk_score_auto_allow",
    }
    NESTED_KEYS = {
        "approval_required": {"create_draft", "archive", "apply_label", "send", "forward", "delete", "download_attachment", "mark_read", "move"},
        "content_analysis": {"enabled", "enforce_risk_threshold", "max_risk_score_auto_allow"},
        "domain_policy": {"internal_domains", "external_domain_deny", "log_external_senders"},
        "approval_workflow": {"expiration", "approver_allowlist"},
        "baseline_denies": {"financial_instructions", "credential_transmission", "mfa_recovery_handling", "bulk_forwarding"},
        "draft_policy": {"max_length", "require_justification", "allow_external_recipients"},
    }
    VALID_RISK_INDICATORS = set(ContentRisk().__dict__.keys())

    def __init__(self, profile: str, rules: Dict[str, Any]):
        self.profile = profile
        self.raw_rules = rules
        self.validate_rules(rules)

        domain_policy = rules.get("domain_policy", {})
        self.internal_domains: Set[str] = set(
            domain_policy.get("internal_domains", rules.get("internal_domains", ["company.com"]))
        )
        self.external_domain_deny = domain_policy.get("external_domain_deny", rules.get("external_domain_deny", True))
        self.log_external_senders = domain_policy.get("log_external_senders", rules.get("log_external_senders", True))

        self.allowed_actions: Set[str] = set(rules.get("allowed_actions", []))
        self.denied_actions: Set[str] = set(rules.get("denied_actions", []))

        approval_required = rules.get("approval_required", {})
        self.approval_required_per_action: Dict[str, bool] = {
            "create_draft": approval_required.get("create_draft", True),
            "archive": approval_required.get("archive", True),
            "apply_label": approval_required.get("apply_label", True),
            "send": approval_required.get("send", True),
            "forward": approval_required.get("forward", True),
            "delete": approval_required.get("delete", True),
        }

        kinetic_policy = rules.get("kinetic_policy", {})
        self.kinetic_requires_approval = kinetic_policy.get("requires_approval", rules.get("kinetic_requires_approval", True))

        draft_policy = rules.get("draft_policy", {})
        self.draft_max_length = draft_policy.get("max_length", 5000)
        self.draft_require_justification = draft_policy.get("require_justification", True)
        self.draft_allow_external_recipients = draft_policy.get("allow_external_recipients", False)

        self.label_allowlist: Set[str] = set(rules.get("label_allowlist", []))

        approval_workflow = rules.get("approval_workflow", {})
        self.approval_expiry_seconds = self._parse_duration(approval_workflow.get("expiration", "3600"))
        self.approver_allowlist: Set[str] = set(approval_workflow.get("approver_allowlist", []))

        content_analysis = rules.get("content_analysis", {})
        self.content_analysis_enabled = content_analysis.get("enabled", rules.get("content_analysis_enabled", True))
        self.enforce_risk_threshold = content_analysis.get("enforce_risk_threshold", rules.get("enforce_risk_threshold", False))
        self.max_risk_score_auto_allow = content_analysis.get("max_risk_score_auto_allow", rules.get("max_risk_score_auto_allow", 0))

        self.high_risk_indicators: Set[str] = set(rules.get("high_risk_indicators", []))

        baseline_denies = rules.get("baseline_denies", {})
        self.baseline_financial = baseline_denies.get("financial_instructions", True)
        self.baseline_credential = baseline_denies.get("credential_transmission", True)
        self.baseline_mfa = baseline_denies.get("mfa_recovery_handling", True)
        self.baseline_bulk = baseline_denies.get("bulk_forwarding", True)

        self.lockdown_threshold = rules.get("lockdown_threshold", 5)

    @classmethod
    def validate_rules(cls, rules: Dict[str, Any]) -> None:
        """Reject ambiguous policy fields before runtime evaluation.

        VMGA policy is intentionally small and deny-by-default. Unknown fields are
        more dangerous than inconvenient because they can make reviewers believe a
        control is active when the adapter ignores it.
        """
        if not isinstance(rules, dict):
            raise ValueError("VMGA policy rules must be a mapping")

        unknown = set(rules) - cls.TOP_LEVEL_KEYS
        if unknown:
            raise ValueError(f"Unknown VMGA policy field(s): {', '.join(sorted(unknown))}")

        for key, allowed_keys in cls.NESTED_KEYS.items():
            value = rules.get(key)
            if value is None:
                continue
            if not isinstance(value, dict):
                raise ValueError(f"VMGA policy field '{key}' must be a mapping")
            nested_unknown = set(value) - allowed_keys
            if nested_unknown:
                raise ValueError(f"Unknown VMGA policy field(s) under '{key}': {', '.join(sorted(nested_unknown))}")

        for list_key in ("allowed_actions", "denied_actions"):
            actions = rules.get(list_key, [])
            if not isinstance(actions, list) or not all(isinstance(item, str) for item in actions):
                raise ValueError(f"VMGA policy field '{list_key}' must be a list of action strings")
            invalid_actions = [action for action in actions if GmailAction.from_string(action) is None]
            if invalid_actions:
                raise ValueError(f"Unknown VMGA action(s) in '{list_key}': {', '.join(sorted(invalid_actions))}")

        indicators = rules.get("high_risk_indicators", [])
        if not isinstance(indicators, list) or not all(isinstance(item, str) for item in indicators):
            raise ValueError("VMGA policy field 'high_risk_indicators' must be a list of risk indicator strings")
        invalid_indicators = [item for item in indicators if item not in cls.VALID_RISK_INDICATORS]
        if invalid_indicators:
            raise ValueError(f"Unknown VMGA risk indicator(s): {', '.join(sorted(invalid_indicators))}")

    @staticmethod
    def _decision(allowed: bool, reason: str, rule_id: str, error_code: Optional[str] = None) -> PolicyDecision:
        return PolicyDecision(allowed=allowed, reason=reason, rule_id=rule_id, error_code=error_code or rule_id)

    def _parse_duration(self, value: Any) -> int:
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            if value.endswith('h'):
                return int(value[:-1]) * 3600
            if value.endswith('m'):
                return int(value[:-1]) * 60
            return int(value)
        return 3600

    def classify_action(self, action: GmailAction) -> ActionClass:
        non_kinetic = {GmailAction.READ, GmailAction.SUMMARIZE, GmailAction.CLASSIFY,
                      GmailAction.EXTRACT_ENTITIES, GmailAction.RECOMMEND_DRAFT}
        return ActionClass.NON_KINETIC if action in non_kinetic else ActionClass.KINETIC

    def evaluate_content_risk(self, content: str, sender: str, recipients: List[str]) -> ContentRisk:
        content_lower = content.lower() if content else ""
        risk = ContentRisk()

        risk.payment_mention = any(term in content_lower for term in [
            "payment", "invoice", "wire transfer", "bank account", "routing number",
            "swift", "iban", "sort code", "ach", "deposit"
        ])
        risk.urgency_language = any(term in content_lower for term in [
            "urgent", "immediate", "asap", "deadline", "expires", "action required",
            "time sensitive", "respond immediately", "within 24 hours"
        ])
        risk.credential_request = any(term in content_lower for term in [
            "password", "login", "credentials", "reset", "verify your account",
            "confirm your identity", "secure your account", "ssn", "social security"
        ])
        risk.mfa_recovery = any(term in content_lower for term in [
            "mfa", "two-factor", "2fa", "recovery code", "backup code",
            "authentication code", "security code"
        ])
        risk.secrecy_instructions = any(term in content_lower for term in [
            "confidential", "do not share", "between us", "don't forward",
            "strictly confidential", "privileged information", "internal only"
        ])
        risk.legal_threat = any(term in content_lower for term in [
            "lawsuit", "legal action", "attorney", "compliance violation",
            "regulatory", "subpoena", "litigation", "gdpr violation"
        ])

        recipient_count = len(recipients) if recipients else 0
        risk.bulk_operation = recipient_count > 10

        sender_domain = sender.split("@")[-1] if "@" in sender else ""
        risk.unknown_sender = sender_domain not in self.internal_domains

        for recipient in recipients:
            recip_domain = recipient.split("@")[-1] if "@" in recipient else ""
            if recip_domain not in self.internal_domains:
                risk.external_recipient = True
                break

        return risk

    def evaluate(self, proposal: VMGAProposal, content_risk: ContentRisk) -> PolicyDecision:
        action_class = self.classify_action(proposal.action)
        action_str = proposal.action.value

        if self.allowed_actions and action_str not in self.allowed_actions:
            return self._decision(False, f"Action '{action_str}' not in allowlist", "vmga_not_allowed")

        if action_str in self.denied_actions:
            return self._decision(False, f"Action '{action_str}' is explicitly denied", "vmga_explicit_deny")

        if self.baseline_credential and content_risk.credential_request:
            if proposal.action in [GmailAction.SEND, GmailAction.FORWARD, GmailAction.CREATE_DRAFT]:
                return self._decision(False, "Credential-related content denied by baseline policy", "vmga_baseline_credential_deny")

        if self.baseline_mfa and content_risk.mfa_recovery:
            if proposal.action in [GmailAction.SEND, GmailAction.FORWARD]:
                return self._decision(False, "MFA/recovery content denied by baseline policy", "vmga_baseline_mfa_deny")

        if self.baseline_bulk and content_risk.bulk_operation:
            if proposal.action in [GmailAction.SEND, GmailAction.FORWARD]:
                return self._decision(False, "Bulk operation denied by baseline policy", "vmga_baseline_bulk_deny")

        if self.baseline_financial and content_risk.payment_mention:
            if proposal.action in [GmailAction.SEND, GmailAction.FORWARD]:
                return self._decision(False, "Payment instructions denied by baseline policy", "vmga_baseline_financial_deny")

        if action_class == ActionClass.NON_KINETIC:
            return self._decision(True, "Non-kinetic action within policy", "vmga_non_kinetic_allow")

        if action_class == ActionClass.KINETIC:
            requires_approval = self.approval_required_per_action.get(action_str, self.kinetic_requires_approval)

            if proposal.action == GmailAction.CREATE_DRAFT:
                content = proposal.content or ""
                if len(content) > self.draft_max_length:
                    return self._decision(False, f"Draft exceeds maximum length ({self.draft_max_length} chars)", "vmga_draft_length_exceeded")

                if not self.draft_allow_external_recipients and content_risk.external_recipient:
                    return self._decision(False, "Draft creation with external recipients not allowed", "vmga_draft_external_recipient_deny")

                if requires_approval and self.draft_require_justification and not proposal.justification:
                    return self._decision(False, "Draft creation requires justification", "vmga_draft_justification_required")

            if content_risk.external_recipient and self.external_domain_deny:
                if proposal.action in [GmailAction.SEND, GmailAction.FORWARD]:
                    return self._decision(False, "External recipients denied for send/forward actions", "vmga_external_recipient_deny")

            high_risk_present = any(getattr(content_risk, indicator, False) for indicator in self.high_risk_indicators)

            if high_risk_present and requires_approval:
                return self._decision(False, "High-risk content indicators present", "vmga_high_risk_review_required")

            if requires_approval:
                return self._decision(False, "Kinetic action requires approval", "vmga_kinetic_approval_required")

            return self._decision(True, "Kinetic action auto-allowed", "vmga_kinetic_auto_allow")

        return self._decision(False, "Policy evaluation requires review", "vmga_review_required")


class VMGAStateStore:
    """Durable state storage with atomic writes and permission hardening."""

    def __init__(self, storage_path: Optional[str] = None):
        if storage_path is None:
            storage_path = os.path.expanduser("~/.vmga_state")
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True, mode=0o700)  # Owner-only

        self.pending_path = self.storage_path / "pending_proposals.json"
        self.approvals_path = self.storage_path / "approvals.json"
        self.evidence_head_path = self.storage_path / "evidence_head.json"
        self._set_permissions()

    def _set_permissions(self) -> None:
        """Ensure files have restrictive permissions (0o600)."""
        try:
            # Set directory to 0o700 (owner only)
            os.chmod(self.storage_path, 0o700)

            # Set existing files to 0o600
            rate_limit_path = self.storage_path / "rate_limit_state.json"
            nonce_path = self.storage_path / "approval_nonces.json"
            canary_path = self.storage_path / "canary_trip_state.json"
            for path in [self.pending_path, self.approvals_path, rate_limit_path, nonce_path, self.evidence_head_path, canary_path]:
                if path.exists():
                    os.chmod(path, 0o600)
        except OSError:
            pass  # May not have permission to change

    def save_rate_limit_state(self, failed_attempts: Dict[str, Dict[str, Any]]) -> None:
        """Persist rate limiting state to disk.

        Format: {attempt_key: {count, first_attempt, last_attempt}}
        """
        # Convert to serializable format
        data = {}
        for key, info in failed_attempts.items():
            data[key] = {
                "count": info["count"],
                "first_attempt": info["first_attempt"],
                "last_attempt": datetime.now(timezone.utc).isoformat(),
            }
        rate_limit_path = self.storage_path / "rate_limit_state.json"
        self._atomic_write_json(rate_limit_path, data)

    def load_rate_limit_state(self, lockout_duration_seconds: int = 3600) -> Dict[str, Dict[str, Any]]:
        """Load rate limiting state, filtering expired lockouts.

        Returns: {attempt_key: {count, first_attempt}} for active lockouts only.
        """
        rate_limit_path = self.storage_path / "rate_limit_state.json"
        if not rate_limit_path.exists():
            return {}
        try:
            with open(rate_limit_path, 'r') as f:
                data = json.load(f)

            now = datetime.now(timezone.utc)
            active = {}
            for key, info in data.items():
                try:
                    first_attempt = datetime.fromisoformat(info["first_attempt"])
                    # Only keep if lockout period hasn't expired
                    if (now - first_attempt).total_seconds() < lockout_duration_seconds:
                        active[key] = {
                            "count": info["count"],
                            "first_attempt": info["first_attempt"],
                        }
                except (ValueError, TypeError):
                    # Invalid timestamp, skip
                    pass
            return active
        except (json.JSONDecodeError, KeyError, OSError):
            return {}

    def save_canary_trip_recorded(self) -> None:
        """Persist the one-way trip bit; there is intentionally no reset API."""
        self._atomic_write_json(
            self.storage_path / "canary_trip_state.json",
            {"canary_trip_recorded": True},
        )

    def load_canary_trip_recorded(self) -> bool:
        # File existence is the one-way bit. Its contents can never reset it.
        return (self.storage_path / "canary_trip_state.json").exists()

    def save_approval_nonce_state(self, used_nonces: Dict[str, str]) -> None:
        nonce_path = self.storage_path / "approval_nonces.json"
        self._atomic_write_json(nonce_path, used_nonces)

    def load_approval_nonce_state(self, validity_horizon_seconds: int = 3900) -> Dict[str, str]:
        nonce_path = self.storage_path / "approval_nonces.json"
        if not nonce_path.exists():
            return {}
        try:
            data = json.loads(nonce_path.read_text(encoding="utf-8"))
            now = datetime.now(timezone.utc)
            active = {}
            for nonce_key, used_at in data.items():
                try:
                    used_dt = datetime.fromisoformat(used_at)
                    if (now - used_dt).total_seconds() <= validity_horizon_seconds:
                        active[str(nonce_key)] = str(used_at)
                except (TypeError, ValueError):
                    pass
            return active
        except (json.JSONDecodeError, OSError):
            return {}

    def _atomic_write_json(self, path: Path, data: Dict[str, Any]) -> None:
        """Write JSON atomically using temp file + rename + fsync."""
        # Write to temp file in same directory
        fd, temp_path = tempfile.mkstemp(dir=path.parent, suffix='.tmp')
        try:
            with os.fdopen(fd, 'w') as f:
                json.dump(data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())

            # Set restrictive permissions before making visible
            os.chmod(temp_path, 0o600)

            # Atomic rename
            os.replace(temp_path, path)

            # Sync directory to ensure rename is durable
            dir_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)

        except Exception:
            # Clean up temp file on failure
            try:
                os.unlink(temp_path)
            except OSError:
                pass
            raise

    def save_pending_proposals(self, proposals: Dict[str, VMGAProposal], proposal_ttl_seconds: int = 86400) -> None:
        """Persist pending proposals to disk with TTL filtering."""
        now = datetime.now(timezone.utc)
        # Filter expired proposals
        valid_proposals = {}
        for pid, prop in proposals.items():
            try:
                requested_at = datetime.fromisoformat(prop.requested_at)
                if (now - requested_at).total_seconds() < proposal_ttl_seconds:
                    valid_proposals[pid] = prop.to_dict()
            except (ValueError, TypeError):
                # Invalid timestamp, keep it (conservative)
                valid_proposals[pid] = prop.to_dict()
        self._atomic_write_json(self.pending_path, valid_proposals)

    def load_pending_proposals(self, proposal_ttl_seconds: int = 86400) -> Dict[str, VMGAProposal]:
        """Load pending proposals from disk with TTL filtering."""
        if not self.pending_path.exists():
            return {}
        try:
            with open(self.pending_path, 'r') as f:
                data = json.load(f)

            now = datetime.now(timezone.utc)
            valid = {}
            for pid, prop_data in data.items():
                try:
                    requested_at = datetime.fromisoformat(prop_data.get("requested_at", ""))
                    if (now - requested_at).total_seconds() < proposal_ttl_seconds:
                        valid[pid] = VMGAProposal.from_dict(prop_data)
                except (ValueError, TypeError):
                    # Invalid timestamp, keep it (conservative GC - don't delete what we can't parse)
                    valid[pid] = VMGAProposal.from_dict(prop_data)
            return valid
        except (json.JSONDecodeError, KeyError, OSError):
            return {}

    def save_approvals(self, approvals: Dict[str, ApprovalRecord]) -> None:
        """Persist approvals to disk."""
        data = {pid: app.to_dict() for pid, app in approvals.items()}
        self._atomic_write_json(self.approvals_path, data)

    def load_approvals(self) -> Dict[str, ApprovalRecord]:
        """Load approvals from disk."""
        if not self.approvals_path.exists():
            return {}
        try:
            with open(self.approvals_path, 'r') as f:
                data = json.load(f)
            return {pid: ApprovalRecord.from_dict(app_data) for pid, app_data in data.items()}
        except (json.JSONDecodeError, KeyError, OSError):
            return {}

    def save_lockdown_state(self, lockdown_active: bool, denial_counts: Dict[str, int]) -> None:
        """Persist lockdown state and denial counts."""
        data = {
            "lockdown_active": lockdown_active,
            "denial_counts": denial_counts,
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }
        lockdown_path = self.storage_path / "lockdown_state.json"
        self._atomic_write_json(lockdown_path, data)

    def load_lockdown_state(self) -> Tuple[bool, Dict[str, int], bool]:
        """Load lockdown state and denial counts. Returns (lockdown_active, denial_counts, corrupted)."""
        lockdown_path = self.storage_path / "lockdown_state.json"
        if not lockdown_path.exists():
            return False, {}, False
        try:
            with open(lockdown_path, 'r') as f:
                data = json.load(f)
            return data.get("lockdown_active", False), data.get("denial_counts", {}), False
        except (json.JSONDecodeError, KeyError, OSError):
            return False, {}, True  # Signal corruption

    def save_evidence_head(self, checkpoint: EvidenceCheckpoint) -> None:
        self._atomic_write_json(self.evidence_head_path, checkpoint.to_dict())

    def load_evidence_head(self) -> Optional[EvidenceCheckpoint]:
        if not self.evidence_head_path.exists():
            return None
        with open(self.evidence_head_path, "r", encoding="utf-8") as f:
            return EvidenceCheckpoint.from_dict(json.load(f))


    def load_all_state(self, proposal_ttl_seconds: int = 86400, fail_closed: bool = False, max_state_size_bytes: int = 10_000_000) -> Dict[str, Any]:
        """Load all state atomically with optional fail-closed semantics and size limits.

        If fail_closed=True and any state file is corrupted, returns empty state
        and triggers lockdown indicators.

        max_state_size_bytes: Maximum total state size (default 10MB) to prevent DoS.
        """
        # Check total state file sizes
        total_size = 0
        for path in [
            self.pending_path,
            self.approvals_path,
            self.storage_path / "lockdown_state.json",
            self.storage_path / "canary_trip_state.json",
        ]:
            if path.exists():
                total_size += path.stat().st_size

        if total_size > max_state_size_bytes:
            # State files too large - possible DoS attack
            import sys
            print(f"[VMGA CRITICAL] State files exceed size limit ({total_size} > {max_state_size_bytes} bytes)", file=sys.stderr)
            if fail_closed:
                return {
                    "pending_proposals": {},
                    "approvals": {},
                    "lockdown_active": True,
                    "denial_counts": {},
                    "canary_trip_recorded": self.load_canary_trip_recorded(),
                    "corrupted": True,
                }

        # Check for corruption in any file
        lockdown_active, denial_counts, lockdown_corrupted = self.load_lockdown_state()

        # Try to load other state (but catch corruption)
        pending_corrupted = False
        approvals_corrupted = False

        try:
            pending = self.load_pending_proposals(proposal_ttl_seconds)
        except Exception:
            pending = {}
            pending_corrupted = True

        try:
            approvals = self.load_approvals()
        except Exception:
            approvals = {}
            approvals_corrupted = True

        any_corrupted = lockdown_corrupted or pending_corrupted or approvals_corrupted

        if fail_closed and any_corrupted:
            # Fail closed: return empty state with lockdown indicator
            return {
                "pending_proposals": {},
                "approvals": {},
                "lockdown_active": True,  # Fail closed
                "denial_counts": {},
                "canary_trip_recorded": self.load_canary_trip_recorded(),
                "corrupted": True,
            }

        # Normal load (returns what we can, with lockdown from file if present)
        return {
            "pending_proposals": pending,
            "approvals": approvals,
            "lockdown_active": lockdown_active,  # Use loaded value (True if was locked)
            "denial_counts": denial_counts,
            "canary_trip_recorded": self.load_canary_trip_recorded(),
            "corrupted": any_corrupted,
        }


class VMGAGmailAdapter:
    """VMGA adapter with secure approval authentication and fail-closed semantics."""

    def __init__(
        self,
        vesta_adapter: Any,
        profile: str,
        policy_rules: Dict[str, Any],
        state_store: Optional[VMGAStateStore] = None,
        approval_secret: Optional[str] = None,
        strict_mode: bool = True,  # Default to secure mode
        fail_closed_on_corrupted_state: bool = False,  # Set True for production
        approval_auth: str = "hmac",
        approval_public_keys: Optional[Dict[str, List[Dict[str, str]]]] = None,
        canary_registry: Sequence[CanaryMarker] = (),
    ):
        self.vesta = vesta_adapter
        self.profile = profile
        self.vmga_policy = VMGAPolicy(profile, policy_rules)
        self.state_store = state_store or VMGAStateStore()
        self.strict_mode = strict_mode
        self.ledger_required_for_kinetic = policy_rules.get("ledger_required_for_kinetic", True)
        self.proposal_ttl_seconds = policy_rules.get("proposal_ttl_seconds", 86400)  # Default 24h
        self.fail_closed_on_corrupted_state = fail_closed_on_corrupted_state
        if approval_auth not in {"hmac", "signature"}:
            raise ValueError("approval_auth must be 'hmac' or 'signature'")
        self.approval_auth = approval_auth
        self.approval_public_keys = approval_public_keys or {}
        self.canary_registry = validate_canary_registry(canary_registry)

        # Load all state atomically (with optional fail-closed semantics)
        state = self.state_store.load_all_state(
            proposal_ttl_seconds=self.proposal_ttl_seconds,
            fail_closed=fail_closed_on_corrupted_state
        )
        self.pending_proposals: Dict[str, VMGAProposal] = state["pending_proposals"]
        self.approvals: Dict[str, ApprovalRecord] = state["approvals"]
        self.lockdown_active: bool = state["lockdown_active"]
        self.denial_counts: Dict[str, int] = state["denial_counts"]
        self.canary_trip_recorded = bool(state.get("canary_trip_recorded", False))

        # If state was corrupted and we failed closed, log it
        if state.get("corrupted") and fail_closed_on_corrupted_state:
            import sys
            print("[VMGA CRITICAL] State corruption detected - LOCKDOWN activated (fail-closed)", file=sys.stderr)

        # Rate limiting for bad token attempts: {proposal_id: {count, first_attempt}}
        self._failed_token_attempts: Dict[str, Dict[str, Any]] = self.state_store.load_rate_limit_state()
        self._used_approval_nonces: Dict[str, str] = self.state_store.load_approval_nonce_state(
            self.vmga_policy.approval_expiry_seconds + 300
        )
        self._max_token_attempts = 5
        self._lockout_duration_seconds = 3600  # 1 hour
        self._state_lock = threading.RLock()

        # Load or generate approval secret
        if approval_secret is None:
            approval_secret = os.environ.get("VMGA_APPROVAL_SECRET")
        if self.approval_auth == "hmac" and approval_secret is None and strict_mode:
            raise ValueError("VMGA_APPROVAL_SECRET must be set in strict_mode, or provide approval_secret")
        elif self.approval_auth == "hmac" and approval_secret is None:
            approval_secret = secrets.token_hex(32)  # Dev mode only
        self.approval_secret = approval_secret.encode() if approval_secret else None
        if self.approval_auth == "signature":
            self.signature_readiness = self._compute_signature_readiness()
        else:
            self.signature_readiness = {"state": "verified_intact", "reason": "configured"}

        self.evidence_hmac = EvidenceHMACConfig.from_env()
        if self.evidence_hmac is not None:
            self._recover_evidence_head_if_one_ahead()


    def _compute_signature_readiness(self) -> Dict[str, str]:
        """Report whether signature approval mode is operative, not merely declared.

        Operative means a keyring is loaded, every declared key parses as
        Ed25519, and at least one key is active. Anything less is
        cannot_verify and must never render as ready.
        """
        if not self.approval_public_keys:
            return {"state": "cannot_verify", "reason": "missing_approval_public_keys"}
        active_keys = 0
        for entries in self.approval_public_keys.values():
            for entry in entries:
                key_id = str(entry.get("key_id", "<missing key_id>"))
                if entry.get("algorithm") != "ed25519":
                    return {"state": "cannot_verify", "reason": f"unsupported_algorithm:{key_id}"}
                try:
                    self._load_ed25519_public_key(entry["public_key"])
                except (KeyError, ValueError, TypeError):
                    return {"state": "cannot_verify", "reason": f"unparseable_public_key:{key_id}"}
                if entry.get("status", "active") == "active":
                    active_keys += 1
        if active_keys == 0:
            return {"state": "cannot_verify", "reason": "no_active_keys"}
        return {"state": "verified_intact", "reason": "active_ed25519_keyring_loaded"}

    def _save_state(self) -> None:
        """Save all state including lockdown and TTL-filtered proposals."""
        self.state_store.save_pending_proposals(self.pending_proposals, self.proposal_ttl_seconds)
        self.state_store.save_approvals(self.approvals)
        self.state_store.save_lockdown_state(self.lockdown_active, self.denial_counts)
        self.state_store.save_approval_nonce_state(self._used_approval_nonces)

    @staticmethod
    def _proposal_correlation_id(proposal: Optional[VMGAProposal]) -> Optional[str]:
        if proposal is None:
            return None
        metadata = proposal.parameters.get("metadata")
        if isinstance(metadata, dict) and metadata.get("correlation_id"):
            return str(metadata["correlation_id"])
        if proposal.parameters.get("correlation_id"):
            return str(proposal.parameters["correlation_id"])
        return None

    @staticmethod
    def _parameters_correlation_id(parameters: Any) -> Optional[str]:
        if not isinstance(parameters, dict):
            return None
        metadata = parameters.get("metadata")
        if isinstance(metadata, dict) and metadata.get("correlation_id"):
            return str(metadata["correlation_id"])
        if parameters.get("correlation_id"):
            return str(parameters["correlation_id"])
        return None

    def _log_state_saved(self, proposal: Optional[VMGAProposal], operation: str, correlation_id: Optional[str] = None) -> bool:
        event = {
            "event_type": "vmga_state_saved",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "proposal_id": proposal.proposal_id if proposal else None,
            "proposal_hash": proposal.compute_hash() if proposal else None,
            "actor_id": proposal.actor_id if proposal else None,
            "operation": operation,
            "correlation_id": correlation_id or self._proposal_correlation_id(proposal),
            "vmga_profile": self.profile,
        }
        return self._write_to_ledger(event)

    def _load_evidence_head(self) -> Optional[EvidenceCheckpoint]:
        loader = getattr(self.state_store, "load_evidence_head", None)
        if loader is None:
            return None
        return loader()

    def _save_evidence_head(self, checkpoint: EvidenceCheckpoint) -> None:
        saver = getattr(self.state_store, "save_evidence_head", None)
        if saver is None:
            raise RuntimeError("state store does not support evidence integrity checkpoint")
        saver(checkpoint)

    def _recover_evidence_head_if_one_ahead(self) -> None:
        if not (hasattr(self.vesta, "audit_ledger") and hasattr(self.vesta.audit_ledger, "path")):
            return
        try:
            ledger_path = str(Path(self.vesta.audit_ledger.path))
            checkpoint = self._load_evidence_head()
            events = load_segmented_events(ledger_path)
            recovered = recover_one_ahead(
                events,
                checkpoint=checkpoint,
                keyring={self.evidence_hmac.key_id: self.evidence_hmac.key},
                ledger_path=ledger_path,
            )
            if recovered is not None:
                self._save_evidence_head(recovered)
        except Exception:
            return

    @staticmethod
    def approval_time_window(now: Optional[datetime] = None, *, window_seconds: int = 300) -> str:
        """Return the short-lived approval-token time window."""
        now = now or datetime.now(timezone.utc)
        epoch = int(now.timestamp())
        window_start = epoch - (epoch % window_seconds)
        return datetime.fromtimestamp(window_start, timezone.utc).strftime("%Y-%m-%d-%H-%M")

    def compute_approval_token(self, proposal_id: str, proposal_hash: str, approver_id: str, time_window: Optional[str] = None) -> str:
        """Compute HMAC token for approval (for out-of-band approval service).

        Includes time-window binding to prevent indefinite token replay.
        The time_window defaults to a five-minute UTC window.

        This method is for the external approval service to compute tokens.
        The adapter does NOT self-generate tokens in approve_proposal().
        """
        if self.approval_secret is None:
            raise RuntimeError("No approval_secret configured")

        if time_window is None:
            time_window = self.approval_time_window()

        message = f"{proposal_id}:{proposal_hash}:{approver_id}:{time_window}"
        return hmac.new(self.approval_secret, message.encode(), hashlib.sha256).hexdigest()

    @staticmethod
    def canonical_approval_signature_payload(payload: Dict[str, Any]) -> bytes:
        required = {
            "proposal_id",
            "proposal_hash",
            "approver_id",
            "time_window",
            "approval_nonce",
            "key_id",
            "signature_version",
        }
        if set(payload) != required:
            raise ValueError("approval signature payload has unexpected fields")
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def approval_signature_payload(
        self,
        proposal_id: str,
        approver_id: str,
        *,
        time_window: str,
        approval_nonce: str,
        key_id: str,
        signature_version: str = "vmga-approval-ed25519-v1",
    ) -> Dict[str, Any]:
        proposal = self.pending_proposals[proposal_id]
        return {
            "proposal_id": proposal_id,
            "proposal_hash": proposal.compute_hash(),
            "approver_id": approver_id,
            "time_window": time_window,
            "approval_nonce": approval_nonce,
            "key_id": key_id,
            "signature_version": signature_version,
        }

    @staticmethod
    def _nonce_key(approver_id: str, key_id: str, approval_nonce: str) -> str:
        return f"{approver_id}:{key_id}:{approval_nonce}"

    def _prune_approval_nonces(self, now: datetime) -> None:
        horizon = self.vmga_policy.approval_expiry_seconds + 300
        active: Dict[str, str] = {}
        for nonce_key, used_at in self._used_approval_nonces.items():
            try:
                if (now - datetime.fromisoformat(used_at)).total_seconds() <= horizon:
                    active[nonce_key] = used_at
            except ValueError:
                pass
        self._used_approval_nonces = active

    def _approval_key_entry(self, approver_id: str, key_id: str) -> Optional[Dict[str, str]]:
        for entry in self.approval_public_keys.get(approver_id, []):
            if entry.get("key_id") == key_id:
                return entry
        return None

    @staticmethod
    def _load_ed25519_public_key(public_key: str) -> Ed25519PublicKey:
        if public_key.startswith("ssh-ed25519 "):
            loaded = load_ssh_public_key(public_key.encode("utf-8"))
            if not isinstance(loaded, Ed25519PublicKey):
                raise ValueError("public key is not Ed25519")
            return loaded
        return Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key))

    def _verify_approval_signature(
        self,
        proposal_id: str,
        approver_id: str,
        *,
        signature: str,
        time_window: str,
        approval_nonce: str,
        key_id: str,
        signature_version: str,
    ) -> Tuple[bool, str, str, Optional[Dict[str, Any]]]:
        now = datetime.now(timezone.utc)
        self._prune_approval_nonces(now)
        if not self.approval_public_keys:
            return False, "Missing approval public keys in signature mode", "vmga_signature_keyring_missing", None
        entry = self._approval_key_entry(approver_id, key_id)
        if entry is None:
            return False, "Unknown approval key", "vmga_signature_key_unknown", None
        if entry.get("status", "active") != "active":
            return False, "Approval key is not active", "vmga_signature_key_inactive", None
        if entry.get("algorithm") != "ed25519" or signature_version != "vmga-approval-ed25519-v1":
            return False, "Approval signature algorithm mismatch", "vmga_signature_algorithm_mismatch", None
        if not approval_nonce or len(approval_nonce) < 16:
            return False, "Approval nonce is missing or too short", "vmga_signature_nonce_invalid", None
        if self._nonce_key(approver_id, key_id, approval_nonce) in self._used_approval_nonces:
            return False, "Approval nonce replay detected", "vmga_signature_nonce_replay", None
        try:
            window_dt = datetime.strptime(time_window, "%Y-%m-%d-%H-%M").replace(tzinfo=timezone.utc)
        except ValueError:
            return False, "Invalid approval time window", "vmga_signature_window_invalid", None
        if abs((now - window_dt).total_seconds()) > 600:
            return False, "Approval time window expired", "vmga_signature_expired", None
        try:
            payload = self.approval_signature_payload(
                proposal_id,
                approver_id,
                time_window=time_window,
                approval_nonce=approval_nonce,
                key_id=key_id,
                signature_version=signature_version,
            )
            public_key = self._load_ed25519_public_key(entry["public_key"])
            public_key.verify(base64.b64decode(signature), self.canonical_approval_signature_payload(payload))
        except (KeyError, ValueError, TypeError, InvalidSignature):
            return False, "Invalid approval signature", "vmga_signature_invalid", None
        return True, "Valid", "vmga_signature_valid", payload

    def _verify_approval_token(self, proposal_id: str, proposal_hash: str, approver_id: str, token: str) -> bool:
        """Verify HMAC token matches expected value for short-lived windows.

        Allows for clock skew by checking current and previous five-minute windows.
        """
        if self.approval_secret is None:
            return False  # Cannot verify without secret

        now = datetime.now(timezone.utc)

        for candidate in (now, now - timedelta(minutes=5)):
            window = self.approval_time_window(candidate)
            expected = self.compute_approval_token(proposal_id, proposal_hash, approver_id, window)
            if hmac.compare_digest(expected, token):
                return True

        return False

    def propose_action(
        self, action: str, actor_id: str, thread_id: Optional[str] = None,
        message_ids: Optional[List[str]] = None, content: Optional[str] = None,
        recipients: Optional[List[str]] = None, attachment_ids: Optional[List[str]] = None,
        parameters: Optional[Dict[str, Any]] = None, justification: str = "", sender: str = "",
    ) -> Dict[str, Any]:
        with self._state_lock:
            return self._propose_action_locked(
                action=action,
                actor_id=actor_id,
                thread_id=thread_id,
                message_ids=message_ids,
                content=content,
                recipients=recipients,
                attachment_ids=attachment_ids,
                parameters=parameters,
                justification=justification,
                sender=sender,
            )

    def _propose_action_locked(
        self, action: str, actor_id: str, thread_id: Optional[str] = None,
        message_ids: Optional[List[str]] = None, content: Optional[str] = None,
        recipients: Optional[List[str]] = None, attachment_ids: Optional[List[str]] = None,
        parameters: Optional[Dict[str, Any]] = None, justification: str = "", sender: str = "",
    ) -> Dict[str, Any]:
        self._detect_canary_markers(
            content=content,
            justification=justification,
            parameters=parameters,
        )
        gmail_action = GmailAction.from_string(action)
        if gmail_action is None:
            result = {
                "status": "DENY", "proposal_id": None, "proposal_hash": None,
                "reason": f"Invalid action '{action}'", "rule_id": "vmga_invalid_action",
                "error_code": "vmga_invalid_action",
                "action_class": None, "risk_score": 0, "risk_flags": [],
            }
            self._log_proposal_received(None, result["status"], None, ContentRisk(), result["rule_id"], result["reason"])
            return result

        if self.lockdown_active:
            result = {
                "status": "LOCKDOWN", "proposal_id": None, "proposal_hash": None,
                "reason": "VMGA is in lockdown state due to repeated violations",
                "rule_id": "vmga_lockdown_active", "action_class": None,
                "error_code": "vmga_lockdown_active",
                "risk_score": 0, "risk_flags": [],
            }
            self._log_proposal_received(None, result["status"], None, ContentRisk(), result["rule_id"], result["reason"])
            return result

        now = datetime.now(timezone.utc)
        proposal = VMGAProposal(
            proposal_id=f"vmga_{hashlib.sha256(f'{actor_id}{action}{thread_id}{now.isoformat()}'.encode()).hexdigest()[:16]}",
            action=gmail_action, actor_id=actor_id, thread_id=thread_id,
            message_ids=message_ids or [], content=content, recipients=recipients or [],
            attachment_ids=attachment_ids or [], parameters=parameters or {}, justification=justification,
            requested_at=now.isoformat(),
        )

        content_risk = self.vmga_policy.evaluate_content_risk(content or "", sender, recipients or [])
        decision = self.vmga_policy.evaluate(proposal, content_risk)

        is_kinetic = self.vmga_policy.classify_action(proposal.action) == ActionClass.KINETIC

        if decision.allowed:
            status = "ALLOW"
        elif decision.rule_id in ["vmga_kinetic_approval_required", "vmga_high_risk_review_required", "vmga_draft_justification_required"]:
            status = "REVIEW_REQUIRED"
            self.pending_proposals[proposal.proposal_id] = proposal
            if not self._save_state_with_fail_closed(is_kinetic, proposal=proposal, operation="proposal_pending"):
                # State save failed for kinetic action
                return {
                    "status": "DENY", "proposal_id": proposal.proposal_id,
                    "proposal_hash": proposal.compute_hash(),
                    "reason": "Failed to persist proposal state (fail-closed)",
                    "rule_id": "vmga_state_persist_failed",
                    "error_code": "vmga_state_persist_failed",
                    "action_class": "kinetic" if is_kinetic else "non_kinetic",
                    "risk_score": content_risk.score,
                    "risk_flags": [k for k, v in content_risk.__dict__.items() if v],
                }
        else:
            status = "DENY"
            self.denial_counts[actor_id] = self.denial_counts.get(actor_id, 0) + 1
            if self.denial_counts[actor_id] >= self.vmga_policy.lockdown_threshold:
                self.lockdown_active = True
                status = "LOCKDOWN"
                self._log_lockdown_event(actor_id, proposal)
                self._save_state()  # Persist lockdown state immediately

        # Log proposal - fail closed for kinetic if ledger fails
        log_success = self._log_proposal_received(proposal, status, decision, content_risk)
        if log_success:
            self._log_proposal_pressure_signals(proposal, status, decision, content_risk)
        if is_kinetic and self.ledger_required_for_kinetic and not log_success:
            # Trigger lockdown on ledger failure for kinetic actions
            self.lockdown_active = True
            status = "LOCKDOWN"
            self._log_lockdown_event(actor_id, proposal)
            return {
                "status": "LOCKDOWN", "proposal_id": proposal.proposal_id,
                "proposal_hash": proposal.compute_hash(),
                "reason": "Ledger write failure triggered lockdown (fail-closed)",
                "rule_id": "vmga_ledger_failure_lockdown",
                "error_code": "vmga_ledger_failure_lockdown",
                "action_class": "kinetic", "risk_score": content_risk.score,
                "risk_flags": [k for k, v in content_risk.__dict__.items() if v],
            }

        return {
            "status": status, "proposal_id": proposal.proposal_id,
            "proposal_hash": proposal.compute_hash(), "reason": decision.reason,
            "rule_id": decision.rule_id,
            "error_code": None if decision.allowed else decision.error_code,
            "action_class": "kinetic" if is_kinetic else "non_kinetic",
            "risk_score": content_risk.score,
            "risk_flags": [k for k, v in content_risk.__dict__.items() if v],
        }

    def _save_state_with_fail_closed(
        self,
        is_kinetic: bool,
        proposal: Optional[VMGAProposal] = None,
        operation: str = "state_save",
        correlation_id: Optional[str] = None,
    ) -> bool:
        """Save state, return False on failure for kinetic actions."""
        try:
            self._save_state()
            self._log_state_saved(proposal, operation, correlation_id=correlation_id)
            return True
        except Exception as e:
            if is_kinetic:
                # Log the failure but don't expose details
                import sys
                print(f"[VMGA ERROR] State persist failed for kinetic action", file=sys.stderr)
                return False
            return True  # Non-kinetic can tolerate state save failures

    def approve_proposal(
        self,
        proposal_id: str,
        approver_id: str,
        approval_token: Optional[str] = None,
        *,
        signature: str = "",
        time_window: str = "",
        approval_nonce: str = "",
        key_id: str = "",
        signature_version: str = "vmga-approval-ed25519-v1",
    ) -> Dict[str, Any]:
        """Approve a pending proposal with mandatory token verification.

        HMAC mode requires approval_token. Signature mode requires a detached
        Ed25519 signature plus the signed payload metadata.
        """
        if self.approval_auth == "hmac" and approval_token is None:
            raise TypeError("approval_token is required in HMAC approval mode")
        with self._state_lock:
            return self._approve_proposal_locked(
                proposal_id,
                approver_id,
                approval_token or "",
                signature=signature,
                time_window=time_window,
                approval_nonce=approval_nonce,
                key_id=key_id,
                signature_version=signature_version,
            )

    def _approve_proposal_locked(
        self,
        proposal_id: str,
        approver_id: str,
        approval_token: str,
        *,
        signature: str = "",
        time_window: str = "",
        approval_nonce: str = "",
        key_id: str = "",
        signature_version: str = "vmga-approval-ed25519-v1",
    ) -> Dict[str, Any]:
        """Approve a pending proposal while holding the adapter state lock."""
        # Check approver allowlist if configured
        if self.vmga_policy.approver_allowlist and approver_id not in self.vmga_policy.approver_allowlist:
            return {"status": "DENY", "error": "Approver not in allowlist", "error_code": "vmga_approver_unauthorized"}

        if proposal_id not in self.pending_proposals:
            return {"status": "ERROR", "error": "Proposal not found or expired", "error_code": "vmga_proposal_not_found"}

        proposal = self.pending_proposals[proposal_id]
        proposal_hash = proposal.compute_hash()

        token_hash = ""
        signature_payload = None
        if self.approval_auth == "signature":
            ok, error, error_code, signature_payload = self._verify_approval_signature(
                proposal_id,
                approver_id,
                signature=signature,
                time_window=time_window,
                approval_nonce=approval_nonce,
                key_id=key_id,
                signature_version=signature_version,
            )
            if not ok:
                return {"status": "DENY", "error": error, "error_code": error_code}
        else:
            # MANDATORY: Verify approval token (no self-generation)
            if not self._verify_approval_token(proposal_id, proposal_hash, approver_id, approval_token):
                return {"status": "DENY", "error": "Invalid approval token", "error_code": "vmga_approval_token_invalid"}
            token_hash = hashlib.sha256(approval_token.encode()).hexdigest()[:32]

        # Calculate expiration
        approved_at = datetime.now(timezone.utc)
        expires_at = approved_at + timedelta(seconds=self.vmga_policy.approval_expiry_seconds)

        # Store approval record (store hash of HMAC token, never the token itself).
        record = ApprovalRecord.from_proposal(
            proposal=proposal, proposal_hash=proposal_hash, approver_id=approver_id,
            approved_at=approved_at.isoformat(), expires_at=expires_at.isoformat(),
            approval_token_hash=token_hash,
        )
        record.approval_auth = self.approval_auth
        if self.approval_auth == "signature":
            record.signature_payload = signature_payload
            record.signature = signature
            record.key_id = key_id
            record.signature_version = signature_version
            record.approval_nonce = approval_nonce
            self._used_approval_nonces[self._nonce_key(approver_id, key_id, approval_nonce)] = approved_at.isoformat()
        self.approvals[proposal_id] = record

        del self.pending_proposals[proposal_id]

        # Save state with fail-closed
        if not self._save_state_with_fail_closed(True, proposal=proposal, operation="proposal_approved"):
            # Rollback
            self.pending_proposals[proposal_id] = proposal
            del self.approvals[proposal_id]
            return {"status": "DENY", "error": "Failed to persist approval state", "error_code": "vmga_state_persist_failed"}

        # Log approval - fail closed
        log_success = self._log_proposal_approved(proposal, approver_id, token_hash, expires_at, record)
        if self.ledger_required_for_kinetic and not log_success:
            # Rollback and lockdown
            self.pending_proposals[proposal_id] = proposal
            del self.approvals[proposal_id]
            self.lockdown_active = True
            return {"status": "LOCKDOWN", "error": "Ledger failure triggered lockdown", "error_code": "vmga_ledger_failure_lockdown"}

        return {
            "status": "APPROVED", "proposal_id": proposal_id,
            "proposal_hash": proposal_hash, "approver_id": approver_id,
            "expires_at": expires_at.isoformat(),
        }

    def _is_approval_valid(self, proposal_id: str, proposal_hash: str, approver_id: str, approval_token: str) -> Tuple[bool, str, str]:
        """Verify approval exists, hasn't expired, matches hash, and token is cryptographically valid.

        In strict_mode, also verifies HMAC to prevent attacks where attacker writes arbitrary token_hash to file.
        Includes rate limiting for repeated invalid token attempts.
        """
        if proposal_id not in self.approvals:
            return False, "Approval not found", "vmga_approval_not_found"

        approval = self.approvals[proposal_id]

        # Rate limiting: check for repeated invalid attempts
        attempt_key = f"{proposal_id}:{approver_id}"
        now = datetime.now(timezone.utc)
        if attempt_key in self._failed_token_attempts:
            attempt_info = self._failed_token_attempts[attempt_key]
            if attempt_info["count"] >= self._max_token_attempts:
                # Check if lockout period (1 hour) has passed
                first_attempt = datetime.fromisoformat(attempt_info["first_attempt"])
                if (now - first_attempt).total_seconds() < 3600:
                    return False, f"Rate limit exceeded: {self._max_token_attempts} failed attempts", "vmga_approval_rate_limited"
                else:
                    # Reset after lockout period
                    del self._failed_token_attempts[attempt_key]

        # Verify hash binding
        if approval.proposal_hash != proposal_hash:
            self._record_failed_attempt(attempt_key, now)
            return False, "Proposal hash mismatch (mutation detected)", "vmga_approval_hash_mismatch"

        if approval.binding_hash:
            try:
                expected_binding_hash = approval.expected_binding_hash()
            except (TypeError, ValueError):
                self._record_failed_attempt(attempt_key, now)
                return False, "Approval binding hash mismatch (approval record mutation detected)", "vmga_approval_binding_mismatch"
            if not hmac.compare_digest(approval.binding_hash, expected_binding_hash):
                self._record_failed_attempt(attempt_key, now)
                return False, "Approval binding hash mismatch (approval record mutation detected)", "vmga_approval_binding_mismatch"
        elif self.strict_mode:
            self._record_failed_attempt(attempt_key, now)
            return False, "Approval binding hash missing", "vmga_approval_binding_missing"

        if approval.approval_auth == "signature":
            if not approval.signature or not approval.signature_payload:
                self._record_failed_attempt(attempt_key, now)
                return False, "Approval signature evidence missing", "vmga_signature_evidence_missing"
            try:
                expected_payload = {
                    "proposal_id": approval.proposal_id,
                    "proposal_hash": approval.proposal_hash,
                    "approver_id": approval.approver_id,
                    "time_window": approval.signature_payload["time_window"],
                    "approval_nonce": approval.approval_nonce,
                    "key_id": approval.key_id,
                    "signature_version": approval.signature_version,
                }
                if approval.signature_payload != expected_payload:
                    self._record_failed_attempt(attempt_key, now)
                    return False, "Approval signature payload mismatch", "vmga_signature_payload_mismatch"
                entry = self._approval_key_entry(approval.approver_id, approval.key_id)
                if entry is None or entry.get("algorithm") != "ed25519":
                    self._record_failed_attempt(attempt_key, now)
                    return False, "Approval signature key cannot verify", "vmga_signature_key_unknown"
                public_key = self._load_ed25519_public_key(entry["public_key"])
                public_key.verify(
                    base64.b64decode(approval.signature),
                    self.canonical_approval_signature_payload(approval.signature_payload),
                )
            except (KeyError, ValueError, TypeError, InvalidSignature):
                self._record_failed_attempt(attempt_key, now)
                return False, "Approval signature verification failed", "vmga_signature_invalid"
        else:
            # Verify token hash matches (first line of defense)
            token_hash = hashlib.sha256(approval_token.encode()).hexdigest()[:32]
            if approval.approval_token_hash != token_hash:
                self._record_failed_attempt(attempt_key, now)
                return False, "Approval token mismatch", "vmga_approval_token_mismatch"

            # In strict_mode, also verify HMAC (prevents file-write attacks)
            if self.strict_mode and self.approval_secret and not self._verify_approval_token(proposal_id, proposal_hash, approver_id, approval_token):
                self._record_failed_attempt(attempt_key, now)
                return False, "Approval token HMAC verification failed", "vmga_approval_token_invalid"

        # Success - clear failed attempts for this key
        if attempt_key in self._failed_token_attempts:
            del self._failed_token_attempts[attempt_key]

        # Check expiration
        try:
            expires_at = datetime.fromisoformat(approval.expires_at)
            if datetime.now(timezone.utc) > expires_at:
                return False, "Approval expired", "vmga_approval_expired"
        except ValueError:
            return False, "Invalid expiration format", "vmga_approval_expiry_invalid"

        # Check not already used
        if approval.used:
            return False, "Approval already used", "vmga_approval_already_used"

        return True, "Valid", "vmga_approval_valid"

    def _record_failed_attempt(self, attempt_key: str, now: datetime) -> None:
        """Record a failed token attempt for rate limiting and persist to disk."""
        if attempt_key not in self._failed_token_attempts:
            self._failed_token_attempts[attempt_key] = {"count": 0, "first_attempt": now.isoformat()}
        self._failed_token_attempts[attempt_key]["count"] += 1
        # Persist immediately to survive restart
        self.state_store.save_rate_limit_state(self._failed_token_attempts)

    def _consume_approval_before_execute(self, proposal_id: str, approval: ApprovalRecord) -> Tuple[bool, str, str]:
        """Consume approval before execution for at-most-once kinetic semantics."""
        consume = getattr(self.state_store, "consume_approval_for_execution", None)
        if consume is not None:
            ok, reason, consumed = consume(proposal_id, approval)
            if ok and consumed is not None:
                self.approvals[proposal_id] = consumed
                return True, "Approval consumed", "vmga_approval_consumed"
            if reason == "already_used":
                return False, "Approval already used", "vmga_approval_already_used"
            if reason == "not_found":
                return False, "Approval not found", "vmga_approval_not_found"
            return False, "Approval state changed before execution", "vmga_approval_binding_mismatch"

        approval.used = True
        approval_correlation_id = self._parameters_correlation_id(approval.parameters)
        if not self._save_state_with_fail_closed(True, proposal=None, operation="approval_used", correlation_id=approval_correlation_id):
            approval.used = False
            return False, "Failed to persist approval consumption", "vmga_state_persist_failed"
        return True, "Approval consumed", "vmga_approval_consumed"

    def execute_approved(
        self, proposal_id: str, proposal_hash: str, approval_token: str, executor_fn: Callable,
    ) -> Dict[str, Any]:
        """Execute an approved proposal with mandatory token presentation."""
        with self._state_lock:
            return self._execute_approved_locked(proposal_id, proposal_hash, approval_token, executor_fn)

    def _execute_approved_locked(
        self, proposal_id: str, proposal_hash: str, approval_token: str, executor_fn: Callable,
    ) -> Dict[str, Any]:
        """Execute an approved proposal while holding the adapter execution lock."""
        if proposal_id not in self.approvals:
            return {"status": "DENY", "error": "Approval not found", "error_code": "vmga_approval_not_found"}

        approval = self.approvals[proposal_id]

        # Verify approval with token and approver_id
        is_valid, reason, error_code = self._is_approval_valid(proposal_id, proposal_hash, approval.approver_id, approval_token)
        if not is_valid:
            self._log_execution_pressure_signal(proposal_id, proposal_hash, approval, reason, error_code)
            return {"status": "DENY", "error": reason, "error_code": error_code, "rule_id": error_code}

        consumed, consume_reason, consume_code = self._consume_approval_before_execute(proposal_id, approval)
        if not consumed:
            self._log_execution_pressure_signal(proposal_id, proposal_hash, approval, consume_reason, consume_code)
            return {"status": "DENY", "error": consume_reason, "error_code": consume_code, "rule_id": consume_code}
        approval = self.approvals[proposal_id]
        try:
            self.state_store.save_rate_limit_state(self._failed_token_attempts)
        except Exception:
            pass

        # Build Vesta envelope
        request = ExecutionRequestEnvelope(
            session_id=proposal_id, actor_id="vmga_executor", tool_id="gmail_execute",
            plugin_id="vmga_gmail", tool_input={"proposal_id": proposal_id, "proposal_hash": proposal_hash},
        )

        execution_result = None
        error_info = None

        try:
            result = self.vesta.execute(request, executor_fn)
            tool_output = getattr(result, "tool_output", getattr(result, "output", None))
            backend_status = tool_output.get("status") if isinstance(tool_output, dict) else None
            if backend_status in {"DENY", "ERROR"}:
                error_info = str(tool_output.get("error") or "Backend execution failed")
                execution_result = {
                    "status": backend_status,
                    "request_id": result.request_id,
                    "duration_ms": result.duration_ms,
                    "error": error_info,
                    "error_code": tool_output.get("error_code", "vmga_backend_execution_failed"),
                    "tool_output": tool_output,
                }
            else:
                execution_result = {
                    "status": "SUCCESS",
                    "request_id": result.request_id,
                    "duration_ms": result.duration_ms,
                    "tool_output": tool_output,
                }
        except Exception as e:
            error_info = str(e)
            execution_result = {"status": "ERROR", "error": error_info, "error_code": "vmga_execution_failed"}

        # Log execution
        self._log_action_executed(proposal_id, proposal_hash, approval.approver_id, execution_result, error_info)

        return execution_result

    def reset_lockdown(self, admin_id: str) -> Dict[str, Any]:
        with self._state_lock:
            return self._reset_lockdown_locked(admin_id)

    def _reset_lockdown_locked(self, admin_id: str) -> Dict[str, Any]:
        """Reset lockdown while holding the adapter state lock."""
        was_locked = self.lockdown_active
        self.lockdown_active = False
        self.denial_counts.clear()
        self._save_state()
        self._log_lockdown_reset(admin_id, was_locked)
        return {"status": "RESET", "was_locked": was_locked, "admin_id": admin_id}

    @staticmethod
    def _redact_evidence_text(
        value: Optional[str], *, limit: int = 1000, extra_values: Sequence[str] = ()
    ) -> Optional[str]:
        if value is None:
            return None
        return redact_text(str(value), extra_values=extra_values)[:limit]

    def _detect_canary_markers(
        self,
        *,
        content: Optional[str],
        justification: str,
        parameters: Any,
    ) -> None:
        correlation_id = self._parameters_correlation_id(parameters)
        matches = find_canary_matches(
            self.canary_registry,
            content=content,
            justification=justification,
            parameters=parameters,
        )
        if not matches:
            return

        markers = tuple(canary.marker for canary in self.canary_registry)
        events = []
        for match in matches:
            event = {
                "event_type": "vmga_canary_tripped",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "severity": "CRITICAL",
                "canary_id": self._redact_evidence_text(match.canary_id, limit=256, extra_values=markers),
                "where_observed": match.where_observed,
                "correlation_id": self._redact_evidence_text(correlation_id, limit=256, extra_values=markers),
                "vmga_profile": self.profile,
            }
            events.append(event)

        self.canary_trip_recorded = True
        try:
            for event in events:
                if not self._write_to_ledger(event):
                    raise RuntimeError("canary trip event persistence failed")
            save_trip = getattr(self.state_store, "save_canary_trip_recorded", None)
            if save_trip is None:
                raise RuntimeError("canary trip state persistence is unavailable")
            if save_trip() is False:
                raise RuntimeError("canary trip state persistence failed")
        except Exception as exc:
            raise RuntimeError("VMGA canary trip could not be durably recorded") from exc

    def _log_proposal_received(
        self, proposal: Optional[VMGAProposal], status: str, decision: Optional[PolicyDecision],
        content_risk: ContentRisk, rule_id: Optional[str] = None, reason: Optional[str] = None,
    ) -> bool:
        event = {
            "event_type": "vmga_proposal_received",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "proposal_id": proposal.proposal_id if proposal else None,
            "proposal_hash": proposal.compute_hash() if proposal else None,
            "action": proposal.action.value if proposal else None,
            "action_class": "kinetic" if proposal and self.vmga_policy.classify_action(proposal.action) == ActionClass.KINETIC else "non_kinetic" if proposal else None,
            "actor_id": proposal.actor_id if proposal else None,
            "vmga_profile": self.profile,
            "policy_state": status,
            "vesta_rule_id": decision.rule_id if decision else rule_id,
            "vesta_reason": self._redact_evidence_text(decision.reason if decision else reason),
            "risk_score": content_risk.score,
            "risk_flags": content_risk.to_dict(),
            "thread_id": proposal.thread_id if proposal else None,
            "recipient_count": len(proposal.recipients) if proposal else 0,
            "attachment_count": len(proposal.attachment_ids) if proposal else 0,
            "justification": self._redact_evidence_text(proposal.justification) if proposal else None,
            "correlation_id": self._proposal_correlation_id(proposal),
        }
        return self._write_to_ledger(event)

    @staticmethod
    def _authority_pressure_present(proposal: VMGAProposal) -> bool:
        text = " ".join(filter(None, [proposal.content or "", proposal.justification or ""])).lower()
        authority_terms = (
            "ceo", "cfo", "founder", "owner", "executive", "board", "general counsel",
            "legal team", "attorney", "administrator", "admin", "manager", "director",
            "on behalf of", "by order of",
        )
        return any(term in text for term in authority_terms)

    def _log_proposal_pressure_signals(
        self,
        proposal: VMGAProposal,
        status: str,
        decision: Optional[PolicyDecision],
        content_risk: ContentRisk,
    ) -> None:
        signals: list[tuple[str, Dict[str, Any]]] = []
        denial_count = self.denial_counts.get(proposal.actor_id, 0)
        if status in {"DENY", "LOCKDOWN"} and denial_count >= 2:
            signals.append(("repeated_denial_escalation", {"denial_count": denial_count}))

        pressure_flags = []
        if content_risk.urgency_language:
            pressure_flags.append("urgency_language")
        if self._authority_pressure_present(proposal):
            pressure_flags.append("authority_language")
        if pressure_flags and status in {"DENY", "LOCKDOWN", "REVIEW_REQUIRED"}:
            signals.append(("urgency_or_authority_pressure", {"pressure_flags": pressure_flags}))

        for signal_type, details in signals:
            event = {
                "event_type": "vmga_pressure_signal",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "signal_type": signal_type,
                "proposal_id": proposal.proposal_id,
                "proposal_hash": proposal.compute_hash(),
                "action": proposal.action.value,
                "actor_id": proposal.actor_id,
                "policy_state": status,
                "vesta_rule_id": decision.rule_id if decision else None,
                "vesta_reason": self._redact_evidence_text(decision.reason if decision else None),
                "denial_count": denial_count,
                "lockdown_threshold": self.vmga_policy.lockdown_threshold,
                "risk_score": content_risk.score,
                "risk_flags": content_risk.to_dict(),
                "correlation_id": self._proposal_correlation_id(proposal),
                "vmga_profile": self.profile,
                **details,
            }
            self._write_to_ledger(event)

    def _log_execution_pressure_signal(
        self,
        proposal_id: str,
        supplied_proposal_hash: str,
        approval: ApprovalRecord,
        reason: str,
        error_code: str,
    ) -> None:
        mutation_codes = {
            "vmga_approval_hash_mismatch",
            "vmga_approval_binding_mismatch",
            "vmga_signature_payload_mismatch",
        }
        malformed_signature_payload = error_code == "vmga_signature_invalid" and not isinstance(approval.signature_payload, dict)
        if error_code not in mutation_codes and not malformed_signature_payload:
            return

        correlation_id = self._parameters_correlation_id(approval.parameters)

        event = {
            "event_type": "vmga_pressure_signal",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "signal_type": "proposal_mutation_attempt",
            "proposal_id": proposal_id,
            "proposal_hash": approval.proposal_hash,
            "supplied_proposal_hash": supplied_proposal_hash,
            "action": approval.action,
            "actor_id": approval.actor_id,
            "approver_id": approval.approver_id,
            "policy_state": "DENY",
            "vesta_rule_id": error_code,
            "vesta_reason": self._redact_evidence_text(reason),
            "error_code": error_code,
            "correlation_id": correlation_id,
            "vmga_profile": self.profile,
        }
        self._write_to_ledger(event)

    def _log_proposal_approved(
        self,
        proposal: VMGAProposal,
        approver_id: str,
        token_hash: str,
        expires_at: datetime,
        record: Optional["ApprovalRecord"] = None,
    ) -> bool:
        event = {
            "event_type": "vmga_proposal_approved",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "proposal_id": proposal.proposal_id,
            "proposal_hash": proposal.compute_hash(),
            "action": proposal.action.value,
            "actor_id": proposal.actor_id,
            "approver_id": approver_id,
            "approval_auth": record.approval_auth if record else self.approval_auth,
            "approval_token_hash": token_hash,
            "expires_at": expires_at.isoformat(),
            "vmga_profile": self.profile,
            "correlation_id": self._proposal_correlation_id(proposal),
        }
        if record is not None and record.approval_auth == "signature":
            # The detached signature is public, non-secret evidence: persisting
            # it in full (not a hash) makes operator approval non-repudiable and
            # independently re-verifiable against the approver public key.
            event["approval_signature"] = {
                "signature": record.signature,
                "signed_payload": record.signature_payload,
                "key_id": record.key_id,
                "signature_version": record.signature_version,
                "approval_nonce": record.approval_nonce,
            }
        return self._write_to_ledger(event)

    def _log_action_executed(self, proposal_id: str, proposal_hash: str, approver_id: str, result: Dict[str, Any], error_info: Optional[str]) -> bool:
        event = {
            "event_type": "vmga_action_executed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "proposal_id": proposal_id,
            "proposal_hash": proposal_hash,
            "approver_id": approver_id,
            "execution_status": result.get("status"),
            "execution_error": error_info,
            "vmga_profile": self.profile,
        }
        approval = self.approvals.get(proposal_id)
        if approval:
            correlation_id = self._parameters_correlation_id(approval.parameters)
            if correlation_id:
                event["correlation_id"] = correlation_id
        return self._write_to_ledger(event)

    def _log_lockdown_event(self, actor_id: str, proposal: VMGAProposal) -> bool:
        event = {
            "event_type": "vmga_lockdown_triggered",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor_id": actor_id,
            "denial_count": self.denial_counts.get(actor_id, 0),
            "threshold": self.vmga_policy.lockdown_threshold,
            "triggering_proposal_id": proposal.proposal_id,
            "triggering_action": proposal.action.value,
            "vmga_profile": self.profile,
        }
        return self._write_to_ledger(event)

    def _log_lockdown_reset(self, admin_id: str, was_locked: bool) -> bool:
        event = {
            "event_type": "vmga_lockdown_reset",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "admin_id": admin_id,
            "was_locked": was_locked,
            "vmga_profile": self.profile,
        }
        return self._write_to_ledger(event)

    def _write_to_ledger(self, event: Dict[str, Any]) -> bool:
        try:
            if hasattr(self.vesta, 'audit_ledger') and hasattr(self.vesta.audit_ledger, 'append'):
                with self._state_lock:
                    if self.evidence_hmac is None:
                        self.vesta.audit_ledger.append(event)
                    else:
                        checkpoint = self._load_evidence_head()
                        prev_mac = checkpoint.last_mac if checkpoint else None
                        sequence = checkpoint.last_sequence + 1 if checkpoint else 1
                        signed = add_integrity_metadata(
                            event,
                            key_id=self.evidence_hmac.key_id,
                            key=self.evidence_hmac.key,
                            sequence=sequence,
                            prev_mac=prev_mac,
                        )
                        line = canonical_json_line(signed)
                        if hasattr(self.vesta.audit_ledger, 'append_line'):
                            self.vesta.audit_ledger.append_line(line)
                        else:
                            self.vesta.audit_ledger.append(signed)
                        mac = signed["integrity"]["mac"]
                        self._save_evidence_head(EvidenceCheckpoint(
                            ledger_path=str(getattr(self.vesta.audit_ledger, "path", "")),
                            genesis_sequence=checkpoint.genesis_sequence if checkpoint else sequence,
                            genesis_mac=checkpoint.genesis_mac if checkpoint else mac,
                            last_sequence=sequence,
                            last_mac=mac,
                            key_id=self.evidence_hmac.key_id,
                        ))
                    return True
            else:
                import sys
                print(f"[VMGA WARNING] Ledger unavailable, event dropped: {event['event_type']}", file=sys.stderr)
                return False
        except Exception as e:
            import sys
            print(f"[VMGA ERROR] Ledger write failed: {e}", file=sys.stderr)
            return False


def load_vmga_policy(path: str) -> Dict[str, Any]:
    import yaml
    with open(path) as f:
        rules = yaml.safe_load(f) or {}
    VMGAPolicy.validate_rules(rules)
    return rules

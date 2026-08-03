"""VMGA (Vesta Mail Governance Adapter) - Gmail-specific governance extension.

This package provides email-domain-specific policy enforcement for agent runtimes,
building on the core Vesta Agent Runtime Governance framework.
"""

from .vmga_adapter import (
    VMGAGmailAdapter,
    VMGAPolicy,
    VMGAProposal,
    VMGAStateStore,
    GmailAction,
    ActionClass,
    ContentRisk,
    ApprovalRecord,
    load_vmga_policy,
)
from .backends import FakeGmailBackend, GogCLIBackend
from .canary import CanaryMarker, load_canary_registry
from .broker import VMGABroker
from .executor import VMGAExecutor
from .redaction import redact_json, redact_text
from .sqlite_state import SQLiteStateStore

__all__ = [
    "VMGAGmailAdapter",
    "VMGAPolicy", 
    "VMGAProposal",
    "VMGAStateStore",
    "GmailAction",
    "ActionClass",
    "ContentRisk",
    "ApprovalRecord",
    "FakeGmailBackend",
    "CanaryMarker",
    "GogCLIBackend",
    "SQLiteStateStore",
    "VMGABroker",
    "VMGAExecutor",
    "redact_json",
    "redact_text",
    "load_vmga_policy",
    "load_canary_registry",
]

__version__ = "0.2.0"

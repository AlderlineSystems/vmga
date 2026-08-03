"""Minimal VMGA broker service and optional HTTP wrapper."""

from __future__ import annotations

import json
import hmac
import uuid
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional
from collections.abc import Mapping

from .broker_contract import validate_broker_proposal_payload
from .executor import VMGAExecutor
from .posture import PostureConfig, assess_posture
from .vmga_adapter import VMGAGmailAdapter


MAX_REQUEST_BODY_BYTES = 1_000_000
GENERIC_REQUEST_ERROR = "VMGA broker request failed"
GENERIC_BAD_REQUEST_ERROR = "Invalid VMGA broker request"


def reject_duplicate_json_object(pairs: list[tuple[str, Any]]) -> Dict[str, Any]:
    """Reject exact or case-colliding JSON keys before Python drops earlier values."""
    seen_exact: set[str] = set()
    seen_folded: set[str] = set()
    result: Dict[str, Any] = {}
    for key, value in pairs:
        folded = key.casefold()
        if key in seen_exact or folded in seen_folded:
            raise ValueError("duplicate or case-colliding JSON object key")
        seen_exact.add(key)
        seen_folded.add(folded)
        result[key] = value
    return result


class VMGABroker:
    def __init__(
        self,
        adapter: VMGAGmailAdapter,
        executor: Optional[VMGAExecutor] = None,
        backend: Optional[Any] = None,
        posture_config: Optional[PostureConfig] = None,
    ):
        self.adapter = adapter
        self.executor = executor
        self.backend = backend if backend is not None else getattr(executor, "backend", None)
        self.posture_config = posture_config

    def health(self) -> Dict[str, Any]:
        return {
            "status": "ok" if not self.adapter.lockdown_active else "lockdown",
            "lockdown_active": self.adapter.lockdown_active,
            "profile": self.adapter.profile,
            "posture_mode": self.posture()["mode"],
        }

    def posture(self) -> Dict[str, Any]:
        config = self.posture_config or PostureConfig()
        if self.adapter.canary_trip_recorded and not config.canary_trip_recorded:
            config = replace(config, canary_trip_recorded=True)
        return assess_posture(config)

    def propose(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        correlation_id = str(payload.get("correlation_id") or uuid.uuid4()) if isinstance(payload, Mapping) else str(uuid.uuid4())
        try:
            payload = validate_broker_proposal_payload(payload)
        except ValueError as exc:
            return {"status": "DENY", "error_code": "vmga_broker_bad_request", "error": str(exc), "correlation_id": correlation_id}
        allowed = {
            "action", "actor_id", "thread_id", "message_ids", "content",
            "recipients", "attachment_ids", "parameters", "justification", "sender",
        }
        parameter_keys = {
            "subject", "search_query", "message_id", "max_results", "metadata",
            "cc", "bcc", "reply_to_message_id", "reply_to",
        }
        kwargs = {key: value for key, value in payload.items() if key in allowed}
        parameters = dict(kwargs.get("parameters") or {})
        metadata = dict(parameters.get("metadata") or {})
        metadata["correlation_id"] = correlation_id
        parameters["metadata"] = metadata
        parameters["correlation_id"] = correlation_id
        for key in parameter_keys:
            if key in payload and payload[key] is not None:
                parameters[key] = payload[key]
        kwargs["parameters"] = parameters
        if "action" not in kwargs or "actor_id" not in kwargs:
            return {"status": "DENY", "error_code": "vmga_broker_bad_request", "error": "action and actor_id are required", "correlation_id": correlation_id}
        result = self.adapter.propose_action(**kwargs)
        result["correlation_id"] = correlation_id
        backend_result = self._execute_allowed_non_kinetic(kwargs, result)
        if backend_result is not None:
            result["backend_result"] = backend_result
        return result

    def _execute_allowed_non_kinetic(self, proposal_kwargs: Dict[str, Any], proposal_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if self.backend is None or proposal_result.get("status") != "ALLOW":
            return None
        action = proposal_kwargs.get("action")
        parameters = proposal_kwargs.get("parameters") or {}
        try:
            if action == "read" and parameters.get("search_query") and hasattr(self.backend, "search"):
                return self.backend.search(str(parameters["search_query"]), int(parameters.get("max_results", 10)))
            if action == "read" and hasattr(self.backend, "read"):
                message_id = parameters.get("message_id")
                if message_id is None and proposal_kwargs.get("message_ids"):
                    message_id = proposal_kwargs["message_ids"][0]
                if message_id:
                    return self.backend.read(str(message_id))
        except Exception as exc:
            return {
                "status": "ERROR",
                "error_code": "vmga_backend_execution_failed",
                "error": "Backend execution failed",
            }
        return None

    def approve(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        try:
            return self.adapter.approve_proposal(
                proposal_id=payload["proposal_id"],
                approver_id=payload["approver_id"],
                approval_token=payload.get("approval_token", ""),
                signature=payload.get("signature", ""),
                time_window=payload.get("time_window", ""),
                approval_nonce=payload.get("approval_nonce", ""),
                key_id=payload.get("key_id", ""),
                signature_version=payload.get("signature_version", "vmga-approval-ed25519-v1"),
            )
        except KeyError as exc:
            return {"status": "DENY", "error_code": "vmga_broker_bad_request", "error": f"missing {exc.args[0]}"}

    def execute(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if self.executor is None:
            return {"status": "DENY", "error_code": "vmga_executor_unavailable", "error": "executor unavailable"}
        try:
            return self.executor.execute_approved(
                proposal_id=payload["proposal_id"],
                proposal_hash=payload["proposal_hash"],
                approval_token=payload["approval_token"],
            )
        except KeyError as exc:
            return {"status": "DENY", "error_code": "vmga_broker_bad_request", "error": f"missing {exc.args[0]}"}


class VMGAHTTPHandler(BaseHTTPRequestHandler):
    broker: VMGABroker
    bearer_token: Optional[str] = None

    def _send(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> Dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("invalid content length") from exc
        if length <= 0:
            return {}
        if length > MAX_REQUEST_BODY_BYTES:
            raise ValueError("request body too large")
        payload = json.loads(self.rfile.read(length).decode("utf-8"), object_pairs_hook=reject_duplicate_json_object)
        if not isinstance(payload, dict):
            raise ValueError("broker request body must be a JSON object")
        return payload

    def _authorized(self) -> bool:
        if not self.bearer_token:
            return True
        return hmac.compare_digest(self.headers.get("Authorization", ""), f"Bearer {self.bearer_token}")

    def do_GET(self) -> None:
        if not self._authorized():
            self._send(401, {"status": "DENY", "error_code": "vmga_broker_unauthorized"})
            return
        if self.path == "/health":
            self._send(200, self.broker.health())
            return
        if self.path == "/v1/posture":
            self._send(200, self.broker.posture())
            return
        self._send(404, {"status": "ERROR", "error_code": "vmga_broker_not_found"})

    def do_POST(self) -> None:
        if not self._authorized():
            self._send(401, {"status": "DENY", "error_code": "vmga_broker_unauthorized"})
            return
        try:
            payload = self._read_json()
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            self._send(400, {"status": "DENY", "error_code": "vmga_broker_bad_request", "error": GENERIC_BAD_REQUEST_ERROR})
            return
        try:
            routes = {
                "/propose": self.broker.propose,
                "/v1/proposals": self.broker.propose,
                "/approve": self.broker.approve,
                "/v1/approvals": self.broker.approve,
                "/execute": self.broker.execute,
                "/v1/executions": self.broker.execute,
            }
            handler = routes.get(self.path)
            if handler is None:
                self._send(404, {"status": "ERROR", "error_code": "vmga_broker_not_found"})
                return
            self._send(200, handler(payload))
        except Exception:
            self._send(500, {"status": "DENY", "error_code": "vmga_broker_request_failed", "error": GENERIC_REQUEST_ERROR})


def make_server(host: str, port: int, broker: VMGABroker, bearer_token: Optional[str] = None) -> ThreadingHTTPServer:
    class Handler(VMGAHTTPHandler):
        pass

    Handler.broker = broker
    Handler.bearer_token = bearer_token
    return ThreadingHTTPServer((host, port), Handler)

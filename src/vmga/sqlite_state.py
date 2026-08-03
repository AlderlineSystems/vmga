"""SQLite-backed VMGA state store.

This implements the same public methods as the JSON VMGAStateStore while using
SQLite transactions for durable approval consumption and restart behavior.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, Optional, Tuple

from .evidence_integrity import EvidenceCheckpoint
from .vmga_adapter import ApprovalRecord, VMGAProposal


class SQLiteStateStore:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = Path(db_path or "~/.vmga_state/vmga.sqlite3").expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute("PRAGMA foreign_keys=ON")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS pending_proposals (
                  proposal_id TEXT PRIMARY KEY,
                  payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS approvals (
                  proposal_id TEXT PRIMARY KEY,
                  payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS rate_limit_state (
                  attempt_key TEXT PRIMARY KEY,
                  payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS approval_nonces (
                  nonce_key TEXT PRIMARY KEY,
                  used_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS lockdown_state (
                  id INTEGER PRIMARY KEY CHECK (id = 1),
                  lockdown_active INTEGER NOT NULL,
                  denial_counts TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS evidence_head (
                  id INTEGER PRIMARY KEY CHECK (id = 1),
                  payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS canary_trip_state (
                  id INTEGER PRIMARY KEY CHECK (id = 1),
                  tripped INTEGER NOT NULL CHECK (tripped = 1)
                );
                """
            )

    def save_pending_proposals(self, proposals: Dict[str, VMGAProposal], proposal_ttl_seconds: int = 86400) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM pending_proposals")
            conn.executemany(
                "INSERT INTO pending_proposals (proposal_id, payload) VALUES (?, ?)",
                [(pid, json.dumps(prop.to_dict(), sort_keys=True)) for pid, prop in proposals.items()],
            )

    def load_pending_proposals(self, proposal_ttl_seconds: int = 86400) -> Dict[str, VMGAProposal]:
        with self._connect() as conn:
            rows = conn.execute("SELECT proposal_id, payload FROM pending_proposals").fetchall()
        return {row["proposal_id"]: VMGAProposal.from_dict(json.loads(row["payload"])) for row in rows}

    def save_approvals(self, approvals: Dict[str, ApprovalRecord]) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM approvals")
            conn.executemany(
                "INSERT INTO approvals (proposal_id, payload) VALUES (?, ?)",
                [(pid, json.dumps(app.to_dict(), sort_keys=True)) for pid, app in approvals.items()],
            )

    def load_approvals(self) -> Dict[str, ApprovalRecord]:
        with self._connect() as conn:
            rows = conn.execute("SELECT proposal_id, payload FROM approvals").fetchall()
        return {row["proposal_id"]: ApprovalRecord.from_dict(json.loads(row["payload"])) for row in rows}

    def consume_approval_for_execution(self, proposal_id: str, expected: ApprovalRecord) -> Tuple[bool, str, Optional[ApprovalRecord]]:
        """Atomically mark an approval used if it still matches the validated record.

        This is VMGA's SQLite at-most-once consume primitive. The caller first
        validates the loaded approval; this method then takes a write
        transaction, reloads the current row, confirms it is still unused and
        byte-for-byte equivalent to the validated record except for `used`, and
        persists `used=true` before execution begins.
        """
        expected_payload = expected.to_dict()
        expected_payload["used"] = False
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT payload FROM approvals WHERE proposal_id = ?", (proposal_id,)).fetchone()
            if row is None:
                return False, "not_found", None
            current = ApprovalRecord.from_dict(json.loads(row["payload"]))
            if current.used:
                return False, "already_used", current
            current_payload = current.to_dict()
            current_payload["used"] = False
            if current_payload != expected_payload:
                return False, "record_mismatch", current
            current.used = True
            conn.execute(
                "UPDATE approvals SET payload = ? WHERE proposal_id = ?",
                (json.dumps(current.to_dict(), sort_keys=True), proposal_id),
            )
            return True, "consumed", current

    def save_rate_limit_state(self, failed_attempts: Dict[str, Dict[str, Any]]) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM rate_limit_state")
            conn.executemany(
                "INSERT INTO rate_limit_state (attempt_key, payload) VALUES (?, ?)",
                [(key, json.dumps(value, sort_keys=True)) for key, value in failed_attempts.items()],
            )

    def load_rate_limit_state(self, lockout_duration_seconds: int = 3600) -> Dict[str, Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT attempt_key, payload FROM rate_limit_state").fetchall()
        now = datetime.now(timezone.utc)
        active: Dict[str, Dict[str, Any]] = {}
        stale_keys: list[str] = []
        for row in rows:
            payload = json.loads(row["payload"])
            try:
                first_attempt = datetime.fromisoformat(str(payload["first_attempt"]))
            except (KeyError, TypeError, ValueError):
                stale_keys.append(row["attempt_key"])
                continue
            if (now - first_attempt).total_seconds() >= lockout_duration_seconds:
                stale_keys.append(row["attempt_key"])
                continue
            active[row["attempt_key"]] = payload
        if stale_keys:
            with self._connect() as conn:
                conn.executemany("DELETE FROM rate_limit_state WHERE attempt_key = ?", [(key,) for key in stale_keys])
        return active

    def save_canary_trip_recorded(self) -> None:
        """Persist the one-way trip bit; there is intentionally no reset API."""
        with self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO canary_trip_state (id, tripped) VALUES (1, 1)"
            )

    def load_canary_trip_recorded(self) -> bool:
        with self._connect() as conn:
            row = conn.execute("SELECT tripped FROM canary_trip_state WHERE id = 1").fetchone()
        return row is not None

    def save_approval_nonce_state(self, used_nonces: Dict[str, str]) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM approval_nonces")
            conn.executemany(
                "INSERT INTO approval_nonces (nonce_key, used_at) VALUES (?, ?)",
                sorted(used_nonces.items()),
            )

    def load_approval_nonce_state(self, validity_horizon_seconds: int = 3900) -> Dict[str, str]:
        with self._connect() as conn:
            rows = conn.execute("SELECT nonce_key, used_at FROM approval_nonces").fetchall()
        now = datetime.now(timezone.utc)
        active: Dict[str, str] = {}
        stale_keys: list[str] = []
        for row in rows:
            try:
                used_at = datetime.fromisoformat(str(row["used_at"]))
            except ValueError:
                stale_keys.append(row["nonce_key"])
                continue
            if (now - used_at).total_seconds() > validity_horizon_seconds:
                stale_keys.append(row["nonce_key"])
                continue
            active[row["nonce_key"]] = row["used_at"]
        if stale_keys:
            with self._connect() as conn:
                conn.executemany("DELETE FROM approval_nonces WHERE nonce_key = ?", [(key,) for key in stale_keys])
        return active

    def save_lockdown_state(self, lockdown_active: bool, denial_counts: Dict[str, int]) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO lockdown_state (id, lockdown_active, denial_counts)
                VALUES (1, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                  lockdown_active=excluded.lockdown_active,
                  denial_counts=excluded.denial_counts
                """,
                (1 if lockdown_active else 0, json.dumps(denial_counts, sort_keys=True)),
            )

    def load_lockdown_state(self) -> Tuple[bool, Dict[str, int], bool]:
        with self._connect() as conn:
            row = conn.execute("SELECT lockdown_active, denial_counts FROM lockdown_state WHERE id = 1").fetchone()
        if row is None:
            return False, {}, False
        return bool(row["lockdown_active"]), json.loads(row["denial_counts"]), False

    def save_evidence_head(self, checkpoint: EvidenceCheckpoint) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO evidence_head (id, payload)
                VALUES (1, ?)
                ON CONFLICT(id) DO UPDATE SET payload=excluded.payload
                """,
                (json.dumps(checkpoint.to_dict(), sort_keys=True),),
            )

    def load_evidence_head(self) -> Optional[EvidenceCheckpoint]:
        with self._connect() as conn:
            row = conn.execute("SELECT payload FROM evidence_head WHERE id = 1").fetchone()
        if row is None:
            return None
        return EvidenceCheckpoint.from_dict(json.loads(row["payload"]))

    def load_all_state(
        self,
        proposal_ttl_seconds: int = 86400,
        fail_closed: bool = False,
        max_state_size_bytes: int = 10_000_000,
    ) -> Dict[str, Any]:
        try:
            lockdown_active, denial_counts, corrupted = self.load_lockdown_state()
            return {
                "pending_proposals": self.load_pending_proposals(proposal_ttl_seconds),
                "approvals": self.load_approvals(),
                "lockdown_active": lockdown_active,
                "denial_counts": denial_counts,
                "canary_trip_recorded": self.load_canary_trip_recorded(),
                "corrupted": corrupted,
            }
        except Exception:
            if fail_closed:
                return {
                    "pending_proposals": {},
                    "approvals": {},
                    "lockdown_active": True,
                    "denial_counts": {},
                    "canary_trip_recorded": False,
                    "corrupted": True,
                }
            return {
                "pending_proposals": {},
                "approvals": {},
                "lockdown_active": False,
                "denial_counts": {},
                "canary_trip_recorded": False,
                "corrupted": True,
            }

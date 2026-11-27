"""Dual-engine gateway historian supporting local SQLite and PostgreSQL.

Architecture:
- BaseGatewayStore: Common abstract interface and shared data serialization routines.
- GatewayStore: Polymorphic dispatcher routing based on constructor parameters and settings.
- SQLiteGatewayStore: Default local development and CI testing engine (100% backward compatible).
- PostgresGatewayStore: Cloud-ready relational store with connection pooling and advisory locking.
"""

from __future__ import annotations

import csv
import hashlib
import json
import logging
import os
import sqlite3
import threading
import time
from abc import ABC, abstractmethod
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from typing import Any, Iterator
from uuid import uuid4

try:
    import psycopg2
    import psycopg2.extensions
    import psycopg2.extras
    import psycopg2.pool
    STATUS_IN_TRANSACTION = getattr(psycopg2.extensions, "STATUS_IN_TRANSACTION", 1)
    STATUS_READY = getattr(psycopg2.extensions, "STATUS_READY", 0)
    TRANSACTION_STATUS_IDLE = getattr(psycopg2.extensions, "TRANSACTION_STATUS_IDLE", 0)
    TRANSACTION_STATUS_ACTIVE = getattr(psycopg2.extensions, "TRANSACTION_STATUS_ACTIVE", 1)
    TRANSACTION_STATUS_INTRANS = getattr(psycopg2.extensions, "TRANSACTION_STATUS_INTRANS", 2)
    TRANSACTION_STATUS_INERROR = getattr(psycopg2.extensions, "TRANSACTION_STATUS_INERROR", 3)
except ImportError:
    psycopg2 = None  # type: ignore[assignment]
    STATUS_IN_TRANSACTION = 1
    STATUS_READY = 0
    TRANSACTION_STATUS_IDLE = 0
    TRANSACTION_STATUS_ACTIVE = 1
    TRANSACTION_STATUS_INTRANS = 2
    TRANSACTION_STATUS_INERROR = 3

from .schema import CANONICAL_FIELDS, TelemetryEvent, utc_now

logger = logging.getLogger("aegis_gateway.storage")

GENESIS_HASH = "0" * 64
# Deterministic 64-bit integer advisory lock key for audit chain serialization:
# ASCII for "AICG_AUD" -> 0x414943475F415544 = 4704337229774636356
AICG_AUDIT_ADVISORY_LOCK_ID = 0x414943475F415544
# Deterministic 64-bit integer advisory lock key for cross-process user mutation serialization:
# ASCII for "AICG_USR" -> 0x414943475F555352 = 4704337229774640466
AICG_USER_MUTATION_ADVISORY_LOCK_ID = 0x414943475F555352


class BaseGatewayStore(ABC):
    """Abstract interface for all AICG persistent storage engines."""

    @abstractmethod
    def connection(self) -> Any:
        """Context manager yielding an active database connection."""
        ...

    @abstractmethod
    def initialize(self) -> None:
        """Provision tables, indexes, baseline schemas, and initial administrative seeds."""
        ...

    @abstractmethod
    def append_telemetry(self, event: TelemetryEvent) -> None:
        ...

    @abstractmethod
    def telemetry(self, limit: int = 100, source_type: str | None = None) -> list[dict[str, Any]]:
        ...

    @abstractmethod
    def create_incident(self, event: TelemetryEvent, evidence: list[str], affected_resources: str) -> dict[str, Any]:
        ...

    @abstractmethod
    def incidents(self, limit: int = 100, severity: str | None = None, state: str | None = None) -> list[dict[str, Any]]:
        ...

    @abstractmethod
    def incident(self, incident_id: str) -> dict[str, Any] | None:
        ...

    @abstractmethod
    def find_active_incident(self, device_id: str | None = None, attack_type: str | None = None) -> dict[str, Any] | None:
        ...

    @abstractmethod
    def correlate_incident(self, incident_id: str, event: TelemetryEvent, new_evidence: list[str], note: str = "Correlated ongoing campaign activity") -> dict[str, Any]:
        ...

    @abstractmethod
    def transition_incident(self, incident_id: str, state: str, actor: str, note: str, evidence: list[str] | None = None) -> dict[str, Any]:
        ...

    @abstractmethod
    def reset_active_incidents_and_alerts(self, actor: str = "system", note: str = "Simulation reset") -> int:
        ...

    @abstractmethod
    def record_action(self, *, event_id: str | None, incident_id: str | None, action: str, reason: str, policy: str, mode: str, result: str, provenance: str = "SIMULATED") -> dict[str, Any]:
        ...

    @abstractmethod
    def actions(self, limit: int = 100) -> list[dict[str, Any]]:
        ...

    @abstractmethod
    def record_iam(self, item: dict[str, Any]) -> None:
        ...

    @abstractmethod
    def record_trust(self, identity: str, score: float, delta: float, reason: str) -> None:
        ...

    @abstractmethod
    def trust(self, identity: str | None = None, limit: int = 300) -> list[dict[str, Any]]:
        ...

    @abstractmethod
    def put_metadata(self, kind: str, version: str, payload: dict[str, Any]) -> None:
        ...

    @abstractmethod
    def latest_metadata(self, kind: str) -> dict[str, Any] | None:
        ...

    @abstractmethod
    def prune(self, days: int) -> int:
        ...

    @abstractmethod
    def get_admin_user(self, username: str) -> dict[str, Any] | None:
        ...

    @abstractmethod
    def get_admin_user_by_id(self, user_id: str) -> dict[str, Any] | None:
        ...

    @abstractmethod
    def list_admin_users(self) -> list[dict[str, Any]]:
        ...

    @abstractmethod
    def create_admin_user(
        self,
        username: str,
        password_hash: str,
        role: str,
        status: str = "ACTIVE",
        mfa_enabled: int = 1,
        must_change_password: bool | int = False,
    ) -> dict[str, Any]:
        ...

    @abstractmethod
    def update_admin_user_status(self, user_id: str, status: str) -> dict[str, Any]:
        ...

    @abstractmethod
    def update_admin_user_role(self, user_id: str, role: str) -> dict[str, Any]:
        ...

    @abstractmethod
    def update_admin_user_password(
        self,
        user_id: str,
        password_hash: str,
        must_change_password: bool | int | None = None,
    ) -> dict[str, Any]:
        ...

    @abstractmethod
    def update_admin_user_username(self, user_id: str, new_username: str) -> dict[str, Any]:
        ...

    @abstractmethod
    def delete_admin_user(self, user_id: str) -> bool:
        ...

    @abstractmethod
    def record_admin_login(self, username: str) -> None:
        ...

    @abstractmethod
    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        ...

    @abstractmethod
    def get_alert_by_incident(self, incident_id: str) -> dict[str, Any] | None:
        ...

    @abstractmethod
    def create_or_update_alert(self, incident: dict[str, Any], event: TelemetryEvent | dict[str, Any] | None = None, decision: Any = None, plan: Any = None) -> dict[str, Any]:
        ...

    @abstractmethod
    def sync_alert_with_incident(self, incident: dict[str, Any]) -> dict[str, Any] | None:
        ...

    @abstractmethod
    def acknowledge_alert(self, alert_id: str, username: str) -> dict[str, Any]:
        ...

    @abstractmethod
    def list_alerts(self, limit: int = 100, status: str | None = None, ack_state: str | None = None, severity: str | None = None) -> list[dict[str, Any]]:
        ...

    @abstractmethod
    def record_audit(self, username: str, role: str, action: str, resource: str, resource_id: str | None = None, result: str = "SUCCESS", details: str = "", source_ip: str | None = None) -> dict[str, Any]:
        ...

    @abstractmethod
    def verify_audit_log_integrity(self) -> dict[str, Any]:
        ...

    @abstractmethod
    def list_audit_logs(self, limit: int = 100, action: str | None = None, username: str | None = None) -> list[dict[str, Any]]:
        ...

    @abstractmethod
    def get_device_identity(self, device_id: str) -> dict[str, Any] | None:
        ...

    @abstractmethod
    def list_device_identities(self, status: str | None = None) -> list[dict[str, Any]]:
        ...

    @abstractmethod
    def upsert_device_identity(self, device_id: str, role: str = "sensor", auth_key_hash: str = "", status: str = "ENROLLED", trust_score: float = 100.0, failures: int = 0, mfa_status: str = "NOT_REQUIRED") -> dict[str, Any]:
        ...

    @abstractmethod
    def update_device_trust(self, device_id: str, score: float, failures: int | None = None) -> None:
        ...

    @abstractmethod
    def update_device_last_seen(self, device_id: str, timestamp: str | None = None) -> None:
        ...

    @abstractmethod
    def set_device_status(self, device_id: str, status: str) -> dict[str, Any] | None:
        ...

    # =========================================================================
    # Shared Serialization and Cryptographic Routines
    # =========================================================================

    @staticmethod
    def _compute_audit_hash(
        prev_hash: str,
        event_id: str,
        timestamp: str,
        username: str,
        role: str,
        action: str,
        resource: str,
        resource_id: str | None,
        result: str,
        source_ip: str | None,
        details: str,
    ) -> str:
        """Deterministic canonical string serialization for cryptographic hash chaining."""
        canonical_repr = (
            f"{prev_hash}|{event_id}|{timestamp}|{username}|{role}|{action}|"
            f"{resource}|{resource_id or ''}|{result}|{source_ip or ''}|{details}"
        )
        return hashlib.sha256(canonical_repr.encode("utf-8")).hexdigest()

    @staticmethod
    def _alert_row(row: Any) -> dict[str, Any]:
        item = dict(row)
        try:
            item["evidence"] = json.loads(item.pop("evidence_json", "[]"))
        except Exception:
            item["evidence"] = []
        return item

    @staticmethod
    def _incident_row(row: Any) -> dict[str, Any]:
        item = dict(row)
        item["evidence"] = json.loads(item.pop("evidence_json"))
        return item

    def export(self, kind: str, fmt: str) -> str:
        """Export tabular historian datasets in JSON or CSV format."""
        if kind == "incidents":
            rows = self.incidents(limit=1000)
        elif kind in ("telemetry", "events"):
            rows = self.telemetry(limit=5000)
            if kind == "events":
                rows = [r for r in rows if r.get("label") == "ATTACK"]
        elif kind == "actions":
            rows = self.actions(limit=1000)
        elif kind == "audit":
            rows = self.list_audit_logs(limit=1000)
        elif kind == "alerts":
            raw_alerts = self.list_alerts(limit=1000)
            rows = []
            for alert in raw_alerts:
                item = dict(alert)
                if "evidence" in item and "evidence_json" not in item:
                    item["evidence_json"] = (
                        json.dumps(item["evidence"])
                        if isinstance(item["evidence"], (list, dict))
                        else str(item["evidence"])
                    )
                rows.append(item)
        else:
            raise ValueError("Export kind must be incidents, telemetry, events, actions, audit, or alerts")

        if fmt == "json":
            return json.dumps(rows, indent=2, sort_keys=True)
        if fmt != "csv":
            raise ValueError("Export format must be csv or json")
        flattened = [
            {
                key: json.dumps(value) if isinstance(value, (list, dict)) else value
                for key, value in row.items()
            }
            for row in rows
        ]
        if not flattened:
            return ""
        result = StringIO()
        writer = csv.DictWriter(
            result,
            fieldnames=sorted({key for row in flattened for key in row}),
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(flattened)
        return result.getvalue()


class GatewayStore(BaseGatewayStore):
    """Polymorphic dispatcher preserving 100% backward compatibility for all callers."""

    def __new__(
        cls,
        path: Path | str | None = None,
        master_key: str | None = None,
        production: bool = False,
        allow_demo_accounts: bool = True,
        initial_admin_username: str | None = None,
        initial_admin_password: str | None = None,
        database_url: str | None = None,
        **kwargs: Any,
    ) -> Any:
        if cls is GatewayStore:
            if database_url:
                return PostgresGatewayStore(
                    database_url=database_url,
                    master_key=master_key,
                    production=production,
                    allow_demo_accounts=allow_demo_accounts,
                    initial_admin_username=initial_admin_username,
                    initial_admin_password=initial_admin_password,
                    **kwargs,
                )
            default_path = Path(path) if path else Path("backend/data/aegis_gateway.sqlite3")
            return SQLiteGatewayStore(
                path=default_path,
                master_key=master_key,
                production=production,
                allow_demo_accounts=allow_demo_accounts,
                initial_admin_username=initial_admin_username,
                initial_admin_password=initial_admin_password,
            )
        return super().__new__(cls)

    def connection(self) -> Any: ...
    def initialize(self) -> None: ...
    def append_telemetry(self, event: TelemetryEvent) -> None: ...
    def telemetry(self, limit: int = 100, source_type: str | None = None) -> list[dict[str, Any]]: ...
    def create_incident(self, event: TelemetryEvent, evidence: list[str], affected_resources: str) -> dict[str, Any]: ...
    def incidents(self, limit: int = 100, severity: str | None = None, state: str | None = None) -> list[dict[str, Any]]: ...
    def incident(self, incident_id: str) -> dict[str, Any] | None: ...
    def find_active_incident(self, device_id: str | None = None, attack_type: str | None = None) -> dict[str, Any] | None: ...
    def correlate_incident(self, incident_id: str, event: TelemetryEvent, new_evidence: list[str], note: str = "Correlated ongoing campaign activity") -> dict[str, Any]: ...
    def transition_incident(self, incident_id: str, state: str, actor: str, note: str, evidence: list[str] | None = None) -> dict[str, Any]: ...
    def reset_active_incidents_and_alerts(self, actor: str = "system", note: str = "Simulation reset") -> int: ...
    def record_action(self, *, event_id: str | None, incident_id: str | None, action: str, reason: str, policy: str, mode: str, result: str, provenance: str = "SIMULATED") -> dict[str, Any]: ...
    def actions(self, limit: int = 100) -> list[dict[str, Any]]: ...
    def record_iam(self, item: dict[str, Any]) -> None: ...
    def record_trust(self, identity: str, score: float, delta: float, reason: str) -> None: ...
    def trust(self, identity: str | None = None, limit: int = 300) -> list[dict[str, Any]]: ...
    def put_metadata(self, kind: str, version: str, payload: dict[str, Any]) -> None: ...
    def latest_metadata(self, kind: str) -> dict[str, Any] | None: ...
    def prune(self, days: int) -> int: ...
    def get_admin_user(self, username: str) -> dict[str, Any] | None: ...
    def get_admin_user_by_id(self, user_id: str) -> dict[str, Any] | None: ...
    def list_admin_users(self) -> list[dict[str, Any]]: ...
    def create_admin_user(self, username: str, password_hash: str, role: str, status: str = "ACTIVE", mfa_enabled: int = 1, must_change_password: bool | int = False) -> dict[str, Any]: ...
    def update_admin_user_status(self, user_id: str, status: str) -> dict[str, Any]: ...
    def update_admin_user_role(self, user_id: str, role: str) -> dict[str, Any]: ...
    def update_admin_user_password(self, user_id: str, password_hash: str, must_change_password: bool | int | None = None) -> dict[str, Any]: ...
    def update_admin_user_username(self, user_id: str, new_username: str) -> dict[str, Any]: ...
    def delete_admin_user(self, user_id: str) -> bool: ...
    def record_admin_login(self, username: str) -> None: ...
    def get_alert(self, alert_id: str) -> dict[str, Any] | None: ...
    def get_alert_by_incident(self, incident_id: str) -> dict[str, Any] | None: ...
    def create_or_update_alert(self, incident: dict[str, Any], event: TelemetryEvent | dict[str, Any] | None = None, decision: Any = None, plan: Any = None) -> dict[str, Any]: ...
    def sync_alert_with_incident(self, incident: dict[str, Any]) -> dict[str, Any] | None: ...
    def acknowledge_alert(self, alert_id: str, username: str) -> dict[str, Any]: ...
    def list_alerts(self, limit: int = 100, status: str | None = None, ack_state: str | None = None, severity: str | None = None) -> list[dict[str, Any]]: ...
    def record_audit(self, username: str, role: str, action: str, resource: str, resource_id: str | None = None, result: str = "SUCCESS", details: str = "", source_ip: str | None = None) -> dict[str, Any]: ...
    def verify_audit_log_integrity(self) -> dict[str, Any]: ...
    def list_audit_logs(self, limit: int = 100, action: str | None = None, username: str | None = None) -> list[dict[str, Any]]: ...
    def get_device_identity(self, device_id: str) -> dict[str, Any] | None: ...
    def list_device_identities(self, status: str | None = None) -> list[dict[str, Any]]: ...
    def upsert_device_identity(self, device_id: str, role: str = "sensor", auth_key_hash: str = "", status: str = "ENROLLED", trust_score: float = 100.0, failures: int = 0, mfa_status: str = "NOT_REQUIRED") -> dict[str, Any]: ...
    def update_device_trust(self, device_id: str, score: float, failures: int | None = None) -> None: ...
    def update_device_last_seen(self, device_id: str, timestamp: str | None = None) -> None: ...
    def set_device_status(self, device_id: str, status: str) -> dict[str, Any] | None: ...


# =============================================================================
# SQLITE ENGINE IMPLEMENTATION (100% PRESERVED FOR LOCAL DEV AND AUTOMATED TESTS)
# =============================================================================

class SQLiteGatewayStore(GatewayStore):
    """Durable local SQLite historian with WAL mode and append-only cryptographic log."""

    def __init__(
        self,
        path: Path,
        master_key: str | None = None,
        production: bool = False,
        allow_demo_accounts: bool = True,
        initial_admin_username: str | None = None,
        initial_admin_password: str | None = None,
    ):
        self.path = Path(path)
        self.master_key = master_key
        self.production = production
        self.allow_demo_accounts = allow_demo_accounts
        self.initial_admin_username = initial_admin_username or "admin"
        self.initial_admin_password = initial_admin_password
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._audit_lock = threading.RLock()
        self.initialize()

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        con = sqlite3.connect(self.path, timeout=10)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode = WAL;")
        con.execute("PRAGMA foreign_keys = ON;")
        con.execute("PRAGMA busy_timeout = 5000;")
        con.execute("PRAGMA synchronous = NORMAL;")
        try:
            yield con
            con.commit()
        except Exception:
            try:
                con.rollback()
            except Exception:
                pass
            raise
        finally:
            con.close()

    def initialize(self) -> None:
        canonical_columns = ",\n".join(f"{field} TEXT" for field in CANONICAL_FIELDS)
        with self.connection() as con:
            con.executescript(
                f"""
                CREATE TABLE IF NOT EXISTS telemetry (
                    {canonical_columns}, raw_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS telemetry_timestamp_idx ON telemetry(timestamp DESC);
                CREATE INDEX IF NOT EXISTS telemetry_scenario_idx ON telemetry(scenario_id);
                CREATE INDEX IF NOT EXISTS telemetry_source_idx ON telemetry(source_type, source_id);
                CREATE INDEX IF NOT EXISTS telemetry_protocol_idx ON telemetry(protocol);
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    event_id TEXT NOT NULL, device_id TEXT, source_id TEXT, attack_type TEXT,
                    severity TEXT, confidence REAL, evidence_json TEXT NOT NULL, affected_resources TEXT,
                    energy_impact TEXT, iam_impact TEXT, trust_impact TEXT, response_action TEXT,
                    response_mode TEXT, operator TEXT, lifecycle_state TEXT NOT NULL,
                    recovery_state TEXT NOT NULL, resolved_at TEXT, provenance TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS incidents_state_idx ON incidents(lifecycle_state, severity);
                CREATE INDEX IF NOT EXISTS incidents_active_idx ON incidents(lifecycle_state, updated_at DESC);
                CREATE TABLE IF NOT EXISTS incident_history (
                    history_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, timestamp TEXT NOT NULL,
                    previous_state TEXT, state TEXT NOT NULL, actor TEXT, note TEXT, evidence_json TEXT NOT NULL,
                    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS incident_history_incident_idx ON incident_history(incident_id, timestamp);
                CREATE TABLE IF NOT EXISTS actions (
                    action_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, event_id TEXT, incident_id TEXT,
                    action TEXT NOT NULL, reason TEXT NOT NULL, policy TEXT NOT NULL, mode TEXT NOT NULL,
                    result TEXT NOT NULL, provenance TEXT NOT NULL,
                    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE SET NULL
                );
                CREATE INDEX IF NOT EXISTS actions_timestamp_idx ON actions(timestamp DESC);
                CREATE TABLE IF NOT EXISTS iam_events (
                    iam_event_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, identity TEXT, role TEXT,
                    authentication_status TEXT, authorization_status TEXT, access_request TEXT,
                    decision TEXT, reason TEXT, provenance TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS iam_timestamp_idx ON iam_events(timestamp DESC);
                CREATE TABLE IF NOT EXISTS trust_history (
                    trust_event_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, identity TEXT NOT NULL,
                    score REAL NOT NULL, delta REAL NOT NULL, reason TEXT NOT NULL, provenance TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS trust_identity_idx ON trust_history(identity, timestamp DESC);
                CREATE TABLE IF NOT EXISTS metadata (
                    metadata_id TEXT PRIMARY KEY, kind TEXT NOT NULL, version TEXT NOT NULL,
                    created_at TEXT NOT NULL, payload_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS metadata_kind_idx ON metadata(kind, created_at DESC);
                CREATE TABLE IF NOT EXISTS admin_users (
                    user_id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
                    role TEXT NOT NULL, status TEXT NOT NULL, mfa_enabled INTEGER NOT NULL DEFAULT 1,
                    mfa_status TEXT NOT NULL DEFAULT 'SIMULATED_VERIFIED', created_at TEXT NOT NULL, last_login TEXT,
                    must_change_password INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS admin_users_username_idx ON admin_users(username);
                CREATE TABLE IF NOT EXISTS admin_alerts (
                    alert_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL UNIQUE, timestamp TEXT NOT NULL,
                    severity TEXT NOT NULL, attack_type TEXT NOT NULL, device_id TEXT, source_id TEXT,
                    target TEXT NOT NULL, confidence REAL NOT NULL, detection_reason TEXT NOT NULL,
                    lifecycle_state TEXT NOT NULL, recommended_action TEXT NOT NULL, current_action TEXT NOT NULL,
                    acknowledgement_state TEXT NOT NULL DEFAULT 'UNACKNOWLEDGED', acknowledged_by TEXT,
                    acknowledged_at TEXT, status TEXT NOT NULL DEFAULT 'ACTIVE', evidence_json TEXT NOT NULL DEFAULT '[]',
                    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS admin_alerts_incident_idx ON admin_alerts(incident_id);
                CREATE INDEX IF NOT EXISTS admin_alerts_status_idx ON admin_alerts(status, acknowledgement_state);
                CREATE TABLE IF NOT EXISTS admin_audit_log (
                    event_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, username TEXT NOT NULL,
                    role TEXT NOT NULL, action TEXT NOT NULL, resource TEXT NOT NULL, resource_id TEXT,
                    result TEXT NOT NULL, source_ip TEXT, details TEXT NOT NULL,
                    prev_hash TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
                    record_hash TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS admin_audit_timestamp_idx ON admin_audit_log(timestamp DESC);
                CREATE INDEX IF NOT EXISTS admin_audit_action_idx ON admin_audit_log(action);
                CREATE TABLE IF NOT EXISTS device_identities (
                    device_id TEXT PRIMARY KEY, role TEXT NOT NULL DEFAULT 'sensor',
                    status TEXT NOT NULL DEFAULT 'ENROLLED', auth_key_hash TEXT NOT NULL,
                    trust_score REAL NOT NULL DEFAULT 100.0, failures INTEGER NOT NULL DEFAULT 0,
                    mfa_status TEXT NOT NULL DEFAULT 'NOT_REQUIRED', created_at TEXT NOT NULL,
                    last_seen TEXT
                );
                CREATE INDEX IF NOT EXISTS device_identities_status_idx ON device_identities(status);
                """
            )
            self._migrate_schema(con)
            self._seed_default_users(con)
            self._seed_default_device_identities(con)

    def _migrate_schema(self, con: sqlite3.Connection) -> None:
        """Backward-compatible schema migration for existing SQLite databases."""
        user_cols = [r["name"] for r in con.execute("PRAGMA table_info(admin_users)").fetchall()]
        if "must_change_password" not in user_cols:
            con.execute("ALTER TABLE admin_users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0")

        audit_cols = [r["name"] for r in con.execute("PRAGMA table_info(admin_audit_log)").fetchall()]
        if "prev_hash" not in audit_cols:
            con.execute(f"ALTER TABLE admin_audit_log ADD COLUMN prev_hash TEXT DEFAULT '{GENESIS_HASH}'")
        if "record_hash" not in audit_cols:
            con.execute("ALTER TABLE admin_audit_log ADD COLUMN record_hash TEXT DEFAULT ''")

        unhashed = con.execute("SELECT rowid, * FROM admin_audit_log WHERE record_hash IS NULL OR record_hash = '' ORDER BY rowid ASC").fetchall()
        if unhashed:
            first_rowid = unhashed[0]["rowid"]
            prev_row = con.execute("SELECT record_hash FROM admin_audit_log WHERE rowid < ? AND record_hash != '' ORDER BY rowid DESC LIMIT 1", (first_rowid,)).fetchone()
            curr_prev = str(prev_row["record_hash"]) if prev_row else GENESIS_HASH
            for row in unhashed:
                h = self._compute_audit_hash(
                    prev_hash=curr_prev,
                    event_id=row["event_id"],
                    timestamp=row["timestamp"],
                    username=row["username"],
                    role=row["role"],
                    action=row["action"],
                    resource=row["resource"],
                    resource_id=row["resource_id"],
                    result=row["result"],
                    source_ip=row["source_ip"],
                    details=row["details"],
                )
                con.execute("UPDATE admin_audit_log SET prev_hash = ?, record_hash = ? WHERE rowid = ?", (curr_prev, h, row["rowid"]))
                curr_prev = h

        con.execute(
            "UPDATE admin_alerts SET status = 'CLOSED', lifecycle_state = 'CLOSED' "
            "WHERE incident_id IN (SELECT incident_id FROM incidents WHERE lifecycle_state = 'CLOSED') AND status != 'CLOSED'"
        )
        con.execute(
            "UPDATE admin_alerts SET status = 'RESOLVED', lifecycle_state = 'RESOLVED' "
            "WHERE incident_id IN (SELECT incident_id FROM incidents WHERE lifecycle_state = 'RESOLVED') AND status NOT IN ('RESOLVED', 'CLOSED')"
        )

    def _seed_default_users(self, con: sqlite3.Connection) -> None:
        from .security import hash_password
        now = utc_now()

        existing = con.execute("SELECT COUNT(*) AS c FROM admin_users").fetchone()["c"]
        if existing > 0:
            return

        if self.production:
            if not self.initial_admin_password or not self.initial_admin_password.strip():
                raise RuntimeError(
                    "Production first-run bootstrap failed: AEGIS_INITIAL_ADMIN_PASSWORD is required "
                    "to initialize the initial administrator account. Set AEGIS_INITIAL_ADMIN_PASSWORD "
                    "in the environment to provision the administrator securely."
                )

            admin_user = (self.initial_admin_username or "admin").strip()
            user_id = f"USR-ADMIN-{uuid4().hex[:8].upper()}"
            hashed = hash_password(self.initial_admin_password.strip())
            con.execute(
                "INSERT INTO admin_users (user_id, username, password_hash, role, status, mfa_enabled, mfa_status, created_at, last_login, must_change_password) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (user_id, admin_user, hashed, "ADMIN", "ACTIVE", 1, "SIMULATED_VERIFIED", now, None, 0)
            )
        else:
            if self.allow_demo_accounts:
                admin_pw = self.initial_admin_password.strip() if self.initial_admin_password else "Admin@AICG2026!"
                admin_user = (self.initial_admin_username or "admin").strip()
                operator_pw = os.getenv("AEGIS_INITIAL_OPERATOR_PASSWORD", "Operator@AICG2026!").strip()
                defaults = [
                    ("USR-ADMIN-01", admin_user, hash_password(admin_pw), "ADMIN", "ACTIVE", 1, "SIMULATED_VERIFIED", now, None, 0),
                    ("USR-OPERATOR-01", "operator", hash_password(operator_pw), "OPERATOR", "ACTIVE", 1, "SIMULATED_VERIFIED", now, None, 0),
                ]
                for row in defaults:
                    con.execute(
                        "INSERT OR IGNORE INTO admin_users (user_id, username, password_hash, role, status, mfa_enabled, mfa_status, created_at, last_login, must_change_password) VALUES (?,?,?,?,?,?,?,?,?,?)",
                        row
                    )

    def _seed_default_device_identities(self, con: sqlite3.Connection) -> None:
        from .iam import DEFAULT_MASTER_KEY, derive_device_key, hash_device_key
        now = utc_now()
        devices = [
            ("SENSOR-01", "sensor", "ENROLLED", 100.0, 0, "NOT_REQUIRED"),
            ("SENSOR-02", "sensor", "ENROLLED", 100.0, 0, "NOT_REQUIRED"),
            ("SENSOR-03", "sensor", "ENROLLED", 100.0, 0, "NOT_REQUIRED"),
            ("SENSOR-GROUP-A", "sensor", "ENROLLED", 100.0, 0, "NOT_REQUIRED"),
            ("ATK-01", "untrusted", "REVOKED", 35.0, 0, "FAILED"),
            ("ATTACKER-01", "untrusted", "REVOKED", 35.0, 0, "FAILED"),
            ("ATTACKER-02", "untrusted", "REVOKED", 35.0, 0, "FAILED"),
            ("ATTACKER-03", "untrusted", "REVOKED", 35.0, 0, "FAILED"),
            ("ATTACKER-04", "untrusted", "REVOKED", 35.0, 0, "FAILED"),
            ("ATTACKER-05", "untrusted", "REVOKED", 35.0, 0, "FAILED"),
            ("ATTACKER-06", "untrusted", "REVOKED", 35.0, 0, "FAILED"),
            ("operator", "operator", "ENROLLED", 100.0, 0, "VERIFIED"),
        ]
        eff_key = getattr(self, "master_key", None) or DEFAULT_MASTER_KEY
        for dev_id, role, status, trust, fails, mfa in devices:
            if role == "untrusted":
                h = hash_device_key(f"untrusted-key-{dev_id}")
            else:
                psk = derive_device_key(dev_id, eff_key)
                h = hash_device_key(psk)
            con.execute(
                """
                INSERT OR IGNORE INTO device_identities
                (device_id, role, status, auth_key_hash, trust_score, failures, mfa_status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (dev_id, role, status, h, trust, fails, mfa, now),
            )

    def append_telemetry(self, event: TelemetryEvent) -> None:
        event.normalize()
        values = event.to_dict()
        values.pop("auth_token", None)
        columns = CANONICAL_FIELDS + ["raw_json"]
        stored = [None if values.get(name) is None else str(values[name]) for name in CANONICAL_FIELDS]
        stored.append(json.dumps(values, sort_keys=True))
        placeholders = ",".join("?" for _ in columns)
        with self.connection() as con:
            con.execute(f"INSERT INTO telemetry ({','.join(columns)}) VALUES ({placeholders})", stored)

    def telemetry(self, limit: int = 100, source_type: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT raw_json FROM telemetry"
        params: list[Any] = []
        if source_type:
            query += " WHERE source_type = ?"
            params.append(source_type.upper())
        query += " ORDER BY timestamp DESC, rowid DESC LIMIT ?"
        params.append(max(1, min(limit, 5000)))
        with self.connection() as con:
            rows = con.execute(query, params).fetchall()
        return [json.loads(row["raw_json"]) for row in reversed(rows)]

    def create_incident(self, event: TelemetryEvent, evidence: list[str], affected_resources: str) -> dict[str, Any]:
        incident_id = f"INC-{datetime.now(timezone.utc):%Y%m%d}-{uuid4().hex[:8].upper()}"
        now = utc_now()
        values = {
            "incident_id": incident_id, "created_at": now, "updated_at": now, "event_id": event.event_id,
            "device_id": event.device_id, "source_id": event.source_id, "attack_type": event.attack_type,
            "severity": event.severity, "confidence": event.confidence, "evidence_json": json.dumps(evidence),
            "affected_resources": affected_resources, "energy_impact": event.energy_cause,
            "iam_impact": event.access_decision, "trust_impact": str(event.trust_score),
            "response_action": event.response_action, "response_mode": event.response_mode, "operator": "system",
            "lifecycle_state": "DETECTED", "recovery_state": "PENDING", "resolved_at": None,
            "provenance": event.provenance,
        }
        with self.connection() as con:
            con.execute(
                "INSERT INTO incidents VALUES (:incident_id,:created_at,:updated_at,:event_id,:device_id,:source_id,"
                ":attack_type,:severity,:confidence,:evidence_json,:affected_resources,:energy_impact,:iam_impact,"
                ":trust_impact,:response_action,:response_mode,:operator,:lifecycle_state,:recovery_state,:resolved_at,:provenance)", values)
            con.execute("INSERT INTO incident_history VALUES (?,?,?,?,?,?,?,?)", (
                str(uuid4()), incident_id, now, None, "DETECTED", "system", "Detection opened incident", json.dumps(evidence)))
        return self.incident(incident_id) or values

    def incidents(self, limit: int = 100, severity: str | None = None, state: str | None = None) -> list[dict[str, Any]]:
        clauses, params = [], []
        if severity:
            clauses.append("severity = ?"); params.append(severity.upper())
        if state:
            clauses.append("lifecycle_state = ?"); params.append(state.upper())
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(max(1, min(limit, 1000)))
        with self.connection() as con:
            rows = con.execute(f"SELECT * FROM incidents{where} ORDER BY created_at DESC LIMIT ?", params).fetchall()
        return [self._incident_row(row) for row in rows]

    def incident(self, incident_id: str) -> dict[str, Any] | None:
        with self.connection() as con:
            row = con.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
            history = con.execute("SELECT * FROM incident_history WHERE incident_id = ? ORDER BY timestamp", (incident_id,)).fetchall()
        if not row:
            return None
        result = self._incident_row(row)
        result["history"] = [{**dict(item), "evidence": json.loads(item["evidence_json"])} for item in history]
        return result

    def find_active_incident(self, device_id: str | None = None, attack_type: str | None = None) -> dict[str, Any] | None:
        clauses = ["lifecycle_state NOT IN ('RESOLVED', 'CLOSED')"]
        params: list[Any] = []
        if device_id and attack_type:
            clauses.append("device_id = ? AND attack_type = ?")
            params.extend([device_id, attack_type])
        elif device_id:
            clauses.append("device_id = ?")
            params.append(device_id)
        elif attack_type:
            clauses.append("attack_type = ?")
            params.append(attack_type)
        where = f"WHERE {' AND '.join(clauses)}"
        with self.connection() as con:
            row = con.execute(f"SELECT * FROM incidents {where} ORDER BY updated_at DESC LIMIT 1", params).fetchone()
        return self._incident_row(row) if row else None

    def correlate_incident(self, incident_id: str, event: TelemetryEvent, new_evidence: list[str], note: str = "Correlated ongoing campaign activity") -> dict[str, Any]:
        current = self.incident(incident_id)
        if not current:
            raise KeyError(f"Unknown incident: {incident_id}")
        now = utc_now()
        merged_evidence = list(dict.fromkeys(current.get("evidence", []) + new_evidence))
        severity_rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        curr_sev = current.get("severity") or "MEDIUM"
        new_sev = event.severity or "MEDIUM"
        effective_sev = new_sev if severity_rank.get(new_sev, 2) > severity_rank.get(curr_sev, 2) else curr_sev
        effective_conf = max(float(current.get("confidence") or 0.0), float(event.confidence or 0.0))

        prev_state = current["lifecycle_state"]
        if prev_state == "RECOVERING":
            effective_state = "CONTAINED"
            history_note = "Attack activity resumed during recovery verification; state regressed from RECOVERING to CONTAINED."
        else:
            effective_state = prev_state
            history_note = note

        with self.connection() as con:
            con.execute(
                "UPDATE incidents SET updated_at=?, event_id=?, severity=?, confidence=?, evidence_json=?, "
                "energy_impact=?, iam_impact=?, trust_impact=?, response_action=?, lifecycle_state=? WHERE incident_id=?",
                (now, event.event_id, effective_sev, round(effective_conf, 3), json.dumps(merged_evidence),
                 event.energy_cause or current.get("energy_impact"),
                 event.access_decision or current.get("iam_impact"),
                 str(event.trust_score) if event.trust_score is not None else current.get("trust_impact"),
                 event.response_action or current.get("response_action"),
                 effective_state,
                 incident_id)
            )
            con.execute(
                "INSERT INTO incident_history (history_id, incident_id, timestamp, previous_state, state, actor, note, evidence_json) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (str(uuid4()), incident_id, now, prev_state, effective_state,
                 "system", history_note, json.dumps(new_evidence))
            )
        return self.incident(incident_id)  # type: ignore[return-value]

    def transition_incident(self, incident_id: str, state: str, actor: str, note: str, evidence: list[str] | None = None) -> dict[str, Any]:
        allowed = {
            "DETECTED": {"TRIAGED", "RESPONDING", "CONTAINED", "CLOSED"},
            "TRIAGED": {"RESPONDING", "CONTAINED", "CLOSED"},
            "RESPONDING": {"CONTAINED", "RECOVERING", "CLOSED"},
            "CONTAINED": {"RECOVERING", "RESPONDING", "RESOLVED", "CLOSED"},
            "RECOVERING": {"RESOLVED", "RESPONDING", "CONTAINED", "CLOSED"},
            "RESOLVED": {"CLOSED", "RESPONDING"},
            "CLOSED": {"RESPONDING", "DETECTED"},
        }
        current = self.incident(incident_id)
        if not current:
            raise KeyError(f"Unknown incident: {incident_id}")
        state = state.upper()
        if state == current["lifecycle_state"]:
            return current
        if state not in allowed.get(current["lifecycle_state"], set()):
            raise ValueError(f"Invalid transition {current['lifecycle_state']} -> {state}")
        now = utc_now()
        recovery = "VERIFIED" if state in {"RESOLVED", "CLOSED"} else current["recovery_state"]
        with self.connection() as con:
            con.execute("UPDATE incidents SET lifecycle_state=?, recovery_state=?, updated_at=?, resolved_at=? WHERE incident_id=?", (
                state, recovery, now, now if state == "RESOLVED" else current["resolved_at"], incident_id))
            con.execute("INSERT INTO incident_history VALUES (?,?,?,?,?,?,?,?)", (
                str(uuid4()), incident_id, now, current["lifecycle_state"], state, actor, note, json.dumps(evidence or [])))
            alert_status = "RESOLVED" if state == "RESOLVED" else ("CLOSED" if state == "CLOSED" else "ACTIVE")
            con.execute(
                "UPDATE admin_alerts SET lifecycle_state = ?, status = ?, timestamp = ? WHERE incident_id = ?",
                (state, alert_status, now, incident_id)
            )
        return self.incident(incident_id)  # type: ignore[return-value]

    def reset_active_incidents_and_alerts(self, actor: str = "system", note: str = "Simulation reset") -> int:
        now = utc_now()
        with self.connection() as con:
            rows = con.execute(
                "SELECT incident_id, lifecycle_state FROM incidents WHERE lifecycle_state NOT IN ('RESOLVED', 'CLOSED')"
            ).fetchall()
            if not rows:
                return 0
            inc_ids = [r["incident_id"] for r in rows]
            placeholders = ",".join("?" for _ in inc_ids)

            con.execute(
                f"UPDATE incidents SET lifecycle_state = 'CLOSED', recovery_state = 'RESET', "
                f"updated_at = ?, resolved_at = ? WHERE incident_id IN ({placeholders})",
                [now, now] + inc_ids,
            )
            for r in rows:
                con.execute(
                    "INSERT INTO incident_history VALUES (?,?,?,?,?,?,?,?)",
                    (str(uuid4()), r["incident_id"], now, r["lifecycle_state"], "CLOSED", actor, note, "[]"),
                )
            con.execute(
                f"UPDATE admin_alerts SET status = 'CLOSED', lifecycle_state = 'CLOSED', timestamp = ? "
                f"WHERE incident_id IN ({placeholders})",
                [now] + inc_ids,
            )
            return len(inc_ids)

    def record_action(self, *, event_id: str | None, incident_id: str | None, action: str, reason: str, policy: str, mode: str, result: str, provenance: str = "SIMULATED") -> dict[str, Any]:
        item = {"action_id": str(uuid4()), "timestamp": utc_now(), "event_id": event_id, "incident_id": incident_id,
                "action": action, "reason": reason, "policy": policy, "mode": mode, "result": result, "provenance": provenance}
        with self.connection() as con:
            con.execute("INSERT INTO actions VALUES (:action_id,:timestamp,:event_id,:incident_id,:action,:reason,:policy,:mode,:result,:provenance)", item)
        return item

    def actions(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.connection() as con:
            rows = con.execute("SELECT * FROM actions ORDER BY timestamp DESC LIMIT ?", (max(1, min(limit, 1000)),)).fetchall()
        return [dict(row) for row in rows]

    def record_iam(self, item: dict[str, Any]) -> None:
        defaults = {
            "iam_event_id": str(uuid4()),
            "timestamp": utc_now(),
            "identity": None,
            "role": None,
            "authentication_status": "AUTHENTICATED",
            "authorization_status": "AUTHORIZED",
            "access_request": "TELEMETRY_INGEST",
            "decision": "ALLOW",
            "reason": "Normal operational access",
            "provenance": "DERIVED",
        }
        item = {**defaults, **item}
        item.pop("auth_token", None)
        with self.connection() as con:
            con.execute("INSERT INTO iam_events VALUES (:iam_event_id,:timestamp,:identity,:role,:authentication_status,:authorization_status,:access_request,:decision,:reason,:provenance)", item)

    def record_trust(self, identity: str, score: float, delta: float, reason: str) -> None:
        with self.connection() as con:
            con.execute("INSERT INTO trust_history VALUES (?,?,?,?,?,?,?)", (str(uuid4()), utc_now(), identity, score, delta, reason, "DERIVED"))

    def trust(self, identity: str | None = None, limit: int = 300) -> list[dict[str, Any]]:
        query, params = "SELECT * FROM trust_history", []
        if identity:
            query += " WHERE identity=?"; params.append(identity)
        query += " ORDER BY timestamp DESC, rowid DESC LIMIT ?"; params.append(max(1, min(limit, 5000)))
        with self.connection() as con:
            rows = con.execute(query, params).fetchall()
        return [dict(row) for row in reversed(rows)]

    def put_metadata(self, kind: str, version: str, payload: dict[str, Any]) -> None:
        with self.connection() as con:
            con.execute("INSERT INTO metadata VALUES (?,?,?,?,?)", (str(uuid4()), kind, version, utc_now(), json.dumps(payload, sort_keys=True)))

    def latest_metadata(self, kind: str) -> dict[str, Any] | None:
        with self.connection() as con:
            row = con.execute("SELECT * FROM metadata WHERE kind=? ORDER BY created_at DESC LIMIT 1", (kind,)).fetchone()
        if not row:
            return None
        item = dict(row); item["payload"] = json.loads(item.pop("payload_json")); return item

    def prune(self, days: int) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max(days, 1))).isoformat()
        with self.connection() as con:
            result = con.execute("DELETE FROM telemetry WHERE timestamp < ?", (cutoff,))
        return result.rowcount

    def get_admin_user(self, username: str) -> dict[str, Any] | None:
        with self.connection() as con:
            row = con.execute("SELECT * FROM admin_users WHERE username = ?", (username,)).fetchone()
        if not row:
            return None
        item = dict(row)
        if "must_change_password" in item:
            item["must_change_password"] = bool(item["must_change_password"])
        return item

    def get_admin_user_by_id(self, user_id: str) -> dict[str, Any] | None:
        with self.connection() as con:
            row = con.execute("SELECT * FROM admin_users WHERE user_id = ?", (user_id,)).fetchone()
        if not row:
            return None
        item = dict(row)
        if "must_change_password" in item:
            item["must_change_password"] = bool(item["must_change_password"])
        return item

    def list_admin_users(self) -> list[dict[str, Any]]:
        with self.connection() as con:
            rows = con.execute("SELECT user_id, username, role, status, mfa_enabled, mfa_status, created_at, last_login, must_change_password FROM admin_users ORDER BY created_at ASC").fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["must_change_password"] = bool(item.get("must_change_password", False))
            result.append(item)
        return result

    def create_admin_user(
        self,
        username: str,
        password_hash: str,
        role: str,
        status: str = "ACTIVE",
        mfa_enabled: int = 1,
        must_change_password: bool | int = False,
    ) -> dict[str, Any]:
        user_id = f"USR-{uuid4().hex[:8].upper()}"
        now = utc_now()
        must_change_val = 1 if must_change_password else 0
        try:
            with self.connection() as con:
                con.execute(
                    "INSERT INTO admin_users (user_id, username, password_hash, role, status, mfa_enabled, mfa_status, created_at, last_login, must_change_password) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (user_id, username, password_hash, role.upper(), status.upper(), mfa_enabled, "SIMULATED_VERIFIED", now, None, must_change_val)
                )
        except sqlite3.IntegrityError as err:
            raise ValueError(f"Username '{username}' already exists") from err
        return {
            "user_id": user_id,
            "username": username,
            "role": role.upper(),
            "status": status.upper(),
            "mfa_enabled": mfa_enabled,
            "mfa_status": "SIMULATED_VERIFIED",
            "created_at": now,
            "last_login": None,
            "must_change_password": bool(must_change_val),
        }

    def update_admin_user_status(self, user_id: str, status: str) -> dict[str, Any]:
        status = status.upper()
        if status not in {"ACTIVE", "DISABLED"}:
            raise ValueError(f"Invalid status: {status}")
        with self.connection() as con:
            con.execute("BEGIN IMMEDIATE")
            target = con.execute("SELECT role, status FROM admin_users WHERE user_id = ?", (user_id,)).fetchone()
            if not target:
                raise KeyError(f"User not found: {user_id}")
            if target["role"] == "ADMIN" and target["status"] == "ACTIVE" and status == "DISABLED":
                rem = con.execute(
                    "SELECT COUNT(*) as cnt FROM admin_users WHERE role = 'ADMIN' AND status = 'ACTIVE' AND user_id != ?",
                    (user_id,)
                ).fetchone()
                if rem["cnt"] == 0:
                    raise ValueError("Cannot disable the last active administrator account")
            con.execute("UPDATE admin_users SET status = ? WHERE user_id = ?", (status, user_id))
        user = self.get_admin_user_by_id(user_id)
        if not user:
            raise KeyError(f"User not found: {user_id}")
        user.pop("password_hash", None)
        return user

    def update_admin_user_role(self, user_id: str, role: str) -> dict[str, Any]:
        role = role.upper()
        if role not in {"ADMIN", "OPERATOR"}:
            raise ValueError(f"Invalid role: {role}")
        with self.connection() as con:
            con.execute("BEGIN IMMEDIATE")
            target = con.execute("SELECT role, status FROM admin_users WHERE user_id = ?", (user_id,)).fetchone()
            if not target:
                raise KeyError(f"User not found: {user_id}")
            if target["role"] == "ADMIN" and target["status"] == "ACTIVE" and role != "ADMIN":
                rem = con.execute(
                    "SELECT COUNT(*) as cnt FROM admin_users WHERE role = 'ADMIN' AND status = 'ACTIVE' AND user_id != ?",
                    (user_id,)
                ).fetchone()
                if rem["cnt"] == 0:
                    raise ValueError("Cannot demote the last active administrator account")
            con.execute("UPDATE admin_users SET role = ? WHERE user_id = ?", (role, user_id))
        user = self.get_admin_user_by_id(user_id)
        if not user:
            raise KeyError(f"User not found: {user_id}")
        user.pop("password_hash", None)
        return user

    def update_admin_user_password(
        self,
        user_id: str,
        password_hash: str,
        must_change_password: bool | int | None = None,
    ) -> dict[str, Any]:
        if not password_hash or not isinstance(password_hash, str) or not password_hash.strip():
            raise ValueError("Password hash is required")
        user = self.get_admin_user_by_id(user_id)
        if not user:
            raise KeyError(f"User not found: {user_id}")
        with self.connection() as con:
            if must_change_password is not None:
                val = 1 if must_change_password else 0
                con.execute(
                    "UPDATE admin_users SET password_hash = ?, must_change_password = ? WHERE user_id = ?",
                    (password_hash, val, user_id),
                )
            else:
                con.execute(
                    "UPDATE admin_users SET password_hash = ? WHERE user_id = ?",
                    (password_hash, user_id),
                )
        updated = self.get_admin_user_by_id(user_id)
        if not updated:
            raise KeyError(f"User not found: {user_id}")
        updated.pop("password_hash", None)
        return updated

    def update_admin_user_username(self, user_id: str, new_username: str) -> dict[str, Any]:
        new_username = str(new_username).strip()
        if not new_username:
            raise ValueError("Username cannot be empty")
        user = self.get_admin_user_by_id(user_id)
        if not user:
            raise KeyError(f"User not found: {user_id}")
        if user["username"] == new_username:
            user.pop("password_hash", None)
            return user
        try:
            with self.connection() as con:
                con.execute("UPDATE admin_users SET username = ? WHERE user_id = ?", (new_username, user_id))
        except sqlite3.IntegrityError as err:
            raise ValueError(f"Username '{new_username}' already exists") from err
        updated = self.get_admin_user_by_id(user_id)
        if not updated:
            raise KeyError(f"User not found: {user_id}")
        updated.pop("password_hash", None)
        return updated

    def delete_admin_user(self, user_id: str) -> bool:
        if not user_id:
            return False
        with self.connection() as con:
            con.execute("BEGIN IMMEDIATE")
            target = con.execute("SELECT role, status FROM admin_users WHERE user_id = ?", (user_id,)).fetchone()
            if not target:
                return False
            if target["role"] == "ADMIN" and target["status"] == "ACTIVE":
                rem = con.execute(
                    "SELECT COUNT(*) as cnt FROM admin_users WHERE role = 'ADMIN' AND status = 'ACTIVE' AND user_id != ?",
                    (user_id,)
                ).fetchone()
                if rem["cnt"] == 0:
                    raise ValueError("Cannot delete the last remaining active administrator account")
            cursor = con.execute("DELETE FROM admin_users WHERE user_id = ?", (user_id,))
            return cursor.rowcount > 0

    def record_admin_login(self, username: str) -> None:
        now = utc_now()
        with self.connection() as con:
            con.execute("UPDATE admin_users SET last_login = ? WHERE username = ?", (now, username))

    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        with self.connection() as con:
            row = con.execute("SELECT * FROM admin_alerts WHERE alert_id = ?", (alert_id,)).fetchone()
        return self._alert_row(row) if row else None

    def get_alert_by_incident(self, incident_id: str) -> dict[str, Any] | None:
        with self.connection() as con:
            row = con.execute("SELECT * FROM admin_alerts WHERE incident_id = ?", (incident_id,)).fetchone()
        return self._alert_row(row) if row else None

    def create_or_update_alert(
        self,
        incident: dict[str, Any],
        event: TelemetryEvent | dict[str, Any] | None = None,
        decision: Any = None,
        plan: Any = None
    ) -> dict[str, Any]:
        incident_id = incident["incident_id"]
        existing = self.get_alert_by_incident(incident_id)

        severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        now = utc_now()

        new_evidence = []
        if decision and hasattr(decision, "evidence") and decision.evidence:
            new_evidence = list(decision.evidence)
        elif incident.get("evidence"):
            new_evidence = list(incident["evidence"])

        inc_sev = (incident.get("severity") or "MEDIUM").upper()
        evt_sev = (getattr(event, "severity", None) or (event.get("severity") if isinstance(event, dict) else None) or "MEDIUM").upper()
        effective_sev = inc_sev if severity_rank.get(inc_sev, 2) >= severity_rank.get(evt_sev, 2) else evt_sev

        conf = float(incident.get("confidence") or (getattr(decision, "confidence", None) or 0.95))
        act = (getattr(plan, "action", None) or incident.get("response_action") or "ISOLATE")

        if existing:
            prev_sev = existing.get("severity", "MEDIUM")
            is_escalation = (
                severity_rank.get(effective_sev, 2) > severity_rank.get(prev_sev, 2)
                or (existing.get("lifecycle_state") == "RECOVERING" and severity_rank.get(effective_sev, 2) >= 2)
            )
            if severity_rank.get(effective_sev, 2) < severity_rank.get(prev_sev, 2):
                effective_sev = prev_sev
            effective_conf = max(float(existing.get("confidence") or 0.0), conf)
            merged_evidence = list(dict.fromkeys(existing.get("evidence", []) + new_evidence))
            new_state = incident.get("lifecycle_state") or existing.get("lifecycle_state", "DETECTED")
            new_status = "RESOLVED" if new_state == "RESOLVED" else ("CLOSED" if new_state == "CLOSED" else existing.get("status", "ACTIVE"))

            ack_state = existing.get("acknowledgement_state", "UNACKNOWLEDGED")
            if is_escalation and ack_state == "ACKNOWLEDGED":
                ack_state = "RE_ESCALATED"
                self.record_audit(
                    username="system",
                    role="SYSTEM",
                    action="ALERT_RE_ESCALATED",
                    resource="alert",
                    resource_id=existing["alert_id"],
                    result="SUCCESS",
                    details=f"Alert {existing['alert_id']} re-escalated from {prev_sev} to {effective_sev} due to intensified attack activity",
                    source_ip="127.0.0.1",
                )

            with self.connection() as con:
                con.execute(
                    "UPDATE admin_alerts SET timestamp = ?, severity = ?, confidence = ?, lifecycle_state = ?, "
                    "current_action = ?, status = ?, acknowledgement_state = ?, evidence_json = ? WHERE alert_id = ?",
                    (
                        now,
                        effective_sev,
                        round(effective_conf, 3),
                        new_state,
                        f"{act} (DRY_RUN)",
                        new_status,
                        ack_state,
                        json.dumps(merged_evidence),
                        existing["alert_id"],
                    )
                )
            return self.get_alert(existing["alert_id"])  # type: ignore[return-value]

        alert_id = f"ALT-{datetime.now(timezone.utc):%Y%m%d}-{uuid4().hex[:6].upper()}"
        attack_type = incident.get("attack_type") or (getattr(event, "attack_type", None) if event else "ANOMALY") or "ANOMALY"
        dev_id = incident.get("device_id") or (getattr(event, "device_id", None) if event else None) or "SENSOR-01"
        src_id = incident.get("source_id") or (getattr(event, "source_id", None) if event else None)
        reason = new_evidence[0] if new_evidence else f"Automated detection of {attack_type} campaign"
        state = incident.get("lifecycle_state") or "DETECTED"
        status = "RESOLVED" if state == "RESOLVED" else ("CLOSED" if state == "CLOSED" else "ACTIVE")

        with self.connection() as con:
            con.execute(
                "INSERT INTO admin_alerts (alert_id, incident_id, timestamp, severity, attack_type, device_id, "
                "source_id, target, confidence, detection_reason, lifecycle_state, recommended_action, "
                "current_action, acknowledgement_state, acknowledged_by, acknowledged_at, status, evidence_json) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    alert_id,
                    incident_id,
                    now,
                    effective_sev,
                    attack_type,
                    dev_id,
                    src_id,
                    "AICG-GW-01 / OT Cell",
                    round(conf, 3),
                    reason,
                    state,
                    f"{act} (DRY_RUN)",
                    f"{act} (DRY_RUN)",
                    "UNACKNOWLEDGED",
                    None,
                    None,
                    status,
                    json.dumps(new_evidence),
                )
            )
        return self.get_alert(alert_id)  # type: ignore[return-value]

    def sync_alert_with_incident(self, incident: dict[str, Any]) -> dict[str, Any] | None:
        existing = self.get_alert_by_incident(incident["incident_id"])
        if not existing:
            return None
        new_state = incident.get("lifecycle_state") or existing["lifecycle_state"]
        new_status = "RESOLVED" if new_state == "RESOLVED" else ("CLOSED" if new_state == "CLOSED" else "ACTIVE")
        now = utc_now()
        with self.connection() as con:
            con.execute(
                "UPDATE admin_alerts SET lifecycle_state = ?, status = ?, timestamp = ? WHERE alert_id = ?",
                (new_state, new_status, now, existing["alert_id"])
            )
        return self.get_alert(existing["alert_id"])

    def acknowledge_alert(self, alert_id: str, username: str) -> dict[str, Any]:
        existing = self.get_alert(alert_id)
        if not existing:
            raise KeyError(f"Unknown alert: {alert_id}")
        now = utc_now()
        with self.connection() as con:
            con.execute(
                "UPDATE admin_alerts SET acknowledgement_state = 'ACKNOWLEDGED', acknowledged_by = ?, acknowledged_at = ? WHERE alert_id = ?",
                (username, now, alert_id)
            )
        return self.get_alert(alert_id)  # type: ignore[return-value]

    def list_alerts(
        self,
        limit: int = 100,
        status: str | None = None,
        ack_state: str | None = None,
        severity: str | None = None
    ) -> list[dict[str, Any]]:
        clauses, params = [], []
        if status:
            clauses.append("status = ?")
            params.append(status.upper())
        if ack_state:
            clauses.append("acknowledgement_state = ?")
            params.append(ack_state.upper())
        if severity:
            clauses.append("severity = ?")
            params.append(severity.upper())
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(max(1, min(limit, 1000)))
        with self.connection() as con:
            rows = con.execute(f"SELECT * FROM admin_alerts{where} ORDER BY timestamp DESC LIMIT ?", params).fetchall()
        return [self._alert_row(row) for row in rows]

    def record_audit(
        self,
        username: str,
        role: str,
        action: str,
        resource: str,
        resource_id: str | None = None,
        result: str = "SUCCESS",
        details: str = "",
        source_ip: str | None = None
    ) -> dict[str, Any]:
        event_id = f"AUD-{datetime.now(timezone.utc):%Y%m%d}-{uuid4().hex[:8].upper()}"
        now = utc_now()
        safe_details = str(details)
        for keyword in ["password", "token", "hash", "secret"]:
            if keyword in safe_details.lower() and "=" in safe_details:
                import re
                safe_details = re.sub(rf"{keyword}\s*=\s*[^\s,]+", f"{keyword}=[REDACTED]", safe_details, flags=re.IGNORECASE)

        item = {
            "event_id": event_id,
            "timestamp": now,
            "username": username or "system",
            "role": (role or "UNKNOWN").upper(),
            "action": action.upper(),
            "resource": resource,
            "resource_id": resource_id,
            "result": result.upper(),
            "source_ip": source_ip or "127.0.0.1",
            "details": safe_details,
        }
        max_retries = 5
        base_backoff = 0.05
        with self._audit_lock:
            for attempt in range(max_retries):
                try:
                    with self.connection() as con:
                        con.execute("BEGIN IMMEDIATE")
                        last_row = con.execute("SELECT record_hash FROM admin_audit_log ORDER BY rowid DESC LIMIT 1").fetchone()
                        prev_hash = str(last_row["record_hash"]) if (last_row and last_row["record_hash"]) else GENESIS_HASH
                        record_hash = self._compute_audit_hash(
                            prev_hash=prev_hash,
                            event_id=event_id,
                            timestamp=now,
                            username=username or "system",
                            role=(role or "UNKNOWN").upper(),
                            action=action.upper(),
                            resource=resource,
                            resource_id=resource_id,
                            result=result.upper(),
                            source_ip=source_ip or "127.0.0.1",
                            details=safe_details,
                        )
                        item["prev_hash"] = prev_hash
                        item["record_hash"] = record_hash
                        con.execute(
                            "INSERT INTO admin_audit_log (event_id, timestamp, username, role, action, resource, resource_id, result, source_ip, details, prev_hash, record_hash) "
                            "VALUES (:event_id, :timestamp, :username, :role, :action, :resource, :resource_id, :result, :source_ip, :details, :prev_hash, :record_hash)",
                            item
                        )
                    break
                except sqlite3.OperationalError as exc:
                    if "locked" in str(exc).lower() and attempt < max_retries - 1:
                        time.sleep(base_backoff * (2 ** attempt))
                        continue
                    raise
        return item

    def verify_audit_log_integrity(self) -> dict[str, Any]:
        with self.connection() as con:
            rows = con.execute("SELECT rowid, * FROM admin_audit_log ORDER BY rowid ASC").fetchall()

        if not rows:
            return {"valid": True, "count": 0, "first_corrupted_id": None, "reason": None}

        expected_prev = GENESIS_HASH
        for idx, row in enumerate(rows):
            event_id = row["event_id"]
            prev_hash = row["prev_hash"]
            record_hash = row["record_hash"]

            if prev_hash != expected_prev:
                return {
                    "valid": False,
                    "count": len(rows),
                    "corrupted_index": idx,
                    "first_corrupted_id": event_id,
                    "reason": f"Broken chain at record {event_id}: expected prev_hash {expected_prev}, got {prev_hash}",
                }

            computed = self._compute_audit_hash(
                prev_hash=prev_hash,
                event_id=event_id,
                timestamp=row["timestamp"],
                username=row["username"],
                role=row["role"],
                action=row["action"],
                resource=row["resource"],
                resource_id=row["resource_id"],
                result=row["result"],
                source_ip=row["source_ip"],
                details=row["details"],
            )
            if computed != record_hash:
                return {
                    "valid": False,
                    "count": len(rows),
                    "corrupted_index": idx,
                    "first_corrupted_id": event_id,
                    "reason": f"Hash mismatch at record {event_id}: expected {computed}, got {record_hash}",
                }
            expected_prev = record_hash

        return {"valid": True, "count": len(rows), "first_corrupted_id": None, "reason": None}

    def list_audit_logs(
        self,
        limit: int = 100,
        action: str | None = None,
        username: str | None = None
    ) -> list[dict[str, Any]]:
        clauses, params = [], []
        if action:
            clauses.append("action = ?")
            params.append(action.upper())
        if username:
            clauses.append("username = ?")
            params.append(username)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(max(1, min(limit, 1000)))
        with self.connection() as con:
            rows = con.execute(f"SELECT * FROM admin_audit_log{where} ORDER BY timestamp DESC LIMIT ?", params).fetchall()
        return [dict(row) for row in rows]

    def get_device_identity(self, device_id: str) -> dict[str, Any] | None:
        with self.connection() as con:
            row = con.execute("SELECT * FROM device_identities WHERE device_id = ?", (device_id,)).fetchone()
        return dict(row) if row else None

    def list_device_identities(self, status: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM device_identities"
        params: list[Any] = []
        if status:
            query += " WHERE status = ?"
            params.append(status.upper())
        query += " ORDER BY device_id ASC"
        with self.connection() as con:
            rows = con.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def upsert_device_identity(
        self,
        device_id: str,
        role: str = "sensor",
        auth_key_hash: str = "",
        status: str = "ENROLLED",
        trust_score: float = 100.0,
        failures: int = 0,
        mfa_status: str = "NOT_REQUIRED",
    ) -> dict[str, Any]:
        now = utc_now()
        with self.connection() as con:
            con.execute(
                """
                INSERT INTO device_identities (device_id, role, status, auth_key_hash, trust_score, failures, mfa_status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    role = excluded.role,
                    status = excluded.status,
                    auth_key_hash = CASE WHEN excluded.auth_key_hash != '' THEN excluded.auth_key_hash ELSE device_identities.auth_key_hash END,
                    trust_score = excluded.trust_score,
                    failures = excluded.failures,
                    mfa_status = excluded.mfa_status
                """,
                (device_id, role.lower(), status.upper(), auth_key_hash, trust_score, failures, mfa_status, now),
            )
        return self.get_device_identity(device_id) or {}

    def update_device_trust(self, device_id: str, score: float, failures: int | None = None) -> None:
        with self.connection() as con:
            if failures is not None:
                con.execute("UPDATE device_identities SET trust_score = ?, failures = ? WHERE device_id = ?", (score, failures, device_id))
            else:
                con.execute("UPDATE device_identities SET trust_score = ? WHERE device_id = ?", (score, device_id))

    def update_device_last_seen(self, device_id: str, timestamp: str | None = None) -> None:
        ts = timestamp or utc_now()
        with self.connection() as con:
            con.execute("UPDATE device_identities SET last_seen = ? WHERE device_id = ?", (ts, device_id))

    def set_device_status(self, device_id: str, status: str) -> dict[str, Any] | None:
        with self.connection() as con:
            con.execute("UPDATE device_identities SET status = ? WHERE device_id = ?", (status.upper(), device_id))
        return self.get_device_identity(device_id)


# =============================================================================
# POSTGRESQL ENGINE IMPLEMENTATION (SUPABASE / CLOUD POSTGRESQL INTEGRATION)
# =============================================================================

class PostgresGatewayStore(GatewayStore):
    """Production PostgreSQL historian utilizing ThreadedConnectionPool and advisory locking."""

    def __init__(
        self,
        database_url: str,
        master_key: str | None = None,
        production: bool = False,
        allow_demo_accounts: bool = True,
        initial_admin_username: str | None = None,
        initial_admin_password: str | None = None,
        min_connections: int = 1,
        max_connections: int = 10,
        initialize: bool = True,
    ):
        if psycopg2 is None:
            raise RuntimeError(
                "psycopg2-binary is required for PostgresGatewayStore. "
                "Ensure psycopg2-binary is installed."
            )
        self.database_url = database_url
        self.master_key = master_key
        self.production = production
        self.allow_demo_accounts = allow_demo_accounts
        self.initial_admin_username = initial_admin_username or "admin"
        self.initial_admin_password = initial_admin_password
        self._audit_lock = threading.RLock()

        self._pool: psycopg2.pool.ThreadedConnectionPool | None = psycopg2.pool.ThreadedConnectionPool(
            min_connections,
            max_connections,
            self.database_url,
        )
        if initialize:
            self.initialize()

    @contextmanager
    def connection(self) -> Iterator[Any]:
        """Borrow connection from pool with strict error handling, rollback, and broken eviction."""
        if self._pool is None:
            raise RuntimeError("PostgresGatewayStore connection pool is closed or not initialized.")
        con = self._pool.getconn()
        is_broken = False
        original_exc: BaseException | None = None
        try:
            yield con
            if not getattr(con, "closed", True):
                status = getattr(con, "status", None)
                txn_status = (
                    con.get_transaction_status()
                    if hasattr(con, "get_transaction_status")
                    else None
                )
                if status == STATUS_IN_TRANSACTION or txn_status == TRANSACTION_STATUS_INTRANS:
                    con.commit()
                elif txn_status == TRANSACTION_STATUS_INERROR:
                    is_broken = True
                    con.rollback()
        except BaseException as exc:
            original_exc = exc
            if not getattr(con, "closed", True):
                try:
                    con.rollback()
                except Exception as rollback_err:
                    is_broken = True
                    logger.debug("Failed to rollback PostgreSQL connection: %s", rollback_err)
            else:
                is_broken = True
            raise
        finally:
            con_closed = getattr(con, "closed", True)
            status = getattr(con, "status", None)
            txn_status = (
                con.get_transaction_status()
                if hasattr(con, "get_transaction_status")
                else None
            )

            if (
                con_closed
                or is_broken
                or isinstance(original_exc, (psycopg2.OperationalError, psycopg2.InterfaceError))
                or status == STATUS_IN_TRANSACTION
                or txn_status in (TRANSACTION_STATUS_INTRANS, TRANSACTION_STATUS_INERROR)
            ):
                try:
                    self._pool.putconn(con, close=True)
                except Exception as put_close_err:
                    logger.debug("Failed to evict broken connection from pool: %s", put_close_err)
            else:
                try:
                    self._pool.putconn(con)
                except Exception as put_err:
                    logger.debug("Failed to return connection to pool, evicting: %s", put_err)
                    try:
                        self._pool.putconn(con, close=True)
                    except Exception:
                        pass

    def close(self) -> None:
        """Safely drain and close all connections in the pool."""
        if hasattr(self, "_pool") and self._pool is not None:
            try:
                self._pool.closeall()
            except Exception as close_err:
                logger.debug("Error during PostgreSQL pool closeall: %s", close_err)
            self._pool = None

    def __del__(self) -> None:
        self.close()

    def initialize(self) -> None:
        """Create PostgreSQL tables, sequences, indexes, and bootstrap identities."""
        canonical_columns = ",\n".join(f"{field} TEXT" for field in CANONICAL_FIELDS)
        ddl = f"""
        CREATE TABLE IF NOT EXISTS telemetry (
            seq_id BIGSERIAL PRIMARY KEY,
            {canonical_columns},
            raw_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS telemetry_timestamp_idx ON telemetry(timestamp DESC);
        CREATE INDEX IF NOT EXISTS telemetry_timestamp_seq_idx ON telemetry(timestamp DESC, seq_id DESC);
        CREATE INDEX IF NOT EXISTS telemetry_scenario_idx ON telemetry(scenario_id);
        CREATE INDEX IF NOT EXISTS telemetry_source_idx ON telemetry(source_type, source_id);
        CREATE INDEX IF NOT EXISTS telemetry_protocol_idx ON telemetry(protocol);

        CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            event_id TEXT NOT NULL,
            device_id TEXT,
            source_id TEXT,
            attack_type TEXT,
            severity TEXT,
            confidence DOUBLE PRECISION,
            evidence_json TEXT NOT NULL,
            affected_resources TEXT,
            energy_impact TEXT,
            iam_impact TEXT,
            trust_impact TEXT,
            response_action TEXT,
            response_mode TEXT,
            operator TEXT,
            lifecycle_state TEXT NOT NULL,
            recovery_state TEXT NOT NULL,
            resolved_at TEXT,
            provenance TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS incidents_state_idx ON incidents(lifecycle_state, severity);
        CREATE INDEX IF NOT EXISTS incidents_active_idx ON incidents(lifecycle_state, updated_at DESC);

        CREATE TABLE IF NOT EXISTS incident_history (
            history_id TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
            timestamp TEXT NOT NULL,
            previous_state TEXT,
            state TEXT NOT NULL,
            actor TEXT,
            note TEXT,
            evidence_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS incident_history_incident_idx ON incident_history(incident_id, timestamp);

        CREATE TABLE IF NOT EXISTS actions (
            action_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            event_id TEXT,
            incident_id TEXT REFERENCES incidents(incident_id) ON DELETE SET NULL,
            action TEXT NOT NULL,
            reason TEXT NOT NULL,
            policy TEXT NOT NULL,
            mode TEXT NOT NULL,
            result TEXT NOT NULL,
            provenance TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS actions_timestamp_idx ON actions(timestamp DESC);

        CREATE TABLE IF NOT EXISTS iam_events (
            iam_event_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            identity TEXT,
            role TEXT,
            authentication_status TEXT,
            authorization_status TEXT,
            access_request TEXT,
            decision TEXT,
            reason TEXT,
            provenance TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS iam_timestamp_idx ON iam_events(timestamp DESC);

        CREATE TABLE IF NOT EXISTS trust_history (
            seq_id BIGSERIAL UNIQUE,
            trust_event_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            identity TEXT NOT NULL,
            score DOUBLE PRECISION NOT NULL,
            delta DOUBLE PRECISION NOT NULL,
            reason TEXT NOT NULL,
            provenance TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS trust_identity_idx ON trust_history(identity, timestamp DESC);

        CREATE TABLE IF NOT EXISTS metadata (
            metadata_id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            version TEXT NOT NULL,
            created_at TEXT NOT NULL,
            payload_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS metadata_kind_idx ON metadata(kind, created_at DESC);

        CREATE TABLE IF NOT EXISTS admin_users (
            user_id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            status TEXT NOT NULL,
            mfa_enabled INTEGER NOT NULL DEFAULT 1,
            mfa_status TEXT NOT NULL DEFAULT 'SIMULATED_VERIFIED',
            created_at TEXT NOT NULL,
            last_login TEXT,
            must_change_password BOOLEAN NOT NULL DEFAULT FALSE
        );
        CREATE INDEX IF NOT EXISTS admin_users_username_idx ON admin_users(username);

        CREATE TABLE IF NOT EXISTS admin_alerts (
            alert_id TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL UNIQUE REFERENCES incidents(incident_id) ON DELETE CASCADE,
            timestamp TEXT NOT NULL,
            severity TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            device_id TEXT,
            source_id TEXT,
            target TEXT NOT NULL,
            confidence DOUBLE PRECISION NOT NULL,
            detection_reason TEXT NOT NULL,
            lifecycle_state TEXT NOT NULL,
            recommended_action TEXT NOT NULL,
            current_action TEXT NOT NULL,
            acknowledgement_state TEXT NOT NULL DEFAULT 'UNACKNOWLEDGED',
            acknowledged_by TEXT,
            acknowledged_at TEXT,
            status TEXT NOT NULL DEFAULT 'ACTIVE',
            evidence_json TEXT NOT NULL DEFAULT '[]'
        );
        CREATE INDEX IF NOT EXISTS admin_alerts_incident_idx ON admin_alerts(incident_id);
        CREATE INDEX IF NOT EXISTS admin_alerts_status_idx ON admin_alerts(status, acknowledgement_state);

        CREATE TABLE IF NOT EXISTS admin_audit_log (
            seq_id BIGSERIAL PRIMARY KEY,
            event_id TEXT UNIQUE NOT NULL,
            timestamp TEXT NOT NULL,
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            action TEXT NOT NULL,
            resource TEXT NOT NULL,
            resource_id TEXT,
            result TEXT NOT NULL,
            source_ip TEXT,
            details TEXT NOT NULL,
            prev_hash TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
            record_hash TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS admin_audit_timestamp_idx ON admin_audit_log(timestamp DESC);
        CREATE INDEX IF NOT EXISTS admin_audit_action_idx ON admin_audit_log(action);

        CREATE TABLE IF NOT EXISTS device_identities (
            device_id TEXT PRIMARY KEY,
            role TEXT NOT NULL DEFAULT 'sensor',
            status TEXT NOT NULL DEFAULT 'ENROLLED',
            auth_key_hash TEXT NOT NULL,
            trust_score DOUBLE PRECISION NOT NULL DEFAULT 100.0,
            failures INTEGER NOT NULL DEFAULT 0,
            mfa_status TEXT NOT NULL DEFAULT 'NOT_REQUIRED',
            created_at TEXT NOT NULL,
            last_seen TEXT
        );
        CREATE INDEX IF NOT EXISTS device_identities_status_idx ON device_identities(status);
        """
        with self.connection() as con:
            with con.cursor() as cur:
                cur.execute(ddl)
                cur.execute("ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE;")
            self._seed_default_users(con)
            self._seed_default_device_identities(con)

    def _seed_default_users(self, con: Any) -> None:
        from .security import hash_password
        now = utc_now()

        with con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT COUNT(*) AS c FROM admin_users;")
            row = cur.fetchone()
            existing = row["c"] if row else 0
            if existing > 0:
                return

            if self.production:
                if not self.initial_admin_password or not self.initial_admin_password.strip():
                    raise RuntimeError(
                        "Production first-run bootstrap failed: AEGIS_INITIAL_ADMIN_PASSWORD is required "
                        "to initialize the initial administrator account. Set AEGIS_INITIAL_ADMIN_PASSWORD "
                        "in the environment to provision the administrator securely."
                    )
                admin_user = (self.initial_admin_username or "admin").strip()
                user_id = f"USR-ADMIN-{uuid4().hex[:8].upper()}"
                hashed = hash_password(self.initial_admin_password.strip())
                cur.execute(
                    """
                    INSERT INTO admin_users (user_id, username, password_hash, role, status, mfa_enabled, mfa_status, created_at, last_login, must_change_password)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (user_id) DO NOTHING;
                    """,
                    (user_id, admin_user, hashed, "ADMIN", "ACTIVE", 1, "SIMULATED_VERIFIED", now, None, False)
                )
            else:
                if self.allow_demo_accounts:
                    admin_pw = self.initial_admin_password.strip() if self.initial_admin_password else "Admin@AICG2026!"
                    admin_user = (self.initial_admin_username or "admin").strip()
                    operator_pw = os.getenv("AEGIS_INITIAL_OPERATOR_PASSWORD", "Operator@AICG2026!").strip()
                    defaults = [
                        ("USR-ADMIN-01", admin_user, hash_password(admin_pw), "ADMIN", "ACTIVE", 1, "SIMULATED_VERIFIED", now, None, False),
                        ("USR-OPERATOR-01", "operator", hash_password(operator_pw), "OPERATOR", "ACTIVE", 1, "SIMULATED_VERIFIED", now, None, False),
                    ]
                    for u_row in defaults:
                        cur.execute(
                            """
                            INSERT INTO admin_users (user_id, username, password_hash, role, status, mfa_enabled, mfa_status, created_at, last_login, must_change_password)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (user_id) DO NOTHING;
                            """,
                            u_row
                        )

    def _seed_default_device_identities(self, con: Any) -> None:
        from .iam import DEFAULT_MASTER_KEY, derive_device_key, hash_device_key
        now = utc_now()
        devices = [
            ("SENSOR-01", "sensor", "ENROLLED", 100.0, 0, "NOT_REQUIRED"),
            ("SENSOR-02", "sensor", "ENROLLED", 100.0, 0, "NOT_REQUIRED"),
            ("SENSOR-03", "sensor", "ENROLLED", 100.0, 0, "NOT_REQUIRED"),
            ("SENSOR-GROUP-A", "sensor", "ENROLLED", 100.0, 0, "NOT_REQUIRED"),
            ("ATK-01", "untrusted", "REVOKED", 35.0, 0, "FAILED"),
            ("ATTACKER-01", "untrusted", "REVOKED", 35.0, 0, "FAILED"),
            ("ATTACKER-02", "untrusted", "REVOKED", 35.0, 0, "FAILED"),
            ("ATTACKER-03", "untrusted", "REVOKED", 35.0, 0, "FAILED"),
            ("ATTACKER-04", "untrusted", "REVOKED", 35.0, 0, "FAILED"),
            ("ATTACKER-05", "untrusted", "REVOKED", 35.0, 0, "FAILED"),
            ("ATTACKER-06", "untrusted", "REVOKED", 35.0, 0, "FAILED"),
            ("operator", "operator", "ENROLLED", 100.0, 0, "VERIFIED"),
        ]
        eff_key = getattr(self, "master_key", None) or DEFAULT_MASTER_KEY
        with con.cursor() as cur:
            for dev_id, role, status, trust, fails, mfa in devices:
                if role == "untrusted":
                    h = hash_device_key(f"untrusted-key-{dev_id}")
                else:
                    psk = derive_device_key(dev_id, eff_key)
                    h = hash_device_key(psk)
                cur.execute(
                    """
                    INSERT INTO device_identities
                    (device_id, role, status, auth_key_hash, trust_score, failures, mfa_status, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (device_id) DO NOTHING;
                    """,
                    (dev_id, role, status, h, trust, fails, mfa, now),
                )

    def append_telemetry(self, event: TelemetryEvent) -> None:
        event.normalize()
        values = event.to_dict()
        values.pop("auth_token", None)
        columns = CANONICAL_FIELDS + ["raw_json"]
        stored = [None if values.get(name) is None else str(values[name]) for name in CANONICAL_FIELDS]
        stored.append(json.dumps(values, sort_keys=True))
        placeholders = ",".join("%s" for _ in columns)
        with self.connection() as con:
            with con.cursor() as cur:
                cur.execute(f"INSERT INTO telemetry ({','.join(columns)}) VALUES ({placeholders});", stored)

    def telemetry(self, limit: int = 100, source_type: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT raw_json FROM telemetry"
        params: list[Any] = []
        if source_type:
            query += " WHERE source_type = %s"
            params.append(source_type.upper())
        query += " ORDER BY timestamp DESC, seq_id DESC LIMIT %s;"
        params.append(max(1, min(limit, 5000)))
        with self.connection() as con:
            with con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(query, params)
                rows = cur.fetchall()
        return [json.loads(row["raw_json"]) for row in reversed(rows)]

    def create_incident(self, event: TelemetryEvent, evidence: list[str], affected_resources: str) -> dict[str, Any]:
        incident_id = f"INC-{datetime.now(timezone.utc):%Y%m%d}-{uuid4().hex[:8].upper()}"
        now = utc_now()
        values = {
            "incident_id": incident_id, "created_at": now, "updated_at": now, "event_id": event.event_id,
            "device_id": event.device_id, "source_id": event.source_id, "attack_type": event.attack_type,
            "severity": event.severity, "confidence": event.confidence, "evidence_json": json.dumps(evidence),
            "affected_resources": affected_resources, "energy_impact": event.energy_cause,
            "iam_impact": event.access_decision, "trust_impact": str(event.trust_score),
            "response_action": event.response_action, "response_mode": event.response_mode, "operator": "system",
            "lifecycle_state": "DETECTED", "recovery_state": "PENDING", "resolved_at": None,
            "provenance": event.provenance,
        }
        with self.connection() as con:
            with con.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO incidents (
                        incident_id, created_at, updated_at, event_id, device_id, source_id, attack_type,
                        severity, confidence, evidence_json, affected_resources, energy_impact, iam_impact,
                        trust_impact, response_action, response_mode, operator, lifecycle_state, recovery_state,
                        resolved_at, provenance
                    ) VALUES (
                        %(incident_id)s, %(created_at)s, %(updated_at)s, %(event_id)s, %(device_id)s,
                        %(source_id)s, %(attack_type)s, %(severity)s, %(confidence)s, %(evidence_json)s,
                        %(affected_resources)s, %(energy_impact)s, %(iam_impact)s, %(trust_impact)s,
                        %(response_action)s, %(response_mode)s, %(operator)s, %(lifecycle_state)s,
                        %(recovery_state)s, %(resolved_at)s, %(provenance)s
                    );
                    """,
                    values,
                )
                cur.execute(
                    """
                    INSERT INTO incident_history (
                        history_id, incident_id, timestamp, previous_state, state, actor, note, evidence_json
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
                    """,
                    (str(uuid4()), incident_id, now, None, "DETECTED", "system", "Detection opened incident", json.dumps(evidence)),
                )
        return self.incident(incident_id) or values

    def incidents(self, limit: int = 100, severity: str | None = None, state: str | None = None) -> list[dict[str, Any]]:
        clauses, params = [], []
        if severity:
            clauses.append("severity = %s")
            params.append(severity.upper())
        if state:
            clauses.append("lifecycle_state = %s")
            params.append(state.upper())
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(max(1, min(limit, 1000)))
        with self.connection() as con:
            with con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(f"SELECT * FROM incidents{where} ORDER BY created_at DESC LIMIT %s;", params)
                rows = cur.fetchall()
        return [self._incident_row(row) for row in rows]

    def incident(self, incident_id: str) -> dict[str, Any] | None:
        with self.connection() as con:
            with con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM incidents WHERE incident_id = %s;", (incident_id,))
                row = cur.fetchone()
                cur.execute("SELECT * FROM incident_history WHERE incident_id = %s ORDER BY timestamp;", (incident_id,))
                history = cur.fetchall()
        if not row:
            return None
        result = self._incident_row(row)
        result["history"] = [{**dict(item), "evidence": json.loads(item["evidence_json"])} for item in history]
        return result

    def find_active_incident(self, device_id: str | None = None, attack_type: str | None = None) -> dict[str, Any] | None:
        clauses = ["lifecycle_state NOT IN ('RESOLVED', 'CLOSED')"]
        params: list[Any] = []
        if device_id and attack_type:
            clauses.append("device_id = %s AND attack_type = %s")
            params.extend([device_id, attack_type])
        elif device_id:
            clauses.append("device_id = %s")
            params.append(device_id)
        elif attack_type:
            clauses.append("attack_type = %s")
            params.append(attack_type)
        where = f"WHERE {' AND '.join(clauses)}"
        with self.connection() as con:
            with con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(f"SELECT * FROM incidents {where} ORDER BY updated_at DESC LIMIT 1;", params)
                row = cur.fetchone()
        return self._incident_row(row) if row else None

    def correlate_incident(
        self,
        incident_id: str,
        event: TelemetryEvent,
        new_evidence: list[str],
        note: str = "Correlated ongoing campaign activity"
    ) -> dict[str, Any]:
        current = self.incident(incident_id)
        if not current:
            raise KeyError(f"Unknown incident: {incident_id}")
        now = utc_now()
        merged_evidence = list(dict.fromkeys(current.get("evidence", []) + new_evidence))
        severity_rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        curr_sev = current.get("severity") or "MEDIUM"
        new_sev = event.severity or "MEDIUM"
        effective_sev = new_sev if severity_rank.get(new_sev, 2) > severity_rank.get(curr_sev, 2) else curr_sev
        effective_conf = max(float(current.get("confidence") or 0.0), float(event.confidence or 0.0))

        prev_state = current["lifecycle_state"]
        if prev_state == "RECOVERING":
            effective_state = "CONTAINED"
            history_note = "Attack activity resumed during recovery verification; state regressed from RECOVERING to CONTAINED."
        else:
            effective_state = prev_state
            history_note = note

        with self.connection() as con:
            with con.cursor() as cur:
                cur.execute(
                    """
                    UPDATE incidents SET updated_at=%s, event_id=%s, severity=%s, confidence=%s, evidence_json=%s,
                    energy_impact=%s, iam_impact=%s, trust_impact=%s, response_action=%s, lifecycle_state=%s
                    WHERE incident_id=%s;
                    """,
                    (now, event.event_id, effective_sev, round(effective_conf, 3), json.dumps(merged_evidence),
                     event.energy_cause or current.get("energy_impact"),
                     event.access_decision or current.get("iam_impact"),
                     str(event.trust_score) if event.trust_score is not None else current.get("trust_impact"),
                     event.response_action or current.get("response_action"),
                     effective_state,
                     incident_id),
                )
                cur.execute(
                    """
                    INSERT INTO incident_history (history_id, incident_id, timestamp, previous_state, state, actor, note, evidence_json)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
                    """,
                    (str(uuid4()), incident_id, now, prev_state, effective_state,
                     "system", history_note, json.dumps(new_evidence)),
                )
        return self.incident(incident_id)  # type: ignore[return-value]

    def transition_incident(
        self,
        incident_id: str,
        state: str,
        actor: str,
        note: str,
        evidence: list[str] | None = None
    ) -> dict[str, Any]:
        allowed = {
            "DETECTED": {"TRIAGED", "RESPONDING", "CONTAINED", "CLOSED"},
            "TRIAGED": {"RESPONDING", "CONTAINED", "CLOSED"},
            "RESPONDING": {"CONTAINED", "RECOVERING", "CLOSED"},
            "CONTAINED": {"RECOVERING", "RESPONDING", "RESOLVED", "CLOSED"},
            "RECOVERING": {"RESOLVED", "RESPONDING", "CONTAINED", "CLOSED"},
            "RESOLVED": {"CLOSED", "RESPONDING"},
            "CLOSED": {"RESPONDING", "DETECTED"},
        }
        current = self.incident(incident_id)
        if not current:
            raise KeyError(f"Unknown incident: {incident_id}")
        state = state.upper()
        if state == current["lifecycle_state"]:
            return current
        if state not in allowed.get(current["lifecycle_state"], set()):
            raise ValueError(f"Invalid transition {current['lifecycle_state']} -> {state}")
        now = utc_now()
        recovery = "VERIFIED" if state in {"RESOLVED", "CLOSED"} else current["recovery_state"]
        with self.connection() as con:
            with con.cursor() as cur:
                cur.execute(
                    "UPDATE incidents SET lifecycle_state=%s, recovery_state=%s, updated_at=%s, resolved_at=%s WHERE incident_id=%s;",
                    (state, recovery, now, now if state == "RESOLVED" else current["resolved_at"], incident_id)
                )
                cur.execute(
                    "INSERT INTO incident_history (history_id, incident_id, timestamp, previous_state, state, actor, note, evidence_json) VALUES (%s, %s, %s, %s, %s, %s, %s, %s);",
                    (str(uuid4()), incident_id, now, current["lifecycle_state"], state, actor, note, json.dumps(evidence or []))
                )
                alert_status = "RESOLVED" if state == "RESOLVED" else ("CLOSED" if state == "CLOSED" else "ACTIVE")
                cur.execute(
                    "UPDATE admin_alerts SET lifecycle_state = %s, status = %s, timestamp = %s WHERE incident_id = %s;",
                    (state, alert_status, now, incident_id)
                )
        return self.incident(incident_id)  # type: ignore[return-value]

    def reset_active_incidents_and_alerts(self, actor: str = "system", note: str = "Simulation reset") -> int:
        now = utc_now()
        with self.connection() as con:
            with con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT incident_id, lifecycle_state FROM incidents WHERE lifecycle_state NOT IN ('RESOLVED', 'CLOSED');"
                )
                rows = cur.fetchall()
                if not rows:
                    return 0
                inc_ids = [r["incident_id"] for r in rows]
                placeholders = ",".join("%s" for _ in inc_ids)

                cur.execute(
                    f"UPDATE incidents SET lifecycle_state = 'CLOSED', recovery_state = 'RESET', "
                    f"updated_at = %s, resolved_at = %s WHERE incident_id IN ({placeholders});",
                    [now, now] + inc_ids,
                )
                for r in rows:
                    cur.execute(
                        "INSERT INTO incident_history (history_id, incident_id, timestamp, previous_state, state, actor, note, evidence_json) VALUES (%s, %s, %s, %s, %s, %s, %s, %s);",
                        (str(uuid4()), r["incident_id"], now, r["lifecycle_state"], "CLOSED", actor, note, "[]"),
                    )
                cur.execute(
                    f"UPDATE admin_alerts SET status = 'CLOSED', lifecycle_state = 'CLOSED', timestamp = %s "
                    f"WHERE incident_id IN ({placeholders});",
                    [now] + inc_ids,
                )
                return len(inc_ids)

    def record_action(
        self,
        *,
        event_id: str | None,
        incident_id: str | None,
        action: str,
        reason: str,
        policy: str,
        mode: str,
        result: str,
        provenance: str = "SIMULATED"
    ) -> dict[str, Any]:
        item = {
            "action_id": str(uuid4()), "timestamp": utc_now(), "event_id": event_id, "incident_id": incident_id,
            "action": action, "reason": reason, "policy": policy, "mode": mode, "result": result, "provenance": provenance
        }
        with self.connection() as con:
            with con.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO actions (
                        action_id, timestamp, event_id, incident_id, action, reason, policy, mode, result, provenance
                    ) VALUES (
                        %(action_id)s, %(timestamp)s, %(event_id)s, %(incident_id)s, %(action)s, %(reason)s, %(policy)s, %(mode)s, %(result)s, %(provenance)s
                    );
                    """,
                    item,
                )
        return item

    def actions(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.connection() as con:
            with con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM actions ORDER BY timestamp DESC LIMIT %s;",
                    (max(1, min(limit, 1000)),)
                )
                rows = cur.fetchall()
        return [dict(row) for row in rows]

    def record_iam(self, item: dict[str, Any]) -> None:
        defaults = {
            "iam_event_id": str(uuid4()),
            "timestamp": utc_now(),
            "identity": None,
            "role": None,
            "authentication_status": "AUTHENTICATED",
            "authorization_status": "AUTHORIZED",
            "access_request": "TELEMETRY_INGEST",
            "decision": "ALLOW",
            "reason": "Normal operational access",
            "provenance": "DERIVED",
        }
        payload = {**defaults, **item}
        payload.pop("auth_token", None)
        with self.connection() as con:
            with con.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO iam_events (
                        iam_event_id, timestamp, identity, role, authentication_status, authorization_status,
                        access_request, decision, reason, provenance
                    ) VALUES (
                        %(iam_event_id)s, %(timestamp)s, %(identity)s, %(role)s, %(authentication_status)s,
                        %(authorization_status)s, %(access_request)s, %(decision)s, %(reason)s, %(provenance)s
                    );
                    """,
                    payload,
                )

    def record_trust(self, identity: str, score: float, delta: float, reason: str) -> None:
        with self.connection() as con:
            with con.cursor() as cur:
                cur.execute(
                    "INSERT INTO trust_history (trust_event_id, timestamp, identity, score, delta, reason, provenance) VALUES (%s, %s, %s, %s, %s, %s, %s);",
                    (str(uuid4()), utc_now(), identity, score, delta, reason, "DERIVED")
                )

    def trust(self, identity: str | None = None, limit: int = 300) -> list[dict[str, Any]]:
        query = "SELECT * FROM trust_history"
        params: list[Any] = []
        if identity:
            query += " WHERE identity = %s"
            params.append(identity)
        query += " ORDER BY timestamp DESC, seq_id DESC LIMIT %s;"
        params.append(max(1, min(limit, 5000)))
        with self.connection() as con:
            with con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(query, params)
                rows = cur.fetchall()
        results: list[dict[str, Any]] = []
        for row in reversed(rows):
            item = dict(row)
            item.pop("seq_id", None)
            results.append(item)
        return results

    def put_metadata(self, kind: str, version: str, payload: dict[str, Any]) -> None:
        with self.connection() as con:
            with con.cursor() as cur:
                cur.execute(
                    "INSERT INTO metadata (metadata_id, kind, version, created_at, payload_json) VALUES (%s, %s, %s, %s, %s);",
                    (str(uuid4()), kind, version, utc_now(), json.dumps(payload, sort_keys=True))
                )

    def latest_metadata(self, kind: str) -> dict[str, Any] | None:
        with self.connection() as con:
            with con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM metadata WHERE kind = %s ORDER BY created_at DESC LIMIT 1;", (kind,))
                row = cur.fetchone()
        if not row:
            return None
        item = dict(row)
        item["payload"] = json.loads(item.pop("payload_json"))
        return item

    def prune(self, days: int) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max(days, 1))).isoformat()
        with self.connection() as con:
            with con.cursor() as cur:
                cur.execute("DELETE FROM telemetry WHERE timestamp < %s;", (cutoff,))
                return cur.rowcount

    def get_admin_user(self, username: str) -> dict[str, Any] | None:
        with self.connection() as con:
            with con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM admin_users WHERE username = %s;", (username,))
                row = cur.fetchone()
        if not row:
            return None
        item = dict(row)
        if "must_change_password" in item:
            item["must_change_password"] = bool(item["must_change_password"])
        return item

    def get_admin_user_by_id(self, user_id: str) -> dict[str, Any] | None:
        with self.connection() as con:
            with con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM admin_users WHERE user_id = %s;", (user_id,))
                row = cur.fetchone()
        if not row:
            return None
        item = dict(row)
        if "must_change_password" in item:
            item["must_change_password"] = bool(item["must_change_password"])
        return item

    def list_admin_users(self) -> list[dict[str, Any]]:
        with self.connection() as con:
            with con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT user_id, username, role, status, mfa_enabled, mfa_status, created_at, last_login, must_change_password FROM admin_users ORDER BY created_at ASC;")
                rows = cur.fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["must_change_password"] = bool(item.get("must_change_password", False))
            result.append(item)
        return result

    def create_admin_user(
        self,
        username: str,
        password_hash: str,
        role: str,
        status: str = "ACTIVE",
        mfa_enabled: int = 1,
        must_change_password: bool | int = False,
    ) -> dict[str, Any]:
        user_id = f"USR-{uuid4().hex[:8].upper()}"
        now = utc_now()
        must_change_val = bool(must_change_password)
        try:
            with self.connection() as con:
                with con.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO admin_users (user_id, username, password_hash, role, status, mfa_enabled, mfa_status, created_at, last_login, must_change_password)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
                        """,
                        (user_id, username, password_hash, role.upper(), status.upper(), mfa_enabled, "SIMULATED_VERIFIED", now, None, must_change_val)
                    )
        except Exception as err:
            if (psycopg2 and isinstance(err, psycopg2.IntegrityError)) or "unique" in str(err).lower() or "admin_users_username" in str(err).lower():
                raise ValueError(f"Username '{username}' already exists") from err
            raise
        return {
            "user_id": user_id,
            "username": username,
            "role": role.upper(),
            "status": status.upper(),
            "mfa_enabled": mfa_enabled,
            "mfa_status": "SIMULATED_VERIFIED",
            "created_at": now,
            "last_login": None,
            "must_change_password": must_change_val,
        }

    def update_admin_user_status(self, user_id: str, status: str) -> dict[str, Any]:
        status = status.upper()
        if status not in {"ACTIVE", "DISABLED"}:
            raise ValueError(f"Invalid status: {status}")
        with self.connection() as con:
            with con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT pg_advisory_xact_lock(%s);", (AICG_USER_MUTATION_ADVISORY_LOCK_ID,))
                cur.execute("SELECT role, status FROM admin_users WHERE user_id = %s FOR UPDATE;", (user_id,))
                target = cur.fetchone()
                if not target:
                    raise KeyError(f"User not found: {user_id}")
                if target["role"] == "ADMIN" and target["status"] == "ACTIVE" and status == "DISABLED":
                    cur.execute(
                        "SELECT COUNT(*) as cnt FROM admin_users WHERE role = 'ADMIN' AND status = 'ACTIVE' AND user_id != %s;",
                        (user_id,)
                    )
                    rem = cur.fetchone()
                    if rem and rem["cnt"] == 0:
                        raise ValueError("Cannot disable the last active administrator account")
                cur.execute("UPDATE admin_users SET status = %s WHERE user_id = %s;", (status, user_id))
        user = self.get_admin_user_by_id(user_id)
        if not user:
            raise KeyError(f"User not found: {user_id}")
        user.pop("password_hash", None)
        return user

    def update_admin_user_role(self, user_id: str, role: str) -> dict[str, Any]:
        role = role.upper()
        if role not in {"ADMIN", "OPERATOR"}:
            raise ValueError(f"Invalid role: {role}")
        with self.connection() as con:
            with con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT pg_advisory_xact_lock(%s);", (AICG_USER_MUTATION_ADVISORY_LOCK_ID,))
                cur.execute("SELECT role, status FROM admin_users WHERE user_id = %s FOR UPDATE;", (user_id,))
                target = cur.fetchone()
                if not target:
                    raise KeyError(f"User not found: {user_id}")
                if target["role"] == "ADMIN" and target["status"] == "ACTIVE" and role != "ADMIN":
                    cur.execute(
                        "SELECT COUNT(*) as cnt FROM admin_users WHERE role = 'ADMIN' AND status = 'ACTIVE' AND user_id != %s;",
                        (user_id,)
                    )
                    rem = cur.fetchone()
                    if rem and rem["cnt"] == 0:
                        raise ValueError("Cannot demote the last active administrator account")
                cur.execute("UPDATE admin_users SET role = %s WHERE user_id = %s;", (role, user_id))
        user = self.get_admin_user_by_id(user_id)
        if not user:
            raise KeyError(f"User not found: {user_id}")
        user.pop("password_hash", None)
        return user

    def update_admin_user_password(
        self,
        user_id: str,
        password_hash: str,
        must_change_password: bool | int | None = None,
    ) -> dict[str, Any]:
        if not password_hash or not isinstance(password_hash, str) or not password_hash.strip():
            raise ValueError("Password hash is required")
        user = self.get_admin_user_by_id(user_id)
        if not user:
            raise KeyError(f"User not found: {user_id}")
        with self.connection() as con:
            with con.cursor() as cur:
                if must_change_password is not None:
                    val = bool(must_change_password)
                    cur.execute(
                        "UPDATE admin_users SET password_hash = %s, must_change_password = %s WHERE user_id = %s;",
                        (password_hash, val, user_id),
                    )
                else:
                    cur.execute(
                        "UPDATE admin_users SET password_hash = %s WHERE user_id = %s;",
                        (password_hash, user_id),
                    )
        updated = self.get_admin_user_by_id(user_id)
        if not updated:
            raise KeyError(f"User not found: {user_id}")
        updated.pop("password_hash", None)
        return updated

    def update_admin_user_username(self, user_id: str, new_username: str) -> dict[str, Any]:
        new_username = str(new_username).strip()
        if not new_username:
            raise ValueError("Username cannot be empty")
        user = self.get_admin_user_by_id(user_id)
        if not user:
            raise KeyError(f"User not found: {user_id}")
        if user["username"] == new_username:
            user.pop("password_hash", None)
            return user
        try:
            with self.connection() as con:
                with con.cursor() as cur:
                    cur.execute("UPDATE admin_users SET username = %s WHERE user_id = %s;", (new_username, user_id))
        except Exception as err:
            if (psycopg2 and isinstance(err, psycopg2.IntegrityError)) or "unique" in str(err).lower() or "admin_users_username" in str(err).lower():
                raise ValueError(f"Username '{new_username}' already exists") from err
            raise
        updated = self.get_admin_user_by_id(user_id)
        if not updated:
            raise KeyError(f"User not found: {user_id}")
        updated.pop("password_hash", None)
        return updated

    def delete_admin_user(self, user_id: str) -> bool:
        if not user_id:
            return False
        with self.connection() as con:
            with con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT pg_advisory_xact_lock(%s);", (AICG_USER_MUTATION_ADVISORY_LOCK_ID,))
                cur.execute("SELECT role, status FROM admin_users WHERE user_id = %s FOR UPDATE;", (user_id,))
                target = cur.fetchone()
                if not target:
                    return False
                if target["role"] == "ADMIN" and target["status"] == "ACTIVE":
                    cur.execute(
                        "SELECT COUNT(*) as cnt FROM admin_users WHERE role = 'ADMIN' AND status = 'ACTIVE' AND user_id != %s;",
                        (user_id,)
                    )
                    rem = cur.fetchone()
                    if rem and rem["cnt"] == 0:
                        raise ValueError("Cannot delete the last remaining active administrator account")
                cur.execute("DELETE FROM admin_users WHERE user_id = %s;", (user_id,))
                return cur.rowcount > 0

    def record_admin_login(self, username: str) -> None:
        now = utc_now()
        with self.connection() as con:
            with con.cursor() as cur:
                cur.execute("UPDATE admin_users SET last_login = %s WHERE username = %s;", (now, username))

    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        with self.connection() as con:
            with con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM admin_alerts WHERE alert_id = %s;", (alert_id,))
                row = cur.fetchone()
        return self._alert_row(row) if row else None

    def get_alert_by_incident(self, incident_id: str) -> dict[str, Any] | None:
        with self.connection() as con:
            with con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM admin_alerts WHERE incident_id = %s;", (incident_id,))
                row = cur.fetchone()
        return self._alert_row(row) if row else None

    def create_or_update_alert(
        self,
        incident: dict[str, Any],
        event: TelemetryEvent | dict[str, Any] | None = None,
        decision: Any = None,
        plan: Any = None
    ) -> dict[str, Any]:
        incident_id = incident["incident_id"]
        existing = self.get_alert_by_incident(incident_id)

        severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        now = utc_now()

        new_evidence = []
        if decision and hasattr(decision, "evidence") and decision.evidence:
            new_evidence = list(decision.evidence)
        elif incident.get("evidence"):
            new_evidence = list(incident["evidence"])

        inc_sev = (incident.get("severity") or "MEDIUM").upper()
        evt_sev = (getattr(event, "severity", None) or (event.get("severity") if isinstance(event, dict) else None) or "MEDIUM").upper()
        effective_sev = inc_sev if severity_rank.get(inc_sev, 2) >= severity_rank.get(evt_sev, 2) else evt_sev

        conf = float(incident.get("confidence") or (getattr(decision, "confidence", None) or 0.95))
        act = (getattr(plan, "action", None) or incident.get("response_action") or "ISOLATE")

        if existing:
            prev_sev = existing.get("severity", "MEDIUM")
            is_escalation = (
                severity_rank.get(effective_sev, 2) > severity_rank.get(prev_sev, 2)
                or (existing.get("lifecycle_state") == "RECOVERING" and severity_rank.get(effective_sev, 2) >= 2)
            )
            if severity_rank.get(effective_sev, 2) < severity_rank.get(prev_sev, 2):
                effective_sev = prev_sev
            effective_conf = max(float(existing.get("confidence") or 0.0), conf)
            merged_evidence = list(dict.fromkeys(existing.get("evidence", []) + new_evidence))
            new_state = incident.get("lifecycle_state") or existing.get("lifecycle_state", "DETECTED")
            new_status = "RESOLVED" if new_state == "RESOLVED" else ("CLOSED" if new_state == "CLOSED" else existing.get("status", "ACTIVE"))

            ack_state = existing.get("acknowledgement_state", "UNACKNOWLEDGED")
            if is_escalation and ack_state == "ACKNOWLEDGED":
                ack_state = "RE_ESCALATED"
                self.record_audit(
                    username="system",
                    role="SYSTEM",
                    action="ALERT_RE_ESCALATED",
                    resource="alert",
                    resource_id=existing["alert_id"],
                    result="SUCCESS",
                    details=f"Alert {existing['alert_id']} re-escalated from {prev_sev} to {effective_sev} due to intensified attack activity",
                    source_ip="127.0.0.1",
                )

            with self.connection() as con:
                with con.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE admin_alerts SET timestamp = %s, severity = %s, confidence = %s, lifecycle_state = %s,
                        current_action = %s, status = %s, acknowledgement_state = %s, evidence_json = %s WHERE alert_id = %s;
                        """,
                        (
                            now,
                            effective_sev,
                            round(effective_conf, 3),
                            new_state,
                            f"{act} (DRY_RUN)",
                            new_status,
                            ack_state,
                            json.dumps(merged_evidence),
                            existing["alert_id"],
                        )
                    )
            return self.get_alert(existing["alert_id"])  # type: ignore[return-value]

        alert_id = f"ALT-{datetime.now(timezone.utc):%Y%m%d}-{uuid4().hex[:6].upper()}"
        attack_type = incident.get("attack_type") or (getattr(event, "attack_type", None) if event else "ANOMALY") or "ANOMALY"
        dev_id = incident.get("device_id") or (getattr(event, "device_id", None) if event else None) or "SENSOR-01"
        src_id = incident.get("source_id") or (getattr(event, "source_id", None) if event else None)
        reason = new_evidence[0] if new_evidence else f"Automated detection of {attack_type} campaign"
        state = incident.get("lifecycle_state") or "DETECTED"
        status = "RESOLVED" if state == "RESOLVED" else ("CLOSED" if state == "CLOSED" else "ACTIVE")

        with self.connection() as con:
            with con.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO admin_alerts (
                        alert_id, incident_id, timestamp, severity, attack_type, device_id, source_id, target,
                        confidence, detection_reason, lifecycle_state, recommended_action, current_action,
                        acknowledgement_state, acknowledged_by, acknowledged_at, status, evidence_json
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    ) ON CONFLICT (incident_id) DO NOTHING;
                    """,
                    (
                        alert_id,
                        incident_id,
                        now,
                        effective_sev,
                        attack_type,
                        dev_id,
                        src_id,
                        "AICG-GW-01 / OT Cell",
                        round(conf, 3),
                        reason,
                        state,
                        f"{act} (DRY_RUN)",
                        f"{act} (DRY_RUN)",
                        "UNACKNOWLEDGED",
                        None,
                        None,
                        status,
                        json.dumps(new_evidence),
                    )
                )
        return self.get_alert(alert_id)  # type: ignore[return-value]

    def sync_alert_with_incident(self, incident: dict[str, Any]) -> dict[str, Any] | None:
        existing = self.get_alert_by_incident(incident["incident_id"])
        if not existing:
            return None
        new_state = incident.get("lifecycle_state") or existing["lifecycle_state"]
        new_status = "RESOLVED" if new_state == "RESOLVED" else ("CLOSED" if new_state == "CLOSED" else "ACTIVE")
        now = utc_now()
        with self.connection() as con:
            with con.cursor() as cur:
                cur.execute(
                    "UPDATE admin_alerts SET lifecycle_state = %s, status = %s, timestamp = %s WHERE alert_id = %s;",
                    (new_state, new_status, now, existing["alert_id"])
                )
        return self.get_alert(existing["alert_id"])

    def acknowledge_alert(self, alert_id: str, username: str) -> dict[str, Any]:
        existing = self.get_alert(alert_id)
        if not existing:
            raise KeyError(f"Unknown alert: {alert_id}")
        now = utc_now()
        with self.connection() as con:
            with con.cursor() as cur:
                cur.execute(
                    "UPDATE admin_alerts SET acknowledgement_state = 'ACKNOWLEDGED', acknowledged_by = %s, acknowledged_at = %s WHERE alert_id = %s;",
                    (username, now, alert_id)
                )
        return self.get_alert(alert_id)  # type: ignore[return-value]

    def list_alerts(
        self,
        limit: int = 100,
        status: str | None = None,
        ack_state: str | None = None,
        severity: str | None = None
    ) -> list[dict[str, Any]]:
        clauses, params = [], []
        if status:
            clauses.append("status = %s")
            params.append(status.upper())
        if ack_state:
            clauses.append("acknowledgement_state = %s")
            params.append(ack_state.upper())
        if severity:
            clauses.append("severity = %s")
            params.append(severity.upper())
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(max(1, min(limit, 1000)))
        with self.connection() as con:
            with con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(f"SELECT * FROM admin_alerts{where} ORDER BY timestamp DESC LIMIT %s;", params)
                rows = cur.fetchall()
        return [self._alert_row(row) for row in rows]

    def record_audit(
        self,
        username: str,
        role: str,
        action: str,
        resource: str,
        resource_id: str | None = None,
        result: str = "SUCCESS",
        details: str = "",
        source_ip: str | None = None
    ) -> dict[str, Any]:
        """Atomically record an audit log using pg_advisory_xact_lock to serialize hash chaining."""
        event_id = f"AUD-{datetime.now(timezone.utc):%Y%m%d}-{uuid4().hex[:8].upper()}"
        now = utc_now()
        safe_details = str(details)
        for keyword in ["password", "token", "hash", "secret"]:
            if keyword in safe_details.lower() and "=" in safe_details:
                import re
                safe_details = re.sub(rf"{keyword}\s*=\s*[^\s,]+", f"{keyword}=[REDACTED]", safe_details, flags=re.IGNORECASE)

        item = {
            "event_id": event_id,
            "timestamp": now,
            "username": username or "system",
            "role": (role or "UNKNOWN").upper(),
            "action": action.upper(),
            "resource": resource,
            "resource_id": resource_id,
            "result": result.upper(),
            "source_ip": source_ip or "127.0.0.1",
            "details": safe_details,
        }
        max_retries = 5
        base_backoff = 0.05
        with self._audit_lock:
            for attempt in range(max_retries):
                try:
                    with self.connection() as con:
                        with con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                            # 1. Acquire dedicated transaction advisory lock for audit log writes
                            cur.execute("SELECT pg_advisory_xact_lock(%s);", (AICG_AUDIT_ADVISORY_LOCK_ID,))

                            # 2. Retrieve previous record hash within the same transaction
                            cur.execute("SELECT record_hash FROM admin_audit_log ORDER BY seq_id DESC LIMIT 1;")
                            last_row = cur.fetchone()
                            prev_hash = str(last_row["record_hash"]) if (last_row and last_row.get("record_hash")) else GENESIS_HASH

                            # 3. Compute deterministic audit hash
                            record_hash = self._compute_audit_hash(
                                prev_hash=prev_hash,
                                event_id=event_id,
                                timestamp=now,
                                username=username or "system",
                                role=(role or "UNKNOWN").upper(),
                                action=action.upper(),
                                resource=resource,
                                resource_id=resource_id,
                                result=result.upper(),
                                source_ip=source_ip or "127.0.0.1",
                                details=safe_details,
                            )
                            item["prev_hash"] = prev_hash
                            item["record_hash"] = record_hash

                            # 4. Insert audit record within the same transaction
                            cur.execute(
                                """
                                INSERT INTO admin_audit_log (
                                    event_id, timestamp, username, role, action, resource,
                                    resource_id, result, source_ip, details, prev_hash, record_hash
                                ) VALUES (
                                    %(event_id)s, %(timestamp)s, %(username)s, %(role)s, %(action)s,
                                    %(resource)s, %(resource_id)s, %(result)s, %(source_ip)s, %(details)s,
                                    %(prev_hash)s, %(record_hash)s
                                );
                                """,
                                item,
                            )
                    break
                except (psycopg2.OperationalError, psycopg2.DatabaseError) as exc:
                    if attempt < max_retries - 1:
                        time.sleep(base_backoff * (2 ** attempt))
                        continue
                    raise
        return item

    def verify_audit_log_integrity(self) -> dict[str, Any]:
        with self.connection() as con:
            with con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT seq_id, event_id, timestamp, username, role, action, resource, resource_id, result, source_ip, details, prev_hash, record_hash FROM admin_audit_log ORDER BY seq_id ASC;"
                )
                rows = cur.fetchall()

        if not rows:
            return {"valid": True, "count": 0, "first_corrupted_id": None, "reason": None}

        expected_prev = GENESIS_HASH
        for idx, row in enumerate(rows):
            event_id = row["event_id"]
            prev_hash = row["prev_hash"]
            record_hash = row["record_hash"]

            if prev_hash != expected_prev:
                return {
                    "valid": False,
                    "count": len(rows),
                    "corrupted_index": idx,
                    "first_corrupted_id": event_id,
                    "reason": f"Broken chain at record {event_id}: expected prev_hash {expected_prev}, got {prev_hash}",
                }

            computed = self._compute_audit_hash(
                prev_hash=prev_hash,
                event_id=event_id,
                timestamp=row["timestamp"],
                username=row["username"],
                role=row["role"],
                action=row["action"],
                resource=row["resource"],
                resource_id=row["resource_id"],
                result=row["result"],
                source_ip=row["source_ip"],
                details=row["details"],
            )
            if computed != record_hash:
                return {
                    "valid": False,
                    "count": len(rows),
                    "corrupted_index": idx,
                    "first_corrupted_id": event_id,
                    "reason": f"Hash mismatch at record {event_id}: expected {computed}, got {record_hash}",
                }
            expected_prev = record_hash

        return {"valid": True, "count": len(rows), "first_corrupted_id": None, "reason": None}

    def list_audit_logs(
        self,
        limit: int = 100,
        action: str | None = None,
        username: str | None = None
    ) -> list[dict[str, Any]]:
        clauses, params = [], []
        if action:
            clauses.append("action = %s")
            params.append(action.upper())
        if username:
            clauses.append("username = %s")
            params.append(username)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(max(1, min(limit, 1000)))
        with self.connection() as con:
            with con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(f"SELECT * FROM admin_audit_log{where} ORDER BY timestamp DESC, seq_id DESC LIMIT %s;", params)
                rows = cur.fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item.pop("seq_id", None)
            results.append(item)
        return results

    def get_device_identity(self, device_id: str) -> dict[str, Any] | None:
        with self.connection() as con:
            with con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM device_identities WHERE device_id = %s;", (device_id,))
                row = cur.fetchone()
        return dict(row) if row else None

    def list_device_identities(self, status: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM device_identities"
        params: list[Any] = []
        if status:
            query += " WHERE status = %s"
            params.append(status.upper())
        query += " ORDER BY device_id ASC;"
        with self.connection() as con:
            with con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(query, params)
                rows = cur.fetchall()
        return [dict(row) for row in rows]

    def upsert_device_identity(
        self,
        device_id: str,
        role: str = "sensor",
        auth_key_hash: str = "",
        status: str = "ENROLLED",
        trust_score: float = 100.0,
        failures: int = 0,
        mfa_status: str = "NOT_REQUIRED",
    ) -> dict[str, Any]:
        now = utc_now()
        with self.connection() as con:
            with con.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO device_identities (device_id, role, status, auth_key_hash, trust_score, failures, mfa_status, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (device_id) DO UPDATE SET
                        role = EXCLUDED.role,
                        status = EXCLUDED.status,
                        auth_key_hash = CASE WHEN EXCLUDED.auth_key_hash != '' THEN EXCLUDED.auth_key_hash ELSE device_identities.auth_key_hash END,
                        trust_score = EXCLUDED.trust_score,
                        failures = EXCLUDED.failures,
                        mfa_status = EXCLUDED.mfa_status;
                    """,
                    (device_id, role.lower(), status.upper(), auth_key_hash, trust_score, failures, mfa_status, now),
                )
        return self.get_device_identity(device_id) or {}

    def update_device_trust(self, device_id: str, score: float, failures: int | None = None) -> None:
        with self.connection() as con:
            with con.cursor() as cur:
                if failures is not None:
                    cur.execute("UPDATE device_identities SET trust_score = %s, failures = %s WHERE device_id = %s;", (score, failures, device_id))
                else:
                    cur.execute("UPDATE device_identities SET trust_score = %s WHERE device_id = %s;", (score, device_id))

    def update_device_last_seen(self, device_id: str, timestamp: str | None = None) -> None:
        ts = timestamp or utc_now()
        with self.connection() as con:
            with con.cursor() as cur:
                cur.execute("UPDATE device_identities SET last_seen = %s WHERE device_id = %s;", (ts, device_id))

    def set_device_status(self, device_id: str, status: str) -> dict[str, Any] | None:
        with self.connection() as con:
            with con.cursor() as cur:
                cur.execute("UPDATE device_identities SET status = %s WHERE device_id = %s;", (status.upper(), device_id))
        return self.get_device_identity(device_id)


def create_gateway_store(settings: Any, **kwargs: Any) -> BaseGatewayStore:
    """Factory selecting the storage engine from application Settings."""
    is_prod = getattr(settings, "production", False)
    db_url = getattr(settings, "database_url", None)

    if is_prod:
        if not db_url or not str(db_url).strip():
            raise ValueError(
                "Production mode requires a valid PostgreSQL database_url and cannot fall back to SQLite."
            )
        url_lower = str(db_url).strip().lower()
        if not (url_lower.startswith("postgresql://") or url_lower.startswith("postgres://")):
            raise ValueError(
                "Production mode requires a valid PostgreSQL URL scheme ('postgresql://' or 'postgres://')."
            )

    if db_url:
        params: dict[str, Any] = {
            "database_url": settings.database_url,
            "master_key": getattr(settings, "device_master_key", None),
            "production": is_prod,
            "allow_demo_accounts": getattr(settings, "allow_demo_accounts", True),
            "initial_admin_username": getattr(settings, "initial_admin_username", "admin"),
            "initial_admin_password": getattr(settings, "initial_admin_password", None),
        }
        params.update(kwargs)
        return PostgresGatewayStore(**params)

    if is_prod:
        raise ValueError(
            "Production mode requires a valid PostgreSQL database_url and cannot fall back to SQLite."
        )

    params = {
        "path": getattr(settings, "database_path", Path("backend/data/aegis_gateway.sqlite3")),
        "master_key": getattr(settings, "device_master_key", None),
        "production": is_prod,
        "allow_demo_accounts": getattr(settings, "allow_demo_accounts", True),
        "initial_admin_username": getattr(settings, "initial_admin_username", "admin"),
        "initial_admin_password": getattr(settings, "initial_admin_password", None),
    }
    params.update(kwargs)
    return SQLiteGatewayStore(**params)


StorageHistorian = GatewayStore

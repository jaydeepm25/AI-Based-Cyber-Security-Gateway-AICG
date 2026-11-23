"""Isolated unit tests for dual-engine storage layer, PostgreSQL pooling, and advisory locking."""

from __future__ import annotations

import hashlib
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import psycopg2.extensions
import pytest

from aegis_gateway.api import create_app
from aegis_gateway.config import Settings
from aegis_gateway.runtime import GatewayRuntime
from aegis_gateway.schema import CANONICAL_FIELDS, TelemetryEvent
from aegis_gateway.storage import (
    AICG_AUDIT_ADVISORY_LOCK_ID,
    GENESIS_HASH,
    BaseGatewayStore,
    GatewayStore,
    PostgresGatewayStore,
    SQLiteGatewayStore,
    StorageHistorian,
    create_gateway_store,
)


# =============================================================================
# 1. FACTORY DISPATCH & ENGINE SELECTION TESTS
# =============================================================================

def test_gateway_store_factory_sqlite(tmp_path: Path):
    """Verify GatewayStore default and path invocations return SQLiteGatewayStore."""
    db_path = tmp_path / "factory_sqlite.sqlite3"
    store = GatewayStore(db_path)
    assert isinstance(store, SQLiteGatewayStore)
    assert isinstance(store, GatewayStore)
    assert isinstance(store, BaseGatewayStore)
    assert store.path == db_path

    # Verify alias
    assert StorageHistorian is GatewayStore

    # Verify create_gateway_store helper with default settings
    settings = Settings(database_path=db_path)
    s_created = create_gateway_store(settings)
    assert isinstance(s_created, SQLiteGatewayStore)
    assert s_created.path == db_path


@patch("psycopg2.pool.ThreadedConnectionPool")
def test_gateway_store_factory_postgres(mock_pool_cls):
    """Verify GatewayStore with database_url returns PostgresGatewayStore without connecting."""
    mock_pool = MagicMock()
    mock_pool_cls.return_value = mock_pool

    url = "postgresql://aicg_user:secret_pass@localhost:5432/aicg_db?sslmode=require"
    store = GatewayStore(database_url=url, initialize=False)
    assert isinstance(store, PostgresGatewayStore)
    assert isinstance(store, GatewayStore)
    assert isinstance(store, BaseGatewayStore)
    assert store.database_url == url

    # Verify create_gateway_store helper with database_url set in settings
    settings = Settings(database_url=url)
    with patch.object(PostgresGatewayStore, "initialize"):
        s_created = create_gateway_store(settings)
        assert isinstance(s_created, PostgresGatewayStore)
        assert s_created.database_url == url


# =============================================================================
# 2. CONNECTION POOL SAFETY & LIFECYCLE TESTS
# =============================================================================

@patch("psycopg2.pool.ThreadedConnectionPool")
def test_connection_pool_lifecycle_commit(mock_pool_cls):
    """Verify healthy connection is committed and returned cleanly to the pool."""
    mock_pool = MagicMock()
    mock_con = MagicMock()
    mock_con.closed = False
    mock_con.status = psycopg2.extensions.STATUS_IN_TRANSACTION
    mock_con.get_transaction_status.return_value = psycopg2.extensions.TRANSACTION_STATUS_INTRANS

    def fake_commit():
        mock_con.status = psycopg2.extensions.STATUS_READY
        mock_con.get_transaction_status.return_value = psycopg2.extensions.TRANSACTION_STATUS_IDLE

    mock_con.commit.side_effect = fake_commit
    mock_pool.getconn.return_value = mock_con
    mock_pool_cls.return_value = mock_pool

    store = PostgresGatewayStore("postgresql://localhost/db", initialize=False)

    with store.connection() as con:
        assert con is mock_con

    mock_con.commit.assert_called_once()
    mock_pool.putconn.assert_called_once_with(mock_con)


@patch("psycopg2.pool.ThreadedConnectionPool")
def test_connection_pool_rollback_on_exception(mock_pool_cls):
    """Verify exception inside transaction causes rollback and healthy return if connection clean."""
    mock_pool = MagicMock()
    mock_con = MagicMock()
    mock_con.closed = False
    mock_con.status = psycopg2.extensions.STATUS_IN_TRANSACTION
    mock_con.get_transaction_status.return_value = psycopg2.extensions.TRANSACTION_STATUS_INERROR

    def fake_rollback():
        mock_con.status = psycopg2.extensions.STATUS_READY
        mock_con.get_transaction_status.return_value = psycopg2.extensions.TRANSACTION_STATUS_IDLE

    mock_con.rollback.side_effect = fake_rollback
    mock_pool.getconn.return_value = mock_con
    mock_pool_cls.return_value = mock_pool

    store = PostgresGatewayStore("postgresql://localhost/db", initialize=False)

    with pytest.raises(ValueError, match="simulated error"):
        with store.connection():
            raise ValueError("simulated error")

    mock_con.rollback.assert_called_once()
    mock_pool.putconn.assert_called_once_with(mock_con)


@patch("psycopg2.pool.ThreadedConnectionPool")
def test_connection_pool_evicts_broken_connections(mock_pool_cls):
    """Verify dead sockets, operational errors, and rollback failures trigger close=True eviction."""
    mock_pool = MagicMock()
    mock_con = MagicMock()
    mock_con.closed = False
    mock_con.rollback.side_effect = psycopg2.OperationalError("server closed the connection unexpectedly")
    mock_pool.getconn.return_value = mock_con
    mock_pool_cls.return_value = mock_pool

    store = PostgresGatewayStore("postgresql://localhost/db", initialize=False)

    with pytest.raises(RuntimeError, match="application failure"):
        with store.connection():
            raise RuntimeError("application failure")

    mock_pool.putconn.assert_called_once_with(mock_con, close=True)


@patch("psycopg2.pool.ThreadedConnectionPool")
def test_connection_pool_evicts_dirty_uncommitted_state(mock_pool_cls):
    """Verify connection left in STATUS_IN_TRANSACTION is evicted with close=True."""
    mock_pool = MagicMock()
    mock_con = MagicMock()
    mock_con.closed = False
    mock_con.status = psycopg2.extensions.STATUS_IN_TRANSACTION
    mock_con.get_transaction_status.return_value = psycopg2.extensions.TRANSACTION_STATUS_INTRANS
    mock_con.commit.side_effect = Exception("commit failed")
    mock_pool.getconn.return_value = mock_con
    mock_pool_cls.return_value = mock_pool

    store = PostgresGatewayStore("postgresql://localhost/db", initialize=False)

    with pytest.raises(Exception, match="commit failed"):
        with store.connection():
            pass

    mock_pool.putconn.assert_called_once_with(mock_con, close=True)


@patch("psycopg2.pool.ThreadedConnectionPool")
def test_safe_pool_shutdown(mock_pool_cls):
    """Verify close() drains and closes all pool connections safely."""
    mock_pool = MagicMock()
    mock_pool_cls.return_value = mock_pool

    store = PostgresGatewayStore("postgresql://localhost/db", initialize=False)
    store.close()
    mock_pool.closeall.assert_called_once()
    assert store._pool is None

    # Redundant close is safe
    store.close()


# =============================================================================
# 3. AUDIT LOG CONCURRENCY & ADVISORY LOCK TESTS
# =============================================================================

@patch("psycopg2.pool.ThreadedConnectionPool")
def test_audit_advisory_lock_and_single_transaction_serialization(mock_pool_cls):
    """Verify record_audit acquires pg_advisory_xact_lock and fetches hash in one transaction."""
    mock_pool = MagicMock()
    mock_con = MagicMock()
    mock_con.closed = False
    mock_con.status = psycopg2.extensions.STATUS_READY
    mock_cur = MagicMock()

    mock_con.cursor.return_value.__enter__.return_value = mock_cur
    mock_pool.getconn.return_value = mock_con
    mock_pool_cls.return_value = mock_pool

    # Simulate empty table on first audit record
    mock_cur.fetchone.return_value = None

    store = PostgresGatewayStore("postgresql://localhost/db", initialize=False)
    audit_rec = store.record_audit(
        username="sec_admin",
        role="ADMIN",
        action="UPDATE_GATEWAY_POLICY",
        resource="firewall",
        resource_id="rule_42",
        result="SUCCESS",
        details="Updated egress filter",
    )

    # 1. Verify advisory lock was queried with the correct constant
    executed_statements = [call_args[0][0] for call_args in mock_cur.execute.call_args_list]
    assert any("pg_advisory_xact_lock" in stmt for stmt in executed_statements)

    lock_call = [call_args for call_args in mock_cur.execute.call_args_list if "pg_advisory_xact_lock" in call_args[0][0]][0]
    assert lock_call[0][1] == (AICG_AUDIT_ADVISORY_LOCK_ID,)

    # 2. Verify previous hash was retrieved using seq_id ordering
    hash_query_call = [call_args for call_args in mock_cur.execute.call_args_list if "SELECT record_hash" in call_args[0][0]][0]
    assert "ORDER BY seq_id DESC LIMIT 1" in hash_query_call[0][0]

    # 3. Verify insert statement executed
    insert_call = [call_args for call_args in mock_cur.execute.call_args_list if "INSERT INTO admin_audit_log" in call_args[0][0]][0]
    assert "%(prev_hash)s" in insert_call[0][0]
    assert "%(record_hash)s" in insert_call[0][0]

    # 4. Verify prev_hash matches GENESIS_HASH on initial empty record
    assert audit_rec["prev_hash"] == GENESIS_HASH
    assert len(audit_rec["record_hash"]) == 64


def test_audit_hash_canonical_calculation():
    """Verify SHA-256 canonical string hashing matches exact gateway specification."""
    expected = hashlib.sha256(
        b"0000000000000000000000000000000000000000000000000000000000000000|AUD-1|2026-01-01T00:00:00|admin|ADMIN|LOGIN|session|s1|SUCCESS|127.0.0.1|Login OK"
    ).hexdigest()

    computed = BaseGatewayStore._compute_audit_hash(
        prev_hash=GENESIS_HASH,
        event_id="AUD-1",
        timestamp="2026-01-01T00:00:00",
        username="admin",
        role="ADMIN",
        action="LOGIN",
        resource="session",
        resource_id="s1",
        result="SUCCESS",
        source_ip="127.0.0.1",
        details="Login OK",
    )
    assert computed == expected


# =============================================================================
# 4. SCHEMA INITIALIZATION & SQL DIALECT COMPATIBILITY TESTS
# =============================================================================

@patch("psycopg2.pool.ThreadedConnectionPool")
def test_postgres_schema_initialization_ddl(mock_pool_cls):
    """Verify PostgreSQL DDL contains all 11 tables, BIGSERIAL sequences, and valid types."""
    mock_pool = MagicMock()
    mock_con = MagicMock()
    mock_con.closed = False
    mock_con.status = psycopg2.extensions.STATUS_READY
    mock_cur = MagicMock()
    mock_con.cursor.return_value.__enter__.return_value = mock_cur
    mock_pool.getconn.return_value = mock_con
    mock_pool_cls.return_value = mock_pool

    # Return existing users = 1 to skip seeding logic during test
    mock_cur.fetchone.return_value = {"c": 1}

    store = PostgresGatewayStore("postgresql://localhost/db", initialize=True)

    executed_statements = [call_args[0][0] for call_args in mock_cur.execute.call_args_list]
    ddl = executed_statements[0]

    expected_tables = [
        "telemetry",
        "incidents",
        "incident_history",
        "actions",
        "iam_events",
        "trust_history",
        "metadata",
        "admin_users",
        "admin_alerts",
        "admin_audit_log",
        "device_identities",
    ]
    for table in expected_tables:
        assert f"CREATE TABLE IF NOT EXISTS {table}" in ddl

    # Verify BIGSERIAL sequences exist for rowid replacements
    assert "seq_id BIGSERIAL PRIMARY KEY" in ddl  # on telemetry and admin_audit_log
    assert "seq_id BIGSERIAL UNIQUE" in ddl       # on trust_history

    # Verify foreign keys
    assert "REFERENCES incidents(incident_id) ON DELETE CASCADE" in ddl
    assert "REFERENCES incidents(incident_id) ON DELETE SET NULL" in ddl

    # Verify zero SQLite PRAGMAs exist in PostgreSQL DDL
    assert "PRAGMA" not in ddl
    assert "rowid" not in ddl


@patch("psycopg2.pool.ThreadedConnectionPool")
def test_device_identity_upsert_postgres_syntax(mock_pool_cls):
    """Verify device identity upsert uses PostgreSQL EXCLUDED syntax with %s markers."""
    mock_pool = MagicMock()
    mock_con = MagicMock()
    mock_con.closed = False
    mock_con.status = psycopg2.extensions.STATUS_READY
    mock_cur = MagicMock()
    mock_con.cursor.return_value.__enter__.return_value = mock_cur
    mock_pool.getconn.return_value = mock_con
    mock_pool_cls.return_value = mock_pool

    store = PostgresGatewayStore("postgresql://localhost/db", initialize=False)
    store.upsert_device_identity(
        device_id="DEV-001",
        role="sensor",
        auth_key_hash="hash123",
        status="ENROLLED",
        trust_score=95.0,
        failures=1,
    )

    executed_statements = [call_args[0][0] for call_args in mock_cur.execute.call_args_list]
    upsert_sql = [s for s in executed_statements if "INSERT INTO device_identities" in s][0]

    assert "ON CONFLICT (device_id) DO UPDATE SET" in upsert_sql
    assert "EXCLUDED.role" in upsert_sql
    assert "EXCLUDED.trust_score" in upsert_sql
    assert "?" not in upsert_sql
    assert "%s" in upsert_sql


# =============================================================================
# 5. PHASE 5.3A RUNTIME INTEGRATION, ROW PARITY & DUPLICATE USERNAME TESTS
# =============================================================================

def test_gateway_runtime_sqlite_selection(tmp_path: Path):
    """Verify GatewayRuntime selects SQLiteGatewayStore when database_url is not set."""
    settings = Settings(database_path=tmp_path / "runtime_sqlite.sqlite3")
    runtime = GatewayRuntime(settings)
    assert isinstance(runtime.store, SQLiteGatewayStore)
    assert isinstance(runtime.store, GatewayStore)
    assert runtime.store.path == tmp_path / "runtime_sqlite.sqlite3"


@patch("psycopg2.pool.ThreadedConnectionPool")
def test_gateway_runtime_postgres_selection(mock_pool_cls):
    """Verify GatewayRuntime selects PostgresGatewayStore when database_url is configured."""
    mock_pool = MagicMock()
    mock_pool_cls.return_value = mock_pool

    url = "postgresql://aicg_user:secret_pass@localhost:5432/aicg_db?sslmode=require"
    settings = Settings(database_url=url)
    with patch.object(PostgresGatewayStore, "initialize"):
        runtime = GatewayRuntime(settings)
        assert isinstance(runtime.store, PostgresGatewayStore)
        assert isinstance(runtime.store, GatewayStore)
        assert runtime.store.database_url == url


def test_aegis_database_url_fallback(monkeypatch):
    """Verify AEGIS_DATABASE_URL acts as fallback when DATABASE_URL is unset."""
    url = "postgresql://aicg_user:fallback_pass@localhost:5432/aicg_db?sslmode=require"
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("AEGIS_DATABASE_URL", url)

    settings = Settings()
    assert settings.is_postgres is True
    assert settings.database_url == url

    with patch("psycopg2.pool.ThreadedConnectionPool"), patch.object(PostgresGatewayStore, "initialize"):
        store = create_gateway_store(settings)
        assert isinstance(store, PostgresGatewayStore)
        assert store.database_url == url


def test_database_credentials_not_logged():
    """Verify database password is not exposed in Settings repr or logging representation."""
    url = "postgresql://aicg_user:SuperSecretPassword123@localhost:5432/aicg_db?sslmode=require"
    settings = Settings(database_url=url)
    repr_str = repr(settings)
    assert "SuperSecretPassword123" not in repr_str
    assert "database_url" not in repr_str


def test_public_api_row_and_csv_parity(tmp_path: Path):
    """Verify list_audit_logs() and trust() strip internal seq_id for bit-for-bit parity with SQLite."""
    # 1. Setup SQLite baseline
    db_path = tmp_path / "baseline_parity.sqlite3"
    sqlite_store = SQLiteGatewayStore(db_path)
    sqlite_store.record_audit(
        username="admin",
        role="ADMIN",
        action="TEST_ACTION",
        resource="device",
        details="Parity check",
    )
    sqlite_audits = sqlite_store.list_audit_logs(limit=10)
    assert len(sqlite_audits) >= 1
    expected_audit_keys = set(sqlite_audits[0].keys())
    assert "seq_id" not in expected_audit_keys

    sqlite_store.record_trust("SENSOR-01", 95.0, 5.0, "Initial calibration")
    sqlite_trust = sqlite_store.trust("SENSOR-01")
    assert len(sqlite_trust) >= 1
    expected_trust_keys = set(sqlite_trust[0].keys())
    assert "seq_id" not in expected_trust_keys

    sqlite_csv = sqlite_store.export("audit", "csv")
    expected_csv_header = sqlite_csv.splitlines()[0]

    # 2. Setup Postgres store with mock returning internal seq_id
    with patch("psycopg2.pool.ThreadedConnectionPool") as mock_pool_cls:
        mock_pool = MagicMock()
        mock_con = MagicMock()
        mock_con.closed = False
        mock_con.status = psycopg2.extensions.STATUS_READY
        mock_cur = MagicMock()
        mock_con.cursor.return_value.__enter__.return_value = mock_cur
        mock_pool.getconn.return_value = mock_con
        mock_pool_cls.return_value = mock_pool

        # Mock audit row with internal seq_id from PostgreSQL BIGSERIAL
        audit_row_with_seq = {
            "seq_id": 101,
            "event_id": "AUD-001",
            "timestamp": "2026-01-01T00:00:00",
            "username": "admin",
            "role": "ADMIN",
            "action": "TEST_ACTION",
            "resource": "device",
            "resource_id": None,
            "result": "SUCCESS",
            "source_ip": "127.0.0.1",
            "details": "Parity check",
            "prev_hash": GENESIS_HASH,
            "record_hash": "a" * 64,
        }
        mock_cur.fetchall.return_value = [audit_row_with_seq]

        pg_store = PostgresGatewayStore("postgresql://localhost/db", initialize=False)
        pg_audits = pg_store.list_audit_logs(limit=10)

        assert len(pg_audits) == 1
        assert "seq_id" not in pg_audits[0]
        assert set(pg_audits[0].keys()) == expected_audit_keys

        # Mock trust row with internal seq_id
        trust_row_with_seq = {
            "seq_id": 202,
            "trust_event_id": "TRU-001",
            "timestamp": "2026-01-01T00:00:00",
            "identity": "SENSOR-01",
            "score": 95.0,
            "delta": 5.0,
            "reason": "Initial calibration",
            "provenance": "DERIVED",
        }
        mock_cur.fetchall.return_value = [trust_row_with_seq]
        pg_trust = pg_store.trust("SENSOR-01")

        assert len(pg_trust) == 1
        assert "seq_id" not in pg_trust[0]
        assert set(pg_trust[0].keys()) == expected_trust_keys

        # Verify CSV export header matches exactly
        mock_cur.fetchall.return_value = [audit_row_with_seq]
        pg_csv = pg_store.export("audit", "csv")
        assert pg_csv.splitlines()[0] == expected_csv_header


def test_duplicate_username_behavior_sqlite_and_postgres(tmp_path: Path):
    """Verify concurrent duplicate username attempts raise ValueError and produce consistent behavior."""
    # 1. SQLite Gateway Store
    db_path = tmp_path / "dup_users.sqlite3"
    sqlite_store = SQLiteGatewayStore(db_path)
    sqlite_store.create_admin_user("analyst1", "hash1", "OPERATOR")

    with pytest.raises(ValueError, match="already exists"):
        sqlite_store.create_admin_user("analyst1", "hash2", "OPERATOR")

    # 2. PostgreSQL Gateway Store
    with patch("psycopg2.pool.ThreadedConnectionPool") as mock_pool_cls:
        mock_pool = MagicMock()
        mock_con = MagicMock()
        mock_con.closed = False
        mock_con.status = psycopg2.extensions.STATUS_READY
        mock_cur = MagicMock()
        mock_con.cursor.return_value.__enter__.return_value = mock_cur
        mock_pool.getconn.return_value = mock_con
        mock_pool_cls.return_value = mock_pool

        # Simulate PostgreSQL unique constraint violation
        mock_cur.execute.side_effect = psycopg2.IntegrityError(
            'duplicate key value violates unique constraint "admin_users_username_key"'
        )

        pg_store = PostgresGatewayStore("postgresql://localhost/db", initialize=False)
        with pytest.raises(ValueError, match="already exists"):
            pg_store.create_admin_user("analyst1", "hash2", "OPERATOR")


def test_api_duplicate_username_returns_409(tmp_path: Path):
    """Verify API endpoint returns HTTP 409 and avoids raw database exception on duplicate username."""
    settings = Settings(database_path=tmp_path / "api_dup.sqlite3")
    runtime = GatewayRuntime(settings)
    app = create_app(runtime)

    with app.test_client() as client:
        # Login as admin
        client.post("/api/auth/login", json={
            "username": "admin",
            "password": "Admin@AICG2026!",
            "mfa_code": "123456",
        })

        # 1. Create a user
        res1 = client.post("/api/admin/users", json={
            "username": "ops_specialist",
            "password": "SecurePassword123!",
            "role": "OPERATOR",
        })
        assert res1.status_code == 201

        # 2. Attempt duplicate creation -> must return HTTP 409
        res2 = client.post("/api/admin/users", json={
            "username": "ops_specialist",
            "password": "DifferentPassword123!",
            "role": "OPERATOR",
        })
        assert res2.status_code == 409
        body = res2.get_json()
        assert "error" in body
        assert "already exists" in body["error"]
        # Ensure no raw SQL / database traceback exposed
        assert "sqlite3" not in body["error"].lower()
        assert "psycopg2" not in body["error"].lower()

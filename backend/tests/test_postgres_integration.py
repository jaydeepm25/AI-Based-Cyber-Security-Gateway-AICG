"""PostgreSQL integration test harness for AI-Based Cyber Security Gateway (AICG).

All tests in this module require explicit opt-in:
    pytest -m postgres_integration backend/tests/test_postgres_integration.py

And require TEST_DATABASE_URL to be set to a dedicated, isolated test database:
    export TEST_DATABASE_URL="postgresql://user:pass@host:5432/test_db?sslmode=require"

CRITICAL PRODUCTION PROTECTION INVARIANTS:
1. Never connects to production public schema.
2. Never modifies production administrator or baseline devices.
3. Never uses or modifies the production audit log.
4. Fails closed (skips cleanly) if TEST_DATABASE_URL is not configured.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

import pytest
from werkzeug.security import check_password_hash

from aegis_gateway.api import create_app
from aegis_gateway.config import Settings
from aegis_gateway.runtime import GatewayRuntime
from aegis_gateway.schema import TelemetryEvent
from aegis_gateway.security import hash_password
from aegis_gateway.storage import (
    GENESIS_HASH,
    PostgresGatewayStore,
    create_gateway_store,
)

pytestmark = pytest.mark.postgres_integration


def _make_test_settings(test_database_url: str, **kwargs: Any) -> Settings:
    """Create a Settings instance configured explicitly with TEST_DATABASE_URL."""
    params: dict[str, Any] = {
        "database_url": test_database_url,
        "production": True,
        "response_mode": "DRY_RUN",
        "allow_demo_accounts": False,
        "initial_admin_username": "test_admin",
        "initial_admin_password": "TestAdminPassword@2026!Secure",
        "secret_key": "test-integration-secret-key-64-bytes-entropy-minimum-padding",
        "device_master_key": "test-integration-master-key-64-bytes-entropy-minimum-padding",
    }
    params.update(kwargs)
    return Settings(**params)


# =============================================================================
# SCENARIO 1: PostgreSQL Connection and Startup
# =============================================================================

def test_scenario_01_postgres_connection_and_startup(test_database_url: str):
    """Verify clean pool establishment, runtime binding, and /api/health response."""
    settings = _make_test_settings(test_database_url)
    runtime = GatewayRuntime(settings)
    assert isinstance(runtime.store, PostgresGatewayStore)
    assert runtime.store.database_url == test_database_url

    app = create_app(runtime)
    with app.test_client() as client:
        res = client.get("/api/health")
        assert res.status_code == 200
        data = res.get_json()
        assert data["ok"] is True
        assert data["response_mode"] == "DRY_RUN"

    runtime.store.close()


# =============================================================================
# SCENARIO 2: Administrator Authentication and MFA
# =============================================================================

def test_scenario_02_admin_authentication_and_mfa(test_database_url: str):
    """Verify administrator password verification, session cookie issuance, and simulated MFA."""
    settings = _make_test_settings(test_database_url)
    runtime = GatewayRuntime(settings)
    app = create_app(runtime)

    with app.test_client() as client:
        # Step 1: Pre-MFA login
        login_res = client.post("/api/auth/login", json={
            "username": settings.initial_admin_username,
            "password": settings.initial_admin_password,
        })
        assert login_res.status_code == 200
        body = login_res.get_json()
        assert body.get("mfa_required") is True
        assert body.get("username") == settings.initial_admin_username

        # Step 2: Simulated MFA verification
        mfa_res = client.post("/api/auth/mfa/verify", json={
            "mfa_code": "123456",
        })
        assert mfa_res.status_code == 200
        mfa_body = mfa_res.get_json()
        assert mfa_body["authenticated"] is True
        assert mfa_body["user"]["role"] == "ADMIN"

    runtime.store.close()


# =============================================================================
# SCENARIO 3: User Creation and Duplicate Handling
# =============================================================================

def test_scenario_03_user_creation_and_duplicate_handling(test_database_url: str):
    """Verify user creation with isolated test namespace and HTTP 409 Conflict on duplicate."""
    settings = _make_test_settings(test_database_url)
    runtime = GatewayRuntime(settings)
    store = runtime.store
    assert isinstance(store, PostgresGatewayStore)

    unique_suffix = uuid.uuid4().hex[:8]
    test_username = f"test_op_{unique_suffix}"
    pw_hash = hash_password("OperatorPass@2026!Secure")

    # 1. Store-level creation -> succeeds
    created = store.create_admin_user(test_username, pw_hash, "OPERATOR")
    assert created["username"] == test_username
    assert created["role"] == "OPERATOR"
    assert created["status"] == "ACTIVE"

    # 2. Store-level duplicate username attempt -> raises ValueError
    with pytest.raises(ValueError, match="already exists"):
        store.create_admin_user(test_username, pw_hash, "OPERATOR")

    # 3. API-level user creation and HTTP 409 duplicate-user behavior
    app = create_app(runtime)
    with app.test_client() as client:
        # Authenticate as test_admin
        client.post("/api/auth/login", json={
            "username": settings.initial_admin_username,
            "password": settings.initial_admin_password,
            "mfa_code": "123456",
        })

        # Attempt to create the same user via API -> must return HTTP 409 Conflict
        api_dup_res = client.post("/api/admin/users", json={
            "username": test_username,
            "password": "AnotherPassword@2026!Secure",
            "role": "OPERATOR",
        })
        assert api_dup_res.status_code == 409
        body = api_dup_res.get_json()
        assert "error" in body
        assert "already exists" in body["error"]
        # Ensure no internal database tracebacks leaked
        assert "psycopg2" not in body["error"].lower()
        assert "sqlite3" not in body["error"].lower()

    store.close()


# =============================================================================
# SCENARIO 4: Telemetry Ingestion and Retrieval
# =============================================================================

def test_scenario_04_telemetry_ingestion_and_retrieval(test_database_url: str):
    """Verify single and batch telemetry insertion and latest event retrieval."""
    settings = _make_test_settings(test_database_url)
    store = create_gateway_store(settings)
    assert isinstance(store, PostgresGatewayStore)

    unique_scenario = f"INT_SCENARIO_{uuid.uuid4().hex[:8]}"
    unique_dev = f"TEST-DEV-{uuid.uuid4().hex[:8]}"

    event = TelemetryEvent(
        event_id=f"EVT-{uuid.uuid4().hex[:8]}",
        timestamp="2026-01-01T12:00:00Z",
        source_type="sensor",
        source_id=unique_dev,
        device_id=unique_dev,
        packet_count=100,
        byte_count=1024,
        packet_rate=10.0,
        energy_consumed=0.05,
        cpu_activity=0.25,
        memory_activity=0.30,
        scenario_id=unique_scenario,
        provenance="SYNTHETIC",
    )

    # Insert single
    store.append_telemetry(event)

    # Ingest batch (iterative canonical append)
    event2 = TelemetryEvent(
        event_id=f"EVT-{uuid.uuid4().hex[:8]}",
        timestamp="2026-01-01T12:00:01Z",
        source_type="sensor",
        source_id=unique_dev,
        device_id=unique_dev,
        packet_count=110,
        byte_count=1100,
        packet_rate=11.0,
        energy_consumed=0.06,
        cpu_activity=0.28,
        memory_activity=0.32,
        scenario_id=unique_scenario,
        provenance="SYNTHETIC",
    )
    for e in [event2]:
        store.append_telemetry(e)

    latest = store.telemetry(limit=50)
    matching = [e for e in latest if e.get("scenario_id") == unique_scenario]
    assert len(matching) >= 2
    # Verify seq_id is not exposed in public dictionary
    assert "seq_id" not in matching[0]
    assert matching[0]["source_id"] == unique_dev

    store.close()


# =============================================================================
# SCENARIO 5: Incident Lifecycle and History
# =============================================================================

def test_scenario_05_incident_lifecycle_and_history(test_database_url: str):
    """Verify incident creation, state mutation, and cascade history entries."""
    settings = _make_test_settings(test_database_url)
    store = create_gateway_store(settings)
    assert isinstance(store, PostgresGatewayStore)

    unique_dev = f"TEST-DEV-{uuid.uuid4().hex[:8]}"

    event = TelemetryEvent(
        event_id=f"EVT-{uuid.uuid4().hex[:8]}",
        timestamp="2026-01-01T12:00:00Z",
        source_type="sensor",
        source_id=unique_dev,
        device_id=unique_dev,
        attack_type="SYN_FLOOD",
        severity="HIGH",
        confidence=0.95,
        provenance="SYNTHETIC",
    )

    incident = store.create_incident(event, ["Synthetic SYN flood observed"], "sensor_network")
    inc_id = incident["incident_id"]
    assert incident["device_id"] == unique_dev
    assert incident["lifecycle_state"] == "DETECTED"

    # Transition to CONTAINED
    store.transition_incident(inc_id, "CONTAINED", "test_admin", "Mitigation applied")
    updated = store.incident(inc_id)
    assert updated is not None
    assert updated["lifecycle_state"] == "CONTAINED"
    assert len(updated["history"]) >= 2

    store.close()


# =============================================================================
# SCENARIO 6: Alert Creation and Acknowledgement
# =============================================================================

def test_scenario_06_alert_creation_and_acknowledgement(test_database_url: str):
    """Verify alert creation and state transition upon acknowledgement."""
    settings = _make_test_settings(test_database_url)
    store = create_gateway_store(settings)
    assert isinstance(store, PostgresGatewayStore)

    unique_dev = f"TEST-DEV-{uuid.uuid4().hex[:8]}"

    event = TelemetryEvent(
        event_id=f"EVT-{uuid.uuid4().hex[:8]}",
        timestamp="2026-01-01T12:00:00Z",
        source_type="sensor",
        source_id=unique_dev,
        device_id=unique_dev,
        attack_type="DDoS",
        severity="CRITICAL",
        confidence=0.99,
        provenance="SYNTHETIC",
    )

    # Parent incident required by foreign key
    incident = store.create_incident(event, ["Volumetric flood detected"], "core")
    inc_id = incident["incident_id"]

    alert = store.create_or_update_alert(incident, event)
    assert alert is not None
    alt_id = alert["alert_id"]
    assert alert["incident_id"] == inc_id
    assert alert["acknowledgement_state"] == "UNACKNOWLEDGED"

    acked = store.acknowledge_alert(alt_id, "test_admin")
    assert acked is not None
    assert acked["acknowledgement_state"] == "ACKNOWLEDGED"
    assert acked["acknowledged_by"] == "test_admin"

    store.close()


# =============================================================================
# SCENARIO 7: Device Identity Operations (Upsert)
# =============================================================================

def test_scenario_07_device_identity_operations(test_database_url: str):
    """Verify device insertion and PostgreSQL EXCLUDED upsert handling."""
    settings = _make_test_settings(test_database_url)
    store = create_gateway_store(settings)
    assert isinstance(store, PostgresGatewayStore)

    dev_id = f"TEST-DEV-{uuid.uuid4().hex[:8]}"

    # Initial upsert
    store.upsert_device_identity(
        device_id=dev_id,
        role="sensor",
        auth_key_hash="hash_v1",
        status="ENROLLED",
        trust_score=100.0,
        failures=0,
    )
    dev = store.get_device_identity(dev_id)
    assert dev is not None
    assert dev["trust_score"] == 100.0

    # Secondary upsert (EXCLUDED update)
    store.upsert_device_identity(
        device_id=dev_id,
        role="sensor",
        auth_key_hash="hash_v2",
        status="DEGRADED",
        trust_score=60.0,
        failures=3,
    )
    updated_dev = store.get_device_identity(dev_id)
    assert updated_dev["trust_score"] == 60.0
    assert updated_dev["failures"] == 3
    assert updated_dev["status"] == "DEGRADED"

    store.close()


# =============================================================================
# SCENARIO 8: Trust History
# =============================================================================

def test_scenario_08_trust_history(test_database_url: str):
    """Verify trust progression recording and seq_id exclusion in public dictionary."""
    settings = _make_test_settings(test_database_url)
    store = create_gateway_store(settings)
    assert isinstance(store, PostgresGatewayStore)

    identity = f"TEST-DEV-{uuid.uuid4().hex[:8]}"
    store.record_trust(identity, 90.0, -10.0, "Anomaly penalty")
    store.record_trust(identity, 85.0, -5.0, "Secondary anomaly")

    history = store.trust(identity)
    assert len(history) == 2
    # Verify seq_id is stripped
    assert "seq_id" not in history[0]
    assert "seq_id" not in history[1]
    assert history[0]["score"] == 90.0
    assert history[1]["score"] == 85.0
    assert history[0]["delta"] == -10.0
    assert history[1]["delta"] == -5.0

    store.close()


# =============================================================================
# SCENARIO 9: Audit Hash-Chain Integrity
# =============================================================================

def test_scenario_09_audit_hash_chain_integrity(test_database_url: str):
    """Verify cryptographic linear hash-chain computation and integrity verification."""
    settings = _make_test_settings(test_database_url)
    store = create_gateway_store(settings)
    assert isinstance(store, PostgresGatewayStore)

    # Record two audit entries
    store.record_audit(
        username="test_admin",
        role="ADMIN",
        action="TEST_ACTION_A",
        resource="firewall",
        resource_id="rule_1",
        result="SUCCESS",
        details="First integration test audit record",
    )
    store.record_audit(
        username="test_admin",
        role="ADMIN",
        action="TEST_ACTION_B",
        resource="firewall",
        resource_id="rule_2",
        result="SUCCESS",
        details="Second integration test audit record",
    )

    # Verify chain
    result = store.verify_audit_log_integrity()
    assert result["valid"] is True
    assert result["count"] >= 2
    assert result["first_corrupted_id"] is None

    store.close()


# =============================================================================
# SCENARIO 10: Connection Pooling, Rollback, and Cleanup
# =============================================================================

def test_scenario_10_connection_pooling_and_rollback(test_database_url: str):
    """Verify transaction rollback on exception and clean pool closure."""
    settings = _make_test_settings(test_database_url)
    store = create_gateway_store(settings)
    assert isinstance(store, PostgresGatewayStore)

    # Simulate an error inside the connection context manager
    with pytest.raises(RuntimeError, match="simulated_failure"):
        with store.connection():
            raise RuntimeError("simulated_failure")

    # Verify that a subsequent connection from the pool is healthy
    with store.connection() as con:
        with con.cursor() as cur:
            cur.execute("SELECT 1;")
            assert cur.fetchone()[0] == 1

    store.close()
    assert store._pool is None


# =============================================================================
# SCENARIO 11: Multi-Session Restart and Persistence
# =============================================================================

def test_scenario_11_restart_and_persistence(test_database_url: str):
    """Verify data persistence across distinct store lifecycles and pool restarts."""
    settings = _make_test_settings(test_database_url)
    dev_id = f"TEST-PERSIST-{uuid.uuid4().hex[:8]}"

    # Session 1: Write
    store1 = create_gateway_store(settings)
    store1.upsert_device_identity(
        device_id=dev_id,
        role="sensor",
        auth_key_hash="persist_hash",
        status="ENROLLED",
        trust_score=99.0,
        failures=0,
    )
    store1.close()

    # Session 2: Connect, read, and verify
    store2 = create_gateway_store(settings)
    dev = store2.get_device_identity(dev_id)
    assert dev is not None
    assert dev["device_id"] == dev_id
    assert dev["trust_score"] == 99.0
    store2.close()

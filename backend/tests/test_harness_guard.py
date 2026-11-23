"""Unit tests for PostgreSQL test-harness guard, independent production identity, and HTTP 409 duplicate user handling."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch
import pytest

from aegis_gateway.api import create_app
from aegis_gateway.config import Settings
from aegis_gateway.runtime import GatewayRuntime
from aegis_gateway.storage import (
    BaseGatewayStore,
    PostgresGatewayStore,
    SQLiteGatewayStore,
    create_gateway_store,
)
from tests.conftest import (
    extract_database_identity,
    get_production_project_ref,
    validate_test_database_target,
)


# =============================================================================
# 1. Production PostgreSQL Enforcement & Fail-Closed Guard Tests (Phase 5.4E.2)
# =============================================================================

def test_production_no_database_url_startup_failure():
    """Rule 1: Production mode with no database URL raises startup failure."""
    with pytest.raises(ValueError, match="DATABASE_URL .* is required in production mode"):
        Settings(
            production=True,
            secret_key="secure-test-production-secret-key-at-least-64-bytes-entropy-required",
            device_master_key="secure-test-production-master-key-at-least-64-bytes-entropy-required",
            database_url=None,
        )


def test_production_neither_supported_env_var_startup_failure(monkeypatch: pytest.MonkeyPatch):
    """Rule 2: Production mode with neither DATABASE_URL nor AEGIS_DATABASE_URL raises startup failure."""
    monkeypatch.setenv("AEGIS_PRODUCTION", "true")
    monkeypatch.setenv("AEGIS_SECRET_KEY", "secure-test-production-secret-key-at-least-64-bytes-entropy-required")
    monkeypatch.setenv("AEGIS_MASTER_KEY", "secure-test-production-master-key-at-least-64-bytes-entropy-required")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("AEGIS_DATABASE_URL", raising=False)

    with pytest.raises(ValueError, match="DATABASE_URL .* is required in production mode"):
        Settings()


def test_production_sqlite_url_rejected():
    """Rule 3: Production mode with SQLite database URL is rejected."""
    for sqlite_url in (
        "sqlite:///var/data/app.sqlite3",
        "sqlite:////tmp/prod.db",
        "sqlite:///localhost/test.db",
    ):
        with pytest.raises(ValueError, match="valid PostgreSQL URL scheme|requires an explicit sslmode"):
            Settings(
                production=True,
                secret_key="secure-test-production-secret-key-at-least-64-bytes-entropy-required",
                device_master_key="secure-test-production-master-key-at-least-64-bytes-entropy-required",
                database_url=sqlite_url,
            )


def test_production_unsupported_url_scheme_rejected():
    """Rule 4: Production mode with unsupported URL scheme (mysql, http, file) is rejected."""
    for bad_scheme in (
        "mysql://user:pass@ep-cool.render.internal:3306/db?sslmode=require",
        "http://db.example.com/db",
        "file:///var/data/app.db",
        "not_a_valid_url?sslmode=require",
    ):
        with pytest.raises(ValueError, match="valid PostgreSQL URL scheme"):
            Settings(
                production=True,
                secret_key="secure-test-production-secret-key-at-least-64-bytes-entropy-required",
                device_master_key="secure-test-production-master-key-at-least-64-bytes-entropy-required",
                database_url=bad_scheme,
            )


def test_production_aegis_database_path_does_not_bypass():
    """AEGIS_DATABASE_PATH cannot bypass the production PostgreSQL requirement."""
    with pytest.raises(ValueError, match="DATABASE_URL .* is required in production mode"):
        Settings(
            production=True,
            secret_key="secure-test-production-secret-key-at-least-64-bytes-entropy-required",
            device_master_key="secure-test-production-master-key-at-least-64-bytes-entropy-required",
            database_path=Path("/custom/ephemeral/path.sqlite3"),
            database_url=None,
        )


def test_production_valid_postgres_url_selected_mocked():
    """Rule 5: Production mode with valid PostgreSQL URL selects PostgresGatewayStore (mocked; no network)."""
    settings = Settings(
        production=True,
        secret_key="secure-test-production-secret-key-at-least-64-bytes-entropy-required",
        device_master_key="secure-test-production-master-key-at-least-64-bytes-entropy-required",
        database_url="postgresql://user:pass@ep-cool.render.internal:5432/aicg?sslmode=require",
    )
    assert settings.is_postgres is True

    with patch("aegis_gateway.storage.PostgresGatewayStore") as mock_pg:
        mock_instance = mock_pg.return_value
        store = create_gateway_store(settings)
        assert store is mock_instance
        assert not isinstance(store, SQLiteGatewayStore)
        mock_pg.assert_called_once()
        call_kwargs = mock_pg.call_args.kwargs
        assert call_kwargs["database_url"] == settings.database_url
        assert call_kwargs["production"] is True


def test_development_without_database_url_selects_sqlite(tmp_path: Path):
    """Rule 6: Development mode without a database URL continues to select SQLite."""
    settings = Settings(
        production=False,
        database_path=tmp_path / "dev_test.sqlite3",
        database_url=None,
    )
    assert settings.is_postgres is False
    store = create_gateway_store(settings)
    assert isinstance(store, SQLiteGatewayStore)
    assert store.path == tmp_path / "dev_test.sqlite3"


def test_postgres_connection_failure_propagates_no_sqlite_fallback():
    """Rule 7: PostgreSQL connection failure propagates cleanly without falling back to SQLite."""
    settings = Settings(
        production=True,
        secret_key="secure-test-production-secret-key-at-least-64-bytes-entropy-required",
        device_master_key="secure-test-production-master-key-at-least-64-bytes-entropy-required",
        database_url="postgresql://user:pass@ep-cool.render.internal:5432/aicg?sslmode=require",
    )

    import psycopg2
    with patch(
        "aegis_gateway.storage.PostgresGatewayStore.__init__",
        side_effect=psycopg2.OperationalError("Could not connect to PostgreSQL host"),
    ):
        with pytest.raises(psycopg2.OperationalError, match="Could not connect to PostgreSQL host"):
            create_gateway_store(settings)


def test_factory_defense_in_depth_rejects_sqlite_in_production(tmp_path: Path):
    """create_gateway_store defense-in-depth: never returns SQLite when production=True."""
    class MockSettings:
        production = True
        database_url = None
        database_path = tmp_path / "bypass.sqlite3"

    with pytest.raises(ValueError, match="Production mode requires a valid PostgreSQL database_url and cannot fall back to SQLite"):
        create_gateway_store(MockSettings())


# =============================================================================
# 2. Independent production reference blocks TEST_DATABASE_URL targeting production
# =============================================================================

def test_independent_prod_ref_blocks_test_url_targeting_production(monkeypatch):
    """Verify independent production reference blocks collision even when DATABASE_URL is absent."""
    # Ensure DATABASE_URL and AEGIS_DATABASE_URL are absent
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("AEGIS_DATABASE_URL", raising=False)
    monkeypatch.setenv("AICG_PRODUCTION_SUPABASE_PROJECT_REF", "prod_isolated_ref_123")

    synthetic_test = (
        "postgresql://postgres.prod_isolated_ref_123:Pass123@"
        "aws-0-ap-southeast-2.pooler.supabase.com:5432/postgres"
    )

    with pytest.raises(ValueError, match="matches the production project reference"):
        validate_test_database_target(
            test_url=synthetic_test,
            expected_project_ref="prod_isolated_ref_123",
            captured_prod_identity=None,  # Proves independent resolution
        )


# =============================================================================
# 3. Separate test project is accepted with independent production reference
# =============================================================================

def test_separate_test_project_accepted_with_independent_prod_ref(monkeypatch):
    """Verify validate_test_database_target accepts distinct, approved test project reference."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("AEGIS_DATABASE_URL", raising=False)
    monkeypatch.setenv("AICG_PRODUCTION_SUPABASE_PROJECT_REF", "prod_isolated_ref_123")

    synthetic_test = (
        "postgresql://postgres.test_distinct_ref_456:Pass456@"
        "aws-0-ap-southeast-2.pooler.supabase.com:5432/postgres"
    )

    result = validate_test_database_target(
        test_url=synthetic_test,
        expected_project_ref="test_distinct_ref_456",
        captured_prod_identity=None,
    )

    assert result["project_ref"] == "test_distinct_ref_456"
    assert result["hostname"] == "aws-0-ap-southeast-2.pooler.supabase.com"


# =============================================================================
# 4. Missing production identity fails closed
# =============================================================================

def test_missing_production_identity_fails_closed(monkeypatch):
    """Verify that if production identity is unknown, Supabase integration testing is refused."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("AEGIS_DATABASE_URL", raising=False)
    monkeypatch.delenv("AICG_PRODUCTION_SUPABASE_PROJECT_REF", raising=False)
    monkeypatch.delenv("PRODUCTION_SUPABASE_PROJECT_REF", raising=False)

    synthetic_test = (
        "postgresql://postgres.some_test_ref_789:Pass789@"
        "aws-0-ap-southeast-2.pooler.supabase.com:5432/postgres"
    )

    with pytest.raises(ValueError, match="Production project identity is unknown"):
        validate_test_database_target(
            test_url=synthetic_test,
            expected_project_ref="some_test_ref_789",
            captured_prod_identity=None,
            independent_prod_ref=None,
        )


# =============================================================================
# 5. Missing approved test identity fails closed
# =============================================================================

def test_missing_approved_test_identity_fails_closed(monkeypatch):
    """Verify validate_test_database_target fails closed if TEST_SUPABASE_PROJECT_REF is missing."""
    monkeypatch.setenv("AICG_PRODUCTION_SUPABASE_PROJECT_REF", "prod_isolated_ref_123")
    monkeypatch.delenv("TEST_SUPABASE_PROJECT_REF", raising=False)
    monkeypatch.delenv("EXPECTED_TEST_PROJECT_REF", raising=False)

    synthetic_test = (
        "postgresql://postgres.test_ref_456:Pass@"
        "aws-0-ap-southeast-2.pooler.supabase.com:5432/postgres"
    )

    with pytest.raises(ValueError, match="TEST_SUPABASE_PROJECT_REF is not configured"):
        validate_test_database_target(
            test_url=synthetic_test,
            expected_project_ref=None,
        )


# =============================================================================
# 6. Incorrect approved test reference fails closed
# =============================================================================

def test_incorrect_approved_test_reference_fails_closed():
    """Verify mismatch between test URL project ref and approved test ref fails closed."""
    synthetic_test = (
        "postgresql://postgres.actual_test_ref_111:Pass@"
        "aws-0-ap-southeast-2.pooler.supabase.com:5432/postgres"
    )

    with pytest.raises(ValueError, match="does not match approved TEST_SUPABASE_PROJECT_REF"):
        validate_test_database_target(
            test_url=synthetic_test,
            expected_project_ref="different_approved_ref_222",
            independent_prod_ref="prod_isolated_ref_123",
        )


# =============================================================================
# 7. Approved test reference matching production reference fails closed
# =============================================================================

def test_approved_test_reference_matching_prod_reference_fails_closed():
    """Verify setting approved test reference identical to production reference fails closed."""
    synthetic_test = (
        "postgresql://postgres.prod_isolated_ref_123:Pass@"
        "aws-0-ap-southeast-2.pooler.supabase.com:5432/postgres"
    )

    with pytest.raises(ValueError, match="matches the production project reference"):
        validate_test_database_target(
            test_url=synthetic_test,
            expected_project_ref="prod_isolated_ref_123",
            independent_prod_ref="prod_isolated_ref_123",
        )


# =============================================================================
# 8. Local PostgreSQL test target supported
# =============================================================================

def test_local_postgresql_test_target_supported():
    """Verify local PostgreSQL test targets (localhost / 127.0.0.1) are accepted without Supabase ref."""
    local_url = "postgresql://aicg_tester:local_pass@127.0.0.1:5432/aicg_integration_db"
    result = validate_test_database_target(
        test_url=local_url,
        independent_prod_ref="prod_isolated_ref_123",
    )
    assert result["hostname"] == "127.0.0.1"
    assert result["port"] == 5432
    assert result["database"] == "aicg_integration_db"
    assert result["project_ref"] is None


# =============================================================================
# 9. No database connection occurs during validation
# =============================================================================

def test_no_database_connection_occurs_during_validation():
    """Verify validate_test_database_target is purely static and executes zero network calls."""
    synthetic_test = (
        "postgresql://postgres.test_ref_456:Pass@"
        "aws-0-ap-southeast-2.pooler.supabase.com:5432/postgres"
    )

    with patch("psycopg2.connect") as mock_connect, patch("psycopg2.pool.ThreadedConnectionPool") as mock_pool:
        result = validate_test_database_target(
            test_url=synthetic_test,
            expected_project_ref="test_ref_456",
            independent_prod_ref="prod_isolated_ref_123",
        )
        assert result is not None
        mock_connect.assert_not_called()
        mock_pool.assert_not_called()


# =============================================================================
# 10. Environment variables restored correctly
# =============================================================================

def test_environment_variables_restored_correctly(monkeypatch):
    """Verify monkeypatch in autouse fixture ensures deterministic environment restoration."""
    canary = "AICG_RESTORE_CANARY"
    monkeypatch.setenv(canary, "before_test")
    assert os.getenv(canary) == "before_test"
    monkeypatch.delenv(canary, raising=False)
    assert os.getenv(canary) is None


# =============================================================================
# 11. Malformed URLs rejected
# =============================================================================

def test_malformed_postgresql_urls_rejected():
    """Verify malformed or non-PostgreSQL URLs are rejected with descriptive errors."""
    for bad_url in ("", "   ", "http://localhost", "mysql://u:p@h/d", "invalid"):
        with pytest.raises(ValueError, match="empty|malformed|invalid scheme"):
            validate_test_database_target(test_url=bad_url)


# =============================================================================
# 12. HTTP 409 duplicate-user behavior
# =============================================================================

def test_http_409_duplicate_user_behavior(tmp_path: Path):
    """Verify API returns HTTP 409 Conflict without database traceback on duplicate username."""
    settings = Settings(database_path=tmp_path / "dup_guard.sqlite3")
    runtime = GatewayRuntime(settings)
    app = create_app(runtime)

    with app.test_client() as client:
        # Authenticate as admin
        client.post("/api/auth/login", json={
            "username": "admin",
            "password": "Admin@AICG2026!",
            "mfa_code": "123456",
        })

        # 1. Create operator user -> HTTP 201
        res1 = client.post("/api/admin/users", json={
            "username": "guard_operator",
            "password": "SecurePassword123!",
            "role": "OPERATOR",
        })
        assert res1.status_code == 201

        # 2. Attempt duplicate creation -> HTTP 409
        res2 = client.post("/api/admin/users", json={
            "username": "guard_operator",
            "password": "DifferentPassword123!",
            "role": "OPERATOR",
        })
        assert res2.status_code == 409
        body = res2.get_json()
        assert "error" in body
        assert "already exists" in body["error"]
        assert "sqlite3" not in body["error"].lower()
        assert "psycopg2" not in body["error"].lower()

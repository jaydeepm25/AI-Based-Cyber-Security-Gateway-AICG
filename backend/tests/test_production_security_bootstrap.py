"""Tests for production credential security, fail-fast configuration, and admin bootstrap."""

from pathlib import Path
import pytest
from aegis_gateway.config import (
    LAB_MASTER_KEY_FALLBACK,
    LAB_SECRET_KEY_FALLBACK,
    Settings,
)
from aegis_gateway.runtime import GatewayRuntime
from aegis_gateway.security import hash_password, verify_password
from aegis_gateway.storage import GatewayStore, SQLiteGatewayStore


def test_production_startup_missing_secret_key():
    """Verify production startup fails fast when AEGIS_SECRET_KEY is missing or lab fallback."""
    with pytest.raises(ValueError, match="AEGIS_SECRET_KEY environment variable is required"):
        Settings(
            production=True,
            secret_key=LAB_SECRET_KEY_FALLBACK,
            device_master_key="prod-master-key-xyz-987654321",
            database_url="postgresql://user:pass@localhost:5432/test_db",
        )


def test_production_startup_missing_device_master_key():
    """Verify production startup fails fast when device master key is missing or lab fallback."""
    with pytest.raises(ValueError, match="AEGIS_MASTER_KEY .* environment variable is required"):
        Settings(
            production=True,
            secret_key="prod-secret-key-xyz-123456789",
            device_master_key=LAB_MASTER_KEY_FALLBACK,
            database_url="postgresql://user:pass@localhost:5432/test_db",
        )


def test_production_startup_without_admin_credentials_on_fresh_db(tmp_path):
    """Verify production first-run bootstrap fails fast when administrator password is not set."""
    db_path = tmp_path / "prod_unbootstrapped.sqlite3"
    with pytest.raises(RuntimeError, match="AEGIS_INITIAL_ADMIN_PASSWORD is required"):
        SQLiteGatewayStore(
            path=db_path,
            production=True,
            initial_admin_password=None,
        )


def test_production_startup_with_valid_bootstrap(tmp_path):
    """Verify production first-run bootstraps custom admin securely and creates no demo accounts."""
    db_path = tmp_path / "prod_bootstrapped.sqlite3"
    admin_pw = "EnterpriseSecureP@ssw0rd2026!"
    store = SQLiteGatewayStore(
        path=db_path,
        production=True,
        initial_admin_username="enterprise_admin",
        initial_admin_password=admin_pw,
    )

    # 1. Verify custom admin account created
    admin_user = store.get_admin_user("enterprise_admin")
    assert admin_user is not None
    assert admin_user["role"] == "ADMIN"
    assert admin_user["status"] == "ACTIVE"
    assert verify_password(admin_pw, admin_user["password_hash"])
    assert not verify_password("WrongPassword123!", admin_user["password_hash"])

    # 2. Verify demo operator account is NOT created in production
    operator_user = store.get_admin_user("operator")
    assert operator_user is None
    default_admin = store.get_admin_user("admin")
    assert default_admin is None

    # 3. Subsequent startup on the same DB succeeds even without initial_admin_password
    store_subsequent = SQLiteGatewayStore(
        path=db_path,
        production=True,
        initial_admin_password=None,
    )
    user_check = store_subsequent.get_admin_user("enterprise_admin")
    assert user_check is not None


def test_development_demo_account_initialization(tmp_path):
    """Verify development/demo environment seeds standard demo accounts when enabled."""
    db_path = tmp_path / "dev_test.sqlite3"
    settings = Settings(
        production=False,
        allow_demo_accounts=True,
        database_path=db_path,
    )
    runtime = GatewayRuntime(settings)

    admin = runtime.store.get_admin_user("admin")
    operator = runtime.store.get_admin_user("operator")
    assert admin is not None
    assert admin["role"] == "ADMIN"
    assert verify_password("Admin@AICG2026!", admin["password_hash"])

    assert operator is not None
    assert operator["role"] == "OPERATOR"
    assert verify_password("Operator@AICG2026!", operator["password_hash"])


def test_testing_account_initialization_with_disabled_demo_accounts(tmp_path):
    """Verify demo accounts can be explicitly suppressed in non-production environments."""
    db_path = tmp_path / "no_demo.sqlite3"
    settings = Settings(
        production=False,
        allow_demo_accounts=False,
        database_path=db_path,
    )
    runtime = GatewayRuntime(settings)

    assert runtime.store.get_admin_user("admin") is None
    assert runtime.store.get_admin_user("operator") is None


def test_password_hashing_and_verification():
    """Verify password hashing produces distinct salts and constant-time matching."""
    pw = "SuperSecretIndustrialKey2026!"
    h1 = hash_password(pw)
    h2 = hash_password(pw)
    assert h1 != h2, "Hashes must contain unique per-generation salts"
    assert verify_password(pw, h1)
    assert verify_password(pw, h2)
    assert not verify_password("WrongKey123", h1)
    assert not verify_password("", h1)
    assert not verify_password(pw, "")


def test_rbac_behavior_with_production_bootstrapped_users(tmp_path):
    """Verify RBAC role checks continue to operate properly with production-bootstrapped accounts."""
    db_path = tmp_path / "rbac_prod.sqlite3"
    store = SQLiteGatewayStore(
        path=db_path,
        production=True,
        initial_admin_username="sec_admin",
        initial_admin_password="SecureAdminPassword@2026!",
    )

    # Admin creates an operator account dynamically via store
    store.create_admin_user(
        username="sec_operator",
        password_hash=hash_password("SecureOperatorPassword@2026!"),
        role="OPERATOR",
    )

    admin_u = store.get_admin_user("sec_admin")
    operator_u = store.get_admin_user("sec_operator")

    assert admin_u["role"] == "ADMIN"
    assert operator_u["role"] == "OPERATOR"

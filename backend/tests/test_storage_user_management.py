"""Comprehensive test suite for Phase 1 User Management storage layer enhancements.

Verifies:
1. Backward-compatible schema migration of admin_users with must_change_password.
2. Preservation of existing user records and password hashes during migration.
3. SQLiteDataStore implementation of:
   - update_admin_user_password()
   - update_admin_user_username()
   - delete_admin_user()
   - list_admin_users() with must_change_password field
   - create_admin_user() with must_change_password support
4. PostgreSQLDataStore compatibility and parity for all new methods.
"""

from __future__ import annotations

from pathlib import Path
import sqlite3
from unittest.mock import MagicMock, patch

import pytest
try:
    import psycopg2
    import psycopg2.extensions
except ImportError:
    psycopg2 = None

from aegis_gateway.storage import PostgresGatewayStore, SQLiteGatewayStore


def test_sqlite_backward_compatible_schema_migration(tmp_path: Path):
    """Verify legacy SQLite databases without must_change_password migrate cleanly and preserve records."""
    db_file = tmp_path / "legacy_gateway.sqlite3"

    # 1. Create a legacy database mimicking pre-Phase 1 schema
    con = sqlite3.connect(db_file)
    con.execute(
        """
        CREATE TABLE admin_users (
            user_id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
            role TEXT NOT NULL, status TEXT NOT NULL, mfa_enabled INTEGER NOT NULL DEFAULT 1,
            mfa_status TEXT NOT NULL DEFAULT 'SIMULATED_VERIFIED', created_at TEXT NOT NULL, last_login TEXT
        );
        """
    )
    legacy_hash = "scrypt:32768:8:1$legacy_salt$legacy_hash_string_12345"
    con.execute(
        """
        INSERT INTO admin_users (user_id, username, password_hash, role, status, mfa_enabled, mfa_status, created_at, last_login)
        VALUES ('USR-LEGACY-01', 'legacy_admin', ?, 'ADMIN', 'ACTIVE', 1, 'SIMULATED_VERIFIED', '2026-01-01T00:00:00Z', NULL);
        """,
        (legacy_hash,)
    )
    con.commit()
    con.close()

    # 2. Instantiate SQLiteGatewayStore to trigger initialize() and _migrate_schema()
    store = SQLiteGatewayStore(db_file)

    # 3. Verify column was added
    with store.connection() as c:
        cols = [r["name"] for r in c.execute("PRAGMA table_info(admin_users)").fetchall()]
        assert "must_change_password" in cols

    # 4. Verify existing record and hash are 100% preserved
    legacy_user = store.get_admin_user("legacy_admin")
    assert legacy_user is not None
    assert legacy_user["user_id"] == "USR-LEGACY-01"
    assert legacy_user["username"] == "legacy_admin"
    assert legacy_user["password_hash"] == legacy_hash
    assert legacy_user["must_change_password"] is False

    # 5. Idempotency check: run initialize again
    store.initialize()
    user_after = store.get_admin_user("legacy_admin")
    assert user_after["password_hash"] == legacy_hash


def test_sqlite_create_and_list_admin_users_with_must_change_password(tmp_path: Path):
    """Verify create_admin_user and list_admin_users handle must_change_password correctly."""
    db_file = tmp_path / "users_flag.sqlite3"
    store = SQLiteGatewayStore(db_file)

    # User with default must_change_password (False)
    u1 = store.create_admin_user("analyst_normal", "hash_normal", "OPERATOR")
    assert u1["must_change_password"] is False

    # User with must_change_password=True
    u2 = store.create_admin_user("analyst_forced", "hash_forced", "OPERATOR", must_change_password=True)
    assert u2["must_change_password"] is True

    # List users
    users = store.list_admin_users()
    user_map = {u["username"]: u for u in users}
    assert user_map["analyst_normal"]["must_change_password"] is False
    assert user_map["analyst_forced"]["must_change_password"] is True
    # Password hash must not be in list output
    assert "password_hash" not in user_map["analyst_normal"]


def test_sqlite_update_admin_user_password(tmp_path: Path):
    """Verify update_admin_user_password properly updates hash, sets/clears flag, and validates inputs."""
    db_file = tmp_path / "pw_update.sqlite3"
    store = SQLiteGatewayStore(db_file)

    created = store.create_admin_user("user_pw", "initial_hash", "OPERATOR")
    user_id = created["user_id"]

    # 1. Update password and set must_change_password to True
    res = store.update_admin_user_password(user_id, "new_hashed_secret", must_change_password=True)
    assert res["user_id"] == user_id
    assert "password_hash" not in res  # Stripped for safety
    assert res["must_change_password"] is True

    user_db = store.get_admin_user_by_id(user_id)
    assert user_db["password_hash"] == "new_hashed_secret"
    assert user_db["must_change_password"] is True

    # 2. Update password and clear must_change_password
    res2 = store.update_admin_user_password(user_id, "cleared_hash", must_change_password=False)
    assert res2["must_change_password"] is False

    # 3. Update password without touching must_change_password (must_change_password=None)
    res3 = store.update_admin_user_password(user_id, "third_hash", must_change_password=None)
    assert res3["must_change_password"] is False

    # 4. Error validations
    with pytest.raises(ValueError, match="Password hash is required"):
        store.update_admin_user_password(user_id, "")
    with pytest.raises(ValueError, match="Password hash is required"):
        store.update_admin_user_password(user_id, "   ")

    with pytest.raises(KeyError, match="User not found"):
        store.update_admin_user_password("NON_EXISTENT_ID", "some_hash")


def test_sqlite_update_admin_user_username(tmp_path: Path):
    """Verify update_admin_user_username renames user, prevents duplicates, and validates input."""
    db_file = tmp_path / "user_rename.sqlite3"
    store = SQLiteGatewayStore(db_file)

    u1 = store.create_admin_user("first_name", "hash1", "OPERATOR")
    u2 = store.create_admin_user("second_name", "hash2", "OPERATOR")

    # 1. Successful rename
    renamed = store.update_admin_user_username(u1["user_id"], "renamed_name")
    assert renamed["username"] == "renamed_name"
    assert "password_hash" not in renamed

    # Verify lookup by new username works and old username is gone
    assert store.get_admin_user("renamed_name") is not None
    assert store.get_admin_user("first_name") is None

    # 2. Same username update is no-op and returns user
    same = store.update_admin_user_username(u1["user_id"], "renamed_name")
    assert same["username"] == "renamed_name"

    # 3. Duplicate username raises ValueError
    with pytest.raises(ValueError, match="already exists"):
        store.update_admin_user_username(u1["user_id"], "second_name")

    # 4. Empty username raises ValueError
    with pytest.raises(ValueError, match="cannot be empty"):
        store.update_admin_user_username(u1["user_id"], "   ")

    # 5. Non-existent user raises KeyError
    with pytest.raises(KeyError, match="User not found"):
        store.update_admin_user_username("NON_EXISTENT_ID", "new_valid_name")


def test_sqlite_delete_admin_user(tmp_path: Path):
    """Verify delete_admin_user removes user and handles edge cases."""
    db_file = tmp_path / "user_delete.sqlite3"
    store = SQLiteGatewayStore(db_file)

    created = store.create_admin_user("to_delete", "hash", "OPERATOR")
    user_id = created["user_id"]

    # 1. Delete user
    deleted = store.delete_admin_user(user_id)
    assert deleted is True

    # User no longer exists
    assert store.get_admin_user_by_id(user_id) is None
    assert store.get_admin_user("to_delete") is None

    # 2. Deleting already deleted user returns False
    assert store.delete_admin_user(user_id) is False

    # 3. Deleting with empty id returns False
    assert store.delete_admin_user("") is False
    assert store.delete_admin_user(None) is False


def test_postgres_storage_user_management_parity():
    """Verify PostgreSQLGatewayStore methods match SQLite behavior and error contracts using mock pool."""
    if not psycopg2:
        pytest.skip("psycopg2 not installed in current environment")

    with patch("psycopg2.pool.ThreadedConnectionPool") as mock_pool_cls:
        mock_pool = MagicMock()
        mock_con = MagicMock()
        mock_con.closed = False
        mock_con.status = psycopg2.extensions.STATUS_READY
        mock_cur = MagicMock()
        mock_con.cursor.return_value.__enter__.return_value = mock_cur
        mock_pool.getconn.return_value = mock_con
        mock_pool_cls.return_value = mock_pool

        pg_store = PostgresGatewayStore("postgresql://localhost/db", initialize=False)

        # 1. Test delete_admin_user
        mock_cur.fetchone.side_effect = [
            {"role": "OPERATOR", "status": "ACTIVE"},  # Target found
            None,  # Target not found for USR-02
        ]
        mock_cur.rowcount = 1
        assert pg_store.delete_admin_user("USR-01") is True
        mock_cur.rowcount = 0
        assert pg_store.delete_admin_user("USR-02") is False
        assert pg_store.delete_admin_user("") is False

        # 2. Test update_admin_user_username with duplicate key violation
        mock_cur.fetchone.side_effect = None
        mock_cur.fetchone.return_value = {
            "user_id": "USR-01",
            "username": "old_name",
            "role": "OPERATOR",
            "status": "ACTIVE",
            "password_hash": "some_hash",
        }
        mock_cur.execute.side_effect = [
            None,  # SELECT for get_admin_user_by_id
            psycopg2.IntegrityError('duplicate key value violates unique constraint "admin_users_username_key"'),
        ]
        with pytest.raises(ValueError, match="already exists"):
            pg_store.update_admin_user_username("USR-01", "existing_name")

        # 3. Test update_admin_user_password input validation
        with pytest.raises(ValueError, match="Password hash is required"):
            pg_store.update_admin_user_password("USR-01", "")


def test_database_level_last_active_admin_atomic_protection(tmp_path: Path):
    """Verify that SQLiteGatewayStore enforces last-active-admin protection directly at the database transaction level."""
    db_file = tmp_path / "atomic_last_admin.sqlite3"
    store = SQLiteGatewayStore(db_file)

    # By default, store initializes 'admin' (role=ADMIN, status=ACTIVE)
    admin_user = store.get_admin_user("admin")
    admin_id = admin_user["user_id"]

    # 1. Attempting to delete the sole active admin at DB level raises ValueError
    with pytest.raises(ValueError, match="Cannot delete the last remaining active administrator account"):
        store.delete_admin_user(admin_id)

    # 2. Attempting to disable the sole active admin at DB level raises ValueError
    with pytest.raises(ValueError, match="Cannot disable the last active administrator account"):
        store.update_admin_user_status(admin_id, "DISABLED")

    # 3. Attempting to demote the sole active admin at DB level raises ValueError
    with pytest.raises(ValueError, match="Cannot demote the last active administrator account"):
        store.update_admin_user_role(admin_id, "OPERATOR")

    # 4. If a second active admin exists, operations on one of them succeed
    admin2 = store.create_admin_user("admin2", "hash2", "ADMIN", "ACTIVE")
    admin2_id = admin2["user_id"]

    # Can now demote admin2
    demoted = store.update_admin_user_role(admin2_id, "OPERATOR")
    assert demoted["role"] == "OPERATOR"

    # Promoting back
    promoted = store.update_admin_user_role(admin2_id, "ADMIN")
    assert promoted["role"] == "ADMIN"

    # Can now delete admin2 (admin is still active)
    assert store.delete_admin_user(admin2_id) is True

    # Now admin is sole active admin again -> deletion blocked again
    with pytest.raises(ValueError, match="Cannot delete the last remaining active administrator account"):
        store.delete_admin_user(admin_id)

"""Comprehensive tests for Phase 2 User Management APIs and Authentication Flow.

Tests:
- Admin password reset (PATCH /api/admin/users/<id>)
- Password hashing, validation and policy enforcement
- Mandatory password-change enforcement (restricted session)
- Change password endpoint (POST /api/auth/change-password)
- Two-stage MFA login flow with must_change_password
- Username modification and duplicate conflict handling
- Role and status modification with last-active-admin protection
- User deletion (DELETE /api/admin/users/<id>)
- Self-deletion and last-active-admin deletion prevention
- Operator RBAC denial on administrative endpoints
- Audit event creation and cryptographic hash-chain integrity
- Strict redaction of plaintext passwords and hashes
"""

from pathlib import Path
import pytest
from aegis_gateway.api import create_app
from aegis_gateway.config import Settings
from aegis_gateway.runtime import GatewayRuntime
from aegis_gateway.security import (
    DEFAULT_SIMULATED_MFA_TOKEN,
    ROLE_ADMIN,
    ROLE_OPERATOR,
    hash_password,
    verify_password,
)


@pytest.fixture
def test_app(tmp_path: Path):
    settings = Settings(
        database_path=tmp_path / "test_user_mgmt_api.sqlite3",
        report_dir=tmp_path / "reports",
        dataset_dir=tmp_path / "datasets",
    )
    runtime = GatewayRuntime(settings)
    app = create_app(runtime)
    return runtime, app


def _login(client, username="admin", password="Admin@AICG2026!", mfa_code=DEFAULT_SIMULATED_MFA_TOKEN):
    return client.post("/api/auth/login", json={
        "username": username,
        "password": password,
        "mfa_code": mfa_code,
    })


# =============================================================================
# 1. ADMIN PASSWORD RESET & PASSWORD POLICY ENFORCEMENT
# =============================================================================

def test_admin_password_reset_and_policy_validation(test_app):
    runtime, app = test_app
    with app.test_client() as client:
        # Login as admin
        login_res = _login(client, "admin", "Admin@AICG2026!")
        assert login_res.status_code == 200

        operator_user = runtime.store.get_admin_user("operator")
        op_id = operator_user["user_id"]

        # Attempt reset with weak password (< 8 chars) -> 400
        weak_res = client.patch(f"/api/admin/users/{op_id}", json={
            "password": "short"
        })
        assert weak_res.status_code == 400
        assert "at least 8 characters" in weak_res.get_json()["error"]

        # Reset with valid new password
        reset_res = client.patch(f"/api/admin/users/{op_id}", json={
            "password": "NewOperatorPass2026!"
        })
        assert reset_res.status_code == 200
        reset_data = reset_res.get_json()
        assert reset_data["user_id"] == op_id
        assert reset_data["must_change_password"] is True
        # Plaintext password and password hash must never be in the response
        assert "password" not in reset_data
        assert "password_hash" not in reset_data

        # Verify DB state
        updated_op = runtime.store.get_admin_user_by_id(op_id)
        assert updated_op["must_change_password"] == 1 or updated_op["must_change_password"] is True
        assert verify_password("NewOperatorPass2026!", updated_op["password_hash"]) is True

        # Verify audit record
        audits = runtime.store.list_audit_logs(limit=10)
        reset_events = [a for a in audits if a["action"] == "USER_PASSWORD_RESET"]
        assert len(reset_events) == 1
        assert reset_events[0]["resource_id"] == op_id
        assert reset_events[0]["result"] == "SUCCESS"
        assert "NewOperatorPass2026!" not in reset_events[0]["details"]
        assert "password_hash" not in reset_events[0]["details"]


# =============================================================================
# 2. MANDATORY PASSWORD CHANGE ENFORCEMENT & RESTRICTED SESSIONS
# =============================================================================

def test_mandatory_password_change_enforcement_flow(test_app):
    runtime, app = test_app
    with app.test_client() as admin_client:
        _login(admin_client, "admin", "Admin@AICG2026!")
        op_user = runtime.store.get_admin_user("operator")
        op_id = op_user["user_id"]
        # Admin resets operator's password
        admin_client.patch(f"/api/admin/users/{op_id}", json={"password": "TempPassword123!"})

    # Operator logs in with the newly reset password
    with app.test_client() as op_client:
        op_login = _login(op_client, "operator", "TempPassword123!")
        assert op_login.status_code == 200
        data = op_login.get_json()
        assert data["authenticated"] is True
        assert data["must_change_password"] is True
        assert data["permissions"] == []
        assert data["redirect"] == "/change-password"

        # Check /api/auth/status returns restricted state
        st_res = op_client.get("/api/auth/status")
        assert st_res.status_code == 200
        st_data = st_res.get_json()
        assert st_data["authenticated"] is True
        assert st_data["must_change_password"] is True
        assert st_data["permissions"] == []

        # Accessing dashboard/protected APIs must return 403 PASSWORD_CHANGE_REQUIRED
        overview_res = op_client.get("/api/admin/overview")
        assert overview_res.status_code == 403
        assert overview_res.get_json()["code"] == "PASSWORD_CHANGE_REQUIRED"
        assert overview_res.get_json()["must_change_password"] is True

        users_res = op_client.get("/api/admin/users")
        assert users_res.status_code == 403
        assert users_res.get_json()["code"] == "PASSWORD_CHANGE_REQUIRED"

        events_res = op_client.get("/events")
        assert events_res.status_code == 403
        assert events_res.get_json()["code"] == "PASSWORD_CHANGE_REQUIRED"

        # Verify ACCESS_DENIED audit log
        audits = runtime.store.list_audit_logs(limit=20)
        denied_logs = [a for a in audits if a["action"] == "ACCESS_DENIED" and "mandatory password change" in a["details"]]
        assert len(denied_logs) >= 1


def test_two_stage_mfa_login_mandatory_password_change(test_app):
    runtime, app = test_app
    # Set operator must_change_password = True
    op_user = runtime.store.get_admin_user("operator")
    runtime.store.update_admin_user_password(op_user["user_id"], op_user["password_hash"], must_change_password=True)

    with app.test_client() as client:
        # Stage 1: Primary password check (without MFA code)
        s1 = client.post("/api/auth/login", json={
            "username": "operator",
            "password": "Operator@AICG2026!"
        })
        assert s1.status_code == 200
        s1_data = s1.get_json()
        assert s1_data["mfa_required"] is True

        # Stage 2: Simulated MFA verification
        s2 = client.post("/api/auth/mfa/verify", json={
            "mfa_code": "123456"
        })
        assert s2.status_code == 200
        s2_data = s2.get_json()
        assert s2_data["authenticated"] is True
        assert s2_data["must_change_password"] is True
        assert s2_data["permissions"] == []
        assert s2_data["redirect"] == "/change-password"


# =============================================================================
# 3. CHANGE PASSWORD ENDPOINT (POST /api/auth/change-password)
# =============================================================================

def test_change_password_endpoint_unauthenticated(test_app):
    _, app = test_app
    with app.test_client() as client:
        res = client.post("/api/auth/change-password", json={
            "current_password": "any",
            "new_password": "NewValidPassword123!"
        })
        assert res.status_code == 401


def test_change_password_endpoint_validation_and_success(test_app):
    runtime, app = test_app
    op_user = runtime.store.get_admin_user("operator")
    runtime.store.update_admin_user_password(op_user["user_id"], op_user["password_hash"], must_change_password=True)

    with app.test_client() as client:
        _login(client, "operator", "Operator@AICG2026!")

        # 1. Missing fields
        missing_res = client.post("/api/auth/change-password", json={
            "current_password": "Operator@AICG2026!"
        })
        assert missing_res.status_code == 400
        assert missing_res.get_json()["code"] == "MISSING_FIELDS"

        # 2. Incorrect current password
        wrong_curr_res = client.post("/api/auth/change-password", json={
            "current_password": "WrongCurrentPassword123!",
            "new_password": "BrandNewPassword2026!"
        })
        assert wrong_curr_res.status_code == 400
        assert wrong_curr_res.get_json()["code"] == "INVALID_CURRENT_PASSWORD"

        # Verify audit of failed password change
        audits = runtime.store.list_audit_logs(limit=5)
        fail_events = [a for a in audits if a["action"] == "PASSWORD_CHANGE_FAILURE"]
        assert len(fail_events) == 1

        # 3. Policy violation (new password too short)
        short_res = client.post("/api/auth/change-password", json={
            "current_password": "Operator@AICG2026!",
            "new_password": "short"
        })
        assert short_res.status_code == 400
        assert short_res.get_json()["code"] == "PASSWORD_POLICY_VIOLATION"

        # 4. Same password reused
        reuse_res = client.post("/api/auth/change-password", json={
            "current_password": "Operator@AICG2026!",
            "new_password": "Operator@AICG2026!"
        })
        assert reuse_res.status_code == 400
        assert reuse_res.get_json()["code"] == "PASSWORD_REUSED"

        # 5. Successful change
        success_res = client.post("/api/auth/change-password", json={
            "current_password": "Operator@AICG2026!",
            "new_password": "BrandNewPassword2026!"
        })
        assert success_res.status_code == 200
        data = success_res.get_json()
        assert data["ok"] is True
        assert data["must_change_password"] is False
        assert len(data["permissions"]) > 0
        assert data["redirect"] == "/"

        # DB must reflect must_change_password = 0 and new hash
        updated_op = runtime.store.get_admin_user("operator")
        assert updated_op["must_change_password"] == 0 or updated_op["must_change_password"] is False
        assert verify_password("BrandNewPassword2026!", updated_op["password_hash"]) is True

        # Session should now allow normal access
        overview_res = client.get("/api/admin/overview")
        assert overview_res.status_code == 200

        # Audit log has USER_PASSWORD_CHANGED
        audits = runtime.store.list_audit_logs(limit=10)
        changed_events = [a for a in audits if a["action"] == "USER_PASSWORD_CHANGED"]
        assert len(changed_events) == 1
        assert "BrandNewPassword2026!" not in changed_events[0]["details"]


# =============================================================================
# 4. USERNAME MODIFICATION & CONFLICT HANDLING
# =============================================================================

def test_username_modification_and_conflict(test_app):
    runtime, app = test_app
    with app.test_client() as client:
        _login(client, "admin", "Admin@AICG2026!")

        op_user = runtime.store.get_admin_user("operator")
        op_id = op_user["user_id"]

        # Rename to valid new username
        rename_res = client.patch(f"/api/admin/users/{op_id}", json={
            "username": "operator_renamed"
        })
        assert rename_res.status_code == 200
        assert rename_res.get_json()["username"] == "operator_renamed"

        # Verify DB updated
        assert runtime.store.get_admin_user("operator_renamed") is not None
        assert runtime.store.get_admin_user("operator") is None

        # Conflict: try to rename to 'admin'
        conflict_res = client.patch(f"/api/admin/users/{op_id}", json={
            "username": "admin"
        })
        assert conflict_res.status_code == 409
        assert conflict_res.get_json()["code"] == "USERNAME_CONFLICT"

        # Verify USER_USERNAME_CHANGED audit log
        audits = runtime.store.list_audit_logs(limit=10)
        rename_logs = [a for a in audits if a["action"] == "USER_USERNAME_CHANGED"]
        assert len(rename_logs) == 1


# =============================================================================
# 5. ROLE & STATUS MODIFICATION & LAST-ADMIN PROTECTION
# =============================================================================

def test_role_and_status_modification(test_app):
    runtime, app = test_app
    with app.test_client() as client:
        _login(client, "admin", "Admin@AICG2026!")

        op_user = runtime.store.get_admin_user("operator")
        op_id = op_user["user_id"]

        # Promote operator to ADMIN
        prom_res = client.patch(f"/api/admin/users/{op_id}", json={"role": ROLE_ADMIN})
        assert prom_res.status_code == 200
        assert prom_res.get_json()["role"] == ROLE_ADMIN

        # Disable user
        dis_res = client.patch(f"/api/admin/users/{op_id}", json={"status": "DISABLED"})
        assert dis_res.status_code == 200
        assert dis_res.get_json()["status"] == "DISABLED"

        # Demote back to OPERATOR
        dem_res = client.patch(f"/api/admin/users/{op_id}", json={"role": ROLE_OPERATOR, "status": "ACTIVE"})
        assert dem_res.status_code == 200

        # Now only 'admin' is the sole active ADMIN. Attempting to demote 'admin' -> 400
        admin_user = runtime.store.get_admin_user("admin")
        adm_id = admin_user["user_id"]
        dem_admin_res = client.patch(f"/api/admin/users/{adm_id}", json={"role": ROLE_OPERATOR})
        assert dem_admin_res.status_code == 400
        assert dem_admin_res.get_json()["code"] == "LAST_ADMIN_PROTECTED"

        # Attempting to disable 'admin' -> 400
        dis_admin_res = client.patch(f"/api/admin/users/{adm_id}", json={"status": "DISABLED"})
        assert dis_admin_res.status_code == 400
        assert dis_admin_res.get_json()["code"] == "LAST_ADMIN_PROTECTED"


# =============================================================================
# 6. USER DELETION & SAFETY PROTECTIONS (DELETE /api/admin/users/<id>)
# =============================================================================

def test_user_deletion_and_protections(test_app):
    runtime, app = test_app
    with app.test_client() as client:
        _login(client, "admin", "Admin@AICG2026!")
        admin_user = runtime.store.get_admin_user("admin")
        admin_id = admin_user["user_id"]

        # Create a disposable test user
        create_res = client.post("/api/admin/users", json={
            "username": "temp_user",
            "password": "TempUser123!",
            "role": ROLE_OPERATOR,
            "status": "ACTIVE"
        })
        assert create_res.status_code == 201
        temp_id = create_res.get_json()["user_id"]

        # Self-deletion prevention
        self_del_res = client.delete(f"/api/admin/users/{admin_id}")
        assert self_del_res.status_code == 400
        assert self_del_res.get_json()["code"] == "SELF_DELETION_DENIED"

        # Nonexistent user -> 404
        nonexist_res = client.delete("/api/admin/users/USR-NONEXISTENT")
        assert nonexist_res.status_code == 404
        assert nonexist_res.get_json()["code"] == "USER_NOT_FOUND"

        # Successful deletion of temp user
        del_res = client.delete(f"/api/admin/users/{temp_id}")
        assert del_res.status_code == 200
        del_data = del_res.get_json()
        assert del_data["ok"] is True
        assert del_data["deleted_user_id"] == temp_id
        assert all(u["user_id"] != temp_id for u in del_data["users"])

        # Verify DB deletion
        assert runtime.store.get_admin_user_by_id(temp_id) is None

        # Verify USER_DELETED audit log
        audits = runtime.store.list_audit_logs(limit=10)
        del_events = [a for a in audits if a["action"] == "USER_DELETED"]
        assert len(del_events) == 1
        assert del_events[0]["resource_id"] == temp_id


def test_last_active_admin_deletion_protection(test_app):
    runtime, app = test_app
    with app.test_client() as client1:
        _login(client1, "admin", "Admin@AICG2026!")

        # Create a second admin: admin2
        res2 = client1.post("/api/admin/users", json={
            "username": "admin2",
            "password": "Admin2Password123!",
            "role": ROLE_ADMIN,
            "status": "ACTIVE"
        })
        assert res2.status_code == 201
        admin2_id = res2.get_json()["user_id"]

    # Admin 2 logs in with their own session
    with app.test_client() as client2:
        _login(client2, "admin2", "Admin2Password123!")

        # In client 1, admin deletes admin2
        with app.test_client() as client1_again:
            _login(client1_again, "admin", "Admin@AICG2026!")
            del_admin2 = client1_again.delete(f"/api/admin/users/{admin2_id}")
            assert del_admin2.status_code == 200

        # Now only 'admin' is the sole active administrator remaining in the gateway.
        # If client2 (whose admin2 was deleted) tries to delete 'admin':
        # Self-deletion won't trigger because client2 user_id is admin2 != admin.
        # But 'admin' is the last active admin, so LAST_ADMIN_PROTECTED must reject it!
        admin_id = runtime.store.get_admin_user("admin")["user_id"]
        res_del_last = client2.delete(f"/api/admin/users/{admin_id}")
        assert res_del_last.status_code == 400
        assert res_del_last.get_json()["code"] == "LAST_ADMIN_PROTECTED"


# =============================================================================
# 7. OPERATOR RBAC REJECTION
# =============================================================================

def test_operator_rbac_rejection(test_app):
    runtime, app = test_app
    with app.test_client() as op_client:
        _login(op_client, "operator", "Operator@AICG2026!")

        admin_id = runtime.store.get_admin_user("admin")["user_id"]

        # Operator attempts PATCH /api/admin/users/<id> -> 403 FORBIDDEN_ROLE
        patch_res = op_client.patch(f"/api/admin/users/{admin_id}", json={"role": ROLE_OPERATOR})
        assert patch_res.status_code == 403
        assert patch_res.get_json()["code"] == "FORBIDDEN_ROLE"

        # Operator attempts DELETE /api/admin/users/<id> -> 403 FORBIDDEN_ROLE
        del_res = op_client.delete(f"/api/admin/users/{admin_id}")
        assert del_res.status_code == 403
        assert del_res.get_json()["code"] == "FORBIDDEN_ROLE"

        # Operator attempts POST /api/admin/users -> 403 FORBIDDEN_ROLE
        post_res = op_client.post("/api/admin/users", json={
            "username": "rogue_user",
            "password": "RoguePassword123!",
            "role": ROLE_ADMIN,
        })
        assert post_res.status_code == 403
        assert post_res.get_json()["code"] == "FORBIDDEN_ROLE"


# =============================================================================
# 8. AUDIT HASH-CHAIN INTEGRITY & CREDENTIAL PRIVACY
# =============================================================================

def test_audit_log_cryptographic_integrity(test_app):
    runtime, app = test_app
    with app.test_client() as client:
        _login(client, "admin", "Admin@AICG2026!")

        # Create user
        c_res = client.post("/api/admin/users", json={
            "username": "audit_test_user",
            "password": "SecretPass12345!",
            "role": ROLE_OPERATOR,
        })
        assert c_res.status_code == 201
        uid = c_res.get_json()["user_id"]

        # Reset password
        client.patch(f"/api/admin/users/{uid}", json={"password": "NewSecretPass6789!"})

        # Rename user
        client.patch(f"/api/admin/users/{uid}", json={"username": "audit_renamed_user"})

        # Delete user
        client.delete(f"/api/admin/users/{uid}")

    # Verify cryptographic audit hash chain
    chain_status = runtime.store.verify_audit_log_integrity()
    assert chain_status["valid"] is True, f"Audit chain corrupted: {chain_status}"
    assert chain_status["count"] > 0

    # Verify no plaintext passwords or hashes in audit log
    all_logs = runtime.store.list_audit_logs(limit=100)
    for entry in all_logs:
        details_lower = str(entry.get("details", "")).lower()
        assert "secretpass12345!" not in details_lower
        assert "newsecretpass6789!" not in details_lower
        assert "admin@aicg2026!" not in details_lower
        assert "password_hash" not in details_lower

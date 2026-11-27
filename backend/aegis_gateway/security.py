"""AICG Administrative Security Layer: RBAC, password security, session handling, and simulated MFA."""

from __future__ import annotations

from collections import defaultdict
from functools import wraps
import hmac
import time
from typing import Any, Callable
from flask import jsonify, redirect, request, session
from werkzeug.security import check_password_hash, generate_password_hash

# =====================================================================
# ROLES AND PERMISSIONS (RBAC)
# =====================================================================

ROLE_ADMIN = "ADMIN"
ROLE_OPERATOR = "OPERATOR"

ALL_ROLES = (ROLE_ADMIN, ROLE_OPERATOR)

# Granular permissions defined in AICG Master Prompt
PERM_VIEW_DASHBOARD = "VIEW_DASHBOARD"
PERM_VIEW_INCIDENTS = "VIEW_INCIDENTS"
PERM_ACK_ALERT = "ACK_ALERT"
PERM_MANAGE_INCIDENT = "MANAGE_INCIDENT"
PERM_CLOSE_INCIDENT = "CLOSE_INCIDENT"
PERM_VIEW_AUDIT = "VIEW_AUDIT"
PERM_MANAGE_USERS = "MANAGE_USERS"
PERM_VIEW_SECURITY_POSTURE = "VIEW_SECURITY_POSTURE"
PERM_VIEW_SYSTEM_STATUS = "VIEW_SYSTEM_STATUS"
PERM_ADMIN_CONTROLS = "ADMIN_CONTROLS"

ROLE_PERMISSIONS: dict[str, set[str]] = {
    ROLE_ADMIN: {
        PERM_VIEW_DASHBOARD,
        PERM_VIEW_INCIDENTS,
        PERM_ACK_ALERT,
        PERM_MANAGE_INCIDENT,
        PERM_CLOSE_INCIDENT,
        PERM_VIEW_AUDIT,
        PERM_MANAGE_USERS,
        PERM_VIEW_SECURITY_POSTURE,
        PERM_VIEW_SYSTEM_STATUS,
        PERM_ADMIN_CONTROLS,
    },
    ROLE_OPERATOR: {
        PERM_VIEW_DASHBOARD,
        PERM_VIEW_INCIDENTS,
        PERM_ACK_ALERT,
        PERM_MANAGE_INCIDENT,
        PERM_VIEW_SECURITY_POSTURE,
        PERM_VIEW_SYSTEM_STATUS,
    },
}

# Explicitly forbidden for OPERATOR per specifications
OPERATOR_DENIED_PERMISSIONS = {
    PERM_MANAGE_USERS,
    PERM_ADMIN_CONTROLS,
    PERM_CLOSE_INCIDENT,
    PERM_VIEW_AUDIT,
}

# Standard Demonstration Lab Token
DEFAULT_SIMULATED_MFA_TOKEN = "123456"


def has_permission(role: str | None, permission: str) -> bool:
    """Check if the specified role possesses the permission."""
    if not role:
        return False
    perms = ROLE_PERMISSIONS.get(role.upper(), set())
    return permission in perms


def hash_password(plaintext: str) -> str:
    """Hash password using Werkzeug's secure PBKDF2/scrypt algorithm."""
    return generate_password_hash(plaintext)


def verify_password(plaintext: str, password_hash: str) -> bool:
    """Constant-time verification of plaintext against password hash."""
    if not plaintext or not password_hash:
        return False
    return check_password_hash(password_hash, plaintext)


def validate_password_policy(plaintext: str) -> tuple[bool, str | None]:
    """Validate password complexity against administrative security baseline."""
    if not plaintext or not isinstance(plaintext, str):
        return False, "Password is required"
    if len(plaintext) < 8:
        return False, "Password must be at least 8 characters long"
    return True, None


def verify_simulated_mfa(token: str) -> bool:
    """Constant-time validation of simulated MFA token."""
    if not token:
        return False
    clean = token.strip()
    return hmac.compare_digest(clean, DEFAULT_SIMULATED_MFA_TOKEN)


# =====================================================================
# SESSION HARDENING & PRE-MFA STATE MANAGEMENT
# =====================================================================

class AuthRateLimiter:
    """In-memory rate limiter tracking failed authentication attempts per (ip, identifier)."""

    def __init__(self, max_attempts: int = 10, window_seconds: int = 60):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._failures: dict[str, list[float]] = defaultdict(list)

    def _key(self, ip: str | None, username: str | None) -> str:
        return f"{ip or 'unknown'}:{username or 'unknown'}"

    def is_rate_limited(self, ip: str | None, username: str | None) -> bool:
        key = self._key(ip, username)
        now = time.time()
        self._failures[key] = [t for t in self._failures[key] if now - t < self.window_seconds]
        return len(self._failures[key]) >= self.max_attempts

    def record_failure(self, ip: str | None, username: str | None) -> None:
        key = self._key(ip, username)
        self._failures[key].append(time.time())

    def reset(self, ip: str | None, username: str | None) -> None:
        key = self._key(ip, username)
        self._failures.pop(key, None)


auth_limiter = AuthRateLimiter(max_attempts=10, window_seconds=60)


def rotate_session() -> None:
    """Rotate session data to prevent session fixation attacks."""
    session.clear()


def set_pre_mfa_user(user: dict[str, Any] | str, role: str = ROLE_OPERATOR) -> None:
    """Store pre-MFA state in session after successful password verification."""
    session.clear()
    if isinstance(user, str):
        session["pre_mfa"] = {
            "user_id": f"USR-{user.upper()}",
            "username": user,
            "role": role,
            "must_change_password": False,
            "timestamp": time.time(),
        }
    else:
        session["pre_mfa"] = {
            "user_id": user.get("user_id", f"USR-{user.get('username', 'UNKNOWN').upper()}"),
            "username": user["username"],
            "role": user.get("role", role),
            "must_change_password": bool(user.get("must_change_password", False)),
            "timestamp": time.time(),
        }


def get_pre_mfa_user() -> dict[str, Any] | None:
    """Retrieve pre-MFA candidate from session. Valid for 10 minutes."""
    pre = session.get("pre_mfa")
    if not pre or not isinstance(pre, dict):
        return None
    if time.time() - float(pre.get("timestamp", 0)) > 600:
        session.pop("pre_mfa", None)
        return None
    return pre


def clear_pre_mfa() -> None:
    """Clear pre-MFA session state."""
    session.pop("pre_mfa", None)


def get_current_user() -> dict[str, Any] | None:
    """Retrieve authenticated user context from Flask session."""
    user = session.get("user")
    if not user or not isinstance(user, dict):
        return None
    if not user.get("authenticated"):
        return None
    return user


RESTRICTED_SESSION_ALLOWED_PATHS = {
    "/api/auth/change-password",
    "/api/auth/status",
    "/logout",
    "/api/auth/logout",
    "/login",
}


def is_restricted_session_blocked(user: dict[str, Any]) -> bool:
    """Check if the session is restricted due to mandatory password change requirement."""
    if not user.get("must_change_password"):
        return False
    return request.path not in RESTRICTED_SESSION_ALLOWED_PATHS


def _log_security_audit(username: str, role: str, action: str, details: str) -> None:
    """Helper to record security audit logs during access control enforcement."""
    try:
        from flask import current_app
        rt = current_app.config.get("runtime")
        if rt and hasattr(rt, "store"):
            rt.store.record_audit(
                username=username,
                role=role,
                action=action,
                resource=request.path,
                resource_id=None,
                result="DENIED",
                details=details,
                source_ip=request.remote_addr,
            )
    except Exception:
        pass


def login_required(f: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator requiring an authenticated session."""
    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:
        user = get_current_user()
        if not user:
            if request.method in ("POST", "PUT", "PATCH", "DELETE") or request.path.startswith("/api/") or request.path == "/events":
                _log_security_audit(
                    "anonymous",
                    "ANONYMOUS",
                    "ACCESS_DENIED",
                    f"Unauthenticated attempt to access {request.method} {request.path}",
                )
            if request.path.startswith("/api/") or request.path == "/events":
                return jsonify({
                    "error": "Unauthorized: Authentication required",
                    "code": "AUTH_REQUIRED",
                    "authenticated": False,
                }), 401
            return redirect(f"/login?next={request.path}")
        if is_restricted_session_blocked(user):
            _log_security_audit(
                user.get("username", "unknown"),
                user.get("role", "UNKNOWN"),
                "ACCESS_DENIED",
                f"Access blocked for {request.method} {request.path}: mandatory password change required",
            )
            if request.path.startswith("/api/") or request.path == "/events":
                return jsonify({
                    "error": "Password change required before accessing gateway services",
                    "code": "PASSWORD_CHANGE_REQUIRED",
                    "must_change_password": True,
                }), 403
            return redirect("/login?password_change_required=1")
        return f(*args, **kwargs)
    return decorated


def roles_required(*roles: str) -> Callable[..., Any]:
    """Decorator requiring the authenticated user to hold one of the given roles."""
    def decorator(f: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(f)
        def decorated(*args: Any, **kwargs: Any) -> Any:
            user = get_current_user()
            if not user:
                _log_security_audit(
                    "anonymous",
                    "ANONYMOUS",
                    "ACCESS_DENIED",
                    f"Unauthenticated attempt to access {request.method} {request.path}",
                )
                if request.path.startswith("/api/") or request.path == "/events":
                    return jsonify({
                        "error": "Unauthorized: Authentication required",
                        "code": "AUTH_REQUIRED",
                        "authenticated": False,
                    }), 401
                return redirect(f"/login?next={request.path}")
            if is_restricted_session_blocked(user):
                _log_security_audit(
                    user.get("username", "unknown"),
                    user.get("role", "UNKNOWN"),
                    "ACCESS_DENIED",
                    f"Access blocked for {request.method} {request.path}: mandatory password change required",
                )
                if request.path.startswith("/api/") or request.path == "/events":
                    return jsonify({
                        "error": "Password change required before accessing gateway services",
                        "code": "PASSWORD_CHANGE_REQUIRED",
                        "must_change_password": True,
                    }), 403
                return redirect("/login?password_change_required=1")
            user_role = str(user.get("role", "")).upper()
            allowed = [r.upper() for r in roles]
            if user_role not in allowed:
                _log_security_audit(
                    user.get("username", "unknown"),
                    user_role,
                    "ACCESS_DENIED",
                    f"Denied role '{user_role}' for endpoint {request.method} {request.path}. Allowed: {allowed}",
                )
                return jsonify({
                    "error": f"Forbidden: Role '{user_role}' lacks authorization. Required: {allowed}",
                    "code": "FORBIDDEN_ROLE",
                    "role": user_role,
                }), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


def permission_required(permission: str) -> Callable[..., Any]:
    """Decorator requiring a specific RBAC permission."""
    def decorator(f: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(f)
        def decorated(*args: Any, **kwargs: Any) -> Any:
            user = get_current_user()
            if not user:
                _log_security_audit(
                    "anonymous",
                    "ANONYMOUS",
                    "ACCESS_DENIED",
                    f"Unauthenticated attempt to access {request.method} {request.path}",
                )
                if request.path.startswith("/api/") or request.path == "/events":
                    return jsonify({
                        "error": "Unauthorized: Authentication required",
                        "code": "AUTH_REQUIRED",
                        "authenticated": False,
                    }), 401
                return redirect(f"/login?next={request.path}")
            if is_restricted_session_blocked(user):
                _log_security_audit(
                    user.get("username", "unknown"),
                    user.get("role", "UNKNOWN"),
                    "ACCESS_DENIED",
                    f"Access blocked for {request.method} {request.path}: mandatory password change required",
                )
                if request.path.startswith("/api/") or request.path == "/events":
                    return jsonify({
                        "error": "Password change required before accessing gateway services",
                        "code": "PASSWORD_CHANGE_REQUIRED",
                        "must_change_password": True,
                    }), 403
                return redirect("/login?password_change_required=1")
            user_role = str(user.get("role", "")).upper()
            if not has_permission(user_role, permission):
                _log_security_audit(
                    user.get("username", "unknown"),
                    user_role,
                    "ACCESS_DENIED",
                    f"Denied role '{user_role}' for endpoint {request.method} {request.path}. Required permission: {permission}",
                )
                return jsonify({
                    "error": f"Forbidden: Role '{user_role}' lacks required permission '{permission}'",
                    "code": "FORBIDDEN_PERMISSION",
                    "role": user_role,
                    "required_permission": permission,
                }), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

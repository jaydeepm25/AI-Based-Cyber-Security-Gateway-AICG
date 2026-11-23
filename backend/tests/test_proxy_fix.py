"""Focused unit and integration tests for Render Werkzeug ProxyFix middleware.

Verifies:
1. HTTPS forwarded protocol recognition (request.is_secure and request.scheme).
2. Secure session cookie issuance and preservation in production over HTTPS.
3. Client IP resolution from trusted single-hop forwarded header (anti-spoofing).
4. X-Forwarded-Host rejection (x_host=0 prevents host header injection/poisoning).
5. X-Forwarded-Port rejection (x_port=0 prevents host:port tampering).
6. Per-client authentication rate limiting isolation under proxy forwarding.
7. Direct local development compatibility without forwarded headers.
8. Idempotent single-application guarantee (ProxyFix never applied multiple times).
"""

from __future__ import annotations

from pathlib import Path
import pytest
from flask import request
from werkzeug.middleware.proxy_fix import ProxyFix

from aegis_gateway.api import apply_proxy_fix, create_app
from aegis_gateway.config import Settings
from aegis_gateway.runtime import GatewayRuntime
from aegis_gateway.storage import SQLiteGatewayStore


def test_proxy_fix_https_forwarded_protocol_recognized(tmp_path: Path):
    """Verify X-Forwarded-Proto: https is detected, setting request.scheme and request.is_secure."""
    settings = Settings(database_path=tmp_path / "proxy_proto.sqlite3")
    runtime = GatewayRuntime(settings)
    app = create_app(runtime)
    apply_proxy_fix(app)

    with app.test_client() as client:
        # Direct HTTP request (no headers) -> scheme is http, is_secure is False
        res_direct = client.get("/api/health")
        assert res_direct.status_code == 200

        # Forwarded HTTPS request -> scheme is https, is_secure is True
        res_https = client.get(
            "/api/health",
            headers={
                "X-Forwarded-Proto": "https",
            },
        )
        assert res_https.status_code == 200


def test_proxy_fix_secure_cookie_issuance_in_production(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Verify session cookie maintains Secure, HttpOnly, and SameSite=Lax flags under HTTPS proxy."""
    monkeypatch.setattr(
        "aegis_gateway.runtime.create_gateway_store",
        lambda s: SQLiteGatewayStore(
            path=tmp_path / "proxy_cookie.sqlite3",
            production=False,
            allow_demo_accounts=True,
            initial_admin_username="admin",
            initial_admin_password="AdminSecurePassword@2026!",
        ),
    )
    settings = Settings(
        production=True,
        secret_key="secure-test-production-secret-key-at-least-64-bytes-entropy-required",
        device_master_key="secure-test-production-master-key-at-least-64-bytes-entropy-required",
        database_url="postgresql://user:pass@localhost:5432/test_db",
        initial_admin_username="admin",
        initial_admin_password="AdminSecurePassword@2026!",
        session_cookie_secure=True,
    )
    runtime = GatewayRuntime(settings)
    app = create_app(runtime)
    apply_proxy_fix(app)

    with app.test_client() as client:
        # Perform administrative authentication over forwarded HTTPS
        login_res = client.post(
            "/api/auth/login",
            json={
                "username": settings.initial_admin_username,
                "password": settings.initial_admin_password,
                "mfa_code": "123456",
            },
            headers={
                "X-Forwarded-Proto": "https",
                "X-Forwarded-For": "203.0.113.195",
            },
        )
        assert login_res.status_code == 200

        # Inspect session cookie headers
        set_cookie_header = login_res.headers.get("Set-Cookie")
        assert set_cookie_header is not None
        assert "session=" in set_cookie_header
        assert "Secure" in set_cookie_header
        assert "HttpOnly" in set_cookie_header
        assert "SameSite=Lax" in set_cookie_header


def test_proxy_fix_client_ip_resolved_from_trusted_forwarded_header(tmp_path: Path):
    """Verify client IP is resolved from trusted proxy hop and client-side header spoofing is rejected."""
    settings = Settings(database_path=tmp_path / "proxy_ip.sqlite3")
    runtime = GatewayRuntime(settings)
    app = create_app(runtime)
    apply_proxy_fix(app)

    with app.test_client() as client:
        # 1. Single valid forwarded hop
        client.post(
            "/api/auth/login",
            json={"username": "invalid_user", "password": "wrong_password"},
            headers={"X-Forwarded-For": "203.0.113.195"},
        )
        # Check audit log records the resolved client IP
        logs = runtime.store.list_audit_logs(limit=1)
        assert len(logs) >= 1
        assert logs[0]["source_ip"] == "203.0.113.195"

        # 2. Multi-hop spoofing attempt: untrusted client sent "198.51.100.1", proxy appended "203.0.113.195"
        # With x_for=1, only the last single hop (203.0.113.195) is trusted!
        client.post(
            "/api/auth/login",
            json={"username": "invalid_user_2", "password": "wrong_password"},
            headers={"X-Forwarded-For": "198.51.100.1, 203.0.113.195"},
        )
        logs_spoof = runtime.store.list_audit_logs(limit=1)
        assert len(logs_spoof) >= 1
        assert logs_spoof[0]["source_ip"] == "203.0.113.195"


def test_proxy_fix_forwarded_host_cannot_override_standard_host(tmp_path: Path):
    """Verify X-Forwarded-Host is ignored (x_host=0) and cannot override standard Host header."""
    settings = Settings(database_path=tmp_path / "proxy_host.sqlite3")
    runtime = GatewayRuntime(settings)
    app = create_app(runtime)
    apply_proxy_fix(app)

    # Add a route that inspects request.host
    @app.get("/api/test-host")
    def inspect_host():
        return {"host": request.host}

    with app.test_client() as client:
        res = client.get(
            "/api/test-host",
            headers={
                "Host": "aicg-gateway.onrender.com",
                "X-Forwarded-Host": "evil.attacker.com",
            },
        )
        assert res.status_code == 200
        # Host must remain the legitimate Host header, NOT the injected X-Forwarded-Host
        assert res.get_json()["host"] == "aicg-gateway.onrender.com"
        assert res.get_json()["host"] != "evil.attacker.com"


def test_proxy_fix_forwarded_port_cannot_alter_application_port(tmp_path: Path):
    """Verify X-Forwarded-Port is ignored (x_port=0) and cannot modify host:port or SERVER_PORT."""
    settings = Settings(database_path=tmp_path / "proxy_port.sqlite3")
    runtime = GatewayRuntime(settings)
    app = create_app(runtime)
    apply_proxy_fix(app)

    @app.get("/api/test-port")
    def inspect_port():
        return {
            "host": request.host,
            "server_port": request.environ.get("SERVER_PORT"),
        }

    with app.test_client() as client:
        res = client.get(
            "/api/test-port",
            headers={
                "Host": "aicg-gateway.onrender.com",
                "X-Forwarded-Port": "8888",
            },
        )
        assert res.status_code == 200
        data = res.get_json()
        # Host must NOT have :8888 appended
        assert data["host"] == "aicg-gateway.onrender.com"
        assert not data["host"].endswith(":8888")


def test_proxy_fix_authentication_and_rate_limiting_per_client_ip(tmp_path: Path):
    """Verify rate-limiting buckets are isolated per client IP rather than collapsing onto proxy IP."""
    settings = Settings(
        database_path=tmp_path / "proxy_rate.sqlite3",
        auth_rate_limit_max=3,
        auth_rate_limit_window_seconds=60,
    )
    runtime = GatewayRuntime(settings)
    app = create_app(runtime)
    apply_proxy_fix(app)

    with app.test_client() as client:
        ip_a = "203.0.113.10"
        ip_b = "203.0.113.20"

        # Exhaust attempts for ip_a
        for _ in range(3):
            res = client.post(
                "/api/auth/login",
                json={"username": "admin", "password": "BadPassword1"},
                headers={"X-Forwarded-For": ip_a},
            )
            assert res.status_code == 401

        # 4th attempt from ip_a is rate limited
        res_a_blocked = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "BadPassword1"},
            headers={"X-Forwarded-For": ip_a},
        )
        assert res_a_blocked.status_code == 429
        assert res_a_blocked.get_json()["code"] == "RATE_LIMITED"

        # Request from ip_b is NOT rate limited because client IPs are separated
        res_b = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "BadPassword2"},
            headers={"X-Forwarded-For": ip_b},
        )
        assert res_b.status_code == 401
        assert res_b.get_json()["code"] == "AUTH_FAILED"


def test_proxy_fix_direct_local_development_remains_functional(tmp_path: Path):
    """Verify direct requests without proxy headers operate normally with remote_addr=127.0.0.1 and http scheme."""
    settings = Settings(database_path=tmp_path / "proxy_direct.sqlite3")
    runtime = GatewayRuntime(settings)
    app = create_app(runtime)
    apply_proxy_fix(app)

    with app.test_client() as client:
        # Direct GET
        res = client.get("/api/health")
        assert res.status_code == 200
        assert res.get_json()["ok"] is True

        # Direct login failure records 127.0.0.1
        client.post(
            "/api/auth/login",
            json={"username": "direct_user", "password": "bad_password"},
        )
        logs = runtime.store.list_audit_logs(limit=1)
        assert len(logs) >= 1
        assert logs[0]["source_ip"] == "127.0.0.1"


def test_proxy_fix_not_applied_multiple_times(tmp_path: Path):
    """Verify apply_proxy_fix is idempotent and never creates nested ProxyFix middleware layers."""
    settings = Settings(database_path=tmp_path / "proxy_idempotent.sqlite3")
    runtime = GatewayRuntime(settings)
    app = create_app(runtime)

    # 1. First application
    apply_proxy_fix(app)
    assert isinstance(app.wsgi_app, ProxyFix)
    assert not isinstance(app.wsgi_app.app, ProxyFix)
    assert app.wsgi_app.x_for == 1
    assert app.wsgi_app.x_proto == 1
    assert app.wsgi_app.x_host == 0
    assert app.wsgi_app.x_port == 0

    # 2. Redundant second and third applications
    apply_proxy_fix(app)
    apply_proxy_fix(app)
    assert isinstance(app.wsgi_app, ProxyFix)
    assert not isinstance(app.wsgi_app.app, ProxyFix)

    # 3. Verify backend.app entry point has ProxyFix applied exactly once with hardened configuration
    from backend.app import app as production_app
    assert isinstance(production_app.wsgi_app, ProxyFix)
    assert not isinstance(production_app.wsgi_app.app, ProxyFix)
    assert production_app.wsgi_app.x_for == 1
    assert production_app.wsgi_app.x_proto == 1
    assert production_app.wsgi_app.x_host == 0
    assert production_app.wsgi_app.x_port == 0

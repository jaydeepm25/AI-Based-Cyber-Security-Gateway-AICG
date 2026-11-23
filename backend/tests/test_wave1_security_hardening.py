"""Tests for Phase 23 Wave 1 Security Hardening:
- SEC-01: HMAC token replay protection & bounded thread-safe replay cache
- SEC-02: Configurable externalized master key & leakage prevention
- SEC-03: Session cookie security configuration & production safety
- SEC-04: Login open redirect prevention & URL sanitization
- SEC-05: Cooja trace import path containment & safe path resolution
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import pytest
import time

from aegis_gateway.api import create_app, sanitize_redirect_url, resolve_contained_path
from aegis_gateway.config import Settings, LAB_MASTER_KEY_FALLBACK, LAB_SECRET_KEY_FALLBACK
from aegis_gateway.iam import (
    DEFAULT_MASTER_KEY,
    TokenReplayCache,
    compute_device_token,
    derive_device_key,
    verify_device_token,
    IAMService,
)
from aegis_gateway.runtime import GatewayRuntime
from aegis_gateway.scenarios import generate_window
from aegis_gateway.schema import TelemetryEvent, utc_now
from aegis_gateway.security import ROLE_ADMIN, ROLE_OPERATOR


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def clean_replay_cache():
    """Isolated replay cache for deterministic unit testing."""
    return TokenReplayCache(max_size=100, default_retention_seconds=300.0)


@pytest.fixture
def wave1_app(tmp_path: Path):
    """Runtime and Flask test client initialized on a temporary database."""
    settings = Settings(
        database_path=tmp_path / "wave1_test.sqlite3",
        cooja_dir=tmp_path / "cooja_dir",
    )
    settings.cooja_dir.mkdir(parents=True, exist_ok=True)
    runtime = GatewayRuntime(settings=settings)
    app = create_app(runtime)
    app.config["TESTING"] = True
    return runtime, app


def _login_as(client, username: str = "admin", role: str = ROLE_ADMIN):
    """Helper to simulate an authenticated admin or operator session."""
    with client.session_transaction() as sess:
        sess["user"] = {
            "user_id": f"USR-{username.upper()}",
            "username": username,
            "role": role,
            "authenticated": True,
            "mfa_verified": True,
            "login_time": utc_now(),
        }


# =============================================================================
# SEC-01: REPLAY PROTECTION TESTS
# =============================================================================

def test_sec01_first_valid_token_accepted(clean_replay_cache):
    """A fresh valid HMAC token within drift window is successfully verified."""
    now_ts = datetime.now(timezone.utc).isoformat()
    dev_id = "SENSOR-01"
    token = compute_device_token(dev_id, now_ts, flow_id="flow-001")

    valid, reason = verify_device_token(
        device_id=dev_id,
        token=token,
        timestamp=now_ts,
        flow_id="flow-001",
        replay_cache=clean_replay_cache,
    )
    assert valid is True
    assert "verified" in reason.lower()
    assert len(clean_replay_cache) == 1


def test_sec01_exact_replay_rejected(clean_replay_cache):
    """Replaying the exact same valid token within freshness window must be rejected."""
    now_ts = datetime.now(timezone.utc).isoformat()
    dev_id = "SENSOR-01"
    token = compute_device_token(dev_id, now_ts, flow_id="flow-002")

    # First attempt: accepted
    valid1, _ = verify_device_token(
        device_id=dev_id,
        token=token,
        timestamp=now_ts,
        flow_id="flow-002",
        replay_cache=clean_replay_cache,
    )
    assert valid1 is True

    # Immediate replay attempt: rejected
    valid2, reason2 = verify_device_token(
        device_id=dev_id,
        token=token,
        timestamp=now_ts,
        flow_id="flow-002",
        replay_cache=clean_replay_cache,
    )
    assert valid2 is False
    assert "replayed" in reason2.lower() or "duplicate" in reason2.lower()


def test_sec01_different_valid_tokens_accepted(clean_replay_cache):
    """Different tokens (with unique timestamps or flow_ids) must both be accepted."""
    dev_id = "SENSOR-01"
    ts1 = datetime.now(timezone.utc).isoformat()
    token1 = compute_device_token(dev_id, ts1, flow_id="flow-101")

    time.sleep(0.01)
    ts2 = datetime.now(timezone.utc).isoformat()
    token2 = compute_device_token(dev_id, ts2, flow_id="flow-102")

    valid1, _ = verify_device_token(dev_id, token1, ts1, "flow-101", replay_cache=clean_replay_cache)
    valid2, _ = verify_device_token(dev_id, token2, ts2, "flow-102", replay_cache=clean_replay_cache)

    assert valid1 is True
    assert valid2 is True
    assert len(clean_replay_cache) == 2


def test_sec01_tampered_token_rejected_and_not_cached(clean_replay_cache):
    """Tampered tokens fail cryptographic verification and are never recorded in cache."""
    now_ts = datetime.now(timezone.utc).isoformat()
    dev_id = "SENSOR-01"
    bad_token = "0" * 64

    valid, reason = verify_device_token(
        device_id=dev_id,
        token=bad_token,
        timestamp=now_ts,
        flow_id="flow-tamper",
        replay_cache=clean_replay_cache,
    )
    assert valid is False
    assert "cryptographic token verification failed" in reason.lower()
    assert len(clean_replay_cache) == 0  # Invalid token must not consume cache entry


def test_sec01_cross_device_token_rejected(clean_replay_cache):
    """A token generated for SENSOR-01 cannot be presented by SENSOR-02."""
    now_ts = datetime.now(timezone.utc).isoformat()
    token_sensor1 = compute_device_token("SENSOR-01", now_ts, flow_id="flow-shared")

    # Present SENSOR-01's token under SENSOR-02
    valid, reason = verify_device_token(
        device_id="SENSOR-02",
        token=token_sensor1,
        timestamp=now_ts,
        flow_id="flow-shared",
        replay_cache=clean_replay_cache,
    )
    assert valid is False
    assert "cryptographic token verification failed" in reason.lower()
    assert len(clean_replay_cache) == 0


def test_sec01_expired_token_rejected_before_replay_check(clean_replay_cache):
    """Tokens older than drift window are rejected for age, not replay."""
    old_ts = (datetime.now(timezone.utc) - timedelta(seconds=350)).isoformat()
    dev_id = "SENSOR-01"
    token = compute_device_token(dev_id, old_ts, flow_id="flow-expired")

    valid, reason = verify_device_token(
        device_id=dev_id,
        token=token,
        timestamp=old_ts,
        flow_id="flow-expired",
        replay_cache=clean_replay_cache,
    )
    assert valid is False
    assert "expired" in reason.lower()
    assert len(clean_replay_cache) == 0


def test_sec01_future_drift_token_rejected(clean_replay_cache):
    """Tokens with timestamps far in the future (>5.0s) are rejected."""
    future_ts = (datetime.now(timezone.utc) + timedelta(seconds=15)).isoformat()
    dev_id = "SENSOR-01"
    token = compute_device_token(dev_id, future_ts, flow_id="flow-future")

    valid, reason = verify_device_token(
        device_id=dev_id,
        token=token,
        timestamp=future_ts,
        flow_id="flow-future",
        replay_cache=clean_replay_cache,
    )
    assert valid is False
    assert "future timestamp drift" in reason.lower()
    assert len(clean_replay_cache) == 0


def test_sec01_bounded_cache_eviction():
    """Verify replay cache stays bounded to max_size and evicts oldest entries."""
    cache = TokenReplayCache(max_size=20, default_retention_seconds=300.0)

    for i in range(30):
        ts = datetime.now(timezone.utc).isoformat()
        token = compute_device_token("SENSOR-01", ts, flow_id=f"flow-bound-{i}")
        fresh, _ = cache.check_and_record("SENSOR-01", token, ts)
        assert fresh is True

    # Cache must not exceed max_size
    assert len(cache) <= 20


def test_sec01_concurrent_replay_verification(clean_replay_cache):
    """Multi-threaded concurrent token verification correctly prevents duplicate acceptance."""
    now_ts = datetime.now(timezone.utc).isoformat()
    dev_id = "SENSOR-01"
    token = compute_device_token(dev_id, now_ts, flow_id="concurrent-flow")

    results = []

    def worker():
        return verify_device_token(
            device_id=dev_id,
            token=token,
            timestamp=now_ts,
            flow_id="concurrent-flow",
            replay_cache=clean_replay_cache,
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(worker) for _ in range(8)]
        for f in futures:
            results.append(f.result())

    # Exactly ONE thread must succeed; all other 7 must be rejected as replay
    success_count = sum(1 for ok, _ in results if ok is True)
    failure_count = sum(1 for ok, _ in results if ok is False)

    assert success_count == 1
    assert failure_count == 7


def test_sec01_replay_does_not_decay_legitimate_sensor_trust(tmp_path: Path):
    """When an attacker replays a valid sensor token, access is denied but sensor trust is NOT decayed."""
    settings = Settings(database_path=tmp_path / "replay_trust.sqlite3")
    runtime = GatewayRuntime(settings=settings)

    initial_trust = runtime.iam.get("SENSOR-01").trust_score
    assert initial_trust == 100.0

    # 1. Legitimate sensor sends initial authenticated event
    ts = utc_now()
    flow = "sensor-legit-01"
    valid_token = compute_device_token("SENSOR-01", ts, flow, master_key=runtime.settings.device_master_key)

    event1 = TelemetryEvent(
        device_id="SENSOR-01",
        timestamp=ts,
        flow_id=flow,
        packet_count=15,
        packet_rate=15.0,
        protocol="UDP",
        auth_token=valid_token,
        provenance="MEASURED",
    )
    res1 = runtime.ingest(event1)
    assert res1["event"]["access_decision"] == "ALLOW"
    assert runtime.iam.get("SENSOR-01").trust_score == 100.0

    # 2. Attacker intercepts and replays the exact same event
    res2 = runtime.ingest(event1)
    assert res2["event"]["access_decision"] == "DENY"
    assert res2["event"]["authentication_status"] == "FAILED_OR_UNVERIFIED"

    # Legitimate sensor trust must remain 100.0
    assert runtime.iam.get("SENSOR-01").trust_score == 100.0
    db_record = runtime.store.get_device_identity("SENSOR-01")
    assert db_record["trust_score"] == 100.0


def test_sec01_cache_repr_does_not_leak_tokens(clean_replay_cache):
    """TokenReplayCache repr and str must not expose cached digests or plaintext tokens."""
    token = compute_device_token("SENSOR-01", utc_now(), flow_id="repr-flow")
    clean_replay_cache.check_and_record("SENSOR-01", token)

    cache_repr = repr(clean_replay_cache)
    cache_str = str(clean_replay_cache)

    assert token not in cache_repr
    assert token not in cache_str
    assert "TokenReplayCache size=1" in cache_repr


# =============================================================================
# SEC-02: EXTERNALIZE MASTER KEY TESTS
# =============================================================================

def test_sec02_environment_provided_master_key(monkeypatch):
    """AEGIS_MASTER_KEY environment variable configures the master key."""
    custom_key = "custom-secure-master-key-prod-987654321"
    monkeypatch.setenv("AEGIS_MASTER_KEY", custom_key)

    settings = Settings()
    assert settings.device_master_key == custom_key
    assert settings.is_lab_master_key is False


def test_sec02_fallback_to_lab_key_when_unset(monkeypatch):
    """When AEGIS_MASTER_KEY is unset, falls back to clearly identifiable lab key."""
    monkeypatch.delenv("AEGIS_MASTER_KEY", raising=False)
    monkeypatch.delenv("AEGIS_DEVICE_MASTER_KEY", raising=False)

    settings = Settings()
    assert settings.device_master_key == LAB_MASTER_KEY_FALLBACK
    assert settings.is_lab_master_key is True


def test_sec02_no_master_key_leakage_in_repr():
    """Settings repr and str must mask device_master_key and secret_key."""
    settings = Settings()
    settings_repr = repr(settings)

    assert LAB_MASTER_KEY_FALLBACK not in settings_repr
    assert LAB_SECRET_KEY_FALLBACK not in settings_repr
    assert "device_master_key" not in settings_repr
    assert "secret_key" not in settings_repr


def test_sec02_deterministic_device_key_derivation():
    """Same master key yields identical derived keys; different master keys yield distinct keys."""
    key_a = "master-key-alpha-2026"
    key_b = "master-key-bravo-2026"

    dev_key_a1 = derive_device_key("SENSOR-01", key_a)
    dev_key_a2 = derive_device_key("SENSOR-01", key_a)
    dev_key_b = derive_device_key("SENSOR-01", key_b)

    assert dev_key_a1 == dev_key_a2
    assert dev_key_a1 != dev_key_b


def test_sec02_device_authentication_with_custom_key():
    """Verify device token computation and authentication using custom master key."""
    custom_master = "custom-edge-key-prod-12345"
    iam = IAMService(master_key=custom_master)

    ts = datetime.now(timezone.utc).isoformat()
    token = compute_device_token("SENSOR-01", ts, flow_id="flow-custom-master", master_key=custom_master)

    ok, reason = iam.authenticate_device("SENSOR-01", token, ts, flow_id="flow-custom-master")
    assert ok is True
    assert "verified" in reason.lower()

    # Reject if token was generated with lab fallback instead of custom master key
    bad_token = compute_device_token("SENSOR-01", ts, flow_id="flow-custom-master", master_key=LAB_MASTER_KEY_FALLBACK)
    bad_ok, _ = iam.authenticate_device("SENSOR-01", bad_token, ts, flow_id="flow-custom-master")
    assert bad_ok is False


# =============================================================================
# SEC-03: SESSION COOKIE SECURITY TESTS
# =============================================================================

def test_sec03_session_cookie_secure_configurable(monkeypatch):
    """AEGIS_SESSION_COOKIE_SECURE controls SESSION_COOKIE_SECURE."""
    monkeypatch.setenv("AEGIS_SESSION_COOKIE_SECURE", "true")
    s_true = Settings()
    assert s_true.session_cookie_secure is True

    monkeypatch.setenv("AEGIS_SESSION_COOKIE_SECURE", "false")
    s_false = Settings()
    assert s_false.session_cookie_secure is False


def test_sec03_production_enables_secure_cookie_by_default(monkeypatch):
    """AEGIS_PRODUCTION=true enables session_cookie_secure by default."""
    monkeypatch.delenv("AEGIS_SESSION_COOKIE_SECURE", raising=False)
    monkeypatch.setenv("AEGIS_PRODUCTION", "true")
    monkeypatch.setenv("AEGIS_SECRET_KEY", "prod-secret-key-for-test-32bytes!")
    monkeypatch.setenv("AEGIS_MASTER_KEY", "prod-master-key-for-test-32bytes!")
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@localhost:5432/test_db")

    settings = Settings()
    assert settings.production is True
    assert settings.session_cookie_secure is True


def test_sec03_cookie_attributes_applied_to_flask_app(wave1_app):
    """Flask application sets HTTPOnly, SameSite=Lax, and respects secure flag."""
    runtime, app = wave1_app

    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert app.config["SESSION_COOKIE_SECURE"] == runtime.settings.session_cookie_secure


# =============================================================================
# SEC-04: LOGIN OPEN REDIRECT TESTS
# =============================================================================

@pytest.mark.parametrize("malicious_target", [
    "https://evil.com",
    "http://evil.com",
    "http://evil.com/phishing",
    "//evil.com",
    "//evil.com/path",
    "/\\evil.com",
    "\\evil.com",
    "\\\\evil.com",
    "javascript:alert(1)",
    "data:text/html,evil",
    "/%2f%2fevil.com",
    "/%5c%5cevil.com",
    "/login\r\nSet-Cookie:malicious=1",
    "/login\nSet-Cookie:malicious=1",
])
def test_sec04_sanitize_redirect_rejects_malicious_urls(malicious_target):
    """Malicious redirect targets must fall back to safe default '/'."""
    assert sanitize_redirect_url(malicious_target) == "/"


@pytest.mark.parametrize("safe_target", [
    "/",
    "/admin/overview",
    "/admin/users",
    "/admin/alerts",
    "/dashboard?tab=incidents&view=compact",
    "/api/status",
])
def test_sec04_sanitize_redirect_accepts_safe_relative_paths(safe_target):
    """Safe internal relative paths must be preserved."""
    assert sanitize_redirect_url(safe_target) == safe_target


def test_sec04_login_endpoint_redirect_sanitization(wave1_app):
    """POST /api/auth/login and /login with malicious ?next= redirect to '/'."""
    _, app = wave1_app

    with app.test_client() as client:
        # JSON API login with malicious next
        res_json = client.post(
            "/api/auth/login?next=https://attacker.example.com",
            json={"username": "admin", "password": "Admin@AICG2026!", "mfa_code": "123456"}
        )
        assert res_json.status_code == 200
        data = res_json.get_json()
        assert data["redirect"] == "/"  # Sanitized to root

        # JSON API login with safe relative next
        res_safe = client.post(
            "/api/auth/login?next=/admin/users",
            json={"username": "admin", "password": "Admin@AICG2026!", "mfa_code": "123456"}
        )
        assert res_safe.status_code == 200
        assert res_safe.get_json()["redirect"] == "/admin/users"

        # HTML Form login with malicious next
        res_form = client.post(
            "/login?next=//evil.example.com",
            data={"username": "admin", "password": "Admin@AICG2026!", "mfa_code": "123456"}
        )
        assert res_form.status_code == 302
        assert res_form.headers["Location"] == "/"


# =============================================================================
# SEC-05: COOJA IMPORT PATH CONTAINMENT TESTS
# =============================================================================

def test_sec05_resolve_contained_path_valid(tmp_path: Path):
    """Resolving a legitimate file inside an approved root succeeds."""
    allowed_dir = tmp_path / "cooja_data"
    allowed_dir.mkdir()
    sample_file = allowed_dir / "valid_trace.csv"
    sample_file.write_text("header\n1\n")

    resolved = resolve_contained_path(sample_file, allowed_roots=[tmp_path])
    assert resolved == sample_file.resolve()


def test_sec05_resolve_contained_path_rejects_traversal(tmp_path: Path):
    """Path traversal attempting to escape approved root via ../ is denied."""
    allowed_dir = tmp_path / "allowed"
    allowed_dir.mkdir()
    outside_file = tmp_path / "outside.txt"
    outside_file.write_text("secret")

    traversal_path = str(allowed_dir / ".." / "outside.txt")
    with pytest.raises(ValueError, match="outside approved directories"):
        resolve_contained_path(traversal_path, allowed_roots=[allowed_dir])


def test_sec05_resolve_contained_path_rejects_absolute_escape(tmp_path: Path):
    """Absolute path pointing outside approved roots raises ValueError."""
    allowed_dir = tmp_path / "allowed"
    allowed_dir.mkdir()

    with pytest.raises(ValueError, match="outside approved directories"):
        resolve_contained_path("/etc/passwd", allowed_roots=[allowed_dir])


def test_sec05_resolve_contained_path_rejects_nonexistent_file(tmp_path: Path):
    """Non-existent path inside approved root raises FileNotFoundError."""
    allowed_dir = tmp_path / "allowed"
    allowed_dir.mkdir()

    with pytest.raises(FileNotFoundError, match="File not found"):
        resolve_contained_path(allowed_dir / "missing.csv", allowed_roots=[allowed_dir])


def test_sec05_cooja_import_api_boundary_enforcement(wave1_app, tmp_path: Path):
    """POST /api/cooja/import rejects path traversal and outside-root paths with HTTP 400."""
    runtime, app = wave1_app

    with app.test_client() as client:
        _login_as(client, "admin", ROLE_ADMIN)

        # 1. Path traversal attempt
        res_traversal = client.post(
            "/api/cooja/import",
            json={"path": "../../../../etc/passwd"}
        )
        assert res_traversal.status_code == 400
        assert "outside approved directories" in res_traversal.get_json()["error"]

        # 2. Absolute path outside approved directories
        res_abs = client.post(
            "/api/cooja/import",
            json={"path": "/etc/shadow"}
        )
        assert res_abs.status_code == 400
        assert "outside approved directories" in res_abs.get_json()["error"]

        # 3. Legitimate file in runtime.settings.cooja_dir succeeds
        sample_csv = runtime.settings.cooja_dir / "test_import.csv"
        sample_csv.write_text("node_id,packets_in_window,packet_rate_mean,radio_activity_ratio_mean,label\n1,10,10.0,0.1,NORMAL\n")

        res_legit = client.post(
            "/api/cooja/import",
            json={"path": str(sample_csv)}
        )
        assert res_legit.status_code == 200
        assert res_legit.get_json()["imported"] == 1
        assert res_legit.get_json()["source_type"] == "COOJA"


def test_sec05_cooja_import_rbac_enforcement(wave1_app):
    """POST /api/cooja/import requires ROLE_ADMIN; operators receive HTTP 403."""
    _, app = wave1_app

    with app.test_client() as client:
        _login_as(client, "operator", ROLE_OPERATOR)
        res = client.post("/api/cooja/import", json={})
        assert res.status_code == 403
        assert "FORBIDDEN_ROLE" in res.get_json()["code"]

"""Comprehensive security and regression tests for CodeQL path-injection hardening.

Validates the hardened file-import endpoints:
- POST /api/ns3/import
- POST /api/cooja/import
- POST /api/pcap/replay
- GET  /api/ns3 (ns3_status using trace_dir)

Covers:
- Valid NS-3 CSV import
- Valid Cooja CSV import from both permitted locations (trace_dir and cooja_dir)
- Valid PCAP import
- Valid PCAPNG import
- Invalid file extensions
- Empty, whitespace, null-byte, and non-string path values
- ../ traversal attempts
- Absolute paths outside approved directories
- Attempts to access .git/config, SQLite databases, and application source files
- Symlinks resolving outside approved directories
- Existing 401 (unauthenticated) and 403 (operator role) authorization behavior
"""

from __future__ import annotations

import os
import socket
import time
from pathlib import Path

import dpkt
import pytest

from aegis_gateway.api import create_app, resolve_contained_path
from aegis_gateway.config import Settings
from aegis_gateway.runtime import GatewayRuntime
from aegis_gateway.schema import utc_now
from aegis_gateway.security import ROLE_ADMIN, ROLE_OPERATOR


@pytest.fixture
def hardened_app(tmp_path: Path):
    """Fixture providing a test client configured with temporary storage and test settings."""
    db_path = tmp_path / "hardened_test.sqlite3"
    settings = Settings(
        database_path=db_path,
        trace_dir=Path(__file__).resolve().parent.parent / "dataset",
        cooja_dir=tmp_path / "external_cooja_sim",
    )
    settings.cooja_dir.mkdir(parents=True, exist_ok=True)
    runtime = GatewayRuntime(settings=settings)
    app = create_app(runtime)
    app.config["TESTING"] = True
    return runtime, app


def _login_as(client, username: str, role: str):
    """Establish an authenticated session with the specified role."""
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
# 1. VALID IMPORT TESTS (NS-3, COOJA, PCAP, PCAPNG)
# =============================================================================

def test_valid_ns3_csv_import(hardened_app):
    """POST /api/ns3/import accepts valid CSV within trace_dir."""
    _, app = hardened_app
    with app.test_client() as client:
        _login_as(client, "admin", ROLE_ADMIN)

        res = client.post(
            "/api/ns3/import",
            json={"path": "dataset/ns3_low_v1_features.csv", "scenario_id": "test_scenario"}
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["imported"] > 0
        assert data["provenance"] == "SIMULATED"
        assert "ns3_low_v1_features.csv" in data["source"]


def test_valid_cooja_csv_import_from_both_locations(hardened_app, tmp_path: Path):
    """POST /api/cooja/import accepts CSV from both trace_dir and cooja_dir."""
    runtime, app = hardened_app
    with app.test_client() as client:
        _login_as(client, "admin", ROLE_ADMIN)

        # Location 1: trace_dir (dataset/cooja_ml_ready_v1.csv)
        res1 = client.post(
            "/api/cooja/import",
            json={"path": "dataset/cooja_ml_ready_v1.csv"}
        )
        assert res1.status_code == 200
        data1 = res1.get_json()
        assert data1["imported"] > 0
        assert data1["source_type"] == "COOJA"

        # Location 2: cooja_dir
        sample_csv = runtime.settings.cooja_dir / "external_sim_run.csv"
        sample_csv.write_text(
            "node_id,packets_in_window,packet_rate_mean,radio_activity_ratio_mean,label\n"
            "1,15,15.0,0.08,NORMAL\n"
            "2,20,20.0,0.12,NORMAL\n"
        )
        res2 = client.post(
            "/api/cooja/import",
            json={"path": str(sample_csv)}
        )
        assert res2.status_code == 200
        data2 = res2.get_json()
        assert data2["imported"] == 2
        assert data2["source_type"] == "COOJA"

        # Default fallback: cooja_dir / cooja_ml_ready_v1.csv
        cooja_default = runtime.settings.cooja_dir / "cooja_ml_ready_v1.csv"
        cooja_default.write_text(
            "node_id,packets_in_window,packet_rate_mean,radio_activity_ratio_mean,label\n"
            "1,5,5.0,0.02,NORMAL\n"
        )
        res_default = client.post("/api/cooja/import", json={})
        assert res_default.status_code == 200
        assert res_default.get_json()["imported"] == 1


def test_valid_pcap_import(hardened_app):
    """POST /api/pcap/replay accepts valid .pcap within trace_dir."""
    _, app = hardened_app
    with app.test_client() as client:
        _login_as(client, "admin", ROLE_ADMIN)

        res = client.post(
            "/api/pcap/replay",
            json={"path": "dataset/ns3_normal_sensor_1-0-0.pcap", "windowed": True}
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["replayed"] > 0
        assert data["provenance"] == "REPLAYED"
        assert data["transmitted"] is False
        assert "ns3_normal_sensor_1-0-0.pcap" in data["source"]


def test_valid_pcapng_import(hardened_app):
    """POST /api/pcap/replay accepts valid .pcapng files within trace_dir."""
    runtime, app = hardened_app
    pcapng_path = runtime.settings.trace_dir / "test_fixture.pcapng"

    with open(pcapng_path, "wb") as f:
        writer = dpkt.pcapng.Writer(f)
        ip = dpkt.ip.IP(
            src=socket.inet_aton("192.168.1.100"),
            dst=socket.inet_aton("192.168.1.1"),
            p=dpkt.ip.IP_PROTO_UDP
        )
        udp = dpkt.udp.UDP(sport=5000, dport=5000)
        udp.data = b"pcapng test packet"
        udp.ulen = len(udp)
        ip.data = udp
        ip.len = len(ip)
        eth = dpkt.ethernet.Ethernet(
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip,
            src=b"\x00" * 6,
            dst=b"\x00" * 6
        )
        writer.writepkt(bytes(eth), ts=time.time())

    try:
        with app.test_client() as client:
            _login_as(client, "admin", ROLE_ADMIN)
            res = client.post(
                "/api/pcap/replay",
                json={"path": f"dataset/{pcapng_path.name}", "windowed": True}
            )
            assert res.status_code == 200
            data = res.get_json()
            assert data["replayed"] == 1
            assert data["provenance"] == "REPLAYED"
    finally:
        if pcapng_path.exists():
            pcapng_path.unlink()


# =============================================================================
# 2. EXTENSION VALIDATION TESTS
# =============================================================================

def test_invalid_file_extensions(hardened_app):
    """Endpoints strictly reject files with unsupported extensions."""
    _, app = hardened_app
    with app.test_client() as client:
        _login_as(client, "admin", ROLE_ADMIN)

        # 1. NS-3 rejecting PCAP and TXT
        res_ns3_pcap = client.post(
            "/api/ns3/import",
            json={"path": "dataset/ns3_normal_sensor_1-0-0.pcap"}
        )
        assert res_ns3_pcap.status_code == 400
        assert "Unsupported file extension" in res_ns3_pcap.get_json()["error"]

        res_ns3_txt = client.post(
            "/api/ns3/import",
            json={"path": "dataset/ns3_baseline_evaluation_v1.txt"}
        )
        assert res_ns3_txt.status_code == 400
        assert "Unsupported file extension" in res_ns3_txt.get_json()["error"]

        # 2. Cooja rejecting TXT
        res_cooja_txt = client.post(
            "/api/cooja/import",
            json={"path": "dataset/ns3_baseline_evaluation_v1.txt"}
        )
        assert res_cooja_txt.status_code == 400
        assert "Unsupported file extension" in res_cooja_txt.get_json()["error"]

        # 3. PCAP replay rejecting CSV
        res_pcap_csv = client.post(
            "/api/pcap/replay",
            json={"path": "dataset/ns3_low_v1_features.csv"}
        )
        assert res_pcap_csv.status_code == 400
        assert "Unsupported file extension" in res_pcap_csv.get_json()["error"]


# =============================================================================
# 3. EMPTY, NULL-BYTE, AND NON-STRING PATH TESTS
# =============================================================================

@pytest.mark.parametrize("endpoint", [
    "/api/ns3/import",
    "/api/cooja/import",
    "/api/pcap/replay",
])
@pytest.mark.parametrize("bad_path", [
    12345,
    ["dataset/ns3_low_v1_features.csv"],
    {"file": "dataset/ns3_low_v1_features.csv"},
    "dataset/test\0.csv",
    "   ",
])
def test_empty_and_non_string_path_values(hardened_app, endpoint, bad_path):
    """Endpoints reject non-string, empty, whitespace-only, and null-byte paths."""
    _, app = hardened_app
    with app.test_client() as client:
        _login_as(client, "admin", ROLE_ADMIN)

        res = client.post(endpoint, json={"path": bad_path})
        assert res.status_code == 400
        error = res.get_json()["error"]
        assert any(
            msg in error
            for msg in (
                "must be a string",
                "must not be empty",
                "contains invalid null byte",
                "Invalid path",
            )
        )


def test_missing_path_on_ns3_and_pcap(hardened_app):
    """Missing or None path parameter is rejected on endpoints without defaults."""
    _, app = hardened_app
    with app.test_client() as client:
        _login_as(client, "admin", ROLE_ADMIN)

        res_ns3 = client.post("/api/ns3/import", json={})
        assert res_ns3.status_code == 400
        assert "must be a string" in res_ns3.get_json()["error"]

        res_pcap = client.post("/api/pcap/replay", json={})
        assert res_pcap.status_code == 400
        assert "must be a string" in res_pcap.get_json()["error"]


# =============================================================================
# 3b. JSON PAYLOAD SHAPE VALIDATION TESTS
# =============================================================================

@pytest.mark.parametrize("endpoint", [
    "/api/ns3/import",
    "/api/cooja/import",
    "/api/pcap/replay",
])
@pytest.mark.parametrize("non_dict_payload", [
    ["dataset/ns3_low_v1_features.csv"],
    "just_a_raw_json_string",
    12345,
    99.99,
    True,
    False,
])
def test_non_dict_json_payloads_return_400(hardened_app, endpoint, non_dict_payload):
    """Endpoints reject non-dictionary JSON payloads with HTTP 400 without an unhandled exception."""
    _, app = hardened_app
    with app.test_client() as client:
        _login_as(client, "admin", ROLE_ADMIN)

        res = client.post(endpoint, json=non_dict_payload)
        assert res.status_code == 400
        data = res.get_json()
        assert data is not None
        assert data.get("error") == "request body must be a JSON object"


def test_cooja_default_path_when_path_omitted(hardened_app):
    """Cooja import uses default file when path key is omitted or when body is empty/None."""
    runtime, app = hardened_app
    cooja_default = runtime.settings.cooja_dir / "cooja_ml_ready_v1.csv"
    cooja_default.write_text(
        "node_id,packets_in_window,packet_rate_mean,radio_activity_ratio_mean,label\n"
        "1,5,5.0,0.02,NORMAL\n"
    )

    with app.test_client() as client:
        _login_as(client, "admin", ROLE_ADMIN)

        # 1. Path key omitted from valid JSON object with other keys
        res_omitted = client.post("/api/cooja/import", json={"scenario_id": "test_scenario"})
        assert res_omitted.status_code == 200
        assert res_omitted.get_json()["imported"] == 1

        # 2. Empty JSON object
        res_empty = client.post("/api/cooja/import", json={})
        assert res_empty.status_code == 200
        assert res_empty.get_json()["imported"] == 1

        # 3. Request without JSON body (None payload)
        res_none = client.post("/api/cooja/import")
        assert res_none.status_code == 200
        assert res_none.get_json()["imported"] == 1


# =============================================================================
# 4. PATH TRAVERSAL AND DIRECTORY ESCAPE TESTS
# =============================================================================

@pytest.mark.parametrize("endpoint", [
    "/api/ns3/import",
    "/api/cooja/import",
    "/api/pcap/replay",
])
@pytest.mark.parametrize("traversal_path", [
    "../../../../etc/passwd",
    "dataset/../../../../etc/passwd",
    "/etc/passwd",
    "/etc/shadow",
    "/tmp/nonexistent_escape.csv",
])
def test_traversal_attempts_and_absolute_escapes(hardened_app, endpoint, traversal_path):
    """All endpoints deny ../ directory traversal and absolute paths outside roots."""
    _, app = hardened_app
    with app.test_client() as client:
        _login_as(client, "admin", ROLE_ADMIN)

        res = client.post(endpoint, json={"path": traversal_path})
        assert res.status_code == 400
        assert "outside approved directories" in res.get_json()["error"]


# =============================================================================
# 5. ATTEMPTS TO ACCESS REPO SENSITIVE FILES (.git, DB, SOURCE)
# =============================================================================

@pytest.mark.parametrize("endpoint", [
    "/api/ns3/import",
    "/api/cooja/import",
    "/api/pcap/replay",
])
@pytest.mark.parametrize("sensitive_file", [
    ".git/config",
    "../.git/config",
    "backend/data/aegis_gateway.sqlite3",
    "data/aegis_gateway.sqlite3",
    "dataset/../data/aegis_gateway.sqlite3",
    "backend/aegis_gateway/security.py",
    "backend/aegis_gateway/api.py",
    "aegis_gateway/api.py",
])
def test_attempts_to_access_sensitive_repo_files(hardened_app, endpoint, sensitive_file):
    """Import endpoints deny access to .git metadata, SQLite databases, and source files."""
    _, app = hardened_app
    with app.test_client() as client:
        _login_as(client, "admin", ROLE_ADMIN)

        res = client.post(endpoint, json={"path": sensitive_file})
        assert res.status_code == 400
        error = res.get_json()["error"]
        assert any(
            msg in error
            for msg in (
                "outside approved directories",
                "Unsupported file extension",
                "not a regular file",
            )
        )


# =============================================================================
# 6. SYMLINK ESCAPE PROTECTION TESTS
# =============================================================================

def test_symlinks_resolving_outside_approved_directories(hardened_app, tmp_path: Path):
    """Symlinks residing in approved directories pointing outside are detected and blocked."""
    runtime, app = hardened_app

    outside_file = tmp_path / "outside_secret.csv"
    outside_file.write_text("header\nsecret_data\n")

    symlink_path = runtime.settings.trace_dir / "external_leak_symlink.csv"
    try:
        symlink_path.symlink_to(outside_file)
    except OSError:
        pytest.skip("Symlink creation not permitted in this environment")

    try:
        with app.test_client() as client:
            _login_as(client, "admin", ROLE_ADMIN)
            res = client.post(
                "/api/ns3/import",
                json={"path": f"dataset/{symlink_path.name}"}
            )
            assert res.status_code == 400
            assert "outside approved directories" in res.get_json()["error"]
    finally:
        if symlink_path.is_symlink() or symlink_path.exists():
            symlink_path.unlink()


# =============================================================================
# 7. AUTHORIZATION AND RBAC TESTS (401, 403)
# =============================================================================

@pytest.mark.parametrize("endpoint,valid_payload", [
    ("/api/ns3/import", {"path": "dataset/ns3_low_v1_features.csv"}),
    ("/api/cooja/import", {"path": "dataset/cooja_ml_ready_v1.csv"}),
    ("/api/pcap/replay", {"path": "dataset/ns3_normal_sensor_1-0-0.pcap"}),
])
def test_authorization_behavior(hardened_app, endpoint, valid_payload):
    """Unauthenticated requests yield 401; non-admin operators receive 403 FORBIDDEN_ROLE."""
    _, app = hardened_app
    with app.test_client() as client:
        # Unauthenticated -> 401
        res_unauth = client.post(endpoint, json=valid_payload)
        assert res_unauth.status_code == 401

        # Operator (non-admin) -> 403
        _login_as(client, "operator", ROLE_OPERATOR)
        res_operator = client.post(endpoint, json=valid_payload)
        assert res_operator.status_code == 403
        assert "FORBIDDEN_ROLE" in res_operator.get_json()["code"]


# =============================================================================
# 8. NS-3 STATUS ENDPOINT USING TRACE_DIR
# =============================================================================

def test_ns3_status_uses_trace_dir(hardened_app):
    """GET /api/ns3 cleanly lists PCAP traces using runtime.settings.trace_dir."""
    _, app = hardened_app
    with app.test_client() as client:
        _login_as(client, "admin", ROLE_ADMIN)

        res = client.get("/api/ns3")
        assert res.status_code == 200
        data = res.get_json()
        assert "pcap_traces" in data
        assert len(data["pcap_traces"]) > 0
        assert all(t.startswith("dataset/ns3_") and t.endswith(".pcap") for t in data["pcap_traces"])


# =============================================================================
# 9. INFORMATION EXPOSURE: ERROR RESPONSES DO NOT EXPOSE FILESYSTEM PATHS
# =============================================================================

@pytest.mark.parametrize("endpoint", [
    "/api/ns3/import",
    "/api/cooja/import",
    "/api/pcap/replay",
])
@pytest.mark.parametrize("bad_path", [
    "/etc/passwd",
    "/etc/shadow",
    "/var/log/syslog",
    "/home/kali/secret.csv",
    "../../../../etc/passwd",
    "dataset/../../../../etc/passwd",
    "nonexistent_relative_trace.csv",
    "dataset/nonexistent_relative_trace.csv",
])
def test_error_responses_do_not_expose_filesystem_paths(hardened_app, endpoint, bad_path):
    """Error responses never leak absolute system paths, exception strings, or directory structures."""
    _, app = hardened_app
    with app.test_client() as client:
        _login_as(client, "admin", ROLE_ADMIN)

        res = client.post(endpoint, json={"path": bad_path})
        assert res.status_code == 400
        error_msg = res.get_json()["error"]

        # 1. Error message must not contain raw requested system path
        assert "/etc" not in error_msg
        assert "/home" not in error_msg
        assert "/var" not in error_msg
        assert "/tmp" not in error_msg
        assert ".." not in error_msg

        # 2. Must not contain Python exception class or traceback markers
        assert "Traceback" not in error_msg
        assert "FileNotFoundError" not in error_msg
        assert "ValueError" not in error_msg
        assert "Errno" not in error_msg


# =============================================================================
# 10. NO PROBING OUTSIDE APPROVED ROOTS BEFORE VALIDATION
# =============================================================================

def test_no_filesystem_probing_outside_approved_roots(hardened_app, monkeypatch):
    """resolve_contained_path does not invoke stat(), exists(), or is_file() on candidates outside roots."""
    _, app = hardened_app
    checked_paths: list[str] = []

    orig_is_file = Path.is_file
    def tracking_is_file(self):
        checked_paths.append(str(self))
        return orig_is_file(self)

    monkeypatch.setattr(Path, "is_file", tracking_is_file)

    with app.test_client() as client:
        _login_as(client, "admin", ROLE_ADMIN)

        res = client.post("/api/ns3/import", json={"path": "../../../../etc/passwd"})
        assert res.status_code == 400

        # Verify that /etc/passwd or any outside path was never probed with is_file()
        assert not any("/etc/passwd" in p for p in checked_paths)


# =============================================================================
# 11. BARE FILENAME AND RELATIVE IMPORT TESTS
# =============================================================================

def test_bare_filename_imports(hardened_app):
    """Endpoints accept bare filenames residing directly in the default approved root."""
    runtime, app = hardened_app
    with app.test_client() as client:
        _login_as(client, "admin", ROLE_ADMIN)

        # NS-3 bare filename in trace_dir
        res_ns3 = client.post(
            "/api/ns3/import",
            json={"path": "ns3_low_v1_features.csv", "scenario_id": "test_bare"}
        )
        assert res_ns3.status_code == 200
        assert res_ns3.get_json()["imported"] > 0

        # Cooja bare filename in cooja_dir
        cooja_bare = runtime.settings.cooja_dir / "cooja_bare.csv"
        cooja_bare.write_text(
            "node_id,packets_in_window,packet_rate_mean,radio_activity_ratio_mean,label\n"
            "1,10,10.0,0.05,NORMAL\n"
        )
        res_cooja = client.post(
            "/api/cooja/import",
            json={"path": "cooja_bare.csv"}
        )
        assert res_cooja.status_code == 200
        assert res_cooja.get_json()["imported"] == 1

        # PCAP bare filename in trace_dir
        res_pcap = client.post(
            "/api/pcap/replay",
            json={"path": "ns3_normal_sensor_1-0-0.pcap", "windowed": True}
        )
        assert res_pcap.status_code == 200
        assert res_pcap.get_json()["replayed"] > 0


# =============================================================================
# 12. REJECTION OF NESTED RELATIVE PATHS
# =============================================================================

@pytest.mark.parametrize("endpoint", [
    "/api/ns3/import",
    "/api/cooja/import",
    "/api/pcap/replay",
])
@pytest.mark.parametrize("nested_path", [
    "sub/nested/trace.csv",
    "deep/dir/structure/file.pcap",
    "dataset/sub/trace.csv",
    "other_dataset/trace.csv",
])
def test_nested_relative_paths_rejected(hardened_app, endpoint, nested_path):
    """Nested relative paths outside the dataset/<filename> pattern are rejected."""
    _, app = hardened_app
    with app.test_client() as client:
        _login_as(client, "admin", ROLE_ADMIN)

        res = client.post(endpoint, json={"path": nested_path})
        assert res.status_code == 400
        assert "outside approved directories" in res.get_json()["error"]


# =============================================================================
# 13. PREFIX-COLLISION PATH REJECTION TESTS
# =============================================================================

@pytest.mark.parametrize("endpoint", [
    "/api/ns3/import",
    "/api/cooja/import",
    "/api/pcap/replay",
])
def test_prefix_collision_paths_rejected(hardened_app, tmp_path: Path, endpoint):
    """Paths matching approved root prefix without directory separator are rejected."""
    runtime, app = hardened_app
    collision_dir = runtime.settings.trace_dir.parent / f"{runtime.settings.trace_dir.name}_collision"
    collision_dir.mkdir(parents=True, exist_ok=True)
    collision_file = collision_dir / "collision_trace.csv"
    collision_file.write_text("dummy,content\n1,2\n")

    try:
        with app.test_client() as client:
            _login_as(client, "admin", ROLE_ADMIN)

            res = client.post(endpoint, json={"path": str(collision_file)})
            assert res.status_code == 400
            assert "outside approved directories" in res.get_json()["error"]
    finally:
        if collision_file.exists():
            collision_file.unlink()
        if collision_dir.exists():
            collision_dir.rmdir()


# =============================================================================
# 14. SERVER-SIDE ALLOWLIST REGISTRY SECURITY TESTS
# =============================================================================

@pytest.mark.parametrize("endpoint", [
    "/api/ns3/import",
    "/api/cooja/import",
    "/api/pcap/replay",
])
@pytest.mark.parametrize("missing_path", [
    "dataset/nonexistent_file_12345.csv",
    "dataset/nonexistent_file_12345.pcap",
    "nonexistent_file_12345.csv",
    "nonexistent_file_12345.pcap",
])
def test_missing_allowlist_entries_rejected(hardened_app, endpoint, missing_path):
    """Paths not present in the server allowlist registry return 400 without exposing paths."""
    _, app = hardened_app
    with app.test_client() as client:
        _login_as(client, "admin", ROLE_ADMIN)

        res = client.post(endpoint, json={"path": missing_path})
        assert res.status_code == 400
        error_msg = res.get_json()["error"]
        assert "not a regular file" in error_msg or "outside approved directories" in error_msg
        assert "/etc" not in error_msg
        assert "/home" not in error_msg


def test_directory_symlink_pointing_outside_approved_roots(hardened_app, tmp_path: Path):
    """Directory symlinks pointing outside approved roots are excluded and lookups rejected."""
    runtime, app = hardened_app
    outside_dir = tmp_path / "outside_directory"
    outside_dir.mkdir(parents=True, exist_ok=True)
    outside_file = outside_dir / "secret_data.csv"
    outside_file.write_text("header,val\n1,2\n")

    dir_symlink = runtime.settings.trace_dir / "leaked_symlink_dir"
    try:
        dir_symlink.symlink_to(outside_dir, target_is_directory=True)
    except OSError:
        pytest.skip("Symlink creation not permitted in this environment")

    try:
        with app.test_client() as client:
            _login_as(client, "admin", ROLE_ADMIN)

            res = client.post(
                "/api/ns3/import",
                json={"path": f"dataset/{dir_symlink.name}/secret_data.csv"}
            )
            assert res.status_code == 400
            assert "outside approved directories" in res.get_json()["error"]
    finally:
        if dir_symlink.is_symlink() or dir_symlink.exists():
            dir_symlink.unlink()


def test_raw_input_never_passed_to_filesystem_apis(hardened_app, monkeypatch):
    """User-supplied path strings are never passed directly to filesystem resolution/stat APIs."""
    _, app = hardened_app
    attacker_payload = "../../../../etc/passwd"
    seen_paths: list[str] = []

    orig_realpath = os.path.realpath
    def tracking_realpath(path, *args, **kwargs):
        seen_paths.append(str(path))
        return orig_realpath(path, *args, **kwargs)

    orig_is_file = Path.is_file
    def tracking_is_file(self):
        seen_paths.append(str(self))
        return orig_is_file(self)

    monkeypatch.setattr(os.path, "realpath", tracking_realpath)
    monkeypatch.setattr(Path, "is_file", tracking_is_file)

    with app.test_client() as client:
        _login_as(client, "admin", ROLE_ADMIN)

        res = client.post("/api/ns3/import", json={"path": attacker_payload})
        assert res.status_code == 400

        # Assert raw user string never touched realpath or is_file
        assert not any(attacker_payload in p for p in seen_paths)
        assert not any("/etc/passwd" in p for p in seen_paths)

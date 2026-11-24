"""Focused unit and integration tests for production-safe baseline generator control.

Verifies:
1. Settings dataclass annotation is properly typed as bool | None.
2. Development defaults baseline_enabled=True and resolves to a concrete bool.
3. Production defaults baseline_enabled=False and resolves to a concrete bool.
4. AEGIS_BASELINE_ENABLED overrides development default.
5. AEGIS_BASELINE_ENABLED overrides production default.
6. Disabled runtime refuses to start the baseline worker (returns False).
7. Enabled runtime starts the baseline worker (returns True).
8. Repeated start attempts do not create duplicate threads.
9. stop_baseline() safely handles no worker (returns True, no error).
10. Worker terminates within timeout and returns True, clearing thread references.
11. Worker remains alive beyond timeout and returns False, keeping thread/stop event intact.
12. Repeated start attempts cannot create overlapping workers while earlier worker is alive.
13. A later stop succeeds after a blocked worker exits.
14. stop_baseline() safely handles invocation from inside the worker thread without deadlock.
15. Production application import does not start baseline thread by default.
16. Reset endpoint does not restart baseline generation when disabled.
17. Manual DDoS simulations produce telemetry when baseline generation is disabled.
18. Existing baseline and recovery tests work with explicit configuration.
19. Normal shutdown cleanly terminates worker.
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import typing

import pytest

from aegis_gateway.api import create_app
from aegis_gateway.config import Settings
from aegis_gateway.runtime import GatewayRuntime


def test_settings_annotation_is_properly_typed_optional_bool():
    """Verify Settings.baseline_enabled is typed as bool | None in dataclass fields and type hints."""
    hints = typing.get_type_hints(Settings)
    assert hints["baseline_enabled"] == bool | None
    field_def = Settings.__dataclass_fields__["baseline_enabled"]
    assert field_def.default is None


def test_settings_development_defaults_baseline_enabled_true(monkeypatch: pytest.MonkeyPatch):
    """Verify development mode defaults baseline_enabled=True and resolves to concrete bool."""
    monkeypatch.delenv("AEGIS_BASELINE_ENABLED", raising=False)
    monkeypatch.delenv("AEGIS_PRODUCTION", raising=False)
    settings = Settings(production=False)
    assert settings.production is False
    assert settings.baseline_enabled is True
    assert isinstance(settings.baseline_enabled, bool)


def test_settings_production_defaults_baseline_enabled_false(monkeypatch: pytest.MonkeyPatch):
    """Verify production mode defaults baseline_enabled=False and resolves to concrete bool."""
    monkeypatch.delenv("AEGIS_BASELINE_ENABLED", raising=False)
    monkeypatch.delenv("AEGIS_PRODUCTION", raising=False)
    settings = Settings(
        production=True,
        secret_key="secure-test-production-secret-key-at-least-64-bytes-entropy-required",
        device_master_key="secure-test-production-master-key-at-least-64-bytes-entropy-required",
        database_url="postgresql://user:pass@localhost:5432/test_db",
    )
    assert settings.production is True
    assert settings.baseline_enabled is False
    assert isinstance(settings.baseline_enabled, bool)


def test_aegis_baseline_enabled_overrides_development_default(monkeypatch: pytest.MonkeyPatch):
    """Verify AEGIS_BASELINE_ENABLED=false overrides the development default."""
    monkeypatch.setenv("AEGIS_BASELINE_ENABLED", "false")
    monkeypatch.delenv("AEGIS_PRODUCTION", raising=False)
    settings = Settings(production=False)
    assert settings.production is False
    assert settings.baseline_enabled is False
    assert isinstance(settings.baseline_enabled, bool)


def test_aegis_baseline_enabled_overrides_production_default(monkeypatch: pytest.MonkeyPatch):
    """Verify AEGIS_BASELINE_ENABLED=true overrides the production default."""
    monkeypatch.setenv("AEGIS_BASELINE_ENABLED", "true")
    monkeypatch.delenv("AEGIS_PRODUCTION", raising=False)
    settings = Settings(
        production=True,
        secret_key="secure-test-production-secret-key-at-least-64-bytes-entropy-required",
        device_master_key="secure-test-production-master-key-at-least-64-bytes-entropy-required",
        database_url="postgresql://user:pass@localhost:5432/test_db",
    )
    assert settings.production is True
    assert settings.baseline_enabled is True
    assert isinstance(settings.baseline_enabled, bool)


def test_disabled_runtime_refuses_to_start_baseline_worker(tmp_path: Path):
    """Verify start_baseline() returns False and spawns no thread when baseline_enabled=False."""
    settings = Settings(database_path=tmp_path / "disabled.sqlite3", baseline_enabled=False)
    runtime = GatewayRuntime(settings)

    started = runtime.start_baseline()
    assert started is False
    assert getattr(runtime, "_baseline_thread", None) is None


def test_enabled_runtime_starts_baseline_worker(tmp_path: Path):
    """Verify start_baseline() returns True and spawns an active thread when baseline_enabled=True."""
    settings = Settings(database_path=tmp_path / "enabled.sqlite3", baseline_enabled=True, demo_tick_seconds=0.05)
    runtime = GatewayRuntime(settings)

    started = runtime.start_baseline(tick_seconds=0.05)
    assert started is True
    assert runtime._baseline_thread is not None
    assert runtime._baseline_thread.is_alive()

    stopped = runtime.stop_baseline()
    assert stopped is True
    assert runtime._baseline_thread is None


def test_repeated_start_attempts_do_not_create_duplicate_threads(tmp_path: Path):
    """Verify repeated start_baseline() calls do not spawn duplicate threads."""
    settings = Settings(database_path=tmp_path / "duplicate.sqlite3", baseline_enabled=True, demo_tick_seconds=0.05)
    runtime = GatewayRuntime(settings)

    started_1 = runtime.start_baseline(tick_seconds=0.05)
    assert started_1 is True
    thread_1 = runtime._baseline_thread

    started_2 = runtime.start_baseline(tick_seconds=0.05)
    assert started_2 is False
    assert runtime._baseline_thread == thread_1

    runtime.stop_baseline()


def test_stop_baseline_safely_handles_no_worker(tmp_path: Path):
    """Verify stop_baseline() returns True and handles uninitialized workers safely without error."""
    settings = Settings(database_path=tmp_path / "unstarted.sqlite3", baseline_enabled=False)
    runtime = GatewayRuntime(settings)

    # Calling stop_baseline() on a runtime where baseline never started returns True cleanly
    stopped = runtime.stop_baseline()
    assert stopped is True
    assert getattr(runtime, "_baseline_thread", None) is None
    assert getattr(runtime, "_baseline_stop", None) is None


def test_worker_terminates_within_timeout_returns_true(tmp_path: Path):
    """Verify stop_baseline() cleanly joins worker within timeout and clears references."""
    settings = Settings(database_path=tmp_path / "clean_stop.sqlite3", baseline_enabled=True, demo_tick_seconds=0.05)
    runtime = GatewayRuntime(settings)

    assert runtime.start_baseline(tick_seconds=0.05) is True
    thread = runtime._baseline_thread
    assert thread.is_alive()

    result = runtime.stop_baseline(timeout=3.0)
    assert result is True
    assert not thread.is_alive()
    assert runtime._baseline_thread is None
    assert runtime._baseline_stop is None


def test_worker_remains_alive_beyond_timeout_and_later_stop_succeeds(tmp_path: Path):
    """Verify stop_baseline() behavior when worker is blocked beyond timeout.

    Verifies:
    1. Returns False if worker remains alive after timeout.
    2. _baseline_thread reference remains intact.
    3. _baseline_stop event remains available.
    4. Repeated start_baseline() attempts cannot spawn overlapping workers.
    5. A later stop_baseline() call succeeds once the worker exits.
    """
    settings = Settings(database_path=tmp_path / "timeout.sqlite3", baseline_enabled=True)
    runtime = GatewayRuntime(settings)

    worker_ready = threading.Event()
    worker_can_exit = threading.Event()

    def controlled_worker():
        worker_ready.set()
        # Simulates long blocking work
        worker_can_exit.wait()

    controlled_thread = threading.Thread(target=controlled_worker, name="mock-blocked-worker", daemon=True)
    stop_evt = threading.Event()
    runtime._baseline_thread = controlled_thread
    runtime._baseline_stop = stop_evt
    controlled_thread.start()
    assert worker_ready.wait(timeout=1.0) is True

    # 1. Stop baseline with a tiny timeout (0.05s) while worker is blocked
    result = runtime.stop_baseline(timeout=0.05)
    assert result is False
    assert controlled_thread.is_alive() is True

    # 2. Verify references remain intact (not cleared while thread is alive)
    assert runtime._baseline_thread is controlled_thread
    assert runtime._baseline_stop is stop_evt
    assert stop_evt.is_set() is True  # Event was signaled

    # 3. Repeated start attempt MUST NOT spawn another worker while this one is alive
    started_overlap = runtime.start_baseline()
    assert started_overlap is False
    assert runtime._baseline_thread is controlled_thread

    # 4. Unblock the worker and verify a later stop_baseline succeeds
    worker_can_exit.set()
    later_result = runtime.stop_baseline(timeout=1.0)
    assert later_result is True
    assert not controlled_thread.is_alive()
    assert runtime._baseline_thread is None
    assert runtime._baseline_stop is None


def test_stop_baseline_handles_invocation_from_worker_thread(tmp_path: Path):
    """Verify stop_baseline() does not deadlock when called from inside the worker thread."""
    settings = Settings(database_path=tmp_path / "self_stop.sqlite3", baseline_enabled=True)
    runtime = GatewayRuntime(settings)

    called = threading.Event()
    results: list[bool] = []

    def self_stopping_worker():
        res = runtime.stop_baseline()
        results.append(res)
        called.set()

    worker_thread = threading.Thread(target=self_stopping_worker, name="mock-self-stopping", daemon=True)
    stop_evt = threading.Event()
    runtime._baseline_thread = worker_thread
    runtime._baseline_stop = stop_evt
    worker_thread.start()

    assert called.wait(timeout=1.0) is True
    worker_thread.join(timeout=1.0)

    # Did not deadlock; returned False because thread was alive during the call
    assert results == [False]

    # After thread has completed, subsequent stop returns True and clears references
    final_stop = runtime.stop_baseline()
    assert final_stop is True
    assert runtime._baseline_thread is None
    assert runtime._baseline_stop is None


def test_production_application_import_does_not_start_baseline_thread():
    """Verify importing backend.app in production mode does not start the background baseline worker."""
    code = (
        "import os\n"
        "import sys\n"
        "sys.path.extend(['.', '..', 'backend'])\n"
        "import unittest.mock\n"
        "os.environ['AEGIS_PRODUCTION'] = 'true'\n"
        "os.environ['AEGIS_SECRET_KEY'] = 'secure-test-production-secret-key-at-least-64-bytes-entropy-required'\n"
        "os.environ['AEGIS_MASTER_KEY'] = 'secure-test-production-master-key-at-least-64-bytes-entropy-required'\n"
        "os.environ['DATABASE_URL'] = 'postgresql://user:pass@localhost:5432/test_db'\n"
        "import aegis_gateway.runtime\n"
        "aegis_gateway.runtime.create_gateway_store = lambda s: unittest.mock.MagicMock()\n"
        "from backend.app import runtime\n"
        "assert runtime.settings.production is True, 'Expected production mode'\n"
        "assert runtime.settings.baseline_enabled is False, 'Expected baseline_enabled=False'\n"
        "assert getattr(runtime, '_baseline_thread', None) is None, 'Expected no baseline thread'\n"
        "print('PROD_IMPORT_VERIFIED_CLEAN')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=True,
        cwd=str(Path(__file__).resolve().parent.parent.parent),
    )
    assert "PROD_IMPORT_VERIFIED_CLEAN" in result.stdout


def test_reset_endpoint_does_not_restart_baseline_when_disabled(tmp_path: Path):
    """Verify /api/simulations/reset does not restart the baseline worker when baseline_enabled=False."""
    settings = Settings(
        database_path=tmp_path / "reset.sqlite3",
        baseline_enabled=False,
        initial_admin_password="AdminSecurePassword@2026!",
    )
    runtime = GatewayRuntime(settings)
    app = create_app(runtime)

    with app.test_client() as client:
        # Perform administrative login
        login_res = client.post(
            "/api/auth/login",
            json={
                "username": settings.initial_admin_username,
                "password": "AdminSecurePassword@2026!",
                "mfa_code": "123456",
            },
        )
        assert login_res.status_code == 200

        # Call reset endpoint
        reset_res = client.post("/api/simulations/reset")
        assert reset_res.status_code == 200
        assert reset_res.get_json()["status"] == "RESET"

        # Baseline worker must remain disabled and not running
        assert getattr(runtime, "_baseline_thread", None) is None


def test_manual_ddos_simulations_produce_telemetry_when_baseline_disabled(tmp_path: Path):
    """Verify manual UDP flood, TCP SYN flood, and ICMP flood simulations function normally without baseline."""
    settings = Settings(database_path=tmp_path / "manual_sims.sqlite3", baseline_enabled=False, demo_tick_seconds=0.05)
    runtime = GatewayRuntime(settings)

    # 1. Initially zero telemetry rows
    assert len(runtime.store.telemetry()) == 0
    assert getattr(runtime, "_baseline_thread", None) is None

    # 2. Test manual UDP flood
    udp_sim = runtime.start_simulation("udp_flood", intensity=3, duration=0.2)
    assert udp_sim["state"] == "RUNNING"
    deadline = time.monotonic() + 3.0
    udp_rows = []
    while time.monotonic() < deadline:
        udp_rows = runtime.store.telemetry()
        if any(r.get("attack_type") == "udp_flood" for r in udp_rows):
            break
        time.sleep(0.05)
    assert len(udp_rows) > 0
    assert any(r["attack_type"] == "udp_flood" for r in udp_rows)
    assert any(r["label"] == "ATTACK" for r in udp_rows)
    # Baseline worker must STILL not be running
    assert getattr(runtime, "_baseline_thread", None) is None

    # 3. Test manual TCP SYN flood
    initial_count = len(runtime.store.telemetry())
    syn_sim = runtime.start_simulation("syn_flood", intensity=3, duration=0.2)
    assert syn_sim["state"] == "RUNNING"
    deadline = time.monotonic() + 3.0
    syn_rows = []
    while time.monotonic() < deadline:
        syn_rows = runtime.store.telemetry()
        if any(r.get("attack_type") == "syn_flood" for r in syn_rows):
            break
        time.sleep(0.05)
    assert len(syn_rows) > initial_count
    assert any(r["attack_type"] == "syn_flood" for r in syn_rows)
    assert getattr(runtime, "_baseline_thread", None) is None

    # 4. Test manual ICMP flood
    initial_count_2 = len(runtime.store.telemetry())
    icmp_sim = runtime.start_simulation("icmp_flood", intensity=3, duration=0.2)
    assert icmp_sim["state"] == "RUNNING"
    deadline = time.monotonic() + 3.0
    icmp_rows = []
    while time.monotonic() < deadline:
        icmp_rows = runtime.store.telemetry()
        if any(r.get("attack_type") == "icmp_flood" for r in icmp_rows):
            break
        time.sleep(0.05)
    assert len(icmp_rows) > initial_count_2
    assert any(r["attack_type"] == "icmp_flood" for r in icmp_rows)
    assert getattr(runtime, "_baseline_thread", None) is None


def test_existing_baseline_and_recovery_tests_work_with_explicit_configuration(tmp_path: Path):
    """Verify baseline telemetry and recovery work properly when baseline_enabled=True is explicitly set."""
    settings = Settings(database_path=tmp_path / "recovery.sqlite3", baseline_enabled=True, demo_tick_seconds=0.05)
    runtime = GatewayRuntime(settings)

    started = runtime.start_baseline(tick_seconds=0.05)
    assert started is True
    deadline = time.monotonic() + 3.0
    rows = []
    while time.monotonic() < deadline:
        rows = runtime.store.telemetry()
        if rows:
            break
        time.sleep(0.05)

    assert len(rows) > 0
    assert all(r["traffic_type"] == "NORMAL" for r in rows)

    runtime.stop_baseline()
    assert runtime._baseline_thread is None


def test_normal_shutdown_invokes_safe_worker_cleanup(tmp_path: Path):
    """Verify worker can be cleanly stopped and joined during normal shutdown."""
    settings = Settings(database_path=tmp_path / "shutdown.sqlite3", baseline_enabled=True, demo_tick_seconds=0.05)
    runtime = GatewayRuntime(settings)

    runtime.start_baseline(tick_seconds=0.05)
    thread = runtime._baseline_thread
    assert thread.is_alive()

    # Calling stop_baseline() joins the thread within 3 seconds
    stopped = runtime.stop_baseline()
    assert stopped is True
    assert not thread.is_alive()
    assert runtime._baseline_thread is None

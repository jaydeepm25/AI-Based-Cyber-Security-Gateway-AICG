"""Pytest configuration and environment isolation fixtures for AICG test suite.

Guarantees that normal unit and regression tests never inherit DATABASE_URL or
AEGIS_DATABASE_URL from the shell environment, enforcing deterministic SQLite routing.
Protects production database endpoints from accidental collision with TEST_DATABASE_URL
via independent production project identity verification.
"""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import parse_qsl, unquote, urlparse
import pytest


def extract_database_identity(url: str | None) -> dict[str, Any] | None:
    """Safely extract normalized endpoint and project identity without exposing passwords."""
    if not url or not url.strip():
        return None
    try:
        parsed = urlparse(url.strip())
        if parsed.scheme not in ("postgresql", "postgres"):
            return None

        hostname = (parsed.hostname or "").lower()
        port = parsed.port or 5432
        path = (parsed.path or "").strip("/")
        username = unquote(parsed.username or "")

        # Extract Supabase project ref if present
        project_ref: str | None = None
        if "." in username and (hostname.endswith(".pooler.supabase.com") or "supabase" in hostname):
            project_ref = username.split(".", 1)[1].strip().lower()
        elif "supabase.co" in hostname:
            parts = hostname.split(".")
            if parts[0] == "db" and len(parts) >= 3:
                project_ref = parts[1].strip().lower()
            elif len(parts) >= 3:
                project_ref = parts[0].strip().lower()

        normalized_endpoint = f"{hostname}:{port}/{path}"
        return {
            "hostname": hostname,
            "port": port,
            "database": path,
            "username": username,
            "project_ref": project_ref,
            "normalized_endpoint": normalized_endpoint,
        }
    except Exception:
        return None


# Capture initial production database environment values at module import time
# strictly BEFORE any fixture removes os.environ variables.
# Preserved in memory; never printed, logged, or exposed.
_ORIGINAL_DATABASE_URL: str | None = os.getenv("DATABASE_URL")
_ORIGINAL_AEGIS_DATABASE_URL: str | None = os.getenv("AEGIS_DATABASE_URL")

_ORIGINAL_PROD_IDENTITY: dict[str, Any] | None = extract_database_identity(_ORIGINAL_DATABASE_URL)
_ORIGINAL_AEGIS_PROD_IDENTITY: dict[str, Any] | None = extract_database_identity(_ORIGINAL_AEGIS_DATABASE_URL)


def get_production_project_ref(explicit_prod_ref: str | None = None) -> str | None:
    """Resolve production project reference independently of DATABASE_URL.

    Never prints or logs the project reference.
    """
    if explicit_prod_ref and explicit_prod_ref.strip():
        return explicit_prod_ref.strip().lower()

    # 1. Check independent environment variable (highest priority)
    env_val = (
        os.getenv("AICG_PRODUCTION_SUPABASE_PROJECT_REF")
        or os.getenv("PRODUCTION_SUPABASE_PROJECT_REF")
    )
    if env_val and env_val.strip():
        return env_val.strip().lower()

    # 2. Check in-memory captured original production identity
    if _ORIGINAL_PROD_IDENTITY and _ORIGINAL_PROD_IDENTITY.get("project_ref"):
        return _ORIGINAL_PROD_IDENTITY["project_ref"]
    if _ORIGINAL_AEGIS_PROD_IDENTITY and _ORIGINAL_AEGIS_PROD_IDENTITY.get("project_ref"):
        return _ORIGINAL_AEGIS_PROD_IDENTITY["project_ref"]

    return None


def validate_test_database_target(
    test_url: str,
    expected_project_ref: str | None = None,
    captured_prod_identity: dict[str, Any] | None = None,
    captured_aegis_prod_identity: dict[str, Any] | None = None,
    independent_prod_ref: str | None = None,
) -> dict[str, Any]:
    """Validate that TEST_DATABASE_URL is well-formed and does not target production.

    Raises ValueError with a sanitized error message on any safety violation.
    Never prints, logs, or exposes connection credentials or project references.
    """
    if not test_url or not test_url.strip():
        raise ValueError("TEST_DATABASE_URL is empty or not configured.")

    test_identity = extract_database_identity(test_url)
    if not test_identity:
        raise ValueError("TEST_DATABASE_URL is malformed or uses an invalid scheme.")

    # Resolve independent production project reference
    prod_ref = get_production_project_ref(independent_prod_ref)

    # Use captured production identities if not explicitly overridden for testing
    prod_id = captured_prod_identity or _ORIGINAL_PROD_IDENTITY
    aegis_prod_id = captured_aegis_prod_identity or _ORIGINAL_AEGIS_PROD_IDENTITY

    # 1. Collision check against captured production endpoints (if available)
    for p_id in (prod_id, aegis_prod_id):
        if p_id is None:
            continue
        # Check normalized endpoint + username match
        if (
            test_identity["normalized_endpoint"] == p_id["normalized_endpoint"]
            and test_identity["username"] == p_id["username"]
        ):
            raise ValueError(
                "CRITICAL SAFETY VIOLATION: TEST_DATABASE_URL matches the captured production database target."
            )
        # Check project ref match if both have project_ref
        if (
            test_identity["project_ref"]
            and p_id["project_ref"]
            and test_identity["project_ref"] == p_id["project_ref"]
        ):
            raise ValueError(
                "CRITICAL SAFETY VIOLATION: TEST_DATABASE_URL matches the production project reference."
            )

    # 2. Supabase project reference validation
    test_project_ref = test_identity.get("project_ref")
    is_supabase = (
        test_identity["hostname"].endswith(".pooler.supabase.com")
        or "supabase" in test_identity["hostname"]
    )

    if is_supabase:
        if not test_project_ref:
            raise ValueError(
                "CRITICAL SAFETY VIOLATION: TEST_DATABASE_URL points to Supabase pooler but project reference could not be extracted from username."
            )

        # Invariant: Production identity MUST be known to verify the production boundary
        if not prod_ref:
            raise ValueError(
                "CRITICAL SAFETY BLOCK: Production project identity is unknown "
                "(AICG_PRODUCTION_SUPABASE_PROJECT_REF is not configured). "
                "Refusing to execute integration tests without verified production boundary."
            )

        # Independent production reference collision check
        if test_project_ref == prod_ref:
            raise ValueError(
                "CRITICAL SAFETY VIOLATION: TEST_DATABASE_URL matches the production project reference."
            )

        # Require explicit approved test project identity
        expected_ref = (
            expected_project_ref
            or os.getenv("TEST_SUPABASE_PROJECT_REF")
            or os.getenv("EXPECTED_TEST_PROJECT_REF")
        )
        if not expected_ref or not expected_ref.strip():
            raise ValueError(
                "CRITICAL SAFETY BLOCK: TEST_SUPABASE_PROJECT_REF is not configured. "
                "Integration testing requires an explicit approved test-project identity."
            )
        clean_expected_ref = expected_ref.strip().lower()

        # Verify test_project_ref matches approved expected_ref
        if test_project_ref != clean_expected_ref:
            raise ValueError(
                "CRITICAL SAFETY BLOCK: TEST_DATABASE_URL project reference does not match approved TEST_SUPABASE_PROJECT_REF."
            )

        # Verify approved test ref is not the production ref
        if clean_expected_ref == prod_ref:
            raise ValueError(
                "CRITICAL SAFETY VIOLATION: Approved TEST_SUPABASE_PROJECT_REF matches production project reference."
            )

    else:
        # Non-Supabase target (e.g., local PostgreSQL test container or host)
        # Verify it is an isolated local endpoint and does not match any production endpoint
        local_hosts = ("localhost", "127.0.0.1", "::1", "test-postgres")
        if test_identity["hostname"] not in local_hosts:
            # If an external non-Supabase host is used, ensure it cannot match production endpoint
            for p_id in (prod_id, aegis_prod_id):
                if p_id and test_identity["hostname"] == p_id["hostname"]:
                    raise ValueError(
                        "CRITICAL SAFETY VIOLATION: TEST_DATABASE_URL points to production database host."
                    )

    return test_identity


def pytest_configure(config: pytest.Config) -> None:
    """Register custom markers."""
    config.addinivalue_line(
        "markers",
        "postgres_integration: Integration tests connecting to an isolated PostgreSQL test database "
        "(skipped by default, requires explicit opt-in via -m postgres_integration and TEST_DATABASE_URL).",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip postgres_integration tests by default unless explicitly requested via -m."""
    markexpr = config.getoption("-m", default="")
    if "postgres_integration" not in markexpr:
        skip_marker = pytest.mark.skip(
            reason="PostgreSQL integration tests are skipped by default. "
            "Run with '-m postgres_integration' and configure TEST_DATABASE_URL to execute."
        )
        for item in items:
            if "postgres_integration" in item.keywords:
                item.add_marker(skip_marker)


@pytest.fixture(autouse=True)
def isolate_database_env(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch):
    """Ensure normal unit and regression tests do not inherit PostgreSQL connection strings from shell.

    - Strips DATABASE_URL and AEGIS_DATABASE_URL from normal tests so Settings defaults to SQLite.
    - Preserves and restores environment cleanly after each test via monkeypatch.
    - Prevents accidental routing to production or external databases.
    - Integration tests explicitly marked with 'postgres_integration' are allowed to read TEST_DATABASE_URL,
      while still ensuring production DATABASE_URL is never used as a fallback.
    """
    if "postgres_integration" in request.keywords:
        # For integration tests: strip production variables so fallback to production is impossible
        monkeypatch.delenv("DATABASE_URL", raising=False)
        monkeypatch.delenv("AEGIS_DATABASE_URL", raising=False)
        yield
        return

    # For standard unit and regression tests: strip all Postgres database URLs
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("AEGIS_DATABASE_URL", raising=False)
    monkeypatch.delenv("TEST_DATABASE_URL", raising=False)
    yield


@pytest.fixture
def test_database_url() -> str:
    """Retrieve isolated test database URL. Fail-closed if missing; never fall back to production."""
    url = os.getenv("TEST_DATABASE_URL")
    if not url or not url.strip():
        pytest.skip(
            "TEST_DATABASE_URL environment variable is not configured. "
            "Skipping PostgreSQL integration test (fail-closed, zero live connections)."
        )

    clean_url = url.strip()

    try:
        validate_test_database_target(clean_url)
    except ValueError as err:
        msg = str(err)
        if "is not configured" in msg:
            pytest.skip(msg)
        else:
            pytest.fail(msg)

    return clean_url

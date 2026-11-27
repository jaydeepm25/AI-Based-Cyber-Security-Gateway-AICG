"""Flask API and SSE transport for the unified laboratory gateway runtime."""

from __future__ import annotations

from datetime import timedelta
import json
import logging
import os
from pathlib import Path
import threading
import time
from typing import Any

from urllib.parse import unquote, urlsplit

from flask import Flask, Response, jsonify, redirect, render_template, request, session
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename

from .adapters import cooja_csv_events, ns3_csv_events, pcap_events, pcap_window_events
from .config import Settings
from .runtime import GatewayRuntime
from .scenarios import catalogue, generate_window
from .schema import utc_now
from .security import (
    ALL_ROLES,
    PERM_ACK_ALERT,
    PERM_ADMIN_CONTROLS,
    PERM_CLOSE_INCIDENT,
    PERM_MANAGE_INCIDENT,
    PERM_MANAGE_USERS,
    PERM_VIEW_AUDIT,
    PERM_VIEW_DASHBOARD,
    PERM_VIEW_INCIDENTS,
    PERM_VIEW_SECURITY_POSTURE,
    PERM_VIEW_SYSTEM_STATUS,
    ROLE_ADMIN,
    ROLE_OPERATOR,
    ROLE_PERMISSIONS,
    auth_limiter,
    clear_pre_mfa,
    get_current_user,
    get_pre_mfa_user,
    has_permission,
    hash_password,
    login_required,
    permission_required,
    roles_required,
    rotate_session,
    set_pre_mfa_user,
    validate_password_policy,
    verify_password,
    verify_simulated_mfa,
    _log_security_audit,
)

_user_mutation_lock = threading.Lock()


def _number(value: Any, default: int = 3) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def sanitize_redirect_url(target: str | None, default: str = "/") -> str:
    """Validate and sanitize post-login redirect targets to prevent open redirect vulnerabilities (CWE-601).

    Permits strictly relative paths (e.g., '/', '/admin/users', '/dashboard?q=1').
    Rejects:
    - Absolute external URLs (e.g., 'https://evil.com')
    - Scheme-relative URLs (e.g., '//evil.example')
    - Backslash-based browser trickery (e.g., '/\\evil.com', '\\evil.com')
    - Control characters and CRLF injection (\\r, \\n, \\0)
    - URL-encoded traversal/scheme exploits
    Falls back to the safe default ('/').
    """
    if not target or not isinstance(target, str):
        return default

    cleaned = target.strip()
    if not cleaned or any(c in cleaned for c in ("\r", "\n", "\0")):
        return default

    if "\\" in cleaned or cleaned.startswith("//") or cleaned.startswith("/\\"):
        return default

    try:
        parsed = urlsplit(cleaned)
        if parsed.scheme or parsed.netloc:
            return default
        if not parsed.path.startswith("/"):
            return default

        # Validate unquoted form to prevent URL-encoded bypasses (%2f%2f or %5c)
        unquoted = unquote(cleaned)
        if "\\" in unquoted or unquoted.startswith("//") or unquoted.startswith("/\\"):
            return default
        parsed_unquoted = urlsplit(unquoted)
        if parsed_unquoted.scheme or parsed_unquoted.netloc:
            return default
        if not parsed_unquoted.path.startswith("/"):
            return default

        return cleaned
    except Exception:
        return default


logger = logging.getLogger(__name__)


def _trace_error_response(prefix: str, error: Exception) -> tuple[Response, int]:
    """Map path validation errors to generic, non-leaking HTTP 400 responses."""
    err_str = str(error)
    if "outside approved directories" in err_str:
        detail = "outside approved directories"
    elif "unsupported file extension" in err_str.lower():
        detail = "Unsupported file extension"
    elif "must not be empty" in err_str or "empty" in err_str:
        detail = "must not be empty"
    elif "null byte" in err_str:
        detail = "contains invalid null byte"
    elif "regular file" in err_str or "not found" in err_str.lower():
        detail = "not a regular file"
    else:
        detail = "Invalid path"
    return jsonify({"error": f"{prefix}: {detail}"}), 400


def _build_file_registry(
    allowed_roots: list[Path] | tuple[Path, ...],
    default_root: Path | None = None,
    allowed_extensions: tuple[str, ...] | set[str] | list[str] | None = None,
) -> tuple[dict[str, Path], dict[str, str], set[str]]:
    """Build a server-side allowlist registry from explicitly approved directories only.

    Discovers files via server directory enumeration, canonicalizes each discovered file,
    verifies boundary containment within its approved root, and registers the canonical Path.

    Returns:
        (valid_registry, rejected_ext_registry, leaked_symlink_keys)
        valid_registry maps allowed lookup keys to prevalidated, canonical Path objects.
        rejected_ext_registry maps lookup keys to the invalid file extension for known files.
        leaked_symlink_keys contains lookup keys that correspond to escaping symlinks.
    """
    valid_registry: dict[str, Path] = {}
    rejected_ext_registry: dict[str, str] = {}
    leaked_symlink_keys: set[str] = set()

    normalized_exts: set[str] | None = None
    if allowed_extensions is not None:
        normalized_exts = {
            ext.lower() if ext.startswith(".") else f".{ext.lower()}"
            for ext in allowed_extensions
        }

    # Order roots: process non-default roots first, default_root last,
    # so that default_root entries take precedence for bare filename keys.
    ordered_roots: list[Path] = []
    for r in allowed_roots:
        if default_root and r != default_root and r not in ordered_roots:
            ordered_roots.append(r)
    if default_root and default_root not in ordered_roots:
        ordered_roots.append(default_root)
    for r in allowed_roots:
        if r not in ordered_roots:
            ordered_roots.append(r)

    for root_obj in ordered_roots:
        root_real = os.path.realpath(str(root_obj))
        root_with_sep = root_real if root_real.endswith(os.sep) else root_real + os.sep
        if not os.path.isdir(root_real):
            continue

        is_dataset_dir = (
            os.path.basename(root_real) == "dataset"
            or getattr(root_obj, "name", "") == "dataset"
        )

        for current_dir, dirnames, filenames in os.walk(root_real, followlinks=False):
            # Detect escaping directory symlinks
            for d in list(dirnames):
                d_path = os.path.join(current_dir, d)
                if os.path.islink(d_path):
                    d_real = os.path.realpath(d_path)
                    is_d_contained = (d_real == root_real or d_real.startswith(root_with_sep))
                    if is_d_contained:
                        try:
                            is_d_contained = (os.path.commonpath([d_real, root_real]) == root_real)
                        except ValueError:
                            is_d_contained = False
                    if not is_d_contained:
                        rel_d = os.path.relpath(d_path, root_real).replace("\\", "/")
                        leaked_symlink_keys.add(d)
                        leaked_symlink_keys.add(d_path)
                        leaked_symlink_keys.add(rel_d)
                        if is_dataset_dir:
                            leaked_symlink_keys.add(f"dataset/{d}")
                            leaked_symlink_keys.add(f"dataset/{rel_d}")
                        dirnames.remove(d)

            # Check if current_dir itself escapes root
            canonical_current = os.path.realpath(current_dir)
            if not (canonical_current == root_real or canonical_current.startswith(root_with_sep)):
                dirnames.clear()
                continue
            try:
                if os.path.commonpath([canonical_current, root_real]) != root_real:
                    dirnames.clear()
                    continue
            except ValueError:
                dirnames.clear()
                continue

            for entry_name in filenames:
                server_entry = os.path.join(current_dir, entry_name)
                canonical_entry = os.path.realpath(server_entry)

                rel_from_root = os.path.relpath(server_entry, root_real).replace("\\", "/")

                keys = [
                    entry_name,
                    server_entry,
                    canonical_entry,
                    rel_from_root,
                ]
                if is_dataset_dir:
                    keys.append(f"dataset/{entry_name}")
                    if rel_from_root != entry_name:
                        keys.append(f"dataset/{rel_from_root}")

                # Boundary containment check against the approved root
                is_contained = (
                    canonical_entry == root_real
                    or canonical_entry.startswith(root_with_sep)
                )
                if is_contained:
                    try:
                        is_contained = (os.path.commonpath([canonical_entry, root_real]) == root_real)
                    except ValueError:
                        is_contained = False

                if not is_contained:
                    for k in keys:
                        leaked_symlink_keys.add(k)
                    continue

                if not os.path.isfile(canonical_entry):
                    continue

                canonical_path = Path(canonical_entry)
                file_suffix = canonical_path.suffix.lower()

                if canonical_path.name != entry_name:
                    keys.append(canonical_path.name)
                    if is_dataset_dir:
                        keys.append(f"dataset/{canonical_path.name}")

                is_valid_ext = (normalized_exts is None or file_suffix in normalized_exts)

                for k in keys:
                    if is_valid_ext:
                        valid_registry[k] = canonical_path
                    else:
                        rejected_ext_registry[k] = file_suffix

    return valid_registry, rejected_ext_registry, leaked_symlink_keys


def resolve_contained_path(
    candidate_path: str | Path | None,
    allowed_roots: list[Path] | tuple[Path, ...],
    default_root: Path | None = None,
    allowed_extensions: tuple[str, ...] | set[str] | list[str] | None = None,
) -> Path:
    """Resolve a candidate path using a server-side allowlist registry of prevalidated files.

    User-supplied paths are used strictly as lookup keys and NEVER passed to filesystem APIs.
    The returned Path originates exclusively from server-side directory enumeration.
    """
    if candidate_path is None or not isinstance(candidate_path, (str, Path)):
        raise ValueError("Path must be a valid string")

    raw_str = str(candidate_path)
    if "\0" in raw_str:
        raise ValueError("Path contains invalid null byte")

    cleaned = raw_str.strip()
    if not cleaned:
        raise ValueError("Path must not be empty")

    if not allowed_roots:
        raise ValueError("No approved directories specified")

    # Reject traversal sequences upfront via pure string check
    segments = cleaned.replace("\\", "/").split("/")
    if any(seg == ".." for seg in segments):
        raise ValueError("Access denied: path is outside approved directories")

    # Reject nested relative paths upfront via pure string check
    if not os.path.isabs(cleaned):
        norm_parts = [p for p in segments if p and p != "."]
        if not norm_parts:
            raise ValueError("Path must not be empty")

        if len(norm_parts) == 2 and norm_parts[0] == "dataset":
            filename = norm_parts[1]
            if secure_filename(filename) != filename:
                raise ValueError("Access denied: path is outside approved directories")
        elif len(norm_parts) == 1:
            if "/" in cleaned or "\\" in cleaned:
                raise ValueError("Invalid path: path separators not permitted in filename")
            filename = norm_parts[0]
            if secure_filename(filename) != filename:
                raise ValueError("Access denied: path is outside approved directories")
        else:
            raise ValueError("Access denied: path is outside approved directories")

    # Build server-side allowlist strictly from approved roots
    valid_registry, rejected_ext_registry, leaked_symlink_keys = _build_file_registry(
        allowed_roots=allowed_roots,
        default_root=default_root,
        allowed_extensions=allowed_extensions,
    )

    # 1. Exact match in server-validated registry
    if cleaned in valid_registry:
        return valid_registry[cleaned]

    # 2. Match in leaked symlink registry (escaping symlinks)
    if cleaned in leaked_symlink_keys:
        raise ValueError("Access denied: path is outside approved directories")

    # 3. Match in rejected extension registry (known file with unsupported extension)
    if cleaned in rejected_ext_registry:
        bad_suffix = rejected_ext_registry[cleaned]
        normalized_exts = {
            ext.lower() if ext.startswith(".") else f".{ext.lower()}"
            for ext in (allowed_extensions or ())
        }
        raise ValueError(
            f"Unsupported file extension '{bad_suffix}'. Approved extensions: {', '.join(sorted(normalized_exts))}"
        )

    # 4. Determine failure mode without filesystem access
    canonical_roots = [os.path.realpath(str(r)) for r in allowed_roots]
    is_inside_root_intent = False

    if os.path.isabs(cleaned):
        for r_str in canonical_roots:
            r_sep = r_str if r_str.endswith(os.sep) else r_str + os.sep
            if cleaned == r_str or cleaned.startswith(r_sep):
                try:
                    if os.path.commonpath([cleaned, r_str]) == r_str:
                        is_inside_root_intent = True
                        break
                except ValueError:
                    pass
    else:
        # Check if the relative prefix corresponds to an approved root
        if norm_parts[0] == "dataset":
            has_dataset_root = any(
                os.path.basename(r_str) == "dataset" or getattr(r, "name", "") == "dataset"
                for r, r_str in zip(allowed_roots, canonical_roots)
            )
            is_inside_root_intent = has_dataset_root or (default_root is not None)
        elif len(norm_parts) == 1:
            is_inside_root_intent = True

    if is_inside_root_intent:
        raise FileNotFoundError(f"File not found or not a regular file: '{cleaned}'")

    raise ValueError("Access denied: path is outside approved directories")


def _safe_relative_path(path: Path, settings: Settings, prefer_repo: bool = False) -> str:
    """Return relative path string relative to backend root or project root if possible."""
    bases = (settings.project_root, settings.root) if prefer_repo else (settings.root, settings.project_root)
    for base in bases:
        try:
            return str(path.relative_to(base))
        except ValueError:
            continue
    return str(path)


def _format_telemetry_row(event: dict[str, Any], runtime: GatewayRuntime) -> dict[str, Any]:
    dev_id = event.get("device_id") or "SENSOR-01"
    identity_obj = runtime.iam.get(dev_id)
    label = event.get("label") or "NORMAL"
    is_attack = label == "ATTACK"
    raw_conf = float(event.get("confidence") or (0.95 if is_attack else 0.05))
    ddos_prob = round(raw_conf if is_attack else max(0.0, 1.0 - raw_conf), 3)
    normal_prob = round(1.0 - ddos_prob, 3)

    rate = float(event.get("packet_rate") or 0.0)
    byte_rate = float(event.get("byte_rate") or 0.0)
    packet_count = int(event.get("packet_count") or round(rate))
    packet_size = float(event.get("packet_size") or (byte_rate / rate if rate > 0 else 0.0))
    protocol = event.get("protocol") or "UDP"

    evidence = [
        f"Protocol: {protocol}",
        f"Packet rate: {rate:.1f} pps (baseline: 20.0 pps)",
        f"Modelled energy deviation: {round(float(event.get('energy_deviation') or 0.0) * 100, 1)}%",
    ]
    if event.get("energy_cause"):
        evidence.append(str(event.get("energy_cause")))

    action = event.get("response_action") or ("BLOCK" if is_attack else "ALERT")
    severity = event.get("severity") or ("HIGH" if is_attack else "INFO")

    row = dict(event)
    row.pop("auth_token", None)
    row.update({
        "window_start": event.get("timestamp"),
        "packet_count": packet_count,
        "packets_per_second": rate,
        "bytes_per_second": byte_rate,
        "average_packet_size": packet_size,
        "prediction": label,
        "ddos_probability": ddos_prob,
        "normal_probability": normal_prob,
        "security_action": action,
        "mitigation_action": action,
        "severity": severity,
        "mitigation_reason": "Automated simulated policy response" if is_attack else "Normal operating baseline",
        "identity_context": {
            "observed_source_count": event.get("unique_sources") or 1,
            "known_device_count": 1 if identity_obj.authenticated else 0,
            "unknown_device_count": 0 if identity_obj.authenticated else 1,
            "device_contexts": [{
                "device_id": dev_id,
                "ip_address": event.get("src_ip") or ("10.42.0.250" if is_attack else "10.42.0.11"),
                "device_role": identity_obj.role.upper(),
                "identity_status": "KNOWN" if identity_obj.authenticated else "UNKNOWN",
                "authentication_status": event.get("authentication_status") or ("AUTHENTICATED" if identity_obj.authenticated else "FAILED_OR_UNVERIFIED"),
                "authorization_decision": event.get("access_decision") or ("ALLOW" if identity_obj.trust_score >= 40 else "DENIED"),
                "identity_source": "GATEWAY_IAM_REGISTRY",
                "environment": "CONTROLLED_LAB",
                "suspicious": is_attack
            }]
        },
        "lifecycle_context": {
            "available": True,
            "lifecycle_state": event.get("lifecycle_state") or ("CONTAINED" if is_attack else "NORMAL"),
            "window_observation_state": event.get("lifecycle_state") or ("DETECTED" if is_attack else "OBSERVED"),
            "lifecycle_stage": "RESPONSE_SIMULATED" if is_attack else "BASELINE_OBSERVATION",
            "implementation_status": "SIMULATED / DRY-RUN",
            "enforcement_status": "HOST FIREWALL UNTOUCHED",
            "recovery_status": "MONITORING" if not is_attack else "CONTAINED_IN_SOFTWARE",
            "window_start": event.get("timestamp")
        },
        "explainability_context": {
            "evidence_status": "OBSERVED",
            "prediction": label,
            "ddos_probability": ddos_prob,
            "normal_probability": normal_prob,
            "packet_count": packet_count,
            "packets_per_second": rate,
            "bytes_per_second": byte_rate,
            "average_packet_size": packet_size,
            "unique_sources": event.get("unique_sources") or 1,
            "unique_destinations": event.get("unique_destinations") or 1,
            "udp_count": packet_count if protocol == "UDP" else 0,
            "tcp_count": packet_count if protocol == "TCP" else 0,
            "icmp_count": packet_count if protocol in ("ICMP", "ICMPV6") else 0,
            "flow_count": event.get("unique_sources") or 1,
            "security_action": action,
            "severity": severity,
            "mitigation_action": action,
            "mitigation_reason": "Automated simulated policy response" if is_attack else "Normal operating baseline",
            "observed_evidence": evidence
        }
    })
    return row


def _format_energy_row(event: dict[str, Any]) -> dict[str, Any]:
    rate = float(event.get("packet_rate") or 0.0)
    baseline = float(event.get("energy_baseline") or 55.0)
    e_rate = float(event.get("energy_rate") or baseline)
    dev = float(event.get("energy_deviation") if event.get("energy_deviation") is not None else ((e_rate - baseline) / baseline))
    consumed = float(event.get("energy_consumed") or e_rate)
    return {
        "window_start": event.get("timestamp"),
        "energy_estimate": round(consumed, 2),
        "energy_rate": round(e_rate, 2),
        "energy_per_packet": round(consumed / rate, 4) if rate > 0 else 0.0,
        "baseline_energy": round(baseline, 2),
        "energy_deviation": round(dev, 4),
        "energy_increase_percent": round(dev * 100.0, 2),
        "tx_activity": float(event.get("radio_tx") or 4.0),
        "rx_activity": float(event.get("radio_rx") or 5.0),
        "cpu_activity": float(event.get("cpu_activity") or 6.0),
        "energy_cause": event.get("energy_cause") or f"MODELLED: baseline rhythm ({e_rate:.1f} mW)",
        "measurement_status": "MODELLED",
        "environment": "CONTROLLED_SIMULATION",
        "hardware_measured": False,
        "provenance": event.get("provenance") or "MODELLED"
    }


def apply_proxy_fix(flask_app: Flask) -> Flask:
    """Wrap Flask WSGI application with Werkzeug ProxyFix middleware exactly once."""
    if not isinstance(flask_app.wsgi_app, ProxyFix):
        flask_app.wsgi_app = ProxyFix(
            flask_app.wsgi_app,
            x_for=1,
            x_proto=1,
            x_host=0,
            x_port=0,
        )
    return flask_app


def create_app(runtime: GatewayRuntime) -> Flask:
    backend_dir = Path(__file__).resolve().parent.parent
    project_root = backend_dir.parent

    frontend_dir = project_root / "frontend"
    if not frontend_dir.exists():
        frontend_dir = project_root / "dashboard"

    template_folder = str(frontend_dir / "templates")
    static_folder = str(frontend_dir / "static")

    app = Flask(
        __name__,
        template_folder=template_folder,
        static_folder=static_folder,
        static_url_path="/static"
    )
    app.config["runtime"] = runtime
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.jinja_env.auto_reload = True
    app.secret_key = runtime.settings.secret_key
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = runtime.settings.session_cookie_secure
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=4)
    auth_limiter.max_attempts = runtime.settings.auth_rate_limit_max
    auth_limiter.window_seconds = runtime.settings.auth_rate_limit_window_seconds

    @app.get("/login")
    def login_page():
        user = get_current_user()
        if user and not user.get("must_change_password"):
            return redirect(sanitize_redirect_url(request.args.get("next")))
        return render_template("login.html")

    @app.route("/login", methods=["POST"])
    @app.route("/api/auth/login", methods=["POST"])
    def login():
        data = request.get_json(silent=True) if request.is_json else request.form.to_dict()
        if not data:
            data = request.get_json(silent=True, force=True) or {}

        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        mfa_code = data.get("mfa_code")

        if auth_limiter.is_rate_limited(request.remote_addr, username):
            return jsonify({
                "error": "Too many failed authentication attempts. Please wait before retrying.",
                "code": "RATE_LIMITED",
            }), 429

        if not username or not password:
            auth_limiter.record_failure(request.remote_addr, username)
            return jsonify({"error": "Invalid administrative credentials", "code": "AUTH_FAILED"}), 401

        user = runtime.store.get_admin_user(username)
        if not user:
            # Constant-time dummy verification
            verify_password("dummy_password", "scrypt:32768:8:1$dummy$dummypasswordhashforconstanttimecheck123456")
            auth_limiter.record_failure(request.remote_addr, username)
            runtime.store.record_audit(
                username=username,
                role="UNKNOWN",
                action="LOGIN_FAILURE",
                resource="session",
                resource_id=None,
                result="FAILURE",
                details="Failed login attempt: invalid administrative credentials",
                source_ip=request.remote_addr,
            )
            return jsonify({"error": "Invalid administrative credentials", "code": "AUTH_FAILED"}), 401

        if not verify_password(password, user["password_hash"]):
            auth_limiter.record_failure(request.remote_addr, username)
            runtime.store.record_audit(
                username=user["username"],
                role=user["role"],
                action=f"{user['role']}_LOGIN_FAILURE",
                resource="session",
                resource_id=None,
                result="FAILURE",
                details="Failed login attempt: invalid administrative credentials",
                source_ip=request.remote_addr,
            )
            return jsonify({"error": "Invalid administrative credentials", "code": "AUTH_FAILED"}), 401

        if user.get("status") == "DISABLED":
            auth_limiter.record_failure(request.remote_addr, username)
            runtime.store.record_audit(
                username=user["username"],
                role=user["role"],
                action=f"{user['role']}_LOGIN_DENIED",
                resource="session",
                resource_id=None,
                result="DENIED",
                details="Login rejected: administrative account is disabled",
                source_ip=request.remote_addr,
            )
            return jsonify({"error": "Administrative account is disabled", "code": "ACCOUNT_DISABLED"}), 403

        # Simulated MFA verification step
        if user.get("mfa_enabled", 1):
            if not mfa_code:
                # Stage 1: Store pre-MFA state, do NOT authenticate yet
                set_pre_mfa_user(user)
                return jsonify({
                    "mfa_required": True,
                    "username": user["username"],
                    "role": user["role"],
                    "token_hint": "123456",
                    "message": "Primary credentials verified. Enter simulated MFA verification code (123456)."
                }), 200

            set_pre_mfa_user(user)
            if not verify_simulated_mfa(str(mfa_code)):
                auth_limiter.record_failure(request.remote_addr, username)
                clear_pre_mfa()
                runtime.store.record_audit(
                    username=user["username"],
                    role=user["role"],
                    action="MFA_VERIFY_FAILURE",
                    resource="session",
                    resource_id=None,
                    result="FAILURE",
                    details="Simulated MFA verification failed: invalid token",
                    source_ip=request.remote_addr,
                )
                return jsonify({"error": "Invalid simulated MFA verification token", "code": "MFA_INVALID"}), 401

        # Stage 2: Successful primary & MFA authentication -> rotate session
        auth_limiter.reset(request.remote_addr, username)
        clear_pre_mfa()
        rotate_session()
        session.permanent = True
        must_change = bool(user.get("must_change_password", False))
        user_session = {
            "user_id": user["user_id"],
            "username": user["username"],
            "role": user["role"],
            "authenticated": True,
            "mfa_verified": True,
            "mfa_status": "SIMULATED_VERIFIED",
            "login_time": utc_now(),
            "must_change_password": must_change,
        }
        session["user"] = user_session
        runtime.store.record_admin_login(user["username"])
        runtime.store.record_audit(
            username=user["username"],
            role=user["role"],
            action=f"{user['role']}_LOGIN_SUCCESS",
            resource="session",
            resource_id=None,
            result="SUCCESS",
            details="Authenticated gateway administrative session via simulated MFA",
            source_ip=request.remote_addr,
        )

        perms = [] if must_change else sorted(list(ROLE_PERMISSIONS.get(user["role"], set())))
        target_next = "/change-password" if must_change else sanitize_redirect_url(request.args.get("next") or (data.get("next") if isinstance(data, dict) else None))
        if request.is_json or request.path.startswith("/api/"):
            return jsonify({
                "ok": True,
                "authenticated": True,
                "must_change_password": must_change,
                "user": user_session,
                "permissions": perms,
                "redirect": target_next
            })
        return redirect(target_next)

    @app.post("/api/auth/mfa/verify")
    def verify_mfa_endpoint():
        data = request.get_json(silent=True) or request.form.to_dict() or {}
        username = str(data.get("username", "")).strip()
        mfa_code = str(data.get("mfa_code") or data.get("code") or "")

        # Enforce Stage 1 pre-MFA requirement: must have passed primary password verification
        pre_user = get_pre_mfa_user()
        if not pre_user:
            auth_limiter.record_failure(request.remote_addr, username or "unknown")
            return jsonify({
                "error": "MFA verification requires prior primary authentication",
                "code": "PRE_AUTH_REQUIRED",
            }), 401

        username = username or pre_user.get("username", "")
        if not mfa_code:
            return jsonify({"error": "mfa_code is required", "code": "MFA_REQUIRED"}), 400

        if auth_limiter.is_rate_limited(request.remote_addr, username):
            return jsonify({
                "error": "Too many failed authentication attempts. Please wait before retrying.",
                "code": "RATE_LIMITED",
            }), 429

        if pre_user.get("username") != username:
            auth_limiter.record_failure(request.remote_addr, username)
            return jsonify({
                "error": "MFA verification requires prior primary authentication",
                "code": "PRE_AUTH_REQUIRED",
            }), 401

        user = runtime.store.get_admin_user(username)
        if not user:
            auth_limiter.record_failure(request.remote_addr, username)
            return jsonify({"error": "Invalid user", "code": "USER_NOT_FOUND"}), 404

        if not verify_simulated_mfa(mfa_code):
            auth_limiter.record_failure(request.remote_addr, username)
            runtime.store.record_audit(
                username=user["username"],
                role=user["role"],
                action="MFA_VERIFY_FAILURE",
                resource="session",
                resource_id=None,
                result="FAILURE",
                details="Simulated MFA verification failed: invalid token",
                source_ip=request.remote_addr,
            )
            return jsonify({"error": "Invalid simulated MFA verification token", "code": "MFA_INVALID"}), 401

        # Clear pre-MFA and rotate session
        auth_limiter.reset(request.remote_addr, username)
        clear_pre_mfa()
        rotate_session()
        session.permanent = True
        must_change = bool(user.get("must_change_password", False))
        user_session = {
            "user_id": user["user_id"],
            "username": user["username"],
            "role": user["role"],
            "authenticated": True,
            "mfa_verified": True,
            "mfa_status": "SIMULATED_VERIFIED",
            "login_time": utc_now(),
            "must_change_password": must_change,
        }
        session["user"] = user_session
        runtime.store.record_admin_login(user["username"])
        runtime.store.record_audit(
            username=user["username"],
            role=user["role"],
            action=f"{user['role']}_LOGIN_SUCCESS",
            resource="session",
            resource_id=None,
            result="SUCCESS",
            details="Authenticated gateway administrative session via simulated MFA",
            source_ip=request.remote_addr,
        )
        perms = [] if must_change else sorted(list(ROLE_PERMISSIONS.get(user["role"], set())))
        target_next = "/change-password" if must_change else sanitize_redirect_url(data.get("next") or request.args.get("next") or "/")
        return jsonify({
            "ok": True,
            "authenticated": True,
            "must_change_password": must_change,
            "user": user_session,
            "permissions": perms,
            "redirect": target_next
        })

    @app.get("/api/auth/status")
    def auth_status():
        user = get_current_user()
        if not user:
            return jsonify({
                "authenticated": False,
                "user": None,
                "permissions": [],
                "environment": "CONTROLLED_LAB",
                "scope": "LOCAL LAB IDENTITY / SIMULATED MFA / DRY_RUN"
            })
        must_change = bool(user.get("must_change_password", False))
        perms = [] if must_change else sorted(list(ROLE_PERMISSIONS.get(user.get("role", ""), set())))
        return jsonify({
            "authenticated": True,
            "user": user,
            "role": user.get("role", ""),
            "must_change_password": must_change,
            "permissions": perms,
            "environment": "CONTROLLED_LAB",
            "scope": "LOCAL LAB IDENTITY / SIMULATED MFA / DRY_RUN"
        })

    @app.post("/api/auth/change-password")
    @login_required
    def change_password_endpoint():
        curr_user = get_current_user()
        if not curr_user:
            return jsonify({"error": "Authentication required", "code": "AUTH_REQUIRED"}), 401

        data = request.get_json(silent=True) or request.form.to_dict() or {}
        current_password = str(data.get("current_password", ""))
        new_password = str(data.get("new_password", ""))

        if not current_password or not new_password:
            return jsonify({"error": "Current password and new password are required", "code": "MISSING_FIELDS"}), 400

        user_id = curr_user.get("user_id")
        user = runtime.store.get_admin_user_by_id(user_id) if user_id else None
        if not user:
            user = runtime.store.get_admin_user(curr_user.get("username", ""))
        if not user:
            return jsonify({"error": "User record not found", "code": "USER_NOT_FOUND"}), 404

        if not verify_password(current_password, user["password_hash"]):
            runtime.store.record_audit(
                username=user["username"],
                role=user["role"],
                action="PASSWORD_CHANGE_FAILURE",
                resource="user",
                resource_id=user["user_id"],
                result="FAILURE",
                details=f"Failed password change attempt for user '{user['username']}': invalid current password",
                source_ip=request.remote_addr,
            )
            return jsonify({"error": "Current password is incorrect", "code": "INVALID_CURRENT_PASSWORD"}), 400

        is_valid, err_msg = validate_password_policy(new_password)
        if not is_valid:
            return jsonify({"error": err_msg, "code": "PASSWORD_POLICY_VIOLATION"}), 400

        if current_password == new_password:
            return jsonify({
                "error": "New password cannot be the same as current password",
                "code": "PASSWORD_REUSED"
            }), 400

        new_hash = hash_password(new_password)
        runtime.store.update_admin_user_password(user["user_id"], new_hash, must_change_password=False)

        runtime.store.record_audit(
            username=user["username"],
            role=user["role"],
            action="USER_PASSWORD_CHANGED",
            resource="user",
            resource_id=user["user_id"],
            result="SUCCESS",
            details=f"User '{user['username']}' successfully changed their password",
            source_ip=request.remote_addr,
        )

        rotate_session()
        session.permanent = True
        user_session = {
            "user_id": user["user_id"],
            "username": user["username"],
            "role": user["role"],
            "authenticated": True,
            "mfa_verified": True,
            "mfa_status": "SIMULATED_VERIFIED",
            "login_time": utc_now(),
            "must_change_password": False,
        }
        session["user"] = user_session

        return jsonify({
            "ok": True,
            "message": "Password changed successfully",
            "authenticated": True,
            "must_change_password": False,
            "user": user_session,
            "permissions": sorted(list(ROLE_PERMISSIONS.get(user["role"], set()))),
            "redirect": "/"
        }), 200

    @app.route("/logout", methods=["POST"])
    @app.route("/api/auth/logout", methods=["POST"])
    def logout():
        user = session.pop("user", None)
        clear_pre_mfa()
        rotate_session()
        if user:
            runtime.store.record_audit(
                username=user.get("username", "unknown"),
                role=user.get("role", "UNKNOWN"),
                action="LOGOUT",
                resource="session",
                resource_id=None,
                result="SUCCESS",
                details="User ended administrative session",
                source_ip=request.remote_addr,
            )
        if request.is_json or request.path.startswith("/api/"):
            return jsonify({"ok": True, "message": "Session terminated", "authenticated": False})
        return redirect("/login")


    # =========================================================================
    # ADMINISTRATIVE CONSOLE & ALERT CENTER ENDPOINTS
    # =========================================================================

    @app.get("/api/admin/overview")
    @login_required
    def admin_overview():
        user = get_current_user()
        alerts = runtime.store.list_alerts(limit=500)
        incidents = runtime.store.incidents(limit=100)
        audits = runtime.store.list_audit_logs(limit=8)

        active_alerts = [a for a in alerts if a.get("status") == "ACTIVE"]
        unack_alerts = [a for a in alerts if a.get("acknowledgement_state") == "UNACKNOWLEDGED"]
        open_incidents = [i for i in incidents if i.get("lifecycle_state") not in ("RESOLVED", "CLOSED")]
        crit_incidents = [i for i in incidents if i.get("severity") == "CRITICAL" and i.get("lifecycle_state") not in ("RESOLVED", "CLOSED")]

        return jsonify({
            "user": user,
            "kpis": {
                "total_alerts": len(alerts),
                "active_alerts": len(active_alerts),
                "unacknowledged_alerts": len(unack_alerts),
                "open_incidents": len(open_incidents),
                "critical_incidents": len(crit_incidents),
                "registered_users": len(runtime.store.list_admin_users()),
            },
            "recent_audits": audits,
            "gateway_mode": runtime.response.mode,
            "host_enforcement": False,
            "dry_run": True,
            "labels": {
                "identity": "LOCAL LAB IDENTITY",
                "mfa": "SIMULATED MFA",
                "mode": "DRY_RUN",
                "enforcement": "NON-ENFORCING",
                "environment": "CONTROLLED LAB SIMULATION"
            },
            "zero_trust_posture": {
                "identity_registry": "LOCAL LAB IDENTITY REGISTRY",
                "mfa": "SIMULATED MFA (VERIFIED)",
                "rbac": "SERVER-SIDE ENFORCED",
                "trust_model": "DYNAMIC OT TRUST REPUTATION (0..100)",
                "access_mode": "POLICY ENGINE DRY_RUN",
                "enforcement": "NON-ENFORCING / LAB ENVIRONMENT"
            }
        })

    @app.get("/api/admin/alerts")
    @login_required
    def list_admin_alerts():
        status = request.args.get("status")
        ack_state = request.args.get("ack_state")
        severity = request.args.get("severity")
        limit = _number(request.args.get("limit"), 100)
        items = runtime.store.list_alerts(limit=limit, status=status, ack_state=ack_state, severity=severity)
        return jsonify({"alerts": items, "count": len(items)})

    @app.get("/api/admin/alerts/<alert_id>")
    @login_required
    def get_admin_alert(alert_id: str):
        item = runtime.store.get_alert(alert_id)
        return (jsonify(item), 200) if item else (jsonify({"error": "Alert not found"}), 404)

    @app.post("/api/admin/alerts/<alert_id>/acknowledge")
    @login_required
    @permission_required(PERM_ACK_ALERT)
    def acknowledge_admin_alert(alert_id: str):
        user = get_current_user() or {"username": "operator", "role": "OPERATOR"}
        try:
            updated = runtime.store.acknowledge_alert(alert_id, user["username"])
            runtime.store.record_audit(
                username=user["username"],
                role=user["role"],
                action="ALERT_ACKNOWLEDGED",
                resource="alert",
                resource_id=alert_id,
                result="SUCCESS",
                details=f"Alert {alert_id} acknowledged by {user['username']}",
                source_ip=request.remote_addr,
            )
            runtime.publish("alert", updated)
            return jsonify(updated)
        except KeyError:
            return jsonify({"error": f"Unknown alert: {alert_id}"}), 404

    @app.get("/api/admin/users")
    @login_required
    @roles_required(ROLE_ADMIN)
    def get_admin_users():
        users = runtime.store.list_admin_users()
        return jsonify({"users": users, "count": len(users)})

    @app.post("/api/admin/users")
    @login_required
    @roles_required(ROLE_ADMIN)
    def create_admin_user_endpoint():
        curr_user = get_current_user() or {"username": "admin", "role": "ADMIN"}
        body = request.get_json(silent=True) or {}
        username = str(body.get("username", "")).strip()
        password = str(body.get("password", ""))
        role = str(body.get("role", "OPERATOR")).upper()
        must_change = bool(body.get("must_change_password", False))
        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400
        if role not in ALL_ROLES:
            return jsonify({"error": f"Role must be one of {ALL_ROLES}"}), 400
        valid_pw, pw_err = validate_password_policy(password)
        if not valid_pw:
            return jsonify({"error": pw_err}), 400
        if runtime.store.get_admin_user(username):
            return jsonify({"error": "Username already exists"}), 409
        try:
            created = runtime.store.create_admin_user(
                username=username,
                password_hash=hash_password(password),
                role=role,
                must_change_password=must_change,
            )
        except ValueError as err:
            return jsonify({"error": str(err)}), 409
        runtime.store.record_audit(
            username=curr_user["username"],
            role=curr_user["role"],
            action="USER_CREATED",
            resource="user",
            resource_id=created["user_id"],
            result="SUCCESS",
            details=f"Created local lab user '{username}' with role '{role}'",
            source_ip=request.remote_addr,
        )
        return jsonify(created), 201

    @app.patch("/api/admin/users/<user_id>")
    @login_required
    @roles_required(ROLE_ADMIN)
    def update_admin_user_endpoint(user_id: str):
        curr_user = get_current_user() or {"username": "admin", "role": "ADMIN"}
        body = request.get_json(silent=True) or {}

        target_user = runtime.store.get_admin_user_by_id(user_id)
        if not target_user:
            return jsonify({"error": f"User not found: {user_id}", "code": "USER_NOT_FOUND"}), 404

        status = body.get("status")
        role = body.get("role")
        username = body.get("username")
        password = body.get("password")
        must_change = body.get("must_change_password")

        try:
            if status is not None:
                new_status = str(status).strip().upper()
                if new_status not in {"ACTIVE", "DISABLED"}:
                    return jsonify({"error": f"Invalid status: {status}. Must be ACTIVE or DISABLED"}), 400
                if target_user["role"] == "ADMIN" and new_status == "DISABLED":
                    all_users = runtime.store.list_admin_users()
                    active_admins = [u for u in all_users if u["role"] == "ADMIN" and u["status"] == "ACTIVE" and u["user_id"] != user_id]
                    if not active_admins:
                        return jsonify({
                            "error": "Cannot disable the last active administrator account",
                            "code": "LAST_ADMIN_PROTECTED",
                        }), 400
                runtime.store.update_admin_user_status(user_id, new_status)
                runtime.store.record_audit(
                    username=curr_user["username"],
                    role=curr_user["role"],
                    action="USER_STATUS_CHANGED",
                    resource="user",
                    resource_id=user_id,
                    result="SUCCESS",
                    details=f"User '{target_user['username']}' ({user_id}) status changed to {new_status}",
                    source_ip=request.remote_addr,
                )

            if role is not None:
                new_role = str(role).strip().upper()
                if new_role not in ALL_ROLES:
                    return jsonify({"error": f"Role must be one of {ALL_ROLES}"}), 400
                if target_user["role"] == "ADMIN" and new_role != "ADMIN":
                    all_users = runtime.store.list_admin_users()
                    active_admins = [u for u in all_users if u["role"] == "ADMIN" and u["status"] == "ACTIVE" and u["user_id"] != user_id]
                    if not active_admins:
                        return jsonify({
                            "error": "Cannot demote the last active administrator account",
                            "code": "LAST_ADMIN_PROTECTED",
                        }), 400
                runtime.store.update_admin_user_role(user_id, new_role)
                runtime.store.record_audit(
                    username=curr_user["username"],
                    role=curr_user["role"],
                    action="USER_ROLE_CHANGED",
                    resource="user",
                    resource_id=user_id,
                    result="SUCCESS",
                    details=f"User '{target_user['username']}' ({user_id}) role changed to {new_role}",
                    source_ip=request.remote_addr,
                )
                if curr_user.get("user_id") == user_id:
                    session["user"]["role"] = new_role

            if username is not None:
                new_username = str(username).strip()
                if not new_username:
                    return jsonify({"error": "Username cannot be empty"}), 400
                old_username = target_user["username"]
                if new_username != old_username:
                    try:
                        runtime.store.update_admin_user_username(user_id, new_username)
                    except ValueError as err:
                        return jsonify({"error": str(err), "code": "USERNAME_CONFLICT"}), 409
                    runtime.store.record_audit(
                        username=curr_user["username"],
                        role=curr_user["role"],
                        action="USER_USERNAME_CHANGED",
                        resource="user",
                        resource_id=user_id,
                        result="SUCCESS",
                        details=f"User {user_id} username changed from '{old_username}' to '{new_username}' by {curr_user['username']}",
                        source_ip=request.remote_addr,
                    )
                    if curr_user.get("user_id") == user_id:
                        session["user"]["username"] = new_username

            if password is not None:
                pw_str = str(password)
                valid, err = validate_password_policy(pw_str)
                if not valid:
                    return jsonify({"error": err}), 400
                hashed = hash_password(pw_str)
                runtime.store.update_admin_user_password(user_id, hashed, must_change_password=True)
                runtime.store.record_audit(
                    username=curr_user["username"],
                    role=curr_user["role"],
                    action="USER_PASSWORD_RESET",
                    resource="user",
                    resource_id=user_id,
                    result="SUCCESS",
                    details=f"Administrator '{curr_user['username']}' reset password for user '{target_user['username']}' ({user_id}) with mandatory change required",
                    source_ip=request.remote_addr,
                )
                if curr_user.get("user_id") == user_id:
                    session["user"]["must_change_password"] = True
            elif must_change is not None:
                val = bool(must_change)
                target = runtime.store.get_admin_user_by_id(user_id)
                if target:
                    runtime.store.update_admin_user_password(user_id, target["password_hash"], must_change_password=val)
                    if curr_user.get("user_id") == user_id:
                        session["user"]["must_change_password"] = val

            updated = runtime.store.get_admin_user_by_id(user_id)
            if updated:
                updated.pop("password_hash", None)
            return jsonify(updated)
        except (KeyError, ValueError) as error:
            return jsonify({"error": str(error)}), 400

    @app.delete("/api/admin/users/<user_id>")
    @login_required
    @roles_required(ROLE_ADMIN)
    def delete_admin_user_endpoint(user_id: str):
        curr_user = get_current_user() or {"username": "admin", "role": "ADMIN"}

        # Prevent self-deletion
        if curr_user.get("user_id") == user_id:
            return jsonify({
                "error": "Administrators cannot delete their own active account",
                "code": "SELF_DELETION_DENIED"
            }), 400

        with _user_mutation_lock:
            target_user = runtime.store.get_admin_user_by_id(user_id)
            if not target_user:
                return jsonify({"error": f"User not found: {user_id}", "code": "USER_NOT_FOUND"}), 404

            if curr_user.get("username") == target_user["username"]:
                return jsonify({
                    "error": "Administrators cannot delete their own active account",
                    "code": "SELF_DELETION_DENIED"
                }), 400

            # Guard against deleting the last active ADMIN account
            if target_user["role"] == "ADMIN":
                all_users = runtime.store.list_admin_users()
                active_admins = [
                    u for u in all_users
                    if u["role"] == "ADMIN" and u["status"] == "ACTIVE" and u["user_id"] != user_id
                ]
                if not active_admins:
                    return jsonify({
                        "error": "Cannot delete the last remaining active administrator account",
                        "code": "LAST_ADMIN_PROTECTED",
                    }), 400

            try:
                success = runtime.store.delete_admin_user(user_id)
            except ValueError as err:
                if "last" in str(err).lower():
                    return jsonify({
                        "error": str(err),
                        "code": "LAST_ADMIN_PROTECTED",
                    }), 400
                return jsonify({"error": str(err)}), 400
            if not success:
                return jsonify({"error": f"Failed to delete user: {user_id}", "code": "DELETE_FAILED"}), 500

            runtime.store.record_audit(
                username=curr_user["username"],
                role=curr_user["role"],
                action="USER_DELETED",
                resource="user",
                resource_id=user_id,
                result="SUCCESS",
                details=f"User '{target_user['username']}' ({user_id}) deleted by administrator '{curr_user['username']}'",
                source_ip=request.remote_addr,
            )

        refreshed_users = runtime.store.list_admin_users()
        return jsonify({
            "ok": True,
            "message": f"User '{target_user['username']}' deleted successfully",
            "deleted_user_id": user_id,
            "users": refreshed_users,
            "count": len(refreshed_users)
        }), 200

    @app.get("/api/admin/audit")
    @login_required
    @roles_required(ROLE_ADMIN)
    def get_admin_audit():
        action = request.args.get("action")
        username = request.args.get("username")
        limit = _number(request.args.get("limit"), 100)
        items = runtime.store.list_audit_logs(limit=limit, action=action, username=username)
        return jsonify({"audit_events": items, "count": len(items)})

    @app.get("/api/admin/audit/integrity")
    @login_required
    @roles_required(ROLE_ADMIN)
    def get_admin_audit_integrity():
        integrity = runtime.store.verify_audit_log_integrity()
        return jsonify(integrity)

    @app.get("/api/admin/security/posture")
    @login_required
    def get_security_posture():
        user = get_current_user()
        return jsonify({
            "identity": {
                "user": user.get("username") if user else "ANONYMOUS",
                "role": user.get("role") if user else "NONE",
                "status": "VERIFIED" if user else "UNAUTHENTICATED",
                "type": "LOCAL LAB IDENTITY REGISTRY"
            },
            "authentication": {
                "status": "AUTHENTICATED" if user else "UNAUTHENTICATED",
                "scheme": "PASSWORD_HASH_PBKDF2_SCRYPT"
            },
            "mfa": {
                "status": user.get("mfa_status", "NOT_VERIFIED") if user else "NOT_VERIFIED",
                "scheme": "SIMULATED_MFA_TOKEN",
                "label": "SIMULATED MFA"
            },
            "authorization": {
                "scheme": "RBAC",
                "enforced": True,
                "role": user.get("role") if user else "NONE",
                "permissions": sorted(list(ROLE_PERMISSIONS.get(user.get("role", ""), set()))) if user else []
            },
            "trust": {
                "score": 100.0 if (user and user.get("role") == ROLE_ADMIN) else (90.0 if user else 0.0),
                "posture": "TRUSTED_ADMIN_SESSION" if (user and user.get("role") == ROLE_ADMIN) else ("OPERATIONAL_SESSION" if user else "UNTRUSTED"),
                "model": "BOUNDED_ZERO_TRUST_0_TO_100"
            },
            "access_decision": {
                "decision": "ALLOW" if user else "DENY",
                "mode": runtime.response.mode,
                "host_enforcement": False,
                "network_transmission": False,
                "safety": "DRY_RUN NON-ENFORCING LAB ENVIRONMENT"
            }
        })

    @app.get("/")
    @login_required
    def dashboard():
        return render_template("index.html")

    @app.get("/attacker")
    @login_required
    def attacker():
        return render_template("attacker.html")

    @app.get("/api/health")
    def health():
        return jsonify({
            "ok": True,
            "status": "ONLINE",
            "service": "AEGIS-OT laboratory gateway",
            "response_mode": runtime.response.mode,
            "auto_response": runtime.response.auto,
            "host_enforcement": False,
            "safety": "All simulator response actions are non-enforcing.",
        })

    @app.get("/api/status")
    @login_required
    def status():
        base_status = runtime.status()
        latest = base_status.get("latest") or {}
        pred = latest.get("label") or "NORMAL"
        is_attack = pred == "ATTACK"
        ddos_p = float(latest.get("confidence") or (0.95 if is_attack else 0.05)) if is_attack else round(1.0 - float(latest.get("confidence") or 0.95), 3)

        dev_id = latest.get("device_id") or "SENSOR-01"
        trust_val = runtime.iam.get(dev_id).trust_score

        active_inc = runtime.store.find_active_incident()
        if not active_inc:
            recent_incidents = runtime.store.incidents(limit=1)
            if recent_incidents and recent_incidents[0].get("lifecycle_state") == "RESOLVED":
                active_inc = recent_incidents[0]

        active_inc_summary = {
            "incident_id": active_inc["incident_id"],
            "lifecycle_state": active_inc["lifecycle_state"],
            "severity": active_inc.get("severity"),
            "attack_type": active_inc.get("attack_type"),
            "recovery_state": active_inc.get("recovery_state"),
        } if active_inc else None
        canonical_state = active_inc["lifecycle_state"] if active_inc else "OBSERVED"

        is_threat_active = is_attack or (active_inc and active_inc.get("lifecycle_state") not in {"RESOLVED", "CLOSED"})
        mit_action = (latest.get("response_action") or "NONE") if is_threat_active else "NONE"
        sec_action = latest.get("response_action") or ("BLOCK" if is_attack else "ALERT")
        if not is_threat_active and sec_action == "ALERT":
            sec_action = "MONITOR"

        base_status["summary"] = {
            "latest_prediction": pred,
            "latest_packet_rate": float(latest.get("packet_rate") or 18.0),
            "latest_bytes_per_second": float(latest.get("byte_rate") or 4140.0),
            "latest_ddos_probability": ddos_p,
            "latest_security_action": sec_action,
            "latest_mitigation_action": mit_action,
            "trust_score": float(trust_val),
            "active_incident": active_inc_summary,
            "lifecycle_state": canonical_state,
        }
        base_status["active_incident"] = active_inc_summary
        base_status["lifecycle_state"] = canonical_state
        base_status["pipeline"] = {
            "traffic_features": True,
            "ml_predictions": True,
            "security_decisions": True,
            "mitigation_decisions": True
        }
        return jsonify(base_status)

    @app.get("/api/telemetry")
    @login_required
    def telemetry():
        limit = _number(request.args.get("limit"), 100)
        raw_rows = runtime.store.telemetry(limit=limit)
        formatted = [_format_telemetry_row(row, runtime) for row in raw_rows]
        return jsonify({
            "rows": formatted,
            "count": len(formatted),
            "provenance_note": "Each row carries its own source provenance."
        })

    @app.get("/api/events")
    @login_required
    def events():
        limit = _number(request.args.get("limit"), 200)
        raw_rows = [row for row in runtime.store.telemetry(limit=limit) if row.get("label") == "ATTACK"]
        formatted = [_format_telemetry_row(row, runtime) for row in raw_rows]
        return jsonify({"events": formatted, "count": len(formatted)})

    @app.get("/api/incidents")
    @login_required
    def incidents():
        limit = _number(request.args.get("limit"), 100)
        items = runtime.store.incidents(limit=limit, severity=request.args.get("severity"), state=request.args.get("state"))
        return jsonify({"incidents": items, "count": len(items)})

    @app.get("/api/incidents/<incident_id>")
    @login_required
    def incident(incident_id: str):
        item = runtime.store.incident(incident_id)
        return (jsonify(item), 200) if item else (jsonify({"error": "not found"}), 404)

    @app.post("/api/incidents/<incident_id>/transition")
    @login_required
    @permission_required(PERM_MANAGE_INCIDENT)
    def transition_incident(incident_id: str):
        body = request.get_json(silent=True) or {}
        state = str(body.get("state", "")).upper()
        curr_user = get_current_user() or {"username": "operator", "role": "OPERATOR"}

        # Enforce RBAC: Only ADMIN can close incidents
        if state == "CLOSED" and not has_permission(curr_user.get("role"), PERM_CLOSE_INCIDENT):
            runtime.store.record_audit(
                username=curr_user.get("username", "operator"),
                role=curr_user.get("role", "OPERATOR"),
                action="ACCESS_DENIED",
                resource="incident",
                resource_id=incident_id,
                result="DENIED",
                details=f"Denied permission to close incident {incident_id}: ADMIN role required",
                source_ip=request.remote_addr,
            )
            return jsonify({
                "error": "Forbidden: ADMIN role required to close incidents",
                "code": "FORBIDDEN_ROLE",
                "role": curr_user.get("role"),
                "required_permission": PERM_CLOSE_INCIDENT,
            }), 403

        actor = str(body.get("actor") or curr_user["username"])
        note = str(body.get("note", "operator transition"))
        try:
            item = runtime.store.transition_incident(incident_id, state, actor, note)
            if state in {"CLOSED", "RESOLVED"} and item.get("device_id"):
                runtime.response.release(item["device_id"])
            runtime.publish("incident", item)
            alert = runtime.store.sync_alert_with_incident(item)
            if alert:
                runtime.publish("alert", alert)

            action_name = "INCIDENT_CLOSED" if state == "CLOSED" else "INCIDENT_TRANSITIONED"
            runtime.store.record_audit(
                username=actor,
                role=curr_user["role"],
                action=action_name,
                resource="incident",
                resource_id=incident_id,
                result="SUCCESS",
                details=f"Incident {incident_id} transitioned to {state}: {note}",
                source_ip=request.remote_addr,
            )
            return jsonify(item)
        except (KeyError, ValueError) as error:
            return jsonify({"error": str(error)}), 400

    @app.post("/api/incidents/<incident_id>/action")
    @login_required
    @permission_required(PERM_MANAGE_INCIDENT)
    def incident_action(incident_id: str):
        curr_user = get_current_user() or {"username": "operator", "role": "OPERATOR"}
        body = request.get_json(silent=True) or {}
        actor = str(body.get("actor") or curr_user["username"])
        action_name = str(body.get("action", ""))
        try:
            res = runtime.manual_action(incident_id, action_name, actor)
            runtime.store.record_audit(
                username=actor,
                role=curr_user["role"],
                action="MANUAL_ACTION_EXECUTED",
                resource="incident",
                resource_id=incident_id,
                result="SUCCESS",
                details=f"Executed manual response action '{action_name}' on incident {incident_id}",
                source_ip=request.remote_addr,
            )
            return jsonify(res)
        except (KeyError, ValueError) as error:
            return jsonify({"error": str(error)}), 400

    @app.post("/api/manual/action")
    @login_required
    @permission_required(PERM_MANAGE_INCIDENT)
    def manual_action():
        curr_user = get_current_user() or {"username": "operator", "role": "OPERATOR"}
        body = request.get_json(silent=True) or {}
        action = str(body.get("action", "")).upper()
        incident_id = body.get("incident_id")
        actor = str(body.get("actor") or curr_user["username"])
        if not incident_id:
            active = runtime.store.find_active_incident()
            if active:
                incident_id = active["incident_id"]
            else:
                incidents_list = runtime.store.incidents(limit=1)
                if incidents_list:
                    incident_id = incidents_list[0]["incident_id"]
        if incident_id:
            try:
                res = runtime.manual_action(incident_id, action, actor)
                runtime.store.record_audit(
                    username=actor,
                    role=curr_user["role"],
                    action="MANUAL_ACTION_EXECUTED",
                    resource="incident",
                    resource_id=incident_id,
                    result="SUCCESS",
                    details=f"Executed manual action '{action}' on incident {incident_id}",
                    source_ip=request.remote_addr,
                )
                return jsonify(res)
            except Exception as e:
                return jsonify({"error": str(e)}), 400
        stored = runtime.store.record_action(
            event_id=None,
            incident_id=None,
            action=action,
            reason="operator manual command",
            policy="operator-manual-v1",
            mode="MANUAL",
            result="SIMULATED_NOT_ENFORCED",
            provenance="SIMULATED"
        )
        runtime.publish("response", stored)
        return jsonify({"action": stored, "incident": None})

    @app.get("/api/actions")
    @login_required
    def actions():
        return jsonify({
            "actions": runtime.store.actions(limit=_number(request.args.get("limit"), 100)),
            "enforcement": "SIMULATED / DRY-RUN only"
        })

    @app.get("/api/export/<kind>.<fmt>")
    @login_required
    def export(kind: str, fmt: str):
        if kind == "audit":
            user = get_current_user()
            user_role = str(user.get("role", "")).upper() if user else ""
            if user_role != ROLE_ADMIN:
                _log_security_audit(
                    user.get("username", "unknown") if user else "anonymous",
                    user_role or "ANONYMOUS",
                    "ACCESS_DENIED",
                    f"Denied role '{user_role}' for endpoint {request.method} {request.path}. Allowed: ['{ROLE_ADMIN}']",
                )
                return jsonify({
                    "error": f"Forbidden: Role '{user_role}' lacks authorization. Required: ['{ROLE_ADMIN}']",
                    "code": "FORBIDDEN_ROLE",
                    "role": user_role,
                }), 403
        try:
            content = runtime.store.export(kind, fmt)
            mimetype = "text/csv" if fmt == "csv" else "application/json"
            return Response(content, mimetype=mimetype, headers={"Content-Disposition": f'attachment; filename="aegis-{kind}.{fmt}"'})
        except ValueError as error:
            return jsonify({"error": str(error)}), 400

    @app.get("/api/scenarios")
    @login_required
    def scenarios():
        return jsonify({
            "scenarios": catalogue(),
            "safety": "These are in-process profiles. They transmit no packets and do not target any device."
        })

    @app.post("/api/simulations/start")
    @login_required
    @permission_required(PERM_ADMIN_CONTROLS)
    def start_simulation():
        curr_user = get_current_user() or {"username": "admin", "role": "ADMIN"}
        body = request.get_json(silent=True) or {}
        scenario_id = str(body.get("scenario_id", ""))
        intensity = _number(body.get("intensity"), 3)
        duration = body.get("duration")
        device_id = body.get("device_id")
        actor = curr_user["username"]
        try:
            payload = runtime.start_simulation(scenario_id, intensity, duration, device_id=device_id)
            runtime.store.record_audit(
                username=actor,
                role=curr_user["role"],
                action="SIMULATION_STARTED",
                resource="simulation",
                resource_id=scenario_id,
                result="SUCCESS",
                details=f"Launched controlled in-process simulation: {scenario_id} (intensity={intensity})",
                source_ip=request.remote_addr,
            )
            return jsonify(payload), 202
        except (KeyError, ValueError) as error:
            return jsonify({"error": str(error)}), 400

    @app.post("/api/simulations/stop")
    @login_required
    @permission_required(PERM_ADMIN_CONTROLS)
    def stop_simulation():
        curr_user = get_current_user() or {"username": "admin", "role": "ADMIN"}
        body = request.get_json(silent=True) or {}
        scenario_id = body.get("scenario_id")
        stopped = runtime.stop_simulation(scenario_id)
        actor = curr_user["username"]
        runtime.store.record_audit(
            username=actor,
            role=curr_user["role"],
            action="SIMULATION_STOPPED",
            resource="simulation",
            resource_id=str(scenario_id),
            result="SUCCESS",
            details=f"Stopped simulation: {stopped}",
            source_ip=request.remote_addr,
        )
        return jsonify({"stopped": stopped, "network_transmission": False})

    @app.post("/api/simulations/reset")
    @login_required
    @permission_required(PERM_ADMIN_CONTROLS)
    def reset_simulation():
        curr_user = get_current_user() or {"username": "admin", "role": "ADMIN"}
        actor = curr_user["username"]
        stopped = runtime.stop_simulation()
        runtime.stop_baseline(timeout=5.0)
        with runtime._lock:
            runtime.store.reset_active_incidents_and_alerts(actor=actor, note="Simulation reset via dashboard/API")
            runtime.iam.reset_identities()
            runtime.response.reset()
            runtime.reset_streaks()
            if runtime.settings.baseline_enabled:
                runtime.start_baseline()
            baseline_event = runtime.ingest(generate_window("normal", intensity=1, sequence=0))
            runtime.store.record_audit(
                username=actor,
                role=curr_user["role"],
                action="SIMULATION_RESET",
                resource="simulation",
                resource_id="baseline",
                result="SUCCESS",
                details=f"Reset simulation state to normal baseline rhythm: stopped {stopped}",
                source_ip=request.remote_addr,
            )
            runtime.publish("simulation", {"state": "RESET", "scenario_id": "normal", "provenance": "SIMULATED"})
        return jsonify({
            "status": "RESET",
            "stopped": stopped,
            "baseline": "RUNNING",
            "network_transmission": False,
            "latest": baseline_event.get("event"),
        })

    @app.post("/api/demo-data")
    @login_required
    @permission_required(PERM_ADMIN_CONTROLS)
    def demo_data():
        """Single-step validated controlled attack execution for the dashboard button."""
        event = generate_window("udp_flood", intensity=3, sequence=0)
        res = runtime.ingest(event)
        is_attack = res["decision"]["prediction"] == "ATTACK"
        ddos_p = float(res["decision"]["confidence"]) if is_attack else round(1.0 - float(res["decision"]["confidence"]), 2)
        return jsonify({
            "prediction": res["decision"]["prediction"],
            "ddos_probability": ddos_p,
            "security_action": res["response"]["action"],
            "severity": res["decision"]["severity"],
            "mitigation_action": res["response"]["action"],
            "mitigation_reason": res["response"]["reason"],
            "enforcement": False,
            "controlled": True,
            "offline_only": True
        })

    @app.post("/api/settings/mode")
    @login_required
    @roles_required(ROLE_ADMIN)
    @permission_required(PERM_ADMIN_CONTROLS)
    def set_mode():
        curr_user = get_current_user() or {"username": "admin", "role": "ADMIN"}
        body = request.get_json(silent=True) or {}
        mode = body.get("mode")
        auto = body.get("auto")
        cfg = runtime.configure_response(mode=mode, auto=auto)
        actor = curr_user["username"]
        runtime.store.record_audit(
            username=actor,
            role=curr_user["role"],
            action="SECURITY_SETTING_CHANGED",
            resource="response_policy",
            resource_id=str(mode or ("AUTO" if auto else "MANUAL")),
            result="SUCCESS",
            details=f"Modified gateway operating mode: mode={cfg.get('mode')}, auto={cfg.get('auto')}",
            source_ip=request.remote_addr,
        )
        return jsonify(cfg)

    @app.post("/api/iam/access")
    @login_required
    @permission_required(PERM_ADMIN_CONTROLS)
    def iam_access():
        body = request.get_json(silent=True) or {}
        decision = runtime.iam.access(body.get("identity"), str(body.get("resource", "gateway:telemetry")))
        runtime.store.record_iam(decision)
        runtime.publish("iam", decision)
        return jsonify(decision)

    @app.get("/api/iam")
    @login_required
    def iam():
        identity_list = []
        for ident in runtime.iam.identities.values():
            d = dict(ident.__dict__)
            d.pop("auth_key_hash", None)
            d.pop("auth_key", None)
            d.pop("psk", None)
            identity_list.append(d)
        return jsonify({
            "identities": identity_list,
            "devices": identity_list,
            "policy": "authenticated role plus trust >= 40"
        })

    @app.get("/api/iam/devices")
    @login_required
    def list_iam_devices():
        devices = runtime.store.list_device_identities()
        sanitized = []
        for dev in devices:
            d = dict(dev)
            d.pop("auth_key_hash", None)
            sanitized.append(d)
        return jsonify({"devices": sanitized, "count": len(sanitized)})

    @app.post("/api/iam/devices")
    @login_required
    @permission_required(PERM_ADMIN_CONTROLS)
    def manage_iam_devices():
        curr_user = get_current_user() or {"username": "admin", "role": "ADMIN"}
        body = request.get_json(silent=True) or {}
        action = str(body.get("action", "")).lower()
        device_id = str(body.get("device_id", "")).strip()

        if action == "list":
            devices = runtime.store.list_device_identities()
            sanitized = []
            for dev in devices:
                d = dict(dev)
                d.pop("auth_key_hash", None)
                sanitized.append(d)
            return jsonify({"ok": True, "devices": sanitized, "count": len(sanitized)}), 200

        if not device_id:
            return jsonify({"error": "device_id is required"}), 400

        if action == "enroll":
            role = str(body.get("role", "sensor")).lower()
            custom_psk = body.get("psk")
            enrolled = runtime.iam.enroll_device(device_id, role=role, psk=custom_psk)
            runtime.store.record_audit(
                username=curr_user["username"],
                role=curr_user["role"],
                action="DEVICE_ENROLLED",
                resource="device",
                resource_id=device_id,
                result="SUCCESS",
                details=f"Enrolled zero-trust device '{device_id}' with role '{role}'",
                source_ip=request.remote_addr,
            )
            return jsonify({"ok": True, "device": enrolled}), 201

        elif action == "revoke":
            revoked = runtime.iam.revoke_device(device_id)
            runtime.store.record_audit(
                username=curr_user["username"],
                role=curr_user["role"],
                action="DEVICE_REVOKED",
                resource="device",
                resource_id=device_id,
                result="SUCCESS",
                details=f"Revoked zero-trust device '{device_id}'",
                source_ip=request.remote_addr,
            )
            return jsonify({"ok": True, "device": revoked}), 200

        return jsonify({"error": "action must be 'enroll', 'revoke', or 'list'"}), 400

    @app.get("/api/trust")
    @login_required
    def trust():
        return jsonify({
            "history": runtime.store.trust(request.args.get("identity")),
            "calculation": "-20 suspicious detection; -15 authentication failure; +3 per normal recovery observation; bounded 0..100."
        })

    @app.get("/api/energy")
    @login_required
    def energy():
        limit = _number(request.args.get("limit"), 100)
        raw_rows = runtime.store.telemetry(limit=limit)
        formatted = [_format_energy_row(r) for r in raw_rows]
        return jsonify({
            "rows": formatted,
            "count": len(formatted),
            "baseline": 55.0,
            "unit": "mW",
            "measurement_status": "MODELLED",
            "environment": "CONTROLLED_SIMULATION",
            "hardware_measured": False,
            "claim_boundary": "Not a physical energy measurement; correlation does not prove attack."
        })

    _protocols_cache: dict[str, Any] = {"ts": 0.0, "data": None}

    @app.get("/api/protocols")
    @login_required
    def protocols():
        now_mono = time.monotonic()
        if _protocols_cache["data"] is not None and (now_mono - _protocols_cache["ts"]) < 2.0:
            return jsonify(_protocols_cache["data"])

        rows = runtime.store.telemetry(limit=500)
        counts: dict[str, int] = {}
        for row in rows:
            proto = str(row.get("protocol") or "UNKNOWN").upper()
            if proto in ("ICMP", "ICMPV6"):
                proto = "ICMP"
            elif proto == "MQTT" or row.get("dst_port") == 1883 or row.get("scenario_id") == "mqtt_anomaly":
                proto = "MQTT"
            elif proto == "UDP":
                proto = "UDP"
            elif proto == "TCP":
                proto = "TCP"
            counts[proto] = counts.get(proto, 0) + 1

        total = sum(counts.values()) or 1
        percentages = {k: round((v / total) * 100, 1) for k, v in counts.items()}
        result = {
            "mix": counts,
            "total": sum(counts.values()),
            "percentages": percentages,
            "aggregation": "ICMP/ICMPv6 grouped under ICMP; port 1883 and mqtt_anomaly grouped under MQTT; port 5683/UDP under UDP.",
            "claim_boundary": "MQTT, CoAP, RPL, and Modbus scenario labels are simulated profiles unless a parsed source explicitly says otherwise."
        }
        _protocols_cache["ts"] = now_mono
        _protocols_cache["data"] = result
        return jsonify(result)

    @app.get("/api/topology")
    @login_required
    def topology():
        attack_nodes = runtime.get_topology_attacker_states()
        sensors = [
            {"name": "SENSOR-01", "id": "SENSOR-01", "ip": "10.42.0.11", "role": "IIoT Sensor", "authorization": "AUTHORIZED", "trust": runtime.iam.get("SENSOR-01").trust_score, "status": "ONLINE", "traffic_indicator": "NORMAL (15.0 pps)"},
            {"name": "SENSOR-02", "id": "SENSOR-02", "ip": "10.42.0.12", "role": "Sensor Cluster", "authorization": "AUTHORIZED", "trust": runtime.iam.get("SENSOR-GROUP-A").trust_score, "status": "ONLINE", "traffic_indicator": "NORMAL (18.0 pps)"},
        ]
        gateway_status = "SHIELD_ACTIVE" if any(a.get("mitigated") for a in attack_nodes) else ("ALERT" if any(a.get("active") for a in attack_nodes) else "ONLINE")
        gateway = {"name": "EDGE-GW-01", "id": "EDGE-GW-01", "alias": "GATEWAY-01", "ip": "10.42.0.1", "role": "Security Gateway", "authorization": "AUTHORIZED", "trust": 100, "status": gateway_status}
        ot_servers = [{"name": "PLC-SINK", "id": "PLC-SINK", "ip": "10.42.0.10", "role": "OT PLC Sink", "authorization": "AUTHORIZED", "trust": 100, "status": "ONLINE"}]

        links = [
            {"source": "SENSOR-01", "target": "EDGE-GW-01", "type": "legitimate", "status": "ACTIVE"},
            {"source": "SENSOR-02", "target": "EDGE-GW-01", "type": "legitimate", "status": "ACTIVE"},
            {"source": "EDGE-GW-01", "target": "PLC-SINK", "type": "ot", "status": "ACTIVE"},
        ]
        for a in attack_nodes:
            links.append({
                "source": a["id"],
                "target": "EDGE-GW-01",
                "type": "attack",
                "status": a["status"],
                "active": a["active"],
                "mitigated": a["mitigated"],
            })

        nodes = [
            {"id": "SENSOR-01", "name": "SENSOR-01", "type": "sensor", "ip": "10.42.0.11", "trust": runtime.iam.get("SENSOR-01").trust_score, "status": "ONLINE"},
            {"id": "SENSOR-02", "name": "SENSOR-02", "type": "sensor", "ip": "10.42.0.12", "trust": runtime.iam.get("SENSOR-GROUP-A").trust_score, "status": "ONLINE"},
            {"id": "EDGE-GW-01", "name": "EDGE-GW-01", "type": "gateway", "ip": "10.42.0.1", "trust": 100, "status": gateway_status},
            {"id": "PLC-SINK", "name": "PLC-SINK", "type": "plc", "ip": "10.42.0.10", "trust": 100, "status": "ONLINE"},
        ]
        for a in attack_nodes:
            nodes.append({
                "id": a["id"],
                "name": a["name"],
                "type": "attacker",
                "ip": a["ip"],
                "role": a["role"],
                "trust": a["trust"],
                "status": a["status"],
                "active": a["active"],
                "mitigated": a["mitigated"],
            })

        ot_count = len(sensors) + 1 + len(ot_servers)
        ddos_count = len(attack_nodes)
        total_nodes = len(nodes)
        total_links = len(links)

        return jsonify({
            "status": "ONLINE",
            "environment": "CONTROLLED_SIMULATION",
            "provenance": "SIMULATED",
            "discovery": False,
            "counts": {
                "ot_nodes": ot_count,
                "ddos_sources": ddos_count,
                "total_nodes": total_nodes,
                "links": total_links,
            },
            "sensors": sensors,
            "gateway": gateway,
            "ot_servers": ot_servers,
            "attack_nodes": attack_nodes,
            "links": links,
            "nodes": nodes,
        })

    @app.get("/api/metrics")
    @login_required
    def metrics():
        path = runtime.settings.report_dir / "evaluation.json"
        return jsonify(json.loads(path.read_text(encoding="utf-8")) if path.exists() else {
            "status": "NOT_TRAINED",
            "instruction": "Run `python3 -m aegis_gateway.cli train` to generate evaluation evidence."
        })

    _model_assurance_cache: dict[str, Any] = {"mtime": 0.0, "data": None}

    @app.get("/api/model-assurance")
    @login_required
    def model_assurance():
        eval_path = runtime.settings.report_dir / "evaluation.json"
        cm_path = runtime.settings.report_dir / "confusion_matrix.csv"

        try:
            current_mtime = eval_path.stat().st_mtime if eval_path.exists() else 0.0
        except OSError:
            current_mtime = 0.0

        if _model_assurance_cache["data"] is not None and _model_assurance_cache["mtime"] == current_mtime and current_mtime > 0.0:
            return jsonify(_model_assurance_cache["data"])

        data: dict[str, Any] = {
            "status": "READY" if eval_path.exists() else "NOT_TRAINED",
            "model_architecture": "Random Forest (240 trees) + Isolation Forest (200 trees)",
            "model_version": "hybrid-rf-if-v2",
            "dataset_version": "synthetic-lab-v2",
            "evaluation_protocol": "stratified campaign-grouped train/validation/test plus scenario-held-out evaluation",
            "evaluation_context": "HELD-OUT SYNTHETIC LAB EVALUATION",
            "metrics": {
                "precision": None,
                "recall": None,
                "f1": None,
                "false_positive_rate": None,
                "roc_auc": None,
                "pr_auc": None,
                "brier_score_calibrated": None,
                "scenario_held_out_f1": None,
            },
            "confusion_matrix": {
                "labels": ["NORMAL", "ATTACK"],
                "true_negative": None,
                "false_positive": None,
                "false_negative": None,
                "true_positive": None,
                "matrix": None,
            },
            "splits": {},
            "provenance": "SYNTHETIC",
            "claim_boundary": "Scenario-separated synthetic evaluation on stratified campaign-grouped lab data without leakage — not a production accuracy claim. Platt calibration guarantees bounded decision probabilities."
        }

        if eval_path.exists():
            try:
                ev = json.loads(eval_path.read_text(encoding="utf-8"))
                data["experiment_id"] = ev.get("experiment_id")
                data["timestamp"] = ev.get("timestamp")
                data["feature_version"] = ev.get("feature_version")
                data["splits"] = ev.get("splits", {})
                data["feature_importance"] = ev.get("feature_importance", {})

                test_block = ev.get("test", {})
                data["metrics"]["precision"] = test_block.get("precision", {}).get("ATTACK")
                data["metrics"]["recall"] = test_block.get("recall", {}).get("ATTACK")
                data["metrics"]["f1"] = test_block.get("f1", {}).get("ATTACK")
                data["metrics"]["false_positive_rate"] = test_block.get("false_positive_rate")
                data["metrics"]["roc_auc"] = test_block.get("roc_auc")
                data["metrics"]["pr_auc"] = test_block.get("pr_auc")

                calib = ev.get("calibration", {})
                data["metrics"]["brier_score_calibrated"] = calib.get("brier_score_calibrated")

                held = ev.get("scenario_held_out", {})
                data["metrics"]["scenario_held_out_f1"] = held.get("f1", {}).get("ATTACK")

                if "confusion_matrix" in test_block:
                    cm = test_block["confusion_matrix"]
                    data["confusion_matrix"]["matrix"] = cm
                    if len(cm) == 2 and len(cm[0]) == 2 and len(cm[1]) == 2:
                        data["confusion_matrix"]["true_negative"] = cm[0][0]
                        data["confusion_matrix"]["false_positive"] = cm[0][1]
                        data["confusion_matrix"]["false_negative"] = cm[1][0]
                        data["confusion_matrix"]["true_positive"] = cm[1][1]
            except Exception as err:
                data["eval_parse_error"] = str(err)

        if cm_path.exists():
            try:
                lines = cm_path.read_text(encoding="utf-8").strip().splitlines()
                if len(lines) >= 3:
                    row_norm = lines[1].split(",")
                    row_atk = lines[2].split(",")
                    tn = int(row_norm[1])
                    fp = int(row_norm[2])
                    fn = int(row_atk[1])
                    tp = int(row_atk[2])
                    data["confusion_matrix"]["true_negative"] = tn
                    data["confusion_matrix"]["false_positive"] = fp
                    data["confusion_matrix"]["false_negative"] = fn
                    data["confusion_matrix"]["true_positive"] = tp
                    data["confusion_matrix"]["matrix"] = [[tn, fp], [fn, tp]]
            except Exception as err:
                data["cm_parse_error"] = str(err)

        _model_assurance_cache["mtime"] = current_mtime
        _model_assurance_cache["data"] = data
        return jsonify(data)

    @app.get("/api/ns3")
    @login_required
    def ns3_status():
        root = runtime.settings.project_root / "ns-allinone-3.48" / "ns-3.48"
        scratch_dir = root / "scratch"
        existing = [str(path.relative_to(runtime.settings.project_root)) for path in scratch_dir.glob("*.cc")] if scratch_dir.exists() else []
        trace_dir = runtime.settings.trace_dir
        return jsonify({
            "available": root.exists(),
            "provenance": "SIMULATED",
            "adapter": "POST /api/ns3/import accepts repository-local CSV paths",
            "existing_scenarios": existing,
            "pcap_traces": [f"dataset/{p.name}" for p in sorted(trace_dir.glob("ns3_*.pcap"))] if trace_dir.exists() else []
        })

    @app.post("/api/ns3/import")
    @login_required
    @roles_required(ROLE_ADMIN)
    def import_ns3():
        curr_user = get_current_user() or {"username": "admin", "role": "ADMIN"}
        payload = request.get_json(silent=True)
        if payload is None:
            body = {}
        elif not isinstance(payload, dict):
            return jsonify({"error": "request body must be a JSON object"}), 400
        else:
            body = payload
        raw_path = body.get("path")
        if raw_path is None or not isinstance(raw_path, str):
            return jsonify({"error": "path must be a string naming a trace CSV"}), 400
        try:
            candidate = resolve_contained_path(
                raw_path,
                allowed_roots=[runtime.settings.trace_dir],
                default_root=runtime.settings.trace_dir,
                allowed_extensions=(".csv",),
            )
        except (ValueError, FileNotFoundError) as error:
            logger.warning("NS-3 trace path validation failed: %s", error)
            return _trace_error_response("Invalid or unsupported NS-3 trace file", error)
        try:
            count = sum(1 for event in ns3_csv_events(candidate, body.get("scenario_id")) for _ in [runtime.ingest(event)])
            rel_source = _safe_relative_path(candidate, runtime.settings)
            runtime.store.record_audit(
                username=curr_user["username"],
                role=curr_user["role"],
                action="DATA_IMPORTED",
                resource="ns3_trace",
                resource_id=rel_source,
                result="SUCCESS",
                details=f"Imported {count} events from NS3 CSV {candidate.name}",
                source_ip=request.remote_addr,
            )
            return jsonify({
                "imported": count,
                "source": rel_source,
                "provenance": "SIMULATED"
            })
        except Exception as error:
            logger.error("NS-3 trace processing failed: %s", error, exc_info=True)
            return jsonify({"error": "Invalid or unsupported NS-3 trace file"}), 400

    @app.get("/api/cooja")
    @login_required
    def cooja():
        cooja_dir = runtime.settings.cooja_dir
        cooja_data = cooja_dir / "cooja_ml_ready_v1.csv"
        candidate_models = [
            runtime.settings.root / "legacy_prototypes" / "detection" / "detection" / "cooja_attack_model_v1.pkl",
            runtime.settings.root / "legacy_prototypes" / "detection" / "cooja_attack_model_v1.pkl",
            runtime.settings.root / "detection" / "cooja_attack_model_v1.pkl",
            runtime.settings.project_root / "backend" / "legacy_prototypes" / "detection" / "detection" / "cooja_attack_model_v1.pkl",
        ]
        frozen_model = next((p for p in candidate_models if p.exists()), candidate_models[0])
        available = cooja_data.exists()
        return jsonify({
            "status": "SIMULATION_READY" if available else "NOT_INSTALLED",
            "adapter_status": "READY" if available else "NOT_IMPLEMENTED",
            "provenance": "SIMULATED",
            "environment": "Contiki-NG / Cooja 6LoWPAN Emulation",
            "data_available": available,
            "data_path": str(cooja_data) if available else None,
            "frozen_model": _safe_relative_path(frozen_model, runtime.settings, prefer_repo=True) if frozen_model.exists() else None,
            "claim_boundary": "Cooja mote emulation output, not physical hardware measurements."
        })

    @app.post("/api/cooja/import")
    @login_required
    @roles_required(ROLE_ADMIN)
    def import_cooja():
        curr_user = get_current_user() or {"username": "admin", "role": "ADMIN"}
        payload = request.get_json(silent=True)
        if payload is None:
            body = {}
        elif not isinstance(payload, dict):
            return jsonify({"error": "request body must be a JSON object"}), 400
        else:
            body = payload
        raw_path = body.get("path")
        if raw_path is None:
            raw_path = str(runtime.settings.cooja_dir / "cooja_ml_ready_v1.csv")
        elif not isinstance(raw_path, str):
            return jsonify({"error": "path must be a string naming a Cooja CSV"}), 400
        try:
            candidate = resolve_contained_path(
                raw_path,
                allowed_roots=[runtime.settings.trace_dir, runtime.settings.cooja_dir],
                default_root=runtime.settings.cooja_dir,
                allowed_extensions=(".csv",),
            )
        except (ValueError, FileNotFoundError) as error:
            logger.warning("Cooja trace path validation failed: %s", error)
            return _trace_error_response("Invalid or unsupported Cooja trace file", error)
        try:
            count = sum(1 for event in cooja_csv_events(candidate, body.get("scenario_id")) for _ in [runtime.ingest(event)])
            runtime.store.record_audit(
                username=curr_user["username"],
                role=curr_user["role"],
                action="DATA_IMPORTED",
                resource="cooja_trace",
                resource_id=str(candidate),
                result="SUCCESS",
                details=f"Imported {count} events from Cooja CSV {candidate.name}",
                source_ip=request.remote_addr,
            )
            return jsonify({
                "imported": count,
                "source": str(candidate),
                "provenance": "SIMULATED",
                "source_type": "COOJA"
            })
        except Exception as error:
            logger.error("Cooja trace processing failed: %s", error, exc_info=True)
            return jsonify({"error": "Invalid or unsupported Cooja trace file"}), 400

    @app.post("/api/pcap/replay")
    @login_required
    @roles_required(ROLE_ADMIN)
    def replay_pcap():
        curr_user = get_current_user() or {"username": "admin", "role": "ADMIN"}
        payload = request.get_json(silent=True)
        if payload is None:
            body = {}
        elif not isinstance(payload, dict):
            return jsonify({"error": "request body must be a JSON object"}), 400
        else:
            body = payload
        raw_path = body.get("path")
        if raw_path is None or not isinstance(raw_path, str):
            return jsonify({"error": "path must be a string naming a PCAP file"}), 400
        try:
            candidate = resolve_contained_path(
                raw_path,
                allowed_roots=[runtime.settings.trace_dir],
                default_root=runtime.settings.trace_dir,
                allowed_extensions=(".pcap", ".pcapng"),
            )
        except (ValueError, FileNotFoundError) as error:
            logger.warning("PCAP trace path validation failed: %s", error)
            return _trace_error_response("Invalid or unsupported PCAP trace file", error)
        try:
            windowed = body.get("windowed", True)
            stream = pcap_window_events(candidate) if windowed else pcap_events(candidate)
            count = sum(1 for event in stream for _ in [runtime.ingest(event)])
            rel_source = _safe_relative_path(candidate, runtime.settings)
            runtime.store.record_audit(
                username=curr_user["username"],
                role=curr_user["role"],
                action="PCAP_REPLAYED",
                resource="pcap_trace",
                resource_id=rel_source,
                result="SUCCESS",
                details=f"Replayed {count} events from PCAP {candidate.name}",
                source_ip=request.remote_addr,
            )
            return jsonify({
                "replayed": count,
                "source": rel_source,
                "provenance": "REPLAYED",
                "transmitted": False
            })
        except Exception as error:
            logger.error("PCAP trace replay failed: %s", error, exc_info=True)
            return jsonify({"error": "Invalid or unsupported PCAP trace file"}), 400

    @app.get("/events")
    @login_required
    def sse():
        def stream():
            for message in runtime.subscribe():
                yield f"event: {message['type']}\ndata: {json.dumps(message['data'], default=str)}\n\n"
        return Response(stream(), mimetype="text/event-stream")

    return app


if __name__ == "__main__":
    runtime = GatewayRuntime()
    if runtime.settings.baseline_enabled:
        runtime.start_baseline()
    app = create_app(runtime)
    app.run(host=runtime.settings.host, port=runtime.settings.port, debug=False, threaded=True)

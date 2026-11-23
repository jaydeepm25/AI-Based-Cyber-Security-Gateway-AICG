"""Repository-relative configuration with safe demonstration defaults."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path


BACKEND_ROOT = Path(__file__).resolve().parent.parent
PROJECT_ROOT = BACKEND_ROOT.parent
ROOT = BACKEND_ROOT


LAB_MASTER_KEY_FALLBACK = "aicg-edge-device-master-lab-2026"
LAB_SECRET_KEY_FALLBACK = "aicg-edge-gateway-lab-secret-key-2026"


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    return default if value is None else value.strip().lower() in {"1", "true", "yes", "on"}


def _database_url_from_env() -> str | None:
    raw = os.getenv("DATABASE_URL") or os.getenv("AEGIS_DATABASE_URL")
    if not raw or not raw.strip():
        return None
    return raw.strip()


def _model_path_from_env() -> Path:
    env_path = os.getenv("AEGIS_MODEL_PATH")
    if not env_path or not env_path.strip():
        return BACKEND_ROOT / "models" / "hybrid_detector.joblib"
    candidate = Path(env_path.strip())
    if candidate.is_absolute():
        return candidate
    if (BACKEND_ROOT / candidate).exists():
        return BACKEND_ROOT / candidate
    if (PROJECT_ROOT / candidate).exists():
        return PROJECT_ROOT / candidate
    if candidate.exists():
        return candidate.resolve()
    return BACKEND_ROOT / candidate


@dataclass(frozen=True)
class Settings:
    """Settings intentionally exclude host-enforcement configuration."""

    root: Path = BACKEND_ROOT
    project_root: Path = PROJECT_ROOT
    database_path: Path = Path(os.getenv("AEGIS_DATABASE_PATH", str(BACKEND_ROOT / "data" / "aegis_gateway.sqlite3")))
    database_url: str | None = field(
        default_factory=_database_url_from_env,
        repr=False,
    )
    model_path: Path = field(default_factory=_model_path_from_env)
    report_dir: Path = BACKEND_ROOT / "reports"
    dataset_dir: Path = BACKEND_ROOT / "data" / "datasets"
    trace_dir: Path = BACKEND_ROOT / "dataset"
    cooja_dir: Path = field(
        default_factory=lambda: Path(
            os.getenv("AEGIS_COOJA_DIR")
            or (
                "/home/kali/contiki-ng/examples/ai_edge_iiot/data"
                if Path("/home/kali/contiki-ng/examples/ai_edge_iiot/data").exists()
                else str(BACKEND_ROOT / "dataset")
            )
        )
    )
    event_retention_days: int = int(os.getenv("AEGIS_RETENTION_DAYS", "30"))
    demo_tick_seconds: float = float(os.getenv("AEGIS_DEMO_TICK_SECONDS", "1.0"))
    response_mode: str = field(default_factory=lambda: os.getenv("AEGIS_RESPONSE_MODE", "DRY_RUN").upper())
    auto_response: bool = _bool("AEGIS_AUTO_RESPONSE", True)
    host: str = os.getenv("AEGIS_HOST", "127.0.0.1")
    port: int = int(os.getenv("AEGIS_PORT", "8000"))
    production: bool = field(default_factory=lambda: _bool("AEGIS_PRODUCTION", False))
    secret_key: str = field(
        default_factory=lambda: os.getenv("AEGIS_SECRET_KEY", LAB_SECRET_KEY_FALLBACK),
        repr=False,
    )
    device_master_key: str = field(
        default_factory=lambda: os.getenv("AEGIS_MASTER_KEY") or os.getenv("AEGIS_DEVICE_MASTER_KEY") or LAB_MASTER_KEY_FALLBACK,
        repr=False,
    )
    allow_demo_accounts: bool = field(
        default_factory=lambda: not _bool("AEGIS_PRODUCTION", False) and _bool("AEGIS_DEMO_ACCOUNTS", True)
    )
    initial_admin_username: str = field(
        default_factory=lambda: (os.getenv("AEGIS_INITIAL_ADMIN_USERNAME") or os.getenv("AEGIS_ADMIN_USERNAME") or "admin").strip()
    )
    initial_admin_password: str | None = field(
        default_factory=lambda: os.getenv("AEGIS_INITIAL_ADMIN_PASSWORD") or os.getenv("AEGIS_ADMIN_PASSWORD"),
        repr=False,
    )
    session_cookie_secure: bool = field(
        default_factory=lambda: _bool(
            "AEGIS_SESSION_COOKIE_SECURE",
            _bool("AEGIS_COOKIE_SECURE", _bool("AEGIS_PRODUCTION", False)),
        )
    )
    auth_rate_limit_max: int = int(os.getenv("AEGIS_AUTH_RATE_LIMIT_MAX", "10"))
    auth_rate_limit_window_seconds: int = int(os.getenv("AEGIS_AUTH_RATE_LIMIT_WINDOW", "60"))
    in_process_enforcement: bool = field(default_factory=lambda: _bool("AEGIS_IN_PROCESS_ENFORCEMENT", True))
    baseline_enabled: bool | None = None

    def __post_init__(self) -> None:
        if self.baseline_enabled is None:
            env_val = os.getenv("AEGIS_BASELINE_ENABLED")
            if env_val is not None:
                computed = env_val.strip().lower() in {"1", "true", "yes", "on"}
            else:
                computed = not self.production
            object.__setattr__(self, "baseline_enabled", computed)
        elif not isinstance(self.baseline_enabled, bool):
            object.__setattr__(
                self,
                "baseline_enabled",
                str(self.baseline_enabled).strip().lower() in {"1", "true", "yes", "on"},
            )

        if self.production:
            if not self.secret_key or self.is_lab_secret_key:
                raise ValueError(
                    "AEGIS_SECRET_KEY environment variable is required in production mode "
                    "and cannot use the default lab fallback key."
                )
            if not self.device_master_key or self.is_lab_master_key:
                raise ValueError(
                    "AEGIS_MASTER_KEY (or AEGIS_DEVICE_MASTER_KEY) environment variable is required in production mode "
                    "and cannot use the default lab fallback key."
                )
            if not self.database_url or not self.database_url.strip():
                raise ValueError(
                    "DATABASE_URL (or AEGIS_DATABASE_URL) environment variable is required in production mode "
                    "and cannot be empty. Production cannot fall back to SQLite."
                )
            raw_url = self.database_url.strip().lower()
            if not (raw_url.startswith("postgresql://") or raw_url.startswith("postgres://")):
                raise ValueError(
                    "Production database connection requires a valid PostgreSQL URL scheme "
                    "('postgresql://' or 'postgres://'). SQLite and other database engines are rejected in production."
                )
            if "sslmode" not in raw_url:
                if not any(h in raw_url for h in ("localhost", "127.0.0.1", "test")):
                    raise ValueError(
                        "PostgreSQL connection in production mode requires an explicit sslmode "
                        "(e.g., '?sslmode=require') for secure cloud database transit."
                    )

    @property
    def is_postgres(self) -> bool:
        """True when a PostgreSQL database URL is configured."""
        return bool(self.database_url)

    @property
    def is_lab_master_key(self) -> bool:
        """True when running with the insecure default lab master key."""
        return self.device_master_key == LAB_MASTER_KEY_FALLBACK

    @property
    def is_lab_secret_key(self) -> bool:
        """True when running with the insecure default lab secret key."""
        return self.secret_key == LAB_SECRET_KEY_FALLBACK

    def ensure_directories(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.dataset_dir.mkdir(parents=True, exist_ok=True)
        self.trace_dir.mkdir(parents=True, exist_ok=True)
        try:
            self.model_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass


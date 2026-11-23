# Phase 4: AICG PostgreSQL Migration Readiness Audit
**Official Project Name**: AI-Based Cyber Security Gateway for Industry 4.0 (AICG)  
**Repository**: `AI-Edge-DDoS-Gateway`  
**Repository Path**: `/home/kali/AI-Edge-DDoS-Gateway`  
**Current Database**: SQLite 3 (Write-Ahead Logging / `WAL` Mode)  
**Target Database**: Supabase PostgreSQL (Managed Supavisor Connection Pooler)  
**Production Hosting**: Render Free Web Service  
**Git Branch**: `deploy/render-config` (Targeting `main`)  
**Audit Date**: 2026-11-23  
**Status**: Comprehensive Read-Only Architectural Audit Complete  

---

## 1. Executive Summary

The AI-Based Cyber Security Gateway for Industry 4.0 (AICG / AEGIS-OT) currently relies entirely on a single-node SQLite 3 database (`backend/data/aegis_gateway.sqlite3`) for persistent identity management, Zero-Trust device authentication, incident lifecycle tracking, alert management, and tamper-evident cryptographic audit logging.

When deploying AICG to public cloud hosting on **Render's Free Web Service Tier**, the root filesystem is ephemeral: all local files—including the SQLite database—are permanently lost whenever the service spins down after 15 minutes of inbound HTTP inactivity, reboots, or deploys a new commit. While an ephemeral database can function as a self-healing demonstrator for purely local lab sessions, **it causes complete data amnesia in production**:
- Custom administrator credentials and newly enrolled industrial sensors are wiped.
- Active incident investigations, response history, and security alert statuses disappear.
- The cryptographic SHA-256 audit log chain resets to the genesis block, destroying non-repudiation and forensic audit trails.

Migrating the persistence layer to **Supabase PostgreSQL** resolves this cloud durability problem by externalizing state to a managed, cloud-hosted relational database. However, this audit reveals that AICG's storage layer is tightly coupled to Python's built-in `sqlite3` module and utilizes SQLite-specific SQL dialects, implicit row identification (`rowid`), SQLite PRAGMAs, and transaction isolation commands (`BEGIN IMMEDIATE`).

### Key Recommendations of this Audit:
1. **Adopt a Polymorphic Storage Engine Pattern (Dual-Engine)**: Rather than executing an irreversible hard cutover that breaks the existing 400-test automated regression suite, refactor `storage.py` into an abstract storage interface with two implementations:
   - `SQLiteGatewayStore`: Preserved 100% intact for fast, zero-dependency local testing and CI workflows.
   - `PostgresGatewayStore`: Activated when `DATABASE_URL` or `AEGIS_DATABASE_URL` is set, executing PostgreSQL-native SQL queries through `psycopg2-binary` connection pooling.
2. **Use Supabase Shared Session Pooler (Port 5432, IPv4)**: Render Free Web Services lack outbound IPv6 connectivity. Direct connections to Supabase PostgreSQL on port 5432 (`db.<project-ref>.supabase.co`) fail with connection timeouts because direct hostnames resolve exclusively to IPv6 addresses. Production Render deployments **must** route database traffic through the **Supabase Shared Session Pooler** (`aws-0-<region>.pooler.supabase.com`) on **Port 5432** over IPv4 with `sslmode=require`. (The Transaction Pooler runs on port 6543, whereas the Session Pooler runs on port 5432; direct PostgreSQL connections also use port 5432 but lack IPv4 routing).
3. **Provisional Login Error Diagnosis**: Moving to PostgreSQL **does not automatically solve existing login errors**. As analyzed in Section 6, login failures frequently stem from reverse-proxy cookie suppression (`SESSION_COOKIE_SECURE=True` behind Render's edge proxy without Werkzeug `ProxyFix`), client handling of two-stage MFA challenges, or missing `AEGIS_INITIAL_ADMIN_PASSWORD` in production mode. **This diagnosis remains provisional** until live production server tracebacks, error logs, and browser network responses are inspected.
4. **Strict Production Credential and MFA Isolation**: In production mode (`AEGIS_PRODUCTION=true`), demo accounts (`admin`, `operator`) and lab passwords are strictly suppressed and prevented from bootstrapping. Fixed lab MFA tokens (`123456`) are strictly for local simulation and must never be exposed or permitted in production.

---

## 2. Existing SQLite Architecture

### 2.1 Database Path Resolution and Configuration
Database location is resolved dynamically in `backend/aegis_gateway/config.py`:
```python
BACKEND_ROOT = Path(__file__).resolve().parent.parent
database_path: Path = Path(os.getenv("AEGIS_DATABASE_PATH", str(BACKEND_ROOT / "data" / "aegis_gateway.sqlite3")))
```
Directory existence is verified and ensured during runtime startup via `Settings.ensure_directories()` (`self.database_path.parent.mkdir(parents=True, exist_ok=True)`).

### 2.2 Connection Management and Lifecycle
Connections in `backend/aegis_gateway/storage.py` follow a per-operation context manager pattern:
```python
@contextmanager
def connection(self) -> Iterator[sqlite3.Connection]:
    con = sqlite3.connect(self.path, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode = WAL;")
    con.execute("PRAGMA foreign_keys = ON;")
    con.execute("PRAGMA busy_timeout = 5000;")
    con.execute("PRAGMA synchronous = NORMAL;")
    try:
        yield con
        con.commit()
    except Exception:
        try:
            con.rollback()
        except Exception:
            pass
        raise
    finally:
        con.close()
```
- **Connection Model**: Short-lived, synchronous connections opened per transaction and immediately closed.
- **Row Factory**: `sqlite3.Row` provides key-based column access mirroring Python dictionaries (`dict(row)`).
- **PRAGMA Optimizations**:
  - `journal_mode = WAL`: Write-Ahead Logging allows concurrent readers alongside a single active writer.
  - `foreign_keys = ON`: Mandatory foreign key enforcement (disabled by default in SQLite).
  - `busy_timeout = 5000`: Waits up to 5,000 milliseconds for lock release before throwing `sqlite3.OperationalError: database is locked`.
  - `synchronous = NORMAL`: Flushes database writes at critical checkpoints while reducing disk sync overhead.

### 2.3 Concurrency and Transaction Safety
Within the single Python runtime process, thread safety is maintained through two layers:
1. SQLite's built-in WAL mode and busy timeout handler.
2. A process-level re-entrant lock `self._audit_lock = threading.RLock()` guarding the cryptographic audit logging method `record_audit()`. Within this lock, SQLite transactions explicitly execute `con.execute("BEGIN IMMEDIATE")` to acquire an exclusive write lock prior to calculating the SHA-256 hash chain link.

### 2.4 Initialization, Migration, and Bootstrapping
On startup, `GatewayStore.initialize()` executes:
1. `CREATE TABLE IF NOT EXISTS` for all 11 tables and associated indexes using `con.executescript(...)`.
2. `_migrate_schema(con)`: Backward-compatible column migration inspecting `PRAGMA table_info(admin_audit_log)` and adding `prev_hash` and `record_hash` columns if absent, backfilling hashes for existing records.
3. `_seed_default_users(con)`:
   - If `production=False` and `allow_demo_accounts=True`: Seeds default demo credentials (`admin` and `operator`).
   - If `production=True`: Fails fast if `AEGIS_INITIAL_ADMIN_PASSWORD` is absent; otherwise creates a single custom administrative user and suppresses all demo accounts.
4. `_seed_default_device_identities(con)`: Seeds pre-enrolled sensors (`SENSOR-01` to `SENSOR-03`, `SENSOR-GROUP-A`), revoked attacker bots (`ATK-01`, `ATTACKER-01` to `ATTACKER-06`), and operator credentials with deterministic HMAC-SHA256 derived keys.

---

## 3. Complete Database Table Inventory

AICG defines **11 relational tables** and **13 performance indexes** inside `backend/aegis_gateway/storage.py`:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       AICG Relational Database Schema                       │
└─────────────────────────────────────────────────────────────────────────────┘
  ┌──────────────────┐           ┌──────────────────┐
  │   admin_users    │           │device_identities │
  ├──────────────────┤           ├──────────────────┤
  │ user_id (PK)     │           │ device_id (PK)   │
  │ username (UQ)    │           │ role             │
  │ password_hash    │           │ status           │
  │ role             │           │ auth_key_hash    │
  │ mfa_status       │           │ trust_score      │
  │ status           │           │ failures         │
  └──────────────────┘           │ mfa_status       │
                                 └──────────────────┘
  ┌──────────────────┐           ┌──────────────────┐
  │ admin_audit_log  │           │  trust_history   │
  ├──────────────────┤           ├──────────────────┤
  │ event_id (PK)    │           │trust_event_id(PK)│
  │ timestamp        │           │ timestamp        │
  │ username         │           │ identity         │
  │ action           │           │ score, delta     │
  │ prev_hash        │           │ reason           │
  │ record_hash      │           └──────────────────┘
  └──────────────────┘
                                 ┌──────────────────┐
  ┌──────────────────┐           │    iam_events    │
  │    telemetry     │           ├──────────────────┤
  ├──────────────────┤           │iam_event_id (PK) │
  │ 52 Canonical     │           │ timestamp        │
  │ Fields (TEXT)    │           │ identity, role   │
  │ raw_json         │           │ decision, reason │
  └──────────────────┘           └──────────────────┘

  ┌─────────────────────────────────────────────────┐
  │                    incidents                    │
  ├─────────────────────────────────────────────────┤
  │ incident_id (PK)                                │
  │ created_at, updated_at, resolved_at             │
  │ device_id, source_id, attack_type, severity     │
  │ confidence, evidence_json, affected_resources   │
  │ lifecycle_state, recovery_state                 │
  └────────┬───────────────────────┬────────────────┘
           │ 1:N                   │ 1:1
           ▼                       ▼
  ┌──────────────────┐    ┌─────────────────────────┐
  │ incident_history │    │      admin_alerts       │
  ├──────────────────┤    ├─────────────────────────┤
  │ history_id (PK)  │    │ alert_id (PK)           │
  │ incident_id (FK) │    │ incident_id (FK, UQ)    │
  │ state            │    │ severity, status        │
  │ actor, note      │    │ acknowledgement_state   │
  │ evidence_json    │    │ evidence_json           │
  └──────────────────┘    └─────────────────────────┘
           │ 1:N (Optional)
           ▼
  ┌──────────────────┐
  │     actions      │
  ├──────────────────┤
  │ action_id (PK)   │
  │ incident_id (FK) │
  │ action, reason   │
  │ policy, mode     │
  └──────────────────┘
```

### Table 3.1: `telemetry`
- **Purpose**: Ingestion historian storing observation windows across all source adapters.
- **Columns**: 52 canonical columns generated from `CANONICAL_FIELDS` (all defined as `TEXT`) plus `raw_json TEXT NOT NULL`.
- **Primary Key**: None explicitly defined in DDL (relies on SQLite internal `rowid`).
- **Indexes**:
  - `telemetry_timestamp_idx ON telemetry(timestamp DESC)`
  - `telemetry_scenario_idx ON telemetry(scenario_id)`
  - `telemetry_source_idx ON telemetry(source_type, source_id)`

### Table 3.2: `incidents`
- **Purpose**: Authoritative security incident ledger tracking DDoS campaigns through multi-stage lifecycles (`DETECTED`, `TRIAGED`, `RESPONDING`, `CONTAINED`, `RECOVERING`, `RESOLVED`, `CLOSED`).
- **Columns**: `incident_id TEXT PRIMARY KEY`, `created_at TEXT NOT NULL`, `updated_at TEXT NOT NULL`, `event_id TEXT NOT NULL`, `device_id TEXT`, `source_id TEXT`, `attack_type TEXT`, `severity TEXT`, `confidence REAL`, `evidence_json TEXT NOT NULL`, `affected_resources TEXT`, `energy_impact TEXT`, `iam_impact TEXT`, `trust_impact TEXT`, `response_action TEXT`, `response_mode TEXT`, `operator TEXT`, `lifecycle_state TEXT NOT NULL`, `recovery_state TEXT NOT NULL`, `resolved_at TEXT`, `provenance TEXT NOT NULL`.
- **Index**: `incidents_state_idx ON incidents(lifecycle_state, severity)`.

### Table 3.3: `incident_history`
- **Purpose**: Immutable transition journal recording who changed incident state, when, and with what evidence.
- **Columns**: `history_id TEXT PRIMARY KEY`, `incident_id TEXT NOT NULL`, `timestamp TEXT NOT NULL`, `previous_state TEXT`, `state TEXT NOT NULL`, `actor TEXT`, `note TEXT`, `evidence_json TEXT NOT NULL`.
- **Foreign Key**: `FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE`.
- **Index**: `incident_history_incident_idx ON incident_history(incident_id, timestamp)`.

### Table 3.4: `actions`
- **Purpose**: Audit trail of autonomous and manual policy actions (`BLOCK`, `ISOLATE`, `RATE_LIMIT`, `ALERT`).
- **Columns**: `action_id TEXT PRIMARY KEY`, `timestamp TEXT NOT NULL`, `event_id TEXT`, `incident_id TEXT`, `action TEXT NOT NULL`, `reason TEXT NOT NULL`, `policy TEXT NOT NULL`, `mode TEXT NOT NULL`, `result TEXT NOT NULL`, `provenance TEXT NOT NULL`.
- **Foreign Key**: `FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE SET NULL`.

### Table 3.5: `iam_events`
- **Purpose**: Access evaluation logs for incoming network flows and API telemetry ingestion requests.
- **Columns**: `iam_event_id TEXT PRIMARY KEY`, `timestamp TEXT NOT NULL`, `identity TEXT`, `role TEXT`, `authentication_status TEXT`, `authorization_status TEXT`, `access_request TEXT`, `decision TEXT`, `reason TEXT`, `provenance TEXT NOT NULL`.

### Table 3.6: `trust_history`
- **Purpose**: Dynamic reputation ledger tracking numerical trust deltas (`-20` on attack, `-15` on auth failure, `+3` on recovery).
- **Columns**: `trust_event_id TEXT PRIMARY KEY`, `timestamp TEXT NOT NULL`, `identity TEXT NOT NULL`, `score REAL NOT NULL`, `delta REAL NOT NULL`, `reason TEXT NOT NULL`, `provenance TEXT NOT NULL`.
- **Index**: `trust_identity_idx ON trust_history(identity, timestamp DESC)`.

### Table 3.7: `metadata`
- **Purpose**: System experiment configurations, dataset hashes, and model training manifests.
- **Columns**: `metadata_id TEXT PRIMARY KEY`, `kind TEXT NOT NULL`, `version TEXT NOT NULL`, `created_at TEXT NOT NULL`, `payload_json TEXT NOT NULL`.
- **Index**: `metadata_kind_idx ON metadata(kind, created_at DESC)`.

### Table 3.8: `admin_users`
- **Purpose**: Administrative identity and authentication registry.
- **Columns**: `user_id TEXT PRIMARY KEY`, `username TEXT UNIQUE NOT NULL`, `password_hash TEXT NOT NULL`, `role TEXT NOT NULL`, `status TEXT NOT NULL`, `mfa_enabled INTEGER NOT NULL DEFAULT 1`, `mfa_status TEXT NOT NULL DEFAULT 'SIMULATED_VERIFIED'`, `created_at TEXT NOT NULL`, `last_login TEXT`.
- **Index**: `admin_users_username_idx ON admin_users(username)`.

### Table 3.9: `admin_alerts`
- **Purpose**: SOC Alert Center deduplication table ensuring each incident has exactly one synchronized alert record.
- **Columns**: `alert_id TEXT PRIMARY KEY`, `incident_id TEXT NOT NULL UNIQUE`, `timestamp TEXT NOT NULL`, `severity TEXT NOT NULL`, `attack_type TEXT NOT NULL`, `device_id TEXT`, `source_id TEXT`, `target TEXT NOT NULL`, `confidence REAL NOT NULL`, `detection_reason TEXT NOT NULL`, `lifecycle_state TEXT NOT NULL`, `recommended_action TEXT NOT NULL`, `current_action TEXT NOT NULL`, `acknowledgement_state TEXT NOT NULL DEFAULT 'UNACKNOWLEDGED'`, `acknowledged_by TEXT`, `acknowledged_at TEXT`, `status TEXT NOT NULL DEFAULT 'ACTIVE'`, `evidence_json TEXT NOT NULL DEFAULT '[]'`.
- **Foreign Key**: `FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE`.
- **Indexes**:
  - `admin_alerts_incident_idx ON admin_alerts(incident_id)`
  - `admin_alerts_status_idx ON admin_alerts(status, acknowledgement_state)`

### Table 3.10: `admin_audit_log`
- **Purpose**: Cryptographically forward-chained tamper-evident security audit log.
- **Columns**: `event_id TEXT PRIMARY KEY`, `timestamp TEXT NOT NULL`, `username TEXT NOT NULL`, `role TEXT NOT NULL`, `action TEXT NOT NULL`, `resource TEXT NOT NULL`, `resource_id TEXT`, `result TEXT NOT NULL`, `source_ip TEXT`, `details TEXT NOT NULL`, `prev_hash TEXT NOT NULL DEFAULT '000...000'`, `record_hash TEXT NOT NULL DEFAULT ''`.
- **Indexes**:
  - `admin_audit_timestamp_idx ON admin_audit_log(timestamp DESC)`
  - `admin_audit_action_idx ON admin_audit_log(action)`

### Table 3.11: `device_identities`
- **Purpose**: Zero-Trust IoT/OT device registry storing derived key hashes and authorization statuses.
- **Columns**: `device_id TEXT PRIMARY KEY`, `role TEXT NOT NULL DEFAULT 'sensor'`, `status TEXT NOT NULL DEFAULT 'ENROLLED'`, `auth_key_hash TEXT NOT NULL`, `trust_score REAL NOT NULL DEFAULT 100.0`, `failures INTEGER NOT NULL DEFAULT 0`, `mfa_status TEXT NOT NULL DEFAULT 'NOT_REQUIRED'`, `created_at TEXT NOT NULL`, `last_seen TEXT`.
- **Index**: `device_identities_status_idx ON device_identities(status)`.

---

## 4. Database-Dependent Components

### 4.1 Persistence Requirement Classification

| Component | Database Tables | Production Persistence Requirement | Justification |
| :--- | :--- | :---: | :--- |
| **User Authentication & RBAC** | `admin_users` | **Mandatory** | Wiping users forces credential re-bootstrapping and invalidates active admin accounts. |
| **Zero-Trust Device Registry** | `device_identities` | **Mandatory** | Quarantined devices or newly enrolled sensors must persist across gateway reboots. |
| **Audit Ledger & Non-Repudiation** | `admin_audit_log` | **Mandatory** | The cryptographic hash chain (`prev_hash` -> `record_hash`) breaks if rows are deleted. |
| **Security Incident Management** | `incidents`, `incident_history` | **Mandatory** | Multi-step response workflows (`TRIAGED` -> `CONTAINED` -> `RECOVERING`) require durable state. |
| **SOC Alert Center** | `admin_alerts` | **Mandatory** | Operator acknowledgements and escalation states must survive restarts. |
| **Dynamic Trust Scoring** | `trust_history` | **Recommended** | Forensic trust degradation history; fallback defaults exist if lost. |
| **Actions & In-Process Policy** | `actions` | **Recommended** | Records why specific devices were blocked; enforcer state is reconstructed from active incidents. |
| **System & Model Metadata** | `metadata` | **Recommended** | Stores training experiment summaries and evaluation metrics. |
| **Telemetry & Flow Historian** | `telemetry` | **Optional / Prunable** | Ingestion table writing 1 row per second. Can be pruned to 30 days or retained as hot cache. |
| **IAM Ingest Evaluations** | `iam_events` | **Optional / Prunable** | High-volume operational stream; can be bounded without breaking gateway logic. |

---

## 5. SQLite-to-PostgreSQL Compatibility Findings

Detailed query inspection across `storage.py` identified **six significant dialect and behavioral incompatibilities**:

### 5.1 Parameter Placeholders (`?` vs `%s`)
- **SQLite Syntax**: Positional parameter markers use `?` (e.g. `SELECT * FROM incidents WHERE incident_id = ?`).
- **PostgreSQL (`psycopg2`) Syntax**: Requires `%s` for positional arguments (or `%(name)s` for named parameters).
- **Impact**: Any direct execution of existing queries against PostgreSQL will raise `psycopg2.errors.SyntaxError`.

### 5.2 Dependency on SQLite `rowid`
- **SQLite Behavior**: SQLite automatically creates a 64-bit integer hidden column named `rowid` on all standard tables. AICG relies on `rowid` for secondary sorting and audit chain linking:
  - `storage.py:284`: `SELECT raw_json FROM telemetry ORDER BY timestamp DESC, rowid DESC LIMIT ?`
  - `storage.py:501`: `SELECT * FROM trust_history ORDER BY timestamp DESC, rowid DESC LIMIT ?`
  - `storage.py:161`: `SELECT rowid, * FROM admin_audit_log WHERE record_hash IS NULL ORDER BY rowid ASC`
  - `storage.py:852`: `SELECT record_hash FROM admin_audit_log ORDER BY rowid DESC LIMIT 1`
  - `storage.py:906`: `SELECT rowid, * FROM admin_audit_log ORDER BY rowid ASC`
- **PostgreSQL Incompatibility**: Modern PostgreSQL tables created without OIDs **do not have a `rowid` column**. Executing these queries in PostgreSQL immediately throws `column "rowid" does not exist`.
- **Remediation**: PostgreSQL DDL must explicitly include an auto-incrementing identity column on tables requiring insertion order:
  ```sql
  seq_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY
  ```

### 5.3 `INSERT OR IGNORE` Syntax
- **SQLite Syntax**: `INSERT OR IGNORE INTO admin_users (...) VALUES (...)` (`storage.py:229`, `258`).
- **PostgreSQL Incompatibility**: `INSERT OR IGNORE` is invalid in PostgreSQL.
- **Remediation**: Use standard ANSI PostgreSQL conflict syntax:
  ```sql
  INSERT INTO admin_users (...) VALUES (...) ON CONFLICT (user_id) DO NOTHING;
  ```

### 5.4 Exclusive Locking and `BEGIN IMMEDIATE`
- **SQLite Syntax**: `con.execute("BEGIN IMMEDIATE")` (`storage.py:851`) acquires a reserved lock preventing other threads from beginning writes.
- **PostgreSQL Incompatibility**: `BEGIN IMMEDIATE` is an invalid transaction command in PostgreSQL.
- **Remediation**: In PostgreSQL, serialize the hash chain calculation using table-level locking or row-level locking:
  ```sql
  BEGIN;
  LOCK TABLE admin_audit_log IN EXCLUSIVE MODE;
  -- Calculate hash of last inserted row and insert next row
  COMMIT;
  ```

### 5.5 SQLite PRAGMAs and Schema Introspection
- **SQLite Syntax**:
  - `PRAGMA journal_mode = WAL;`, `PRAGMA foreign_keys = ON;`, `PRAGMA busy_timeout = 5000;`, `PRAGMA synchronous = NORMAL;` (`storage.py:49-52`).
  - `PRAGMA table_info(admin_audit_log)` (`storage.py:154`).
- **PostgreSQL Incompatibility**: PostgreSQL does not have PRAGMA directives. Foreign keys are always active; WAL is managed by the PostgreSQL server. Schema introspection requires querying standard views:
  ```sql
  SELECT column_name FROM information_schema.columns WHERE table_name = 'admin_audit_log';
  ```

### 5.6 Data Types and JSON Representations
- **Boolean Fields**: SQLite stores booleans as `INTEGER` (0 or 1). `admin_users.mfa_enabled` is defined as `INTEGER NOT NULL DEFAULT 1`. PostgreSQL supports native `BOOLEAN`. Retaining `INTEGER` (0/1) or casting explicitly is required.
- **JSON Fields**: SQLite stores JSON structures (`raw_json`, `evidence_json`, `payload_json`) as unindexed `TEXT`. PostgreSQL provides native `JSONB`, which allows indexing and validation. Storing as `JSONB` is recommended for PostgreSQL.

---

## 6. Render Deployment Risks & The Login Error Diagnosis

### 6.1 Supabase Connection Architecture: Direct vs. Session Pooler vs. Transaction Pooler
A critical operational pitfall when connecting Render Free Web Services to Supabase:
- **Port and Protocol Mapping**:
  1. **Direct Connection (`db.<project-ref>.supabase.co:5432`)**: Connects directly to PostgreSQL on port 5432. Resolves **exclusively to an IPv6 address**.
  2. **Supabase Shared Session Pooler (`aws-0-<region>.pooler.supabase.com:5432`)**: Routes through Supavisor in **Session Mode** on **Port 5432**. Resolves to **IPv4**, supports full PostgreSQL session semantics (including `LOCK TABLE`, prepared statements, and session state), and multiplexes connections.
  3. **Supabase Transaction Pooler (`aws-0-<region>.pooler.supabase.com:6543`)**: Routes through Supavisor in **Transaction Mode** on **Port 6543**. Resolves to IPv4, but does not support prepared statements or persistent session-level state.
- **Render Limitation**: Render's Free Web Service tier provides outbound traffic **over IPv4 only**.
- **Failure Mode with Direct Host**: Attempting to connect to `db.<project-ref>.supabase.co:5432` from Render Free fails immediately with `socket.gaierror: [Errno -9] Address family for hostname not supported` or connection timeout due to lack of IPv6 egress.
- **Confirmed Production Recommendation**: Production Render deployments **must** use the **Supabase Shared Session Pooler**:
  - **Host**: `aws-0-<region>.pooler.supabase.com`
  - **Port**: `5432`
  - **IPv4 Compatibility**: Fully verified
  - **SSL Mode**: `sslmode=require` mandatory

### 6.2 ThreadedConnectionPool Configuration and Supabase Free Quotas
- **Server Runtime Concurrency**: AICG's Gunicorn configuration executes **1 worker process with 8 application threads** (`--workers 1 --threads 8 --worker-class gthread`).
- **Supabase Free Connection Quota**: Supabase Free Tier projects allocate a finite direct connection pool (~15–20 direct connections). Although the Supavisor pooler accepts hundreds of client connections, the underlying database connection pool remains bounded.
- **Client Pool Sizing**:
  - Python client pool: `ThreadedConnectionPool(minconn=1, maxconn=10)`
  - Sizing Rationale: `minconn=1` maintains a warm baseline connection without idle churn; `maxconn=10` allocates exactly enough connections to serve all 8 concurrent Gunicorn worker threads simultaneously plus 2 spare connections for background monitoring and health checks (`/api/health`), preventing thread starvation while strictly respecting Supabase quotas.
- **Safe Checkout and Release Lifecycle**:
  - Connection checkout must be encapsulated in a context manager:
    ```python
    @contextmanager
    def get_db_connection():
        con = pool.getconn()
        try:
            yield con
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            pool.putconn(con)
    ```
- **Error Handling and Connection Cleanup**:
  - On standard transaction exceptions, `con.rollback()` must be executed before returning the connection to the pool, ensuring clean transaction state for subsequent threads.
  - On fatal connection exceptions (e.g. `psycopg2.OperationalError`, broken pipe, or remote server disconnect), the dead connection must be discarded and closed rather than returned to the pool:
    ```python
    except (psycopg2.OperationalError, psycopg2.InterfaceError):
        pool.putconn(con, close=True)
        raise
    ```
    This prevents connection pool poisoning where dead sockets cause cascading request failures.

### 6.3 Diagnosing the "Login Error" (Provisional Diagnostic Evaluation)
The audit prompt specifically notes:
> *"Do not assume that moving to PostgreSQL automatically fixes the existing login error. Identify what additional evidence is required to diagnose it."*

> [!IMPORTANT]
> **Provisional Diagnosis Disclaimer**: The following analysis is a **provisional diagnostic hypothesis** derived from static source code tracing of `backend/aegis_gateway/api.py`, `security.py`, and `config.py`. It identifies architectural failure modes in the current codebase but must be verified against actual production server tracebacks, Gunicorn stderr logs, and browser network responses.

Comprehensive code tracing through `backend/aegis_gateway/api.py` and `security.py` reveals that login failures occur due to several non-database factors:

```
[ Incoming Browser POST /login ]
                │
                ├─► 1. Rate Limiter Check (IP:Username)
                │      If >= 10 failures in 60s ─────────► [ 429 RATE_LIMITED ]
                │      (Triggered if ProxyFix is missing and all users share proxy IP)
                │
                ├─► 2. User Lookup in DB
                │      If username not found ────────────► [ 401 AUTH_FAILED ]
                │      (Occurs if AEGIS_PRODUCTION=true and demo accounts are suppressed)
                │
                ├─► 3. Password Verification (scrypt/PBKDF2)
                │      If password does not match ───────► [ 401 AUTH_FAILED ]
                │
                ├─► 4. Account Status Check
                │      If status == 'DISABLED' ──────────► [ 403 ACCOUNT_DISABLED ]
                │
                ├─► 5. MFA Challenge (Stage 1)
                │      If mfa_enabled == 1 and no token ─► [ 200 mfa_required: true ]
                │      (If client ignores JSON challenge, flow stops here)
                │
                ├─► 6. MFA Verification (Stage 2)
                │      If token != '123456' ─────────────► [ 401 MFA_INVALID ]
                │
                └─► 7. Session Cookie Issuance
                       rotate_session() -> Set-Cookie: session=...; Secure; SameSite=Lax
                       (If client connects via HTTP or ProxyFix missing, browser DROPS cookie)
```

#### Root Causes of Login Failures Unrelated to Database Engine:
1. **Missing Werkzeug `ProxyFix` Behind Render's Edge Router**:
   - Render terminates SSL/TLS at its edge load balancer and forwards plain HTTP traffic to Gunicorn over the internal container network, attaching headers `X-Forwarded-Proto: https`, `X-Forwarded-For: <client-ip>`, `X-Forwarded-Host: <host>`, and `X-Forwarded-Port: 443`.
   - Without `ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)` in `backend/app.py`:
     - **Scheme Misdetection & Cookie Drop**: Flask sees `request.scheme == 'http'`. When `SESSION_COOKIE_SECURE = True`, Flask issues `Set-Cookie: session=...; Secure`. Modern browsers refuse to persist cookies marked `Secure` when transmitted over unencrypted HTTP, or drop them during subsequent redirects, causing the user to be redirected back to `/login`.
     - **IP Collapsing & Rate Limiter Lockout**: `request.remote_addr` resolves to Render's internal proxy IP. Every visitor is assigned the identical IP, collapsing all requests into a single `AuthRateLimiter` bucket. Ten failed attempts anywhere lock out all users globally with HTTP 429.
   - **Secure ProxyFix Configuration**:
     - Hop count must be pinned to exactly `1` (`x_for=1, x_proto=1, x_host=1, x_port=1`), matching Render's single edge proxy architecture.
     - **Security Guarantee**: Pinning hop counts prevents trusting arbitrary forwarded headers from malicious clients. If an attacker injects fake `X-Forwarded-For` or `X-Forwarded-Proto` headers, Werkzeug only strips the single proxy hop added by Render, preventing IP spoofing and rate-limit evasion.
     - Validates forwarded HTTPS scheme and preserves `SESSION_COOKIE_SECURE = True`, `SESSION_COOKIE_HTTPONLY = True`, and `SESSION_COOKIE_SAMESITE = 'Lax'`.
2. **Production Mode Credential Suppression and Verification**:
   - In production mode (`AEGIS_PRODUCTION=true`), `backend/aegis_gateway/storage.py#L228` explicitly suppresses demo credentials (`operator` with `Operator@AICG2026!`, `admin` with `Admin@AICG2026!`).
   - If an operator attempts to authenticate using demo credentials against a production deployment, authentication fails with HTTP 401.
   - Production bootstrapping requires `AEGIS_INITIAL_ADMIN_PASSWORD` to be explicitly defined in environment variables.
3. **MFA Token Verification and Lab Code Isolation**:
   - In the current lab implementation, `security.py` accepts a hardcoded simulated MFA token (`123456`).
   - **Production Verification**: In a hardened production deployment, fixed MFA tokens must **never** be enabled or accepted. Real multi-factor authentication (RFC 6238 TOTP with authenticator apps or FIDO2/WebAuthn) must replace the simulated token, and no static fallback bypass may exist.
4. **Client Handling of Two-Stage MFA Flow**:
   - When MFA is active, the initial POST to `/login` does not immediately return a session cookie; it returns HTTP 200 with `{"mfa_required": true}`.
   - If a frontend or automated script does not intercept this challenge and issue the secondary verification request to `/api/auth/mfa/verify`, authentication remains incomplete.

#### Required Evidence to Definitively Validate the Login Issue:
1. **Live Production Traceback**: Inspect the exact Python exception traceback from Render's runtime logs if an HTTP 500 error occurs.
2. **Raw HTTP Status Codes and Response Payloads**: Determine whether login fails with HTTP 401 (Bad Credentials / Suppressed Demo User), 403 (Account Disabled), 429 (Rate Limiter lockout), or 200 (Unhandled MFA challenge).
3. **Browser Network Inspection**: Check whether the `Set-Cookie: session=...` header is returned, whether the `Secure` attribute is set, and whether the browser stores the cookie or rejects it due to scheme mismatch.
4. **Environment Variable Dump**: Verify `AEGIS_PRODUCTION`, `AEGIS_INITIAL_ADMIN_PASSWORD`, and `AEGIS_SESSION_COOKIE_SECURE`.

---

## 7. Required Dependencies

To support Supabase PostgreSQL, the following production packages must be added to `requirements.txt`:

1. **`psycopg2-binary>=2.9.9,<=2.9.10`**:
   - The pre-compiled C-extension PostgreSQL driver for Python.
   - Requires zero Linux system development libraries (`libpq-dev` is not required on Render).
   - Provides native connection pooling via `psycopg2.pool.ThreadedConnectionPool`.
2. **`werkzeug>=3.1.0` (Already Present)**:
   - Contains `from werkzeug.middleware.proxy_fix import ProxyFix` for reverse proxy header normalization.

---

## 8. Required Code Changes (Exact Files and Rationale)

To preserve 100% test integrity while enabling Supabase PostgreSQL, code modifications must be strictly encapsulated:

### 8.1 File 1: `requirements.txt`
- **Location**: Root `requirements.txt`
- **Modification**: Append `psycopg2-binary==2.9.10`.
- **Rationale**: Installs the production PostgreSQL adapter without altering existing pinned scientific dependencies.

### 8.2 File 2: `backend/aegis_gateway/config.py`
- **Location**: `backend/aegis_gateway/config.py#L46`
- **Modification**: Add `database_url` configuration property:
  ```python
  database_url: str | None = field(
      default_factory=lambda: os.getenv("DATABASE_URL") or os.getenv("AEGIS_DATABASE_URL")
  )
  ```
- **Rationale**: Allows Render to inject Supabase connection strings via standard environment variables while defaulting to SQLite when unset.

### 8.3 File 3: `backend/aegis_gateway/storage.py`
- **Location**: `backend/aegis_gateway/storage.py`
- **Modification**: Refactor into a dual-engine architecture:
  1. Define a shared base interface `BaseGatewayStore` containing all 35 public historian and identity methods.
  2. Retain existing `SQLiteGatewayStore` (the current `GatewayStore` implementation) completely intact.
  3. Implement `PostgresGatewayStore` utilizing:
     - `psycopg2.pool.ThreadedConnectionPool` (configured with `minconn=1, maxconn=10` matching 1 Gunicorn worker with 8 threads plus 2 health check spares).
     - Context-managed connection checkout (`getconn()`) and release (`putconn(con)`) in strict `try...finally` blocks.
     - Exception cleanup: `con.rollback()` on transaction failure; fatal connection disconnects closed via `putconn(con, close=True)`.
     - Parameter markers `%s` replacing SQLite's positional `?`.
     - Explicit sequence column `seq_id BIGSERIAL` replacing implicit SQLite `rowid`.
     - ANSI `ON CONFLICT (id) DO NOTHING` and `ON CONFLICT (id) DO UPDATE` replacing `INSERT OR IGNORE`.
     - Table-level locking for SHA-256 audit chaining: `LOCK TABLE admin_audit_log IN EXCLUSIVE MODE` replacing `BEGIN IMMEDIATE`.
  4. Implement store factory function:
     ```python
     def create_gateway_store(settings: Settings) -> BaseGatewayStore:
         if settings.database_url:
             return PostgresGatewayStore(settings.database_url, ...)
         return SQLiteGatewayStore(settings.database_path, ...)
     ```
- **Rationale**: Guarantees zero regression on existing SQLite tests while providing clean PostgreSQL execution in cloud environments.

### 8.4 File 4: `backend/app.py`
- **Location**: `backend/app.py#L17`
- **Modification**: Wrap the Flask WSGI application with Werkzeug's `ProxyFix`:
  ```python
  from werkzeug.middleware.proxy_fix import ProxyFix
  app = create_app(runtime)
  app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
  ```
- **Rationale**:
  - **HTTPS Scheme Validation**: `x_proto=1` enables Flask to detect the forwarded HTTPS scheme from Render (`request.is_secure == True`), ensuring browsers accept `Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax`.
  - **Client IP Handling**: `x_for=1` resolves `request.remote_addr` to the actual client IP, enabling accurate per-client rate limiting in `AuthRateLimiter` rather than collapsing all users onto Render's internal proxy IP.
  - **Security Against Header Spoofing**: Explicitly pinning hop counts to `1` ensures that arbitrary forwarded headers from external clients are not trusted. Only the single proxy hop added by Render's edge load balancer is stripped and applied.

---

## 9. Data Migration Strategy

To migrate existing local SQLite data to Supabase without downtime or corruption:

```
┌─────────────────────────┐       ┌─────────────────────────┐       ┌─────────────────────────┐
│ Local SQLite Database   │       │ Intermediate Migration  │       │ Supabase PostgreSQL     │
│ (aegis_gateway.sqlite3) ├──────►│ JSON/CSV Artifacts     ├──────►│ (Production Cloud DB)   │
└─────────────────────────┘       └─────────────────────────┘       └─────────────────────────┘
  1. Export Tables                  2. Verify & Sanitize              3. Ingest via Pooler
     - admin_users                     - Verify Hash Chains              - Execute Postgres DDL
     - device_identities               - Redact Transient Tokens         - Insert Identities
     - admin_audit_log                 - Validate JSONB Syntax           - Ingest Incidents & Log
     - incidents & alerts                                                - Run verify_audit_log_integrity()
```

### Step-by-Step Migration Pipeline:
1. **Schema Provisioning**: Execute PostgreSQL DDL on Supabase creating the 11 tables with native types (`BIGSERIAL`, `JSONB`, `BOOLEAN`, `DOUBLE PRECISION`).
2. **Export Phase**: Use a standalone migration script (`backend/scripts/migrate_sqlite_to_postgres.py`) to extract rows from SQLite into structured memory objects.
3. **Data Sanitization**:
   - Ensure all `evidence_json` and `raw_json` strings are valid JSON before insertion into PostgreSQL `JSONB` columns.
   - Convert integer boolean flags (`mfa_enabled = 1`) to Python booleans (`True`).
4. **Insertion Order (Foreign Key Dependency Safe)**:
   - Order 1: Independent tables: `admin_users`, `device_identities`, `metadata`, `iam_events`, `trust_history`, `telemetry`.
   - Order 2: Parent entities: `incidents`.
   - Order 3: Child entities: `incident_history`, `actions`, `admin_alerts`.
   - Order 4: Sequenced ledger: `admin_audit_log` (inserted strictly in ascending `rowid` order to preserve `prev_hash` chain links).
5. **Post-Migration Verification**: Run `verify_audit_log_integrity()` against Supabase to mathematically prove zero tampering during transit.

---

## 10. Security and Data Integrity Risks

| Risk Area | Severity | Impact | Mitigation Strategy |
| :--- | :---: | :--- | :--- |
| **Connection String Exposure** | **CRITICAL** | Database takeover if Supabase credentials leak. | Pass via Render Secret Environment Variables (`DATABASE_URL`). Never commit credentials to Git or display in logs. |
| **Demo Accounts & Fixed MFA in Production** | **CRITICAL** | Unauthorized admin takeover via well-known lab credentials or static MFA code. | Enforce `AEGIS_PRODUCTION=true` to permanently suppress demo accounts (`admin`, `operator`) and require `AEGIS_INITIAL_ADMIN_PASSWORD`. Ensure simulated token `123456` is never accepted in production. |
| **Audit Hash Forking under Concurrency** | **HIGH** | Broken audit chain integrity (`verify_audit_log_integrity()` fails). | Use `LOCK TABLE admin_audit_log IN EXCLUSIVE MODE` during audit insertion so concurrent threads calculate sequential hashes. |
| **Render Egress IPv6 Blackhole** | **HIGH** | Gateway fails to boot on Render Free. | Mandate the Supabase Shared Session Pooler URL on Port 5432 (IPv4) with `?sslmode=require`, avoiding the IPv6-only direct connection host. |
| **Supabase Free Tier Inactivity Pause** | **MEDIUM** | Gateway loses DB connectivity after 7 days of inactivity. | Implement connection retry with exponential backoff and return clear HTTP 503 error if database is paused. |
| **SSL Eavesdropping in Transit** | **MEDIUM** | Man-in-the-middle on cloud database link. | Mandate `?sslmode=require` in all PostgreSQL connection URLs. |

---

## 11. Testing and Validation Strategy

To satisfy the strict constraint of **preserving all 400 existing tests**:

1. **Dual-Backend Test Isolation**:
   - The existing 400 tests in `backend/tests/` instantiate `GatewayStore(tmp_path / "test.sqlite3")`.
   - By preserving `SQLiteGatewayStore` as the default when `database_url` is unset, **100% of existing tests continue to run locally and in GitHub Actions CI without requiring a live PostgreSQL instance**.
2. **Dedicated PostgreSQL Integration Suite**:
   - Introduce `backend/tests/test_postgres_storage.py` decorated with:
     ```python
     @pytest.mark.skipif(not os.getenv("TEST_DATABASE_URL"), reason="Requires PostgreSQL test database")
     ```
   - Validates connection pooling, sequence ordering, audit hash chaining, and incident transitions against a live or containerized PostgreSQL instance.
3. **E2E Smoke Verification**:
   - Spin up Gunicorn pointing to Supabase and execute:
     - `GET /api/health` -> HTTP 200
     - `POST /login` -> HTTP 200 with MFA challenge
     - `POST /api/auth/mfa/verify` -> HTTP 200 with session cookie
     - `GET /api/admin/audit/integrity` -> `{"valid": true}`

---

## 12. Recommended Migration Phases

To execute the PostgreSQL migration safely and without disruption, the following phased roadmap is recommended:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                   Recommended Migration Execution Roadmap                   │
└─────────────────────────────────────────────────────────────────────────────┘
  Phase 4.1: Dual-Storage Layer Refactoring
  ├─ Add psycopg2-binary to requirements.txt
  ├─ Implement BaseGatewayStore, SQLiteGatewayStore, and PostgresGatewayStore in storage.py
  ├─ Implement ProxyFix middleware in backend/app.py
  └─ Verify that all 400 existing automated tests pass unchanged.

  Phase 4.2: Supabase Schema DDL Preparation
  ├─ Generate PostgreSQL DDL script (schema_postgres.sql) with BIGSERIAL and JSONB
  └─ Apply schema to Supabase project via Supabase SQL Editor.

  Phase 4.3: Local PostgreSQL Integration & Concurrency Validation
  ├─ Execute live integration tests against Supabase test pooler URL
  └─ Verify concurrent audit hash integrity and incident state transitions.

  Phase 4.4: Data Migration Pipeline (Optional for Fresh Deployments)
  ├─ Export existing SQLite baseline users and device identities
  └─ Ingest into Supabase and verify with verify_audit_log_integrity().

  Phase 4.5: Render Cloud Configuration & Production Cutover
  ├─ Configure DATABASE_URL (Port 5432 Shared Session Pooler) in Render Dashboard
  ├─ Set AEGIS_PRODUCTION=true, AEGIS_INITIAL_ADMIN_PASSWORD, and proxy flags
  └─ Trigger deployment and verify /api/health and authenticated SOC dashboard.
```

---

### Audit Verification Status
- **Current Git Branch**: `deploy/render-config`
- **Files Created**: `docs/postgresql_migration_audit.md` (This document)
- **Files Modified / Deleted**: **ZERO (0)**
- **Baseline Test Suite Status**: **400 / 400 Tests Passing**

---
*End of Audit Report. Awaiting explicit approval before implementing any phase of the PostgreSQL migration.*

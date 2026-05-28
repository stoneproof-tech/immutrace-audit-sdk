"""SQLite event store + schema."""
import aiosqlite
import sqlite3
from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    case_id TEXT,
    activity_type TEXT,
    justification TEXT,
    ts TEXT NOT NULL,                 -- ISO-8601 UTC
    event_type TEXT NOT NULL,         -- http_request, auth_grant, etc.
    method TEXT,
    path TEXT,
    query TEXT,
    body_sha256 TEXT,
    response_status INTEGER,
    response_sha256 TEXT,
    remote_ip TEXT,
    user_agent TEXT,
    prev_hash TEXT NOT NULL,
    this_hash TEXT NOT NULL UNIQUE,
    anchor_id INTEGER REFERENCES anchors(id)
);

CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_case ON events(case_id);
CREATE INDEX IF NOT EXISTS idx_events_anchor ON events(anchor_id);

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    actor TEXT NOT NULL,
    case_id TEXT,
    activity_type TEXT,
    justification TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS anchors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    merkle_root TEXT NOT NULL,
    event_count INTEGER NOT NULL,
    first_event_id INTEGER NOT NULL,
    last_event_id INTEGER NOT NULL,
    submitted_at TEXT NOT NULL,
    chain TEXT NOT NULL,              -- 'polygon-amoy' or 'mock'
    tx_hash TEXT,
    block_number INTEGER,
    confirmed INTEGER DEFAULT 0
);

-- ── Identity (Step 2) ──────────────────────────────────────────────────────
-- NOTE: the legacy `sessions` table above is the *investigation* session
-- (justification-bound authorization context, kept for backward compat).
-- `login_sessions` below is the *authentication* session (who is logged in) —
-- a deliberately separate table to avoid colliding with the legacy schema.
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('analyst','supervisor','admin','custodian')),
    full_name TEXT,
    email TEXT,
    created_at TEXT NOT NULL,
    last_login_at TEXT,
    active INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

CREATE TABLE IF NOT EXISTS login_sessions (
    id TEXT PRIMARY KEY,                 -- uuid hex
    user_id INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT,
    revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_login_sessions_user ON login_sessions(user_id);

-- ── Approval workflow (Step 3, pre-authorization model) ────────────────────
-- Analyst requests access to a sensitive endpoint prefix; a supervisor approves
-- (granting time-boxed authorization) or rejects. Decisions are also written to
-- the hash chain as auditable events.
CREATE TABLE IF NOT EXISTS approval_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    requester_user_id INTEGER NOT NULL REFERENCES users(id),
    requested_at TEXT NOT NULL,
    endpoint_prefix TEXT NOT NULL,
    justification TEXT NOT NULL,
    case_id TEXT,
    urgency TEXT NOT NULL DEFAULT 'normal' CHECK(urgency IN ('low','normal','high')),
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected','expired')),
    supervisor_user_id INTEGER REFERENCES users(id),
    decided_at TEXT,
    decision_note TEXT,
    expires_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_approval_status ON approval_requests(status);
CREATE INDEX IF NOT EXISTS idx_approval_requester ON approval_requests(requester_user_id);

-- ── Shamir key custody (Step 4) ────────────────────────────────────────────
-- The master key (used by AES-GCM in Step 5) is never stored in plaintext: it
-- is split k-of-n across custodians. Each custodian holds an RSA keypair; their
-- Shamir fragment is stored RSA-encrypted to their public key. Reconstruction
-- needs k custodians and happens in RAM only (master key never persisted).
CREATE TABLE IF NOT EXISTS custodians (
    id INTEGER PRIMARY KEY,              -- Shamir share index (1-based)
    name TEXT NOT NULL,
    role_label TEXT NOT NULL,            -- e.g. notaio / avvocato / revisore
    username TEXT,                       -- linked login user (role 'custodian')
    public_pem TEXT NOT NULL,
    is_local INTEGER NOT NULL DEFAULT 1  -- 1 = local simulated, 0 = remote/real
);

CREATE TABLE IF NOT EXISTS key_shards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    custodian_id INTEGER NOT NULL REFERENCES custodians(id),
    share_index INTEGER NOT NULL,
    share_data_encrypted BLOB NOT NULL,  -- RSA-OAEP(indexed fragment) to custodian pubkey
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked'))
);
CREATE INDEX IF NOT EXISTS idx_key_shards_custodian ON key_shards(custodian_id);

CREATE TABLE IF NOT EXISTS key_reassembly_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    requester_user_id INTEGER NOT NULL REFERENCES users(id),
    requested_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','complete','failed')),
    shares_collected INTEGER NOT NULL DEFAULT 0,
    threshold INTEGER NOT NULL,
    completed_at TEXT
);

-- Singleton metadata for the current master key: a SHA-256 of the key lets us
-- verify a reassembly reconstructed the SAME key (detects fake/corrupted shares).
-- The key itself is NEVER stored — only its hash.
CREATE TABLE IF NOT EXISTS key_meta (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    master_sha256 TEXT NOT NULL,
    threshold INTEGER NOT NULL,
    num_shares INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

-- ── Per-record encryption keys (Step 5, AES-GCM + crypto-erasure) ───────────
-- Each encrypted event gets a random AES key, itself wrapped by the master key.
-- GDPR Art.17 erasure = destroy the wrapped key (wrapped_key -> NULL): the
-- ciphertext (and the hash chain over it) stay intact, but the plaintext becomes
-- permanently unrecoverable.
CREATE TABLE IF NOT EXISTS record_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    record_table TEXT NOT NULL,
    record_id INTEGER NOT NULL,
    wrapped_key BLOB,                 -- AES-GCM(master, per-record key); NULL once erased
    wrap_nonce BLOB,
    created_at TEXT NOT NULL,
    erased_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_record_keys_ref ON record_keys(record_table, record_id);

-- ── Event timestamps (Step 6, eIDAS-ready) ─────────────────────────────────
-- Each timestamped event gets a signed time token committing to its this_hash.
-- provider 'local' = IMMUTRACE-native signed timestamp (NOT eIDAS-qualified);
-- QTSP providers produce qualified RFC-3161 tokens (is_qualified=1) once active.
CREATE TABLE IF NOT EXISTS event_timestamps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL REFERENCES events(id),
    provider_name TEXT NOT NULL,
    token BLOB NOT NULL,
    timestamp_iso TEXT NOT NULL,
    is_qualified INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    verified_at TEXT,
    verification_status TEXT
);
CREATE INDEX IF NOT EXISTS idx_event_timestamps_event ON event_timestamps(event_id);

-- ── Anchor worker error log (Step 7.6, unattended-operation hardening) ──────
CREATE TABLE IF NOT EXISTS anchor_errors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    error_msg TEXT NOT NULL,
    retry_count INTEGER NOT NULL
);
"""


def init_sync():
    """Create schema synchronously at startup."""
    conn = sqlite3.connect(str(config.DB_PATH))
    # WAL lets readers (dashboard, verify) run without blocking the single chain
    # writer, and vice-versa — important when the browser hammers the proxy with
    # parallel asset requests during a demo.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.executescript(SCHEMA)
    # Idempotent additive migration: extend the existing anchors table (Step 7).
    for col, decl in (("gas_used", "INTEGER"), ("chain_id", "INTEGER"), ("status", "TEXT")):
        try:
            conn.execute(f"ALTER TABLE anchors ADD COLUMN {col} {decl}")
        except sqlite3.OperationalError:
            pass  # column already exists
    conn.commit()
    conn.close()


async def get_conn():
    """Async sqlite connection (caller must close)."""
    conn = await aiosqlite.connect(str(config.DB_PATH))
    conn.row_factory = aiosqlite.Row
    return conn


async def last_hash() -> str:
    """Return the hash of the most recent event (or genesis if empty)."""
    conn = await get_conn()
    try:
        async with conn.execute(
            "SELECT this_hash FROM events ORDER BY id DESC LIMIT 1"
        ) as cur:
            row = await cur.fetchone()
            return row["this_hash"] if row else "0" * 64
    finally:
        await conn.close()

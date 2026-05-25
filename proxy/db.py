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

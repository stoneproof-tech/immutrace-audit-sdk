"""Legacy investigation-session authorization (DEPRECATED).

⚠️ DEPRECATED — single-user "investigation session" model (justification → blanket
access to all sensitive endpoints, no login). Superseded in Step 2/3 by multi-user
login (identity.py) + supervisor approval workflow (workflow.py). Retained ONLY as a
backward-compatible fallback and because the base smoke test still uses it.

TODO (Step 9 follow-up): remove this module and the legacy gate branch in
proxy.handle_proxy_request once the smoke / e2e_encryption / e2e_timestamp suites
are migrated to the login + approval flow. Tracked as a deliberate, tested change
(not done now to avoid regressing the 146-test suite at the wire).
"""
import uuid
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from . import config

COOKIE_NAME = "__immutrace_session"


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def create_session(
    actor: str,
    case_id: Optional[str],
    activity_type: str,
    justification: str,
    ttl_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    """Create a new investigation session, returning the session record."""
    ttl = ttl_seconds if ttl_seconds is not None else config.AUTH_TTL
    sid = uuid.uuid4().hex
    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=ttl)
    rec = {
        "session_id": sid,
        "actor": actor,
        "case_id": case_id or "",
        "activity_type": activity_type,
        "justification": justification,
        "created_at": now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "expires_at": expires.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "revoked": 0,
    }
    conn = sqlite3.connect(str(config.DB_PATH))
    try:
        conn.execute(
            "INSERT INTO sessions(session_id, actor, case_id, activity_type, "
            "justification, created_at, expires_at, revoked) "
            "VALUES (?,?,?,?,?,?,?,0)",
            (rec["session_id"], rec["actor"], rec["case_id"], rec["activity_type"],
             rec["justification"], rec["created_at"], rec["expires_at"]),
        )
        conn.commit()
    finally:
        conn.close()
    return rec


def get_session(session_id: Optional[str]) -> Optional[Dict[str, Any]]:
    """Look up an active session; returns None if missing/expired/revoked."""
    if not session_id:
        return None
    conn = sqlite3.connect(str(config.DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.execute(
            "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
        )
        row = cur.fetchone()
        if not row:
            return None
        if row["revoked"]:
            return None
        try:
            expires = datetime.strptime(row["expires_at"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        except Exception:
            return None
        if datetime.now(timezone.utc) > expires:
            return None
        return dict(row)
    finally:
        conn.close()


def revoke_session(session_id: str) -> None:
    conn = sqlite3.connect(str(config.DB_PATH))
    try:
        conn.execute("UPDATE sessions SET revoked = 1 WHERE session_id = ?", (session_id,))
        conn.commit()
    finally:
        conn.close()


def is_sensitive_path(path: str) -> bool:
    """Path matches one of the sensitive prefixes from config."""
    return any(path.startswith(p) for p in config.SENSITIVE_PREFIXES)

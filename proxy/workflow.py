"""Query-approval workflow (Step 3, pre-authorization model A).

Flow: an analyst requests access to a sensitive endpoint prefix → a supervisor
approves (granting time-boxed authorization) or rejects. The gate in proxy.py
then lets the analyst through for that prefix while the approval is active.
Approve/reject decisions are also written to the hash chain (auditable actions).
"""
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List

from fastapi import APIRouter, Request, HTTPException, Depends
from pydantic import BaseModel

from . import config, identity

APPROVAL_TTL = config._env_int("APPROVAL_TTL_SECONDS", 3600)  # 1h default
MIN_JUSTIFICATION = 10
URGENCIES = ("low", "normal", "high")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(config.DB_PATH), timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


# ── Logic ───────────────────────────────────────────────────────────────────
def create_request(user_id: int, target_path: str, justification: str,
                   case_id: str, urgency: str) -> Dict[str, Any]:
    prefix = config.matched_prefix(target_path)
    if not prefix:
        raise ValueError("path is not a sensitive endpoint")
    conn = _conn()
    try:
        cur = conn.execute(
            "INSERT INTO approval_requests(requester_user_id, requested_at, endpoint_prefix, "
            "justification, case_id, urgency, status) VALUES (?,?,?,?,?,?,'pending')",
            (user_id, _iso(_now()), prefix, justification, case_id or "", urgency),
        )
        conn.commit()
        rid = cur.lastrowid
        return dict(conn.execute("SELECT * FROM approval_requests WHERE id = ?", (rid,)).fetchone())
    finally:
        conn.close()


def _rows(sql: str, params=()) -> List[Dict[str, Any]]:
    conn = _conn()
    try:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


def list_pending() -> List[Dict[str, Any]]:
    return _rows(
        "SELECT r.*, u.username AS requester FROM approval_requests r "
        "JOIN users u ON u.id = r.requester_user_id WHERE r.status = 'pending' "
        "ORDER BY CASE r.urgency WHEN 'high' THEN 0 WHEN 'normal' THEN 1 ELSE 2 END, r.requested_at")


def list_my(user_id: int) -> List[Dict[str, Any]]:
    return _rows("SELECT * FROM approval_requests WHERE requester_user_id = ? "
                 "ORDER BY requested_at DESC LIMIT 100", (user_id,))


def get_request(rid: int) -> Optional[Dict[str, Any]]:
    rows = _rows("SELECT * FROM approval_requests WHERE id = ?", (rid,))
    return rows[0] if rows else None


def approve(rid: int, supervisor_id: int, note: str, ttl_seconds: Optional[int]) -> Dict[str, Any]:
    req = get_request(rid)
    if not req:
        raise LookupError("request not found")
    if req["status"] != "pending":
        raise ValueError(f"request is {req['status']}, not pending")
    if req["requester_user_id"] == supervisor_id:
        # separation of duties: you cannot approve your own request
        raise PermissionError("cannot approve your own request")
    ttl = ttl_seconds if (ttl_seconds and ttl_seconds > 0) else APPROVAL_TTL
    expires = _iso(_now() + timedelta(seconds=ttl))
    conn = _conn()
    try:
        conn.execute(
            "UPDATE approval_requests SET status='approved', supervisor_user_id=?, "
            "decided_at=?, decision_note=?, expires_at=? WHERE id=?",
            (supervisor_id, _iso(_now()), note or "", expires, rid),
        )
        conn.commit()
    finally:
        conn.close()
    return get_request(rid)


def reject(rid: int, supervisor_id: int, note: str) -> Dict[str, Any]:
    req = get_request(rid)
    if not req:
        raise LookupError("request not found")
    if req["status"] != "pending":
        raise ValueError(f"request is {req['status']}, not pending")
    conn = _conn()
    try:
        conn.execute(
            "UPDATE approval_requests SET status='rejected', supervisor_user_id=?, "
            "decided_at=?, decision_note=? WHERE id=?",
            (supervisor_id, _iso(_now()), note or "", rid),
        )
        conn.commit()
    finally:
        conn.close()
    return get_request(rid)


def active_authorization(user_id: int, path: str) -> Optional[Dict[str, Any]]:
    """Return an approved, non-expired request authorizing this user for this
    path (longest matching prefix), or None. Lazily marks expired ones."""
    conn = _conn()
    try:
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM approval_requests WHERE requester_user_id=? AND status='approved'",
            (user_id,)).fetchall()]
        now = _now()
        match = None
        for r in rows:
            exp = _parse(r["expires_at"])
            if exp and now > exp:
                conn.execute("UPDATE approval_requests SET status='expired' WHERE id=?", (r["id"],))
                continue
            if path.startswith(r["endpoint_prefix"]):
                if match is None or len(r["endpoint_prefix"]) > len(match["endpoint_prefix"]):
                    match = r
        conn.commit()
        return match
    finally:
        conn.close()


# ── FastAPI router ────────────────────────────────────────────────────────
router = APIRouter(prefix="/_immutrace/approval")


class RequestReq(BaseModel):
    target_path: str
    justification: str
    case_id: str = ""
    urgency: str = "normal"


class ApproveReq(BaseModel):
    note: str = ""
    ttl_seconds: Optional[int] = None


class RejectReq(BaseModel):
    note: str = ""


async def _log_decision(request: Request, supervisor: dict, req: dict, event_type: str):
    """Record an approve/reject decision in the hash chain (auditable action)."""
    from . import proxy as proxy_mod  # lazy import to avoid circular import
    session = {
        "session_id": "login:" + str(supervisor["user_id"]),
        "actor": supervisor["username"],
        "case_id": req.get("case_id") or "",
        "activity_type": "APPROVAL_DECISION",
        "justification": req.get("decision_note") or "",
    }
    ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or (
        request.client.host if request.client else "unknown")
    await proxy_mod.log_event(
        session=session, event_type=event_type, method="POST",
        path=f"/_immutrace/approval/{req['id']}/{event_type.split('_')[-1]}",
        query="", body_bytes=b"", response_status=200, response_bytes=b"",
        remote_ip=ip, user_agent=request.headers.get("user-agent", ""),
    )


@router.post("/request")
async def create(req: RequestReq, request: Request, user: dict = Depends(identity.require_user)):
    if len(req.justification.strip()) < MIN_JUSTIFICATION:
        raise HTTPException(400, f"justification must be at least {MIN_JUSTIFICATION} characters")
    if req.urgency not in URGENCIES:
        raise HTTPException(400, f"urgency must be one of {URGENCIES}")
    try:
        row = create_request(user["user_id"], req.target_path, req.justification.strip(),
                             req.case_id.strip(), req.urgency)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"id": row["id"], "status": row["status"], "endpoint_prefix": row["endpoint_prefix"]}


@router.get("/queue")
async def queue(_: dict = Depends(identity.require_supervisor)):
    return {"pending": list_pending()}


@router.get("/my")
async def my(user: dict = Depends(identity.require_user)):
    return {"requests": list_my(user["user_id"])}


@router.post("/{rid}/approve")
async def do_approve(rid: int, body: ApproveReq, request: Request,
                     sup: dict = Depends(identity.require_supervisor)):
    try:
        row = approve(rid, sup["user_id"], body.note, body.ttl_seconds)
    except LookupError:
        raise HTTPException(404, "request not found")
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(409, str(e))
    await _log_decision(request, sup, row, "approval_approved")
    return {"id": row["id"], "status": row["status"], "expires_at": row["expires_at"]}


@router.post("/{rid}/reject")
async def do_reject(rid: int, body: RejectReq, request: Request,
                    sup: dict = Depends(identity.require_supervisor)):
    try:
        row = reject(rid, sup["user_id"], body.note)
    except LookupError:
        raise HTTPException(404, "request not found")
    except ValueError as e:
        raise HTTPException(409, str(e))
    await _log_decision(request, sup, row, "approval_rejected")
    return {"id": row["id"], "status": row["status"]}

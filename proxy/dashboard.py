"""Dashboard + audit API + PDF export routes."""
import sqlite3
import json
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, Request, Response, HTTPException, Depends
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse, RedirectResponse
from pydantic import BaseModel
from . import config, auth, identity, encryption
from .chain import verify_chain

router = APIRouter(prefix="/_immutrace")

ROOT = Path(__file__).resolve().parent.parent
DASHBOARD_DIR = ROOT / "dashboard"


# ─── Authorization endpoints ────────────────────────────────────────────

class SessionStartRequest(BaseModel):
    actor: str
    activity_type: str
    justification: str
    case_id: Optional[str] = ""


@router.post("/session/start")
async def session_start(req: SessionStartRequest):
    if len(req.justification.strip()) < 20:
        raise HTTPException(400, "Justification must be at least 20 characters.")
    if req.activity_type not in ("OSINT_RESEARCH", "INVESTIGATION", "ROUTINE_MONITORING"):
        raise HTTPException(400, "Invalid activity_type.")
    if not req.actor.strip():
        raise HTTPException(400, "Actor name required.")

    rec = auth.create_session(
        actor=req.actor.strip(),
        case_id=(req.case_id or "").strip() or None,
        activity_type=req.activity_type,
        justification=req.justification.strip(),
    )
    resp = JSONResponse({
        "session_id": rec["session_id"],
        "expires_at": rec["expires_at"],
        "actor": rec["actor"],
        "case_id": rec["case_id"],
        "activity_type": rec["activity_type"],
    })
    resp.set_cookie(
        key=auth.COOKIE_NAME,
        value=rec["session_id"],
        max_age=config.AUTH_TTL,
        httponly=True,
        samesite="lax",
        path="/",
    )
    return resp


@router.get("/session/current")
async def session_current(request: Request):
    sid = request.cookies.get(auth.COOKIE_NAME)
    sess = auth.get_session(sid)
    if not sess:
        return {"active": False}
    return {
        "active": True,
        "session_id": sess["session_id"],
        "actor": sess["actor"],
        "case_id": sess["case_id"],
        "activity_type": sess["activity_type"],
        "justification": sess["justification"],
        "expires_at": sess["expires_at"],
    }


@router.post("/session/end")
async def session_end(request: Request):
    sid = request.cookies.get(auth.COOKIE_NAME)
    if sid:
        auth.revoke_session(sid)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(auth.COOKIE_NAME, path="/")
    return resp


# ─── Audit query endpoints ──────────────────────────────────────────────

@router.get("/audit/events")
async def audit_events(session_id: Optional[str] = None, case_id: Optional[str] = None,
                       actor: Optional[str] = None, risk: Optional[str] = None,
                       ts_from: Optional[str] = None, ts_to: Optional[str] = None,
                       limit: int = 500):
    """Audit events with filters: session_id, case_id, actor, risk level
    (critical|high|medium|low|none), and ISO date range (ts_from/ts_to)."""
    conn = sqlite3.connect(str(config.DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        sql = "SELECT * FROM events"
        params = []
        where = []
        if session_id:
            where.append("session_id = ?"); params.append(session_id)
        if case_id:
            where.append("case_id = ?"); params.append(case_id)
        if actor:
            where.append("actor = ?"); params.append(actor)
        if ts_from:
            where.append("ts >= ?"); params.append(ts_from)
        if ts_to:
            where.append("ts <= ?"); params.append(ts_to)
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        cur = conn.execute(sql, params)
        # risk is derived from the path (not a column) -> filter in Python.
        rows_raw = [dict(r) for r in cur.fetchall()]
        if risk:
            rows_raw = [r for r in rows_raw if config.risk_level(r.get("path") or "") == risk.lower()]
        # Decrypt encrypted fields for display (erased -> [ERASED], locked -> [LOCKED]).
        rows = [encryption.decrypt_event_fields(r) for r in rows_raw]
        # Attach per-event timestamp summary (batch query, no N+1).
        ids = [r["id"] for r in rows]
        tmap = {}
        if ids:
            ph = ",".join("?" * len(ids))
            for tr in conn.execute(
                f"SELECT event_id, provider_name, is_qualified FROM event_timestamps "
                f"WHERE event_id IN ({ph})", ids):
                tmap[tr[0]] = {"provider": tr[1], "qualified": bool(tr[2])}
        for r in rows:
            t = tmap.get(r["id"])
            r["ts_provider"] = t["provider"] if t else None
            r["ts_qualified"] = t["qualified"] if t else False
        return {"events": rows, "count": len(rows)}
    finally:
        conn.close()


@router.get("/audit/sessions")
async def audit_sessions():
    conn = sqlite3.connect(str(config.DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.execute(
            "SELECT s.session_id, s.actor, s.case_id, s.activity_type, "
            "s.justification, s.created_at, s.expires_at, s.revoked, "
            "(SELECT COUNT(*) FROM events e WHERE e.session_id = s.session_id) AS event_count "
            "FROM sessions s ORDER BY s.created_at DESC LIMIT 100"
        )
        return {"sessions": [dict(r) for r in cur.fetchall()]}
    finally:
        conn.close()


@router.get("/audit/anchors")
async def audit_anchors():
    conn = sqlite3.connect(str(config.DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.execute(
            "SELECT * FROM anchors ORDER BY id DESC LIMIT 100"
        )
        return {"anchors": [dict(r) for r in cur.fetchall()]}
    finally:
        conn.close()


@router.get("/audit/verify/{session_id}")
async def audit_verify(session_id: str):
    # The hash chain is GLOBAL (each event's prev_hash links to the immediately
    # preceding event across ALL sessions). Events from different sessions /
    # background tasks (timestamps, approvals) interleave, so a session's events
    # are not contiguous — verifying a per-session subset's prev_hash linkage is
    # wrong. We verify the whole chain: a session's events are intact iff the
    # global chain is intact.
    conn = sqlite3.connect(str(config.DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        all_rows = [dict(r) for r in conn.execute("SELECT * FROM events ORDER BY id ASC")]
        sess_n = conn.execute("SELECT COUNT(*) FROM events WHERE session_id=?",
                              (session_id,)).fetchone()[0]
    finally:
        conn.close()
    if sess_n == 0:
        return {"ok": False, "error": "no events for session", "count": 0}
    result = verify_chain(all_rows)
    result["session_id"] = session_id
    result["session_events"] = sess_n
    result["count"] = len(all_rows)
    return result


class EraseRequest(BaseModel):
    case_id: Optional[str] = None
    session_id: Optional[str] = None


@router.post("/gdpr/erase")
async def gdpr_erase(req: EraseRequest, request: Request, admin: dict = Depends(identity.require_admin)):
    """Cryptographic erasure (GDPR Art.17): destroy the per-record keys for the
    matching events. Ciphertext and hash chain stay intact; plaintext becomes
    unrecoverable. The erasure itself is recorded in the chain."""
    if not req.case_id and not req.session_id:
        raise HTTPException(400, "provide case_id or session_id")
    conn = sqlite3.connect(str(config.DB_PATH))
    try:
        if req.case_id:
            ids = [r[0] for r in conn.execute("SELECT id FROM events WHERE case_id=?", (req.case_id,))]
        else:
            ids = [r[0] for r in conn.execute("SELECT id FROM events WHERE session_id=?", (req.session_id,))]
    finally:
        conn.close()
    n = encryption.erase_records(ids)

    # Audit the erasure itself (auditable action). NOTE: this event is a SYSTEM
    # action, not subject data — so it carries no case_id (the erased target is
    # recorded in the justification), keeping case queries clean.
    target = f"case {req.case_id}" if req.case_id else f"session {req.session_id}"
    from . import proxy as proxy_mod
    sess = {"session_id": "login:" + str(admin["user_id"]), "actor": admin["username"],
            "case_id": "", "activity_type": "GDPR_ERASURE",
            "justification": f"Crypto-erasure of {n} record key(s) for {target}"}
    ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or (
        request.client.host if request.client else "unknown")
    await proxy_mod.log_event(session=sess, event_type="gdpr_erasure", method="POST",
                              path="/_immutrace/gdpr/erase", query="", body_bytes=b"",
                              response_status=200, response_bytes=b"", remote_ip=ip,
                              user_agent=request.headers.get("user-agent", ""))
    return {"erased_record_keys": n, "events_matched": len(ids)}


@router.post("/audit/anchor-now")
async def anchor_now():
    """Force an immediate anchor batch (debug / demo use)."""
    from . import anchor
    rec = anchor.anchor_batch()
    if not rec:
        return {"ok": False, "message": "no pending events"}
    await anchor.log_anchor_event(rec)
    return {"ok": True, "anchor": rec}


# ─── Static dashboard ───────────────────────────────────────────────────

@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard_html():
    p = DASHBOARD_DIR / "dashboard.html"
    return HTMLResponse(p.read_text(encoding="utf-8"))


@router.get("/supervisor/queue", response_class=HTMLResponse)
async def supervisor_queue_page():
    return HTMLResponse((DASHBOARD_DIR / "supervisor.html").read_text(encoding="utf-8"))


@router.get("/analyst/requests", response_class=HTMLResponse)
async def analyst_requests_page():
    return HTMLResponse((DASHBOARD_DIR / "analyst.html").read_text(encoding="utf-8"))


@router.get("/admin/keys", response_class=HTMLResponse)
async def admin_keys_page():
    return HTMLResponse((DASHBOARD_DIR / "admin_keys.html").read_text(encoding="utf-8"))


@router.get("/admin/worker/status")
async def worker_status(_: dict = Depends(identity.require_admin)):
    from . import anchor
    return anchor.worker_status()


@router.get("/admin/worker", response_class=HTMLResponse)
async def worker_page():
    return HTMLResponse((DASHBOARD_DIR / "worker.html").read_text(encoding="utf-8"))


@router.get("/custodian/panel", response_class=HTMLResponse)
async def custodian_panel_page():
    return HTMLResponse((DASHBOARD_DIR / "custodian.html").read_text(encoding="utf-8"))


@router.get("/sdk.js")
async def sdk_js():
    # Canonical source is the standalone, backend-agnostic observer library.
    p = ROOT / "sdk" / "immutrace-observer.js"
    return Response(
        content=p.read_text(encoding="utf-8"),
        media_type="application/javascript",
        headers={"Cache-Control": "no-cache"},
    )


@router.get("/dashboard/style.css")
async def dashboard_css():
    p = DASHBOARD_DIR / "style.css"
    return Response(
        content=p.read_text(encoding="utf-8"),
        media_type="text/css",
    )


@router.get("/dashboard/app.js")
async def dashboard_app_js():
    p = DASHBOARD_DIR / "app.js"
    return Response(
        content=p.read_text(encoding="utf-8"),
        media_type="application/javascript",
    )


# ─── PDF export ─────────────────────────────────────────────────────────

@router.get("/audit/export/{session_id}.pdf")
async def export_pdf(session_id: str):
    from .pdf_export import build_session_pdf
    out = build_session_pdf(session_id)
    return FileResponse(
        path=str(out["path"]),
        media_type="application/pdf",
        filename=out["filename"],
    )

"""Dashboard + audit API + PDF export routes."""
import sqlite3
import json
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, Request, Response, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse, RedirectResponse
from pydantic import BaseModel
from . import config, auth
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
                       limit: int = 500):
    conn = sqlite3.connect(str(config.DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        sql = "SELECT * FROM events"
        params = []
        where = []
        if session_id:
            where.append("session_id = ?")
            params.append(session_id)
        if case_id:
            where.append("case_id = ?")
            params.append(case_id)
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        cur = conn.execute(sql, params)
        rows = [dict(r) for r in cur.fetchall()]
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
    conn = sqlite3.connect(str(config.DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.execute(
            "SELECT * FROM events WHERE session_id = ? ORDER BY id ASC",
            (session_id,),
        )
        rows = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
    if not rows:
        return {"ok": False, "error": "no events for session", "count": 0}
    result = verify_chain(rows)
    return result


@router.post("/audit/anchor-now")
async def anchor_now():
    """Force an immediate anchor batch (debug / demo use)."""
    from . import anchor
    rec = anchor.anchor_batch()
    if not rec:
        return {"ok": False, "message": "no pending events"}
    return {"ok": True, "anchor": rec}


# ─── Static dashboard ───────────────────────────────────────────────────

@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard_html():
    p = DASHBOARD_DIR / "dashboard.html"
    return HTMLResponse(p.read_text(encoding="utf-8"))


@router.get("/sdk.js")
async def sdk_js():
    p = DASHBOARD_DIR / "sdk.js"
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

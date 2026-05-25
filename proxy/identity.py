"""Identity & authentication: multi-user login, roles, password hashing.

Design choices (documented honestly):
- Password hashing: argon2 (argon2-cffi). ledgereye uses bcrypt+JWT; we picked
  argon2 + DB-backed login sessions instead — no JWT secret to manage, and login
  sessions are revocable/auditable rows.
- This is ADDITIVE: the legacy investigation-session flow (auth.py / sessions
  table) is untouched, so existing behaviour (and the smoke test) keeps working.
  Login becomes the production identity layer; the gate wiring lands in Step 3.
"""
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List

from fastapi import APIRouter, Request, Response, HTTPException, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

from . import config

LOGIN_COOKIE = "__immutrace_auth"
ROLES = ("analyst", "supervisor", "admin", "custodian")
LOGIN_TTL = config._env_int("LOGIN_TTL_SECONDS", 28800)          # 8h work session
SECURE_COOKIE = config._env_bool("COOKIE_SECURE", False)         # False on localhost http
SEED_DEMO_USERS = config._env_bool("SEED_DEMO_USERS", True)      # DEMO ONLY — disable in prod

_ph = PasswordHasher()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def utcnow_iso() -> str:
    return _iso(_now())


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(config.DB_PATH), timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


# ── Password hashing ──────────────────────────────────────────────────────
def hash_password(pw: str) -> str:
    return _ph.hash(pw)


def verify_password(stored_hash: str, pw: str) -> bool:
    try:
        return _ph.verify(stored_hash, pw)
    except (VerifyMismatchError, InvalidHashError, Exception):
        return False


# ── User CRUD ───────────────────────────────────────────────────────────────
def create_user(username: str, password: str, role: str,
                full_name: str = "", email: str = "") -> Dict[str, Any]:
    if role not in ROLES:
        raise ValueError(f"invalid role: {role}")
    conn = _conn()
    try:
        conn.execute(
            "INSERT INTO users(username, password_hash, role, full_name, email, created_at, active) "
            "VALUES (?,?,?,?,?,?,1)",
            (username, hash_password(password), role, full_name, email, utcnow_iso()),
        )
        conn.commit()
        return get_user_by_username(username)
    finally:
        conn.close()


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    conn = _conn()
    try:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_user_by_id(uid: int) -> Optional[Dict[str, Any]]:
    conn = _conn()
    try:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def list_users() -> List[Dict[str, Any]]:
    conn = _conn()
    try:
        rows = conn.execute(
            "SELECT id, username, role, full_name, email, created_at, last_login_at, active "
            "FROM users ORDER BY id"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def update_user(uid: int, role: Optional[str] = None, active: Optional[bool] = None) -> bool:
    sets, params = [], []
    if role is not None:
        if role not in ROLES:
            raise ValueError(f"invalid role: {role}")
        sets.append("role = ?"); params.append(role)
    if active is not None:
        sets.append("active = ?"); params.append(1 if active else 0)
    if not sets:
        return False
    params.append(uid)
    conn = _conn()
    try:
        cur = conn.execute(f"UPDATE users SET {', '.join(sets)} WHERE id = ?", params)
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


# ── Login sessions ────────────────────────────────────────────────────────
def create_login_session(user_id: int, ip: str, user_agent: str) -> str:
    sid = uuid.uuid4().hex
    now = _now()
    conn = _conn()
    try:
        conn.execute(
            "INSERT INTO login_sessions(id, user_id, created_at, expires_at, ip, user_agent) "
            "VALUES (?,?,?,?,?,?)",
            (sid, user_id, _iso(now), _iso(now + timedelta(seconds=LOGIN_TTL)), ip, user_agent),
        )
        conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (_iso(now), user_id))
        conn.commit()
        return sid
    finally:
        conn.close()


def get_login_session(sid: Optional[str]) -> Optional[Dict[str, Any]]:
    """Return joined {session + user} for an active login session, else None."""
    if not sid:
        return None
    conn = _conn()
    try:
        row = conn.execute(
            "SELECT s.id AS session_id, s.user_id, s.expires_at, s.revoked_at, "
            "u.username, u.role, u.full_name, u.email, u.active "
            "FROM login_sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ?",
            (sid,),
        ).fetchone()
        if not row:
            return None
        if row["revoked_at"] or not row["active"]:
            return None
        try:
            exp = datetime.strptime(row["expires_at"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        except Exception:
            return None
        if _now() > exp:
            return None
        return dict(row)
    finally:
        conn.close()


def revoke_login_session(sid: str) -> None:
    conn = _conn()
    try:
        conn.execute("UPDATE login_sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
                     (utcnow_iso(), sid))
        conn.commit()
    finally:
        conn.close()


def current_user(request: Request) -> Optional[Dict[str, Any]]:
    return get_login_session(request.cookies.get(LOGIN_COOKIE))


def _ensure_user(username: str, password: str, role: str, full_name: str = "") -> bool:
    """Create the user if it doesn't already exist. Idempotent (safe on restart)."""
    if get_user_by_username(username):
        return False
    create_user(username, password, role, full_name)
    return True


def seed_users() -> None:
    """Idempotently ensure bootstrap/demo users exist. Always ensures an admin
    (ADMIN_USER/ADMIN_PASSWORD). Ensures demo analyst/supervisor/custodian only if
    SEED_DEMO_USERS is true — DEMO ONLY, must be disabled in production."""
    if _ensure_user(config.ADMIN_USER, config.ADMIN_PASSWORD, "admin", "Bootstrap Admin"):
        print(f"[immutrace] seeded admin user '{config.ADMIN_USER}'")
    if SEED_DEMO_USERS:
        seeded = []
        for uname, role in (("analyst", "analyst"), ("supervisor", "supervisor"),
                            ("custodian", "custodian")):
            if _ensure_user(uname, "demo1234", role, f"Demo {role.title()}"):
                seeded.append(uname)
        if seeded:
            print(f"[immutrace] seeded DEMO users {seeded} (pw 'demo1234') "
                  "— SEED_DEMO_USERS=false to disable in production")


# ── FastAPI router ────────────────────────────────────────────────────────
router = APIRouter(prefix="/_immutrace/auth")


class LoginReq(BaseModel):
    username: str
    password: str


class CreateUserReq(BaseModel):
    username: str
    password: str
    role: str
    full_name: str = ""
    email: str = ""


class UpdateUserReq(BaseModel):
    role: Optional[str] = None
    active: Optional[bool] = None


def require_user(request: Request) -> Dict[str, Any]:
    u = current_user(request)
    if not u:
        raise HTTPException(401, "Authentication required")
    return u


def require_admin(request: Request) -> Dict[str, Any]:
    u = require_user(request)
    if u["role"] != "admin":
        raise HTTPException(403, "Admin role required")
    return u


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@router.post("/login")
async def login(req: LoginReq, request: Request):
    user = get_user_by_username(req.username)
    if not user or not user["active"] or not verify_password(user["password_hash"], req.password):
        raise HTTPException(401, "Invalid credentials")
    sid = create_login_session(user["id"], _client_ip(request), request.headers.get("user-agent", ""))
    resp = JSONResponse({"id": user["id"], "username": user["username"],
                         "role": user["role"], "full_name": user["full_name"]})
    resp.set_cookie(LOGIN_COOKIE, sid, max_age=LOGIN_TTL, httponly=True,
                    samesite="lax", secure=SECURE_COOKIE, path="/")
    return resp


@router.post("/logout")
async def logout(request: Request):
    sid = request.cookies.get(LOGIN_COOKIE)
    if sid:
        revoke_login_session(sid)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(LOGIN_COOKIE, path="/")
    return resp


@router.get("/me")
async def me(request: Request):
    u = current_user(request)
    if not u:
        return {"authenticated": False}
    return {"authenticated": True, "id": u["user_id"], "username": u["username"],
            "role": u["role"], "full_name": u["full_name"]}


@router.get("/users")
async def users_list(_: dict = Depends(require_admin)):
    return {"users": list_users()}


@router.post("/users")
async def users_create(req: CreateUserReq, _: dict = Depends(require_admin)):
    if req.role not in ROLES:
        raise HTTPException(400, f"role must be one of {ROLES}")
    if get_user_by_username(req.username):
        raise HTTPException(409, "username already exists")
    if len(req.password) < 8:
        raise HTTPException(400, "password must be at least 8 characters")
    u = create_user(req.username, req.password, req.role, req.full_name, req.email)
    return {"id": u["id"], "username": u["username"], "role": u["role"]}


@router.patch("/users/{uid}")
async def users_update(uid: int, req: UpdateUserReq, _: dict = Depends(require_admin)):
    if req.role is not None and req.role not in ROLES:
        raise HTTPException(400, f"role must be one of {ROLES}")
    if not get_user_by_id(uid):
        raise HTTPException(404, "user not found")
    update_user(uid, role=req.role, active=req.active)
    return {"ok": True, "user": get_user_by_id(uid)}

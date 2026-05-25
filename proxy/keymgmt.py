"""Master-key custody orchestration (Shamir k-of-n).

The master key (consumed by the AES-GCM layer in Step 5) is never stored in
plaintext. setup() generates it, splits it across custodians (encrypted
fragments stored in key_shards), and keeps it in RAM. A reassembly ceremony
(start -> custodians submit shares -> finalize) reconstructs it in RAM only.

For the LOCAL custodian backend (demo), auto_unlock() reconstructs the key at
startup using the on-machine custodian keys, so encryption keeps working across
restarts without a manual ceremony — an honest convenience of the simulation
(real/remote custodians would require the ceremony). The key is held only in
this module's memory and never written to disk.
"""
import hashlib
import secrets
import sqlite3
from typing import Optional, Dict, List

from fastapi import APIRouter, Request, HTTPException, Depends
from pydantic import BaseModel

from . import config, shamir, custodians as custodians_mod, identity

THRESHOLD = config._env_int("SHAMIR_THRESHOLD", 3)

_backend = custodians_mod.get_backend()
_master_key: Optional[bytes] = None
# attempt_id -> {custodian_id: decrypted_indexed_fragment}  (RAM only)
_pending: Dict[int, Dict[int, bytes]] = {}


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(config.DB_PATH), timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def get_master_key() -> Optional[bytes]:
    """Current in-RAM master key (None if not configured / locked)."""
    return _master_key


def is_unlocked() -> bool:
    return _master_key is not None


def _meta() -> Optional[dict]:
    conn = _conn()
    try:
        row = conn.execute("SELECT * FROM key_meta WHERE id=1").fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


# ── Setup ───────────────────────────────────────────────────────────────────
def setup(requester_user_id: int) -> dict:
    """Generate a fresh master key, split it k-of-n, store encrypted fragments.
    Keeps the key in RAM. Re-running re-keys (clears previous shards)."""
    global _master_key
    _backend.provision()
    custs = _backend.custodians()
    if len(custs) < THRESHOLD:
        raise ValueError("not enough custodians for the configured threshold")
    master = secrets.token_bytes(32)  # AES-256 master key
    pubs = [(c["id"], c["public_pem"]) for c in custs]
    enc_fragments = shamir.escrow_key(master, pubs, threshold=THRESHOLD)  # [(cid, enc)]

    conn = _conn()
    try:
        conn.execute("DELETE FROM key_shards")
        for cid, enc in enc_fragments:
            conn.execute(
                "INSERT INTO key_shards(custodian_id, share_index, share_data_encrypted, "
                "created_at, status) VALUES (?,?,?,?,'active')",
                (cid, cid, enc, identity.utcnow_iso()),
            )
        conn.execute(
            "INSERT INTO key_meta(id, master_sha256, threshold, num_shares, created_at) "
            "VALUES (1,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
            "master_sha256=excluded.master_sha256, threshold=excluded.threshold, "
            "num_shares=excluded.num_shares, created_at=excluded.created_at",
            (_sha(master), THRESHOLD, len(custs), identity.utcnow_iso()),
        )
        conn.commit()
    finally:
        conn.close()
    _master_key = master
    return status()


def status() -> dict:
    meta = _meta()
    conn = _conn()
    try:
        custs = [dict(r) for r in conn.execute(
            "SELECT id, name, role_label, username FROM custodians ORDER BY id")]
        shards = conn.execute("SELECT COUNT(*) FROM key_shards WHERE status='active'").fetchone()[0]
    finally:
        conn.close()
    return {
        "configured": meta is not None,
        "unlocked": is_unlocked(),
        "threshold": meta["threshold"] if meta else THRESHOLD,
        "num_shares": meta["num_shares"] if meta else len(custs),
        "shards_active": shards,
        "custodians": custs,
    }


# ── Reassembly ceremony ─────────────────────────────────────────────────────
def reassembly_start(requester_user_id: int) -> int:
    meta = _meta()
    if not meta:
        raise ValueError("no master key configured; run setup first")
    conn = _conn()
    try:
        cur = conn.execute(
            "INSERT INTO key_reassembly_attempts(requester_user_id, requested_at, status, "
            "shares_collected, threshold) VALUES (?,?, 'pending', 0, ?)",
            (requester_user_id, identity.utcnow_iso(), meta["threshold"]),
        )
        conn.commit()
        aid = cur.lastrowid
    finally:
        conn.close()
    _pending[aid] = {}
    return aid


def reassembly_submit(attempt_id: int, custodian_id: int) -> int:
    conn = _conn()
    try:
        att = conn.execute("SELECT * FROM key_reassembly_attempts WHERE id=?", (attempt_id,)).fetchone()
        if not att:
            raise LookupError("attempt not found")
        if att["status"] != "pending":
            raise ValueError(f"attempt is {att['status']}")
        shard = conn.execute(
            "SELECT share_data_encrypted FROM key_shards WHERE custodian_id=? AND status='active'",
            (custodian_id,)).fetchone()
        if not shard:
            raise LookupError("no active shard for custodian")
        frag = _backend.decrypt_share(custodian_id, shard["share_data_encrypted"])
        _pending.setdefault(attempt_id, {})[custodian_id] = frag
        count = len(_pending[attempt_id])
        conn.execute("UPDATE key_shards SET last_used_at=? WHERE custodian_id=? AND status='active'",
                     (identity.utcnow_iso(), custodian_id))
        conn.execute("UPDATE key_reassembly_attempts SET shares_collected=? WHERE id=?",
                     (count, attempt_id))
        conn.commit()
        return count
    finally:
        conn.close()


def reassembly_finalize(attempt_id: int) -> dict:
    global _master_key
    meta = _meta()
    frags = list(_pending.get(attempt_id, {}).values())
    if not meta:
        raise ValueError("no master key configured")
    if len(frags) < meta["threshold"]:
        _mark_attempt(attempt_id, "failed")
        raise ValueError(f"below threshold: {len(frags)}/{meta['threshold']} shares")
    master = shamir.recover_key(frags, threshold=meta["threshold"])
    if _sha(master) != meta["master_sha256"]:
        _mark_attempt(attempt_id, "failed")
        raise ValueError("reconstruction mismatch — invalid or corrupted shares")
    _master_key = master
    _mark_attempt(attempt_id, "complete")
    _pending.pop(attempt_id, None)
    return {"ok": True, "unlocked": True}


def _mark_attempt(attempt_id: int, status_val: str):
    conn = _conn()
    try:
        conn.execute("UPDATE key_reassembly_attempts SET status=?, completed_at=? WHERE id=?",
                     (status_val, identity.utcnow_iso(), attempt_id))
        conn.commit()
    finally:
        conn.close()


def reassembly_status(attempt_id: int) -> Optional[dict]:
    conn = _conn()
    try:
        row = conn.execute("SELECT * FROM key_reassembly_attempts WHERE id=?", (attempt_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def list_pending_attempts() -> List[dict]:
    conn = _conn()
    try:
        return [dict(r) for r in conn.execute(
            "SELECT id, requested_at, shares_collected, threshold, status "
            "FROM key_reassembly_attempts WHERE status='pending' ORDER BY id DESC LIMIT 20")]
    finally:
        conn.close()


def auto_unlock() -> bool:
    """At startup, reconstruct the master key into RAM using locally-held shards
    (LOCAL backend only). Returns True if unlocked. No-op if not configured."""
    global _master_key
    meta = _meta()
    if not meta:
        return False
    try:
        conn = _conn()
        try:
            shards = conn.execute(
                "SELECT custodian_id, share_data_encrypted FROM key_shards "
                "WHERE status='active' ORDER BY custodian_id LIMIT ?", (meta["threshold"],)).fetchall()
        finally:
            conn.close()
        frags = [_backend.decrypt_share(s["custodian_id"], s["share_data_encrypted"]) for s in shards]
        master = shamir.recover_key(frags, threshold=meta["threshold"])
        if _sha(master) == meta["master_sha256"]:
            _master_key = master
            print(f"[immutrace] master key auto-unlocked via local custodians ({meta['threshold']}-of-{meta['num_shares']})")
            return True
    except Exception as e:  # remote backend or missing local keys -> stays locked
        print(f"[immutrace] master key NOT auto-unlocked ({e}); reassembly ceremony required")
    return False


# ── Audit + router ──────────────────────────────────────────────────────────
async def _log(request: Request, user: dict, event_type: str, note: str = ""):
    from . import proxy as proxy_mod  # lazy: avoid circular import
    sess = {"session_id": "login:" + str(user["user_id"]), "actor": user["username"],
            "case_id": "", "activity_type": "KEY_CUSTODY", "justification": note}
    ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or (
        request.client.host if request.client else "unknown")
    await proxy_mod.log_event(session=sess, event_type=event_type, method="POST",
                              path="/_immutrace/keys", query="", body_bytes=b"",
                              response_status=200, response_bytes=b"", remote_ip=ip,
                              user_agent=request.headers.get("user-agent", ""))


router = APIRouter(prefix="/_immutrace/keys")


class SubmitShareReq(BaseModel):
    custodian_id: int


@router.post("/setup")
async def keys_setup(request: Request, admin: dict = Depends(identity.require_admin)):
    try:
        st = setup(admin["user_id"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    await _log(request, admin, "key_setup", f"{st['threshold']}-of-{st['num_shares']} master key created")
    return st


@router.get("/status")
async def keys_status(_: dict = Depends(identity.require_user)):
    return status()


@router.post("/reassembly/start")
async def reassembly_begin(request: Request, admin: dict = Depends(identity.require_admin)):
    try:
        aid = reassembly_start(admin["user_id"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    await _log(request, admin, "key_reassembly_start", f"attempt {aid}")
    return {"attempt_id": aid, "threshold": THRESHOLD}


@router.post("/reassembly/{attempt_id}/submit-share")
async def submit_share(attempt_id: int, body: SubmitShareReq, request: Request,
                       user: dict = Depends(identity.require_user)):
    # A custodian may submit only their own share; an admin may submit any (local ceremony).
    if user["role"] == "admin":
        pass
    elif user["role"] == "custodian":
        conn = _conn()
        try:
            own = conn.execute("SELECT id FROM custodians WHERE username=?", (user["username"],)).fetchone()
        finally:
            conn.close()
        if not own or own["id"] != body.custodian_id:
            raise HTTPException(403, "custodians may only submit their own share")
    else:
        raise HTTPException(403, "custodian or admin role required")
    try:
        count = reassembly_submit(attempt_id, body.custodian_id)
    except LookupError as e:
        raise HTTPException(404, str(e))
    except ValueError as e:
        raise HTTPException(409, str(e))
    await _log(request, user, "key_share_submitted", f"attempt {attempt_id} custodian {body.custodian_id}")
    return {"attempt_id": attempt_id, "shares_collected": count, "threshold": THRESHOLD}


@router.post("/reassembly/{attempt_id}/finalize")
async def finalize(attempt_id: int, request: Request, admin: dict = Depends(identity.require_admin)):
    try:
        res = reassembly_finalize(attempt_id)
    except ValueError as e:
        await _log(request, admin, "key_reassembly_failed", str(e))
        raise HTTPException(409, str(e))
    await _log(request, admin, "key_reassembly_complete", f"attempt {attempt_id}")
    return res


@router.get("/reassembly")
async def reassembly_list(_: dict = Depends(identity.require_user)):
    return {"pending": list_pending_attempts()}


@router.get("/reassembly/{attempt_id}")
async def reassembly_get(attempt_id: int, _: dict = Depends(identity.require_user)):
    st = reassembly_status(attempt_id)
    if not st:
        raise HTTPException(404, "attempt not found")
    return st

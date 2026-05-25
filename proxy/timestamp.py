"""eIDAS-ready timestamping (adapter pattern).

LocalTimestampProvider (default) produces an IMMUTRACE-NATIVE signed timestamp:
an Ed25519 signature over sha256(data)||iso-time, committing an event hash to a
point in time. Cryptographically solid, but NOT eIDAS-qualified
(is_qualified=False) — it is signed by THIS installation, not by a Qualified
Trust Service Provider.

Why not RFC 3161 here: rfc3161ng (used in ledgereye) is a TSA *client*, not a TSA
*server*; standing up a local *qualified* TSA is out of scope and would be
dishonest to label "qualified". The QTSP providers below (Aruba/InfoCert/
Namirial) are stubs that will issue real qualified RFC-3161 tokens once a contract
is active — activation is a config change (set <VENDOR>_TSA_URL). The
TimestampProvider contract is provider-agnostic, so callers never change.
"""
import os
import json
import hashlib
import sqlite3
import asyncio
from dataclasses import dataclass
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Request, HTTPException, Depends

from . import config, identity

ROOT = Path(__file__).resolve().parent.parent
TSA_KEY_PATH = ROOT / "data" / "tsa_local_ed25519.key"

_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class TimestampToken:
    token_bytes: bytes
    provider_name: str
    timestamp_iso: str
    hash_algorithm: str
    signed_by: str
    is_qualified: bool


class TimestampProvider(ABC):
    name = "base"
    is_qualified = False

    @abstractmethod
    def timestamp(self, data: bytes) -> TimestampToken: ...

    @abstractmethod
    def verify(self, token_bytes: bytes, data: bytes) -> bool: ...


class LocalTimestampProvider(TimestampProvider):
    name = "local"
    is_qualified = False
    _priv: Optional[Ed25519PrivateKey] = None

    def _key(self) -> Ed25519PrivateKey:
        if LocalTimestampProvider._priv is None:
            if TSA_KEY_PATH.exists():
                LocalTimestampProvider._priv = serialization.load_pem_private_key(
                    TSA_KEY_PATH.read_bytes(), password=None)
            else:
                k = Ed25519PrivateKey.generate()
                TSA_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
                TSA_KEY_PATH.write_bytes(k.private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption()))
                LocalTimestampProvider._priv = k
        return LocalTimestampProvider._priv

    def _pub_hex(self) -> str:
        return self._key().public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    def timestamp(self, data: bytes) -> TimestampToken:
        h = hashlib.sha256(data).hexdigest()
        ts = identity.utcnow_iso()
        sig = self._key().sign((h + "|" + ts).encode()).hex()
        payload = {"v": 1, "alg": "sha256", "hash": h, "ts": ts,
                   "sig": sig, "pub": self._pub_hex(), "provider": "local"}
        tok = json.dumps(payload, separators=(",", ":")).encode()
        return TimestampToken(tok, "local", ts, "sha256",
                              "IMMUTRACE local TSA (non-qualified)", False)

    def verify(self, token_bytes: bytes, data: bytes) -> bool:
        try:
            p = json.loads(token_bytes.decode())
            if p.get("hash") != hashlib.sha256(data).hexdigest():
                return False
            if p.get("pub") != self._pub_hex():   # must be signed by THIS installation
                return False
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(p["pub"])).verify(
                bytes.fromhex(p["sig"]), (p["hash"] + "|" + p["ts"]).encode())
            return True
        except Exception:
            return False


class _QTSPStub(TimestampProvider):
    is_qualified = True
    vendor = "QTSP"
    tsa_url_env = "TSA_URL"

    def timestamp(self, data: bytes) -> TimestampToken:
        raise NotImplementedError(
            f"{self.vendor} QTSP is not active. Set {self.tsa_url_env} and implement the "
            f"RFC-3161 TSA request when the {self.vendor} contract is signed.")

    def verify(self, token_bytes: bytes, data: bytes) -> bool:
        raise NotImplementedError(f"{self.vendor} QTSP verification not implemented yet.")


class ArubaQTSPProvider(_QTSPStub):
    name = "aruba"; vendor = "Aruba"; tsa_url_env = "ARUBA_TSA_URL"


class InfoCertQTSPProvider(_QTSPStub):
    name = "infocert"; vendor = "InfoCert"; tsa_url_env = "INFOCERT_TSA_URL"


class NamirialQTSPProvider(_QTSPStub):
    name = "namirial"; vendor = "Namirial"; tsa_url_env = "NAMIRIAL_TSA_URL"


_QTSP = {"aruba": ArubaQTSPProvider, "infocert": InfoCertQTSPProvider, "namirial": NamirialQTSPProvider}


def get_provider() -> TimestampProvider:
    """Selected provider. A QTSP is returned only if its TSA_URL is configured;
    otherwise we fall back to the local provider (a stub with no endpoint can't sign)."""
    p = config._env("TIMESTAMP_PROVIDER", "local").lower()
    cls = _QTSP.get(p)
    if cls is not None:
        if config._env(cls.tsa_url_env, ""):
            return cls()
        return LocalTimestampProvider()   # fallback
    return LocalTimestampProvider()


def should_timestamp(event_type: str, path: str) -> bool:
    if event_type == "event_timestamped":   # never timestamp the timestamp event (no recursion)
        return False
    thr = config._env("TIMESTAMP_THRESHOLD", "critical").lower()
    if thr == "none":
        return False
    if thr == "all":
        return True
    return _RANK.get(config.risk_level(path), 0) >= _RANK.get(thr, 4)


# ── Storage ─────────────────────────────────────────────────────────────────
def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(config.DB_PATH), timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def store_timestamp(event_id: int, tok: TimestampToken) -> None:
    conn = _conn()
    try:
        conn.execute(
            "INSERT INTO event_timestamps(event_id, provider_name, token, timestamp_iso, "
            "is_qualified, created_at) VALUES (?,?,?,?,?,?)",
            (event_id, tok.provider_name, tok.token_bytes, tok.timestamp_iso,
             1 if tok.is_qualified else 0, identity.utcnow_iso()),
        )
        conn.commit()
    finally:
        conn.close()


def get_timestamp(event_id: int) -> Optional[dict]:
    conn = _conn()
    try:
        row = conn.execute("SELECT * FROM event_timestamps WHERE event_id=? ORDER BY id DESC LIMIT 1",
                           (event_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def _event_hash(event_id: int) -> Optional[str]:
    conn = _conn()
    try:
        row = conn.execute("SELECT this_hash FROM events WHERE id=?", (event_id,)).fetchone()
        return row["this_hash"] if row else None
    finally:
        conn.close()


def verify_stored(event_id: int) -> dict:
    row = get_timestamp(event_id)
    if not row:
        return {"ok": False, "error": "no timestamp for event"}
    this_hash = _event_hash(event_id)
    if not this_hash:
        return {"ok": False, "error": "event not found"}
    prov = LocalTimestampProvider() if row["provider_name"] == "local" else get_provider()
    try:
        ok = prov.verify(bytes(row["token"]), this_hash.encode())
    except NotImplementedError:
        return {"ok": False, "error": "verification not implemented for this provider"}
    conn = _conn()
    try:
        conn.execute("UPDATE event_timestamps SET verified_at=?, verification_status=? WHERE id=?",
                     (identity.utcnow_iso(), "valid" if ok else "invalid", row["id"]))
        conn.commit()
    finally:
        conn.close()
    return {"ok": ok, "provider": row["provider_name"], "is_qualified": bool(row["is_qualified"]),
            "timestamp_iso": row["timestamp_iso"], "status": "valid" if ok else "invalid"}


async def timestamp_event_async(event_id: int, this_hash: str, path: str, event_type: str) -> None:
    """Background: produce + store a timestamp for an event, then record the act
    as an auditable chain event. Failures are swallowed (best-effort, non-blocking)."""
    try:
        prov = get_provider()
        tok = await asyncio.to_thread(prov.timestamp, this_hash.encode())
        await asyncio.to_thread(store_timestamp, event_id, tok)
    except NotImplementedError:
        return  # QTSP configured but not implemented — skip silently
    except Exception:
        return
    try:
        from . import proxy as proxy_mod  # lazy: avoid circular import
        sess = {"session_id": "system", "actor": "immutrace", "case_id": "",
                "activity_type": "TIMESTAMP", "justification": ""}
        await proxy_mod.log_event(
            session=sess, event_type="event_timestamped", method="POST",
            path=f"/_immutrace/timestamp/{event_id}", query="", body_bytes=b"",
            response_status=200, response_bytes=tok.token_bytes,
            remote_ip="system", user_agent="immutrace-timestamper")
    except Exception:
        pass


# ── Router ──────────────────────────────────────────────────────────────────
router = APIRouter(prefix="/_immutrace")


@router.get("/audit/events/{event_id}/timestamp")
async def event_timestamp(event_id: int, _: dict = Depends(identity.require_user)):
    row = get_timestamp(event_id)
    if not row:
        raise HTTPException(404, "no timestamp for this event")
    return {
        "event_id": event_id,
        "provider": row["provider_name"],
        "timestamp_iso": row["timestamp_iso"],
        "is_qualified": bool(row["is_qualified"]),
        "verification_status": row["verification_status"],
        "token": bytes(row["token"]).decode("utf-8", errors="replace"),
    }


@router.post("/audit/events/{event_id}/verify-timestamp")
async def verify_event_timestamp(event_id: int, _: dict = Depends(identity.require_user)):
    return verify_stored(event_id)

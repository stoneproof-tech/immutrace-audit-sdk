"""Universal decision-attestation protocol (Step 8).

The reverse proxy (proxy.py) attests decisions IMPLICITLY by observing the
data-access traffic that flows through it. This router adds the SECOND entry
point: an EXPLICIT endpoint where any system can certify ANY decision —
an AI model's output, a credit ruling, a GDPR lawful-basis call, a governance
vote — by handing IMMUTRACE a structured description of it.

Nothing here re-implements the audit core. An attestation is just one more event
in the SAME global hash chain (chain.py), inserted through the SAME single-writer
path the proxy uses (proxy._chain_lock + proxy._insert_event_sync), encrypted
at-rest with the SAME AES-GCM layer, timestamped by the SAME eIDAS-ready
provider, and batched into the SAME Polygon Merkle anchor. The decision payload
is mapped onto the existing event columns:

    event_type   = "decision.attested"   (NOT a system type → it IS anchored)
    method       = "ATTEST"
    case_id      = subject
    justification = rationale
    query        = canonical JSON {action, subject, decision, inputs_digest, metadata}

Verification (GET /verify/{this_hash}) is PUBLIC and key-free: it recomputes the
event hash from the stored fields and reports integrity + anchor status, so a
third party can check a receipt without an account and without trusting us.
"""
import asyncio
import re
import sqlite3
from typing import Optional, Dict, Any

from fastapi import APIRouter, Request, HTTPException, Depends
from pydantic import BaseModel

from . import config, identity, keymgmt, encryption, timestamp
from . import proxy as proxy_mod
from .chain import chain_hash, canonical_event

router = APIRouter(prefix="/_immutrace/attest")

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")

# Explorer base per anchor chain (mock anchors have no on-chain tx to point at).
_EXPLORER = {
    "polygon-mainnet": "https://polygonscan.com/tx/",
    "polygon-amoy": "https://amoy.polygonscan.com/tx/",
}


class AttestReq(BaseModel):
    action: str                                   # REQUIRED — what was decided/done
    subject: str = ""                             # who/what the decision is about
    decision: str = ""                            # the outcome ("approved", "denied", ...)
    rationale: str = ""                           # human-readable justification
    inputs_digest: str = ""                       # sha256 of the inputs (hashed by the caller)
    actor: str = ""                               # who/what made the decision (e.g. a model id)
    metadata: Dict[str, Any] = {}                 # arbitrary structured context


def _decision_payload(req: AttestReq) -> str:
    """Canonical JSON of the decision content (stable, sorted) — stored in `query`
    and what the chain hash commits to. Excludes rationale/subject (kept in their
    own columns) to avoid double-storing them."""
    doc = {
        "action": req.action,
        "subject": req.subject,
        "decision": req.decision,
        "inputs_digest": req.inputs_digest,
        "metadata": req.metadata or {},
    }
    return canonical_event(doc).decode("utf-8")


async def _attest(req: AttestReq, request: Request, user: dict) -> dict:
    actor = (req.actor or user["username"]).strip() or user["username"]
    ts = identity.utcnow_iso()

    # Map the decision onto the existing event schema (see module docstring).
    event = {
        "session_id": "login:" + str(user["user_id"]),
        "actor": actor,
        "case_id": req.subject,
        "activity_type": "ATTESTATION",
        "justification": req.rationale,
        "ts": ts,
        "event_type": "decision.attested",
        "method": "ATTEST",
        "path": "/_immutrace/attest",
        "query": _decision_payload(req),
        "body_sha256": "",
        "response_status": 200,
        "response_sha256": "",
        "remote_ip": proxy_mod._client_ip(request),
        "user_agent": request.headers.get("user-agent", ""),
    }

    # Encrypt sensitive fields at rest when unlocked — IDENTICAL to proxy.log_event
    # (the chain is computed over the ciphertext, so verification needs no key).
    record_wrap = None
    if keymgmt.is_unlocked() and any(event.get(f) for f in encryption.ENCRYPTED_FIELDS):
        rk = encryption.generate_record_key()
        for f in encryption.ENCRYPTED_FIELDS:
            if event.get(f):
                event[f] = encryption.encrypt_field(rk, event[f])
        record_wrap = encryption.wrap_record_key(rk)

    # Single-writer insert through the SAME lock + chain primitive as the proxy.
    async with proxy_mod._chain_lock:
        this_hash, event_id = await asyncio.to_thread(
            proxy_mod._insert_event_sync, event, record_wrap)
    prev_hash = event["prev_hash"]   # filled in by _insert_event_sync under the lock

    # Timestamp the attestation (eIDAS-ready, non-blocking). Attestations are
    # always worth a signed time token, so we launch it directly.
    asyncio.create_task(
        timestamp.timestamp_event_async(event_id, this_hash, event["path"], event["event_type"]))

    return {
        "receipt_id": "rcpt_" + this_hash[:24],
        "event_id": event_id,
        "this_hash": this_hash,
        "prev_hash": prev_hash,
        "ts": ts,
        "actor": actor,
        "event_type": "decision.attested",
        "anchored": False,
        "verify_url": f"/_immutrace/attest/verify/{this_hash}",
        "note": ("Decision recorded in the IMMUTRACE hash chain. It will be batched "
                 "into a Polygon Merkle anchor by the background worker; poll "
                 "verify_url to watch 'anchored' flip to true. Verification is "
                 "public and key-free."),
    }


@router.post("")
async def attest(req: AttestReq, request: Request, user: dict = Depends(identity.require_user)):
    return await _attest(req, request, user)


@router.post("/")
async def attest_slash(req: AttestReq, request: Request, user: dict = Depends(identity.require_user)):
    return await _attest(req, request, user)


def _lookup_event(this_hash: str) -> Optional[dict]:
    conn = sqlite3.connect(str(config.DB_PATH), timeout=30.0)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT * FROM events WHERE this_hash=?", (this_hash,)).fetchone()
        if not row:
            return None
        ev = dict(row)
        anchor = None
        if ev.get("anchor_id") is not None:
            arow = conn.execute("SELECT * FROM anchors WHERE id=?", (ev["anchor_id"],)).fetchone()
            anchor = dict(arow) if arow else None
        ev["_anchor"] = anchor
        return ev
    finally:
        conn.close()


@router.get("/verify/{this_hash}")
async def verify(this_hash: str):
    """PUBLIC, key-free verification of an attestation receipt.

    Recomputes the event hash from the stored fields (exactly as the chain did at
    write time) to prove the record has not been altered, and reports whether it
    has been anchored on Polygon yet."""
    if not _HEX64.match(this_hash):
        raise HTTPException(400, "this_hash must be 64 hexadecimal characters")
    this_hash = this_hash.lower()

    ev = _lookup_event(this_hash)
    if ev is None:
        raise HTTPException(404, "no attestation found for this hash")

    # Recompute the hash from the stored columns (same recipe as chain.verify_chain
    # / proxy._insert_event_sync): everything except this_hash, id, anchor_id.
    rebuilt = {k: ev[k] for k in ev.keys()
               if k not in ("this_hash", "id", "anchor_id", "_anchor")}
    recomputed = chain_hash(ev["prev_hash"], rebuilt)
    integrity_ok = recomputed == this_hash

    anchor = ev.get("_anchor")
    anchored = anchor is not None
    anchor_tx = anchor.get("tx_hash") if anchor else None
    anchor_explorer = None
    if anchor and anchor_tx and anchor.get("chain") in _EXPLORER:
        anchor_explorer = _EXPLORER[anchor["chain"]] + anchor_tx

    return {
        "found": True,
        "event_id": ev["id"],
        "ts": ev["ts"],
        "actor": ev["actor"],
        "event_type": ev["event_type"],
        "integrity_ok": integrity_ok,
        "anchored": anchored,
        "anchor_tx": anchor_tx,
        "anchor_explorer": anchor_explorer,
    }

"""AES-256-GCM field encryption + cryptographic erasure (GDPR Art. 17).

AES primitives ported from decision-flow-ledger/ledgereye/backend/services/
encryption.py; the keystore is reworked for SQLite and the master key comes from
the Shamir custody layer (keymgmt.get_master_key()) instead of an env variable.

Model: each encrypted event gets a random per-record AES key. The sensitive
fields are encrypted with it; the per-record key is then wrapped (encrypted) with
the in-RAM master key and stored in record_keys. Erasure destroys the wrapped key
-> ciphertext unrecoverable, while the hash chain (computed over the ciphertext)
stays valid. Encryption only happens when the master key is unlocked; otherwise
fields are stored in plaintext (backward-compatible / single-user legacy mode).
"""
import sqlite3
from typing import Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import config, keymgmt, identity

ENC_PREFIX = "enc:v1:"
# Fields of an audit event encrypted at rest (free-text PII / sensitive params).
# case_id stays plaintext so it remains filterable; actor/path stay operational.
ENCRYPTED_FIELDS = ("justification", "query")


# ── AES-256-GCM primitives (ported) ─────────────────────────────────────────
def generate_record_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def _encrypt(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
    aes = AESGCM(key)
    import os
    nonce = os.urandom(12)
    return nonce, aes.encrypt(nonce, plaintext, None)


def _decrypt(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, None)


def is_encrypted(value: Optional[str]) -> bool:
    return isinstance(value, str) and value.startswith(ENC_PREFIX)


def encrypt_field(record_key: bytes, plaintext: str) -> str:
    nonce, ct = _encrypt(plaintext.encode("utf-8"), record_key)
    return f"{ENC_PREFIX}{nonce.hex()}:{ct.hex()}"


def decrypt_field(record_key: bytes, enc: str) -> str:
    body = enc[len(ENC_PREFIX):]
    nonce_hex, ct_hex = body.split(":", 1)
    return _decrypt(bytes.fromhex(nonce_hex), bytes.fromhex(ct_hex), record_key).decode("utf-8")


# ── Master-key wrap/unwrap (master key from Shamir custody, RAM) ─────────────
def wrap_record_key(record_key: bytes) -> Optional[Tuple[bytes, bytes]]:
    master = keymgmt.get_master_key()
    if master is None:
        return None
    nonce, wrapped = _encrypt(record_key, master)
    return nonce, wrapped


def _unwrap_record_key(nonce: bytes, wrapped: bytes) -> Optional[bytes]:
    master = keymgmt.get_master_key()
    if master is None:
        return None
    try:
        return _decrypt(nonce, wrapped, master)
    except Exception:
        return None


# ── record_keys store (SQLite) ──────────────────────────────────────────────
def insert_record_key(conn: sqlite3.Connection, record_id: int, wrapped: bytes,
                      nonce: bytes, record_table: str = "events") -> None:
    """Insert a wrapped per-record key (called inside the event insert txn)."""
    conn.execute(
        "INSERT INTO record_keys(record_table, record_id, wrapped_key, wrap_nonce, created_at) "
        "VALUES (?,?,?,?,?)",
        (record_table, record_id, wrapped, nonce, identity.utcnow_iso()),
    )


def get_record_key(record_id: int, record_table: str = "events") -> Optional[bytes]:
    """Return the unwrapped per-record key, or None (erased / locked / absent)."""
    conn = sqlite3.connect(str(config.DB_PATH), timeout=30.0)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT wrapped_key, wrap_nonce, erased_at FROM record_keys "
            "WHERE record_table=? AND record_id=? ORDER BY id DESC LIMIT 1",
            (record_table, record_id)).fetchone()
    finally:
        conn.close()
    if not row or row["erased_at"] or row["wrapped_key"] is None:
        return None
    return _unwrap_record_key(bytes(row["wrap_nonce"]), bytes(row["wrapped_key"]))


def decrypt_event_fields(event: dict) -> dict:
    """Return a copy of an event row with encrypted fields decrypted for display.
    Encrypted-but-unreadable -> '[ERASED]' (key destroyed) or '[LOCKED]' (no master)."""
    out = dict(event)
    enc_present = any(is_encrypted(out.get(f)) for f in ENCRYPTED_FIELDS)
    if not enc_present:
        return out
    rk = get_record_key(out["id"]) if "id" in out else None
    for f in ENCRYPTED_FIELDS:
        v = out.get(f)
        if not is_encrypted(v):
            continue
        if rk is None:
            # distinguish erased (row exists, key gone) vs locked (no master)
            out[f] = "[ERASED]" if keymgmt.get_master_key() is not None else "[LOCKED]"
        else:
            try:
                out[f] = decrypt_field(rk, v)
            except Exception:
                out[f] = "[DECRYPTION_FAILED]"
    return out


def erase_records(record_ids, record_table: str = "events") -> int:
    """Cryptographic erasure: destroy wrapped keys for the given record ids."""
    if not record_ids:
        return 0
    conn = sqlite3.connect(str(config.DB_PATH), timeout=30.0)
    try:
        conn.execute("PRAGMA busy_timeout=30000")
        n = 0
        for rid in record_ids:
            cur = conn.execute(
                "UPDATE record_keys SET wrapped_key=NULL, wrap_nonce=NULL, erased_at=? "
                "WHERE record_table=? AND record_id=? AND erased_at IS NULL",
                (identity.utcnow_iso(), record_table, rid))
            n += cur.rowcount
        conn.commit()
        return n
    finally:
        conn.close()

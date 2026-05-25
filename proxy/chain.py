"""SHA-256 hash chain helpers."""
import hashlib
import json
from typing import Any, Dict


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_event(event: Dict[str, Any]) -> bytes:
    """Canonical JSON encoding (sorted keys, separators) for stable hashing."""
    return json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def chain_hash(prev_hash: str, event: Dict[str, Any]) -> str:
    """h_n = sha256(prev_hash || canonical(event))."""
    payload = prev_hash.encode("ascii") + canonical_event(event)
    return sha256_hex(payload)


def merkle_root(hashes: list[str]) -> str:
    """Binary Merkle root over a list of hex-encoded sha256 hashes.
    Uses duplication of last leaf if odd count (Bitcoin-style)."""
    if not hashes:
        return "0" * 64
    level = [bytes.fromhex(h) for h in hashes]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        next_level = []
        for i in range(0, len(level), 2):
            next_level.append(hashlib.sha256(level[i] + level[i + 1]).digest())
        level = next_level
    return level[0].hex()


def verify_chain(rows: list[Dict[str, Any]]) -> Dict[str, Any]:
    """Recompute the chain and report whether any event is tampered.

    rows: ordered list of event dicts as stored (must contain prev_hash, this_hash,
          and all fields used at hash time — i.e. everything except this_hash itself).
    Returns: {ok: bool, broken_at: int|None, count: int}
    """
    expected_prev = rows[0]["prev_hash"] if rows else "0" * 64
    for i, row in enumerate(rows):
        if row["prev_hash"] != expected_prev:
            return {"ok": False, "broken_at": i, "count": len(rows)}
        # Rebuild the canonical event exactly as inserted (see proxy.py)
        event = {k: row[k] for k in row.keys() if k not in ("this_hash", "id", "anchor_id")}
        recomputed = chain_hash(row["prev_hash"], event)
        if recomputed != row["this_hash"]:
            return {"ok": False, "broken_at": i, "count": len(rows)}
        expected_prev = row["this_hash"]
    return {"ok": True, "broken_at": None, "count": len(rows)}

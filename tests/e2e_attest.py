"""E2E test — Step 8 universal decision-attestation protocol (live proxy on :3001).

Verifies the second entry point (explicit "certify any decision"): auth gate,
certification, receipt shape, PUBLIC key-free verification, input validation, and
tamper detection (mutate a stored field → independent verify flips to false).

Usage: python tests/e2e_attest.py
Requires the proxy running with the demo users seeded (analyst pw 'demo1234').
"""
import sys
import sqlite3
import hashlib
from pathlib import Path
import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from proxy import config  # noqa: E402

BASE = f"http://{config.PROXY_HOST}:{config.PROXY_PORT}"
DB = str(config.DB_PATH)
PASS = 0
FAIL = 0


def check(name, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"[ OK ] {name}")
    else:
        FAIL += 1
        print(f"[FAIL] {name} {extra}")


def main():
    # 1) attestation requires authentication
    r = httpx.post(f"{BASE}/_immutrace/attest",
                   json={"action": "test.noauth"}, timeout=10)
    check("attest requires auth (401)", r.status_code == 401, f"got {r.status_code}")

    # 2) login as analyst, then certify a decision
    with httpx.Client(base_url=BASE, timeout=15) as c:
        r = c.post("/_immutrace/auth/login", json={"username": "analyst", "password": "demo1234"})
        check("analyst login 200", r.status_code == 200, f"got {r.status_code}")

        inputs = b"the raw decision inputs that must never be transmitted"
        local_digest = hashlib.sha256(inputs).hexdigest()
        r = c.post("/_immutrace/attest", json={
            "action": "loan.decision",
            "subject": "application-42",
            "decision": "denied",
            "rationale": "Debt-to-income ratio above the policy threshold.",
            "inputs_digest": local_digest,
            "actor": "credit-model-v3",
            "metadata": {"model": "credit-v3", "score": 0.31},
        })
        check("attest 200", r.status_code == 200, f"got {r.status_code}: {r.text[:160]}")
        receipt = r.json()

        check("receipt has receipt_id", isinstance(receipt.get("receipt_id"), str)
              and receipt["receipt_id"].startswith("rcpt_"), f"got {receipt.get('receipt_id')}")
        this_hash = receipt.get("this_hash", "")
        check("this_hash is 64 hex chars",
              len(this_hash) == 64 and all(ch in "0123456789abcdef" for ch in this_hash),
              f"got {this_hash!r}")
        check("receipt_id derived from this_hash",
              receipt.get("receipt_id") == "rcpt_" + this_hash[:24])
        check("receipt event_type is decision.attested",
              receipt.get("event_type") == "decision.attested")
        check("receipt actor preserved", receipt.get("actor") == "credit-model-v3")
        check("receipt anchored is False at creation", receipt.get("anchored") is False)
        check("receipt carries verify_url",
              receipt.get("verify_url") == f"/_immutrace/attest/verify/{this_hash}")

    # 3) INDEPENDENT verification — no auth, fresh client
    r = httpx.get(f"{BASE}/_immutrace/attest/verify/{this_hash}", timeout=10)
    check("verify (no auth) 200", r.status_code == 200, f"got {r.status_code}")
    vj = r.json()
    check("verify found", vj.get("found") is True)
    check("verify integrity_ok true", vj.get("integrity_ok") is True, f"got {vj}")
    check("verify reports actor", vj.get("actor") == "credit-model-v3")
    check("verify exposes anchored flag", "anchored" in vj)

    # 4) input validation — malformed and unknown hashes
    r = httpx.get(f"{BASE}/_immutrace/attest/verify/not-a-valid-hash", timeout=10)
    check("malformed hash 400", r.status_code == 400, f"got {r.status_code}")
    unknown = "f" * 64
    r = httpx.get(f"{BASE}/_immutrace/attest/verify/{unknown}", timeout=10)
    check("unknown hash 404", r.status_code == 404, f"got {r.status_code}")

    # 5) TAMPER DETECTION — mutate the stored actor, confirm verify flips to false,
    #    then restore so the global chain heals.
    conn = sqlite3.connect(DB)
    try:
        orig = conn.execute("SELECT actor FROM events WHERE this_hash=?", (this_hash,)).fetchone()[0]
        conn.execute("UPDATE events SET actor=? WHERE this_hash=?",
                     ("TAMPERED-BY-E2E", this_hash))
        conn.commit()
    finally:
        conn.close()
    r = httpx.get(f"{BASE}/_immutrace/attest/verify/{this_hash}", timeout=10)
    check("tampering detected (integrity_ok false)", r.json().get("integrity_ok") is False,
          f"got {r.json()}")

    conn = sqlite3.connect(DB)
    try:
        conn.execute("UPDATE events SET actor=? WHERE this_hash=?", (orig, this_hash))
        conn.commit()
    finally:
        conn.close()
    r = httpx.get(f"{BASE}/_immutrace/attest/verify/{this_hash}", timeout=10)
    check("integrity heals after restore (integrity_ok true)",
          r.json().get("integrity_ok") is True, f"got {r.json()}")

    print(f"\nPASS: {PASS}    FAIL: {FAIL}")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()

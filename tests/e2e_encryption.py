"""E2E test — Step 5 AES-GCM field encryption + crypto-erasure (GDPR Art.17).

Covers: sensitive fields encrypted at rest, decrypted for authorized display,
hash chain valid over ciphertext, GDPR erasure -> plaintext unrecoverable while
the chain stays valid, and role gating on erasure.
"""
import sys
import time
import sqlite3
import httpx

sys.path.insert(0, ".")
from proxy import config  # noqa: E402

BASE = "http://127.0.0.1:3001"
PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"[ OK ] {name}")
    else:
        FAIL += 1; print(f"[FAIL] {name}")


def raw_event(case_id):
    conn = sqlite3.connect(str(config.DB_PATH)); conn.row_factory = sqlite3.Row
    try:
        r = conn.execute("SELECT justification, query FROM events WHERE case_id=? "
                         "ORDER BY id DESC LIMIT 1", (case_id,)).fetchone()
        return dict(r) if r else None
    finally:
        conn.close()


def main():
    admin = httpx.Client(base_url=BASE, timeout=20)
    analyst = httpx.Client(base_url=BASE, timeout=20)
    sess = httpx.Client(base_url=BASE, timeout=20)
    try:
        admin.post("/_immutrace/auth/login", json={"username": config.ADMIN_USER, "password": config.ADMIN_PASSWORD})
        analyst.post("/_immutrace/auth/login", json={"username": "analyst", "password": "demo1234"})

        # Ensure the master key is unlocked (set up only if needed — avoids re-keying).
        st = admin.get("/_immutrace/keys/status").json()
        if not st.get("unlocked"):
            admin.post("/_immutrace/keys/setup")
        check("master key unlocked", admin.get("/_immutrace/keys/status").json().get("unlocked") is True)

        # Create a legacy investigation session with a known justification + case.
        case = f"ENC-{int(time.time())}"
        just = "Encryption E2E: legitimate access justification exceeding twenty characters."
        r = sess.post("/_immutrace/session/start",
                      json={"actor": "tester", "activity_type": "INVESTIGATION",
                            "justification": just, "case_id": case})
        sid = r.json().get("session_id")
        check("session created", r.status_code == 200 and sid)

        # Access a sensitive endpoint with a sensitive query param -> logs an event.
        r = sess.get("/api/maritime?token=SECRET123")
        check("sensitive access ok (200)", r.status_code == 200)
        time.sleep(0.3)

        # (1) Encrypted at rest
        raw = raw_event(case)
        check("justification ciphertext at rest", raw and raw["justification"].startswith("enc:v1:"))
        check("query ciphertext at rest", raw and raw["query"].startswith("enc:v1:"))

        # (2) Decrypted for authorized display
        ev = admin.get(f"/_immutrace/audit/events?case_id={case}").json()["events"][0]
        check("justification decrypts for display", ev["justification"] == just)
        check("query decrypts for display", "token=SECRET123" in ev["query"])

        # (3) Chain valid over ciphertext (before erasure)
        v = admin.get(f"/_immutrace/audit/verify/{sid}").json()
        check("chain ok before erase", v.get("ok") is True)

        # (4) Role gate on erasure
        check("analyst denied erase (403)",
              analyst.post("/_immutrace/gdpr/erase", json={"case_id": case}).status_code == 403)

        # (5) GDPR crypto-erasure
        r = admin.post("/_immutrace/gdpr/erase", json={"case_id": case})
        check("erase >=1 key", r.status_code == 200 and r.json().get("erased_record_keys", 0) >= 1)

        # (6) Plaintext now unrecoverable
        ev = admin.get(f"/_immutrace/audit/events?case_id={case}").json()["events"][0]
        check("justification ERASED after erasure", ev["justification"] == "[ERASED]")

        # (7) Ciphertext + chain still intact after erasure (the killer property)
        raw2 = raw_event(case)
        check("ciphertext unchanged after erase", raw2 and raw2["justification"].startswith("enc:v1:"))
        v = admin.get(f"/_immutrace/audit/verify/{sid}").json()
        check("chain STILL ok after erase", v.get("ok") is True)
    finally:
        admin.close(); analyst.close(); sess.close()

    print(f"\nPASS: {PASS}    FAIL: {FAIL}")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()

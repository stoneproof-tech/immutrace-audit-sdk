"""End-to-end smoke test for the IMMUTRACE Audit SDK.

Assumes:
  * OSIRIS is running on http://127.0.0.1:3000
  * IMMUTRACE proxy is running on http://127.0.0.1:3001

Run: python -m tests.smoke_test
Exit code 0 = all PASS.
"""
import sys
import sqlite3
import time
from pathlib import Path
import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from proxy import config

PROXY = f"http://{config.PROXY_HOST}:{config.PROXY_PORT}"
DB = str(config.DB_PATH)
PASS, FAIL = [], []


def case(name: str, ok: bool, detail: str = ""):
    bucket = PASS if ok else FAIL
    bucket.append((name, detail))
    sym = "[ OK ]" if ok else "[FAIL]"
    print(f"{sym} {name}" + (f"  -- {detail}" if detail and not ok else ""))


def main():
    # 1. Proxy health
    try:
        r = httpx.get(f"{PROXY}/_immutrace/health", timeout=5)
        case("proxy health 200", r.status_code == 200 and r.json()["ok"],
             f"got {r.status_code}")
    except Exception as e:
        case("proxy health 200", False, str(e))
        return summary()

    # 2. HTML root is proxied + SDK injected
    r = httpx.get(f"{PROXY}/", timeout=15)
    case("root HTML proxied 200", r.status_code == 200,
         f"got {r.status_code}")
    case("SDK script injected into HTML",
         "/_immutrace/sdk.js" in r.text,
         "sdk.js script tag not found")

    # 3. SDK assets served
    for asset in ["/_immutrace/sdk.js", "/_immutrace/dashboard",
                  "/_immutrace/dashboard/style.css", "/_immutrace/dashboard/app.js"]:
        r = httpx.get(f"{PROXY}{asset}", timeout=5)
        case(f"asset {asset} 200", r.status_code == 200,
             f"got {r.status_code}")

    # 4. Sensitive endpoint without session → 401
    r = httpx.get(f"{PROXY}/api/flights", timeout=10)
    case("sensitive endpoint blocked without session",
         r.status_code == 401 and r.json().get("error") == "AUTH_REQUIRED",
         f"got {r.status_code}: {r.text[:120]}")
    case("X-Immutrace-Gate header present",
         r.headers.get("X-Immutrace-Gate") == "blocked")

    # 5. Auth denial is itself logged
    conn = sqlite3.connect(DB)
    cur = conn.execute("SELECT COUNT(*) FROM events WHERE event_type='auth_denied'")
    n_denied = cur.fetchone()[0]
    conn.close()
    case("auth_denied event logged", n_denied >= 1, f"count={n_denied}")

    # 6. Bad session start (justification too short)
    with httpx.Client(timeout=5) as c:
        r = c.post(f"{PROXY}/_immutrace/session/start", json={
            "actor": "test", "activity_type": "OSINT_RESEARCH",
            "justification": "too short"})
        case("bad justification rejected (<20 chars)",
             r.status_code == 400, f"got {r.status_code}")
        r = c.post(f"{PROXY}/_immutrace/session/start", json={
            "actor": "test", "activity_type": "INVALID_TYPE",
            "justification": "Long enough justification text for testing."})
        case("invalid activity_type rejected",
             r.status_code == 400, f"got {r.status_code}")

    # 7. Good session creates cookie + lets us through
    with httpx.Client(timeout=15) as c:
        r = c.post(f"{PROXY}/_immutrace/session/start", json={
            "actor": "smoke.test@example.com",
            "activity_type": "OSINT_RESEARCH",
            "case_id": "SMOKE-001",
            "justification": "Automated smoke test — verifying gate and chain end-to-end.",
        })
        case("session/start succeeds with valid input",
             r.status_code == 200, f"got {r.status_code}: {r.text[:120]}")
        sid = r.json()["session_id"]
        case("session_id returned", bool(sid))

        # Sensitive endpoint now works
        r = c.get(f"{PROXY}/api/flights")
        case("sensitive endpoint OK with session",
             r.status_code == 200, f"got {r.status_code}")

        # A few more for chain depth
        for url in ["/api/maritime", "/api/satellites", "/api/earthquakes"]:
            r = c.get(f"{PROXY}{url}")
            case(f"{url} OK with session", r.status_code == 200,
                 f"got {r.status_code}")

    # 8. Verify chain
    r = httpx.get(f"{PROXY}/_immutrace/audit/verify/{sid}", timeout=5)
    j = r.json()
    case("chain verifies (ok=true)", j.get("ok") is True,
         f"got {j}")
    case("chain has events", j.get("count", 0) >= 4,
         f"count={j.get('count')}")

    # 9. Force anchor + check
    r = httpx.post(f"{PROXY}/_immutrace/audit/anchor-now", timeout=10)
    j = r.json()
    case("anchor-now succeeds", j.get("ok") is True,
         f"got {j}")
    if j.get("ok"):
        case("anchor has merkle_root",
             bool(j["anchor"].get("merkle_root")))
        case("anchor has tx_hash",
             bool(j["anchor"].get("tx_hash")))
        case("anchor chain identified",
             j["anchor"].get("chain") in ("mock", "polygon-amoy"))

    # 10. PDF export
    r = httpx.get(f"{PROXY}/_immutrace/audit/export/{sid}.pdf", timeout=15)
    case("PDF export 200", r.status_code == 200,
         f"got {r.status_code}")
    case("PDF is non-empty (>2 KB)", len(r.content) > 2048,
         f"size={len(r.content)}")
    case("PDF starts with %PDF magic", r.content[:4] == b"%PDF",
         f"head={r.content[:8]}")

    # 11. Tampering detection
    conn = sqlite3.connect(DB)
    orig = conn.execute(
        "SELECT path FROM events WHERE session_id=? ORDER BY id ASC LIMIT 1",
        (sid,)
    ).fetchone()[0]
    conn.execute(
        "UPDATE events SET path = ? WHERE session_id = ? "
        "AND id = (SELECT MIN(id) FROM events WHERE session_id = ?)",
        ("/api/TAMPERED-BY-SMOKE-TEST", sid, sid),
    )
    conn.commit()
    conn.close()
    r = httpx.get(f"{PROXY}/_immutrace/audit/verify/{sid}", timeout=5)
    case("tampering detected (ok=false)",
         r.json().get("ok") is False, f"got {r.json()}")

    # Restore
    conn = sqlite3.connect(DB)
    conn.execute(
        "UPDATE events SET path = ? WHERE session_id = ? "
        "AND id = (SELECT MIN(id) FROM events WHERE session_id = ?)",
        (orig, sid, sid),
    )
    conn.commit()
    conn.close()
    r = httpx.get(f"{PROXY}/_immutrace/audit/verify/{sid}", timeout=5)
    case("chain heals after restore (ok=true)",
         r.json().get("ok") is True)

    summary()


def summary():
    print()
    print(f"PASS: {len(PASS)}    FAIL: {len(FAIL)}")
    if FAIL:
        print("\nFAILURES:")
        for n, d in FAIL:
            print(f"  [FAIL] {n}  -- {d}")
    sys.exit(0 if not FAIL else 1)


if __name__ == "__main__":
    main()

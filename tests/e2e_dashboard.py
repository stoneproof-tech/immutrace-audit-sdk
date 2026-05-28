"""E2E test — Step 8 dashboard filters (audit events + approval queue)."""
import sys
import httpx

sys.path.insert(0, ".")
from proxy import config  # noqa: E402

BASE = "http://127.0.0.1:3001"
PASS = 0
FAIL = 0


def check(name, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"[ OK ] {name}")
    else:
        FAIL += 1; print(f"[FAIL] {name} {extra}")


def main():
    c = httpx.Client(base_url=BASE, timeout=20)
    try:
        c.post("/_immutrace/auth/login", json={"username": config.ADMIN_USER, "password": config.ADMIN_PASSWORD})

        # actor filter (system events from timestamping/anchoring use actor 'immutrace')
        evs = c.get("/_immutrace/audit/events?actor=immutrace&limit=100").json()["events"]
        check("actor filter returns rows", len(evs) > 0)
        check("actor filter all match", all(e["actor"] == "immutrace" for e in evs))

        # risk filter
        crit = c.get("/_immutrace/audit/events?risk=critical&limit=200").json()["events"]
        check("risk=critical all critical",
              all(config.risk_level(e.get("path") or "") == "critical" for e in crit))
        none_ev = c.get("/_immutrace/audit/events?risk=none&limit=100").json()["events"]
        check("risk=none all non-sensitive",
              all(config.risk_level(e.get("path") or "") == "none" for e in none_ev))

        # date range
        fut = c.get("/_immutrace/audit/events?ts_from=2099-01-01").json()["events"]
        check("future ts_from -> empty", len(fut) == 0)

        # approval queue status filter (admin has supervisor access)
        appr = c.get("/_immutrace/approval/queue?status=approved").json()["requests"]
        check("queue approved all approved", all(r["status"] == "approved" for r in appr))
        rej = c.get("/_immutrace/approval/queue?status=rejected").json()["requests"]
        check("queue rejected all rejected", all(r["status"] == "rejected" for r in rej))
        allr = c.get("/_immutrace/approval/queue?status=all").json()["requests"]
        check("queue all >= approved+rejected", len(allr) >= len(appr) + len(rej))
    finally:
        c.close()

    print(f"\nPASS: {PASS}    FAIL: {FAIL}")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()

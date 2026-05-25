"""E2E test — Step 3 approval workflow (pre-authorization). Run against live :3001.

Verifies: analyst request -> still blocked -> supervisor approves -> access granted;
reject path; separation of duties; role gating; audit events recorded.
"""
import sys
import time
import httpx

sys.path.insert(0, ".")
from proxy import config  # noqa: E402  (admin password, never printed)

BASE = "http://127.0.0.1:3001"
PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"[ OK ] {name}")
    else:
        FAIL += 1; print(f"[FAIL] {name}")


def client():
    return httpx.Client(base_url=BASE, timeout=15)


def login(c, user, pw):
    return c.post("/_immutrace/auth/login", json={"username": user, "password": pw})


def main():
    analyst = client()
    supervisor = client()
    admin = client()
    try:
        # Fresh analyst per run (so leftover approvals from prior runs don't leak,
        # since approvals are time-boxed and persist in the DB).
        check("admin login", login(admin, config.ADMIN_USER, config.ADMIN_PASSWORD).status_code == 200)
        uname = f"wf_{int(time.time())}"
        r = admin.post("/_immutrace/auth/users",
                       json={"username": uname, "password": "wfpass12345", "role": "analyst"})
        check("admin created fresh analyst", r.status_code == 200)

        check("analyst login", login(analyst, uname, "wfpass12345").status_code == 200)
        check("supervisor login", login(supervisor, "supervisor", "demo1234").status_code == 200)

        # analyst hits sensitive endpoint with NO approval -> blocked
        r = analyst.get("/api/maritime")
        check("maritime blocked before approval (401)", r.status_code == 401
              and r.headers.get("X-Immutrace-Gate") == "blocked")

        # analyst requests authorization
        r = analyst.post("/_immutrace/approval/request", json={
            "target_path": "/api/maritime",
            "justification": "Sanctions enforcement review, Red Sea vessel traffic.",
            "case_id": "CASE-2026-0142", "urgency": "high"})
        check("request created (pending)", r.status_code == 200 and r.json().get("status") == "pending")
        rid = r.json().get("id")

        # still blocked while pending
        check("still blocked while pending (401)", analyst.get("/api/maritime").status_code == 401)

        # analyst cannot see the supervisor queue
        check("analyst denied /queue (403)", analyst.get("/_immutrace/approval/queue").status_code == 403)

        # supervisor sees it in queue
        r = supervisor.get("/_immutrace/approval/queue")
        ids = [x["id"] for x in r.json().get("pending", [])]
        check("request visible in supervisor queue", rid in ids)

        # supervisor approves
        r = supervisor.post(f"/_immutrace/approval/{rid}/approve",
                            json={"note": "Approved — legitimate sanctions case."})
        check("approve 200", r.status_code == 200 and r.json().get("status") == "approved")

        # analyst now authorized
        r = analyst.get("/api/maritime")
        check("maritime ALLOWED after approval (200)", r.status_code == 200)

        # audit chain recorded the approval decision
        ev = supervisor.get("/_immutrace/audit/events?limit=200").json().get("events", [])
        types = {e["event_type"] for e in ev}
        check("approval_approved event in chain", "approval_approved" in types)

        # reject path
        r = analyst.post("/_immutrace/approval/request", json={
            "target_path": "/api/flights",
            "justification": "Checking flight near restricted area for case.",
            "urgency": "normal"})
        rid2 = r.json().get("id")
        r = supervisor.post(f"/_immutrace/approval/{rid2}/reject", json={"note": "Insufficient justification."})
        check("reject 200", r.status_code == 200 and r.json().get("status") == "rejected")
        check("flights still blocked after reject (401)", analyst.get("/api/flights").status_code == 401)

        # separation of duties: supervisor cannot approve own request
        r = supervisor.post("/_immutrace/approval/request", json={
            "target_path": "/api/cctv",
            "justification": "Reviewing camera feeds for incident corroboration.",
            "urgency": "low"})
        rid3 = r.json().get("id")
        r = supervisor.post(f"/_immutrace/approval/{rid3}/approve", json={"note": "self"})
        check("cannot approve own request (403)", r.status_code == 403)

        # validation: short justification rejected
        r = analyst.post("/_immutrace/approval/request",
                         json={"target_path": "/api/maritime", "justification": "short"})
        check("short justification rejected (400)", r.status_code == 400)

        # validation: non-sensitive path rejected
        r = analyst.post("/_immutrace/approval/request",
                         json={"target_path": "/api/earthquakes", "justification": "not sensitive at all here"})
        check("non-sensitive path rejected (400)", r.status_code == 400)
    finally:
        analyst.close(); supervisor.close(); admin.close()

    print(f"\nPASS: {PASS}    FAIL: {FAIL}")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()

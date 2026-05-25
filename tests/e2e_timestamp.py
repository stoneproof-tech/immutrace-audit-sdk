"""E2E test — Step 6 eIDAS-ready timestamping.

Covers: local provider signs/verifies, token commits to the data hash, QTSP stub
raises a clear NotImplementedError, factory falls back to local when a QTSP is
selected but not configured, HTTP timestamp + verify endpoints, and the fact that
timestamp generation is itself an auditable chain event.
"""
import os
import sys
import json
import time
import hashlib
import httpx

sys.path.insert(0, ".")
from proxy import config, timestamp  # noqa: E402

BASE = "http://127.0.0.1:3001"
PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"[ OK ] {name}")
    else:
        FAIL += 1; print(f"[FAIL] {name}")


def unit():
    local = timestamp.LocalTimestampProvider()
    tok = local.timestamp(b"hello-immutrace")
    check("local token not qualified", tok.is_qualified is False and tok.provider_name == "local")
    check("local verify OK", local.verify(tok.token_bytes, b"hello-immutrace") is True)
    check("local verify fails on tampered data", local.verify(tok.token_bytes, b"tampered") is False)
    payload = json.loads(tok.token_bytes.decode())
    check("token commits to data hash",
          payload["hash"] == hashlib.sha256(b"hello-immutrace").hexdigest())

    try:
        timestamp.ArubaQTSPProvider().timestamp(b"x"); raised = False
    except NotImplementedError as e:
        raised = "contract" in str(e).lower() or "not active" in str(e).lower()
    check("QTSP stub raises clear NotImplementedError", raised)

    # factory fallback: select aruba but leave ARUBA_TSA_URL empty -> local
    old = os.environ.get("TIMESTAMP_PROVIDER")
    os.environ["TIMESTAMP_PROVIDER"] = "aruba"
    os.environ.pop("ARUBA_TSA_URL", None)
    check("factory falls back to local when QTSP unconfigured",
          isinstance(timestamp.get_provider(), timestamp.LocalTimestampProvider))
    if old is None:
        os.environ.pop("TIMESTAMP_PROVIDER", None)
    else:
        os.environ["TIMESTAMP_PROVIDER"] = old


def main():
    unit()

    admin = httpx.Client(base_url=BASE, timeout=20)
    sess = httpx.Client(base_url=BASE, timeout=20)
    try:
        admin.post("/_immutrace/auth/login", json={"username": config.ADMIN_USER, "password": config.ADMIN_PASSWORD})

        # create a legacy session and hit a CRITICAL endpoint -> event gets timestamped
        case = f"TS-{int(time.time())}"
        r = sess.post("/_immutrace/session/start",
                      json={"actor": "tester", "activity_type": "INVESTIGATION",
                            "justification": "Timestamp E2E justification exceeding twenty characters.",
                            "case_id": case})
        sid = r.json().get("session_id")
        sess.get("/api/maritime")  # /api/maritime is 'critical' -> timestamped by default

        # find the access event id
        eid = None
        evs = admin.get(f"/_immutrace/audit/events?session_id={sid}").json()["events"]
        for e in evs:
            if e["event_type"] == "http_request" and e["path"] == "/api/maritime":
                eid = e["id"]; break
        check("found access event", eid is not None)

        # poll for the background-generated timestamp
        ts = None
        for _ in range(20):
            r = admin.get(f"/_immutrace/audit/events/{eid}/timestamp")
            if r.status_code == 200:
                ts = r.json(); break
            time.sleep(0.4)
        check("timestamp generated for event", ts is not None)
        check("timestamp provider local", ts and ts["provider"] == "local")
        check("timestamp not qualified (local)", ts and ts["is_qualified"] is False)

        # verify endpoint
        r = admin.post(f"/_immutrace/audit/events/{eid}/verify-timestamp")
        check("verify-timestamp ok", r.status_code == 200 and r.json().get("ok") is True)
        check("verify status valid", r.json().get("status") == "valid")

        # timestamp generation is itself auditable
        types = {e["event_type"] for e in admin.get("/_immutrace/audit/events?limit=300").json()["events"]}
        check("event_timestamped in chain", "event_timestamped" in types)

        # missing timestamp -> 404
        check("no timestamp -> 404", admin.get("/_immutrace/audit/events/99999999/timestamp").status_code == 404)
    finally:
        admin.close(); sess.close()

    print(f"\nPASS: {PASS}    FAIL: {FAIL}")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()

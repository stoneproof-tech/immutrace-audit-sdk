"""E2E test — Step 4 Shamir key custody. Run against live :3001.

Covers: Shamir split/reconstruct math (incl. below-threshold and tampered),
the HTTP custody ceremony (setup -> reassembly start/submit/finalize), role
gating, and audit-chain events.
"""
import sys
import httpx

sys.path.insert(0, ".")
from proxy import config, shamir  # noqa: E402

BASE = "http://127.0.0.1:3001"
PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"[ OK ] {name}")
    else:
        FAIL += 1; print(f"[FAIL] {name}")


def c():
    return httpx.Client(base_url=BASE, timeout=20)


def login(cl, u, p):
    return cl.post("/_immutrace/auth/login", json={"username": u, "password": p})


def shamir_unit():
    s = b"IMMUTRACE-master-key-32bytes!!!!"  # 32 bytes
    shares = shamir.split_secret(s, threshold=3, num_shares=5)
    check("split -> 5 shares", len(shares) == 5)
    check("reconstruct first 3 == secret", shamir.reconstruct_secret(shares[:3], threshold=3) == s)
    check("reconstruct any 3 == secret",
          shamir.reconstruct_secret([shares[0], shares[2], shares[4]], threshold=3) == s)
    try:
        shamir.reconstruct_secret(shares[:2], threshold=3); below = False
    except ValueError:
        below = True
    check("2 shares rejected (below threshold)", below)
    idx, data = shares[0]
    tampered = [(idx, bytes([data[0] ^ 0xFF]) + data[1:]), shares[1], shares[2]]
    check("tampered share -> wrong key", shamir.reconstruct_secret(tampered, threshold=3) != s)


def main():
    shamir_unit()

    admin, analyst, notaio = c(), c(), c()
    try:
        check("admin login", login(admin, config.ADMIN_USER, config.ADMIN_PASSWORD).status_code == 200)
        check("analyst login", login(analyst, "analyst", "demo1234").status_code == 200)

        # non-admin cannot set up keys
        check("analyst denied setup (403)", analyst.post("/_immutrace/keys/setup").status_code == 403)

        # admin setup
        r = admin.post("/_immutrace/keys/setup")
        check("admin setup 200", r.status_code == 200)
        st = r.json()
        check("configured + unlocked", st.get("configured") and st.get("unlocked"))
        check("3-of-5", st.get("threshold") == 3 and st.get("num_shares") == 5)
        check("5 custodians provisioned", len(st.get("custodians", [])) == 5)

        # below-threshold finalize fails
        aid = admin.post("/_immutrace/keys/reassembly/start").json()["attempt_id"]
        admin.post(f"/_immutrace/keys/reassembly/{aid}/submit-share", json={"custodian_id": 1})
        admin.post(f"/_immutrace/keys/reassembly/{aid}/submit-share", json={"custodian_id": 2})
        check("finalize below threshold (409)",
              admin.post(f"/_immutrace/keys/reassembly/{aid}/finalize").status_code == 409)

        # full reassembly with 3 shares
        aid2 = admin.post("/_immutrace/keys/reassembly/start").json()["attempt_id"]
        for cid in (1, 2, 3):
            admin.post(f"/_immutrace/keys/reassembly/{aid2}/submit-share", json={"custodian_id": cid})
        rf = admin.post(f"/_immutrace/keys/reassembly/{aid2}/finalize")
        check("finalize with 3 shares 200", rf.status_code == 200 and rf.json().get("unlocked"))

        # custodian self-only rule (notaio = custodian id 1, created during setup)
        check("notaio (custodian) login", login(notaio, "notaio", "demo1234").status_code == 200)
        aid3 = admin.post("/_immutrace/keys/reassembly/start").json()["attempt_id"]
        check("custodian submits OWN share (200)",
              notaio.post(f"/_immutrace/keys/reassembly/{aid3}/submit-share",
                          json={"custodian_id": 1}).status_code == 200)
        check("custodian denied OTHER share (403)",
              notaio.post(f"/_immutrace/keys/reassembly/{aid3}/submit-share",
                          json={"custodian_id": 2}).status_code == 403)
        check("analyst denied submit (403)",
              analyst.post(f"/_immutrace/keys/reassembly/{aid3}/submit-share",
                           json={"custodian_id": 1}).status_code == 403)

        # audit chain events
        ev = admin.get("/_immutrace/audit/events?limit=300").json().get("events", [])
        types = {e["event_type"] for e in ev}
        for et in ("key_setup", "key_reassembly_start", "key_share_submitted", "key_reassembly_complete"):
            check(f"audit event {et}", et in types)
    finally:
        admin.close(); analyst.close(); notaio.close()

    print(f"\nPASS: {PASS}    FAIL: {FAIL}")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()

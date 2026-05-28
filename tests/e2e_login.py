"""E2E test — Step 2 multi-user login (run against a live proxy on :3001).

Usage: python tests/e2e_login.py
Requires the proxy running with the demo users seeded (analyst/supervisor/
custodian pw 'demo1234', admin pw from ADMIN_PASSWORD).
"""
import sys
import time
import httpx

# Pull the admin password from config (so it's never hard-coded / printed).
sys.path.insert(0, ".")
from proxy import config  # noqa: E402

BASE = "http://127.0.0.1:3001"
PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"[ OK ] {name}")
    else:
        FAIL += 1
        print(f"[FAIL] {name}")


def main():
    # 1) analyst login
    with httpx.Client(base_url=BASE, timeout=10) as c:
        r = c.post("/_immutrace/auth/login", json={"username": "analyst", "password": "demo1234"})
        check("analyst login 200", r.status_code == 200)
        check("analyst role correct", r.json().get("role") == "analyst")
        check("auth cookie set", "__immutrace_auth" in c.cookies

        )
        r = c.get("/_immutrace/auth/me")
        check("me authenticated", r.json().get("authenticated") is True)
        check("me username analyst", r.json().get("username") == "analyst")

        # analyst must NOT reach admin endpoints
        r = c.get("/_immutrace/auth/users")
        check("analyst denied /users (403)", r.status_code == 403)

        # logout
        r = c.post("/_immutrace/auth/logout")
        check("logout 200", r.status_code == 200)
        r = c.get("/_immutrace/auth/me")
        check("me not authenticated after logout", r.json().get("authenticated") is False)

    # 2) wrong password
    with httpx.Client(base_url=BASE, timeout=10) as c:
        r = c.post("/_immutrace/auth/login", json={"username": "analyst", "password": "wrong"})
        check("wrong password 401", r.status_code == 401)

    # 3) admin flow
    with httpx.Client(base_url=BASE, timeout=10) as c:
        r = c.post("/_immutrace/auth/login", json={"username": config.ADMIN_USER, "password": config.ADMIN_PASSWORD})
        check("admin login 200", r.status_code == 200)
        check("admin role correct", r.json().get("role") == "admin")

        r = c.get("/_immutrace/auth/users")
        check("admin lists users 200", r.status_code == 200)
        users = r.json().get("users", [])
        roles = {u["role"] for u in users}
        check("4 demo roles present", {"admin", "analyst", "supervisor", "custodian"} <= roles)

        # create a fresh user (unique name per run)
        uname = f"e2e_{int(time.time())}"
        r = c.post("/_immutrace/auth/users",
                   json={"username": uname, "password": "strongpw123", "role": "analyst"})
        check("admin creates user 200", r.status_code == 200)
        new_id = r.json().get("id")

        # duplicate username rejected
        r = c.post("/_immutrace/auth/users",
                   json={"username": uname, "password": "strongpw123", "role": "analyst"})
        check("duplicate username 409", r.status_code == 409)

        # weak password rejected
        r = c.post("/_immutrace/auth/users",
                   json={"username": uname + "x", "password": "short", "role": "analyst"})
        check("weak password 400", r.status_code == 400)

        # deactivate the created user
        r = c.patch(f"/_immutrace/auth/users/{new_id}", json={"active": False})
        check("admin deactivates user 200", r.status_code == 200)

    # 4) deactivated user cannot log in
    with httpx.Client(base_url=BASE, timeout=10) as c:
        r = c.post("/_immutrace/auth/login", json={"username": uname, "password": "strongpw123"})
        check("deactivated user cannot login (401)", r.status_code == 401)

    print(f"\nPASS: {PASS}    FAIL: {FAIL}")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()

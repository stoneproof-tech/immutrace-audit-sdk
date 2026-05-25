"""E2E test — anchor self-loop prevention (Step 7.6 fix).

Verifies get_pending_events() excludes system event types so anchoring its own
'anchor_posted' (and 'event_timestamped'/'gdpr_erasure') events can't feed an
infinite batch loop. Uses an ISOLATED temp DB (does not touch the real chain).
"""
import sys
import os
import sqlite3
import tempfile
sys.path.insert(0, ".")
from proxy import anchor, config  # noqa: E402

PASS = 0
FAIL = 0


def check(name, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"[ OK ] {name}")
    else:
        FAIL += 1; print(f"[FAIL] {name} {extra}")


def main():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    c = sqlite3.connect(path)
    c.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, this_hash TEXT, "
              "anchor_id INTEGER, event_type TEXT)")
    rows = [
        (1, "h1", None, "http_request"),       # real, pending  -> included
        (2, "h2", None, "http_request"),       # real, pending  -> included
        (3, "h3", None, "anchor_posted"),      # system         -> excluded
        (4, "h4", None, "event_timestamped"),  # system         -> excluded
        (5, "h5", None, "gdpr_erasure"),       # system         -> excluded
        (6, "h6", 1, "http_request"),          # already anchored -> excluded
        (7, "h7", None, "auth_denied"),        # real, pending  -> included
    ]
    c.executemany("INSERT INTO events VALUES (?,?,?,?)", rows)
    c.commit(); c.close()

    orig = config.DB_PATH
    config.DB_PATH = path
    try:
        pending = anchor.get_pending_events()
        ids = sorted(e["id"] for e in pending)
        check("system event types defined",
              set(anchor.SYSTEM_EVENT_TYPES) == {"anchor_posted", "event_timestamped", "gdpr_erasure"})
        check("batch includes only real, un-anchored events", ids == [1, 2, 7], f"got {ids}")
        check("anchor_posted excluded (loop broken)", 3 not in ids)
        check("event_timestamped excluded", 4 not in ids)
        check("gdpr_erasure excluded", 5 not in ids)
        check("already-anchored event excluded", 6 not in ids)
        # idle system-only scenario: no real events pending -> empty batch -> no anchor
        c2 = sqlite3.connect(path)
        c2.execute("UPDATE events SET anchor_id=99 WHERE id IN (1,2,7)")  # all real anchored
        c2.commit(); c2.close()
        check("system-only pending -> empty batch (no idle anchor)",
              len(anchor.get_pending_events()) == 0)
    finally:
        config.DB_PATH = orig
        os.unlink(path)

    print(f"\nPASS: {PASS}    FAIL: {FAIL}")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()

"""E2E test — Step 7.6 anchor worker robustness (MOCK, no real tx, no network).

Drives the extracted _try_anchor_once() with monkeypatched anchor_batch /
pre-flight to verify: failures don't crash, errors are logged + counted, the
worker stops after ANCHOR_MAX_RETRIES, success resets, a 'stopped' worker skips,
and pre-flight failure skips WITHOUT attempting an anchor.
"""
import sys
import sqlite3
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


def err_count():
    c = sqlite3.connect(str(config.DB_PATH))
    try:
        return c.execute("SELECT COUNT(*) FROM anchor_errors").fetchone()[0]
    finally:
        c.close()


def reset_state():
    anchor._worker_state.update({"active": True, "stopped": False, "retry_count": 0,
                                 "last_error": None, "last_anchor_at": None, "last_anchor_tx": None})


def main():
    orig_batch = anchor.anchor_batch
    orig_preflight = anchor._preflight_mainnet
    orig_mock = config.MOCK_ANCHOR
    config.MOCK_ANCHOR = True  # mock: no pre-flight, no real tx

    try:
        # A) failures don't crash; retry increments; stops after MAX_RETRIES
        reset_state()
        anchor.anchor_batch = lambda: (_ for _ in ()).throw(RuntimeError("simulated RPC down"))
        e0 = err_count()
        r1 = anchor._try_anchor_once(); r2 = anchor._try_anchor_once(); r3 = anchor._try_anchor_once()
        check("failed attempts return None (no crash)", r1 is None and r2 is None and r3 is None)
        check("retry_count reached max", anchor._worker_state["retry_count"] == config.ANCHOR_MAX_RETRIES)
        check("worker stopped after max retries", anchor._worker_state["stopped"] is True)
        check("errors logged to anchor_errors", err_count() >= e0 + config.ANCHOR_MAX_RETRIES)
        check("last_error recorded", "simulated RPC down" in (anchor._worker_state["last_error"] or ""))

        # B) a stopped worker skips without attempting
        called = {"n": 0}
        def boom():
            called["n"] += 1; raise RuntimeError("should not be called")
        anchor.anchor_batch = boom
        r = anchor._try_anchor_once()
        check("stopped worker skips (no attempt)", r is None and called["n"] == 0)

        # C) success resets failure counters
        reset_state()
        anchor._worker_state["retry_count"] = 2
        anchor.anchor_batch = lambda: {"chain": "mock", "merkle_root": "ab" * 32,
                                       "event_count": 1, "tx_hash": "0xmocktx"}
        rec = anchor._try_anchor_once()
        check("success returns record", rec is not None and rec["tx_hash"] == "0xmocktx")
        check("retry_count reset on success", anchor._worker_state["retry_count"] == 0)
        check("not stopped on success", anchor._worker_state["stopped"] is False)
        check("last_anchor_tx updated", anchor._worker_state["last_anchor_tx"] == "0xmocktx")

        # D) pre-flight failure skips WITHOUT attempting an anchor (mainnet path)
        reset_state()
        config.MOCK_ANCHOR = False
        anchor._preflight_mainnet = lambda: (False, "LOW BALANCE 0.0100 POL < reserve — refill needed")
        called["n"] = 0
        anchor.anchor_batch = boom
        r = anchor._try_anchor_once()
        check("pre-flight failure skips (no anchor attempt)", r is None and called["n"] == 0)
        check("pre-flight reason recorded", "LOW BALANCE" in (anchor._worker_state["last_error"] or ""))

        # E) pre-flight pass proceeds to anchor (still mocked send)
        reset_state()
        anchor._preflight_mainnet = lambda: (True, "ok")
        anchor.anchor_batch = lambda: {"chain": "polygon-mainnet", "merkle_root": "cd" * 32,
                                       "event_count": 2, "tx_hash": "0xfakemainnet"}
        rec = anchor._try_anchor_once()
        check("pre-flight pass -> anchor proceeds", rec is not None and rec["tx_hash"] == "0xfakemainnet")

        # F) worker_status shape
        config.MOCK_ANCHOR = True
        st = anchor.worker_status()
        check("worker_status has required keys",
              all(k in st for k in ("active", "mode", "retry_count", "stopped",
                                    "last_anchor_tx", "last_error", "balance_pol", "nonce")))
        check("worker_status mode mock", st["mode"] == "mock")
    finally:
        anchor.anchor_batch = orig_batch
        anchor._preflight_mainnet = orig_preflight
        config.MOCK_ANCHOR = orig_mock
        reset_state(); anchor._worker_state["stopped"] = False

    print(f"\nPASS: {PASS}    FAIL: {FAIL}")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()

"""Concurrent-load test for the chain writer.

Validates the _chain_lock + WAL + asyncio.to_thread fix: when the browser
hammers the proxy with 30+ parallel asset/API fetches (as Next.js does on
page load), every event must still land in the chain with a correct
prev_hash linkage and no SQLite-locked errors.

Run: python -m tests.concurrency_test
"""
import asyncio
import sqlite3
import sys
from pathlib import Path
import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from proxy import config

PROXY = f"http://{config.PROXY_HOST}:{config.PROXY_PORT}"
N_PARALLEL = 30


async def burst(client: httpx.AsyncClient, path: str) -> int:
    r = await client.get(f"{PROXY}{path}")
    return r.status_code


async def main() -> int:
    # 1. Start a session
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.post(f"{PROXY}/_immutrace/session/start", json={
            "actor": "concurrency.test@example.com",
            "activity_type": "OSINT_RESEARCH",
            "case_id": "CONC-001",
            "justification": "Concurrent load test — validating chain writer under parallel asset bursts.",
        })
        assert r.status_code == 200, r.text
        sid = r.json()["session_id"]

        # 2. Burst N_PARALLEL requests in parallel, mixing endpoints
        endpoints = ["/api/flights", "/api/maritime", "/api/satellites",
                     "/api/earthquakes", "/api/news", "/api/health"]
        tasks = [burst(c, endpoints[i % len(endpoints)]) for i in range(N_PARALLEL)]
        statuses = await asyncio.gather(*tasks, return_exceptions=True)

    # 3. Verify all returned 2xx (or 5xx from upstream, not 4xx auth fail)
    ok_count = sum(1 for s in statuses if isinstance(s, int) and 200 <= s < 300)
    err_count = sum(1 for s in statuses if isinstance(s, Exception))
    print(f"Bursted {N_PARALLEL} parallel requests:")
    print(f"  2xx: {ok_count}")
    print(f"  exceptions: {err_count}")
    print(f"  status distribution: "
          f"{sorted(set(s for s in statuses if isinstance(s, int)))}")

    # 4. Verify the chain is still intact for this session
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get(f"{PROXY}/_immutrace/audit/verify/{sid}")
        v = r.json()
    print(f"  chain verify: ok={v.get('ok')} count={v.get('count')}")

    # 5. Sanity: every event in the DB has a unique this_hash and prev_hash
    #    points to the previous row's this_hash
    conn = sqlite3.connect(str(config.DB_PATH))
    n_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    n_uniq = conn.execute("SELECT COUNT(DISTINCT this_hash) FROM events").fetchone()[0]
    # Detect any orphan prev_hash (prev that doesn't match any prior this_hash
    # and isn't the genesis 64-zero hash)
    orphans = conn.execute("""
        SELECT COUNT(*) FROM events e
        WHERE e.prev_hash <> '0000000000000000000000000000000000000000000000000000000000000000'
          AND NOT EXISTS (SELECT 1 FROM events p WHERE p.this_hash = e.prev_hash AND p.id < e.id)
    """).fetchone()[0]
    conn.close()
    print(f"  DB total events: {n_events}")
    print(f"  unique this_hash: {n_uniq}  (should equal total)")
    print(f"  orphan prev_hash rows: {orphans}  (must be 0)")

    ok = (ok_count >= N_PARALLEL - 2  # tolerate 1-2 upstream flakes
          and err_count == 0
          and v.get("ok") is True
          and n_events == n_uniq
          and orphans == 0)
    print()
    print("RESULT:", "[ OK ]" if ok else "[FAIL]")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

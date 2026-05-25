# IMMUTRACE Audit SDK

> Cryptographic audit-trail proxy for OSINT / intelligence dashboards.
> First reference integration: [OSIRIS](https://github.com/simplifaisoul/osiris).

**License:** AGPL-3.0
**Status:** Demo / Proof of Concept (built 2026-05-25)

## What it does

Sits as a reverse proxy in front of a dashboard (e.g. OSIRIS) and:

1. **Captures** every HTTP request (analyst → backend) with a SHA-256 hash chain
2. **Authorization gate** — before any sensitive endpoint, the analyst must
   provide a justification (motivation + activity type + optional case ID).
   Justifications are bound to a 30-minute session token.
3. **Anchors** the chain Merkle root on **Polygon Amoy testnet** every
   5 minutes (or every 100 events).
4. **Dashboard** at `/audit` shows the session timeline, integrity verifier,
   and on-chain anchors.
5. **PDF export** with full chain-of-custody, blockchain proofs, and QR
   verification code.

## Architecture

```
                  ┌────────────────────────────────────────┐
analyst browser ──┤ IMMUTRACE proxy (FastAPI, :3001)       ├── OSIRIS (:3000)
                  │  ├── reverse proxy + auth gate         │
                  │  ├── SHA-256 hash chain (SQLite)       │
                  │  ├── Polygon Amoy anchor worker        │
                  │  └── /audit dashboard + PDF export     │
                  └────────────────────────────────────────┘
                                  │
                                  └── Polygon Amoy (testnet)
```

## Quick start

```powershell
# 1. Install Python deps
pip install -r requirements.txt

# 2. Copy env file
copy .env.example .env

# 3. Start OSIRIS upstream on :3000
#    (in another terminal, from osiris repo: npm run dev)

# 4. Start IMMUTRACE proxy on :3001
python -m proxy.app

# 5. Open dashboard
start http://127.0.0.1:3001
```

Audit dashboard: `http://127.0.0.1:3001/_immutrace/dashboard`

## Repo layout

```
proxy/         FastAPI proxy + auth gate + audit chain + anchor worker
dashboard/     HTML/JS frontend served on /_immutrace/dashboard
contracts/     IMMUTRACEAnchor.sol + deploy script (Polygon Amoy)
data/          SQLite event store (gitignored)
tests/         Smoke test (Playwright + pytest)
```

See [HOW_TO_RUN.md](HOW_TO_RUN.md) and [DEMO_SCRIPT.md](DEMO_SCRIPT.md).

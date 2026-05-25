# HOW TO RUN — IMMUTRACE Audit SDK (local demo)

> Tested on Windows 11 + PowerShell + Python 3.12 + Node 24.
> 100% local; no cloud account, no GitHub push, no Polygon mainnet.

## 0. Prerequisites

- Python 3.10+ (3.12 confirmed)
- Node.js 20+ (24.14 confirmed)
- ~1 GB free disk for OSIRIS `node_modules`
- No Docker required (we run everything natively)

## 1. Clone & install (once)

```powershell
# IMMUTRACE SDK (this repo)
cd C:\Users\39338\immutrace-audit-sdk
pip install -r requirements.txt
copy .env.example .env
python -m scripts.bootstrap_wallet     # generates Polygon Amoy wallet in .env

# OSIRIS (upstream, NOT modified)
git clone https://github.com/simplifaisoul/osiris C:\Users\39338\osiris-analysis  # if not yet
cd C:\Users\39338\osiris-analysis
npm install
```

## 2. Start the two services (two terminals)

**Terminal A — OSIRIS upstream (port 3000):**
```powershell
cd C:\Users\39338\osiris-analysis
npm run dev
# wait for "Ready in N ms"
```

**Terminal B — IMMUTRACE proxy (port 3001):**
```powershell
cd C:\Users\39338\immutrace-audit-sdk
python -m proxy.app
# you'll see:
# [immutrace] proxy listening on http://127.0.0.1:3001
# [immutrace] upstream OSIRIS: http://127.0.0.1:3000
# [immutrace] anchor mode: MOCK
# [immutrace] dashboard: http://127.0.0.1:3001/_immutrace/dashboard
```

## 3. Open the dashboard

```powershell
start http://127.0.0.1:3001                       # OSIRIS (proxied + audited)
start http://127.0.0.1:3001/_immutrace/dashboard  # IMMUTRACE audit dashboard
```

## 4. Run the smoke test (sanity check)

```powershell
cd C:\Users\39338\immutrace-audit-sdk
python -m tests.smoke_test
# expected: PASS: 29    FAIL: 0
```

## 5. (Optional) Switch from MOCK to real Polygon Amoy

Mock anchor is enabled by default — anchors get a deterministic fake
`tx_hash`/`block_number` but never touch the blockchain. To flip to a real
testnet submission:

1. **Fund the wallet.** Open `.env`, copy `ANCHOR_ADDRESS`, then go to
   https://faucet.polygon.technology → pick **Polygon Amoy** → paste the
   address → receive ~0.5 POL test tokens (manual, ~30 sec).
2. **Deploy the anchor contract:**
   ```powershell
   pip install py-solc-x
   python -m scripts.deploy_anchor
   # outputs the deployed contract address
   ```
3. **Edit `.env`:**
   ```
   MOCK_ANCHOR=false
   ANCHOR_CONTRACT=0x<deployed-address-from-step-2>
   ```
4. Restart the proxy. Next batch will hit Amoy for real (~5-10 sec
   confirmation). Check `https://amoy.polygonscan.com/tx/<txhash>` from the
   dashboard.

## 6. Stop everything

```powershell
# Terminal A:  Ctrl+C
# Terminal B:  Ctrl+C
# Data persists in C:\Users\39338\immutrace-audit-sdk\data\audit.db
```

## 7. Reset state (start clean)

```powershell
del C:\Users\39338\immutrace-audit-sdk\data\audit.db
del C:\Users\39338\immutrace-audit-sdk\data\exports\*
```

---

## Configuration knobs (`.env`)

| Variable | Default | Purpose |
|----------|---------|---------|
| `PROXY_PORT` | 3001 | IMMUTRACE proxy port |
| `OSIRIS_URL` | http://127.0.0.1:3000 | Upstream dashboard |
| `AUTH_TOKEN_TTL_SECONDS` | 1800 | Session lifetime (30 min) |
| `MOCK_ANCHOR` | true | If true, anchors are fake locally |
| `ANCHOR_BATCH_SIZE` | 100 | Anchor when N pending events |
| `ANCHOR_BATCH_INTERVAL_SECONDS` | 300 | Anchor every M seconds |
| `AMOY_RPC` | https://rpc-amoy.polygon.technology | Amoy RPC |

Sensitive paths that trigger the gate are listed in `proxy/config.py` →
`SENSITIVE_PREFIXES` (default covers `/api/flights`, `/api/cctv`,
`/api/maritime`, `/api/satellites`, `/api/osint/*`, `/api/scanner`, etc.).

# IMMUTRACE — Integration Guide

How to put IMMUTRACE in front of *your* system (not just OSIRIS). IMMUTRACE is a
reverse proxy + injected SDK; the upstream needs **no code changes**.

## Step 1 — Deploy the proxy

```bash
git clone https://github.com/stoneproof-tech/immutrace-audit-sdk
cd immutrace-audit-sdk
python -m venv .venv && . .venv/bin/activate   # (or your env)
pip install -r requirements.txt
cp .env.example .env        # then edit (see env vars below)
python -m proxy.app         # listens on :3001, forwards to UPSTREAM_URL
```

Key env vars (`.env`, never committed):

| Var | Meaning | Default |
|-----|---------|---------|
| `UPSTREAM_URL` | the backend you are auditing | `http://127.0.0.1:3000` |
| `BACKEND_ADAPTER` | `http` (impl) \| `graphql` \| `grpc` (stubs) | `http` |
| `SENSITIVE_ENDPOINTS_CONFIG` | path to your YAML | `config/sensitive_endpoints.yaml` |
| `ADMIN_USER` / `ADMIN_PASSWORD` | bootstrap admin | `admin` / (set one) |
| `SEED_DEMO_USERS` | seed demo analyst/supervisor/custodian | `true` (**set `false` in prod**) |
| `TIMESTAMP_PROVIDER` | `local` \| `aruba` \| `infocert` \| `namirial` | `local` |
| `MOCK_ANCHOR` | `true`=mock, `false`=real Polygon mainnet | `true` |
| `POLYGON_RPC` | dedicated RPC (recommended for prod) | (keyless fallback) |
| `ANCHOR_WALLET_ADDRESS` / `ANCHOR_PRIVATE_KEY` | anchoring wallet | — |

## Step 2 — Choose / configure the backend adapter

The upstream transport is behind `proxy/adapters/`. HTTP is implemented. For a
different transport, subclass `BackendAdapter`:

```python
# proxy/adapters/my_adapter.py
from .base import BackendAdapter, UpstreamResponse, UpstreamError

class MyAdapter(BackendAdapter):
    name = "my"
    def __init__(self, upstream_url, http_client): ...
    async def forward(self, *, method, path, query, headers, body,
                      remote_ip, client_host, scheme) -> UpstreamResponse:
        ...  # call your backend, return a normalized UpstreamResponse
```
Register it in `adapters/__init__.py:_ADAPTERS` and set `BACKEND_ADAPTER`.

## Step 3 — Declare your sensitive endpoints

Edit `config/sensitive_endpoints.yaml` (matching is by path prefix):

```yaml
endpoints:
  - prefix: /api/customers
    risk: high
    description: Customer PII records
  - prefix: /admin
    risk: critical
    description: Administrative actions
```
See `demos/generic/sensitive_endpoints.example.yaml`. Switching the audited
system is **config only** (`UPSTREAM_URL` + this YAML).

## Step 4 — Key custody (Shamir)

- **Demo**: `CUSTODIAN_BACKEND=local` provisions 5 local custodian keypairs on
  `/_immutrace/keys/setup` (admin). **DEMO ONLY** — single machine holds all keys.
- **Production**: implement `RemoteCustodianBackend` (stub in `custodians.py`) so
  each custodian's private key lives with a separate party (notary, lawyer,
  auditor, DPO, security officer) offline behind an authenticated API + MFA.
  3-of-5 reconstruction happens via the ceremony (`/_immutrace/keys/reassembly/*`).

## Step 5 — Timestamping (eIDAS)

`TIMESTAMP_PROVIDER=local` (default) signs an IMMUTRACE-native timestamp.
For eIDAS-qualified tokens, set `TIMESTAMP_PROVIDER=aruba|infocert|namirial` and
the `<VENDOR>_TSA_URL` (and implement the stub's RFC-3161 call) once the QTSP
contract is active. `TIMESTAMP_THRESHOLD` controls which events get timestamped
(`critical` default, or `high|all|none`).

## Step 6 — Anchoring

- **Dev**: `MOCK_ANCHOR=true` (no chain, fake tx hashes).
- **Production**: `MOCK_ANCHOR=false`, set `ANCHOR_WALLET_ADDRESS` +
  `ANCHOR_PRIVATE_KEY` (the key MUST control the wallet — the code refuses
  otherwise), and a dedicated `POLYGON_RPC`. The worker batches every
  `ANCHOR_BATCH_INTERVAL_SECONDS` (300) or at `ANCHOR_BATCH_SIZE` (100) pending
  events, pre-flighting chain/balance/nonce. Emergency stop: `MOCK_ANCHOR=true` + restart.

## The frontend SDK

`sdk/immutrace-observer.js` is a standalone, dependency-free browser library. The
proxy injects it into upstream HTML automatically; or include it manually:

```html
<script defer src="https://your-immutrace-host/_immutrace/sdk.js"></script>
```
It renders the login + authorization-request modals and the audit banner. It is
backend-agnostic (no references to any specific upstream).

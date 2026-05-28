# IMMUTRACE — Architecture

IMMUTRACE is a **universal cryptographic audit layer**: a reverse proxy that sits
in front of any OSINT / AI / decisional backend and produces a tamper-evident,
optionally-encrypted, custodian-escrowed, timestamped and blockchain-anchored
record of every sensitive access — without modifying the upstream system.

OSIRIS (a Next.js OSINT dashboard) is the reference demo; nothing in the core is
OSIRIS-specific (that lives under `demos/osiris/`).

## Components

```
                          Browser (analyst / supervisor / admin / custodian)
                                   │  (HTML pages get sdk.js injected)
                                   ▼
┌──────────────────────────── IMMUTRACE proxy (:3001, FastAPI) ─────────────────────────────┐
│                                                                                            │
│  app.py  ── routers ──┬─ identity.py     users, roles, argon2, login sessions              │
│                       ├─ workflow.py     analyst request → supervisor approve (pre-auth)   │
│                       ├─ keymgmt.py       Shamir master-key custody + reassembly ceremony  │
│                       ├─ timestamp.py     eIDAS adapter (local | QTSP stubs)               │
│                       └─ dashboard.py     audit API, PDF export, GDPR erase, admin pages   │
│                                                                                            │
│  proxy.py  handle_proxy_request:                                                           │
│     1. AUTH GATE  (auth.py / identity.py / workflow.py)                                     │
│        sensitive path?  → authorized via legacy session OR (login + active approval)       │
│     2. FORWARD    via adapters/  (http_adapter [impl] | graphql/grpc [stub])  ───────────────▶ upstream backend (OSIRIS :3000)
│     3. LOG        log_event → encryption.py (AES-GCM sensitive fields)                      │
│                            → chain.py (SHA-256 global hash chain) → db.py (SQLite)          │
│        WebSocket bridge for dev-server HMR                                                  │
│                                                                                            │
│  anchor.py  background worker: batch pending events → merkle_root                          │
│        → timestamp (eIDAS) → Polygon mainnet CALLDATA anchor (or MOCK)                      │
│                                                                                            │
│  Storage: SQLite  data/audit.db   (events, sessions, users, login_sessions,                │
│           approval_requests, custodians, key_shards, key_reassembly_attempts,              │
│           key_meta, record_keys, event_timestamps, anchors, anchor_errors)                 │
└────────────────────────────────────────────────────────────────────────────────────────────┘
   config/sensitive_endpoints.yaml  (client-editable)      data/tsa_local_ed25519.key, custodian PEMs (gitignored)
```

## Layers

| Layer | Module | What it guarantees |
|------|--------|--------------------|
| **Proxy + gate** | `proxy.py`, `adapters/`, `auth.py` | Only authorized identities reach sensitive endpoints; transparent to the upstream |
| **Identity & authZ** | `identity.py`, `workflow.py` | Who acted (multi-user, roles) + supervisor pre-authorization with separation of duties |
| **Audit hash chain** | `chain.py` + `log_event` | Integrity & ordering: each event commits `sha256(prev_hash ‖ canonical(event))`; tampering or deletion is detectable |
| **Encryption at rest** | `encryption.py` | Confidentiality of sensitive fields (AES-256-GCM) + GDPR Art.17 crypto-erasure |
| **Key custody** | `keymgmt.py`, `shamir.py`, `custodians.py` | The master key is split k-of-n (3-of-5) across custodians; no single party reconstructs it; key lives only in RAM |
| **Timestamping** | `timestamp.py` | Each event hash is signed to a point in time; eIDAS-qualified once a QTSP is activated |
| **Blockchain anchor** | `anchor.py` | Public immutability: merkle roots of event batches anchored on Polygon mainnet |

## Flow of one sensitive request

1. Browser (logged-in analyst) requests `GET /api/maritime` through the proxy.
2. **Gate**: path is sensitive. No active authorization → `401 X-Immutrace-Gate: blocked`. The injected `sdk.js` shows the **request-authorization** modal → `POST /_immutrace/approval/request`.
3. A **supervisor** approves (`/_immutrace/approval/{id}/approve`) — time-boxed authorization; the decision is itself written to the hash chain.
4. Analyst retries `GET /api/maritime`. Gate now finds an active approval → request is **forwarded** to OSIRIS via the HTTP adapter.
5. `log_event`: sensitive fields (`justification`, `query`) are **AES-GCM encrypted** (per-record key wrapped by the Shamir master key); the event is **hash-chained** into `events`.
6. The background **worker** periodically batches pending events into a **merkle root**, **timestamps** it (eIDAS-ready), and **anchors** it on Polygon mainnet (CALLDATA self-transfer).
7. Anyone can later **verify** the chain (`/audit/verify`), **decrypt** for authorized viewing, **erase** per GDPR (destroying the per-record key while the chain stays valid), and check the on-chain anchor on Polygonscan.

## Key architectural decisions

- **Adapter pattern everywhere** — backend transport (`adapters/`), timestamp provider (`timestamp/`) and custodians (`custodians.py`) are all behind abstract interfaces, so switching upstream/QTSP/custody is configuration, not code.
- **Global hash chain** — `prev_hash` links to the immediately-preceding event across ALL sessions; verification is over the whole chain (a per-session subset is not contiguous because events from different sessions/background tasks interleave).
- **Hash over ciphertext** — the chain commits to the stored (encrypted) fields, so verification needs no key and crypto-erasure cannot break integrity.
- **Batch anchoring** — many events → one merkle root → one on-chain tx (cost-efficient; ~0.007 POL/batch).
- **Master key only in RAM** — reconstructed via Shamir; never persisted. (Local custodian backend auto-unlocks for the demo — see SECURITY_MODEL.md.)
- **Zero upstream changes** — `sdk.js` is injected into HTML responses; the proxy is transparent.

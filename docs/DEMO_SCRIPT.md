# IMMUTRACE — Demo Script (NGI Zero, ~15 min)

**Tagline:** *Universal cryptographic audit layer for OSINT, AI and decisional systems — demonstrated on OSIRIS.*

## Setup (before the demo)
```bash
# 1. OSIRIS (the system being audited)
cd C:/Users/39338/osiris-analysis && npm run dev          # :3000
# 2. IMMUTRACE proxy
cd C:/Users/39338/immutrace-audit-sdk && python -m proxy.app   # :3001
# Open http://127.0.0.1:3001  and  http://127.0.0.1:3001/_immutrace/dashboard
```
**Demo credentials** (seeded; `SEED_DEMO_USERS=true`, DEMO ONLY):
- analyst / `demo1234` · supervisor / `demo1234` · custodian roles `notaio|avvocato|revisore|dpo|secofficer` / `demo1234` · admin / (from `.env`)

For the anchor scene, run with `MOCK_ANCHOR=false` + the funded wallet, or show the already-anchored txs on Polygonscan.

## The 7 scenes

**Scene 1 — Login (identity).** Open `:3001`. OSIRIS loads; the IMMUTRACE login modal appears. Log in as **analyst**. *Say: "OSIRIS has no identity or logging. IMMUTRACE adds multi-user identity in front of it, with zero changes to OSIRIS."*

**Scene 2 — Blocked search (authorization gate).** Toggle a sensitive layer (e.g. maritime/flights). It's blocked → "Request authorization" modal. *Say: "Sensitive intelligence access now requires authorization — declared by the client in a YAML, not hard-coded."*

**Scene 3 — Approval workflow (separation of duties).** Fill justification + urgency → submit. Open a second window, log in as **supervisor**, go to **Approval queue**, approve. *Say: "An analyst can't self-authorize. A supervisor approves; the decision itself is chained and auditable."*

**Scene 4 — Approved search.** Back as analyst, reload → the data now loads. *Say: "Time-boxed authorization. Every request is now recorded."*

**Scene 5 — The hash chain (integrity).** Open the **Audit Dashboard** → Events. Show the global SHA-256 chain, filters (user / risk / date), and the **eIDAS** timestamp column. Click **Verify chain** → INTEGRITY VERIFIED. *Optional:* tamper a row in the DB, re-verify → CHAIN BROKEN at index N. *Say: "Tampering or deletion is mathematically detectable."*

**Scene 6 — GDPR erasure + confidentiality.** Show an event's justification decrypted in the dashboard (it's AES-256-GCM encrypted at rest). Then `POST /_immutrace/gdpr/erase` for that case → the justification becomes **[ERASED]**, but **Verify chain still passes**. *Say: "Confidential at rest. GDPR Art.17 erasure destroys the key — the personal data is gone forever, yet the audit chain stays intact. Integrity and the right to erasure, together."*

**Scene 7 — Polygon anchor (public immutability).** Show the **anchors** view / Polygonscan: merkle roots anchored on Polygon **mainnet**. Open the first verified tx: `https://polygonscan.com/tx/0x6ce8629c4a3f2da6e40ef7485e312e0df7ec7ee3deeef2529903204fb23d664e`. *Say: "Batches of events are anchored on a public blockchain — anyone can independently confirm a record existed at a block time, for ~$0.0006 per batch. 29 real anchors are already on mainnet."*

**Close — key custody.** Show `/_immutrace/admin/keys` (Shamir 3-of-5) and `/_immutrace/custodian/panel`. *Say: "The master encryption key is split across a notary, a lawyer, an auditor… No single party — not even us — can read the data alone. In production these custodians are independent parties holding their keys offline."*

## Backup plan (if the live demo fails)
- Keep **pre-recorded screenshots / a short screen capture** of all 7 scenes.
- The Polygonscan txs are permanent — show them directly (no local stack needed).
- If OSIRIS/`:3000` is down: the IMMUTRACE dashboard (`/_immutrace/dashboard`) and the verify/erase/anchor flows work independently of OSIRIS using existing data.
- If anchoring/RPC is flaky: switch to `MOCK_ANCHOR=true` and narrate the mainnet txs from Polygonscan instead.
- Honesty note to reviewers: be upfront that local custodians and QTSP are demo/roadmap (see SECURITY_MODEL.md) — NLnet values candor.

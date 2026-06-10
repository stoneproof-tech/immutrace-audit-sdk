# IMMUTRACE

**Universal cryptographic audit layer for OSINT, AI, and decisional systems.**
A transparent reverse proxy that turns any backend into an accountable one —
identity, supervisor authorization, a tamper-evident hash chain, encryption at
rest, Shamir key custody, eIDAS-ready timestamping, and Polygon-anchored
immutability — **with zero changes to the audited system.**

Why it's needed: regulations like the **EU AI Act (Art. 12 record-keeping)** and
**GDPR (Art. 17 erasure)** demand accountability *and* privacy, while systems
like OSINT/intelligence dashboards typically have neither identity nor audit
logging. IMMUTRACE provides verifiable accountability **without requiring trust**
in the operator — integrity is cryptographic and publicly anchored, and personal
data can be irreversibly erased without breaking the audit trail.

**License:** AGPL-3.0 · **Reference demo:** [OSIRIS](https://github.com/simplifaisoul/osiris) (Next.js OSINT dashboard)

## Quick start (Docker-free, local)

```bash
pip install -r requirements.txt
cp .env.example .env            # set ADMIN_PASSWORD etc.
python -m proxy.app             # proxy on :3001 → forwards to UPSTREAM_URL (:3000)
# open http://127.0.0.1:3001  and  http://127.0.0.1:3001/_immutrace/dashboard
```
Point it at any backend by setting `UPSTREAM_URL` and editing
`config/sensitive_endpoints.yaml`. See [docs/INTEGRATION_GUIDE.md](docs/INTEGRATION_GUIDE.md).

## Features

- **Identity & RBAC** — multi-user (analyst / supervisor / admin / custodian), argon2 password hashing, revocable DB-backed sessions.
- **Authorization workflow** — analyst requests → supervisor approves (time-boxed), with separation of duties; every decision is auditable.
- **Tamper-evident hash chain** — global SHA-256 chain; tampering, deletion or reordering is detectable (`/audit/verify`).
- **Encryption at rest + GDPR crypto-erasure** — AES-256-GCM on sensitive fields; erasure destroys the per-record key (plaintext gone, chain intact).
- **Shamir key custody (3-of-5)** — master key split across custodians (notary / lawyer / auditor / DPO / security officer); RAM-only; no single party can reconstruct it.
- **eIDAS-ready timestamping** — adapter pattern: local signed timestamps now; Aruba/InfoCert/Namirial QTSP via config when contracted.
- **Polygon mainnet anchoring** — merkle roots of event batches anchored on-chain (CALLDATA pattern), ~0.007 POL/batch; hardened unattended worker.
- **Audit dashboard + signed PDF export** — filters (user / risk / date), approval queue, custodian panel, worker status; PDF shows encrypted fields as `[ENCRYPTED]`.
- **Backend-agnostic** — adapter pattern for HTTP (implemented), GraphQL/gRPC (stubs); standalone injectable JS SDK (`sdk/immutrace-observer.js`).

## On-chain proof (Polygon mainnet)

29 real anchors on the wallet `0x1Ec495d01e91a1929C651680cd7E5758dBF412C2`. First verified test anchor:
[`0x6ce8629c…b23d664e`](https://polygonscan.com/tx/0x6ce8629c4a3f2da6e40ef7485e312e0df7ec7ee3deeef2529903204fb23d664e)
(block 87427721, CALLDATA `immutrace-ledgereye-audit:<merkle_root>`).

## Production-ready vs roadmap (honest)

| Capability | Status |
|-----------|--------|
| Reverse proxy + auth gate + RBAC + approval workflow | ✅ Production-ready |
| SHA-256 hash chain + integrity verification | ✅ Production-ready |
| AES-256-GCM encryption + GDPR crypto-erasure | ✅ Production-ready |
| Shamir 3-of-5 split/reconstruct (math + ceremony) | ✅ Production-ready |
| Polygon mainnet anchoring (CALLDATA) + hardened worker | ✅ Working (use a dedicated RPC in prod) |
| Local-signed timestamps | ✅ Working (not eIDAS-qualified) |
| **Remote custodians** (separate parties, offline + MFA) | 🚧 Interface ready, impl = roadmap |
| **eIDAS-qualified QTSP** (Aruba/InfoCert/Namirial) | 🚧 Stubs, contractual activation |
| **Key rotation `/keys/rotate`** | 🚧 TODO (post-grant) |
| **Searchable encryption (Blind Index) for case_id** | 🚧 Roadmap |
| GraphQL / gRPC adapters | 🚧 Stubs |

See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) for the full threat model and limitations.

## Docs
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — components, layers, request flow
- [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) — threat model, guarantees, **honest limitations**, recovery
- [docs/INTEGRATION_GUIDE.md](docs/INTEGRATION_GUIDE.md) — apply IMMUTRACE to your own system
- [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md) — 15-min NGI Zero demo

## Repo layout
```
proxy/        FastAPI core: proxy, gate, identity, workflow, chain, encryption,
              keymgmt (Shamir), timestamp (eIDAS), anchor (Polygon), dashboard
adapters/     pluggable backend transports (proxy/adapters/)
sdk/          standalone injectable browser SDK
dashboard/    audit UI + supervisor/analyst/custodian/admin/worker pages
config/       sensitive_endpoints.yaml (client-editable)
demos/osiris/ OSIRIS-specific demo assets (custodian keys gitignored)
docs/         ARCHITECTURE / SECURITY_MODEL / INTEGRATION_GUIDE / DEMO_SCRIPT
tests/        smoke + e2e suites (login, workflow, shamir, encryption,
              timestamp, anchor, dashboard, worker robustness)
```

Built for the **NGI Zero Commons Fund** submission. Contributions under AGPL-3.0.

# IMMUTRACE — NGI Zero Commons Fund submission

## Abstract

IMMUTRACE is a **universal cryptographic audit layer** for OSINT, AI and
decisional systems: a transparent reverse proxy that makes any backend
accountable — identity, supervisor authorization, a tamper-evident hash chain,
AES-256-GCM encryption at rest with GDPR Art.17 crypto-erasure, Shamir k-of-n key
custody, eIDAS-ready timestamping, and Polygon-mainnet anchoring — **with zero
changes to the audited system**. Reference integration: OSIRIS (an open-source
OSINT/intelligence dashboard). License: AGPL-3.0.

## The problem

EU regulation demands both accountability and privacy — the **AI Act (Art. 12,
record-keeping for high-risk systems)** and **GDPR (Art. 17, right to erasure)** —
yet OSINT/AI dashboards typically ship with **no identity, no audit logging, and
no cryptographic guarantees**. Organizations must today choose between
accountability and privacy, and must *trust the operator's* logs. IMMUTRACE
removes that trust assumption: integrity is cryptographic and publicly anchored,
and personal data can be irreversibly erased **without breaking** the audit
trail.

## Technical approach

A backend-agnostic proxy (adapter pattern) + an injectable browser SDK. Each
sensitive access is gated (login + supervisor pre-authorization), hash-chained
(global SHA-256), optionally AES-256-GCM-encrypted (per-record key wrapped by a
Shamir-escrowed master key held only in RAM), timestamped (eIDAS-ready), and
periodically merkle-batched and anchored on Polygon mainnet. Full design in
`ARCHITECTURE.md`; threat model and honest limitations in `SECURITY_MODEL.md`;
on-chain evidence in `BLOCKCHAIN_PROOFS.md`.

**Status (honest):** working end-to-end with **153 passing tests**; **29 real
anchor transactions on Polygon mainnet**. Production-ready: proxy/gate/RBAC/
workflow, hash chain, AES-GCM + erasure, Shamir split/reconstruct, mainnet
anchoring. Roadmap (this grant): remote separate-party custodians, eIDAS-qualified
QTSP activation, key rotation, searchable encryption. See the README status table.

## Background (team)

Manuel Emilio Di Fenza is an engineer and professional trainer with **9+ years**
of experience, working as an **external consultant (forfettario)** for **WINTIME
S.p.A.**, a licensed Italian work agency, as Senior Technical Trainer / Curriculum
Architect (100+ technical manuals authored; classroom training; selected as
WINTIME's public representative for didactics).

In that representative capacity he has public, verifiable institutional
visibility: he **participated in the Award Ceremony** of the National Award "La
Sicurezza prima di tutto" at the **Italian Chamber of Deputies (Camera dei
Deputati), 20 February 2026** ([reference](https://www.confederazionecnl.it/salute-e-sicurezza-sul-lavoro-alla-camera-dei-deputati-confronto-istituzionale-e-consegna-del-premio-nazionale-la-sicurezza-prima-di-tutto/)),
an event attended by Members of Parliament, the Deputy Public Prosecutor of Rome,
Ministry of Economy officials and the Guardia di Finanza; and he **appeared as
WINTIME's didactics lead** on national broadcaster **RAI 2** in *"Il Nostro
Capitale Umano"* (Premio Moige "Quality Program", on RaiPlay)
([reference](https://it.wikipedia.org/wiki/Il_nostro_capitale_umano)). Full
detail in `TEAM.md`.

IMMUTRACE was built as an **AI-augmented solo development** effort with Anthropic
Claude Code, under Manuel's requirements, architecture, testing and validation —
a test-driven, multi-layer cryptographic system that doubles as a live
demonstration of that workflow.

## Distribution & Adoption Strategy

**Unique adoption advantage:** the founder has direct institutional ties to
Italian public bodies (institutional visibility at a Chamber-of-Deputies event,
February 2026), national broadcaster recognition (RAI 2), and connection to
Italy's structured workforce-training ecosystem via **Forma.Temp** (the bilateral
training fund supervised by the **Italian Ministry of Labour**). Post-grant pilot
deployment with an Italian public administration is realistically achievable
through these existing, Ministry-recognized channels rather than through cold
outreach.

Open-source distribution: AGPL-3.0 on GitHub; a standalone injectable SDK;
config-/Docker-driven self-hosting. The OSIRIS reference demo lowers the barrier
for OSINT vendors to adopt the audit layer.

## Funding

- **Amount requested: €5,000.**
- **Duration: 6 months (post-grant).**
- **Milestones:**
  - **M1** — External security audit (independent review of the crypto).
  - **M2** — `RemoteCustodianBackend` (5 real separate-party custodians, offline + MFA).
  - **M3** — `/keys/rotate` (key rotation with re-wrap) + Blind Index for searchable `case_id`.
  - **M4** — eIDAS QTSP contract + integration (Aruba / InfoCert / Namirial).
  - **M5** — Pilot with 1–2 Italian public administrations.
  - **M6** — v1.0 release + whitepaper.
- **Budget breakdown (€5,000):**
  | Item | € |
  |------|---|
  | External security audit | 1,500 |
  | Remote custodians + key rotation development | 1,500 |
  | QTSP contract (1 year) | 1,000 |
  | Dedicated RPC (Alchemy, 1 year) | 500 |
  | Docs + pilot | 500 |

## Open source & standards

AGPL-3.0. Builds on/with: EU AI Act Art.12, GDPR Art.17, eIDAS / RFC-3161
timestamping, Shamir Secret Sharing, AES-256-GCM, Polygon (EVM). No vendor
lock-in; backend/timestamp/custody all behind swappable adapters.

## Comparison / state of the art

| Tool | Nature | Gap vs IMMUTRACE |
|------|--------|------------------|
| Splunk Audit Logs | Commercial SIEM | No blockchain immutability, proprietary |
| Datadog SIEM | Commercial, logs only | No cryptographic immutability |
| Google Chronicle | Proprietary cloud | Closed, vendor cloud lock-in |
| Hyperledger Fabric | Permissioned DLT | Heavy, complex; not a transparent overlay |
| Sigstore | Artifact signing | Signing only, not an audit chain over access |
| OpenZiti | Network identity | Identity/networking, no audit chain |

**IMMUTRACE differentiator:** open AGPL-3.0 + a *transparent proxy overlay*
(zero upstream change) that uniquely provides **integrity AND GDPR-native
crypto-erasure together**, plus notary-style key custody.

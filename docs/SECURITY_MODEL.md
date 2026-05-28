# IMMUTRACE — Security Model

This document is deliberately candid about both guarantees and limitations.
Reviewers should read the **Limitations** and **Production hardening** sections
as carefully as the guarantees.

## Threat model

Actors and what we defend against:

| Adversary | Capability | IMMUTRACE response |
|-----------|-----------|--------------------|
| Malicious/curious analyst | Accesses sensitive data without justification | Auth gate + supervisor pre-authorization; every access (and denial) is chained |
| Insider tampering with logs | Edits/deletes audit rows in the DB | Global SHA-256 hash chain → tampering/deletion detected by `verify`; merkle roots anchored on a public blockchain |
| Operator reading sensitive data at rest | Reads the SQLite file | Sensitive fields AES-256-GCM encrypted; key not on disk (Shamir-escrowed, RAM-only) |
| Single rogue custodian / single party | Tries to recover the master key alone | Shamir 3-of-5 — no single custodian can reconstruct |
| Data subject exercising GDPR Art.17 | Requests erasure | Crypto-erasure: destroy per-record key → plaintext unrecoverable, chain stays valid |
| External party disputing a record after the fact | Claims a record was fabricated/backdated | Timestamp token + on-chain anchor with a public block time |

Out of scope (trusted): the host OS/process while running (the master key is in RAM), the `cryptography`/`web3`/`argon2` libraries, the analyst's browser integrity.

## Guarantees

- **Integrity & ordering** — `this_hash = sha256(prev_hash ‖ canonical(event))`; any modification, reordering or deletion breaks `verify`. The chain commits to the *stored* (ciphertext) fields, so verification needs no decryption key.
- **Confidentiality** — sensitive fields (`justification`, `query`) encrypted with AES-256-GCM; per-record key wrapped by a master key held only in RAM.
- **Accountability / non-repudiation (eIDAS-ready)** — each event hash is signed to a point in time; with a QTSP activated, the timestamp is eIDAS-qualified.
- **Public immutability** — merkle roots of event batches anchored on Polygon mainnet (CALLDATA pattern, continuity with prior anchors); verifiable on Polygonscan.
- **Separation of duties** — a supervisor cannot approve their own request; admin-only operations are role-gated (argon2-hashed passwords, revocable DB-backed login sessions).
- **GDPR Art.17 (crypto-erasure)** — destroying a per-record key makes plaintext permanently unrecoverable **while preserving** chain integrity.

## Limitations (HONEST — read this)

1. **LocalCustodianBackend is a DEMO SIMULATION.** The 5 custodian private keys live on one machine, so that machine can reconstruct the master key alone — this defeats the "no single party" property. **Production requires `RemoteCustodianBackend`**: each custodian's private key held by a separate party, offline, behind an authenticated API + MFA. The abstract interface is in place; the remote implementation is a stub (`custodians.py`). The demo auto-unlocks the key at startup precisely because the keys are local.
2. **Key rotation / re-keying is NOT implemented.** Running `/keys/setup` again generates a new master key but does **not** re-wrap existing per-record keys → events encrypted under the old key become undecryptable. **TODO `/keys/rotate`** (re-wrap all `record_keys` under the new master before swapping) — see code TODO; planned post-grant.
3. **`case_id` is stored in plaintext** (so it stays filterable). If case identifiers are themselves sensitive, a **searchable-encryption / Blind-Index (HMAC) scheme** is needed — roadmap.
4. **QTSP timestamps are not yet qualified.** The local provider produces a cryptographically-solid but **non-qualified** IMMUTRACE-native signature. Aruba/InfoCert/Namirial providers are configurable **stubs**; activating real eIDAS-qualified timestamping is a contractual + config step.
5. **Public RPCs are unreliable for anchoring.** During testing a public node returned a wrong nonce (0). The worker now reads the nonce by **consensus (max across RPCs)** and pre-flights chain/balance/nonce, but **a dedicated `POLYGON_RPC`** (Alchemy/Infura/QuickNode) is **strongly recommended** for unattended production operation.
6. **Shamir core is hand-rolled** (GF(256), correct construction, covered by tests). Independent security audit of the crypto is on the roadmap (e.g. swap to PyCryptodome SSS).
7. **Legacy "investigation session"** (justification → blanket access, no login) is **deprecated**, retained only as a single-user fallback and for the base smoke test. Slated for removal once the test suite is migrated fully to login+approval.

## Recovery procedures

- **Chain corruption / tampering detected** (`verify` → `ok:false`, `broken_at`): the broken index identifies the first altered event. The on-chain anchors prove the merkle root of each anchored batch at its block time; cross-check the suspect batch's events against its anchored root to localize tampering. Restore from the last known-good backup; the chain self-heals once the altered fields are corrected (the hash recomputes).
- **Master key loss** (RAM lost, not auto-unlockable): run the **reassembly ceremony** — ≥3 custodians submit their shares (`/keys/reassembly/*`); the key is reconstructed in RAM and verified against `key_meta.master_sha256`. Fake/corrupted shares are rejected (hash mismatch).
- **Custodian compromise**: with 3-of-5, up to 2 compromised custodians cannot reconstruct the key. Re-issue that custodian's keypair and re-run `/keys/setup` to re-split (NOTE: until `/keys/rotate` exists, re-setup invalidates old ciphertext — see limitation 2).
- **Anchor wallet / RPC issues**: the worker stops after 3 consecutive failures ("manual intervention required"); fix the RPC/balance and restart. The emergency stop is `MOCK_ANCHOR=true` + restart.

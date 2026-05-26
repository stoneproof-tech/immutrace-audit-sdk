# IMMUTRACE — Risk Assessment

Honest assessment of project risks and mitigations. Technical risks are grounded
in `SECURITY_MODEL.md`.

| Risk | Level | Why | Mitigation |
|------|-------|-----|-----------|
| **Adoption** | **MEDIUM** | Launch-stage open-source compliance project with **no pre-existing distribution partnerships**. The founder has professional credentials and public visibility (Chamber of Deputies award ceremony Feb 2026, RAI 2 didactics appearance) that help credibility for outreach, but adoption requires active post-grant business development. | Self-hostable (AGPL, Docker, config-driven) so adoption is never gated on the founder; OSIRIS reference demo as proof-of-value; technical excellence (153 tests, on-chain anchoring) as credibility. |
| **Technical — crypto correctness** | Medium | Shamir core is hand-rolled (GF(256), correct construction, 42+ tests) rather than a formally-audited library. | Independent security audit (M1, funded); option to swap to PyCryptodome SSS behind the same API. |
| **Key management** | Medium | `LocalCustodianBackend` is a DEMO simulation (all 5 keys on one machine); key rotation (`/keys/rotate`) not yet implemented (re-keying invalidates old ciphertext). | `RemoteCustodianBackend` interface ready (M2: separate parties, offline + MFA); rotation in M3. Documented in SECURITY_MODEL.md. |
| **Timestamping legal validity** | Medium | Local timestamps are cryptographically solid but **not eIDAS-qualified**; QTSP providers are stubs. | Adapter pattern ready; activate Aruba/InfoCert/Namirial via contract + config (M4). |
| **Infrastructure — RPC reliability** | Medium | Public Polygon RPCs are flaky (rate-limits; a node once returned a wrong nonce). | Nonce consensus + pre-flight + hardened worker already shipped; **dedicated `POLYGON_RPC`** (Alchemy, funded) for production. |
| **Cost runaway (anchoring)** | LOW (fixed) | A self-feeding anchor loop (anchoring emitted events that triggered more anchors) bled real POL. | **Fixed**: system event types excluded from anchor batches (`e2e_anchor_loop_prevention`); idle ⇒ no anchoring. |
| **Regulatory fit** | LOW | Directly targets AI Act Art.12 + GDPR Art.17; the "integrity + erasure together" design is the core value. | Keep claims honest (see SECURITY_MODEL limitations); legal review before marketing timestamps as "eIDAS-qualified". |
| **Sustainability (solo founder)** | Medium | Single maintainer. | AGPL + clean docs lower the bus-factor; grant funds a security audit + hardening; the institutional network can attract contributors/users. |

## Summary
The adoption risk is **MEDIUM** — typical for an early-stage open-source project
without pre-existing partnerships. The founder's professional credentials provide
visibility but not guaranteed channels. The main *open* risks are
technical-maturity items already documented and roadmapped (remote custody, key
rotation, QTSP activation, dedicated RPC, security audit) — funding-and-engineering
matters, not unknowns.

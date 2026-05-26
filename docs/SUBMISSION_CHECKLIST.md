# IMMUTRACE — NGI Zero Submission Checklist (for Manuel)

Status of the submission package and the remaining human steps.

## Package status
- [x] `TEAM.md` — founder profile, contacts (no phone), institutional recognition (Camera dei Deputati, RAI 2), Forma.Temp framing, AI-augmented build note.
- [x] `NGI_SUBMISSION.md` — abstract, problem, approach, background, distribution, **€5,000 / 6 months / M1–M6 + budget**, comparators.
- [x] `RISK_ASSESSMENT.md` — Adoption **LOW** (institutional, Forma.Temp — no "CNL network" claim), honest technical risks.
- [x] `BLOCKCHAIN_PROOFS.md` — 29 on-chain anchors, verified tx list, how-to-verify.
- [x] `ARCHITECTURE.md`, `SECURITY_MODEL.md`, `INTEGRATION_GUIDE.md`, `DEMO_SCRIPT.md` (from Step 9).
- [x] All `[ASK MANUEL]` placeholders removed.

## TODO — Manuel (before submitting)

**Review & accuracy**
- [ ] Read `TEAM.md` + `NGI_SUBMISSION.md` and confirm every institutional statement is exactly how you want it (wording is deliberately non-inflated).
- [ ] Confirm both reference links still resolve (confederazionecnl.it, it.wikipedia.org).
- [ ] Confirm the €5,000 / forfettario positioning with your commercialista.

**Privacy / publication**
- [ ] Decide repo visibility: it is **private** now. These docs contain your name, email and institutional references — confirm you're OK publishing them when the repo goes public (AGPL), or keep `NGI_SUBMISSION.md`/`TEAM.md` out of the public tree.

**Engineering gate**
- [ ] Decide merge `feat/full-integration` → `main` (currently all work is on the feature branch; `main` is the working demo at `v0.1-demo-working`).

**Demo & submission**
- [ ] Reactivate mainnet (`MOCK_ANCHOR=false` + restart) **only** to record the NGI video demo (follow `DEMO_SCRIPT.md`), then set it back to MOCK to avoid idle cost.
- [ ] Optionally provision a dedicated `POLYGON_RPC` (Alchemy) before the recording for reliability.
- [ ] Record the 15-min demo (7 scenes) + capture backup screenshots.
- [ ] Map `NGI_SUBMISSION.md` sections onto the NLnet form at https://nlnet.nl/propose/ and submit.
- [ ] Deadline: **NGI Zero Commons Fund — round 14, 1 August 2026** (confirm on nlnet.nl).

## Current system state
- Worker in **MOCK** (no real spend). Anchor wallet balance ~29.85 POL.
- 153/153 tests passing on `feat/full-integration`.

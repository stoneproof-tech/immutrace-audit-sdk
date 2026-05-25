# DEMO SCRIPT — IMMUTRACE × OSIRIS

> Audience: NGI Zero reviewers, compliance buyers, AI Act stakeholders.
> Length: **8–10 minutes** live.
> Stack: 100% local, no internet required after setup (except the
> Polygon Amoy faucet in step 0, only if you want REAL on-chain).

---

## 0. Setup (do this before the audience joins)

```powershell
# Terminal A
cd C:\Users\39338\osiris-analysis
npm run dev                       # wait for "Ready"

# Terminal B
cd C:\Users\39338\immutrace-audit-sdk
python -m proxy.app               # wait for "proxy listening on …"

# Terminal C (optional sanity)
python -m tests.smoke_test        # PASS: 29  FAIL: 0
```

Open three browser tabs side-by-side:
- **Tab 1:** http://127.0.0.1:3001 — OSIRIS through the proxy
- **Tab 2:** http://127.0.0.1:3001/_immutrace/dashboard — audit dashboard
- **Tab 3:** https://amoy.polygonscan.com (only if real anchoring enabled)

Clear browser cookies for `127.0.0.1` so the analyst session starts fresh.

---

## 1. The pitch (60 sec)

> *"OSIRIS is an open-source 3D OSINT dashboard. It tracks 10K+ aircraft,
> 2K satellites, worldwide CCTV. It's literally pitched as the 'open-source
> Palantir alternative'. But today, **if a Maria-the-analyst uses OSIRIS
> to profile a citizen, decide on military targeting, or run port scans
> on a foreign infrastructure, no audit trail exists.** Nothing tells you
> who clicked what, when, why.*
>
> *Under the EU AI Act, this is **non-compliant**. Article 12 mandates
> automatic, tamper-evident logging for any high-risk AI system —
> intelligence dashboards being a textbook example.*
>
> *IMMUTRACE is the **drop-in cryptographic audit layer** that makes
> any analyst dashboard AI Act-ready. Zero modifications to OSIRIS itself.
> Let me show you."*

---

## 2. Act I — "Without IMMUTRACE" (90 sec)

**Tab 1:** open http://127.0.0.1:3001 *(still OSIRIS, but proxied)*

> *"This is the exact same OSIRIS UI Maria would use. Notice the
> **red banner** at the top: 'NO SESSION'. IMMUTRACE is watching but
> no investigation has been declared."*

Try to click a flight on the map.

→ **Modal appears immediately:** "Investigation authorization required."

> *"Watch what happens. The moment Maria tries to access intelligence
> data — even something as innocent as the flight list — IMMUTRACE
> intercepts the request. **No justification = no access.**"*

---

## 3. Act II — "The justification" (90 sec)

In the modal, fill in:

- **Investigator:** `maria.rossi@maritime.authority.gov.it`
- **Activity:** `INVESTIGATION`
- **Case ID:** `CASE-2026-RED-SEA-014`
- **Justification:** *"Routine maritime traffic review for sanctions enforcement near Bab-el-Mandeb chokepoint. Coordinated with EUNAVFOR Atalanta liaison."*

Click **Authorize & start session**.

→ Modal closes, banner turns **green**: `IMMUTRACE AUDIT ACTIVE — maria.rossi@... · INVESTIGATION · case CASE-2026-RED-SEA-014`.

> *"Maria provided the legal purpose, the case ID, and the operational
> context. **This justification is now bound to every action for the next
> 30 minutes** — and permanently chained into a SHA-256 hash chain. She
> can't pretend later she was 'just browsing'."*

---

## 4. Act III — "The investigation" (3 min)

Click around OSIRIS naturally:

1. **Open Layers panel** (top-left) → toggle ON: `Maritime / Naval`,
   `Military`, `Live News Feeds`, `Satellites`.
2. **Click "RED SEA THREAT"** in Region Presets → map flies to lat 16, lng 40.
3. **Click a military aircraft** on the map → popup shows callsign + ICAO24.
4. **Click a naval base** (red dot in Red Sea) → popup with fleet info.
5. **Click chokepoint "Bab-el-Mandeb"** → traffic + risk shown.
6. **Right-click somewhere over Yemen** → triggers `/api/region-dossier`.
7. **Search bar** → type `USS Eisenhower` → fly-to result.
8. **Open OSINT toolkit** (right side) → DNS lookup for `example.com`,
   then Vuln Sweep for `8.8.8.8/24` (small CIDR for speed).

> *"Notice: Maria isn't aware of IMMUTRACE except for the discreet green
> banner. **The UX is identical to bare OSIRIS.** No friction, no extra
> clicks. But every action is being captured."*

---

## 5. Act IV — "The audit dashboard" (90 sec)

**Switch to Tab 2** (already loaded): the IMMUTRACE dashboard.

**Sessions tab** is open by default.

→ Maria's session is at the top: **15+ events** captured.
- Show the **justification box** (yellow left border).
- Show the **case pill** `case CASE-2026-RED-SEA-014`.
- Show the **active pill** in green.

Click **Verify chain** on the card.

→ Dialog: **✓ INTEGRITY VERIFIED — 15 events checked**.

> *"Every single one of those 15 events is hash-chained with SHA-256.
> Each event's hash includes the previous event's hash. **If anyone — Maria,
> the IT admin, even me — alters a single byte of any event, the next
> verification breaks immediately.** Let me prove it."*

---

## 6. Act V — "The tampering proof" (60 sec)

**Open Terminal C:**

```powershell
sqlite3 C:\Users\39338\immutrace-audit-sdk\data\audit.db
UPDATE events SET justification='I was just curious' WHERE id=5;
.exit
```

**Back to the dashboard** → click **Verify chain** again.

→ **✗ CHAIN BROKEN — Tampering detected at event index 1.**

> *"Even changing one character — the justification — breaks the chain.
> The evidence of tampering is **mathematically undeniable**. An auditor
> sees this in 1 second."*

Restore:
```powershell
# (the original is `Routine maritime…` — restore manually or rerun the demo)
```

---

## 7. Act VI — "The blockchain anchor" (60 sec)

In the dashboard, click **⚓ Anchor pending** in the top-right.

→ Popup: `Anchored 15 events. Tx: 0xabc1234567890def…`

Click the **On-chain anchors** tab.

→ Anchor #1 visible:
- **Merkle root** — 64-char SHA-256
- **Tx hash** + **block number**
- **Polygonscan ↗** link (only on real mode — in MOCK mode shows a label)

> *"Every 5 minutes, or every 100 events, the entire chain's Merkle root
> is committed to Polygon. **Cost: about $0.001 per batch.** Even if
> tomorrow our company disappears, the cryptographic proof is on a
> public ledger. **Forever.**"*

(If real Amoy enabled, **click the Polygonscan link** to show the actual TX.)

---

## 8. Act VII — "The legal artifact" (90 sec)

Back to **Sessions tab**, click **Download PDF** on Maria's session.

→ Browser downloads `immutrace_audit_<sid>_<hash>.pdf`.

**Open the PDF live.**

Walk through the sections:

1. **§1 Investigator block** — actor, justification, case, expires.
2. **§2 Event timeline** — every HTTP request, hash, status code.
3. **§3 Hash-chain proof** — `VERIFIED ✓`, first/last hash.
4. **§4 On-chain anchors** — Merkle roots + tx hashes + Polygonscan links.
5. **§5 QR code** — scan it (use your phone live!) → opens the verification
   endpoint that recomputes the chain in real-time.

> *"This is what Maria's compliance officer hands to the AI Act auditor
> 6 months later. **A self-contained, signed, blockchain-anchored
> chain-of-custody PDF.** Every claim is verifiable independently.
> No trust in IMMUTRACE required — the math speaks for itself."*

---

## 9. The close (45 sec)

> *"What you just saw: an open-source intelligence dashboard, completely
> unmodified, **transformed into an AI Act-compliant system by adding
> a reverse proxy and one config file.** Total integration effort: zero
> lines of OSIRIS source code touched.*
>
> *We did this in one day. **We want NGI Zero funding to package this as
> a vendor-neutral SDK** and integrate the next three high-risk dashboards
> in the European OSINT ecosystem: BookStack, Apache Superset, Datasette.*
>
> *Questions?"*

---

## Demo cheat sheet (single screen)

| URL | What |
|-----|------|
| http://127.0.0.1:3001/ | OSIRIS (proxied + audited) |
| http://127.0.0.1:3001/_immutrace/dashboard | Audit dashboard |
| http://127.0.0.1:3001/_immutrace/audit/sessions | JSON sessions |
| http://127.0.0.1:3001/_immutrace/audit/anchors | JSON anchors |
| http://127.0.0.1:3001/_immutrace/health | Proxy health |
| http://127.0.0.1:3001/_immutrace/docs | OpenAPI Swagger UI |

| File | What |
|------|------|
| `data/audit.db` | SQLite event store (chain + sessions + anchors) |
| `data/exports/*.pdf` | Generated audit reports |
| `.env` | Wallet, ports, mock toggle |

## Backup plan if something breaks live

| Symptom | Quick fix |
|---------|-----------|
| OSIRIS port 3000 not responding | Restart `npm run dev` in osiris-analysis |
| Proxy 502 errors | Check `OSIRIS_URL` in `.env` |
| Modal doesn't appear | Hard-refresh (Ctrl+F5) — SDK might be cached |
| Dashboard shows no sessions | Make sure cookies for `127.0.0.1` are allowed |
| Faucet doesn't work | Keep `MOCK_ANCHOR=true` — the demo is identical visually |
| Smoke test fails | Re-run `python -m tests.smoke_test` and read the failure list |

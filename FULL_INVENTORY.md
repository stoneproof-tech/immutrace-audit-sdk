# FULL INVENTORY — Pre-integrazione IMMUTRACE × OSIRIS

**Generato:** 2026-05-25 · esplorazione read-only (nessun file modificato/committato/pushato).
**Scopo:** mappa completa di ciò che già esiste prima di integrare i 3 componenti crypto (Shamir, AES-GCM, eIDAS/QTSP) nel plugin `immutrace-audit-sdk`, per non riscrivere da zero.

**Metodo:** 3 agenti di esplorazione paralleli (repo grande, cartella `mvp/`, OSIRIS) + lettura diretta di SDK, docs di deploy e memoria di progetto. I test in `mvp/` sono stati eseguiti davvero (risultati reali sotto). Hetzner solo da docs locali (nessun SSH).

> **Nota di onestà trasversale:** la maggior parte dei componenti "interessanti" (Shamir, AES-GCM, QTSP) **non sono né nel plugin `immutrace-audit-sdk` né in `mvp/`** — vivono in `decision-flow-ledger/ledgereye/backend/services/`. Sono completi e testati lì, ma scritti per **PostgreSQL + stack pesante**, mentre il plugin è volutamente **single-process FastAPI + SQLite**. "Portarli" = adattare il layer DB e le dipendenze, non copia-incolla.

---

## 1. decision-flow-ledger (repo "vecchio" / monorepo principale)

**Path:** `C:\Users\39338\decision-flow-ledger` · branch `fix/audit-totale` · versione **0.4.0 (beta)**

Monorepo di **IMMUTRACE**, piattaforma di audit-trail crittografico (SHA-256 hash chain, anchoring Polygon Amoy, Shamir key escrow, cancellazione crittografica GDPR), confezionata in 3 prodotti: **Protocol** (open source), **LedgerEye/Secure** (OSINT enterprise — il cuore), **Business** (non costruito).

### Albero (2-3 livelli, rumore escluso)
```
decision-flow-ledger/
├── .github/workflows/ci.yml      # CI: 4 job (mvp, ledgereye, sdk, lint ruff) — gira con "|| true"
├── mvp/                          # API Protocol core (FastAPI + PoW chain) — vedi §2
├── ledgereye/                    # ⭐ Piattaforma OSINT (IL componente principale)
│   ├── backend/                  # FastAPI: main.py (2199 righe) + routers/ + services/ + tests/
│   ├── frontend/                 # React 18.3 + Vite 5 + d3
│   └── landing/
├── contracts/                    # Hardhat/Solidity: Anchor.sol, IMMUTRACERoleRegistry.sol
├── immutrace-crypto/             # Crate Rust (PyO3): sha2, blake3, sharks(Shamir), hmac — acceleratore opzionale
├── saas/                         # "DecisionLedger SaaS" — FastAPI 0.111 + asyncpg (linea parallela/legacy?)
├── connector/                    # "Universal Connector" FastAPI (Fernet, SQLite, monitor file/Excel)
├── sdk/                          # Client SDK: js/ (TypeScript) + python/immutrace/
├── dashboard/                    # SPA React 19 + Vite 8 (dashboard Protocol)
├── ml/                           # Anomaly detection (isolation forest .joblib, VAE .pt, adversarial)
├── llm/                          # Layer NLP (intent_parser, query_agent, guardrails, prompts)
├── simulation/                   # Generatore dati sintetici AML/intelligence
├── browser-extension/            # Estensione Chrome/Firefox
├── nginx/  scripts/  backup/  monitor/  docs/(~22 file)  landing/  protocol/
└── secure/ (VUOTA)  business/ (solo README)
```
**Root:** ~8 Dockerfile (uno per servizio), `docker-compose.yml` (8 servizi), `crypto.py` (crypto unificato Rust→Python fallback), `analytics.py`, molti `*_REPORT.md`, `codebase_export.md` (3.2 MB), `IMMUTRACE-demo.mp4`.

### Tecnologie (con evidenza)
- **Python 3.11+** (primario) — FastAPI 0.115, uvicorn, psycopg2, pyjwt, bcrypt, **cryptography 44.0**, pyotp, **web3≥6**, anthropic 0.40, reportlab, slowapi, apscheduler.
- **Node/React** — `dashboard/` React **19** + Vite 8 (bleeding-edge); `ledgereye/frontend/` React 18.3 + Vite 5 + d3; SDK TypeScript.
- **Solidity 0.8.20** — Hardhat 2.28 + OpenZeppelin 5.6 + ethers 6 (Anchor.sol = Ownable+Pausable, `anchor(bytes32)`/`verify`).
- **Rust (2021)** — PyO3 0.22, sha2/blake3/sharks/hmac, benches criterion.
- **PostgreSQL 15** — schema in vari `init.sql`/`*.sql`.
- **Docker Compose**, **Nginx + Certbot**, **Railway** (`railway.json` deploya mvp + saas), **scikit-learn/PyTorch** (ML).

### Cosa fa girare oggi
Stack Docker Compose a 8 servizi dietro Nginx: `postgres` · `immutrace-api` (mvp:8000) · `immutrace-dashboard`/`landing` · `ledgereye-backend` (:8000, chiama immutrace-api) · `ledgereye-frontend`/`landing` · `nginx` (80/443) · `certbot`. Entry point: `uvicorn ledgereye/backend/main.py` e `mvp/main.py`. Contratti via `npx hardhat run scripts/deploy_anchor.js --network amoy`.

### Stato: **Sviluppo attivo / Beta** (non production-hardened, non abbandonato)
- **Attivo:** ultimo commit ~2026-05-15 (~10 gg prima dello snapshot), 79 commit, picco aprile 2026. v0.4.0 = passata di "audit fix" che ha sostituito crypto fake con implementazioni reali (README ha tabella onesta "What Is NOT Yet Available").
- **Beta:** auto-etichettato beta; mainnet Polygon, HSM/KMS, QTSP aggiuntivi rinviati a Q3-Q4 2026; chiavi custodi via env in dev.
- **Sprawl/incertezze (onesto):** `secure/` vuota; `saas/` vs `mvp/`+`ledgereye/` → **probabile duplicazione di prodotto, non confermato quale sia davvero deployato**; molti report `.md`, `codebase_export.md` da 3.2 MB e un `.mp4` in repo → workflow solo-dev assistito da AI, non team-hardened.
- **Segreti (solo path, contenuti NON letti):** `.env.local`, `.env.production.example` (template), `contracts/.env`, `mvp/.env`. Da confermare gitignored.

---

## 2. decision-flow-ledger\mvp\ (focus speciale)

**Cos'è:** la **IMMUTRACE Protocol API MVP** — FastAPI che implementa un ledger immutabile per query su DB sensibili (operatore → approvazione multi-sig 2-di-N → esecuzione), registrato su PostgreSQL **+** una blockchain PoW locale, con anchoring opzionale dei Merkle root su Polygon.

### ⚠️ Problema trasversale (leggere per primo)
La mvp **non è self-contained**. `main.py` e `polygon_anchor.py` fanno `sys.path.insert(0, "..")` e importano moduli che stanno nel **root del repo**, non in `mvp/`:
`from crypto import ...`, `from analytics import ...`, `from ml.inference import ...`, `from llm.query_agent import ...`.
Ma `mvp/Dockerfile` fa `COPY . .` solo dal contesto `mvp/`, e `requirements.txt` **omette `cryptography`**. → **L'immagine Docker della mvp così com'è crasherebbe all'import** o al primo hit degli endpoint analytics/ML/LLM. È il principale problema di completezza/portabilità.

### Componente per componente
| File | Cosa fa | Stato | Test | Riuso |
|------|---------|-------|------|-------|
| `mvp/main.py` (1579 righe) | Tutta la REST API: query submit/approve/execute, `/ledger`, `/blockchain*`, `/integrity`, anchor Polygon, certificazione pubblica, analytics/anomaly/NLQ | **WIP** — core ledger COMPLETO; analytics/ML/NLQ dipendono dai moduli root non bundlati. Bug confermato `/api/leads` → `send_test_email()` chiamata con args ma firma a 0 args (TypeError silenziato). Versioni incoerenti (0.2.0 vs 0.3.0) | solo e2e (serve server live) → falliti | **Basso** (hardwired Postgres + import cross-dir) |
| `mvp/blockchain.py` (348) | Blockchain PoW single-node: SHA-256 PoW diff=4, Merkle per blocco, linkage prev-hash, `verify_chain()`, persistenza Postgres JSONB, thread-safe | **COMPLETO** per ciò che è. Onestamente è un **hash chain decorato da PoW**, non consenso distribuito | `test_unit_blockchain.py` quasi tutti pass; 1 fail reale (`test_persistence`: API `chain_file=` non più supportata) | **Medio-Alto** (pulito, dep leggere; sostituire persistenza) |
| `mvp/polygon_anchor.py` (290) | Anchoring on-chain `IMMUTRACEAnchor.anchor(bytes32)` via web3: nonce lock, gas+20%, retry x3, wait receipt, parse evento; `verify_anchor()`; Merkle puro-Python | **COMPLETO** ma **inerte senza config** (richiede `ANCHOR_CONTRACT_ADDRESS`/`POLYGON_PRIVATE_KEY`/`POLYGON_WALLET`). Default Amoy (80002) | `test_polygon_anchor.py` (4) **FALLITI = stale** (assert tipo sbagliato, manca env). Subset integration pass | **Medio-Alto** (logica anchoring solida e generica) |
| `mvp/init.sql` (165) ⭐ | Schema Postgres: `operators`, `queries`, **`audit_ledger`** (chain `entry_hash`/`previous_hash` a livello SQL), `approvals` (multi-sig), `blockchain_blocks`, `polygon_anchors`. **Immutabilità via trigger plpgsql** che fanno RAISE su UPDATE/DELETE | **COMPLETO**, ben disegnato (i trigger di immutabilità sono ottimi) | n/a | **Alto** (idempotente, portabile) |
| `mvp/notifications.py` (147) | Email HTML fire-and-forget via Resend (httpx, thread daemon) | **COMPLETO** ma inerte senza `RESEND_API_KEY`; mismatch firma `send_test_email()` | — | **Medio** (Resend-specifico) |
| `mvp/dashboard.html` (34 KB) | Dashboard statica single-file | Presunto completo, **non verificato riga per riga** | — | Medio |
| `mvp/Dockerfile` / `requirements.txt` | — | **WIP/rotto** (moduli parent mancanti, manca `cryptography`) | — | — |
| `mvp/docker-compose.yml` | postgres:15 + neo4j:5 + ledger-api | Completo ma **`neo4j` non referenziato da alcun codice mvp** (leftover) | — | — |

### Test eseguiti — risultati REALI
- **Suite completa** (`pytest mvp/tests/`, Python 3.12.10): **`51 failed, 36 passed, 4 skipped` in 198s**.
- **Subset offline** (senza server/DB live): **`36 passed, 1 failed, 4 skipped` in 0.29s**.
- Dei 51 fail: **45** sono `ConnectError` verso `http://localhost:8000` non in esecuzione (errori d'ambiente, non di logica); **4** = test polygon **stale**; **1** = drift API `test_persistence`; **4 skipped** = on-chain senza creds. **I 36 offline validano davvero SHA-256, Merkle, PoW, tamper-detection, linkage.** I primitivi core funzionano.

### Caccia esplicita ai componenti richiesti
| Componente | Esito | Dove | Stato |
|-----------|-------|------|-------|
| **Shamir Secret Sharing** | ✅ TROVATO, COMPLETO (2 impl) — **NON in mvp** | `ledgereye/backend/services/shamir.py` (215 righe, GF(256) poly 0x11B, **g=3** corretto, Lagrange, default **3-di-5**, + wrapping RSA-4096 OAEP, `escrow_key`/`recover_key` per GDPR Art.17). Anche Rust `immutrace-crypto/src/shamir.rs` (crate `sharks`) | COMPLETO. Richiede `cryptography`. **mvp non lo usa** |
| **AES-GCM** | ✅ TROVATO, COMPLETO — **NON in mvp** | `ledgereye/backend/services/encryption.py` (125 righe): AES-256-GCM, nonce 96-bit, **chiave per-record wrappata da master key** (`MASTER_ENCRYPTION_KEY`), keystore su DB, **cancellazione crittografica** (distruggi chiave → ciphertext irrecuperabile) per GDPR Art.17 | COMPLETO. Keystore **assume DB** (da adattare a SQLite) |
| **eIDAS / QTSP / RFC 3161** | ✅ TROVATO, COMPLETO (con mock) — **NON in mvp** | `ledgereye/backend/services/qtsp_aruba.py` (310 righe): timestamp RFC 3161 verso **Aruba PEC TSA**; 2 path reali (`rfc3161ng`, oppure ASN.1 grezzo via `asn1crypto`) + **mock TSA CA** (`MOCK_QTSP=true`); marca `eidas_qualified=True` su risposta Aruba reale | COMPLETO **ma** il path ASN.1 grezzo ha un `MessageImprint`/AlgorithmIdentifier probabilmente bacato — **usare il path `rfc3161ng`** |
| Altro crypto/signing/anchoring | ✅ | `mvp/polygon_anchor.py` (on-chain), `mvp/blockchain.py` (PoW), `crypto.py` root (HMAC-SHA256 proof), Rust `immutrace-crypto` (BLAKE3/SHA-256/Merkle/Shamir/HMAC). **`immutrace-crypto/src/pqc.rs` = STUB esplicito** (Kyber768/Dilithium3 → "not yet implemented") | — |
| Schema DB audit | ✅ COMPLETO | `mvp/init.sql` (`audit_ledger` + trigger immutabilità) | — |
| Hash chain | ✅ COMPLETO | 2 layer: chain SQL in `audit_ledger`; `mvp/blockchain.py` (SHA-256 linkato + Merkle). Merkle unit-tested e passante | — |

---

## 3. immutrace-audit-sdk (plugin nuovo, già pushato)

**Path:** `C:\Users\39338\immutrace-audit-sdk` · ora su **github.com/stoneproof-tech/immutrace-audit-sdk (privato)**.
> ⚠️ **Conflitto con la memoria di progetto:** la memoria `project-osiris-demo` dice "AGPL-3.0, **NON pushare GitHub**". È stato pushato **privato** in questa sessione su esplicita richiesta dell'utente (l'istruzione recente prevale; il privato è reversibile). La memoria andrebbe aggiornata.

**Filosofia (diversa dal repo grande, by design):** un **solo processo Python FastAPI fa TUTTO** — niente PostgreSQL, niente backend separato, niente Docker. Autocontenuto: **SQLite + reportlab + web3.py**.

### Albero + dimensioni
```
proxy/
  app.py        (72)   # entry FastAPI: lifespan(anchor worker), /_immutrace/health, route WebSocket bridge, catch-all HTTP
  proxy.py      (303)  # reverse proxy + log_event (hash chain su SQLite) + handle_proxy_websocket (bridge HMR)
  chain.py      (55)   # sha256_hex, canonical_event, chain_hash, merkle_root, verify_chain  ← HASH CHAIN
  db.py         (89)   # SQLite (WAL), schema events/sessions/anchors, last_hash
  auth.py       (89)   # create_session/get_session (TTL, revoke), is_sensitive_path (prefix match)
  config.py     (79)   # .env loader, SENSITIVE_PREFIXES (15 prefissi /api/*), MOCK_ANCHOR default True
  anchor.py     (184)  # anchor_worker: batch eventi → merkle root → Polygon Amoy o MOCK
  dashboard.py  (218)  # API audit (events/sessions/anchors/verify), endpoint sessione, dashboard, PDF export
  pdf_export.py (311)  # report PDF firmato (reportlab + QR)
dashboard/
  sdk.js        (273)  # iniettato in OGNI HTML: modal autorizzazione + intercettore fetch (401→modal) + banner
  app.js (207) dashboard.html (60) style.css (118)   # UI audit su /_immutrace/dashboard
scripts/  bootstrap_wallet.py (58)  deploy_anchor.py (112)   # Polygon Amoy
tests/    smoke_test.py (183, 29 casi)  concurrency_test.py (90)
.env (segreto, gitignored)  .env.example  README/HOW_TO_RUN/DEMO_SCRIPT/LAYOUT_INTEGRATION_MARKER
```
`requirements.txt`: fastapi, uvicorn[standard], httpx, jinja2, **aiosqlite**, python-multipart, **reportlab, qrcode, pillow**, **web3, eth-account**, python-dotenv, pydantic. (**Manca `cryptography`** → da aggiungere per i 3 componenti nuovi.)

### Cos'è già implementato
- **Reverse proxy** :3001 → OSIRIS :3000, trasparente, **WebSocket bridge** per HMR (aggiunto in questa sessione: senza, OSIRIS dev resta sullo splash).
- **Hash chain SHA-256** per richiesta (`chain.py` + `log_event`): ogni evento HTTP → `prev_hash`+`this_hash` su SQLite, scrittura serializzata da `asyncio.Lock` + `to_thread` (fix concorrenza di questa sessione), WAL.
- **Auth gate**: endpoint sensibili (15 prefissi `/api/*`) bloccati con 401 `X-Immutrace-Gate: blocked` se non c'è sessione → `sdk.js` mostra il modal (justification ≥20 char, activity type, case id).
- **Anchor worker**: batch periodico → `merkle_root` → Polygon Amoy (o MOCK default). Wallet demo in `.env` (gitignored).
- **Dashboard + verifica catena + export PDF firmato con QR.**
- **Tamper-evidence** testata: `verify_chain` ricostruisce e rileva manomissioni; smoke test 29 casi.

### Architettura (flusso dati attuale)
```
Browser → :3001 proxy ──(HTTP)──> log_event → SQLite events (chain) → anchor_worker → Polygon/MOCK
                       └─(inietta sdk.js in HTML)→ modal auth → POST /_immutrace/session/start → cookie
   endpoint sensibile senza sessione → 401 gate → modal → con sessione → forward a OSIRIS :3000
```

### Punti di estensione dove agganciare i 3 componenti
1. **Shamir** → escrow di `ANCHOR_PRIVATE_KEY` / nuova `MASTER_ENCRYPTION_KEY` (oggi singola chiave in `.env` = single point of failure). Nuovo modulo `proxy/escrow.py`; endpoint recovery in `dashboard.py`; tabella custodi in `db.py`.
2. **AES-GCM + crypto-erasure** → cifrare a riposo i **campi PII in chiaro** dell'evento (`justification`, `case_id`, `actor`) e delle sessioni. Hook in `log_event` (`proxy/proxy.py`) e in `auth.create_session`; keystore per-record nuova tabella in `db.py`; endpoint `/_immutrace/gdpr/erase` in `dashboard.py`. (Nota: il proxy oggi memorizza **hash** dei body, non i body → poco plaintext da cifrare, ma justification/case_id sono PII reali.)
3. **QTSP/RFC 3161** → timestamp qualificato del **merkle root di ogni batch** accanto (o in alternativa) all'anchoring Polygon. Hook in `anchor.py` (`anchor_worker`); colonne `tsa_token`/`eidas_qualified` nella tabella `anchors` (`db.py`); endpoint verifica timestamp in `dashboard.py`.

---

## 4. osiris-analysis (clone OSIRIS)

**Cos'è:** **OSIRIS** (Open Source Intelligence & Reconnaissance Integrated System) — dashboard di intelligence globale real-time. **Next.js 16 (App Router, Turbopack) + TypeScript 5 + MapLibre GL (WebGL)**. Aggrega voli, navi (AIS), CCTV, sismi, satelliti, conflitti, cyber-threat, news. **Nessuna autenticazione, nessun logging, solo rate-limit IP** (`src/middleware.ts`, 100 req/min). ~30 endpoint API in `src/app/api/*/route.ts`.

### Endpoint sensibili intercettati dal proxy (match per prefisso in `config.SENSITIVE_PREFIXES`)
**CRITICAL:** `/api/flights` (voli commerciali/militari, zone jamming), `/api/maritime` (AIS, basi navali, choke point), `/api/satellites` (recon/SIGINT NRO), `/api/frontlines` (fronte Ucraina DeepState), `/api/infrastructure` (infrastrutture critiche), `/api/scanner` + `/api/osint/*` (toolkit RECON: DNS/WHOIS/CVE/port-scan, SSRF-hardened).
**HIGH:** `/api/cctv` (2000+ telecamere), `/api/sentinel` (SAR/multispettrale), `/api/gdelt` (eventi conflitto).
**MEDIUM:** `/api/region-dossier`, `/api/cyber-threats` (CISA KEV — fetchato da `GlobalStatusBar` al load → è ciò che fa scattare il modal). `/api/balloons`, `/api/radiation` referenziati ma forse non implementati.

### Punti di contatto plugin ↔ OSIRIS
- **Frontend** (`src/app/page.tsx`, client component): `fetch()` raw senza interceptor, fetch iniziali al mount + polling per-layer. **Nessuna astrazione** → il proxy intercetta tutto a livello rete.
- **Auth/middleware** esistente: solo rate-limit IP, nessuna identità → terreno ideale per il layer audit IMMUTRACE.
- **Aggancio naturale:** reverse proxy davanti a `/api/*` (già fatto). Per il 30% di eventi semantici (click MapLibre, search, toggle layer) servirebbe l'SDK drop-in in `layout.tsx` (vedi memoria `project-osiris-integration`, max 1 import + 1 wrap, **NON modificare OSIRIS in modo invasivo**).

---

## 5. Server produzione Hetzner (solo da docs locali — NON verificato live)

**Fonte:** `DEPLOY_AND_FUNDING_REPORT.md` (2026-05-15) + `IMMUTRACE_AUDIT_REPORT.md` / `SESSION_*_REPORT.md` / `docs/MIGRATION.md`. **Nessun SSH eseguito**, quindi lo stato reale ad oggi non è confermato (snapshot di ~10 giorni fa).

- **Server:** `168.119.231.109` (Hetzner, **Ubuntu 24.04**, EU/GDPR). **Path deploy:** `/opt/immutrace`. **Docker Compose** (riportato "v5.1.1").
- **Servizi riportati healthy** (dietro nginx SSL :443):
  - `immutrace.eu` → landing (nginx statico)
  - `api.immutrace.eu` → immutrace-api (MVP) v0.3.0
  - `ledgereye-api.immutrace.eu` → ledgereye-backend **v0.4.0** (`immutrace_connected: True`)
  - `dashboard.immutrace.eu` → dashboard · `app.immutrace.eu` → ledgereye-frontend
  - `postgres:5432` (interno, volume persistente) · `certbot` (Let's Encrypt)
- **Note operative dai docs:** conflitto risolto Caddy (agent Hetzner) vs nginx su :80; backup cron `/opt/immutrace/backup.sh` → Hetzner Storage Box/S3-EU.
- **Comandi di gestione (dai docs):** `ssh root@168.119.231.109 "docker ps ..."`; recovery `cd /opt/immutrace && docker compose up -d`.

> **Onesto:** questo è il deploy del **monorepo grande** (LedgerEye + MVP), **non** del plugin `immutrace-audit-sdk` (che gira solo in locale per la demo OSIRIS). Il plugin non è ancora deployato da nessuna parte.

---

## 6. SINTESI STRATEGICA — RACCOMANDAZIONI

### A. Già PRONTO, va solo PORTATO nel plugin
Tutti e 3 i componenti crypto esistono **completi e testati** in `ledgereye/backend/services/`. Il lavoro è **adattamento** (DB Postgres→SQLite, dipendenze, wiring nell'event flow del proxy), non scrittura.
| Componente | Sorgente | Lavoro di port | Stima |
|-----------|----------|----------------|-------|
| Shamir (escrow chiave anchor/master) | `services/shamir.py` (puro, testato 42 test) | Copiare, aggiungere `cryptography`, tabella custodi SQLite, endpoint recovery | **3–5 h** |
| AES-GCM + crypto-erasure | `services/encryption.py` (18 test) | Adattare keystore Postgres→SQLite, hook su justification/case_id/actor, endpoint GDPR erase | **5–8 h** |
| QTSP/RFC 3161 (timestamp Amoy batch) | `services/qtsp_aruba.py` (19 test, path `rfc3161ng`) | Copiare, aggiungere deps (`rfc3161ng`/`asn1crypto`), hook in `anchor_worker`, colonne `anchors` | **5–8 h** |
| (riuso opzionale) `mvp/init.sql` trigger immutabilità, Merkle helpers | — | Pattern da imitare in SQLite | 1–2 h |

### B. Bozza/STUB da COMPLETARE
| Cosa | Dove | Lavoro | Stima |
|------|------|--------|-------|
| Path ASN.1 grezzo QTSP bacato (MessageImprint) | `qtsp_aruba.py` | Evitarlo usando `rfc3161ng`, oppure fixare AlgorithmIdentifier | 2–4 h (se serve il path grezzo) |
| Test stale polygon_anchor | `mvp/tests/test_polygon_anchor.py` | Solo se si riusa quel codice: aggiornare assert (dict vs str) + env | 1–2 h |
| PQC (Kyber/Dilithium) | `immutrace-crypto/src/pqc.rs` | **Fuori scope ora** — è dichiaratamente non implementato | — |

### C. Da SCRIVERE da zero (glue di integrazione nel plugin)
| Cosa | Stima |
|------|-------|
| Schema chiavi/custodi + migrazione SQLite (keystore AES, tabella Shamir custodi, colonne TSA in `anchors`) | 3–5 h |
| Wiring nell'event flow: cifratura a riposo in `log_event`/`create_session`, escrow della chiave anchor, timestamp QTSP in `anchor_worker` | 5–8 h |
| Endpoint dashboard nuovi: `/gdpr/erase`, `/escrow/recover`, `/timestamp/verify` + UI minima | 4–7 h |
| Test (port dei test ledgereye su SQLite + nuovi test integrazione) | 4–6 h |
| PDF firmato: includere token QTSP + prova Shamir nel report | 2–3 h |

**Totale realistico:** Porting (A) **~14–23 h** · Completamento (B) **~3–6 h** · Da zero (C) **~18–29 h** → **≈ 35–58 h** complessive (4–7 giornate). *Stima onesta da solo-dev; esclude imprevisti su Aruba TSA reale e Amoy reale.*

### D. Ordine consigliato (dal meno al più rischioso)
1. **Shamir escrow** — rischio **basso**: matematica pura, niente rete, niente DB live; risolve subito il single-point-of-failure della chiave anchor in `.env`.
2. **AES-GCM + crypto-erasure** — rischio **basso-medio**: self-contained, niente rete; richiede solo keystore SQLite. Abilita la storia GDPR Art.17.
3. **QTSP/RFC 3161** — rischio **medio**: chiamata di rete esterna (Aruba), ma c'è il mock; aggiunge il timestamp eIDAS accanto a Polygon.
4. **Glue + endpoint + UI + PDF** — rischio **medio-alto**: tocca l'event flow live e la concorrenza.
5. **Real Amoy + Aruba reali end-to-end** — rischio **più alto**: faucet, contratto deployato, credenziali TSA, costi.

### E. Rischi tecnici concreti
1. **⚠️ Concorrenza/event-loop (il più importante):** la chiamata di rete QTSP e il crypto pesante **NON devono girare sull'event loop** del proxy, altrimenti si ripresenta il bug di stallo già risolto in questa sessione (SQLite bloccante → ReadTimeout). Usare `asyncio.to_thread`/worker come fatto per `log_event` e per l'anchor worker.
2. **Divergenza schema DB Postgres→SQLite:** `encryption.py` e l'escrow assumono un keystore su DB Postgres + tipi/JSONB. Va riscritto il layer di persistenza per SQLite (no JSONB nativo, tipi diversi).
3. **Dipendenze nuove nel plugin:** `cryptography` (ok, leggera), `rfc3161ng` + `asn1crypto` (QTSP). Il plugin oggi è volutamente snello — ogni dep aggiunta va valutata.
4. **Gerarchia delle chiavi poco definita:** oggi c'è `ANCHOR_PRIVATE_KEY` in `.env`. Introducendo `MASTER_ENCRYPTION_KEY` (AES) + escrow Shamir serve un disegno chiaro di chi-cifra-cosa e chi-custodisce-cosa, altrimenti si crea confusione/lock-out.
5. **Bug noto QTSP path grezzo** (vedi B) — preferire `rfc3161ng`.
6. **Rust `immutrace-crypto` NON portarlo:** per la scala del plugin il puro Python basta; evitare la complessità del build maturin/PyO3.
7. **NON portare `mvp/blockchain.py` (PoW):** il plugin ha già un hash chain + anchoring più adatto al caso "audit layer"; la PoW single-node sarebbe peso inutile.
8. **OSIRIS:** non modificare in modo invasivo (memoria `project-osiris-integration`: max 1 import in `layout.tsx`, contattare il maintainer prima di PR).

### Conclusione onesta
Non si parte da zero: **i 3 componenti chiesti esistono già, completi e testati**, ma in un altro stack (Postgres/heavy) — il valore del lavoro è **adattarli al plugin snello SQLite e integrarli nel flusso senza rompere la concorrenza**, non reimplementarli. Il rischio maggiore non è la crypto (è pronta) ma il **wiring nell'event loop** e la **gestione delle chiavi**.

# IMMUTRACE — Integration Plan (Fase 1, pianificazione)

**Data:** 2026-05-25 · **Branch:** `feat/full-integration` · **Deadline:** 2026-08-01 (NGI Zero round 14)
**Regola d'oro:** `main` (demo `:3001`) non si tocca mai; ogni commit su `feat/full-integration` deve lasciare verde lo smoke test 29/29.

> Questo documento è **solo pianificazione**. Nessun codice scritto. Le stime sono oneste e includono debug/integrazione, non solo "scrittura felice".

---

## 1. Architettura target (chi parla con chi)

```
                          ┌────────────────────────────────────────────────┐
  Browser (analista)      │              IMMUTRACE CORE (:3001)              │
  ───────────────────────▶│                                                 │
   1. GET / (HTML OSIRIS) │  app.py  ──FastAPI router──┐                     │
   2. sdk.js iniettato    │                            │                     │
   3. login               │  identity.py ◀── users/sessions (argon2)         │
   4. richiesta query     │  workflow.py ◀── query_requests/approvals        │
   5. (supervisore approva)│        │                                        │
   6. query autorizzata   │  proxy.py / adapters/http_adapter.py ───────────────▶ OSIRIS :3000
                          │        │                            (forward)    │      (o altro backend
                          │        ▼                                         │       via altro adapter)
                          │  log_event → chain.py (SHA-256) → db.py (SQLite) │
                          │        │            │                            │
                          │        │            ├─ crypto/encryption.py (AES-GCM su campi sensibili)
                          │        ▼            │                            │
                          │  anchor.py (batch)  └─ crypto/shamir.py (master key 3-of-5)
                          │     ├─ merkle_root → timestamp/ (eIDAS adapter: locale|QTSP)
                          │     └─ → Polygon (mock dev | mainnet reale prod)
                          │  dashboard.py: audit UI, coda approvazioni, pannello custodi, PDF
                          └────────────────────────────────────────────────┘
   Config esterna:  config/sensitive_endpoints.yaml  (il cliente la compila)
   Demo-specifico:  demos/osiris/ (config + 5 custodi locali + scenari)
```

**Principio adapter:** il *core* non sa cosa c'è dietro. `adapters/base.py` definisce `BackendAdapter` (forward request, normalizza response). `http_adapter.py` = comportamento attuale (reverse proxy). `graphql_adapter.py` / `grpc_adapter.py` = stub con interfaccia pronta. Stessa logica per `timestamp/` (provider locale|QTSP) e custodi (locali|reali).

---

## 2. File structure target

```
proxy/                          # CORE universale (zero riferimenti OSIRIS)
  app.py            (esistente) # + monta router identity/workflow/custodian
  proxy.py          (esistente) # gating spostato: usa workflow.py prima del forward
  chain.py          (esistente) # hash chain (rafforzare test)
  db.py             (esistente) # + nuove tabelle/migrazioni
  config.py         (esistente) # + carica sensitive_endpoints.yaml, flags adapter
  auth.py           (esistente) # rifuso dentro identity.py (sessioni) — vedi §5.2
  anchor.py         (esistente) # + hook timestamp, switch mock/mainnet
  dashboard.py      (esistente) # + endpoint nuovi
  pdf_export.py     (esistente) # + timestamp + anchor hash nel PDF
  identity.py       (NUOVO)     # utenti, ruoli, password hashing, login/logout
  workflow.py       (NUOVO)     # richiesta→approvazione→esecuzione
  crypto/           (NUOVO pkg)
    __init__.py
    encryption.py   # AES-GCM  ← port da ledgereye/backend/services/encryption.py
    shamir.py       # Shamir   ← port da ledgereye/backend/services/shamir.py
    keymgmt.py      # gerarchia chiavi: master key + escrow Shamir + wrap AES
  timestamp/        (NUOVO pkg)
    base.py         # TimestampProvider (astratto)
    local_provider.py
    qtsp_provider.py # ← port da ledgereye/backend/services/qtsp_aruba.py (path rfc3161ng)
  adapters/         (NUOVO pkg)
    base.py         # BackendAdapter (astratto)
    http_adapter.py # comportamento attuale
    graphql_adapter.py / grpc_adapter.py  # STUB estendibili
config/
  sensitive_endpoints.yaml      # client-editable (prefissi + livello rischio)
demos/osiris/
  osiris_config.yaml            # mappa OSIRIS-specifica
  custodians/                   # 5 keypair locali (PRIVATE gitignored!)
  scenarios/*.md|*.py           # scenari demo scriptati
sdk/                            # libreria JS standalone riusabile
  immutrace-observer.js         # estratta/generalizzata da dashboard/sdk.js
  README.md
dashboard/                      # UI (de-OSIRIS-izzata)
  sdk.js (esistente→generalizzato), app.js, dashboard.html, style.css
  + viste: approval-queue, custodian-panel, login
docs/
  ARCHITECTURE.md  SECURITY_MODEL.md  INTEGRATION_GUIDE.md  DEMO_SCRIPT.md (update)  README.md (riscritto)
tests/
  smoke_test.py (29, intatto)  +  e2e_login.py  e2e_workflow.py  e2e_shamir.py
  e2e_encryption.py  e2e_timestamp.py  e2e_anchor.py   (target 50+ test)
```

---

## 3. Schema DB nuovo (`data/audit.db`, SQLite — additive, nessun DROP)

Tabelle **esistenti** (intatte): `events`, `sessions`, `anchors`.
Migrazioni additive (script `db.migrate()` idempotente, `CREATE TABLE IF NOT EXISTS`):

```sql
-- Identità
users(id PK, username UNIQUE, password_hash, role CHECK(analyst|supervisor|admin|custodian),
      display_name, email, created_at, disabled INT DEFAULT 0)
-- sessions: aggiungere user_id FK (oggi c'è solo 'actor' stringa)
ALTER sessions ADD COLUMN user_id INTEGER REFERENCES users(id)

-- Workflow approvazione
query_requests(id PK, requester_user_id FK, target_path, query, justification,
               activity_type, case_id, risk_level, status CHECK(pending|approved|rejected|executed),
               created_at, decided_by FK, decided_at, decision_reason)
-- (l'esecuzione effettiva resta loggata in events, con FK request_id)
ALTER events ADD COLUMN request_id INTEGER REFERENCES query_requests(id)

-- Shamir / custodi
custodians(id PK, name, role_label, pubkey, contact, is_local INT)   -- is_local=1 demo, 0 reale
key_shards(id PK, key_id, custodian_id FK, share_index, share_ciphertext, created_at)
key_meta(key_id PK, threshold, total_shares, created_at, purpose)     -- es. 3-of-5 master key

-- AES-GCM keystore (chiave per-record wrappata da master key)
record_keys(id PK, record_table, record_id, wrapped_key, nonce, created_at, erased INT DEFAULT 0)
-- crypto-erasure: erased=1 + wrapped_key NULL → plaintext irrecuperabile

-- Timestamp eIDAS
qtsp_timestamps(id PK, anchor_id FK, provider, hash_hex, tsa_token BLOB,
                eidas_qualified INT, timestamped_at)
ALTER anchors ADD COLUMN timestamp_id INTEGER REFERENCES qtsp_timestamps(id)
```

> **Nota immutabilità:** SQLite non ha trigger plpgsql come `mvp/init.sql`, ma si possono usare trigger SQLite `BEFORE UPDATE/DELETE ... RAISE(ABORT)` su `events`/`query_requests` per replicare l'append-only. Da valutare (rischio: complica i test). In alternativa: append-only applicativo + verifica hash chain (come oggi).

---

## 4. API endpoints (nuovi, prefisso `/_immutrace`)

**Auth/Identity:**
- `POST /auth/login` {username,password} → cookie sessione
- `POST /auth/logout`
- `GET  /auth/me` → {user, role}
- `GET/POST/PATCH/DELETE /users` (solo admin)

**Workflow approvazione:**
- `POST /requests` (analyst) {target_path, justification, activity_type, case_id} → request pending
- `GET  /requests?status=pending` (supervisor) → coda
- `POST /requests/{id}/approve` (supervisor) → status=approved (sblocca la query)
- `POST /requests/{id}/reject` {reason}

**Custodi / Shamir:**
- `GET  /custodians`
- `GET  /custodians/{id}/share` (il custode vede SOLO il proprio share)
- `POST /shamir/reassemble` {shares[]} → ricostruisce master key (≥ threshold) — operazione auditata
- `POST /shamir/rotate` (admin) → nuova master key + ri-split

**Timestamp / Anchor:**
- `GET  /timestamp/{anchor_id}/verify`
- `GET  /anchor/{id}` (stato anchor + tx mainnet)

**Esistenti (intatti):** `/health`, `/session/*`, `/audit/events|sessions|anchors|verify`, `/dashboard`, `/sdk.js`, `/audit/export/{id}.pdf`.

---

## 5. Dettaglio per componente

### 5.1 Architettura universale (P0)
- **Cosa fa:** estrae la config sensibile in `config/sensitive_endpoints.yaml`; introduce `adapters/base.py` + `http_adapter.py` (rifattorizza l'attuale `proxy.py`); de-OSIRIS-izza il core (riferimenti OSIRIS → `demos/osiris/`); estrae l'SDK JS standalone in `sdk/`.
- **File target:** `config/`, `proxy/adapters/`, `proxy/config.py` (loader YAML), `sdk/immutrace-observer.js`, `demos/osiris/osiris_config.yaml`.
- **Riuso ledgereye:** nessuno (è refactoring interno).
- **Dipendenze nuove:** `PyYAML`.
- **Acceptance E2E:** la demo OSIRIS gira identica a prima ma leggendo `sensitive_endpoints.yaml`; un secondo config fittizio (`demos/generic/`) dimostra che cambiando solo YAML il gate cambia endpoint. Smoke 29/29 verde.
- **Rollback:** refactoring puro su branch; se rompe, `git revert`.
- **Stima onesta:** **12–18 h** (rischio medio: tocca il cuore del proxy senza rompere la demo).

### 5.2 Identity & Authorization (P0)
- **Cosa fa:** tabella `users`, ruoli, hashing password (**argon2** via `argon2-cffi`, fallback bcrypt), login/logout, sessione legata a `user_id` (rifonde `auth.py` → `identity.py`). UI di login nel modal.
- **File target:** `proxy/identity.py`, modifiche `proxy/db.py`, `dashboard/` (vista login).
- **Riuso ledgereye:** pattern da `ledgereye/backend/main.py` (auth JWT/bcrypt) e `services/totp.py` se si vuole 2FA (opzionale, fuori scope ora).
- **Dipendenze nuove:** `argon2-cffi`.
- **Acceptance E2E:** `e2e_login.py` — login analyst/supervisor/admin, password sbagliata rifiutata, sessione scade, ruoli applicati.
- **Rollback:** la sessione singola attuale resta come fallback se `users` vuota.
- **Stima onesta:** **16–24 h**.

### 5.3 Workflow approvazione (P1) — ⚠️ il pezzo più rischioso
- **Cosa fa:** analista crea `query_request` (pending) invece di colpire subito l'endpoint sensibile; supervisore approva/rifiuta; solo dopo approval la query parte e viene loggata.
- **Decisione architetturale critica (DA VALIDARE):** *non* tenere aperta la connessione HTTP del browser in attesa dell'umano (fragile, timeout). Modello scelto: **pre-autorizzazione** — l'analista sottomette una *richiesta*; il gate del proxy lascia passare la query solo se esiste un `query_request` **approved** che la matcha (per sessione+path+finestra temporale). Il browser fa polling/ricarica della coda.
- **File target:** `proxy/workflow.py`, gating in `proxy/proxy.py`, `dashboard/` (vista approval-queue).
- **Riuso ledgereye:** concetto multi-sig da `mvp/main.py` (`/query/submit`+`/query/approve`), ma riscritto (lì è Postgres + 2-of-N operatori).
- **Dipendenze nuove:** nessuna.
- **Acceptance E2E:** `e2e_workflow.py` — analyst richiede → endpoint bloccato → supervisor approva → endpoint passa → audit registra requester+approver; reject blocca.
- **Rollback:** feature-flag `WORKFLOW_ENABLED`; se off, comportamento attuale (gate solo a sessione).
- **Stima onesta:** **20–30 h** — *e qui segnalo che può esplodere a 35–40 h* se si scopre che il modello pre-autorizzazione non basta per la UX desiderata (es. approvazione per singola query live).

### 5.4 Shamir 3-of-5 (P1)
- **Cosa fa:** la master key (che wrappa le chiavi AES) è splittata in 5 share, 3 per ricostruirla; pannello custodi dove ognuno vede/contribuisce il proprio share; 5 keypair locali in `demos/osiris/custodians/` (privati gitignored); interfaccia `Custodian` astratta pronta per custodi reali.
- **File target:** `proxy/crypto/shamir.py`, `proxy/crypto/keymgmt.py`, `proxy/db.py` (`custodians`,`key_shards`,`key_meta`), `dashboard/` (custodian-panel).
- **Riuso ledgereye:** `ledgereye/backend/services/shamir.py` — **Alta riusabilità** (GF(256), g=3 corretto, RSA-4096 OAEP wrapping, `escrow_key`/`recover_key`). Test: `ledgereye/backend/tests/test_shamir.py` (42 test) da portare.
- **Dipendenze nuove:** `cryptography`.
- **Acceptance E2E:** `e2e_shamir.py` — split master in 5, ricostruzione con 3 OK, con 2 fallisce, share manomesso rilevato; reassemble è un evento auditato.
- **Rollback:** se off, master key da `.env` (come oggi) — ma è l'anti-pattern che Shamir risolve.
- **Stima onesta:** **14–22 h**.

### 5.5 AES-GCM (P1)
- **Cosa fa:** cifra a riposo i campi sensibili dell'audit (`justification`, `case_id`, `actor`, query payload) con chiave per-record wrappata dalla master key; crypto-erasure (distruggi chiave per-record → GDPR Art.17).
- **File target:** `proxy/crypto/encryption.py`, hook in `proxy/proxy.py` (`log_event`) e `proxy/identity.py`, `proxy/db.py` (`record_keys`), endpoint `/gdpr/erase`.
- **Riuso ledgereye:** `ledgereye/backend/services/encryption.py` — **riusabilità Media** (logica AES-256-GCM ottima, ma il keystore assume PostgreSQL → riscrivere per SQLite). Test: `test_crypto_erasure.py` (18 test).
- **Dipendenze nuove:** `cryptography` (già da Shamir).
- **Acceptance E2E:** `e2e_encryption.py` — campo cifrato non leggibile in chiaro nel DB, decifrabile con master key, erasure rende irrecuperabile, hash chain resta valida (si cifra il payload, l'hash è sul canonico).
- **⚠️ Attenzione:** definire se l'hash chain copre il plaintext o il ciphertext — **deve coprire il canonico stabile** per non rompere `verify_chain`. Decisione da fissare in `SECURITY_MODEL.md`.
- **Stima onesta:** **14–20 h**.

### 5.6 Timestamp eIDAS (P2)
- **Cosa fa:** `timestamp/base.py` (astratto) + `local_provider.py` (attivo, firma locale per dev/demo) + `qtsp_provider.py` (stub configurabile per Aruba/InfoCert/Namirial). Timestampa il merkle root di ogni batch.
- **File target:** `proxy/timestamp/`, hook in `proxy/anchor.py`, `proxy/db.py` (`qtsp_timestamps`).
- **Riuso ledgereye:** `ledgereye/backend/services/qtsp_aruba.py` — **riusabilità Media** (usare il path `rfc3161ng`; il path ASN.1 grezzo ha un bug su `MessageImprint`). Test: `test_qtsp_aruba.py` (19 test).
- **Dipendenze nuove:** `rfc3161ng`, `asn1crypto` (solo per il provider QTSP; il locale non ne ha bisogno).
- **Acceptance E2E:** `e2e_timestamp.py` — provider locale produce token verificabile; switch a QTSP via config non rompe (stub risponde con mock dichiarato); verify endpoint OK.
- **Stima onesta:** **12–18 h**.

### 5.7 Anchor Polygon Mainnet REALE (P2) — ⚠️ irreversibile + costa
- **Cosa fa:** switch `MOCK_ANCHOR=false` + rete mainnet; ancora i merkle root reali sul contratto mainnet.
- **File target:** `proxy/anchor.py`, `proxy/config.py` (network), `scripts/deploy_anchor.py`.
- **Riuso ledgereye:** `mvp/polygon_anchor.py` (logica retry/nonce/gas solida) come riferimento; il plugin ha già `anchor.py`.
- **Dipendenze nuove:** nessuna (`web3` già presente).
- **⚠️ PRE-FLIGHT OBBLIGATORIO (prima di qualsiasi tx reale):** verificare on-chain che il wallet `0x1Ec495d01e91a1929C651680cd7E5758dBF412C2` sia davvero **su mainnet**, il saldo (dichiarato 29.95 POL), e che le "17 ancore già fatte" e il contratto target esistano e combacino con l'ABI. **Non do per scontato nulla di questo** finché non lo leggo dalla chain. Tx mainnet = soldi reali e immutabili.
- **Acceptance E2E:** `e2e_anchor.py` — mock di default; un *dry-run* mainnet (stima gas, nessun invio) passa; invio reale **solo dietro flag esplicito + conferma**.
- **Rollback:** una tx mainnet non si annulla; il "rollback" è restare in mock finché tutto il resto è verde.
- **Stima onesta:** **10–16 h** (+ costo POL reale).

### 5.8 Audit dashboard (P2)
- **Cosa fa:** filtri (utente/team/data/rischio/evento), coda approvazioni (supervisore), pannello custodi (Shamir), PDF firmato con timestamp+anchor hash.
- **File target:** `dashboard/app.js`, `dashboard.html`, `style.css`, `proxy/dashboard.py` (query filtrate), `proxy/pdf_export.py`.
- **Riuso ledgereye:** UI d3/React di `ledgereye/frontend` come riferimento visivo (non portabile direttamente: l'SDK è vanilla JS).
- **Dipendenze nuove:** nessuna.
- **Acceptance E2E:** filtri restituiscono subset corretti; PDF contiene timestamp+anchor+QR verificabili.
- **Stima onesta:** **16–24 h**.

### 5.9 Docs + Test (P3, continuo)
- **Cosa fa:** `ARCHITECTURE.md`, `SECURITY_MODEL.md` (threat model + garanzie), `INTEGRATION_GUIDE.md` (come applicare a un altro backend), update `DEMO_SCRIPT.md` (scenari nuovi), riscrittura `README.md`. Test E2E per ogni componente → target 50+.
- **Stima onesta:** **20–30 h** (da spalmare, non a fine progetto).

---

## 6. Ordine di implementazione (meno → più rischioso)

1. **Architettura universale** (P0) — refactor a freddo, abilita tutto, basso rischio.
2. **Login multi-utente** (P0) — prerequisito, contenuto.
3. **Workflow approvazione** (P1) — ⚠️ il più nuovo; farlo presto per scoprire subito eventuali esplosioni di stima.
4. **Shamir** (P1) — codice pronto, puro, niente rete.
5. **AES-GCM** (P1) — self-contained, rework keystore SQLite.
6. **eIDAS adapter** (P2) — provider locale; QTSP stub.
7. **Anchor Polygon mainnet reale** (P2) — ⚠️ ultimo dei "rischiosi": irreversibile, soldi reali, dopo pre-flight on-chain.
8. **Dashboard polish** (P2).
9. **Test E2E completi + docs** (P3) — consolidamento.

> Razionale: il workflow (3) è prima di Shamir/AES nonostante il rischio, perché se la stima esplode voglio saperlo a settimana 3, non a settimana 8. Mainnet (7) è penultimo perché è l'unica cosa davvero irreversibile.

---

## 7. Roadmap 10 settimane (→ 1 agosto)

| Sett. | Date (2026) | Milestone | Verifica |
|------|-------------|-----------|----------|
| 1 | 26 mag–1 giu | Architettura universale + config YAML + adapter HTTP | demo identica, 2° config fittizio funziona |
| 2 | 2–8 giu | Login multi-utente + ruoli | 3 ruoli loggano, sessione per-utente |
| 3 | 9–15 giu | Workflow approvazione (modello pre-auth) | analyst→supervisor→query passa |
| 4 | 16–22 giu | Shamir 3-of-5 + pannello custodi (5 locali) | reassemble 3/5 OK, 2/5 fallisce |
| 5 | 23–29 giu | AES-GCM + crypto-erasure | campo cifrato a riposo, erasure GDPR |
| 6 | 30 giu–6 lug | eIDAS adapter (locale) + QTSP stub config | timestamp locale verificabile |
| 7 | 7–13 lug | Pre-flight mainnet + anchor reale (dry-run→reale) | tx mainnet verificata on-chain |
| 8 | 14–20 lug | Dashboard: filtri + coda + custodi + PDF | tutte le viste funzionanti |
| 9 | 21–27 lug | Scenari demo E2E + test → 50+ | scenario completo cifrato/shardato/firmato/ancorato |
| 10 | 28 lug–1 ago | Docs finali + freeze + submission NGI | tutto verde, pacchetto NGI pronto |

**Buffer:** zero settimane di buffer esplicite → **è un piano teso.** Se il workflow (sett. 3) o il mainnet (sett. 7) slittano, la valvola di sfogo è: GraphQL/gRPC restano stub (già previsto), QTSP resta solo-locale (già previsto), dashboard polish ridotto.

---

## 8. Rischi tecnici + mitigazione

| # | Rischio | Gravità | Mitigazione |
|---|---------|---------|-------------|
| R1 | **Workflow su event-loop / connessioni appese** — gating di una query live su approvazione umana è fragile | **Alta** | Modello **pre-autorizzazione** (no hold connessione); decisione da validare prima di scrivere codice (sett. 3) |
| R2 | **Refactor universale rompe la demo** funzionante | Alta | feat branch + smoke 29/29 a ogni commit + `main` intoccato |
| R3 | **Polygon mainnet: assunzioni non verificate** (rete/saldo/contratto/17 ancore) + irreversibilità + costo | Alta | Pre-flight on-chain obbligatorio; mock default; reale solo dietro flag+conferma; dry-run prima |
| R4 | **Crypto sull'event-loop** → ristallo come il bug già visto (SQLite bloccante) | Media-Alta | Tutto crypto/rete in `asyncio.to_thread`/worker (lezione già appresa in questa codebase) |
| R5 | **AES vs hash chain**: cifrare i campi può rompere `verify_chain` | Media | L'hash copre il canonico stabile, non il plaintext; fissato in SECURITY_MODEL.md |
| R6 | **Riusabilità ledgereye inferiore all'atteso**: encryption keystore è Postgres-bound, qtsp ha un path bacato | Media | Shamir port diretto; AES = rework keystore SQLite (messo in stima); QTSP = solo path rfc3161ng |
| R7 | **Gerarchia chiavi confusa** (master key + escrow + wrap) → lock-out | Media | `keymgmt.py` centralizza; documentare in SECURITY_MODEL.md; test di recovery |
| R8 | **Stima totale tesa (145–220 h in 10 sett.)** = 15–22 h/settimana costanti | Media | Ordine che scopre presto le esplosioni; scope tagliabile (stub adapter, QTSP locale) |

---

## 9. Stima totale (onesta)

| Componente | Ore (min–max) |
|-----------|---------------|
| 1. Architettura universale | 12–18 |
| 2. Login multi-utente | 16–24 |
| 3. Workflow approvazione | 20–30 *(può esplodere a 40)* |
| 4. Shamir | 14–22 |
| 5. AES-GCM | 14–20 |
| 6. eIDAS adapter | 12–18 |
| 7. Anchor mainnet reale | 10–16 |
| 8. Dashboard polish | 16–24 |
| 9. Docs + test E2E | 20–30 |
| **TOTALE** | **134–202 h** |

Coerente con la stima di Manuel (145–220 h). **In 10 settimane = ~15–20 h/settimana costanti.** Fattibile, ma **senza buffer**: il rischio non è la crittografia (è pronta), è il **workflow di approvazione** e il **mainnet reale**. Se uno dei due esplode, si taglia scope (adapter non-HTTP restano stub, QTSP resta locale) — quelle riduzioni sono già messe in conto e non intaccano il messaggio NGI.

**Onestà finale:** i due punti dove più probabilmente sbaglio la stima per difetto sono **5.3 (workflow)** e **5.7 (mainnet pre-flight + sorprese on-chain)**. Tutto il resto lo considero stimabile con buona confidenza.

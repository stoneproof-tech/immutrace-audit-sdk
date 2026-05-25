# IMMUTRACE — Vision

**Stato:** 2026-05-25, ore 14:00 — Fase 1 (pianificazione). Demo `:3001` funzionante, branch `feat/full-integration` aperto.
**Deadline strategica:** 1 agosto 2026 — NGI Zero Commons Fund, round 14.

---

## 1. Visione strategica

IMMUTRACE è un **framework universale di audit crittografico**, **agnostico al backend**, che si applica come **audit layer** davanti a qualsiasi sistema OSINT / AI / decisionale. Non è un prodotto monolitico né un concorrente di quei sistemi: è il **livello di accountability** che oggi manca.

**OSIRIS** è il **primo reference demo case** — non l'unico target. Il codice del *core* deve restare riusabile su altri sistemi (Maltego, SpiderFoot, n8n, generici backend HTTP/API). Tutto ciò che è specifico di OSIRIS vive in `/demos/osiris/`, mai nel core.

**Tre pilastri architetturali:**
1. **Config-driven** — il cliente dichiara i propri endpoint sensibili in un file (`sensitive_endpoints.yaml`), senza toccare il codice.
2. **SDK frontend pluggable** — una libreria JS standalone, riusabile, non OSIRIS-specifica.
3. **Adapter pattern** — il backend osservato è dietro un'interfaccia astratta (HTTP ora; GraphQL/gRPC come stub estendibili). Allo stesso modo: provider di timestamp astratto (locale ora, QTSP poi) e custodi astratti (5 keypair locali ora, custodi reali poi).

**Tagline NGI Zero:**
> "Universal cryptographic audit layer for OSINT/AI systems — demonstrated on OSIRIS."

---

## 2. I 9 componenti (con priorità)

| # | Componente | Priorità | Note |
|---|-----------|----------|------|
| 1 | **Architettura universale** (config YAML, adapter pattern, SDK standalone, de-OSIRIS-izzazione del core) | **P0 — prima di tutto** | Abilita tutto il resto; refactor a freddo, basso rischio |
| 2 | **Identity & Authorization** (login multi-utente, ruoli, password hashing argon2/bcrypt) | **P0** | Prerequisito del workflow |
| 3 | **Workflow approvazione query** (analista→supervisore→esecuzione, coda pending) | **P1** | Il pezzo più nuovo e architetturalmente delicato |
| 4 | **Shamir 3-of-5** (master key, pannello custodi, 5 keypair locali) | **P1** | Codice già pronto in ledgereye, portabile |
| 5 | **AES-GCM** (cifratura query/payload sensibili + crypto-erasure GDPR) | **P1** | Pronto in ledgereye, da adattare a SQLite |
| 6 | **Timestamp eIDAS** (adapter: provider locale attivo + QTSP stub configurabile) | **P2** | Solo locale ora; QTSP reale = cambio di config |
| 7 | **Blockchain anchor Polygon Mainnet REALE** | **P2** | Riusa wallet `0x1Ec4…412C2`; **irreversibile, costa POL reali — da verificare on-chain prima** |
| 8 | **Audit dashboard** (filtri utente/team/data/rischio/evento, coda approvazioni, pannello custodi, PDF firmato) | **P2** | Estende la dashboard esistente |
| 9 | **Docs + Test** (INTEGRATION_GUIDE, ARCHITECTURE, SECURITY_MODEL, DEMO_SCRIPT, README; 50+ test) | **P3 — continuo** | Da fare in parallelo, non alla fine |

---

## 3. Decisione di principio: prima il codice, poi i contratti esterni

**Prima costruiamo il codice perfetto e completo**, con le interfacce astratte pronte per i fornitori esterni. **Solo dopo** (quando Manuel firma i contratti) si **attivano** QTSP reale e custodi reali — e questo deve essere **solo un cambio di configurazione**, non una riscrittura.

Concretamente:
- **Crypto interna** (hash chain, AES-GCM, Shamir) = **VERA da subito**, nessun mock.
- **Dipendenze esterne** (QTSP qualificato, custodi notaio/avvocato/revisore) = **interfaccia astratta vera + implementazione locale/simulata ora**; l'implementazione reale è uno stub configurabile che si attiva via config.
- **Polygon** = mock in dev, **reale in produzione** via config switch.

Questo è onesto verso NGI Zero (nessun mock spacciato per reale: ciò che è simulato è dichiarato tale e l'architettura per il reale è pronta e dimostrabile).

---

## 4. Stato attuale (2026-05-25 14:00)

**Già funzionante (demo `:3001`, taggata `v0.1-demo-working`):**
- Reverse proxy trasparente davanti a OSIRIS + WebSocket bridge (HMR)
- Hash chain SHA-256 per richiesta su SQLite (scrittura concorrente-safe)
- Auth gate a sessione singola (modal con justification) su endpoint sensibili
- Anchor worker Polygon Amoy (MOCK default)
- Dashboard audit + verifica catena + export PDF firmato
- Smoke test 29/29

**Da costruire:** tutto il resto dei 9 componenti.

**Riusabilità del codice esistente (onesta, da `decision-flow-ledger/ledgereye/`):**
- Shamir → **Alta** (modulo pulito, autoportante)
- AES-GCM → **Media** (keystore assume PostgreSQL, da riscrivere per SQLite)
- QTSP → **Media** (un path ASN.1 è bacato; usare il path `rfc3161ng`)

Dettagli completi e piano operativo: vedi `INTEGRATION_PLAN.md`. Inventario sorgenti: `FULL_INVENTORY.md`.

# Demo: OSIRIS (reference)

OSIRIS (Next.js OSINT/map dashboard) is IMMUTRACE's **first reference demo case**,
not part of the core. Everything OSIRIS-specific lives under `demos/osiris/`.

## Run the demo
1. `cd C:/Users/39338/osiris-analysis && npm run dev`   → OSIRIS on :3000
2. `cd C:/Users/39338/immutrace-audit-sdk && python -m proxy.app`   → IMMUTRACE on :3001
3. Open `http://127.0.0.1:3001` and `http://127.0.0.1:3001/_immutrace/dashboard`

The core reads `config/sensitive_endpoints.yaml`, which currently lists the OSIRIS
intelligence endpoints (flights, maritime, satellites, …). To audit a *different*
system, point `SENSITIVE_ENDPOINTS_CONFIG` at another YAML (see
`demos/generic/sensitive_endpoints.example.yaml`) and set `UPSTREAM_URL`.

## Contents (now / planned)
- `custodians/`  — 5 local custodian keypairs for the Shamir demo *(added in Step 4; private parts gitignored)*
- `scenarios/`   — scripted end-to-end demo scenarios *(added in Step 9)*

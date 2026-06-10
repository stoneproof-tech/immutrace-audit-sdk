# IMMUTRACE Universal Attestation Protocol

> Certify **any decision** — not just reverse-proxy traffic — into the same
> tamper-evident hash chain, encryption-at-rest, eIDAS-ready timestamping, and
> Polygon anchoring that IMMUTRACE already provides. Verification is **public and
> key-free**.

IMMUTRACE has two complementary entry points to the same trust core:

| | Reverse proxy (*observe*) | Attestation API (*certify any decision*) |
|---|---|---|
| What it records | data-access traffic through a backend | a structured description of a decision |
| Integration | transparent, zero code changes | one HTTP call (API / Python / CLI) |
| Event type | `http_request`, `auth_denied`, … | `decision.attested` |
| Use when | you proxy a system | the thing to prove is a *decision*, not a request |

Both write **one event into the same global SHA-256 hash chain**, are encrypted
at rest with the same AES-256-GCM layer, timestamped by the same provider, and
batched into the same Polygon Merkle anchor. Nothing in the attestation path
re-implements the audit core — it reuses `proxy._chain_lock` /
`proxy._insert_event_sync`, `encryption`, `timestamp`, and `anchor`.

---

## 1. The field model

`POST /_immutrace/attest` (authenticated) accepts a JSON body:

| Field | Required | Meaning |
|-------|----------|---------|
| `action` | **yes** | What was decided/done — a stable verb-noun id, e.g. `loan.decision`, `content.moderation`, `data.access_grant`. |
| `subject` | no | Who/what the decision is about (an application id, a data subject, a case). Stored in the `case_id` column → filterable. |
| `decision` | no | The outcome: `approved` / `denied` / `flagged` / a score label. |
| `rationale` | no | Human-readable justification. Stored in `justification` → **encrypted at rest** when the master key is unlocked. |
| `inputs_digest` | no | `sha256` hex of the inputs that led to the decision. **You hash the inputs locally; the raw inputs are never sent.** |
| `actor` | no | Who/what made the decision (e.g. `credit-model-v3`, a username). Defaults to the authenticated user. |
| `metadata` | no | Arbitrary JSON object of extra context (model version, scores, policy ids). |

### How it maps onto the existing event schema

```
event_type    = "decision.attested"     # NOT a system type → it IS anchored on Polygon
method        = "ATTEST"
case_id       = subject
justification = rationale                # encrypted at rest (ENCRYPTED_FIELDS)
query         = canonical JSON {action, subject, decision, inputs_digest, metadata}   # encrypted at rest
path          = "/_immutrace/attest"
actor         = actor (or the logged-in user)
```

The chain hash commits to **all** of these fields, so altering any of them later
is detectable by anyone.

### The receipt

```json
{
  "receipt_id": "rcpt_<this_hash[:24]>",
  "event_id": 1234,
  "this_hash": "<64 hex>",
  "prev_hash": "<64 hex>",
  "ts": "2026-06-10T12:34:56.000000Z",
  "actor": "credit-model-v3",
  "event_type": "decision.attested",
  "anchored": false,
  "verify_url": "/_immutrace/attest/verify/<this_hash>",
  "note": "…"
}
```

`anchored` is `false` at creation. The background anchor worker batches the event
into a Polygon Merkle root within the configured interval; poll `verify_url` to
watch it flip to `true` (with an `anchor_tx` and `anchor_explorer` link).

### Independent verification (public, no auth)

`GET /_immutrace/attest/verify/{this_hash}` — recomputes the event hash from the
stored fields (same recipe the chain used at write time) and reports:

```json
{
  "found": true,
  "event_id": 1234,
  "ts": "…",
  "actor": "credit-model-v3",
  "event_type": "decision.attested",
  "integrity_ok": true,
  "anchored": true,
  "anchor_tx": "0x…",
  "anchor_explorer": "https://polygonscan.com/tx/0x…"
}
```

- `this_hash` must be **64 hex characters** → otherwise `400`.
- unknown hash → `404`.
- if any stored field was tampered with, `integrity_ok` becomes `false`.

No account and no key are needed: a third party can validate a receipt against a
running proxy (and, once anchored, against Polygon directly).

---

## 2. Three ways to use it

### A) Raw HTTP

```bash
# 1. login (capture the session cookie)
curl -s -c jar.txt -X POST http://127.0.0.1:3001/_immutrace/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"analyst","password":"demo1234"}'

# 2. certify a decision
curl -s -b jar.txt -X POST http://127.0.0.1:3001/_immutrace/attest \
  -H 'Content-Type: application/json' \
  -d '{
        "action":"loan.decision",
        "subject":"application-42",
        "decision":"denied",
        "rationale":"DTI ratio above policy threshold",
        "inputs_digest":"<sha256-of-inputs>",
        "actor":"credit-model-v3",
        "metadata":{"model":"credit-v3","score":0.31}
      }'

# 3. verify (no auth needed)
curl -s http://127.0.0.1:3001/_immutrace/attest/verify/<this_hash>
```

### B) Python client (zero dependencies, stdlib only)

```python
from immutrace_client import ImmutraceClient

c = ImmutraceClient("http://127.0.0.1:3001", "analyst", "demo1234")
c.login()

receipt = c.attest(
    action="loan.decision",
    subject="application-42",
    decision="denied",
    rationale="DTI ratio above policy threshold",
    inputs=open("model_input_bundle.json", "rb").read(),  # hashed LOCALLY → inputs_digest
    actor="credit-model-v3",
    metadata={"model": "credit-v3", "score": 0.31},
)
print(receipt["this_hash"])

print(c.verify(receipt["this_hash"]))   # independent, key-free
```

> The raw inputs you pass as `inputs=` are hashed with `sha256` **on your machine**;
> only the digest leaves the process.

### C) CLI

```bash
python -m immutrace_client attest \
  --url http://127.0.0.1:3001 --user analyst --password demo1234 \
  --action loan.decision --subject application-42 --decision denied \
  --rationale "DTI above threshold" --actor credit-model-v3 \
  --inputs-file ./model_input_bundle.json \
  --metadata '{"model":"credit-v3","score":0.31}'

python -m immutrace_client verify --url http://127.0.0.1:3001 <this_hash>
```

---

## 3. What to certify (regulatory examples)

### AI decisions — EU AI Act, Art. 12 (record-keeping / logging)

High-risk AI systems must keep automatic logs of their operation. Attest each
inference that has legal or significant effects:

```json
{
  "action": "ai.inference",
  "subject": "candidate-7781",
  "decision": "rejected",
  "rationale": "score 0.42 < hiring threshold 0.6",
  "inputs_digest": "<sha256 of the feature vector / prompt>",
  "actor": "hiring-model-2026.02",
  "metadata": {"model_version": "2026.02", "threshold": 0.6, "score": 0.42, "human_review": false}
}
```

The `inputs_digest` proves *which* inputs produced the output without storing the
(possibly personal) inputs themselves — and `rationale` is encrypted at rest, so
GDPR erasure still works.

### Credit decisions

```json
{
  "action": "credit.decision",
  "subject": "application-42",
  "decision": "denied",
  "rationale": "Debt-to-income ratio above policy threshold",
  "metadata": {"policy": "consumer-2026", "dti": 0.51, "adverse_action_code": "07"}
}
```

A tamper-evident, independently verifiable record of *why* credit was denied —
useful for adverse-action notices and dispute resolution.

### GDPR — lawful basis & data-subject decisions

```json
{
  "action": "gdpr.lawful_basis",
  "subject": "data-subject-9921",
  "decision": "consent",
  "rationale": "Explicit opt-in captured at signup form v3",
  "metadata": {"basis": "Art.6(1)(a)", "purpose": "marketing", "form_version": "v3"}
}
```

Also fits erasure decisions, access-request fulfilment, and DPIA conclusions —
each becomes a verifiable, time-stamped, anchored record.

### Governance / approvals

```json
{
  "action": "governance.vote",
  "subject": "proposal-2026-014",
  "decision": "approved",
  "rationale": "Quorum reached; 7 of 9 in favour",
  "metadata": {"quorum": 9, "in_favour": 7, "against": 2}
}
```

Board resolutions, change-management approvals, and policy sign-offs gain a
neutral, third-party-verifiable proof of what was decided and when.

---

## 4. Trust properties

- **Tamper-evidence** — the decision is hashed into the global chain; any later
  edit to any stored field is detectable by recomputation (`integrity_ok=false`).
- **Independent verification** — `verify` needs no account and no key; once
  anchored, the Merkle root is on Polygon under a public wallet.
- **Privacy-preserving** — raw inputs never leave the caller (only `inputs_digest`);
  `rationale`/`query` are encrypted at rest and subject to GDPR crypto-erasure.
- **Same anchor, same wallet** — attestations are ordinary chain events
  (`decision.attested` is deliberately *not* in `anchor.SYSTEM_EVENT_TYPES`), so
  they ride the same Polygon anchoring as proxy traffic.

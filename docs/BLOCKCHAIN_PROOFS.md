# IMMUTRACE — Blockchain Proofs (Polygon mainnet)

All anchors are **0-value self-transfers** from the anchor wallet whose **input
data** carries the audit commitment, in the format:

```
immutrace-ledgereye-audit:<sha256_hex_merkle_root>
```

Anyone can independently verify these: open a transaction on Polygonscan, read
the **Input Data** field, and decode it from hex to UTF-8.

## Anchor wallet

**`0x1Ec495d01e91a1929C651680cd7E5758dBF412C2`**
Full history (all anchor transactions): https://polygonscan.com/address/0x1Ec495d01e91a1929C651680cd7E5758dBF412C2

- **Total outgoing anchor transactions: 29** (account nonce = 29 at the time of writing).
- **17** pre-date the IMMUTRACE integration (historical anchors proving the wallet + pattern).
- **12** were produced during IMMUTRACE integration testing (the test transaction below + worker batches). A few of these were batches from a **self-anchoring loop that has since been fixed** (system event types are now excluded from batches — see `SECURITY_MODEL.md` and `e2e_anchor_loop_prevention`); they are valid anchors, simply more frequent than intended.

## Verified transactions (selection)

| tx_hash | block | gas | events |
|---------|-------|-----|--------|
| [`0x6ce8629c…b23d664e`](https://polygonscan.com/tx/0x6ce8629c4a3f2da6e40ef7485e312e0df7ec7ee3deeef2529903204fb23d664e) | 87427721 | 24600 | test anchor (Step 7.4, manually verified) |
| [`0x5e533e9f…87c15f67`](https://polygonscan.com/tx/0x5e533e9f4faf033ed2acb05c8ee080eef86888b654405aae2612900587c15f67) | 87428391 | 24600 | 1 (first unattended worker batch) |
| [`0xb04316b1…bacf2dae`](https://polygonscan.com/tx/0xb04316b15255080a61b2ec84e606dfe8ae866c24692b214e8ad9525fbacf2dae) | 87429826 | 24600 | 5 |
| [`0xee1740f1…8451e24e`](https://polygonscan.com/tx/0xee1740f1d9c7080314d16b26788a431cf165c9f9caf7457b252ea38b8451e24e) | 87429838 | 24600 | 1 |
| [`0xa90ba6bb…269cf1b4`](https://polygonscan.com/tx/0xa90ba6bb630abe0126489a2c2bce0bac536227c514cb16eb04ccdac7269cf1b4) | 87429923 | 24600 | 6 |
| [`0xc2d21f01…0eb9be37`](https://polygonscan.com/tx/0xc2d21f01e029b6e18ac80eaacdec1b758a5eefbc69f52a1c12e415510eb9be37) | 87429955 | 24600 | 1 |
| [`0xad4c4fee…6714c013`](https://polygonscan.com/tx/0xad4c4fee4bba1202758a2892807c9ecce3eda4c3e51f81adeebfa9096714c013) | 87430027 | 24600 | 1 |
| [`0xa4a6cb42…ad18399e`](https://polygonscan.com/tx/0xa4a6cb426ef976f265651047bbad57b76342ae5c73926fe240e52575ad18399e) | 87430095 | 24600 | 1 |
| [`0x995a2de5…0a477d8b`](https://polygonscan.com/tx/0x995a2de58fbe43d002b71a8ee7224f31284e61402405c2081ea7c1680a477d8b) | 87430175 | 24600 | 1 |
| [`0xf089b2bd…99a65e125`](https://polygonscan.com/tx/0xf089b2bd5d3748b0d3c8c7c19cb4e66f7f45f324311599f381f2fb799a65e125) | 87430320 | 24600 | 6 |

## Economics

- Gas per anchor: ~24,600 · cost ~**0.007 POL (~$0.0006)** per batch, regardless of how many events are in the batch (one merkle root per batch).
- Batching means cost is independent of audit volume.

## How to verify an anchor yourself

1. Open the transaction on Polygonscan.
2. Confirm **From = To = `0x1Ec4…412C2`** and **Status: Success**.
3. Read **Input Data**, switch to UTF-8 → it reads `immutrace-ledgereye-audit:<root>`.
4. `<root>` is the SHA-256 Merkle root of that batch's event hashes; recompute it from the audit `events` of that anchor (`anchors.merkle_root`) to confirm the on-chain commitment matches the local chain.

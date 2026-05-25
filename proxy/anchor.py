"""Anchor worker: mock (default), Polygon mainnet (CALLDATA), or Amoy (legacy)."""
import asyncio
import hashlib
import json
import sqlite3
import time
import urllib.request
from datetime import datetime, timezone
from typing import Optional, Tuple
from pathlib import Path
from . import config
from .chain import merkle_root


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# ════════════════════════════════════════════════════════════════════════════
# MAINNET ANCHORING: code ready, requires ANCHOR_PRIVATE_KEY for wallet
# 0x1Ec495d01e91a1929C651680cd7E5758dBF412C2. Currently in MOCK mode.
# Activation: set MOCK_ANCHOR=false in .env once the key is configured.
# 17 historical anchors already on mainnet prove the pattern works.
# (submit_anchor_mainnet refuses to sign unless the key controls that wallet.)
# ════════════════════════════════════════════════════════════════════════════
# ── Polygon MAINNET, CALLDATA pattern (Step 7) ──────────────────────────────
# Continuity with the 17 historical anchors: a 0-value self-transfer whose input
# data is "immutrace-ledgereye-audit:<sha256_hex_root>".
PAYLOAD_PREFIX = "immutrace-ledgereye-audit:"
# Keyless public mainnet RPCs (best-effort). For production, set POLYGON_RPC to a
# dedicated endpoint (Alchemy/Infura/QuickNode) — public RPCs rate-limit/403.
_MAINNET_FALLBACK_RPCS = [
    "https://1rpc.io/matic",
    "https://polygon.drpc.org",
    "https://polygon.blockpi.network/v1/rpc/public",
    "https://endpoints.omniatech.io/v1/matic/mainnet/public",
    "https://polygon.gateway.tenderly.co",
    "https://polygon-bor-rpc.publicnode.com",
    "https://rpc.polygon.fraxfinance.com",
]


def build_anchor_payload(root_hex: str) -> str:
    """The exact input-data string anchored on-chain (matches the 17 prior tx)."""
    return PAYLOAD_PREFIX + root_hex


def _payload_hex(root_hex: str) -> str:
    return "0x" + build_anchor_payload(root_hex).encode("utf-8").hex()


def _rpc_urls() -> list[str]:
    urls = []
    if config.POLYGON_RPC:
        urls.append(config.POLYGON_RPC)
    urls.extend(_MAINNET_FALLBACK_RPCS)
    return urls


def _rpc_call(url: str, method: str, params: list):
    """Single JSON-RPC call to one endpoint."""
    req = urllib.request.Request(
        url,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "immutrace-anchor/1.0"})
    with urllib.request.urlopen(req, timeout=20) as r:
        j = json.load(r)
    if "error" in j:
        raise RuntimeError(j["error"])
    return j["result"]


def _rpc(method: str, params: list):
    """JSON-RPC over the mainnet RPC(s) with fallback + one retry pass
    (public RPCs rate-limit, so a brief retry over the full list usually clears)."""
    last = None
    for attempt in range(2):
        for url in _rpc_urls():
            try:
                return _rpc_call(url, method, params)
            except Exception as e:
                last = e
                continue
        time.sleep(1.5)  # brief backoff before the second pass
    raise RuntimeError(f"all Polygon RPCs failed for {method}: {last}")


def _nonce_consensus() -> int:
    """Return the MAX pending nonce across all reachable RPCs. Defends against
    flaky nodes returning a stale/zero nonce — signing with a too-low nonce would
    replace/fail a tx. Requires at least one successful read."""
    addr = config.ANCHOR_WALLET_ADDRESS
    vals = []
    for url in _rpc_urls():
        try:
            vals.append(int(_rpc_call(url, "eth_getTransactionCount", [addr, "pending"]), 16))
        except Exception:
            continue
    if not vals:
        raise RuntimeError("no RPC returned a nonce")
    return max(vals)


def verify_mainnet_state() -> dict:
    """Read-only pre-flight: chain id, wallet balance, pending nonce."""
    addr = config.ANCHOR_WALLET_ADDRESS
    cid = int(_rpc("eth_chainId", []), 16)
    bal = int(_rpc("eth_getBalance", [addr, "latest"]), 16)
    nonce = _nonce_consensus()   # max across RPCs — robust to flaky/zero nodes
    return {"chain_id": cid, "wallet": addr, "balance_pol": bal / 1e18,
            "balance_wei": bal, "nonce": nonce, "chain_ok": cid == config.POLYGON_CHAIN_ID}


def estimate_anchor(root_hex: str) -> dict:
    """DRY-RUN: build payload, estimate gas + price + cost. Sends NOTHING."""
    addr = config.ANCHOR_WALLET_ADDRESS
    payload = build_anchor_payload(root_hex)
    data_hex = _payload_hex(root_hex)
    gas = int(_rpc("eth_estimateGas",
                   [{"from": addr, "to": addr, "value": "0x0", "data": data_hex}]), 16)
    gas_price = int(_rpc("eth_gasPrice", []), 16)
    nonce = int(_rpc("eth_getTransactionCount", [addr, "pending"]), 16)
    cost_wei = gas * gas_price
    return {"payload": payload, "data_hex": data_hex, "gas": gas,
            "gas_price_gwei": gas_price / 1e9, "cost_pol": cost_wei / 1e18,
            "nonce": nonce}


def submit_anchor_mainnet(root_hex: str) -> dict:
    """Sign + send ONE real mainnet anchor tx, wait for the receipt. Sends REAL POL.

    Refuses to send unless the configured private key actually controls
    ANCHOR_WALLET_ADDRESS (so we never sign from the wrong wallet)."""
    from eth_account import Account
    acct = Account.from_key(config.ANCHOR_PRIVATE_KEY)
    if acct.address.lower() != config.ANCHOR_WALLET_ADDRESS.lower():
        raise RuntimeError(
            f"refusing to send: ANCHOR_PRIVATE_KEY controls {acct.address}, "
            f"not the anchor wallet {config.ANCHOR_WALLET_ADDRESS}")
    state = verify_mainnet_state()
    if not state["chain_ok"]:
        raise RuntimeError(f"chain id {state['chain_id']} != {config.POLYGON_CHAIN_ID}")
    gas_price = int(_rpc("eth_gasPrice", []), 16)
    data_hex = _payload_hex(root_hex)
    gas = int(_rpc("eth_estimateGas",
                   [{"from": acct.address, "to": acct.address, "value": "0x0", "data": data_hex}]), 16)
    tx = {"nonce": state["nonce"], "to": acct.address, "value": 0,
          "data": data_hex, "gas": int(gas * 1.25), "gasPrice": gas_price,
          "chainId": config.POLYGON_CHAIN_ID}
    signed = acct.sign_transaction(tx)
    raw = signed.raw_transaction if hasattr(signed, "raw_transaction") else signed.rawTransaction
    tx_hash = _rpc("eth_sendRawTransaction", ["0x" + raw.hex()])
    # poll for the receipt
    receipt = None
    for _ in range(60):
        receipt = _rpc("eth_getTransactionReceipt", [tx_hash])
        if receipt:
            break
        time.sleep(3)
    if not receipt:
        return {"tx_hash": tx_hash, "block_number": None, "gas_used": None, "status": "pending"}
    return {"tx_hash": tx_hash,
            "block_number": int(receipt["blockNumber"], 16),
            "gas_used": int(receipt["gasUsed"], 16),
            "status": "confirmed" if receipt.get("status") == "0x1" else "failed"}


# Minimal ABI for the IMMUTRACEAnchor contract (anchor + Anchored event)
ANCHOR_ABI = [
    {
        "inputs": [{"internalType": "bytes32", "name": "root", "type": "bytes32"}],
        "name": "anchor",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "bytes32", "name": "root", "type": "bytes32"}],
        "name": "verify",
        "outputs": [
            {"internalType": "uint256", "name": "timestamp", "type": "uint256"},
            {"internalType": "address", "name": "submitter", "type": "address"},
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "bytes32", "name": "root", "type": "bytes32"},
            {"indexed": False, "internalType": "uint256", "name": "timestamp", "type": "uint256"},
            {"indexed": True, "internalType": "address", "name": "submitter", "type": "address"},
        ],
        "name": "Anchored",
        "type": "event",
    },
]


def get_pending_events() -> list[dict]:
    """Fetch events with anchor_id IS NULL, ordered by id."""
    conn = sqlite3.connect(str(config.DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.execute(
            "SELECT id, this_hash FROM events WHERE anchor_id IS NULL ORDER BY id ASC"
        )
        return [{"id": r["id"], "hash": r["this_hash"]} for r in cur.fetchall()]
    finally:
        conn.close()


def submit_anchor(root_hex: str) -> Tuple[str, Optional[int]]:
    """Submit anchor on-chain. Returns (tx_hash, block_number).

    In mock mode, generates a deterministic fake tx_hash.
    """
    if config.MOCK_ANCHOR or not config.ANCHOR_PRIVATE_KEY or not config.ANCHOR_CONTRACT:
        fake_tx = "0x" + hashlib.sha256(f"mock:{root_hex}:{time.time()}".encode()).hexdigest()
        # Mock block number: rough simulation
        fake_block = int(time.time()) % 100_000_000
        return fake_tx, fake_block

    # Real Polygon Amoy submission
    from web3 import Web3
    from eth_account import Account

    w3 = Web3(Web3.HTTPProvider(config.AMOY_RPC, request_kwargs={"timeout": 30}))
    if not w3.is_connected():
        raise RuntimeError(f"Cannot reach Amoy RPC: {config.AMOY_RPC}")

    acct = Account.from_key(config.ANCHOR_PRIVATE_KEY)
    contract = w3.eth.contract(
        address=Web3.to_checksum_address(config.ANCHOR_CONTRACT),
        abi=ANCHOR_ABI,
    )

    root_bytes = bytes.fromhex(root_hex)
    nonce = w3.eth.get_transaction_count(acct.address)
    tx = contract.functions.anchor(root_bytes).build_transaction({
        "from": acct.address,
        "nonce": nonce,
        "chainId": config.AMOY_CHAIN_ID,
        "gas": 100_000,
        "maxFeePerGas": w3.to_wei("50", "gwei"),
        "maxPriorityFeePerGas": w3.to_wei("30", "gwei"),
    })
    signed = acct.sign_transaction(tx)
    raw = signed.raw_transaction if hasattr(signed, "raw_transaction") else signed.rawTransaction
    tx_hash = w3.eth.send_raw_transaction(raw)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    return tx_hash.hex(), receipt.blockNumber


def anchor_batch() -> Optional[dict]:
    """Anchor all pending events into one Merkle root, persist the anchor row,
    and back-link events to it. Returns the anchor record dict, or None if no pending."""
    pending = get_pending_events()
    if not pending:
        return None

    hashes = [e["hash"] for e in pending]
    root = merkle_root(hashes)

    if config.MOCK_ANCHOR:
        chain = "mock"
        tx_hash, block_number = submit_anchor(root)
        gas_used, chain_id, status, confirmed = None, None, "mock", 1
    else:
        chain = "polygon-mainnet"
        res = submit_anchor_mainnet(root)   # sends a REAL tx
        tx_hash = res["tx_hash"]
        block_number = res["block_number"]
        gas_used = res["gas_used"]
        chain_id = config.POLYGON_CHAIN_ID
        status = res["status"]
        confirmed = 1 if status == "confirmed" else 0

    conn = sqlite3.connect(str(config.DB_PATH))
    try:
        cur = conn.execute(
            "INSERT INTO anchors (merkle_root, event_count, first_event_id, "
            "last_event_id, submitted_at, chain, tx_hash, block_number, confirmed, "
            "gas_used, chain_id, status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (root, len(hashes), pending[0]["id"], pending[-1]["id"],
             utcnow_iso(), chain, tx_hash, block_number, confirmed,
             gas_used, chain_id, status),
        )
        anchor_id = cur.lastrowid
        ids = [e["id"] for e in pending]
        # Back-link events
        conn.executemany(
            "UPDATE events SET anchor_id = ? WHERE id = ?",
            [(anchor_id, eid) for eid in ids],
        )
        conn.commit()
    finally:
        conn.close()

    return {
        "anchor_id": anchor_id,
        "merkle_root": root,
        "event_count": len(hashes),
        "tx_hash": tx_hash,
        "block_number": block_number,
        "chain": chain,
        "gas_used": gas_used,
        "status": status,
    }


async def log_anchor_event(rec: dict) -> None:
    """Record a successful anchor as an auditable 'anchor_posted' chain event."""
    try:
        from . import proxy as proxy_mod  # lazy: avoid circular import
        sess = {"session_id": "system", "actor": "immutrace", "case_id": "",
                "activity_type": "ANCHOR",
                "justification": f"{rec['chain']} anchor of {rec['event_count']} events "
                                 f"(tx {str(rec.get('tx_hash',''))[:18]})"}
        await proxy_mod.log_event(
            session=sess, event_type="anchor_posted", method="POST",
            path="/_immutrace/anchor", query="", body_bytes=b"",
            response_status=200, response_bytes=b"", remote_ip="system",
            user_agent="immutrace-anchor")
    except Exception:
        pass


async def anchor_worker():
    """Background coroutine: anchor on size or interval, whichever first."""
    last_run = time.monotonic()
    while True:
        try:
            await asyncio.sleep(5)
            pending = get_pending_events()
            now = time.monotonic()
            should_anchor = (
                len(pending) >= config.ANCHOR_BATCH_SIZE
                or (pending and (now - last_run) >= config.ANCHOR_BATCH_INTERVAL)
            )
            if should_anchor:
                rec = anchor_batch()
                if rec:
                    print(f"[anchor] {rec['chain']} root={rec['merkle_root'][:16]}... "
                          f"events={rec['event_count']} tx={str(rec['tx_hash'])[:16]}...")
                    await log_anchor_event(rec)
                last_run = now
        except Exception as e:
            print(f"[anchor] error: {e}")
            await asyncio.sleep(30)


def generate_wallet_if_needed() -> dict:
    """Generate Amoy wallet if not configured. Returns dict with address/private_key/created."""
    from eth_account import Account
    if config.ANCHOR_PRIVATE_KEY and config.ANCHOR_ADDRESS:
        return {
            "address": config.ANCHOR_ADDRESS,
            "private_key": config.ANCHOR_PRIVATE_KEY,
            "created": False,
        }
    acct = Account.create()
    return {
        "address": acct.address,
        "private_key": acct.key.hex(),
        "created": True,
    }

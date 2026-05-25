"""Polygon Amoy testnet anchor worker (with mock fallback)."""
import asyncio
import hashlib
import sqlite3
import time
from datetime import datetime, timezone
from typing import Optional, Tuple
from pathlib import Path
from . import config
from .chain import merkle_root


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


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
    chain = "mock" if config.MOCK_ANCHOR else "polygon-amoy"

    tx_hash, block_number = submit_anchor(root)

    conn = sqlite3.connect(str(config.DB_PATH))
    try:
        cur = conn.execute(
            "INSERT INTO anchors (merkle_root, event_count, first_event_id, "
            "last_event_id, submitted_at, chain, tx_hash, block_number, confirmed) "
            "VALUES (?,?,?,?,?,?,?,?,1)",
            (root, len(hashes), pending[0]["id"], pending[-1]["id"],
             utcnow_iso(), chain, tx_hash, block_number),
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
    }


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
                          f"events={rec['event_count']} tx={rec['tx_hash'][:16]}...")
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

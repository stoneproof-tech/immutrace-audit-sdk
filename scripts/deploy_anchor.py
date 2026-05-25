"""Deploy IMMUTRACEAnchor.sol to Polygon Amoy via py-solcx.

Requires:
  - ANCHOR_PRIVATE_KEY funded with test POL on Amoy
  - py-solcx installed (`pip install py-solc-x`)

Run: python -m scripts.deploy_anchor
"""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from proxy import config


# Minimal standalone version of the contract — no OpenZeppelin imports.
# Functionally equivalent to the Ownable/Pausable IMMUTRACEAnchor.
ANCHOR_SOURCE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract IMMUTRACEAnchor {
    struct AnchorRecord { uint256 timestamp; address submitter; }
    mapping(bytes32 => AnchorRecord) private _anchors;
    address public owner;
    bool public paused;

    event Anchored(bytes32 indexed root, uint256 timestamp, address indexed submitter);

    constructor() { owner = msg.sender; }

    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
    modifier whenNotPaused() { require(!paused, "paused"); _; }

    function anchor(bytes32 root) external whenNotPaused {
        require(root != bytes32(0), "zero hash");
        _anchors[root] = AnchorRecord({ timestamp: block.timestamp, submitter: msg.sender });
        emit Anchored(root, block.timestamp, msg.sender);
    }

    function verify(bytes32 root) external view returns (uint256, address) {
        AnchorRecord storage rec = _anchors[root];
        return (rec.timestamp, rec.submitter);
    }

    function pause() external onlyOwner { paused = true; }
    function unpause() external onlyOwner { paused = false; }
}
"""


def compile_contract():
    try:
        from solcx import compile_source, install_solc, set_solc_version
    except ImportError:
        print("Install py-solc-x: pip install py-solc-x")
        sys.exit(1)
    install_solc("0.8.24")
    set_solc_version("0.8.24")
    out = compile_source(ANCHOR_SOURCE, output_values=["abi", "bin"])
    _, info = next(iter(out.items()))
    return info["abi"], info["bin"]


def deploy():
    from web3 import Web3
    from eth_account import Account

    if not config.ANCHOR_PRIVATE_KEY:
        print("ERROR: ANCHOR_PRIVATE_KEY missing. Run scripts/bootstrap_wallet.py first.")
        sys.exit(1)

    w3 = Web3(Web3.HTTPProvider(config.AMOY_RPC, request_kwargs={"timeout": 30}))
    if not w3.is_connected():
        print(f"ERROR: cannot connect to Amoy RPC {config.AMOY_RPC}")
        sys.exit(1)

    acct = Account.from_key(config.ANCHOR_PRIVATE_KEY)
    bal = w3.eth.get_balance(acct.address)
    print(f"Deployer: {acct.address}")
    print(f"Balance:  {w3.from_wei(bal, 'ether')} POL")
    if bal == 0:
        print()
        print("⚠ Wallet has 0 POL. Fund it at https://faucet.polygon.technology before deploying.")
        sys.exit(1)

    abi, bytecode = compile_contract()
    contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    nonce = w3.eth.get_transaction_count(acct.address)
    tx = contract.constructor().build_transaction({
        "from": acct.address, "nonce": nonce, "chainId": config.AMOY_CHAIN_ID,
        "gas": 1_500_000,
        "maxFeePerGas": w3.to_wei("50", "gwei"),
        "maxPriorityFeePerGas": w3.to_wei("30", "gwei"),
    })
    signed = acct.sign_transaction(tx)
    raw = signed.raw_transaction if hasattr(signed, "raw_transaction") else signed.rawTransaction
    tx_hash = w3.eth.send_raw_transaction(raw)
    print(f"Deploy tx: {tx_hash.hex()}")
    print("Waiting for confirmation…")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
    print()
    print(f"✓ Deployed at: {receipt.contractAddress}")
    print(f"  Block: {receipt.blockNumber}")
    print(f"  Polygonscan: https://amoy.polygonscan.com/tx/{tx_hash.hex()}")
    print()
    print(f"Now update .env:")
    print(f"  ANCHOR_CONTRACT={receipt.contractAddress}")
    print(f"  MOCK_ANCHOR=false")


if __name__ == "__main__":
    deploy()

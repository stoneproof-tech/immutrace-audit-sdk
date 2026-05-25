"""Generate a fresh Polygon Amoy wallet and patch .env with the values.
Run once before starting the proxy if you want a real (non-mock) anchor mode.

Usage: python -m scripts.bootstrap_wallet
"""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from eth_account import Account

ENV_PATH = ROOT / ".env"


def main():
    if not ENV_PATH.exists():
        print("ERROR: .env not found. Copy .env.example first.")
        sys.exit(1)
    text = ENV_PATH.read_text(encoding="utf-8")
    # Skip if already set
    for line in text.splitlines():
        if line.startswith("ANCHOR_PRIVATE_KEY=") and line.split("=", 1)[1].strip():
            print("ANCHOR_PRIVATE_KEY already set in .env. Leaving wallet untouched.")
            return

    acct = Account.create()
    pk = acct.key.hex()
    if not pk.startswith("0x"):
        pk = "0x" + pk

    out_lines = []
    set_pk = set_addr = False
    for line in text.splitlines():
        if line.startswith("ANCHOR_PRIVATE_KEY="):
            out_lines.append(f"ANCHOR_PRIVATE_KEY={pk}"); set_pk = True
        elif line.startswith("ANCHOR_ADDRESS="):
            out_lines.append(f"ANCHOR_ADDRESS={acct.address}"); set_addr = True
        else:
            out_lines.append(line)
    if not set_pk:
        out_lines.append(f"ANCHOR_PRIVATE_KEY={pk}")
    if not set_addr:
        out_lines.append(f"ANCHOR_ADDRESS={acct.address}")
    ENV_PATH.write_text("\n".join(out_lines) + "\n", encoding="utf-8")

    print("Generated Polygon Amoy wallet:")
    print(f"  Address:     {acct.address}")
    print(f"  Private key: {pk}  (stored in .env, gitignored)")
    print()
    print("To enable REAL on-chain anchoring (instead of mock):")
    print(f"  1. Fund the address with test POL: https://faucet.polygon.technology")
    print(f"     (select Polygon Amoy testnet)")
    print(f"  2. Deploy IMMUTRACEAnchor.sol (see scripts/deploy_anchor.py)")
    print(f"  3. Set MOCK_ANCHOR=false and ANCHOR_CONTRACT=<deployed addr> in .env")


if __name__ == "__main__":
    main()

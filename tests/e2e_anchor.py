"""E2E test — Step 7 mainnet anchoring (DRY-RUN ONLY, sends NOTHING).

Validates the CALLDATA payload format (compatible with the 17 historical
anchors), the safety guard that refuses to sign from the wrong wallet, and the
read-only mainnet state + gas estimate. NO transaction is ever sent here.
"""
import sys
sys.path.insert(0, ".")
from proxy import anchor, config  # noqa: E402

PASS = 0
FAIL = 0


def check(name, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"[ OK ] {name}")
    else:
        FAIL += 1; print(f"[FAIL] {name} {extra}")


def main():
    root = "a3f1" * 16  # 64 hex chars, like a real sha256 merkle root

    # payload format (must match historical "immutrace-ledgereye-audit:<root>")
    check("payload format", anchor.build_anchor_payload(root) == "immutrace-ledgereye-audit:" + root)
    ph = anchor._payload_hex(root)
    check("payload hex 0x-prefixed", ph.startswith("0x"))
    check("payload hex round-trips",
          bytes.fromhex(ph[2:]).decode() == "immutrace-ledgereye-audit:" + root)

    # SAFETY GUARD: must refuse to sign when the key doesn't control the wallet
    try:
        anchor.submit_anchor_mainnet(root); raised = False
    except RuntimeError as e:
        raised = "refusing to send" in str(e).lower()
    except Exception:
        raised = False
    check("refuses to send when key != anchor wallet", raised)

    # read-only mainnet pre-flight
    st = anchor.verify_mainnet_state()
    check("chain id 137", st["chain_id"] == 137 and st["chain_ok"], f"got {st['chain_id']}")
    check("wallet is the mainnet anchor wallet",
          st["wallet"].lower() == "0x1ec495d01e91a1929c651680cd7e5758dbf412c2")
    check("balance > 0", st["balance_pol"] > 0, f"bal={st['balance_pol']}")
    check("nonce >= 17 (historical anchors)", st["nonce"] >= 17, f"nonce={st['nonce']}")

    # DRY-RUN gas estimate (NO send)
    est = anchor.estimate_anchor(root)
    check("gas estimate sane (< 10x of ~30k)", 0 < est["gas"] < 300_000, f"gas={est['gas']}")
    check("cost positive & small (< 1 POL)", 0 < est["cost_pol"] < 1.0, f"cost={est['cost_pol']}")

    print(f"\nPASS: {PASS}    FAIL: {FAIL}")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()

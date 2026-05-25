"""Configuration loader (reads .env + external sensitive-endpoints YAML).

IMMUTRACE is backend-agnostic: the upstream system is configured via UPSTREAM_URL
and the list of protected paths lives in an external YAML file that a client edits
for their own system. Nothing here is hard-coded to OSIRIS (the reference demo
config ships in config/sensitive_endpoints.yaml).
"""
import os
import sys
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default).strip()


def _env_int(key: str, default: int) -> int:
    try:
        return int(_env(key, str(default)))
    except ValueError:
        return default


def _env_bool(key: str, default: bool = False) -> bool:
    v = _env(key, "").lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    return default


# Paths
DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)
EXPORT_DIR = DATA_DIR / "exports"
EXPORT_DIR.mkdir(exist_ok=True)

# Proxy
PROXY_HOST = _env("PROXY_HOST", "127.0.0.1")
PROXY_PORT = _env_int("PROXY_PORT", 3001)

# Upstream backend (agnostic). UPSTREAM_URL is preferred; OSIRIS_URL is kept as a
# backward-compatible alias so existing .env files (and the demo) keep working.
UPSTREAM_URL = (_env("UPSTREAM_URL", "") or _env("OSIRIS_URL", "http://127.0.0.1:3000")).rstrip("/")
OSIRIS_URL = UPSTREAM_URL  # deprecated alias — do not use in new code

# Which backend adapter to use (http | graphql | grpc). Only http is implemented.
BACKEND_ADAPTER = _env("BACKEND_ADAPTER", "http").lower()

# Audit
DB_PATH = ROOT / _env("DB_PATH", "data/audit.db")

# Authorization
AUTH_TTL = _env_int("AUTH_TOKEN_TTL_SECONDS", 1800)
ADMIN_USER = _env("ADMIN_USER", "admin")
ADMIN_PASSWORD = _env("ADMIN_PASSWORD", "demo")

# Polygon (anchoring). MOCK by default; real Polygon MAINNET only when MOCK_ANCHOR
# is explicitly false (Step 7 uses the CALLDATA self-transfer pattern).
MOCK_ANCHOR = _env_bool("MOCK_ANCHOR", True)
AMOY_RPC = _env("AMOY_RPC", "https://rpc-amoy.polygon.technology")
AMOY_CHAIN_ID = _env_int("AMOY_CHAIN_ID", 80002)
ANCHOR_PRIVATE_KEY = _env("ANCHOR_PRIVATE_KEY", "")
ANCHOR_ADDRESS = _env("ANCHOR_ADDRESS", "")
ANCHOR_CONTRACT = _env("ANCHOR_CONTRACT", "")
ANCHOR_BATCH_SIZE = _env_int("ANCHOR_BATCH_SIZE", 100)
ANCHOR_BATCH_INTERVAL = _env_int("ANCHOR_BATCH_INTERVAL_SECONDS", 300)

# Polygon mainnet (Step 7 — real CALLDATA anchoring, continuity with the 17
# historical anchors: self-transfer with data "immutrace-ledgereye-audit:<root>").
POLYGON_RPC = _env("POLYGON_RPC", "")              # empty -> built-in keyless fallback
POLYGON_CHAIN_ID = _env_int("POLYGON_CHAIN_ID", 137)
ANCHOR_WALLET_ADDRESS = _env("ANCHOR_WALLET_ADDRESS",
                             "0x1Ec495d01e91a1929C651680cd7E5758dBF412C2")
# Worker hardening: minimum wallet reserve before anchoring, and max consecutive
# failures before the worker stops attempting (manual intervention required).
ANCHOR_MIN_RESERVE_POL = float(_env("ANCHOR_MIN_RESERVE_POL", "0.05"))
ANCHOR_MAX_RETRIES = _env_int("ANCHOR_MAX_RETRIES", 3)


# ── Sensitive endpoints (loaded from external YAML, client-editable) ──────────
# Built-in fallback so the core never crashes if the YAML is missing/broken.
_DEFAULT_SENSITIVE = (
    "/api/flights", "/api/cctv", "/api/maritime", "/api/infrastructure",
    "/api/region-dossier", "/api/satellites", "/api/osint", "/api/scanner",
    "/api/sentinel", "/api/sweep", "/api/balloons", "/api/radiation",
    "/api/frontlines", "/api/gdelt", "/api/cyber-threats",
)

SENSITIVE_ENDPOINTS_CONFIG = ROOT / _env(
    "SENSITIVE_ENDPOINTS_CONFIG", "config/sensitive_endpoints.yaml"
)


def _load_sensitive_rules():
    """Return (prefixes_tuple, rules_dict[prefix]->{risk,description}).

    Falls back to the built-in list (warning on stderr) if the YAML is absent or
    unparseable — the audit gate must never go down because of a config typo.
    """
    try:
        import yaml  # local import: keep config importable even without pyyaml
        with open(SENSITIVE_ENDPOINTS_CONFIG, "r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or {}
        entries = doc.get("endpoints", [])
        rules = {}
        for e in entries:
            prefix = (e.get("prefix") or "").strip()
            if not prefix:
                continue
            rules[prefix] = {
                "risk": (e.get("risk") or "unknown").lower(),
                "description": e.get("description") or "",
            }
        if not rules:
            raise ValueError("no endpoints defined")
        return tuple(rules.keys()), rules
    except Exception as exc:  # noqa: BLE001 — robustness over precision here
        print(f"[immutrace] WARNING: could not load {SENSITIVE_ENDPOINTS_CONFIG} "
              f"({exc}); using built-in default sensitive prefixes.", file=sys.stderr)
        return _DEFAULT_SENSITIVE, {p: {"risk": "unknown", "description": ""}
                                    for p in _DEFAULT_SENSITIVE}


SENSITIVE_PREFIXES, SENSITIVE_RULES = _load_sensitive_rules()


def matched_prefix(path: str) -> Optional[str]:
    """Longest sensitive prefix matching this path, or None."""
    best = None
    for prefix in SENSITIVE_RULES:
        if path.startswith(prefix) and (best is None or len(prefix) > len(best)):
            best = prefix
    return best


def risk_level(path: str) -> str:
    """Risk level for a path (by longest matching prefix), or 'none'."""
    best = matched_prefix(path)
    return SENSITIVE_RULES[best]["risk"] if best else "none"

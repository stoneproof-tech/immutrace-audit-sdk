"""Configuration loader (reads .env)."""
import os
from pathlib import Path
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
OSIRIS_URL = _env("OSIRIS_URL", "http://127.0.0.1:3000").rstrip("/")

# Audit
DB_PATH = ROOT / _env("DB_PATH", "data/audit.db")

# Authorization
AUTH_TTL = _env_int("AUTH_TOKEN_TTL_SECONDS", 1800)
ADMIN_USER = _env("ADMIN_USER", "analyst")
ADMIN_PASSWORD = _env("ADMIN_PASSWORD", "demo")

# Polygon Amoy
MOCK_ANCHOR = _env_bool("MOCK_ANCHOR", True)
AMOY_RPC = _env("AMOY_RPC", "https://rpc-amoy.polygon.technology")
AMOY_CHAIN_ID = _env_int("AMOY_CHAIN_ID", 80002)
ANCHOR_PRIVATE_KEY = _env("ANCHOR_PRIVATE_KEY", "")
ANCHOR_ADDRESS = _env("ANCHOR_ADDRESS", "")
ANCHOR_CONTRACT = _env("ANCHOR_CONTRACT", "")
ANCHOR_BATCH_SIZE = _env_int("ANCHOR_BATCH_SIZE", 100)
ANCHOR_BATCH_INTERVAL = _env_int("ANCHOR_BATCH_INTERVAL_SECONDS", 300)

# Endpoints considered "sensitive" — require authorization
# Match by path prefix on the upstream URL after /api/
# OSIRIS uses /api/flights, /api/cctv, /api/maritime, /api/infrastructure,
# /api/region-dossier, /api/satellites, /api/osint/*, /api/scanner, /api/sweep
SENSITIVE_PREFIXES = (
    "/api/flights",
    "/api/cctv",
    "/api/maritime",
    "/api/infrastructure",
    "/api/region-dossier",
    "/api/satellites",
    "/api/osint",
    "/api/scanner",
    "/api/sentinel",
    "/api/sweep",
    "/api/balloons",
    "/api/radiation",
    "/api/frontlines",
    "/api/gdelt",
    "/api/cyber-threats",
)

"""Custodian backends for Shamir key custody.

A CustodianBackend abstracts WHO holds the Shamir fragments and HOW a fragment
is decrypted for reassembly. Two backends:

- LocalCustodianBackend (implemented): 5 simulated custodians whose RSA keypairs
  live on this machine under demos/osiris/custodians/ (private PEMs gitignored).
  Because the keys are local, the system can decrypt fragments itself — this is
  a DEMO SIMULATION, not real custody (a single machine effectively holds all
  shares).
- RemoteCustodianBackend (interface only): real custodians where each private
  key lives with an independent party behind an authenticated API + MFA, so no
  single party can reconstruct. Wiring this up is a config change later.
"""
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict

from . import config, shamir

ROOT = Path(__file__).resolve().parent.parent
CUSTODIAN_DIR = ROOT / "demos" / "osiris" / "custodians"

# Fixed roster for the demo (Shamir index 1..5). username links a 'custodian' login.
CUSTODIAN_SPECS = [
    (1, "Notaio Demo", "notaio", "notaio"),
    (2, "Avvocato Demo", "avvocato", "avvocato"),
    (3, "Revisore Demo", "revisore", "revisore"),
    (4, "DPO Demo", "dpo", "dpo"),
    (5, "Security Officer Demo", "security_officer", "secofficer"),
]


class CustodianBackend(ABC):
    @abstractmethod
    def provision(self) -> None:
        """Ensure custodian identities/keys exist (idempotent)."""

    @abstractmethod
    def custodians(self) -> List[Dict]:
        """[{id, name, role_label, username, public_pem}] for all custodians."""

    @abstractmethod
    def decrypt_share(self, custodian_id: int, encrypted: bytes) -> bytes:
        """Decrypt a custodian's RSA-encrypted fragment to raw bytes."""


class LocalCustodianBackend(CustodianBackend):
    name = "local"

    def __init__(self):
        CUSTODIAN_DIR.mkdir(parents=True, exist_ok=True)

    def _priv_path(self, cid: int) -> Path:
        return CUSTODIAN_DIR / f"custodian_{cid}.priv.pem"

    def _pub_path(self, cid: int) -> Path:
        return CUSTODIAN_DIR / f"custodian_{cid}.pub.pem"

    def provision(self) -> None:
        from . import identity
        for cid, name, role_label, username in CUSTODIAN_SPECS:
            if not self._priv_path(cid).exists():
                priv_pem, pub_pem = shamir.generate_rsa_keypair()
                self._priv_path(cid).write_text(priv_pem, encoding="utf-8")
                self._pub_path(cid).write_text(pub_pem, encoding="utf-8")
            # ensure a 'custodian' login exists for this custodian (demo)
            identity._ensure_user(username, "demo1234", "custodian", name)
            self._sync_row(cid, name, role_label, username)

    def _sync_row(self, cid, name, role_label, username):
        import sqlite3
        pub_pem = self._pub_path(cid).read_text(encoding="utf-8")
        conn = sqlite3.connect(str(config.DB_PATH), timeout=30.0)
        try:
            conn.execute("PRAGMA busy_timeout=30000")
            conn.execute(
                "INSERT INTO custodians(id, name, role_label, username, public_pem, is_local) "
                "VALUES (?,?,?,?,?,1) ON CONFLICT(id) DO UPDATE SET "
                "name=excluded.name, role_label=excluded.role_label, "
                "username=excluded.username, public_pem=excluded.public_pem",
                (cid, name, role_label, username, pub_pem),
            )
            conn.commit()
        finally:
            conn.close()

    def custodians(self) -> List[Dict]:
        import sqlite3
        conn = sqlite3.connect(str(config.DB_PATH), timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            return [dict(r) for r in conn.execute(
                "SELECT id, name, role_label, username, public_pem FROM custodians ORDER BY id")]
        finally:
            conn.close()

    def decrypt_share(self, custodian_id: int, encrypted: bytes) -> bytes:
        priv = self._priv_path(custodian_id)
        if not priv.exists():
            raise FileNotFoundError(f"no local private key for custodian {custodian_id}")
        return shamir.decrypt_fragment_rsa(encrypted, priv.read_text(encoding="utf-8"))


class RemoteCustodianBackend(CustodianBackend):
    """STUB. Real custodians behind an authenticated API + MFA."""
    name = "remote"

    def provision(self) -> None:
        raise NotImplementedError("RemoteCustodianBackend is a stub (real custody, MFA).")

    def custodians(self) -> List[Dict]:
        raise NotImplementedError

    def decrypt_share(self, custodian_id: int, encrypted: bytes) -> bytes:
        raise NotImplementedError


def get_backend() -> CustodianBackend:
    kind = config._env("CUSTODIAN_BACKEND", "local").lower()
    return RemoteCustodianBackend() if kind == "remote" else LocalCustodianBackend()

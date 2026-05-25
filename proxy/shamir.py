"""
Shamir's Secret Sharing — master-key escrow (k-of-n custodians).

Ported ~1:1 from decision-flow-ledger/ledgereye/backend/services/shamir.py.
Splits a secret (the master key) over GF(256) into N fragments, threshold K
(default 3-of-5); each fragment is RSA-4096-OAEP-encrypted to a custodian's
public key before storage. No single custodian can reconstruct the key alone.

Honest note: the GF(256) Shamir core is hand-rolled (correct construction with
generator g=3, covered by ledgereye's 42-test suite). RSA uses the vetted
`cryptography` library. For production hardening, a formally-audited SSS
implementation (e.g. PyCryptodome) could replace the core; the public API here
(split_secret/reconstruct_secret/escrow_key/recover_key) would stay the same.
"""

import os
import logging
import secrets
from typing import List, Tuple

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

logger = logging.getLogger("immutrace.shamir")

# ─── GF(256) Arithmetic ────────────────────────────────────

# Irreducible polynomial for GF(256): x^8 + x^4 + x^3 + x + 1
_EXP = [0] * 512
_LOG = [0] * 256

def _init_tables():
    # Generator g=3 has order 255 in GF(256) with irreducible polynomial 0x11B.
    # NOTE: g=2 has order 51 with 0x11B — using it is a common Shamir implementation bug.
    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        # Multiply x by 3 in GF(256): x*3 = (x*2) XOR x, with reduction mod 0x11B
        x2 = (x << 1) ^ (0x11B if x & 0x80 else 0)
        x = x2 ^ x
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]

_init_tables()


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("Cannot invert zero in GF(256)")
    return _EXP[255 - _LOG[a]]


def _gf_div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("Division by zero in GF(256)")
    if a == 0:
        return 0
    return _EXP[(_LOG[a] + 255 - _LOG[b]) % 255]


# ─── Shamir Core ───────────────────────────────────────────

def _eval_poly(coeffs: List[int], x: int) -> int:
    """Evaluate polynomial at x in GF(256)."""
    result = 0
    for coeff in reversed(coeffs):
        result = _gf_mul(result, x) ^ coeff
    return result


def split_secret(secret: bytes, threshold: int = 3, num_shares: int = 5) -> List[Tuple[int, bytes]]:
    """Split a secret into shares using Shamir's Secret Sharing over GF(256).

    Returns list of (index, share_bytes) tuples. index is 1-based.
    Each byte of the secret is split independently.
    """
    if threshold > num_shares:
        raise ValueError("Threshold cannot exceed number of shares")
    if threshold < 2:
        raise ValueError("Threshold must be at least 2")
    if num_shares > 254:
        raise ValueError("Cannot create more than 254 shares")

    shares = [bytearray() for _ in range(num_shares)]

    for byte_val in secret:
        # Random polynomial: coeffs[0] = secret byte, coeffs[1..k-1] = random
        coeffs = [byte_val] + [secrets.randbelow(256) for _ in range(threshold - 1)]
        for i in range(num_shares):
            x = i + 1  # x values are 1-based (never 0)
            shares[i].append(_eval_poly(coeffs, x))

    return [(i + 1, bytes(shares[i])) for i in range(num_shares)]


def reconstruct_secret(shares: List[Tuple[int, bytes]], threshold: int = 3) -> bytes:
    """Reconstruct a secret from K shares using Lagrange interpolation in GF(256).

    shares: list of (index, share_bytes) tuples
    """
    if len(shares) < threshold:
        raise ValueError(f"Need at least {threshold} shares, got {len(shares)}")

    # Use only first `threshold` shares
    used = shares[:threshold]
    secret_len = len(used[0][1])

    result = bytearray()
    for byte_idx in range(secret_len):
        # Lagrange interpolation at x=0
        val = 0
        for i, (xi, share_i) in enumerate(used):
            yi = share_i[byte_idx]
            # Compute Lagrange basis polynomial at x=0
            num = 1
            den = 1
            for j, (xj, _) in enumerate(used):
                if i == j:
                    continue
                num = _gf_mul(num, xj)       # 0 ^ xj = xj
                den = _gf_mul(den, xi ^ xj)  # xi ^ xj in GF(256) = xi XOR xj
            basis = _gf_div(num, den)
            val ^= _gf_mul(yi, basis)
        result.append(val)

    return bytes(result)


# ─── RSA Key Operations ───────────────────────────────────

def generate_rsa_keypair() -> Tuple[str, str]:
    """Generate an RSA-4096 keypair. Returns (private_pem, public_pem)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


def encrypt_fragment_rsa(fragment: bytes, public_key_pem: str) -> bytes:
    """Encrypt a Shamir fragment with a custodian's RSA-4096 public key."""
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    return public_key.encrypt(
        fragment,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def decrypt_fragment_rsa(encrypted_fragment: bytes, private_key_pem: str) -> bytes:
    """Decrypt a Shamir fragment with a custodian's RSA-4096 private key."""
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    return private_key.decrypt(
        encrypted_fragment,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# ─── High-Level Escrow Operations ─────────────────────────

def escrow_key(
    aes_key: bytes,
    custodian_public_keys: List[Tuple[int, str]],
    threshold: int = 3,
) -> List[Tuple[int, bytes]]:
    """Split AES key and encrypt each fragment with custodian RSA keys.

    custodian_public_keys: list of (custodian_id, public_key_pem)
    Returns: list of (custodian_id, encrypted_fragment)
    """
    num_shares = len(custodian_public_keys)
    shares = split_secret(aes_key, threshold=threshold, num_shares=num_shares)

    encrypted_fragments = []
    for (share_idx, share_data), (cust_id, pub_key) in zip(shares, custodian_public_keys):
        # Prepend share index byte so we know position during reconstruction
        indexed_share = bytes([share_idx]) + share_data
        encrypted = encrypt_fragment_rsa(indexed_share, pub_key)
        encrypted_fragments.append((cust_id, encrypted))

    return encrypted_fragments


def recover_key(
    decrypted_fragments: List[bytes],
    threshold: int = 3,
) -> bytes:
    """Reconstruct AES key from decrypted Shamir fragments.

    decrypted_fragments: list of raw decrypted fragment bytes (with index prefix)
    """
    shares = []
    for frag in decrypted_fragments:
        idx = frag[0]  # First byte is the share index
        data = frag[1:]
        shares.append((idx, data))

    return reconstruct_secret(shares, threshold=threshold)

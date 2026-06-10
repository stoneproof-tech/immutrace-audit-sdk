"""IMMUTRACE universal-attestation client — zero external dependencies (stdlib only).

Certify ANY decision against an IMMUTRACE proxy and verify a receipt independently.
Nothing here is specific to a backend: you hand it a structured description of a
decision and get back a tamper-evident, blockchain-anchorable receipt.

The raw inputs of a decision NEVER leave your machine: pass them as bytes and the
client hashes them locally (sha256) into `inputs_digest`. Only the digest is sent.

Library use:
    from immutrace_client import ImmutraceClient
    c = ImmutraceClient("http://127.0.0.1:3001", "analyst", "demo1234")
    c.login()
    receipt = c.attest(action="loan.decision", subject="application-42",
                       decision="denied", rationale="DTI ratio above policy threshold",
                       inputs=b"<the model input bundle>", actor="credit-model-v3",
                       metadata={"model": "credit-v3", "score": 0.31})
    print(receipt["this_hash"])
    print(c.verify(receipt["this_hash"]))      # independent, no auth needed

CLI use:
    python -m immutrace_client attest --url http://127.0.0.1:3001 \
        --user analyst --password demo1234 \
        --action loan.decision --subject application-42 --decision denied \
        --rationale "DTI above threshold" --actor credit-model-v3 \
        --inputs-file ./bundle.json --metadata '{"score":0.31}'
    python -m immutrace_client verify --url http://127.0.0.1:3001 <this_hash>
"""
import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request
from http.cookiejar import CookieJar
from typing import Any, Dict, Optional


class ImmutraceError(RuntimeError):
    pass


class ImmutraceClient:
    """Minimal IMMUTRACE attestation client. Session cookies are tracked manually
    from the Set-Cookie response header (no requests/httpx dependency)."""

    def __init__(self, url: str, user: str = "", password: str = ""):
        self.url = url.rstrip("/")
        self.user = user
        self.password = password
        self._cookies: Dict[str, str] = {}

    # ── low-level HTTP (stdlib urllib) ──────────────────────────────────────
    def _request(self, method: str, path: str, body: Optional[dict] = None,
                 auth_required: bool = True) -> Dict[str, Any]:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")
        if self._cookies:
            req.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in self._cookies.items()))
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                self._absorb_cookies(resp)
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")
            try:
                detail = json.loads(detail)
            except Exception:
                pass
            raise ImmutraceError(f"HTTP {e.code} {method} {path}: {detail}")
        except urllib.error.URLError as e:
            raise ImmutraceError(f"connection error to {self.url}{path}: {e.reason}")

    def _absorb_cookies(self, resp) -> None:
        """Parse Set-Cookie header(s) and remember the cookie name=value pairs."""
        # get_all preserves multiple Set-Cookie headers (one per cookie).
        for header in resp.headers.get_all("Set-Cookie") or []:
            pair = header.split(";", 1)[0].strip()
            if "=" in pair:
                name, value = pair.split("=", 1)
                self._cookies[name.strip()] = value.strip()

    # ── high-level API ──────────────────────────────────────────────────────
    def login(self) -> Dict[str, Any]:
        """Authenticate and capture the session cookie."""
        res = self._request("POST", "/_immutrace/auth/login",
                            {"username": self.user, "password": self.password})
        if "__immutrace_auth" not in self._cookies:
            raise ImmutraceError("login did not return a session cookie")
        return res

    def attest(self, action: str, subject: str = "", decision: str = "",
               rationale: str = "", inputs: Optional[bytes] = None,
               inputs_digest: str = "", actor: str = "",
               metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Certify a decision. If `inputs` (raw bytes) is given it is hashed LOCALLY
        with sha256 and only the digest is transmitted — the raw inputs never leave
        this machine. An explicit `inputs_digest` takes precedence if both given."""
        digest = inputs_digest
        if not digest and inputs is not None:
            digest = hashlib.sha256(inputs).hexdigest()
        payload = {
            "action": action,
            "subject": subject,
            "decision": decision,
            "rationale": rationale,
            "inputs_digest": digest,
            "actor": actor,
            "metadata": metadata or {},
        }
        return self._request("POST", "/_immutrace/attest", payload)

    def verify(self, this_hash: str) -> Dict[str, Any]:
        """Independently verify a receipt. No authentication required."""
        return self._request("GET", f"/_immutrace/attest/verify/{this_hash}",
                             auth_required=False)


# ── CLI ──────────────────────────────────────────────────────────────────────
def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="immutrace_client",
        description="Certify any decision against an IMMUTRACE proxy, or verify a receipt.")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("attest", help="certify a decision (requires login)")
    a.add_argument("--url", required=True, help="IMMUTRACE proxy base URL")
    a.add_argument("--user", required=True)
    a.add_argument("--password", required=True)
    a.add_argument("--action", required=True, help="what was decided/done")
    a.add_argument("--subject", default="", help="who/what the decision is about")
    a.add_argument("--decision", default="", help="the outcome")
    a.add_argument("--rationale", default="", help="human-readable justification")
    a.add_argument("--actor", default="", help="who/what made the decision")
    a.add_argument("--inputs-file", default="", help="file whose bytes are hashed LOCALLY into inputs_digest")
    a.add_argument("--inputs-digest", default="", help="precomputed sha256 of the inputs")
    a.add_argument("--metadata", default="", help="JSON object of extra context")

    v = sub.add_parser("verify", help="independently verify a receipt (no auth)")
    v.add_argument("--url", required=True, help="IMMUTRACE proxy base URL")
    v.add_argument("this_hash", help="the receipt's this_hash (64 hex chars)")

    return p


def main(argv=None) -> int:
    args = _build_parser().parse_args(argv)

    if args.cmd == "attest":
        metadata = {}
        if args.metadata:
            try:
                metadata = json.loads(args.metadata)
            except json.JSONDecodeError as e:
                print(f"error: --metadata is not valid JSON: {e}", file=sys.stderr)
                return 2
        inputs = None
        if args.inputs_file:
            try:
                with open(args.inputs_file, "rb") as fh:
                    inputs = fh.read()
            except OSError as e:
                print(f"error: cannot read --inputs-file: {e}", file=sys.stderr)
                return 2
        client = ImmutraceClient(args.url, args.user, args.password)
        try:
            client.login()
            receipt = client.attest(
                action=args.action, subject=args.subject, decision=args.decision,
                rationale=args.rationale, inputs=inputs,
                inputs_digest=args.inputs_digest, actor=args.actor, metadata=metadata)
        except ImmutraceError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        print(json.dumps(receipt, indent=2))
        return 0

    if args.cmd == "verify":
        client = ImmutraceClient(args.url)
        try:
            result = client.verify(args.this_hash)
        except ImmutraceError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        print(json.dumps(result, indent=2))
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())

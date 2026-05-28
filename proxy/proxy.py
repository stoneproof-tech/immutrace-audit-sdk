"""Reverse proxy + per-request hash-chain logging."""
import asyncio
import sqlite3
import hashlib
from typing import Optional
import httpx
import websockets
from fastapi import Request, Response, WebSocket
from fastapi.responses import StreamingResponse, JSONResponse, HTMLResponse
from . import config, auth, identity, workflow, keymgmt, encryption, timestamp
from .chain import sha256_hex, chain_hash, canonical_event
from .adapters import make_adapter, UpstreamError

# Serializes hash-chain writes. The chain is inherently sequential (each event's
# prev_hash is the previous event's this_hash), so a single writer both removes
# the read-prev/insert race AND avoids SQLite "database is locked" contention
# when the browser loads many assets in parallel.
_chain_lock = asyncio.Lock()

# Pre-built async HTTP client (reused across requests)
_http = httpx.AsyncClient(
    timeout=httpx.Timeout(30.0, connect=5.0),
    follow_redirects=False,
    limits=httpx.Limits(max_connections=200, max_keepalive_connections=50),
)

# The upstream backend is reached through a pluggable adapter (HTTP by default).
# The audit core below is identical regardless of the upstream transport.
_adapter = make_adapter(config.BACKEND_ADAPTER, config.UPSTREAM_URL, _http)


# Headers we strip from the upstream response before returning to client
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "content-encoding",
    "content-length",
}


def _strip_hop_by_hop(headers: dict) -> dict:
    return {k: v for k, v in headers.items() if k.lower() not in HOP_BY_HOP}


# JS shim injected into every text/html response
_INJECT_TAG = b'<script defer src="/_immutrace/sdk.js"></script>\n'


def _maybe_inject(body: bytes, content_type: str) -> bytes:
    if "text/html" not in content_type.lower():
        return body
    # Inject before </head> if present, else before </body>, else prepend
    lower = body.lower()
    idx = lower.find(b"</head>")
    if idx >= 0:
        return body[:idx] + _INJECT_TAG + body[idx:]
    idx = lower.find(b"</body>")
    if idx >= 0:
        return body[:idx] + _INJECT_TAG + body[idx:]
    return _INJECT_TAG + body


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def log_event(
    session: Optional[dict],
    event_type: str,
    method: str,
    path: str,
    query: str,
    body_bytes: bytes,
    response_status: int,
    response_bytes: bytes,
    remote_ip: str,
    user_agent: str,
) -> str:
    """Insert an event into the SQLite chain. Returns this_hash."""
    body_sha = sha256_hex(body_bytes) if body_bytes else ""
    resp_sha = sha256_hex(response_bytes) if response_bytes else ""

    # Snapshot session-bound fields (so the chain is independent of session table)
    actor = session["actor"] if session else "anonymous"
    sid = session["session_id"] if session else "no-session"
    case_id = (session.get("case_id") or "") if session else ""
    activity_type = (session.get("activity_type") or "") if session else ""
    justification = (session.get("justification") or "") if session else ""

    from .auth import utcnow_iso
    ts = utcnow_iso()

    # Event fields as they will be hashed (prev_hash is filled in under the lock,
    # so reading the previous hash and inserting are atomic — see _insert_event_sync).
    event = {
        "session_id": sid,
        "actor": actor,
        "case_id": case_id,
        "activity_type": activity_type,
        "justification": justification,
        "ts": ts,
        "event_type": event_type,
        "method": method,
        "path": path,
        "query": query,
        "body_sha256": body_sha,
        "response_status": response_status,
        "response_sha256": resp_sha,
        "remote_ip": remote_ip,
        "user_agent": user_agent,
    }

    # Encrypt sensitive fields at rest when the master key is unlocked. The hash
    # chain is computed over the (now ciphertext) fields, so verification needs no
    # key and crypto-erasure (destroying the per-record key) cannot break it.
    record_wrap = None
    if keymgmt.is_unlocked() and any(event.get(f) for f in encryption.ENCRYPTED_FIELDS):
        rk = encryption.generate_record_key()
        for f in encryption.ENCRYPTED_FIELDS:
            if event.get(f):
                event[f] = encryption.encrypt_field(rk, event[f])
        record_wrap = encryption.wrap_record_key(rk)  # (nonce, wrapped) | None

    # One writer at a time; the blocking SQLite work runs in a worker thread so it
    # never stalls the event loop (which would otherwise time out concurrent
    # upstream reads when the browser fetches dozens of assets at once).
    async with _chain_lock:
        this_hash, event_id = await asyncio.to_thread(_insert_event_sync, event, record_wrap)

    # Timestamp eligible events in the background (non-blocking, eIDAS-ready).
    if timestamp.should_timestamp(event_type, path):
        asyncio.create_task(timestamp.timestamp_event_async(event_id, this_hash, path, event_type))
    return this_hash


def _insert_event_sync(event: dict, record_wrap=None):
    """Blocking: read prev hash, compute this_hash, insert (and, if the event was
    encrypted, store its wrapped per-record key in the same transaction). Runs in
    a thread under _chain_lock so the read-then-insert is atomic and single-writer."""
    conn = sqlite3.connect(str(config.DB_PATH), timeout=30.0)
    try:
        conn.execute("PRAGMA busy_timeout=30000")
        cur = conn.execute("SELECT this_hash FROM events ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
        prev = row[0] if row else "0" * 64

        event["prev_hash"] = prev
        this_hash = chain_hash(prev, event)

        cur = conn.execute(
            "INSERT INTO events (session_id, actor, case_id, activity_type, "
            "justification, ts, event_type, method, path, query, body_sha256, "
            "response_status, response_sha256, remote_ip, user_agent, prev_hash, this_hash) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (event["session_id"], event["actor"], event["case_id"],
             event["activity_type"], event["justification"], event["ts"],
             event["event_type"], event["method"], event["path"], event["query"],
             event["body_sha256"], event["response_status"], event["response_sha256"],
             event["remote_ip"], event["user_agent"], prev, this_hash),
        )
        event_id = cur.lastrowid
        if record_wrap is not None:
            nonce, wrapped = record_wrap
            encryption.insert_record_key(conn, event_id, wrapped, nonce)
        conn.commit()
        return this_hash, event_id
    finally:
        conn.close()


async def handle_proxy_request(request: Request) -> Response:
    """Forward a request to the upstream backend (via the adapter) and log it."""
    path = "/" + request.path_params.get("full_path", "")
    query = request.url.query
    method = request.method
    remote_ip = _client_ip(request)
    user_agent = request.headers.get("user-agent", "")

    # Read body (FastAPI gives bytes)
    body = await request.body()

    # Authorization gate for sensitive endpoints.
    # Authorization may come from EITHER:
    #  (a) a legacy investigation session (session/start + justification) — kept
    #      for backward compatibility / single-user mode, and
    #  (b) the Step-3 workflow: a logged-in user with an active supervisor-approved
    #      authorization for this path's prefix.
    session = auth.get_session(request.cookies.get(auth.COOKIE_NAME))  # legacy (a)
    if not session:
        login_user = identity.current_user(request)
        if login_user:
            appr = workflow.active_authorization(login_user["user_id"], path)
            if appr:
                # Build a session-like context so the audit log captures who
                # accessed under which approval.
                session = {
                    "session_id": "login:" + str(login_user["user_id"]),
                    "actor": login_user["username"],
                    "case_id": appr.get("case_id") or "",
                    "activity_type": "APPROVED:" + appr["endpoint_prefix"],
                    "justification": appr.get("justification") or "",
                }
    if auth.is_sensitive_path(path) and not session:
        # Log the denial too — important: an attempted access is itself auditable
        await log_event(
            session=None,
            event_type="auth_denied",
            method=method, path=path, query=query, body_bytes=body,
            response_status=401, response_bytes=b"",
            remote_ip=remote_ip, user_agent=user_agent,
        )
        return JSONResponse(
            status_code=401,
            content={
                "error": "AUTH_REQUIRED",
                "message": "Supervisor-approved authorization (or an investigation session) "
                           "is required for this endpoint.",
                "endpoint": path,
            },
            headers={"X-Immutrace-Gate": "blocked"},
        )

    # Forward to the upstream backend through the configured adapter
    try:
        upstream = await _adapter.forward(
            method=method, path=path, query=query,
            headers=dict(request.headers), body=body,
            remote_ip=remote_ip,
            client_host=request.headers.get("host", ""),
            scheme=request.url.scheme,
        )
    except UpstreamError as e:
        await log_event(
            session=session,
            event_type="upstream_error",
            method=method, path=path, query=query, body_bytes=body,
            response_status=502, response_bytes=str(e).encode(),
            remote_ip=remote_ip, user_agent=user_agent,
        )
        return JSONResponse(
            status_code=502,
            content={"error": "UPSTREAM_UNREACHABLE", "detail": str(e),
                     "upstream": config.UPSTREAM_URL},
        )

    content_type = upstream.content_type
    body_resp = upstream.content

    # Inject the SDK shim into HTML responses
    if "text/html" in content_type.lower():
        body_resp = _maybe_inject(body_resp, content_type)

    # Log the event (hash chain)
    await log_event(
        session=session,
        event_type="http_request",
        method=method, path=path, query=query, body_bytes=body,
        response_status=upstream.status_code, response_bytes=body_resp,
        remote_ip=remote_ip, user_agent=user_agent,
    )

    # Build response
    resp_headers = _strip_hop_by_hop(upstream.headers)
    return Response(
        content=body_resp,
        status_code=upstream.status_code,
        headers=resp_headers,
        media_type=content_type or None,
    )


async def handle_proxy_websocket(websocket: WebSocket, full_path: str) -> None:
    """Transparently bridge a browser WebSocket to the upstream backend.

    Dev servers (e.g. a Next.js upstream like the OSIRIS demo) open an HMR
    WebSocket. A reverse proxy that only speaks HTTP would reject the upgrade,
    stalling the upstream's client runtime. We relay frames in both directions.
    WebSocket traffic is dev-server/transport infrastructure, so it is not added
    to the audit chain (which records data access, not hot-reload noise).
    """
    try:
        upstream_url = _adapter.ws_url("/" + full_path, websocket.url.query)
    except NotImplementedError:
        await websocket.close(code=1011)
        return

    offered = websocket.scope.get("subprotocols") or None

    try:
        upstream = await websockets.connect(
            upstream_url,
            subprotocols=offered,
            open_timeout=10,
            max_size=None,
            ping_interval=None,  # pure relay — let the app manage its own keepalive
        )
    except Exception:
        # Upstream unreachable/refused — close so the browser can retry cleanly.
        await websocket.close(code=1011)
        return

    await websocket.accept(subprotocol=upstream.subprotocol)

    async def client_to_upstream():
        try:
            while True:
                msg = await websocket.receive()
                if msg["type"] == "websocket.disconnect":
                    break
                if msg.get("text") is not None:
                    await upstream.send(msg["text"])
                elif msg.get("bytes") is not None:
                    await upstream.send(msg["bytes"])
        except Exception:
            pass

    async def upstream_to_client():
        try:
            async for message in upstream:
                if isinstance(message, (bytes, bytearray)):
                    await websocket.send_bytes(bytes(message))
                else:
                    await websocket.send_text(message)
        except Exception:
            pass

    t1 = asyncio.create_task(client_to_upstream())
    t2 = asyncio.create_task(upstream_to_client())
    try:
        await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in (t1, t2):
            t.cancel()
        await upstream.close()
        try:
            await websocket.close()
        except Exception:
            pass

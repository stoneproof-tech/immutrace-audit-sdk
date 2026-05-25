"""IMMUTRACE Audit SDK — main FastAPI entry point."""
import asyncio
from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import RedirectResponse, JSONResponse
from contextlib import asynccontextmanager

from . import (config, db, proxy as proxy_mod, dashboard as dash_mod,
               anchor as anchor_mod, identity as identity_mod)

# Initialize DB schema
db.init_sync()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Seed bootstrap/demo users if the users table is empty
    identity_mod.seed_users()
    # Start the anchor worker
    task = asyncio.create_task(anchor_mod.anchor_worker())
    print(f"[immutrace] proxy listening on http://{config.PROXY_HOST}:{config.PROXY_PORT}")
    print(f"[immutrace] upstream: {config.UPSTREAM_URL} (adapter: {config.BACKEND_ADAPTER})")
    print(f"[immutrace] db: {config.DB_PATH}")
    print(f"[immutrace] anchor mode: {'MOCK' if config.MOCK_ANCHOR else 'polygon-amoy'}")
    print(f"[immutrace] dashboard: http://{config.PROXY_HOST}:{config.PROXY_PORT}/_immutrace/dashboard")
    yield
    task.cancel()


app = FastAPI(
    title="IMMUTRACE Audit Proxy",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/_immutrace/docs",
    openapi_url="/_immutrace/openapi.json",
)

# Mount audit + dashboard + auth routes FIRST (precedence over proxy catch-all)
app.include_router(dash_mod.router)
app.include_router(identity_mod.router)


@app.get("/_immutrace/health")
async def health():
    return {"ok": True, "version": "0.1.0",
            "anchor_mode": "mock" if config.MOCK_ANCHOR else "polygon-amoy"}


# WebSocket catch-all: bridges the Next.js dev-server HMR socket to OSIRIS.
# Without this the dev runtime never connects and the app freezes on its splash.
@app.websocket("/{full_path:path}")
async def ws_catch_all(websocket: WebSocket, full_path: str):
    await proxy_mod.handle_proxy_websocket(websocket, full_path)


# Reverse proxy catch-all: forwards every other request to OSIRIS
@app.api_route(
    "/{full_path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
)
async def catch_all(full_path: str, request: Request):
    return await proxy_mod.handle_proxy_request(request)


def main():
    import uvicorn
    uvicorn.run(
        "proxy.app:app",
        host=config.PROXY_HOST,
        port=config.PROXY_PORT,
        log_level="info",
        access_log=False,  # we have our own audit log
    )


if __name__ == "__main__":
    main()

"""HTTP/HTTPS reverse-proxy adapter (the default, fully implemented)."""
import httpx
from .base import BackendAdapter, UpstreamResponse, UpstreamError

# Request headers we never forward upstream.
_DROP_REQUEST_HEADERS = {"host", "content-length"}


class HttpAdapter(BackendAdapter):
    name = "http"

    def __init__(self, upstream_url: str, http_client: httpx.AsyncClient):
        self.upstream = upstream_url.rstrip("/")
        self._http = http_client

    async def forward(self, *, method, path, query, headers, body,
                      remote_ip, client_host, scheme) -> UpstreamResponse:
        fwd_headers = {
            k: v for k, v in headers.items()
            if k.lower() not in _DROP_REQUEST_HEADERS
        }
        fwd_headers["x-forwarded-for"] = remote_ip
        fwd_headers["x-forwarded-host"] = client_host
        fwd_headers["x-forwarded-proto"] = scheme

        try:
            r = await self._http.request(
                method=method,
                url=f"{self.upstream}{path}",
                params=query if query else None,
                content=body if body else None,
                headers=fwd_headers,
            )
        except httpx.RequestError as e:
            raise UpstreamError(str(e)) from e

        return UpstreamResponse(
            status_code=r.status_code,
            headers=dict(r.headers),
            content=r.content,
            content_type=r.headers.get("content-type", ""),
        )

    def ws_url(self, path: str, query: str) -> str:
        ws_scheme = "wss" if self.upstream.startswith("https") else "ws"
        host = self.upstream.split("://", 1)[1]
        return f"{ws_scheme}://{host}{path}" + (f"?{query}" if query else "")

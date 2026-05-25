"""Backend adapters: pluggable transport to the observed upstream system."""
import httpx

from .base import BackendAdapter, UpstreamResponse, UpstreamError
from .http_adapter import HttpAdapter
from .graphql_adapter import GraphQLAdapter
from .grpc_adapter import GrpcAdapter

_ADAPTERS = {
    "http": HttpAdapter,
    "https": HttpAdapter,
    "graphql": GraphQLAdapter,
    "grpc": GrpcAdapter,
}


def make_adapter(kind: str, upstream_url: str, http_client: httpx.AsyncClient) -> BackendAdapter:
    """Instantiate the configured backend adapter (defaults to HTTP)."""
    cls = _ADAPTERS.get((kind or "http").lower(), HttpAdapter)
    return cls(upstream_url, http_client)


__all__ = [
    "BackendAdapter", "UpstreamResponse", "UpstreamError",
    "HttpAdapter", "GraphQLAdapter", "GrpcAdapter", "make_adapter",
]

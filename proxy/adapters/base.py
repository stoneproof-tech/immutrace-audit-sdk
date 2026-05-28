"""Backend adapter abstraction.

IMMUTRACE observes traffic to *some* upstream system. The transport to that
system is hidden behind a BackendAdapter so the audit core (hash chain, gate,
anchoring) stays identical whether the upstream speaks HTTP, GraphQL or gRPC.
Only the HTTP adapter is implemented today; the others are extensible stubs.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass


class UpstreamError(Exception):
    """Raised when the upstream cannot be reached / the request fails in transit."""


@dataclass
class UpstreamResponse:
    """Normalized upstream response, transport-agnostic."""
    status_code: int
    headers: dict
    content: bytes
    content_type: str


class BackendAdapter(ABC):
    """Forwards a request to the upstream backend and returns a normalized response."""

    name: str = "base"

    @abstractmethod
    async def forward(
        self,
        *,
        method: str,
        path: str,
        query: str,
        headers: dict,
        body: bytes,
        remote_ip: str,
        client_host: str,
        scheme: str,
    ) -> UpstreamResponse:
        ...

    def ws_url(self, path: str, query: str) -> str:
        """WebSocket upstream URL for this path (HTTP-family backends).

        Raises NotImplementedError for transports without a WebSocket notion.
        """
        raise NotImplementedError(f"{self.name} adapter does not support WebSocket")

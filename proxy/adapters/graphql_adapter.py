"""GraphQL backend adapter — STUB.

Extension point for auditing a GraphQL upstream (e.g. logging each operation
name / variables as a distinct audit event). Not implemented yet; raising on use
keeps the contract explicit rather than silently misbehaving.
"""
from .base import BackendAdapter, UpstreamResponse


class GraphQLAdapter(BackendAdapter):
    name = "graphql"

    def __init__(self, upstream_url: str, *args, **kwargs):
        self.upstream = upstream_url.rstrip("/")

    async def forward(self, **kwargs) -> UpstreamResponse:
        raise NotImplementedError(
            "GraphQL adapter is a stub. Implement operation-level forwarding/auditing here."
        )

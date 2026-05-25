"""gRPC backend adapter — STUB.

Extension point for auditing a gRPC upstream (e.g. logging each method call as an
audit event). Not implemented yet.
"""
from .base import BackendAdapter, UpstreamResponse


class GrpcAdapter(BackendAdapter):
    name = "grpc"

    def __init__(self, upstream_url: str, *args, **kwargs):
        self.upstream = upstream_url

    async def forward(self, **kwargs) -> UpstreamResponse:
        raise NotImplementedError(
            "gRPC adapter is a stub. Implement method-level forwarding/auditing here."
        )

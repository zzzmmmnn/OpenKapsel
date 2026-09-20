"""Client-side RPC plugin registry."""

from .registry import ClientRpcRegistry, RpcPlugin, load_client_rpc_registry

__all__ = ["ClientRpcRegistry", "RpcPlugin", "load_client_rpc_registry"]

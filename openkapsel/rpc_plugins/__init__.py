"""RPC plugin registries shared by client mappings and server workspaces."""

from .registry import ClientRpcRegistry, RpcPlugin, load_client_rpc_registry, load_server_rpc_registry

__all__ = ["ClientRpcRegistry", "RpcPlugin", "load_client_rpc_registry", "load_server_rpc_registry"]

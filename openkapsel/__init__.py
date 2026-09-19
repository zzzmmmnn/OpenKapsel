"""OpenKapsel."""

__version__ = "1.57.1"

__all__ = ["ServerConfig", "create_server"]


def __getattr__(name):
    """Load server-only dependencies only when the server API is requested."""
    if name in __all__:
        from .server import ServerConfig, create_server

        globals().update(ServerConfig=ServerConfig, create_server=create_server)
        return globals()[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

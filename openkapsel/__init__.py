"""OpenKapsel."""

__version__ = "1.62.0"

__all__ = ["ServerConfig", "create_server"]

_LEGACY_MODULE_EXPORTS = {
    "client_files": "openkapsel.client_runtime.client_files",
    "client_tasks": "openkapsel.client_runtime.client_tasks",
    "client_file_api": "openkapsel.client_runtime.client_file_api",
    "client_windows": "openkapsel.client_runtime.client_windows",
    "git_read": "openkapsel.files.git_read",
}


def __getattr__(name):
    """Load public server exports and lightweight legacy module attributes lazily."""
    if name in __all__:
        from .server import ServerConfig, create_server

        globals().update(ServerConfig=ServerConfig, create_server=create_server)
        return globals()[name]
    target = _LEGACY_MODULE_EXPORTS.get(name)
    if target is not None:
        from importlib import import_module

        module = import_module(target)
        globals()[name] = module
        return module
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

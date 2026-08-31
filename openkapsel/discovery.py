"""Self-describing Discovery document builders."""

from __future__ import annotations

import os
from http import HTTPStatus
from typing import Any
from urllib.parse import quote

from .context_store import (
    CONTEXT_TRIM_ENTRIES,
    MAX_CONTEXT_OPERATION_MESSAGE_CHARS,
    MAX_CONTEXT_ENTRIES,
    MAX_CONTEXT_QUERY_LIMIT,
    MAX_CONTEXT_TASKNAME_CHARS,
    MAX_PLAN_HINT_CONTENT_CHARS,
    MAX_UNFINISHED_ROOT_PLAN_HINTS,
    PLAN_STATUSES,
)
from .cgroups import BUBBLEWRAP_PROCESS_OVERHEAD
from .discovery_sections import (
    SECTION_CAPABILITIES,
    SECTION_ENDPOINTS,
    SECTION_LIMITS,
    SECTION_NAMES,
    SECTION_SUMMARIES,
    SECTION_WORKFLOWS,
)
from .errors import ApiError
from .mcp import (
    MCP_PROTOCOL_VERSION,
    PUBLIC_SERVER_VERSION,
    SUPPORTED_PROTOCOL_VERSIONS,
    tools_for,
)
from .memory_contracts import memory_actions_schema, plan_debrief_schema
from .memory_store import (
    MAX_MEMORY_CONTENT_CHARS,
    MAX_MEMORY_QUERY_LIMIT,
    MEMORY_CATEGORIES,
    MEMORY_SEVERITIES,
    MEMORY_STATUSES,
)
from .routes import discovery_keys
from .skill_handlers import skill_discovery
from .workspace_images import WorkspaceImageError


class DiscoveryMixin:
    """Discovery-domain methods mixed into the main request handler."""

    def _workspace_storage_limits(self) -> dict[str, Any]:
        image_name = self.token_record.workspace_image
        if image_name is None:
            return {
                "backend": "directory",
                "image_name": None,
                "mounted": None,
                "hard_quota_enforced": False,
                "quota_bytes": None,
                "filesystem_total_bytes": None,
                "filesystem_used_bytes": None,
                "filesystem_available_bytes": None,
                "accounting": "no OpenKapsel hard quota is enforced for ordinary directories",
            }

        image = None
        try:
            image = next(
                (
                    item
                    for item in self.server.workspace_images.list()
                    if item.name == image_name
                ),
                None,
            )
        except WorkspaceImageError:
            pass

        total_bytes = used_bytes = available_bytes = None
        if image is not None and image.mounted:
            try:
                stats = os.statvfs(self.token_scope_root)
            except OSError:
                pass
            else:
                block_size = stats.f_frsize or stats.f_bsize
                total_bytes = stats.f_blocks * block_size
                used_bytes = (stats.f_blocks - stats.f_bfree) * block_size
                available_bytes = stats.f_bavail * block_size

        return {
            "backend": "ext4_image",
            "image_name": image_name,
            "mounted": image.mounted if image is not None else False,
            "hard_quota_enforced": True,
            "quota_bytes": image.size_bytes if image is not None else None,
            "filesystem_total_bytes": total_bytes,
            "filesystem_used_bytes": used_bytes,
            "filesystem_available_bytes": available_bytes,
            "accounting": (
                "quota_bytes is the sparse image logical size; filesystem totals exclude "
                "ext4 metadata overhead"
            ),
        }

    def _discovery(self, section: str | None = None) -> dict[str, Any]:
        requested = "main" if section in {None, "", "main"} else str(section)
        if requested != "full" and requested not in SECTION_NAMES and requested != "main":
            raise ApiError(
                HTTPStatus.NOT_FOUND,
                "discovery_section_not_found",
                "discovery section does not exist",
            )
        full = self._full_discovery()
        if requested == "full":
            full["section"] = "full"
            full["index_url"] = "../../"
            return full
        if requested == "main":
            return self._main_discovery(full)
        return self._section_discovery(full, requested)

    def _discovery_common(self, full: dict[str, Any], section: str) -> dict[str, Any]:
        return {
            key: full[key]
            for key in (
                "protocol", "server_version", "name", "os", "root", "cwd",
                "authentication", "token", "skills",
            )
        } | {
            "section": section,
            "index_url": "../../" if section != "main" else "./",
            "full_url": "./discovery/full" if section == "main" else "./full",
        }

    def _main_discovery(self, full: dict[str, Any]) -> dict[str, Any]:
        capabilities = full["capabilities"]
        sections: dict[str, Any] = {}
        availability = {
            "files": bool(
                capabilities["files"]["read"] or capabilities["files"]["write"]
            ),
            "context": capabilities["context"]["enabled"],
            "memory": capabilities["memory"]["enabled"],
            "shell": capabilities["shell"] != "none",
            "web": capabilities["web_preview"]["enabled"],
            "sharing": capabilities["sharing"]["enabled"],
        }
        for name in SECTION_NAMES:
            sections[name] = {
                "url": f"./discovery/{name}",
                "summary": SECTION_SUMMARIES[name],
                "available": availability[name],
            }
        sections["full"] = {
            "url": "./discovery/full",
            "summary": "Complete compatibility document containing every capability, limit, endpoint, and workflow entry.",
            "available": True,
        }
        result = self._discovery_common(full, "main")
        result.update(
            {
                "path_rules": {
                    "relative_paths_from": full["path_rules"]["relative_paths_from"],
                    "symlink_escape": full["path_rules"]["symlink_escape"],
                    "private_directories": [".recycle", ".sql", ".context"],
                },
                "capabilities": {
                    "files": capabilities["files"],
                    "recycle": capabilities["recycle"],
                    "context": {"enabled": capabilities["context"]["enabled"]},
                    "memory": {"enabled": capabilities["memory"]["enabled"]},
                    "sharing": {
                        key: capabilities["sharing"][key]
                        for key in ("enabled", "create", "inspect_by_id", "import", "delete_own")
                    },
                    "shell": capabilities["shell"],
                    "network": capabilities["network"],
                    "web_preview": {"enabled": capabilities["web_preview"]["enabled"]},
                    "web_app_api": {"enabled": capabilities["web_app_api"]["enabled"]},
                    "mcp": {
                        "enabled": capabilities["mcp"]["enabled"],
                        "transport": capabilities["mcp"]["transport"],
                        "available_tool_count": len(capabilities["mcp"]["available_tools"]),
                    },
                    "extra_paths_redacted": capabilities["extra_paths_redacted"],
                },
                "limits": {
                    key: full["limits"][key]
                    for key in (
                        "workspace_storage", "max_request_body_bytes", "max_file_bytes",
                        "max_concurrent_transfers", "max_concurrent_shell_tasks_per_token",
                        "max_sse_streams_per_token", "max_sse_duration_seconds",
                        "max_batch_file_operations",
                        "share_ttl_seconds", "max_share_entries", "max_share_bytes",
                        "max_operation_message_characters", "max_taskname_characters",
                    )
                },
                "sections": sections,
                "endpoints": {
                    "discovery": {
                        **full["endpoints"]["discovery"],
                        "url": "./",
                    },
                    "discovery_section": {
                        **full["endpoints"]["discovery_section"],
                        "url": "./discovery/<files|context|memory|shell|web|sharing|full>",
                    },
                    "credentials_renew": {
                        **full["endpoints"]["credentials_renew"],
                        "url": "./credentials/renew",
                    },
                    "mcp": {
                        **full["endpoints"]["mcp"],
                        "url": "./mcp",
                    },
                },
                "workflow": [
                    "The URL token is read-only. Send Authorization: Bearer <CONTROL_TOKEN> for mutations, Context, Memory, MCP, Shell, and task control.",
                    "REST Skill clients should first invoke the installed scripts/openkapsel_config.py init <workspace-url> <control-token> by its Skill path while the working directory is the local controlling project; it creates a mode-0600 .openkapsel.env there. The nearest file follows the current working directory; explicit helper arguments and legacy process environment variables remain supported.",
                    "The bundled REST helpers automatically renew and atomically update directory-scoped credentials when less than two days remain; renewal rotates both workspace credentials for three more days and leaves the preview token unchanged.",
                    "Skill-capable REST clients should inspect skills.openkapsel_rest and may install its token-free SHA-256-verified archive or read the linked SKILL.md remotely before loading detailed endpoint contracts.",
                    "Read only the relevant discovery section before acting; use discovery/full only for compatibility or comprehensive inspection.",
                    "Before modifying a workspace, create or reuse a Context plan. Every modifying REST or MCP operation requires plan_id, taskname, and a brief message.",
                    "Start ordinary workspace work with discovery/files; use discovery/context and discovery/memory when coordinating or retaining project knowledge.",
                    "MCP clients should call tools/list for authoritative tool input schemas; workspace_info returns this compact index by default and accepts a section parameter.",
                    "Use discovery/sharing for temporary cross-workspace transfer by random share ID.",
                ],
                "errors": full["errors"],
            }
        )
        return result

    def _section_discovery(self, full: dict[str, Any], section: str) -> dict[str, Any]:
        result = self._discovery_common(full, section)
        result["summary"] = SECTION_SUMMARIES[section]
        if section in {"files", "web", "sharing"}:
            result["path_rules"] = full["path_rules"]
        capability_names = SECTION_CAPABILITIES[section]
        result["capabilities"] = {
            key: value
            for key, value in full["capabilities"].items()
            if key in capability_names
        }
        limit_names = SECTION_LIMITS[section]
        result["limits"] = {
            key: value for key, value in full["limits"].items() if key in limit_names
        }
        endpoint_names = SECTION_ENDPOINTS[section]
        result["endpoints"] = {
            key: value for key, value in full["endpoints"].items() if key in endpoint_names
        }
        result["workflow"] = SECTION_WORKFLOWS[section]
        result["errors"] = full["errors"]
        if section == "shell":
            result["task_states"] = full["task_states"]
        return result

    def _handle_discovery_section(self, section: str) -> None:
        payload = self._discovery(section)
        if self._wants_html():
            from .admin_ui import render_discovery

            self._send_html(
                HTTPStatus.OK,
                render_discovery(payload),
                headers={"Vary": "Authorization"},
            )
        else:
            self._send_json(
                HTTPStatus.OK,
                payload,
                headers={"Vary": "Authorization"},
            )

    def _full_discovery(self) -> dict[str, Any]:
        base = self._base_path()
        share_public_base = (
            f"{self._public_base_url().rstrip('/')}"
            f"/shares"
        )
        if self.server.config.preview_base_url:
            preview_base = (
                f"{self.server.config.preview_base_url.rstrip('/')}/"
                f"{quote(self.token_record.preview_token, safe='')}"
            )
        else:
            preview_base = (
                f"{self.server.config.url_base_path}/w/"
                f"{quote(self.token_record.preview_token, safe='')}"
            )
        control_authorized = getattr(self, "control_authorized", False)
        read_enabled = self.token_record.can_read
        write_enabled = control_authorized and self.token_record.can_write
        shell_enabled = control_authorized and self.token_record.shell_mode != "none"
        recycle_enabled = self.token_scope_root != self.server.config.root
        mcp_tool_names = (
            [
                tool["name"]
                for tool in tools_for(
                    self.token_record,
                    recycle_enabled,
                    self.server.config.mcp_binary_chunk_bytes,
                )
            ]
            if control_authorized
            else []
        )
        optional_read_context_query = {
            "plan_id": (
                "<optional owning plan id; used only with taskname and message to "
                "associate the recorded read>"
            ),
            "taskname": (
                "<optional task grouping name; must be supplied together with message "
                "to record this read>"
            ),
            "message": (
                "<optional brief read summary; must be supplied together with taskname "
                "to record this read>"
            ),
        }
        payload = {
            "protocol": "openkapsel/1",
            "server_version": PUBLIC_SERVER_VERSION,
            "name": self.server.config.name,
            "os": {"name": os.name, "platform": os.uname().sysname, "release": os.uname().release},
            "root": str(self.token_scope_root),
            "cwd": str(self.token_scope_root),
            "authentication": {
                "url_token": "read-only workspace capability",
                "control": "Authorization: Bearer <CONTROL_TOKEN>",
                "control_authorized": control_authorized,
                "control_token": "<redacted>",
                "mcp_requires_control_token": True,
                "read_token_expires_at": self.token_record.credentials_expires_at,
                "control_token_expires_at": self.token_record.credentials_expires_at,
                "preview_token_expires_at": self.token_record.expires_at,
                "preview_token_uses_workspace_lifetime": True,
                "self_renewal": {
                    "available": control_authorized,
                    "allowed_when_remaining_seconds_below": 2 * 24 * 60 * 60,
                    "renewed_lifetime_seconds": 3 * 24 * 60 * 60,
                    "rotates": ["read_token", "control_token"],
                    "preview_token_unchanged": True,
                },
            },
            "path_rules": {
                "relative_paths_from": str(self.token_scope_root),
                "absolute_paths": "allowed inside the token workspace or an authorized extra directory",
                "symlink_escape": "rejected",
                "recycle_directory": ".recycle is private and only accessible through recycle endpoints",
                "context_directory": ".context is private and only accessible through context endpoints",
                "memory_database": ".context/memory.sqlite3 is private and only accessible through Memory endpoints",
            },
            "token": {
                "name": self.token_record.name,
                "expires_at": self.token_record.expires_at,
                "workspace_expires_at": self.token_record.expires_at,
                "credentials_expires_at": self.token_record.credentials_expires_at,
                "path_scope": self.token_record.path_prefix,
                "workspace_image": self.token_record.workspace_image,
            },
            "skills": {
                "openkapsel_rest": skill_discovery(self._public_base_url()),
            },
            "capabilities": {
                "files": {"read": read_enabled, "write": write_enabled},
                "sharing": {
                    "enabled": True,
                    "create": control_authorized and read_enabled,
                    "inspect_by_id": True,
                    "import": write_enabled,
                    "delete_own": control_authorized,
                    "single_root_item": True,
                    "immutable_until_expiry": True,
                    "public_id_is_read_only_capability": True,
                    "source_token_not_required_for_inspection_or_import": True,
                    "destination_control_token_required_for_import": True,
                },
                "recycle": recycle_enabled,
                "context": {
                    "enabled": control_authorized and read_enabled,
                    "authentication": "Bearer control token",
                    "types": ["operation", "plan", "note"],
                    "families": {
                        "event_log": ["operation", "plan", "note"],
                        "long_term": ["memory"],
                    },
                    "memory_capability": "capabilities.memory",
                    "plan_statuses": sorted(PLAN_STATUSES),
                    "query_filters": [
                        "id",
                        "query",
                        "type",
                        "status",
                        "taskname",
                        "actor_id",
                        "path",
                        "plan_id",
                        "root_plans",
                        "before_id",
                    ],
                    "plan_hierarchy": {
                        "relation_field": "plan_id",
                        "root_plan": "a plan record with plan_id null",
                        "sub_plan": "a plan record whose plan_id references its parent plan id",
                        "operation": "plan_id references the plan or sub-plan that owns the operation",
                        "note": "plan_id references the plan or sub-plan that owns the note",
                        "cycles_rejected": True,
                        "max_tree_depth": 32,
                    },
                    "taskname_required_for_new_entries": True,
                    "mutation_taskname_required": True,
                    "mutation_message_required": True,
                    "mutation_plan_id_required": True,
                    "root_plan_creation_plan_id_omitted": True,
                    "legacy_entries_may_have_null_plan_id": True,
                    "read_taskname_and_message_optional_as_pair": True,
                    "recorded_reads_require_control_token": True,
                    "unmessaged_reads_recorded": False,
                    "plan_updates_in_place": True,
                    "plan_creation_returns_unfinished_root_plans": True,
                    "unfinished_root_plan_hint_limit": MAX_UNFINISHED_ROOT_PLAN_HINTS,
                    "note_edits_create_new_id_and_delete_old": True,
                    "database": ".context/context.sqlite3",
                    "database_file_api_access": False,
                    "database_preview_access": False,
                    "database_worker_access": False,
                    "database_restricted_shell_access": False,
                    "max_query_entries": MAX_CONTEXT_QUERY_LIMIT,
                    "max_entries": MAX_CONTEXT_ENTRIES,
                    "trim_oldest_entries": CONTEXT_TRIM_ENTRIES,
                    "trim_policy": "oldest operations/notes first; plans are retained while referenced",
                },
                "memory": {
                    "enabled": control_authorized and read_enabled,
                    "authentication": "Bearer control token",
                    "type": "memory",
                    "identifier_field": "memory_id",
                    "part_of_workspace_context": True,
                    "database": ".context/memory.sqlite3",
                    "separate_from_operation_log": True,
                    "categories": sorted(MEMORY_CATEGORIES),
                    "statuses": sorted(MEMORY_STATUSES),
                    "severities": sorted(MEMORY_SEVERITIES),
                    "query_filters": [
                        "query",
                        "category",
                        "status",
                        "severity",
                        "tag",
                        "path",
                        "include_archived",
                        "limit",
                    ],
                    "revisioned": True,
                    "updates_require_current_revision": True,
                    "soft_archive": True,
                    "tags_indexed": True,
                    "plan_creation_pushes_related_memory": True,
                    "plan_relevance_inputs": ["content", "scope_paths", "memory_tags"],
                    "plan_completion_requires_debrief": True,
                    "empty_memory_actions_allowed": True,
                    "memory_action_enum": ["create", "update", "resolve", "archive"],
                    "memory_actions_schema": memory_actions_schema(),
                    "operation_message_max_characters": MAX_CONTEXT_OPERATION_MESSAGE_CHARS,
                    "taskname_max_characters": MAX_CONTEXT_TASKNAME_CHARS,
                    "title_max_characters": 256,
                    "content_max_characters": MAX_MEMORY_CONTENT_CHARS,
                    "max_query_entries": MAX_MEMORY_QUERY_LIMIT,
                },
                "mcp": {
                    "enabled": control_authorized,
                    "authentication": "Bearer control token",
                    "transport": "streamable-http",
                    "protocol_version": MCP_PROTOCOL_VERSION,
                    "supported_protocol_versions": sorted(SUPPORTED_PROTOCOL_VERSIONS),
                    "tools_list_method": "tools/list",
                    "available_tools": mcp_tool_names,
                },
                "shell": self.token_record.shell_mode if control_authorized else "none",
                "shell_sandbox": (
                    (
                        self.server.config.sandbox_default_backend
                        if self.token_record.sandbox_backend == "auto"
                        else self.token_record.sandbox_backend
                    )
                    if control_authorized and self.token_record.shell_mode == "restricted"
                    else None
                ),
                "shell_sandbox_requested": (
                    self.token_record.sandbox_backend
                    if control_authorized and self.token_record.shell_mode == "restricted"
                    else None
                ),
                "shell_sandbox_image": (
                    (self.token_record.sandbox_image or self.server.config.podman_image)
                    if control_authorized
                    and self.token_record.shell_mode == "restricted"
                    and (
                        self.server.config.sandbox_default_backend
                        if self.token_record.sandbox_backend == "auto"
                        else self.token_record.sandbox_backend
                    ) == "podman"
                    else None
                ),
                "shell_sandbox_image_requested": (
                    self.token_record.sandbox_image
                    if control_authorized and self.token_record.shell_mode == "restricted"
                    else None
                ),
                "sandbox_backends": (
                    self.server.sandboxes.status() if control_authorized else None
                ),
                "shell_pid_namespace": (
                    control_authorized and self.token_record.shell_mode == "restricted"
                ),
                "network": (
                    control_authorized
                    and (
                        self.token_record.shell_mode == "full"
                        or self.token_record.network_mode != "none"
                    )
                ),
                "network_mode": (
                    "full"
                    if control_authorized and self.token_record.shell_mode == "full"
                    else self.token_record.network_mode
                    if control_authorized
                    else "redacted"
                ),
                "network_domains": (
                    list(self.token_record.allowed_domains)
                    if control_authorized and self.token_record.network_mode == "domain_allowlist"
                    else []
                ),
                "network_protocols": (
                    ["http", "https", "websocket", "git+https"]
                    if control_authorized and self.token_record.network_mode == "domain_allowlist"
                    else ["all"]
                    if control_authorized and (
                        self.token_record.shell_mode == "full"
                        or self.token_record.network_mode == "full"
                    )
                    else []
                ),
                "extra_paths": [
                    {"path": item.path, "read_only": item.read_only}
                    for item in self.token_record.allowed_paths
                ] if control_authorized else [],
                "extra_paths_redacted": not control_authorized,
                "shell_outside_workspace": (
                    control_authorized
                    and (
                        self.token_record.shell_mode == "full"
                        or bool(self.token_record.allowed_paths)
                    )
                ),
                "tasks": shell_enabled,
                "file_operations": {
                    "list": read_enabled,
                    "read_text": read_enabled,
                    "metadata": read_enabled,
                    "batch_manifest": read_enabled,
                    "search": read_enabled,
                    "tree": read_enabled,
                    "write_text": write_enabled,
                    "batch_replace_text": write_enabled,
                    "mkdir": write_enabled,
                    "move": write_enabled,
                    "recoverable_delete": write_enabled and recycle_enabled,
                    "batch_recoverable_delete": write_enabled and recycle_enabled,
                    "restore": write_enabled and recycle_enabled,
                },
                "binary_transfer": {
                    "download": read_enabled,
                    "range_download": read_enabled,
                    "direct_upload": write_enabled,
                    "resumable_upload": write_enabled,
                    "mcp_base64_download": control_authorized and read_enabled,
                    "mcp_base64_upload": write_enabled,
                    "mcp_raw_download_handoff": control_authorized and read_enabled,
                    "mcp_raw_upload_handoff": write_enabled,
                    "mcp_transfer_urls_include_tokens": False,
                    "mcp_raw_transfer_authentication": "Bearer control token",
                },
                "task_control": {
                    "enabled": shell_enabled,
                    "asynchronous": shell_enabled,
                    "list": shell_enabled,
                    "incremental_output": shell_enabled,
                    "sse_output": shell_enabled,
                    "interactive_stdin": shell_enabled,
                    "interrupt": shell_enabled,
                    "force_kill": shell_enabled,
                },
                "web_preview": {
                    "enabled": read_enabled and self.token_record.can_preview,
                    "permission_granted": self.token_record.can_preview,
                    "directory_index": "index.html",
                    "range_requests": read_enabled and self.token_record.can_preview,
                    "sandboxed_document_origin": True,
                    "dedicated_origin": self.server.config.preview_base_url is not None,
                    "opaque_origin": self.server.config.preview_base_url is None,
                    "allow_same_origin": self.server.config.preview_base_url is not None,
                    "cross_origin_readable": False,
                    "es_modules": self.server.config.preview_base_url is not None,
                },
                "web_app_api": {
                    "enabled": self.token_record.can_preview,
                    "framework": "FastAPI",
                    "entrypoint": "<app-directory>/api/app.py",
                    "multiple_apps": True,
                    "routing": (
                        "the first api path component selects the FastAPI app "
                        "rooted at its parent directory"
                    ),
                    "sandboxed": True,
                    "pid_namespace": True,
                    "host_proc_visible": False,
                    "runtime_mount": "/opt/openkapsel/venv (read-only)",
                    "authentication": "application-defined",
                    "built_in_users": False,
                    "built_in_sessions": False,
                    "default_documentation_routes": {
                        "public": False,
                        "blocked_paths": ["/docs", "/redoc", "/openapi.json"],
                    },
                    "runtime_helpers": ["openkapsel_runtime.database"],
                    "available_libraries": {
                        "fastapi": "ASGI application framework and routing",
                        "sqlalchemy": "portable database ORM, Core, schema, and transactions",
                        "python-multipart": "multipart/form-data, UploadFile, File, and Form parsing",
                        "jinja2": "server-side HTML and text templates",
                        "httpx": (
                            "HTTP client; outbound requests require this token's "
                            "network permission"
                        ),
                        "numpy": "multidimensional arrays and numerical computing",
                        "numba": "JIT compilation for numerical Python code",
                        "pandas": "data frames, tabular data, and time-series tools",
                        "matplotlib": "non-interactive plotting with DejaVu and Noto fonts",
                        "scipy": "scientific algorithms, optimization, statistics, and signal processing",
                        "cryptography": "high-level cryptographic recipes and low-level primitives",
                        "lxml": "XML and HTML parsing, validation, and XPath support",
                        "pillow": "image decoding, encoding, resizing, and transformation",
                        "pyyaml": "YAML parsing and serialization",
                        "beautifulsoup4": "fault-tolerant HTML and XML document traversal",
                    },
                    "database": {
                        "enabled": self.token_record.can_preview,
                        "browser_access": (
                            "no direct database endpoint; define a workspace FastAPI "
                            "route and access it through /<app-path>/api/<route>"
                        ),
                        "scope": "each app uses its parent directory's private .sql storage",
                        "runtime_module": "openkapsel_runtime.database",
                        "library": "SQLAlchemy",
                        "storage": {
                            "managed_by_runtime": True,
                            "persistent": True,
                            "private": True,
                            "application_paths_exposed": False,
                            "do_not_construct_storage_paths": True,
                            "workspace_file_api_access": False,
                            "static_preview_access": False,
                            "restricted_shell_access": False,
                            "web_app_worker_access": "read-write",
                        },
                        "database_id": {
                            "default": "main",
                            "pattern": "^[A-Za-z0-9_-]{1,64}$",
                            "description": (
                                "logical database name using 1-64 ASCII letters, numbers, "
                                "underscore, or hyphen"
                            ),
                        },
                        "python_api": {
                            "import": "from openkapsel_runtime import database",
                            "engine": {
                                "call": "database.engine(database_id='main')",
                                "returns": "sqlalchemy.Engine",
                                "lifecycle": "cached per database id for the API worker lifetime",
                            },
                            "session": {
                                "call": "with database.session(database_id='main') as session:",
                                "returns": "sqlalchemy.orm.Session",
                                "success": "commit and close",
                                "exception": "rollback and close, then re-raise",
                            },
                        },
                        "portability": {
                            "backend_details_exposed": False,
                            "recommendation": (
                                "use SQLAlchemy ORM, Core, schema, and transaction APIs; "
                                "do not depend on backend-specific SQL or storage paths"
                            ),
                        },
                        "isolation": (
                            "runtime-managed database storage is available only inside this "
                            "token's sandboxed API worker and is hidden from static preview, "
                            "workspace file APIs, and restricted Shell"
                        ),
                    },
                },
                "process": {
                    "list": control_authorized and self.token_record.shell_mode == "restricted",
                    "resource_limits": (
                        control_authorized and self.token_record.shell_mode == "restricted"
                    ),
                    "cgroup_v2_available": self.server.cgroups.available,
                    "unavailable_reason": self.server.cgroups.unavailable_reason or None,
                },
            },
            "limits": {
                "workspace_storage": self._workspace_storage_limits(),
                "max_request_body_bytes": self.server.config.max_body_bytes,
                "max_read_chars": self.server.config.max_read_chars,
                "default_read_chars": self.server.config.default_read_chars,
                "max_task_output_bytes_per_stream": self.server.config.max_task_output_bytes,
                "max_finished_tasks_per_token": self.server.config.max_finished_tasks_per_token,
                "finished_task_retention_seconds": self.server.config.finished_task_retention_seconds,
                "finished_task_storage": "disk",
                "max_concurrent_shell_tasks": self.server.config.max_concurrent_shell_tasks,
                "max_concurrent_shell_tasks_per_token": (
                    self.server.config.max_concurrent_shell_tasks_per_token
                ),
                "max_sse_streams": self.server.config.max_sse_streams,
                "max_sse_streams_per_token": self.server.config.max_sse_streams_per_token,
                "max_sse_duration_seconds": self.server.config.max_sse_duration_seconds,
                "max_direct_upload_bytes": self.server.config.max_direct_upload_bytes,
                "max_file_bytes": self.server.config.max_file_bytes,
                "recommended_upload_chunk_bytes": self.server.config.upload_chunk_bytes,
                "max_mcp_binary_chunk_bytes": self.server.config.mcp_binary_chunk_bytes,
                "upload_ttl_seconds": self.server.config.upload_ttl_seconds,
                "max_incomplete_upload_bytes": self.server.config.max_incomplete_upload_bytes,
                "max_text_replace_bytes": self.server.config.max_text_replace_bytes,
                "max_concurrent_transfers": self.server.config.max_concurrent_transfers,
                "max_search_results": self.server.config.max_search_results,
                "max_search_file_bytes": self.server.config.max_search_file_bytes,
                "max_tree_nodes": self.server.config.max_tree_nodes,
                "max_recursion_depth": self.server.config.max_recursion_depth,
                "max_batch_file_operations": self.server.config.max_batch_file_operations,
                "share_ttl_seconds": self.server.config.share_ttl_seconds,
                "max_share_entries": self.server.config.max_share_entries,
                "max_share_bytes": self.server.config.max_share_bytes,
                "max_task_output_chunk_bytes": 262144,
                "max_task_input_bytes_per_request": 262144,
                "max_task_wait_seconds": 30,
                "max_command_characters": 100000,
                "max_context_query_entries": MAX_CONTEXT_QUERY_LIMIT,
                "max_context_entries": MAX_CONTEXT_ENTRIES,
                "context_trim_oldest_entries": CONTEXT_TRIM_ENTRIES,
                "max_unfinished_root_plan_hints": MAX_UNFINISHED_ROOT_PLAN_HINTS,
                "max_plan_hint_content_characters": MAX_PLAN_HINT_CONTENT_CHARS,
                "max_operation_message_characters": MAX_CONTEXT_OPERATION_MESSAGE_CHARS,
                "max_taskname_characters": MAX_CONTEXT_TASKNAME_CHARS,
                "max_memory_query_entries": MAX_MEMORY_QUERY_LIMIT,
                "max_memory_content_characters": MAX_MEMORY_CONTENT_CHARS,
                "sandbox_max_processes": (
                    self.token_record.sandbox_max_processes if control_authorized else None
                ),
                "bubblewrap_process_overhead": BUBBLEWRAP_PROCESS_OVERHEAD,
                "sandbox_memory_bytes": (
                    self.token_record.sandbox_memory_mb * 1024 * 1024
                    if control_authorized
                    else None
                ),
                "sandbox_cpu_percent": (
                    self.token_record.sandbox_cpu_percent if control_authorized else None
                ),
            },
            "task_states": ["running", "finished"],
            "errors": {
                "format": {"error": {"code": "<stable_code>", "message": "<message>", "details": "<optional>"}},
                "http_status": "errors use a non-2xx HTTP status; rate limits use 429",
                "shell_limit_codes": [
                    "shell_task_token_limit_reached",
                    "shell_task_global_limit_reached",
                    "sandbox_process_limit_reached",
                    "too_many_streams",
                ],
            },
            "endpoints": {
                "discovery": {"method": "GET", "url": f"{base}/"},
                "discovery_section": {
                    "method": "GET",
                    "url": f"{base}/discovery/<files|context|memory|shell|web|sharing|full>",
                    "notes": "main discovery is a compact index; section documents contain domain-specific details and full preserves the complete compatibility document",
                },
                "credentials_renew": {
                    "method": "POST",
                    "url": f"{base}/credentials/renew",
                    "authentication": "current Bearer control token bound to the current read URL",
                    "request_body": None,
                    "available_when": "credentials have less than 172800 seconds remaining",
                    "notes": "atomically invalidates the current read and control tokens, returns both replacements, and sets their shared expiration to request time plus three days; preview token is unchanged",
                    "response": {
                        "read_token": "<new URL token>",
                        "control_token": "<new Bearer token>",
                        "workspace_url": "<new full workspace URL>",
                        "credentials_expires_at": "<UTC timestamp>",
                    },
                },
                "context_query": {
                    "method": "GET",
                    "url": f"{base}/context?id=<integer>&query=<text>&type=<operation|plan|note>&status=<status>&taskname=<exact-taskname>&actor_id=<exact-actor-id>&path=<exact-recorded-path>&plan_id=<direct-parent-or-owner>&root_plans=false&before_id=<integer>&limit=100",
                    "authentication": "Bearer control token",
                    "notes": "all filters are optional and composable except plan_id cannot combine with root_plans=true; plan_id returns direct children/entries only; root_plans=true finds plan roots; newest first; limit cannot exceed 200; context queries do not recursively record themselves",
                },
                "context_plan_tree": {
                    "method": "GET",
                    "url": f"{base}/context/plans/<plan_id>/tree?max_depth=8&limit=200",
                    "authentication": "Bearer control token",
                    "notes": "returns a flat depth-annotated plans array for the selected subtree plus operations/notes attached to those plans; rebuild the tree using each plan id and plan_id; truncation flags are explicit",
                },
                "context_add": {
                    "method": "POST",
                    "url": f"{base}/context",
                    "authentication": "Bearer control token",
                    "json": {
                        "type": "plan or note",
                        "taskname": "<required task grouping name>",
                        "plan_id": "<omit for a root plan; parent plan id for a sub-plan; required owning plan id for a note>",
                        "content": "<AI-authored context>",
                        "status": "in_progress, completed, or cancelled; plans only; defaults to in_progress",
                        "scope_paths": ["<optional paths used to retrieve related Memory for a plan>"],
                        "memory_tags": ["<optional exact tags used to retrieve related Memory for a plan>"],
                    },
                    "response": {
                        "related_memory": "relevant Memory summaries for a created plan",
                        "unfinished_root_plans": "array of up to 20 newest previously existing in_progress root-plan summaries; sub-plans and the newly created plan are excluded",
                        "unfinished_root_plans_total": "total matching unfinished root plans",
                        "unfinished_root_plans_truncated": "true when more than 20 unfinished root plans exist",
                    },
                    "notes": "operation entries are generated automatically by OpenKapsel and cannot be added manually; every created plan response includes related_memory and unfinished_root_plans; the newly created plan is excluded from the hint list; content_preview is capped at 256 characters",
                },
                "context_plan_update": {
                    "method": "PATCH",
                    "url": f"{base}/context/plans/<context_id>",
                    "authentication": "Bearer control token",
                    "json": {
                        "taskname": "<required task grouping name>",
                        "plan_id": "<optional new parent plan id; null moves this plan to the root>",
                        "content": "<optional replacement content>",
                        "status": "<optional in_progress, completed, or cancelled>",
                        "debrief": {
                            **plan_debrief_schema(),
                            "required_when": "status transitions to completed",
                        },
                    },
                    "notes": "updates the existing plan row; completion requires a debrief but does not block unrelated plans; self-parenting and indirect cycles are rejected",
                },
                "context_note_replace": {
                    "method": "PATCH",
                    "url": f"{base}/context/notes/<context_id>",
                    "authentication": "Bearer control token",
                    "json": {
                        "taskname": "<required task grouping name>",
                        "plan_id": "<required owning plan id>",
                        "content": "<required replacement content>",
                    },
                    "notes": "atomically inserts a new note with a newer id and deletes the old note row",
                },
                "memory_query": {
                    "method": "GET",
                    "url": f"{base}/memory?query=<text>&category=<category>&status=<status>&severity=<severity>&tag=<exact-tag>&path=<overlapping-path>&include_archived=false&limit=100",
                    "authentication": "Bearer control token",
                    "response": {
                        "memories": "array of records identified by memory_id",
                        "limit": "integer",
                        "total": "integer",
                        "truncated": "boolean",
                    },
                    "notes": "returns project-level long-term Memory newest first; exact indexed tags and overlapping workspace-relative paths are important relevance signals",
                },
                "memory_project": {
                    "method": "GET",
                    "url": f"{base}/memory/project",
                    "authentication": "Bearer control token",
                    "notes": "returns a bounded project profile prioritizing overview, architecture, and open high-severity known issues",
                },
                "memory_add": {
                    "method": "POST",
                    "url": f"{base}/memory",
                    "authentication": "Bearer control token",
                    "json": {
                        "category": "overview, architecture, convention, decision, or known_issue",
                        "key": "<optional stable key unique within category>",
                        "title": "<required short title>",
                        "content": "<required self-contained long-term knowledge>",
                        "status": "<optional category-compatible status>",
                        "severity": "<optional high, medium, or low; known_issue only>",
                        "tags": ["<up to 32 exact relevance tags>"],
                        "paths": ["<up to 64 workspace-relative scope paths>"],
                        "plan_id": "<required source plan id>",
                        "taskname": "<required task grouping>",
                        "message": "<required change reason, at most 200 characters>",
                    },
                    "response": {
                        "memory_id": "stable Memory identifier",
                        "revision": 1,
                        "etag_header": "current revision validator",
                    },
                    "notes": "returns a stable memory_id, revision 1, and ETag; Memory is stored in .context/memory.sqlite3 rather than the operation-log database",
                },
                "memory_item": {
                    "method": "GET, PATCH, or DELETE",
                    "methods": ["GET", "PATCH", "DELETE"],
                    "url": f"{base}/memory/<memory_id>",
                    "authentication": "Bearer control token",
                    "response_identifier_field": "memory_id",
                    "notes": "GET returns the current Memory and ETag; PATCH revises it; DELETE archives it. Mutations require plan_id, taskname, message, and either If-Match or expected_revision",
                },
                "memory_revisions": {
                    "method": "GET",
                    "url": f"{base}/memory/<memory_id>/revisions?limit=100",
                    "authentication": "Bearer control token",
                    "notes": "returns newest revisions first, including the plan and anonymous actor responsible for each revision",
                },
                "web_preview": {
                    "method": "GET or HEAD",
                    "url": f"{preview_base}/<workspace-relative-path>",
                    "notes": "serves files inline for browser testing; directories resolve index.html; a configured dedicated preview origin supports same-origin modules without cross-origin read access",
                },
                "web_app_api": {
                    "methods": "GET, HEAD, POST, PUT, PATCH, DELETE",
                    "url": f"{preview_base}/<app-path>/api/<route>",
                    "entrypoint": "<app-directory>/api/app.py",
                    "notes": "app-path may be empty for the workspace-root app; the first api path component owns the remaining route; default FastAPI documentation routes are not exposed",
                    "authentication": "defined entirely by the workspace FastAPI application; OpenKapsel adds no users, cookies, sessions, or auth routes",
                },
                "fs_list": {
                    "method": "GET",
                    "url": f"{base}/fs/list?path=<path>&offset=0&limit=1000",
                    "notes": "path may be root-relative or an absolute path inside root",
                    "query": {
                        "path": ".",
                        "offset": 0,
                        "limit": 1000,
                        **optional_read_context_query,
                    },
                },
                "fs_read": {
                    "method": "GET",
                    "url": f"{base}/fs/read?path=<path>&offset=0&limit=65536",
                    "notes": "UTF-8 text only; use byte_offset instead of offset for efficient large-file cursors",
                    "query": {
                        "path": "<required>",
                        "offset": 0,
                        "byte_offset": "alternative to offset",
                        "limit": self.server.config.default_read_chars,
                        **optional_read_context_query,
                    },
                },
                "fs_stat": {
                    "method": "GET",
                    "url": f"{base}/fs/stat?path=<path>&fields=type,size,created_at,modified_at,sha256",
                    "notes": "sha256 is calculated only when explicitly requested",
                    "query": {
                        "path": "<required>",
                        "fields": "<optional comma-separated metadata fields>",
                        **optional_read_context_query,
                    },
                    "fields": [
                        "type",
                        "size",
                        "created_at",
                        "modified_at",
                        "changed_at",
                        "etag",
                        "content_type",
                        "sha256",
                    ],
                },
                "fs_manifest": {
                    "method": "POST",
                    "url": f"{base}/fs/manifest",
                    "authentication": "read-only URL token; Bearer token is not required",
                    "json": {
                        "items": [
                            {
                                "path": "<path>",
                                "size": "<optional expected non-negative bytes>",
                                "sha256": "<optional expected SHA-256>",
                            }
                        ],
                        "include_sha256": False,
                    },
                    "response_statuses": ["missing", "same", "conflict", "exists"],
                    "notes": "bounded multi-path status and synchronization preflight; hashes are calculated only when expected or explicitly requested",
                },
                "fs_search": {
                    "method": "GET",
                    "url": f"{base}/fs/search?path=.&query=<text>&depth=8&max_results=100",
                    "notes": "searches UTF-8 text; supports regex and case_sensitive flags",
                    "query": {
                        "path": ".",
                        "query": "<required text or regex>",
                        "depth": 8,
                        "max_results": min(100, self.server.config.max_search_results),
                        "regex": False,
                        "case_sensitive": True,
                        **optional_read_context_query,
                    },
                },
                "fs_tree": {
                    "method": "GET",
                    "url": f"{base}/fs/tree?path=.&depth=2",
                    "notes": "returns a nested directory tree bounded by depth and max_tree_nodes",
                    "query": {
                        "path": ".",
                        "depth": 2,
                        **optional_read_context_query,
                    },
                },
                "fs_content": {
                    "method": "GET or HEAD",
                    "url": f"{base}/fs/content?path=<path>",
                    "notes": "streams raw bytes and supports one standard HTTP Range",
                    "query": {
                        "path": "<required>",
                        **optional_read_context_query,
                    },
                    "request_headers": {"Range": "bytes=<start>-<end>", "If-None-Match": "<etag>"},
                    "response_headers": ["Content-Length", "Content-Range", "ETag", "Last-Modified"],
                },
                "fs_content_put": {
                    "method": "PUT",
                    "url": f"{base}/fs/content?path=<path>&create_parents=false",
                    "content_type": "application/octet-stream",
                    "request_headers": {
                        "Content-Length": "<required byte count>",
                        "X-Content-SHA256": "<optional SHA-256>",
                        "OpenKapsel-Plan-Id": "<required owning plan id>",
                        "OpenKapsel-Taskname": "<required task grouping name>",
                        "OpenKapsel-Message": "<required brief operation summary>",
                    },
                    "notes": "atomically creates a new file only; if the destination exists, recycle it with fs_delete before uploading so the previous version is retained; use resumable uploads above the direct-upload limit",
                },
                "fs_write": {
                    "method": "POST",
                    "url": f"{base}/fs/write",
                    "json": {
                        "path": "<path>",
                        "content": "<UTF-8 text>",
                        "create_parents": False,
                        "expected_etag": "<optional current ETag>",
                        "plan_id": "<required owning plan id>",
                        "taskname": "<required task grouping name>",
                        "message": "<required brief operation summary>",
                    },
                    "notes": "expected_etag provides If-Match-style optimistic concurrency",
                },
                "fs_replace": {
                    "method": "POST",
                    "url": f"{base}/fs/replace",
                    "json": {
                        "path": "<path>",
                        "old": "<exact text>",
                        "new": "<replacement>",
                        "expected_etag": "<optional current ETag>",
                        "plan_id": "<required owning plan id>",
                        "taskname": "<required task grouping name>",
                        "message": "<required brief operation summary>",
                    },
                    "notes": "safe by default: old must occur exactly once; set expected_matches or replace_all explicitly; expected_etag provides If-Match-style optimistic concurrency",
                },
                "fs_replace_batch": {
                    "method": "POST",
                    "url": f"{base}/fs/replace/batch",
                    "json": {
                        "items": [
                            {
                                "path": "<existing UTF-8 file>",
                                "expected_etag": "<optional current ETag>",
                                "replacements": [
                                    {
                                        "old": "<exact original text>",
                                        "new": "<replacement text>",
                                        "expected_matches": 1,
                                    }
                                ],
                            }
                        ],
                        "plan_id": "<required owning plan id>",
                        "taskname": "<required task grouping name>",
                        "message": "<required brief operation summary>",
                    },
                    "notes": "replace-only multi-file edit; every rule matches the original file text, all files and non-overlapping source ranges are preflighted before publication, and a post-preflight race can return 207 with per-file results",
                },
                "fs_mkdir": {
                    "method": "POST",
                    "url": f"{base}/fs/mkdir",
                    "json": {"path": "<path>", "parents": False, "exist_ok": False, "plan_id": "<required owning plan id>", "taskname": "<required task grouping name>", "message": "<required brief operation summary>"},
                },
                "fs_delete": {
                    "method": "POST",
                    "url": f"{base}/fs/delete",
                    "json": {"path": "<path>", "plan_id": "<required owning plan id>", "taskname": "<required task grouping name>", "message": "<required brief operation summary>"},
                    "notes": "moves the path into this child workspace's .recycle directory; the token root cannot be deleted",
                },
                "fs_delete_batch": {
                    "method": "POST",
                    "url": f"{base}/fs/delete/batch",
                    "json": {
                        "paths": ["<path>", "<path>"],
                        "plan_id": "<required owning plan id>",
                        "taskname": "<required task grouping name>",
                        "message": "<required brief operation summary>",
                    },
                    "notes": "preflights every unique non-overlapping path before moving each item into .recycle; ordinary precondition errors delete nothing; a post-preflight race can return 207 with per-item results",
                },
                "fs_move": {
                    "method": "POST",
                    "url": f"{base}/fs/move",
                    "json": {
                        "source": "<path>",
                        "destination": "<path>",
                        "overwrite": False,
                        "create_parents": False,
                        "plan_id": "<required owning plan id>",
                        "taskname": "<required task grouping name>",
                        "message": "<required brief operation summary>",
                    },
                    "notes": "moves or renames a file/directory; overwrite is disabled by default",
                },
                "recycle_list": {
                    "method": "GET",
                    "url": f"{base}/recycle/list?offset=0&limit=1000",
                    "notes": "lists recycle items belonging to this token workspace",
                    "query": {
                        "offset": 0,
                        "limit": 1000,
                        **optional_read_context_query,
                    },
                },
                "recycle_restore": {
                    "method": "POST",
                    "url": f"{base}/recycle/restore",
                    "json": {"recycle_id": "<recycle_id>", "plan_id": "<required owning plan id>", "taskname": "<required task grouping name>", "message": "<required brief operation summary>"},
                    "notes": "restores to the original path and refuses to overwrite an existing path",
                },
                "share_create": {
                    "method": "POST",
                    "url": f"{base}/shares",
                    "authentication": "Bearer control token",
                    "json": {
                        "path": "<one file or directory inside this token workspace>",
                        "plan_id": "<required owning plan id>",
                        "taskname": "<required task grouping name>",
                        "message": "<required brief operation summary>",
                    },
                    "response": {
                        "share_id": "random 22-character read-only capability ID",
                        "query_url": f"{share_public_base}/<share_id>",
                        "expires_at": "UTC timestamp",
                    },
                    "notes": "copies exactly one workspace file or directory; the workspace root, extra authorized paths, symlinks, and private internal directories are rejected",
                },
                "share_query": {
                    "method": "GET",
                    "url": f"{share_public_base}/<share_id>?path=<relative-path>&depth=1",
                    "authentication": "none; possession of share_id grants read-only metadata listing",
                    "notes": "returns ls-like names, paths, types, sizes, and modification times; expired, evicted, deleted, and invalid IDs return 404 without revealing their prior state",
                },
                "share_import": {
                    "method": "POST",
                    "url": f"{base}/shares/<share_id>/import",
                    "authentication": "destination Bearer control token",
                    "json": {
                        "destination": "<new path inside this token workspace>",
                        "create_parents": False,
                        "plan_id": "<required owning plan id>",
                        "taskname": "<required task grouping name>",
                        "message": "<required brief operation summary>",
                    },
                    "notes": "the destination token may differ from the creator; existing destinations are never overwritten",
                },
                "share_delete": {
                    "method": "DELETE",
                    "url": f"{base}/shares/<share_id>",
                    "authentication": "creator Bearer control token",
                    "request_headers": {
                        "OpenKapsel-Plan-Id": "<required owning plan id>",
                        "OpenKapsel-Taskname": "<required task grouping name>",
                        "OpenKapsel-Message": "<required brief operation summary>",
                    },
                    "notes": "deletes a share early; only the stable token application that created it can do this, including after that token is regenerated",
                },
                "upload_create": {
                    "method": "POST",
                    "url": f"{base}/uploads",
                    "json": {
                        "path": "<path>",
                        "size": 0,
                        "sha256": None,
                        "create_parents": False,
                        "plan_id": "<required owning plan id>",
                        "taskname": "<required task grouping name>",
                        "message": "<required brief operation summary>",
                    },
                    "notes": "creates a new file only; recycle an existing destination before uploading; MCP start_upload results also include token-free control-authenticated raw-transfer URLs",
                },
                "upload_status": {
                    "method": "GET or HEAD",
                    "url": f"{base}/uploads/<upload_id>",
                    "query": {**optional_read_context_query},
                },
                "upload_chunk": {
                    "method": "PATCH",
                    "url": f"{base}/uploads/<upload_id>",
                    "content_type": "application/octet-stream",
                    "headers": {"Upload-Offset": "<current offset>", "OpenKapsel-Plan-Id": "<required owning plan id>", "OpenKapsel-Taskname": "<required task grouping name>", "OpenKapsel-Message": "<required brief operation summary>"},
                },
                "upload_commit": {"method": "POST", "url": f"{base}/uploads/<upload_id>/commit", "request_headers": {"OpenKapsel-Plan-Id": "<required owning plan id>", "OpenKapsel-Taskname": "<required task grouping name>", "OpenKapsel-Message": "<required brief operation summary>"}},
                "upload_cancel": {"method": "DELETE", "url": f"{base}/uploads/<upload_id>", "request_headers": {"OpenKapsel-Plan-Id": "<required owning plan id>", "OpenKapsel-Taskname": "<required task grouping name>", "OpenKapsel-Message": "<required brief operation summary>"}},
                "mcp": {
                    "method": "POST",
                    "url": f"{base}/mcp",
                    "transport": "Streamable HTTP (stateless JSON responses; GET SSE is not offered)",
                },
                "shell_exec": {
                    "method": "POST",
                    "url": f"{base}/shell/exec",
                    "json": {
                        "command": "<shell command>",
                        "cwd": "<path inside root>",
                        "timeout_seconds": None,
                        "interactive": False,
                        "plan_id": "<required owning plan id>",
                        "taskname": "<required task grouping name>",
                        "message": "<required brief operation summary>",
                    },
                },
                "task_list": {
                    "method": "GET",
                    "url": f"{base}/tasks?offset=0&limit=100&status=running",
                    "query": {
                        "offset": 0,
                        "limit": 100,
                        "status": "running or finished; omit for all",
                        **optional_read_context_query,
                    },
                },
                "task_status": {
                    "method": "GET",
                    "url": f"{base}/tasks/<task_id>",
                    "query": {**optional_read_context_query},
                },
                "task_output": {
                    "method": "GET",
                    "url": f"{base}/tasks/<task_id>/output?stdout_offset=0&stderr_offset=0&wait_seconds=20",
                    "query": {
                        "stdout_offset": 0,
                        "stderr_offset": 0,
                        "limit": 65536,
                        "wait_seconds": 0,
                        **optional_read_context_query,
                    },
                },
                "task_stream": {
                    "method": "GET",
                    "url": f"{base}/tasks/<task_id>/stream?stdout_offset=0&stderr_offset=0",
                    "content_type": "text/event-stream",
                    "events": ["output", "done", "reconnect"],
                    "notes": "reconnect closes a duration-limited stream and returns the exact stdout/stderr offsets to use for the next request; concurrent streams are bounded globally and per token",
                    "query": {
                        "stdout_offset": 0,
                        "stderr_offset": 0,
                        **optional_read_context_query,
                    },
                },
                "task_stdin": {
                    "method": "POST",
                    "url": f"{base}/tasks/<task_id>/stdin",
                    "json": {
                        "data": "<optional UTF-8 input>",
                        "data_base64": "<optional Base64 input; mutually exclusive with data>",
                        "close": False,
                        "plan_id": "<required owning plan id>",
                        "taskname": "<required task grouping name>",
                        "message": "<required brief operation summary>",
                    },
                },
                "task_interrupt": {
                    "method": "POST",
                    "url": f"{base}/tasks/<task_id>/interrupt",
                    "request_headers": {"OpenKapsel-Plan-Id": "<required owning plan id>", "OpenKapsel-Taskname": "<required task grouping name>", "OpenKapsel-Message": "<required brief operation summary>"},
                    "notes": "sends SIGTERM, then SIGKILL after a two-second grace period",
                },
                "task_kill": {
                    "method": "POST",
                    "url": f"{base}/tasks/<task_id>/kill",
                    "request_headers": {"OpenKapsel-Plan-Id": "<required owning plan id>", "OpenKapsel-Taskname": "<required task grouping name>", "OpenKapsel-Message": "<required brief operation summary>"},
                    "notes": "immediately sends SIGKILL to the process group",
                },
                "sandbox_processes": {
                    "method": "GET",
                    "url": f"{base}/sandbox/processes?offset=0&limit=100",
                    "notes": "lists host-visible processes inside this token's restricted-shell cgroup, with aggregate CPU, memory, PID, and OOM counters",
                    "query": {
                        "offset": 0,
                        "limit": 100,
                        **optional_read_context_query,
                    },
                },
            },
            "workflow": [
                "The URL token is read-only. Send Authorization: Bearer <CONTROL_TOKEN> for Context access, mutations, uploads, MCP, Shell, task control, and sandbox process inspection.",
                "REST Skill clients should invoke the installed scripts/openkapsel_config.py init <workspace-url> <control-token> by its Skill path while the working directory is the local controlling project to create a mode-0600 .openkapsel.env there. Resolve the nearest file from the current directory so changing project directories selects different workspaces; explicit helper arguments and the legacy process environment remain supported.",
                "When credentials have less than two days remaining, call credentials_renew once and atomically replace both values in .openkapsel.env with the returned workspace_url and control_token. The bundled helpers perform this check and update automatically for directory-scoped configuration.",
                "Skill-capable REST clients should inspect skills.openkapsel_rest and may install its token-free SHA-256-verified archive or read the linked SKILL.md remotely before loading detailed endpoint contracts.",
                "Before changing the workspace, query context with type=plan&root_plans=true&status=in_progress. Reuse a suitable plan tree or create one root plan by POST context/add_context with type=plan and no plan_id.",
                "At task start, read memory_project/get_project_memory when project-wide knowledge is needed. When creating a plan, provide scope_paths and memory_tags when known; OpenKapsel returns related_memory using path overlap, exact tags, and text relevance.",
                "Decompose a root plan by creating sub-plans whose plan_id is the parent plan's integer id. Use context_plan_tree/get_plan_tree to inspect the depth-annotated hierarchy and its attached operations/notes.",
                "Every modifying REST or MCP operation must provide plan_id, taskname, and a short message. plan_id must identify the plan or sub-plan that owns the action; OpenKapsel rejects missing, nonexistent, non-plan, self-referential, and cyclic relationships before changing the workspace.",
                "Reads should normally omit taskname, message, and plan_id and are then not recorded. To record a read, provide taskname and message; plan_id is optional but recommended to attach it to the relevant plan.",
                "Use context_query/query_context to filter history by direct plan_id, root plans, text, integer id, exact taskname, anonymous actor_id, or exact recorded path. Plans update in place and move through in_progress, completed, or cancelled; replacing a note creates a newer id and removes the old row.",
                "Use memory_query/query_memory for long-lived project knowledge. Create or revise Memory when a fact, convention, decision, architecture rule, or reusable known-issue lesson should survive the current task. Tags are exact indexed retrieval keys; paths scope a Memory to relevant workspace areas.",
                "Completing a plan requires debrief with summary, outcome, and memory_actions. Use an empty memory_actions array when nothing deserves long-term retention; otherwise create, update, resolve, or archive Memory in the same completion request.",
                "MCP clients should initialize the mcp endpoint, call tools/list, and then use tools/call; REST clients can use the endpoints below directly.",
                "Inspect the workspace first with list_files/fs_list and read_file/fs_read.",
                "Open the web_preview endpoint URL to preview workspace HTML and its relative CSS, JavaScript, images, fonts, or media in a sandboxed browser document.",
                "Implement registration, login, roles, cookies, sessions, CSRF, and access control directly in the workspace FastAPI application when the site needs them; OpenKapsel does not add an authentication layer.",
                "For persistent application data, define a FastAPI route in <app-directory>/api/app.py and use openkapsel_runtime.database.engine('main') or database.session('main') with portable SQLAlchemy APIs; each app gets private .sql storage in its parent directory, while browser code calls /<app-path>/api/* and never accesses database storage directly.",
                "Use list_tree/fs_tree for a bounded recursive overview and search_files/fs_search for cross-file text search.",
                "Request sha256 explicitly from stat_file/fs_stat only when content verification is needed.",
                "Use fs_stat before transferring files; MCP clients can call prepare_download for a token-free control-authenticated fs_content URL, then stream binary or large downloads with HTTP Range.",
                "Use direct fs_content PUT for small binary files, or create an upload session for large files; MCP start_upload returns raw_transfer URLs so bytes do not need Base64 encoding.",
                "Uploads never overwrite. To replace a file, first use delete_path/fs_delete so its previous version is retained in .recycle, then upload the new file.",
                "Create directories with create_directory/fs_mkdir, and move or rename paths with move_path/fs_move.",
                "Prefer replace_text/fs_replace for one focused edit. Use fs_replace_batch for multiple exact non-overlapping replacements in one or more files; all rules match each file's original text. Use write_file/fs_write for complete file creation or replacement, and pass expected_etag to prevent overwriting a concurrent change.",
                "Use delete_path/fs_delete for recoverable deletion, list_recycle/recycle_list to inspect deleted items, and restore_recycle/recycle_restore to recover them.",
                "For cross-workspace transfer, create_share/share_create copies one file or directory and returns a one-day random share_id. The recipient can inspect it with the public share_query endpoint and import it with import_share/share_import using only that ID plus the recipient workspace's own control token; imports never overwrite.",
                "Run tests or builds with run_shell/shell_exec; list tasks, read output incrementally, and send input to interactive tasks.",
                "For restricted Shell, inspect this token's live sandbox processes and aggregate resource usage with list_sandbox_processes/sandbox_processes.",
                "Use interrupt_task/task_interrupt for normal termination; reserve kill_task/task_kill for an unresponsive task that must stop immediately.",
            ],
        }

        missing_contract_docs = discovery_keys() - payload["endpoints"].keys()
        if missing_contract_docs:
            raise RuntimeError(
                "endpoint contract is missing Discovery entries: "
                + ", ".join(sorted(missing_contract_docs))
            )
        endpoint_permissions = {
            "discovery_section": ("URL token", True),
            "credentials_renew": ("Bearer control token", control_authorized),
            "context_query": (
                "Bearer control token + files.read",
                control_authorized and read_enabled,
            ),
            "context_plan_tree": (
                "Bearer control token + files.read",
                control_authorized and read_enabled,
            ),
            "context_add": ("Bearer control token", control_authorized),
            "context_plan_update": ("Bearer control token", control_authorized),
            "context_note_replace": ("Bearer control token", control_authorized),
            "memory_query": (
                "Bearer control token + files.read",
                control_authorized and read_enabled,
            ),
            "memory_project": (
                "Bearer control token + files.read",
                control_authorized and read_enabled,
            ),
            "memory_add": ("Bearer control token", control_authorized),
            "memory_item": ("Bearer control token", control_authorized),
            "memory_revisions": (
                "Bearer control token + files.read",
                control_authorized and read_enabled,
            ),
            "web_preview": (
                "files.read + web_preview",
                read_enabled and self.token_record.can_preview,
            ),
            "web_app_api": (
                "web_preview",
                self.token_record.can_preview,
            ),
            "fs_list": ("files.read", read_enabled),
            "fs_read": ("files.read", read_enabled),
            "fs_stat": ("files.read", read_enabled),
            "fs_manifest": ("files.read", read_enabled),
            "fs_search": ("files.read", read_enabled),
            "fs_tree": ("files.read", read_enabled),
            "fs_content": ("files.read", read_enabled),
            "fs_content_put": ("Bearer control token + files.write", write_enabled),
            "fs_write": ("Bearer control token + files.write", write_enabled),
            "fs_replace": ("Bearer control token + files.write", write_enabled),
            "fs_replace_batch": ("Bearer control token + files.write", write_enabled),
            "fs_mkdir": ("Bearer control token + files.write", write_enabled),
            "fs_delete": (
                "Bearer control token + files.write + recycle",
                write_enabled and recycle_enabled,
            ),
            "fs_delete_batch": (
                "Bearer control token + files.write + recycle",
                write_enabled and recycle_enabled,
            ),
            "fs_move": ("Bearer control token + files.write", write_enabled),
            "recycle_list": ("files.read + recycle", read_enabled and recycle_enabled),
            "recycle_restore": (
                "Bearer control token + files.write + recycle",
                write_enabled and recycle_enabled,
            ),
            "upload_create": ("Bearer control token + files.write", write_enabled),
            "upload_status": ("Bearer control token + files.write", write_enabled),
            "upload_chunk": ("Bearer control token + files.write", write_enabled),
            "upload_commit": ("Bearer control token + files.write", write_enabled),
            "upload_cancel": ("Bearer control token + files.write", write_enabled),
            "share_create": ("Bearer control token + files.read", control_authorized and read_enabled),
            "share_query": ("share_id capability; no workspace token", True),
            "share_import": ("destination Bearer control token + files.write", write_enabled),
            "share_delete": ("creator Bearer control token", control_authorized),
            "mcp": ("Bearer control token", control_authorized),
            "shell_exec": ("Bearer control token + shell", shell_enabled),
            "task_list": ("Bearer control token + shell", shell_enabled),
            "task_status": ("Bearer control token + shell", shell_enabled),
            "task_output": ("Bearer control token + shell", shell_enabled),
            "task_stream": ("Bearer control token + shell", shell_enabled),
            "task_stdin": ("Bearer control token + shell", shell_enabled),
            "task_interrupt": ("Bearer control token + shell", shell_enabled),
            "task_kill": ("Bearer control token + shell", shell_enabled),
            "sandbox_processes": (
                "Bearer control token + restricted shell",
                control_authorized and self.token_record.shell_mode == "restricted",
            ),
        }
        for name, endpoint in payload["endpoints"].items():
            capability, available = endpoint_permissions.get(name, ("token", True))
            endpoint["required_capability"] = capability
            endpoint["available"] = available
        if not control_authorized:
            privileged_endpoints = {
                "credentials_renew",
                "fs_content_put",
                "context_query",
                "context_plan_tree",
                "context_add",
                "context_plan_update",
                "context_note_replace",
                "memory_query",
                "memory_project",
                "memory_add",
                "memory_item",
                "memory_revisions",
                "fs_write",
                "fs_replace",
                "fs_replace_batch",
                "fs_mkdir",
                "fs_delete",
                "fs_delete_batch",
                "fs_move",
                "recycle_restore",
                "upload_create",
                "upload_status",
                "upload_chunk",
                "upload_commit",
                "upload_cancel",
                "share_create",
                "share_import",
                "share_delete",
                "mcp",
                "shell_exec",
                "task_list",
                "task_status",
                "task_output",
                "task_stream",
                "task_stdin",
                "task_interrupt",
                "task_kill",
                "sandbox_processes",
            }
            for name in privileged_endpoints:
                endpoint = payload["endpoints"][name]
                payload["endpoints"][name] = {
                    "method": endpoint["method"],
                    "url": endpoint["url"],
                    "required_capability": endpoint["required_capability"],
                    "available": False,
                    "details": "redacted until a matching Bearer control token is supplied",
                }
        return payload

    def _mcp_workspace_info(self, section: str = "main") -> dict[str, Any]:
        """Return Discovery metadata without echoing the capability token into MCP logs."""
        payload = self._discovery(section)
        base = self._base_path()
        payload["authentication"]["control_authorized"] = True
        payload["authentication"]["control_token"] = "<redacted>"
        payload["index_url"] = "./"
        payload["full_url"] = "./discovery/full"
        for name, endpoint in payload["endpoints"].items():
            url = endpoint.get("url")
            if name in {"web_preview", "web_app_api"}:
                suffix = (
                    "<app-path>/api/<route>" if name == "web_app_api"
                    else "<workspace-relative-path>"
                )
                if self.server.config.preview_base_url:
                    endpoint["url"] = (
                        f"{self.server.config.preview_base_url.rstrip('/')}/"
                        f"<PREVIEW_TOKEN>/{suffix}"
                    )
                else:
                    endpoint["url"] = f"../<PREVIEW_TOKEN>/{suffix}"
            elif name == "share_query":
                endpoint["url"] = "./../../shares/<share_id>?path=<relative-path>&depth=1"
            elif isinstance(url, str) and url.startswith(base):
                endpoint["url"] = "." + url[len(base) :]
        return payload

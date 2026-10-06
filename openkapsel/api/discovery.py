"""Self-describing Discovery document builders."""

from __future__ import annotations

import os
from http import HTTPStatus
from typing import Any
from urllib.parse import quote

from openkapsel.context.conversation import (
    DEFAULT_RECENT_CONVERSATION_COUNT,
    MAX_CONVERSATION_QUERY_LIMIT,
    CONVERSATION_SUMMARY_PROMPT_AFTER,
    CONVERSATION_SUMMARY_REQUIRED_AFTER,
)
from openkapsel.context.context_store import (
    CONTEXT_TRIM_ENTRIES,
    MAX_CONTEXT_OPERATION_MESSAGE_CHARS,
    MAX_CONTEXT_ENTRIES,
    MAX_CONTEXT_QUERY_LIMIT,
    MAX_CONTEXT_TASKNAME_CHARS,
    MAX_PLAN_HINT_CONTENT_CHARS,
    MAX_UNFINISHED_ROOT_PLAN_HINTS,
)
from openkapsel.api.discovery_sections import (
    SECTION_CAPABILITIES,
    SECTION_ENDPOINTS,
    SECTION_LIMITS,
    SECTION_NAMES,
    SECTION_SUMMARIES,
    SECTION_WORKFLOWS,
)
from openkapsel.errors import ApiError
from openkapsel.auth.oauth_consent import consent_metadata
from openkapsel.files.mutation import (
    LARGE_FILE_WINDOW_MAX_BYTES,
    SMALL_FILE_MAX_BYTES,
    STANDARD_FILE_MAX_BYTES,
)
from openkapsel.execution.environment_store import (
    EnvironmentStore,
    MAX_ENVIRONMENT_NAME_CHARS,
    MAX_ENVIRONMENT_RC_CHARS,
    MAX_ENVIRONMENT_TOTAL_CHARS,
    MAX_ENVIRONMENT_VALUE_CHARS,
    MAX_ENVIRONMENT_VARIABLES,
    RESERVED_ENVIRONMENT_NAMES,
)
from openkapsel.api.mcp import (
    MCP_PROTOCOL_VERSION,
    PUBLIC_SERVER_VERSION,
    SERVER_VERSION,
    SUPPORTED_PROTOCOL_VERSIONS,
    auxiliary_operations_for,
    tools_for,
)
from openkapsel.contract import (
    MAX_CONVERSATION_CONTENT_CHARS,
    MAX_CONVERSATION_SUMMARY_CHARS,
    MAX_MEMORY_CONTENT_CHARS,
    MAX_PLAN_REQUEST_BYTES,
    PLAN_COMPLETION_MEMORY_GUIDANCE,
    PLAN_STATUSES,
    MAX_PLAN_REQUESTS,
    MAX_SUBPLANS,
    MEMORY_ACTIONS,
    memory_actions_schema,
    mutation_item_example,
    mutation_item_schema,
    mutation_operation_contracts,
    plan_creation_properties,
    plan_debrief_schema,
)
from openkapsel.context.memory_store import (
    MAX_MEMORY_QUERY_LIMIT,
    MAX_MEMORY_RELATED_CANDIDATES,
    MAX_MEMORY_REVISION_LIMIT,
)
from openkapsel.routes import discovery_keys, discovery_route_metadata
from openkapsel.execution.scheduler_store import (
    MAX_ACTIVE_SCHEDULES_PER_APP,
    MAX_SCHEDULE_RUNS_PER_SCHEDULE,
    MIN_SCHEDULE_INTERVAL_MINUTES,
    SCHEDULE_RUN_RETENTION_DAYS,
)
from openkapsel.api.skill_handlers import skill_discovery
from openkapsel.workspace.workspace_images import WorkspaceImageError


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
            result = full
        elif requested == "main":
            result = self._main_discovery(full)
        else:
            result = self._section_discovery(full, requested)
        if getattr(self, "oauth_connection_id", None) or getattr(self, "static_mcp_connection_id", None):
            return result
        return self._rest_discovery(result)

    @staticmethod
    def _rest_discovery(payload):
        """Keep REST Discovery incremental and free of MCP-only configuration.

        The main document is the shared preamble. Section documents are deltas: clients
        that follow the advertised workflow read main once, then load only the sections
        needed for the current task. Do not repeat shared authentication, Skill, default,
        or error metadata in every section.
        """
        section = str(payload.get("section", "main"))
        payload.get("endpoints", {}).pop("mcp", None)
        payload.get("authentication", {}).pop("mcp_requires_control_token", None)
        payload.get("limits", {}).pop("max_mcp_binary_chunk_bytes", None)
        capabilities = payload.get("capabilities", {})
        capabilities.pop("mcp", None)
        transfer = capabilities.get("binary_transfer", {})
        for key in list(transfer):
            if key.startswith("mcp_"):
                transfer.pop(key)
        if "workflow" in payload:
            payload["workflow"] = [
                item.replace("REST or MCP", "REST").replace("REST and MCP", "REST").replace(", MCP,", ",")
                for item in payload["workflow"] if not item.startswith("MCP ")
            ]

        if section == "main":
            # Main is an index plus the shared REST preamble. Detailed capability, limit,
            # path, and error contracts live only in their authoritative sections.
            for key in ("request_transport", "path_rules", "capabilities", "limits", "errors"):
                payload.pop(key, None)
            payload.get("sections", {}).pop("mcp", None)
            endpoints = payload.get("endpoints", {})
            for key in list(endpoints):
                if key not in {"discovery", "credential"}:
                    endpoints.pop(key)
            payload["bootstrap"] = [
                "On first use of a workspace, query the most recent Conversation context first and use it to restore recent user/AI context.",
                "Then query active root Plans and reuse the relevant Plan when possible.",
                "Load relevant Memory before starting work that depends on durable cross-task facts.",
            ]
            payload["mutation_core"] = {
                "sections": ["context", "memory", "files"],
                "context_covers": ["conversation", "plan"],
                "rule": "Load these sections before workspace mutation; section contracts are authoritative.",
            }
            payload["workflow"] = [
                "Read main once for shared authentication, token, Skill, endpoint-default metadata, bootstrap order, and mutation-core section requirements.",
                "Load optional sections only when their capability is needed; use discovery/full only for compatibility or comprehensive inspection.",
            ]
        elif section != "full":
            # Section documents inherit this shared preamble from main. Keep only minimal
            # routing identity plus section-specific contracts.
            for key in (
                "server_version", "name", "os", "root", "authentication",
                "token", "skills", "endpoint_defaults", "errors",
            ):
                payload.pop(key, None)
            payload["inherits"] = "main"
        return payload

    @staticmethod
    def _compact_endpoint_families(endpoints: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
        def operation(
            source: str,
            *,
            method: str | None = None,
            path: str | None = None,
            description: str | None = None,
        ) -> dict[str, Any]:
            endpoint = endpoints[source]
            item: dict[str, Any] = {
                "method": method or endpoint.get("method"),
                "available": endpoint.get("available", True),
                "required_capability": endpoint.get("required_capability", "token"),
            }
            if path is not None:
                item["path"] = path
            if not item["available"]:
                if endpoint.get("details"):
                    item["details"] = endpoint["details"]
                return item
            query = endpoint.get("query")
            if isinstance(query, dict):
                item["query_fields"] = sorted(query)
            body = endpoint.get("json")
            if not isinstance(body, dict):
                body = endpoint.get("body")
            if isinstance(body, dict):
                item["body_fields"] = sorted(body)
                if source == "fs_mutate":
                    item["item_schema"] = mutation_item_schema()
                    item["operation_contracts"] = mutation_operation_contracts()
                    item["item_example"] = mutation_item_example()
            headers = endpoint.get("request_headers")
            if not isinstance(headers, dict):
                headers = endpoint.get("headers")
            if isinstance(headers, dict):
                item["header_fields"] = sorted(headers)
            for key in ("plan_extension_schema", "events"):
                if key in endpoint:
                    item[key] = endpoint[key]
            if description:
                item["description"] = description
            return item

        def family(
            path: str,
            description: str,
            operations: dict[str, dict[str, Any]],
        ) -> dict[str, Any]:
            result: dict[str, Any] = {
                "path": path,
                "description": description,
                "operations": operations,
            }
            defaults = {
                "available": True,
                "required_capability": "token",
            }
            for key, default in defaults.items():
                values = [operation.get(key, default) for operation in operations.values()]
                if values and all(value == values[0] for value in values):
                    common = values[0]
                    for operation in operations.values():
                        operation.pop(key, None)
                    if common != default:
                        result[key] = common
                    continue
                for operation in operations.values():
                    if operation.get(key, default) == default:
                        operation.pop(key, None)
            return result

        return {
            "discovery": family(
                "./discovery/<section>",
                "Discovery index and split capability sections.",
                {
                    "main": operation("discovery", path="./"),
                    "section": operation("discovery_section"),
                },
            ),
            "transport": family(
                "./transport/hmac",
                "GET-only helpers for constrained transports.",
                {"hmac": operation("transport_hmac")},
            ),
            "credential": family(
                "./credential/renew",
                "Workspace REST credential lifecycle.",
                {"renew": operation("credential_renew")},
            ),
            "rpc": family(
                "./rpc/<family>/<operation>",
                "Generic plugin RPC for server or mapped execution targets.",
                {
                    "server": operation("server_rpc"),
                    "mapping": operation(
                        "mapping_rpc",
                        path="./mapping/<mapping_name>/rpc/<family>/<operation>",
                    ),
                },
            ),
            "mapping": family(
                "./mapping",
                "Mapping discovery and client capability inspection.",
                {"list": operation("mapping_list")},
            ),
            "fs_query": family(
                "./fs/query/<operation>",
                "File metadata, tree, filename find, content grep, and manifest queries.",
                {
                    "list": operation("fs_list"),
                    "stat": operation("fs_stat"),
                    "tree": operation("fs_tree"),
                    "find": operation("fs_find"),
                    "grep": operation("fs_grep"),
                    "manifest": operation("fs_manifest"),
                },
            ),
            "fs_read": family(
                "./fs/read/<operation>",
                "Text-file batches and bounded large-file reads.",
                {
                    "files": operation("fs_read_files"),
                    "large": operation("fs_read_large"),
                },
            ),
            "fs_content": family(
                "./fs/content",
                "Raw Range streaming and direct create-only byte upload.",
                {
                    "read": operation("fs_content"),
                    "write": operation("fs_content_put"),
                },
            ),
            "fs_write": family(
                "./fs/write/<operation>",
                "Guarded file mutations and path changes.",
                {
                    "mutate": operation("fs_mutate"),
                    "replace_large": operation("fs_replace_large"),
                    "mkdir": operation("fs_mkdir"),
                    "move": operation("fs_move"),
                    "copy": operation("fs_copy"),
                },
            ),
            "transfer": family(
                "./fs/transfer/<transfer_id>",
                "Asynchronous copy/move transfer progress and control.",
                {
                    "get": operation("file_transfer", method="GET"),
                    "cancel": operation(
                        "file_transfer",
                        method="POST",
                        path="./fs/transfer/cancel/<transfer_id>",
                    ),
                    "resume": operation(
                        "file_transfer",
                        method="POST",
                        path="./fs/transfer/resume/<transfer_id>",
                    ),
                },
            ),
            "recycle": family(
                "./recycle/<operation>",
                "Workspace or mapping recycle inspection, restore, and purge.",
                {
                    "list": operation("recycle_list"),
                    "restore": operation("recycle_restore"),
                    "purge": operation("recycle_purge"),
                },
            ),
            "upload": family(
                "./upload/<operation>[/<upload_id>]",
                "Resumable create-only upload sessions.",
                {
                    "create": operation("upload_create"),
                    "status": operation("upload_status", path="./upload/status/<upload_id>"),
                    "chunk": operation("upload_chunk", path="./upload/chunk/<upload_id>"),
                    "commit": operation("upload_commit", path="./upload/commit/<upload_id>"),
                    "cancel": operation("upload_cancel", path="./upload/cancel/<upload_id>"),
                },
            ),
            "share": family(
                "./share/<operation>[/<share_id>]",
                "Temporary cross-workspace file/directory sharing.",
                {
                    "create": operation("share_create", path="./share/create"),
                    "query": operation(
                        "share_query",
                        path=endpoints["share_query"].get("url"),
                    ),
                    "import": operation("share_import", path="./share/import/<share_id>"),
                    "delete": operation("share_delete", path="./share/<share_id>"),
                },
            ),
            "environment": family(
                "./env",
                "App-identity-scoped Shell environment configuration.",
                {
                    "get": operation("environment_get"),
                    "replace": operation("environment_replace"),
                    "clear": operation("environment_clear"),
                },
            ),
            "shell": family(
                "./shell/exec",
                "Shell execution and restricted-sandbox process inspection.",
                {
                    "exec": operation("shell_exec"),
                    "processes": operation(
                        "sandbox_processes",
                        path="./sandbox/processes",
                    ),
                },
            ),
            "task": family(
                "./task/<operation>[/<task_id>]",
                "Server/unified task listing, output, streaming, and control.",
                {
                    "list": operation("task_list", path="./task/list"),
                    "get": operation("task_get", path="./task/get/<task_id>"),
                    "output": operation("task_output", path="./task/output/<task_id>"),
                    "stream": operation(
                        "task_stream",
                        path="./task/stream/<task_id>",
                        description=endpoints.get("task_stream", {}).get("notes"),
                    ),
                    "stdin": operation("task_stdin", path="./task/stdin/<task_id>"),
                    "interrupt": operation(
                        "task_interrupt",
                        path="./task/interrupt/<task_id>",
                        description=endpoints.get("task_interrupt", {}).get("notes"),
                    ),
                    "kill": operation(
                        "task_kill",
                        path="./task/<task_id>",
                        description=endpoints.get("task_kill", {}).get("notes"),
                    ),
                },
            ),
            "schedule": family(
                "./schedule[/<schedule_id>]",
                "Persistent Shell schedules and dispatch history.",
                {
                    "list": operation("schedule_list"),
                    "create": operation("schedule_create"),
                    "get": operation("schedule_get"),
                    "update": operation("schedule_update"),
                    "delete": operation("schedule_delete"),
                    "execute": operation(
                        "schedule_execute",
                        path="./schedule/execute/<schedule_id>",
                    ),
                    "pause": operation(
                        "schedule_pause",
                        path="./schedule/pause/<schedule_id>",
                    ),
                    "resume": operation(
                        "schedule_resume",
                        path="./schedule/resume/<schedule_id>",
                    ),
                    "run_list": operation(
                        "schedule_run_list",
                        path="./schedule/run/list/<schedule_id>",
                    ),
                    "run_get": operation(
                        "schedule_run_get",
                        path="./schedule/run/<run_id>",
                    ),
                },
            ),
            "context": family(
                "./context",
                "Operation history, plans, and notes.",
                {
                    "query": operation("context_query"),
                    "add": operation("context_add"),
                    "plan_tree": operation(
                        "context_plan_tree",
                        path="./context/plans/<plan_id>/tree",
                    ),
                    "plan_update": operation(
                        "context_plan_update",
                        path="./context/plans/<plan_id>",
                    ),
                    "note_replace": operation(
                        "context_note_replace",
                        path="./context/notes/<note_id>",
                    ),
                },
            ),
            "conversation": family(
                "./conversation",
                "Append-only user/ai conversation summaries with periodic summary checkpoints.",
                {
                    "query": operation("conversation_query"),
                    "create": operation("conversation_create"),
                    "append": operation(
                        "conversation_append",
                        path="./conversation/<conversation_id>/entries",
                    ),
                },
            ),
            "memory": family(
                "./memory",
                "Revisioned project Memory.",
                {
                    "query": operation("memory_query"),
                    "project": operation(
                        "memory_project",
                        path="./memory/project",
                    ),
                    "add": operation("memory_add"),
                    "get": operation(
                        "memory_item",
                        method="GET",
                        path="./memory/<memory_id>",
                    ),
                    "update": operation(
                        "memory_item",
                        method="PATCH",
                        path="./memory/<memory_id>",
                    ),
                    "archive": operation(
                        "memory_item",
                        method="DELETE",
                        path="./memory/<memory_id>",
                    ),
                    "revisions": operation(
                        "memory_revisions",
                        path="./memory/<memory_id>/revisions",
                    ),
                },
            ),
            "web": family(
                endpoints["web_preview"].get(
                    "url",
                    "<preview-base>/<preview-token>/<workspace-relative-path>",
                ),
                "Static preview and workspace FastAPI routes.",
                {
                    "preview": operation("web_preview"),
                    "api": operation(
                        "web_app_api",
                        path=endpoints["web_app_api"].get("url"),
                    ),
                },
            ),
            "mcp": family(
                "./mcp",
                "Streamable HTTP MCP endpoint.",
                {"call": operation("mcp")},
            ),
        }

    def _discovery_common(self, full: dict[str, Any], section: str) -> dict[str, Any]:
        return {
            key: full[key]
            for key in (
                "protocol", "server_version", "name", "os", "root",
                "authentication", "token", "skills", "endpoint_defaults",
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
            "transport": True,
            "files": bool(
                capabilities["files"]["read"] or capabilities["files"]["write"]
            ),
            "context": capabilities["context"]["enabled"],
            "memory": capabilities["memory"]["enabled"],
            "paths": bool(
                capabilities["files"]["read"] or capabilities["files"]["write"]
                or capabilities["shell"] != "none"
            ),
            "rpc": bool(
                capabilities["files"]["read"] or capabilities["files"]["write"]
            ),
            "network": bool(
                capabilities["shell"] != "none" or capabilities["web_preview"]["enabled"]
            ),
            "mcp": capabilities["mcp"]["enabled"],
            "shell": bool(
                capabilities["shell"] != "none"
                or capabilities["files"]["read"]
                or capabilities["files"]["write"]
            ),
            "schedules": capabilities["schedules"]["enabled"],
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
                "request_transport": {
                    "available": True,
                    "discovery_url": "./discovery/transport",
                    "summary": "GET-only query routing and signed transport fallback for constrained clients.",
                },
                "path_rules": {
                    "relative_paths_from": full["path_rules"]["relative_paths_from"],
                    "symlink_escape": full["path_rules"]["symlink_escape"],
                    "private_directories": [".openkapsel"],
                },
                "capabilities": {
                    "mappings": capabilities["mappings"],
                    "files": capabilities["files"],
                    "recycle": capabilities["recycle"],
                    "context": {"enabled": capabilities["context"]["enabled"]},
                    "memory": {"enabled": capabilities["memory"]["enabled"]},
                    "sharing": {
                        key: capabilities["sharing"][key]
                        for key in ("enabled", "create", "inspect_by_id", "import", "delete_own")
                    },
                    "shell": capabilities["shell"],
                    "schedules": {"enabled": capabilities["schedules"]["enabled"]},
                    "environment": {
                        "enabled": capabilities["environment"]["enabled"],
                        "configured": capabilities["environment"]["configured"],
                        "scope": capabilities["environment"]["scope"],
                    },
                    "network": capabilities["network"],
                    "web_preview": {"enabled": capabilities["web_preview"]["enabled"]},
                    "web_app_api": {
                        "enabled": capabilities["web_app_api"]["enabled"],
                        "sse": capabilities["web_app_api"]["sse"],
                    },
                    "mcp": {
                        "enabled": capabilities["mcp"]["enabled"],
                        "transport": capabilities["mcp"]["transport"],
                        "available_tool_count": len(capabilities["mcp"]["available_tools"]),
                        "dynamic_tool": capabilities["mcp"]["dynamic_tool"],
                        "dynamic_families": sorted(capabilities["mcp"]["operation_families"]),
                        "operation_specs_discovery": "./discovery/mcp",
                    },
                    "extra_paths_redacted": capabilities["extra_paths_redacted"],
                },
                "limits": {
                    key: full["limits"][key]
                    for key in (
                        "workspace_storage", "max_request_body_bytes", "max_file_bytes",
                        "file_size_tiers", "max_concurrent_transfers", "max_concurrent_shell_tasks_per_token",
                        "max_sse_streams_per_token", "max_sse_duration_seconds",
                        "http_socket_timeout_seconds",
                        "max_batch_file_operations",
                        "share_ttl_seconds", "max_share_entries", "max_share_bytes",
                        "max_operation_message_characters", "max_taskname_characters",
                        "max_environment_variables", "max_environment_name_characters",
                        "max_environment_value_characters", "max_environment_total_characters",
                        "max_environment_rc_characters",
                    )
                },
                "sections": sections,
                "endpoints": {
                    key: full["endpoints"][key]
                    for key in ("discovery", "credential", "environment", "mcp")
                    if key in full["endpoints"]
                },
                "workflow": [
                    "The URL token is read-only. Send Authorization: Bearer <CONTROL_TOKEN> for mutations, Context, Memory, MCP, Shell, schedules, and task control.",
                    "REST Skill clients should first invoke the installed scripts/openkapsel_config.py init <workspace-url> <control-token> by its Skill path while the working directory is the local controlling project; it creates a mode-0600 .openkapsel.env there. The nearest file follows the current working directory; explicit helper arguments and legacy process environment variables remain supported.",
                    "The bundled REST helpers automatically renew and atomically update directory-scoped credentials when less than two days remain; renewal rotates both workspace credentials for three more days and leaves the preview token unchanged.",
                    "Skill-capable REST clients should inspect skills.openkapsel_rest and may install its token-free SHA-256-verified archive or read the linked SKILL.md remotely before loading detailed endpoint contracts.",
                    "Read only the relevant discovery section before acting; use discovery/full only for compatibility or comprehensive inspection.",
                    "Before modifying a workspace, create or reuse a Context plan. Every modifying REST or MCP operation requires plan_id, taskname, and a brief message.",
                    "Configure server Shell variables and POSIX initialization with the control-authenticated env endpoint.",
                    "Start ordinary workspace work with discovery/files; use discovery/context and discovery/memory when coordinating or retaining project knowledge.",
                    "MCP clients use tools/list for core tool schemas. Low-frequency native capabilities use capability_call; load discovery/mcp only when their family/operation schemas are needed.",
                    "Use discovery/sharing for temporary cross-workspace transfer by random share ID.",
                ],
                "errors": full["errors"],
            }
        )
        return result

    def _section_discovery(self, full: dict[str, Any], section: str) -> dict[str, Any]:
        result = self._discovery_common(full, section)
        result["summary"] = SECTION_SUMMARIES[section]
        if section == "transport":
            result["request_transport"] = full["request_transport"]
        if section == "paths":
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
            from openkapsel.auth.admin_ui import render_discovery

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
            f"/share/query"
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
        schedules_enabled = shell_enabled and self.token_record.can_schedule
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
        mcp_operation_families = (
            auxiliary_operations_for(self.token_record, recycle_enabled)
            if control_authorized
            else {}
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
            "authentication": {
                "url_token": "read-only workspace capability",
                "control": "Authorization: Bearer <CONTROL_TOKEN>",
                "control_authorized": control_authorized,
                "mcp_requires_control_token": True,
                "credentials_expires_at": self.token_record.credentials_expires_at,
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
            "request_transport": {
                "summary": (
                    "Compatibility transport for constrained clients; prefer ordinary REST "
                    "paths and Authorization headers whenever the client supports them."
                ),
                "discovery_url": "./transport",
                "selection": {
                    "ordinary_rest": (
                        "preferred when the client can set the request path, HTTP method, "
                        "and Authorization header"
                    ),
                    "query_route": (
                        "use only when the client must keep the exact workspace root path "
                        "but can issue an ordinary GET request"
                    ),
                    "signed_get_envelope": (
                        "use only when the client is restricted to GET at the exact workspace "
                        "root and cannot send the required method or Authorization header"
                    ),
                    "hmac_helper": (
                        "use when the client can issue only bare GET requests and cannot compute "
                        "HMAC-SHA256 locally"
                    ),
                },
                "examples": {
                    "query_route": "GET <workspace_url>?req=fs/query/list&path=.",
                    "hmac_helper_path": "GET <workspace_url>transport/hmac?key=<url-encoded-key>&target=<url-encoded-target>",
                    "hmac_helper_query_route": "GET <workspace_url>?req=transport/hmac&key=<url-encoded-key>&target=<url-encoded-target>",
                    "signed_get_envelope": (
                        "GET <workspace_url>?req=context&timestamp=<unix-seconds>"
                        "&nonce=<8-alnum>&body=<url-encoded-json>&http_method=POST"
                        "&signature=<base64url-hmac>"
                    ),
                },
                "query_route": {
                    "available": True,
                    "outer_method": "GET",
                    "scope": "exact workspace root URL only",
                    "req_parameter": "req",
                    "req_format": "relative endpoint route without a leading slash",
                    "control_authorization": "not implied; ordinary endpoint authorization still applies",
                },
                "hmac_helper": {
                    "available": True,
                    "method": "GET",
                    "paths": ["./transport/hmac", "?req=transport/hmac"],
                    "authentication": "workspace read URL only; no Authorization header",
                    "required_parameters": ["key", "target"],
                    "algorithm": "HMAC-SHA256",
                    "input_encoding": "UTF-8 key and target strings after URL query decoding",
                    "result_encoding": "base64url without padding",
                    "max_key_bytes": 4096,
                    "max_target_bytes": 32768,
                    "side_effects": "none",
                    "response_cache": "no-store",
                    "logging": "OpenKapsel removes the complete query from its access log for both helper entry forms; upstream HTTP infrastructure may still log URLs",
                    "transport_use": "URL-encode the exact raw signed-envelope query prefix as target, then append the returned result as the final signature parameter without changing that prefix",
                },
                "signed_get_envelope": {
                    "available": True,
                    "outer_method": "GET",
                    "required_parameters": ["req", "timestamp", "nonce", "http_method", "signature"],
                    "optional_parameters": ["body"],
                    "http_method_position": "penultimate query parameter",
                    "signature_position": "final query parameter",
                    "signature_format": "base64url without padding",
                    "signature_algorithm": "HMAC-SHA256",
                    "signature_key": "matching control token",
                    "signed_bytes": "raw query string bytes before the final &signature= field; do not reorder or re-encode",
                    "query_encoding": "ASCII request-target; percent-encode UTF-8 values before signing",
                    "timestamp_format": "Unix time in whole seconds",
                    "timestamp_window_seconds": 300,
                    "nonce_format": "fresh random string of exactly 8 ASCII letters or digits",
                    "nonce_replay": "a nonce cannot be reused for the same credential identity inside the acceptance window",
                    "nonce_replay_scope": "process-local cache bounded to the remaining timestamp acceptance window",
                    "body": "optional URL-encoded UTF-8 JSON object for simple JSON-body endpoints",
                    "response_cache": "no-store",
                },
            },
            "path_rules": {
                "relative_paths_from": str(self.token_scope_root),
                "absolute_paths": "allowed inside the token workspace or an authorized extra directory",
                "symlink_escape": "rejected",
                "private_directory": ".openkapsel is reserved for runtime-managed recycle, database, Context, Memory, Shell-environment, and scheduler state",
                "private_directory_access": "hidden from file APIs, preview, application source mounts, restricted Shell, and sharing",
            },
            "token": {
                "name": self.token_record.name,
                "workspace_expires_at": self.token_record.expires_at,
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
                    "conversation": {
                        "append_only": True,
                        "identifier_field": "conversation_id",
                        "identifier_type": "non-negative integer",
                        "first_conversation_id": 0,
                        "caller_supplied_sequential_ids": True,
                        "create_id_must_equal_next_conversation_id": True,
                        "writer_nonce_returned_on_create": True,
                        "writer_nonce_usage": "retain the value returned by conversation_create and pass it back unchanged",
                        "roles": ["user", "ai", "summary"],
                        "ordinary_content_max_characters": MAX_CONVERSATION_CONTENT_CHARS,
                        "summary_content_max_characters": MAX_CONVERSATION_SUMMARY_CHARS,
                        "user_ai_context_may_retain_original_text": True,
                        "user_ai_context_need_not_be_recompressed_when_within_limit": True,
                        "summary_is_compressed_aggregate_checkpoint": True,
                        "summary_preserves_important_content": True,
                        "create_min_entries": 2,
                        "create_first_roles": ["user", "ai"],
                        "summary_prompt_after_user_ai_entries": CONVERSATION_SUMMARY_PROMPT_AFTER,
                        "summary_required_after_user_ai_entries": CONVERSATION_SUMMARY_REQUIRED_AFTER,
                        "summary_sub_id_fixed": False,
                        "summary_window_starts_at_latest_summary_or_one": True,
                        "append_returns_summary_status": True,
                        "conversation_id_query_max_entries": MAX_CONVERSATION_QUERY_LIMIT,
                        "cross_conversation_default_count": DEFAULT_RECENT_CONVERSATION_COUNT,
                        "cross_conversation_default_window": "newest non-empty conversation_ids; each whole window from newest summary entry (or sub_id 1) through latest entry",
                        "conversation_sub_id_range_supported": True,
                        "plan_create_requires_writer_nonce_and_entry": True,
                        "plan_update_requires_writer_nonce_and_entry": True,
                        "plan_complete_requires_ai_entry": True,
                        "plan_cancel_only_requires_writer_nonce": False,
                        "plan_and_conversation_append_atomic": True,
                    },
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
                    "plan_updates_require_current_revision": True,
                    "plan_completion_requires_no_in_progress_descendants": True,
                    "plan_creation_returns_unfinished_root_plans": True,
                    "plan_creation": {
                        "atomic_subplans": True, "max_direct_subplans": MAX_SUBPLANS,
                        "root_plan_requires_subplans_array": True,
                        "creation_status_must_be_omitted": True,
                        "creation_status_initial": "in_progress",
                        "subplan_root_immutable": True,
                        "subplan_creation_requires_in_progress_root": True,
                        "empty_root_subplans_allowed": True,
                        "max_normalized_request_bytes": MAX_PLAN_REQUEST_BYTES,
                        "child_taskname_inherits": True, "nested_subplans": False,
                        "child_refs": "optional unique request-local labels echoed beside IDs",
                        "request_id": "optional durable key scoped to workspace and stable actor; same normalized request returns original creation IDs",
                        "max_idempotency_keys_per_workspace": MAX_PLAN_REQUESTS,
                        "replay": "HTTP 200 with replayed=true and original creation fields; hints are refreshed; query current plan state separately",
                        "conflicts": ["context_request_conflict", "context_request_gone", "context_request_limit"],
                        "pruned_receipts": "used keys are never silently reused; reset only with the workspace Context database",
                        "memory_hints": "one lookup using combined content and union of paths/tags; at most 64 distinct paths and 32 tags across the request",
                    },
                    "unfinished_root_plan_hint_limit": MAX_UNFINISHED_ROOT_PLAN_HINTS,
                    "note_edits_create_new_id_and_delete_old": True,
                    "storage": "private OpenKapsel Context storage",
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
                    "storage": "private OpenKapsel Memory storage",
                    "separate_from_operation_log": True,
                    "semantic_fields": ["path", "content", "tags"],
                    "query_filters": [
                        "query",
                        "tag",
                        "path",
                        "include_archived",
                        "limit",
                    ],
                    "revisioned": True,
                    "updates_require_current_revision": True,
                    "soft_archive": True,
                    "tags_indexed": True,
                    "tags_required_on_create": True,
                    "recommended_tag_range": [4, 16],
                    "content_max_characters": MAX_MEMORY_CONTENT_CHARS,
                    "legacy_long_content_preserved_until_rewritten": True,
                    "path_scopes": ["server:<path>", "mapping:<mapping_id>:<path>", "storage:<provider_id>:<path>"],
                    "global_path_scope": "server:.",
                    "debrief_path_server_derived": True,
                    "change_message_max_chars": 200,
                    "helpful_feedback_affects_relevance": True,
                    "plan_creation_pushes_related_memory": True,
                    "plan_relevance_inputs": ["content", "scope_paths", "memory_tags"],
                    "plan_completion_requires_debrief": True,
                    "plan_completion_context_begin_immediate_before_memory": True,
                    "plan_completion_context_dry_run_before_memory": True,
                    "plan_completion_context_lock_held_through_memory_and_commit": True,
                    "plan_completion_memory_applied_before_context_commit": True,
                    "plan_completion_memory_mutations_atomic": True,
                    "plan_completion_memory_atomic_with_plan_conversation": False,
                    "plan_completion_memory_repairable_via_revisioned_update_or_archive": True,
                    "plan_completion_retry_should_reconcile_memory_first": True,
                    "empty_memory_actions_allowed": True,
                    "memory_action_enum": list(MEMORY_ACTIONS),
                    "memory_actions_schema": memory_actions_schema(),
                    "plan_debrief_schema": plan_debrief_schema(),
                    "operation_message_max_characters": MAX_CONTEXT_OPERATION_MESSAGE_CHARS,
                    "taskname_max_characters": MAX_CONTEXT_TASKNAME_CHARS,
                    "max_query_entries": MAX_MEMORY_QUERY_LIMIT,
                    "max_revision_entries": MAX_MEMORY_REVISION_LIMIT,
                    "related_candidate_entries": MAX_MEMORY_RELATED_CANDIDATES,
                },
                "mcp": {
                    "enabled": control_authorized,
                    "authentication": "Bearer control token",
                    "transport": "streamable-http",
                    "protocol_version": MCP_PROTOCOL_VERSION,
                    "supported_protocol_versions": sorted(SUPPORTED_PROTOCOL_VERSIONS),
                    "tools_list_method": "tools/list",
                    "available_tools": mcp_tool_names,
                    "dynamic_tool": "capability_call",
                    "operation_families": mcp_operation_families,
                },
                "shell": self.token_record.shell_mode if control_authorized else "none",
                "schedules": {
                    "enabled": schedules_enabled,
                    "authentication": "Bearer control token",
                    "separate_permission": True,
                    "types": ["once", "interval", "cron"],
                    "cron_fields": ["second", "minute", "hour", "day", "month", "weekday"],
                    "cron_second": "one explicit integer from 0 through 59",
                    "timezone": "IANA timezone name",
                    "overlap_policy": "skip",
                    "misfire_policies": ["skip", "coalesce"],
                    "context_per_run": True,
                    "credential_rotation_preserves_schedules": True,
                    "read_control_credential_expiry_stops_schedules": False,
                    "workspace_expiry_or_permission_revocation_stops_schedules": True,
                    "once_claimed_before_shell_start": True,
                    "same_once_id_cannot_be_reactivated_by_its_command": True,
                    "run_now_available": True,
                    "control_tokens_injected_into_shell": False,
                },
                "environment": {
                    "enabled": control_authorized,
                    "authentication": "Bearer control token",
                    "configured": (
                        EnvironmentStore(self.token_scope_root)
                        .load(self.token_record.app_id)
                        .configured
                        if control_authorized
                        else False
                    ),
                    "scope": "workspace app identity",
                    "applies_to_server_shell": True,
                    "posix_rc": True,
                    "reserved_names": sorted(RESERVED_ENVIRONMENT_NAMES),
                    "reserved_prefixes": ["OPENKAPSEL_"],
                },
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
                    "transactional_mutation": write_enabled,
                    "large_file_range_read": read_enabled,
                    "large_file_equal_length_replace": write_enabled,
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
                    "sse": {
                        "enabled": self.token_record.can_preview,
                        "method": "GET",
                        "content_type": "text/event-stream",
                        "incremental_passthrough": True,
                        "response_buffered_until_eof": False,
                        "browser_reconnects_after_stream_close": True,
                        "shared_with_shell_stream_limits": True,
                        "max_global": self.server.config.max_sse_streams,
                        "max_per_token": self.server.config.max_sse_streams_per_token,
                        "max_duration_seconds": self.server.config.max_sse_duration_seconds,
                        "upstream_idle_timeout_seconds": (
                            self.server.config.http_socket_timeout_seconds
                        ),
                        "heartbeat_recommendation": (
                            "send an SSE comment more frequently than the upstream idle timeout"
                        ),
                    },
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
                        "scope": "each app uses private runtime-managed storage scoped to its parent directory",
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
                "http_socket_timeout_seconds": self.server.config.http_socket_timeout_seconds,
                "mapping_rpc_timeout_seconds": self.server.config.mapping_rpc_timeout_seconds,
                "mapping_provider_idle_timeout_seconds": self.server.config.mapping_provider_idle_timeout_seconds,
                "max_direct_upload_bytes": self.server.config.max_direct_upload_bytes,
                "max_file_bytes": self.server.config.max_file_bytes,
                "file_size_tiers": {
                    "small_max_bytes": SMALL_FILE_MAX_BYTES,
                    "medium_max_bytes": STANDARD_FILE_MAX_BYTES,
                    "large_min_bytes": STANDARD_FILE_MAX_BYTES + 1,
                    "ordinary_content_max_bytes": STANDARD_FILE_MAX_BYTES,
                    "large_range_max_bytes": LARGE_FILE_WINDOW_MAX_BYTES,
                },
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
                "min_schedule_interval_minutes": MIN_SCHEDULE_INTERVAL_MINUTES,
                "max_schedules_per_token": MAX_ACTIVE_SCHEDULES_PER_APP,
                "schedule_misfire_grace_seconds": self.server.config.schedule_misfire_grace_seconds,
                "max_schedule_runs_per_schedule": MAX_SCHEDULE_RUNS_PER_SCHEDULE,
                "schedule_run_retention_days": SCHEDULE_RUN_RETENTION_DAYS,
                "max_environment_variables": MAX_ENVIRONMENT_VARIABLES,
                "max_environment_name_characters": MAX_ENVIRONMENT_NAME_CHARS,
                "max_environment_value_characters": MAX_ENVIRONMENT_VALUE_CHARS,
                "max_environment_total_characters": MAX_ENVIRONMENT_TOTAL_CHARS,
                "max_environment_rc_characters": MAX_ENVIRONMENT_RC_CHARS,
                "max_context_query_entries": MAX_CONTEXT_QUERY_LIMIT,
                "max_conversation_query_entries": MAX_CONVERSATION_QUERY_LIMIT,
                "max_conversation_content_characters": MAX_CONVERSATION_CONTENT_CHARS,
                "max_conversation_summary_characters": MAX_CONVERSATION_SUMMARY_CHARS,
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
                    "notes": "main discovery is a compact index; section documents contain domain-specific details and full preserves the complete compatibility document",
                },
                "transport_hmac": {
                    "authentication": "workspace read URL only; no Authorization header",
                    "query": {
                        "key": "required UTF-8 HMAC key, at most 4096 bytes",
                        "target": "required UTF-8 target string, at most 32768 bytes",
                    },
                    "response": {
                        "algorithm": "HMAC-SHA256",
                        "encoding": "base64url-nopad",
                        "result": "<43-character base64url digest>",
                    },
                    "notes": "pure computation with no server-side state change; also available through ?req=transport/hmac at the exact workspace root; the secret-bearing query is redacted from OpenKapsel access logs but upstream proxies may still log request URLs",
                },
                "credential_renew": {
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
                "environment_get": {
                    "authentication": "Bearer control token",
                    "notes": "returns this stable app identity's persisted Shell variables and POSIX rc content; responses contain secrets and are never cached",
                },
                "environment_replace": {
                    "authentication": "Bearer control token",
                    "json": {
                        "variables": {"NAME": "string value"},
                        "rc": "optional POSIX Shell initialization commands",
                        "plan_id": "required plan id",
                        "taskname": "required task grouping name",
                        "message": "required short operation message",
                    },
                    "notes": "replaces the complete server Shell environment configuration; reserved launcher and proxy variables are rejected",
                },
                "environment_clear": {
                    "authentication": "Bearer control token",
                    "json": {
                        "plan_id": "required plan id",
                        "taskname": "required task grouping name",
                        "message": "required short operation message",
                    },
                    "notes": "removes the complete per-app environment configuration",
                },
                "conversation_query": {
                    "url_query": "conversation_id=<integer>&start_sub_id=<integer>&end_sub_id=<integer>",
                    "authentication": "Bearer control token + files.read",
                    "response": {"next_conversation_id": "required id for the next conversation_create; 0 when no Conversation exists"},
                    "notes": f"without conversation_id, return the {DEFAULT_RECENT_CONVERSATION_COUNT} newest non-empty conversation_ids as whole contiguous windows, newest id first and each window ordered from its newest summary (or sub_id 1) forward; with conversation_id, return that Conversation's newest at most {MAX_CONVERSATION_QUERY_LIMIT} entries; start_sub_id/end_sub_id first restrict the range and then the newest at most {MAX_CONVERSATION_QUERY_LIMIT} entries in that range are returned; query before creating a Conversation and pass next_conversation_id to conversation_create",
                },
                "conversation_create": {
                    "authentication": "Bearer control token",
                    "json": {
                        "conversation_id": "<required next_conversation_id from conversation_query; first id is 0>",
                        "entries": [
                            {"role": "user", "content": "<user-side context summary, max 1000 chars; may retain original wording without extra compression when it fits>"},
                            {"role": "ai", "content": "<AI-side context summary, max 1000 chars; may retain original wording without extra compression when it fits>"},
                        ],
                    },
                    "response": {
                        "conversation_id": "caller-supplied searchable non-negative sequential integer id",
                        "writer_nonce": "value to retain for this Conversation and pass back unchanged",
                        "entries": "created append-only entries with per-conversation sub_id",
                        "instructions": "mandatory AI usage guidance for later appends and Plan integration",
                    },
                    "notes": "creation is atomic; conversation_id must equal the current next_conversation_id (previous maximum + 1, or 0 for the first Conversation); requires at least two complete entries with first role=user then role=ai",
                },
                "conversation_append": {
                    "authentication": "Bearer control token",
                    "json": {
                        "writer_nonce": "<required value returned by conversation_create; pass unchanged>",
                        "entries": [
                            {"role": "user|ai|summary", "content": "<user/ai max 1000 chars; summary max 8192 chars>"}
                        ],
                    },
                    "response": {"summary_status": {"user_ai_since_summary": "count since newest summary", "recommended": "true at 40+", "required_before_next_user_ai": "true at 49+", "source_start_sub_id": "latest summary sub_id, or 1 when none exists", "source_end_sub_id": "latest entry sub_id", "instruction": "summary guidance when recommended"}},
                    "notes": "append-only; entries cannot be modified; user/ai entries are per-side context summaries and may preserve original wording without extra compression when already within 1000 chars; summary is not tied to a fixed sub_id. After 40 user/ai entries since the newest summary, append responses recommend a compressed role=summary covering the range from that newest summary itself (or sub_id 1 when none exists) through the latest entry. After 49 user/ai entries, another user/ai entry is rejected until role=summary is appended; summary resets the counter and may be written before the hard limit.",
                },
                "context_query": {
                    "url_query": "id=<integer>&query=<text>&type=<operation|plan|note>&status=<status>&taskname=<exact-taskname>&actor_id=<exact-actor-id>&path=<exact-recorded-path>&plan_id=<direct-parent-or-owner>&root_plans=false&before_id=<integer>&limit=100",
                    "authentication": "Bearer control token",
                    "notes": "all filters are optional and composable except plan_id cannot combine with root_plans=true; plan_id returns direct children/entries only; root_plans=true finds plan roots; newest first; limit cannot exceed 200; context queries do not recursively record themselves",
                },
                "context_plan_tree": {
                    "url_query": "max_depth=8&limit=200",
                    "authentication": "Bearer control token",
                    "notes": "returns a flat depth-annotated plans array for the selected subtree plus operations/notes attached to those plans; rebuild the tree using each plan id and plan_id; truncation flags are explicit",
                },
                "context_add": {
                    "authentication": "Bearer control token",
                    "json": {
                        "type": "plan or note",
                        "taskname": "<required task grouping name>",
                        "plan_id": "<omit for a root plan; parent plan id for a sub-plan; required owning plan id for a note>",
                        "content": "<AI-authored context>",
                        "scope_paths": ["<optional paths used to retrieve related Memory for a plan>"],
                        "memory_tags": ["<optional exact tags used to retrieve related Memory for a plan>"],
                        "subplans": [{"ref": "implementation", "content": "Implement one part; taskname inherits when omitted"}],
                        "request_id": "<optional caller-generated stable retry key; plans only>",
                        "conversation_id": "<required owning Conversation numeric id for a plan>",
                        "writer_nonce": "<required value returned for the owning Conversation; pass unchanged>",
                        "conversation_entries": [{"role": "user|ai|summary", "content": "<at least one append-only entry committed atomically with Plan creation>"}],
                    },
                    "plan_extension_schema": plan_creation_properties(),
                    "response": {
                        "id": "ID of the newly created top-level plan (or the original ID on retry)",
                        "revision": "current top-level Plan revision; newly created Plans start at 1",
                        "subplans": "compact children in request order with index/id/plan_id/taskname/status/revision and optional ref; no repeated content or hints",
                        "request_id": "echoed when supplied",
                        "replayed": "false for first keyed creation (HTTP 201), true for matching retry (HTTP 200)",
                        "related_memory": "one deduplicated Memory result for the complete plan batch",
                        "unfinished_root_plans": "array of up to 20 newest previously existing in_progress root-plan summaries; sub-plans and the newly created plan are excluded",
                        "unfinished_root_plans_total": "total matching unfinished root plans",
                        "unfinished_root_plans_truncated": "true when more than 20 unfinished root plans exist",
                    },
                    "notes": "operation entries are generated automatically by OpenKapsel and cannot be added manually; Plan creation requires conversation_id, its returned writer_nonce, and at least one Conversation entry. Every created Plan starts in_progress and creation rejects status. Creating a sub-plan requires its hierarchy root to remain in_progress; every created plan response also includes related_memory and unfinished_root_plans; the newly created plan is excluded from the hint list; content_preview is capped at 256 characters",
                },
                "context_plan_update": {
                    "authentication": "Bearer control token",
                    "json": {
                        "taskname": "<required task grouping name>",
                        "expected_revision": "<required current positive Plan revision>",
                        "plan_id": "<optional new parent within the same root hierarchy; roots stay root and sub-plans cannot change root>",
                        "content": "<optional replacement content>",
                        "status": "<optional in_progress, completed, or cancelled>",
                        "conversation_id": "<required owning Conversation id except cancellation-only>",
                        "writer_nonce": "<required value returned for the owning Conversation except cancellation-only; pass unchanged>",
                        "conversation_entries": [{"role": "user|ai|summary", "content": "<at least one entry; completion requires at least one ai entry>"}],
                        "debrief": {
                            **plan_debrief_schema(),
                            "required_when": "status transitions to completed",
                        },
                    },
                    "notes": "updates only when expected_revision matches; every non-cancellation-only update requires the owning conversation_id, returned writer_nonce, and at least one Conversation entry. A root stays root; a sub-plan may change parent only within its existing root. Completion additionally requires at least one role=ai entry plus debrief and is rejected while any descendant Plan remains in_progress. cancellation-only needs no writer_nonce; stale revisions fail with 412; self-parenting and indirect cycles are rejected",
                },
                "context_note_replace": {
                    "authentication": "Bearer control token",
                    "json": {
                        "taskname": "<required task grouping name>",
                        "plan_id": "<required owning plan id>",
                        "content": "<required replacement content>",
                    },
                    "notes": "atomically inserts a new note with a newer id and deletes the old note row",
                },
                "memory_query": {
                    "url_query": "query=<text>&tag=<exact-tag>&path=<overlapping-canonical-scope>&include_archived=false&limit=100",
                    "authentication": "Bearer control token",
                    "response": {
                        "memories": "array of records identified by memory_id",
                        "limit": "integer",
                        "total": "integer",
                        "truncated": "boolean",
                    },
                    "notes": "returns project-level long-term Memory ordered by latest content update or confirmed helpful use; exact indexed tags and overlapping canonical path scopes are important relevance signals; server:. is global",
                },
                "memory_project": {
                    "authentication": "Bearer control token",
                    "notes": "returns a bounded recent/helpful profile of active Memory entries",
                },
                "memory_add": {
                    "authentication": "Bearer control token",
                    "json": {
                        "content": "<required self-contained Memory, 1-256 characters>",
                        "tags": ["<required: 1-32 exact relevance tags; prefer 4-16 specific reusable tags>"],
                        "path": "<optional canonical scope: server:<path>, mapping:<id>:<path>, storage:<id>:<path>; omitted defaults to server:.>",
                        "plan_id": "<required source plan id>",
                        "taskname": "<required task grouping>",
                        "message": "<required change reason, at most 200 characters>",
                    },
                    "response": {
                        "memory_id": "stable Memory identifier",
                        "revision": 1,
                        "etag_header": "current revision validator",
                    },
                    "notes": "returns a stable memory_id, revision 1, and ETag; Memory uses separate private runtime-managed storage from the operation log",
                },
                "memory_item": {
                    "authentication": "Bearer control token",
                    "response_identifier_field": "memory_id",
                    "notes": "GET returns the current Memory and ETag; PATCH revises it; DELETE archives it. Mutations require plan_id, taskname, message, and either If-Match or expected_revision",
                },
                "memory_revisions": {
                    "url_query": "limit=100",
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
                    "notes": "app-path may be empty for the workspace-root app; the first api path component owns the remaining route; GET responses with Content-Type text/event-stream are flushed incrementally and share the published SSE limits; default FastAPI documentation routes are not exposed",
                    "authentication": "defined entirely by the workspace FastAPI application; OpenKapsel adds no users, cookies, sessions, or auth routes",
                },
                "fs_list": {
                    "url_query": "path=<path>&offset=0&limit=1000",
                    "notes": "path may be root-relative or an absolute path inside root. Root listings show virtual mapping entries with is_mapping and mapping_id without contacting providers; listing inside a mapping uses client RPC, not a native mount.",
                    "query": {
                        "path": ".",
                        "offset": 0,
                        "limit": 1000,
                        **optional_read_context_query,
                    },
                },
                "fs_read_files": {
                    "authentication": "read-only URL token; Bearer token is not required",
                    "query": dict(optional_read_context_query),
                    "json": {"paths": ["src/main.py", "README.md"], "encoding": "utf-8", "offset": 0, "limit": 65536, "max_total_chars": 262144},
                    "notes": "Explicit encoding, UTF-8 by default; literal newlines. paths is bounded by max_batch_file_operations; use one path for a single-file read. offset is a shared character offset; limit is per-file characters and max_total_chars is shared. Items contain status, content, offset, etag, truncated and next_offset; errors are per-item (HTTP 207). Continue truncated files by calling fs_read_files again with offset=next_offset and the same encoding. Same-mapping batches execute in one client RPC.",
                },
                "fs_stat": {
                    "url_query": "path=<path>&fields=type,size,created_at,modified_at,sha256",
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
                    "recursive_json": {"recursive": True, "path": ".", "depth": 8, "include_sha256": False},
                    "recursive_notes": "Alternative to items (mutually exclusive): flat recursive metadata including root, bounded by depth and max_tree_nodes. Returns path/type/size/modified_at, optional SHA256 for regular files, total and truncated. Depth 0 includes only root; depth 1 includes direct children. Symlinks are never followed. Mapping subtrees are queried and hashed on each client with the remaining global budget; unavailable mapping nodes include is_mapping, mapping_id, unavailable and error. Results are not a transactional directory snapshot.",
                    "notes": "bounded multi-path status and synchronization preflight; hashes are calculated only when expected or explicitly requested",
                },
                "fs_find": {
                    "url_query": "path=.&query=<filename>&max_results=100&timeout_seconds=5",
                    "notes": "recursively finds files/directories whose basename contains a literal query string. Default timeout is 5 seconds; timeout returns partial results with timed_out=true and truncated=true. A mapped subtree uses its indexed file_search backend when advertised, otherwise the client recursively traverses it.",
                    "query": {
                        "path": ".",
                        "query": "<required filename fragment>",
                        "max_results": min(100, self.server.config.max_search_results),
                        "case_sensitive": False,
                        "timeout_seconds": 5,
                        **optional_read_context_query,
                    },
                },
                "fs_grep": {
                    "url_query": "path=.&query=<text>&depth=8&max_results=100",
                    "notes": "greps UTF-8 file contents; MCP name is fs_grep. Supports regex and case_sensitive flags. Repeated include/exclude globs: slash-free patterns match basenames, others match root-relative POSIX paths; case-sensitive fnmatch semantics (* spans /). Exclude wins and prunes matching directories. Up to 64 patterns per group, 512 characters each. Each visited mapping subtree is grepped on its client, preserving the original glob root and remaining depth/result budget. unavailable_mappings plus truncated=true report incomplete results; never assume an unavailable mapping has no matches.",
                    "query": {
                        "path": ".",
                        "query": "<required text or regex>",
                        "depth": 8,
                        "max_results": min(100, self.server.config.max_search_results),
                        "regex": False,
                        "case_sensitive": True,
                        "include": "optional repeated glob parameter, e.g. include=*.py&include=*.js",
                        "exclude": "optional repeated glob parameter, e.g. exclude=node_modules&exclude=*.min.js; matching directories are pruned",
                        **optional_read_context_query,
                    },
                },
                "fs_tree": {
                    "url_query": "path=.&depth=2",
                    "notes": "returns a nested directory tree bounded by depth and max_tree_nodes; mapping subtrees are listed on their clients with the remaining global budget, without native mounts. Mapping roots have is_mapping and mapping_id; unavailable roots also contain unavailable and error.",
                    "query": {
                        "path": ".",
                        "depth": 2,
                        **optional_read_context_query,
                    },
                },
                "fs_content": {
                    "url_query": "path=<path>",
                    "notes": "streams raw bytes and supports one standard HTTP Range",
                    "query": {
                        "path": "<required>",
                        **optional_read_context_query,
                    },
                    "request_headers": {"Range": "bytes=<start>-<end>", "If-None-Match": "<etag>"},
                    "response_headers": ["Content-Length", "Content-Range", "ETag", "Last-Modified"],
                },
                "fs_content_put": {
                    "url_query": "path=<path>&create_parents=false",
                    "content_type": "application/octet-stream",
                    "request_headers": {
                        "Content-Length": "<required byte count>",
                        "X-Content-SHA256": "<optional SHA-256>",
                        "OpenKapsel-Plan-Id": "<required owning plan id>",
                        "OpenKapsel-Taskname": "<required task grouping name>",
                        "OpenKapsel-Message": "<required brief operation summary>",
                    },
                    "notes": "atomically creates a new file only; if the destination exists, use fs_mutate path.delete first so the previous version is retained in recycle storage; use resumable uploads above the direct-upload limit",
                },
                "fs_mutate": {
                    "json": {
                        "items": [
                            {
                                **mutation_item_example(),
                            }
                        ],
                        "dry_run": False,
                        "plan_id": "<required owning plan id>",
                        "taskname": "<required task grouping name>",
                        "message": "<required brief operation summary>",
                    },
                    "notes": (
                        "single-backend request transaction for files at or below "
                        f"{STANDARD_FILE_MAX_BYTES} bytes. Existing targets require exact ETags; "
                        "all items are preflighted and staged before publication. Supports exact "
                        "text replacement/insertion with optional zero-based inclusive line bounds or unique multiline full-file start_text/end_text markers, JSON/YAML/TOML structured patch, create-only files and "
                        "whole-file replacement and recoverable file/directory deletion. Content operations are limited to standard files; path.delete may recycle larger files and directories. Ordinary request failures roll back all published "
                        "items; v1 does not claim durable crash recovery across process/OS failure."
                    ),
                },
                "fs_read_large": {
                    "json": {"path": "<file>", "offset": 0, "length": LARGE_FILE_WINDOW_MAX_BYTES},
                    "notes": (
                        f"only accepts files larger than {STANDARD_FILE_MAX_BYTES} bytes; offset and "
                        f"length are mandatory and length is at most {LARGE_FILE_WINDOW_MAX_BYTES} bytes. "
                        "Returns Base64 data plus the exact ETag and SHA-256 of the returned range."
                    ),
                },
                "fs_replace_large": {
                    "json": {
                        "path": "<file>",
                        "offset": 0,
                        "length": "<1..262144>",
                        "data_base64": "<replacement bytes>",
                        "expected_etag": "<exact ETag from fs_read_large>",
                        "expected_range_sha256": "<SHA-256 from fs_read_large>",
                        "plan_id": "<required owning plan id>",
                        "taskname": "<required task grouping name>",
                        "message": "<required brief operation summary>",
                    },
                    "notes": (
                        "replacement byte length must equal length, so the file size cannot change. "
                        "The current file ETag and current selected range SHA-256 are both checked before writing; "
                        "ordinary write/verification failures attempt to restore the original range."
                    ),
                },
                "fs_mkdir": {
                    "json": {"path": "<path>", "parents": False, "exist_ok": False, "plan_id": "<required owning plan id>", "taskname": "<required task grouping name>", "message": "<required brief operation summary>"},
                },
                "fs_move": {
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
                    "url_query": "offset=0&limit=1000",
                    "notes": "lists recycle items belonging to this token workspace",
                    "query": {
                        "offset": 0,
                        "limit": 1000,
                        **optional_read_context_query,
                    },
                },
                "recycle_restore": {
                    "json": {"recycle_id": "<recycle_id>", "plan_id": "<required owning plan id>", "taskname": "<required task grouping name>", "message": "<required brief operation summary>"},
                    "notes": "restores to the original path and refuses to overwrite an existing path",
                },
                "share_create": {
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
                    "authentication": "creator Bearer control token",
                    "request_headers": {
                        "OpenKapsel-Plan-Id": "<required owning plan id>",
                        "OpenKapsel-Taskname": "<required task grouping name>",
                        "OpenKapsel-Message": "<required brief operation summary>",
                    },
                    "notes": "deletes a share early; only the stable token application that created it can do this, including after that token is regenerated",
                },
                "upload_create": {
                    "json": {
                        "path": "<path>",
                        "size": 0,
                        "sha256": None,
                        "create_parents": False,
                        "plan_id": "<required owning plan id>",
                        "taskname": "<required task grouping name>",
                        "message": "<required brief operation summary>",
                    },
                    "notes": "creates a new file only; recycle an existing destination before uploading",
                },
                "upload_status": {
                    "query": {**optional_read_context_query},
                },
                "upload_chunk": {
                    "content_type": "application/octet-stream",
                    "headers": {"Upload-Offset": "<current offset>", "OpenKapsel-Plan-Id": "<required owning plan id>", "OpenKapsel-Taskname": "<required task grouping name>", "OpenKapsel-Message": "<required brief operation summary>"},
                },
                "upload_commit": {"request_headers": {"OpenKapsel-Plan-Id": "<required owning plan id>", "OpenKapsel-Taskname": "<required task grouping name>", "OpenKapsel-Message": "<required brief operation summary>"}},
                "upload_cancel": {"request_headers": {"OpenKapsel-Plan-Id": "<required owning plan id>", "OpenKapsel-Taskname": "<required task grouping name>", "OpenKapsel-Message": "<required brief operation summary>"}},
                "mcp": {
                    "transport": "Streamable HTTP (stateless JSON responses; GET SSE is not offered)",
                },
                "shell_exec": {
                    "target_values": ["auto", "server", "client"],
                    "native_dependencies": "Server tasks acquire the cwd mapping automatically; declare other mapping dependencies with mount_mappings because command text is not inspected.",
                    "routing": "Default auto uses client RPC when cwd is inside a mapping; otherwise server. Explicit server executes on server even for a mapped cwd; client requires a mapped cwd. Command text is never inspected for cd. Offline/denied/old clients fail closed, never fall back.",
                    "client_contract": "Client execution requires an executable writable mapping, uses client-local policy/environment, never falls back to server, and returns an ordinary task_id. Client tasks survive reconnect but not client process exit.",
                    "json": {
                        "command": "<shell command>",
                        "target": "auto",
                        "mount_mappings": [],
                        "cwd": "<path inside root>",
                        "timeout_seconds": None,
                        "interactive": False,
                        "plan_id": "<required owning plan id>",
                        "taskname": "<required task grouping name>",
                        "message": "<required brief operation summary>",
                    },
                },
                "schedule_list": {
                },
                "schedule_create": {
                    "json": {
                        "name": "nightly build",
                        "schedule": {
                            "type": "cron",
                            "expression": "0 0 2 * * *",
                            "timezone": "UTC",
                        },
                        "command": "make test",
                        "cwd": ".",
                        "timeout_seconds": 3600,
                        "overlap_policy": "skip",
                        "misfire_policy": "skip",
                        "plan_id": "<required owning plan id>",
                        "taskname": "<required task grouping name>",
                        "message": "<required brief operation summary>",
                        "run_context": {
                            "plan_id": "<optional; defaults to the mutation plan_id>",
                            "taskname": "<optional; defaults to the mutation taskname>",
                            "message": "<optional; defaults to the mutation message>",
                        },
                    },
                    "schedule_variants": {
                        "interval": {"type": "interval", "minutes": 3, "timezone": "UTC"},
                        "once": {"type": "once", "run_at": "<timezone-aware ISO 8601 timestamp at least 3 minutes ahead>", "timezone": "UTC"},
                    },
                    "notes": "cron has exactly six required fields and occurrences must never be less than 3 minutes apart",
                },
                "schedule_get": {
                },
                "schedule_update": {
                    "json": {
                        "expected_revision": 1,
                        "name": "<optional>",
                        "schedule": "<optional complete schedule object>",
                        "command": "<optional>",
                        "cwd": "<optional>",
                        "timeout_seconds": "<optional number or null>",
                        "overlap_policy": "<optional; only skip is supported>",
                        "misfire_policy": "<optional skip or coalesce>",
                        "run_context": "<optional complete plan_id/taskname/message for future runs>",
                        "plan_id": "<required owning plan id for this API mutation>",
                        "taskname": "<required task grouping name>",
                        "message": "<required brief operation summary>",
                    },
                },
                "schedule_delete": {
                    "json": {
                        "plan_id": "<required owning plan id>",
                        "taskname": "<required task grouping name>",
                        "message": "<required brief operation summary>",
                    },
                },
                "schedule_execute": {
                    "json": {
                        "plan_id": "<required owning plan id>",
                        "taskname": "<required task grouping name>",
                        "message": "<required brief operation summary>",
                    },
                    "notes": "explicit immediate run; task capacity and overlap limits still apply",
                },
                "schedule_pause": {
                    "json": {"plan_id": "<required>", "taskname": "<required>", "message": "<required>"},
                },
                "schedule_resume": {
                    "json": {"plan_id": "<required>", "taskname": "<required>", "message": "<required>"},
                },
                "schedule_run_list": {
                    "url_query": "limit=50",
                },
                "schedule_run_get": {
                    "notes": "task_id links to ordinary Shell task status and output while retained",
                },
                "task_list": {
                    "url_query": "offset=0&limit=100&status=running",
                    "notes": "auto lists server token tasks and workspace client tasks. unavailable_mappings reports offline/denied clients; missing entries do not mean stopped tasks.",
                    "query": {
                        "target": "auto | server | client (default auto)",
                        "offset": 0,
                        "limit": 100,
                        "status": "running or finished; omit for all",
                        **optional_read_context_query,
                    },
                },
                "task_get": {
                    "query": {**optional_read_context_query},
                },
                "task_output": {
                    "url_query": "stdout_offset=0&stderr_offset=0&wait_seconds=20",
                    "query": {
                        "stdout_offset": 0,
                        "stderr_offset": 0,
                        "limit": 65536,
                        "wait_seconds": 0,
                        **optional_read_context_query,
                    },
                },
                "task_stream": {
                    "url_query": "stdout_offset=0&stderr_offset=0",
                    "content_type": "text/event-stream",
                    "events": ["output", "done", "reconnect", "error"],
                    "notes": "reconnect closes a duration-limited stream and returns the exact stdout/stderr offsets to use for the next request; error ends an already-started stream with a stable code plus byte cursors, including client/provider failures; concurrent streams are bounded globally and per token",
                    "query": {
                        "stdout_offset": 0,
                        "stderr_offset": 0,
                        **optional_read_context_query,
                    },
                },
                "task_stdin": {
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
                    "request_headers": {"OpenKapsel-Plan-Id": "<required owning plan id>", "OpenKapsel-Taskname": "<required task grouping name>", "OpenKapsel-Message": "<required brief operation summary>"},
                    "notes": "requests normal task termination; use task_kill when forced termination is required",
                },
                "task_kill": {
                    "request_headers": {"OpenKapsel-Plan-Id": "<required owning plan id>", "OpenKapsel-Taskname": "<required task grouping name>", "OpenKapsel-Message": "<required brief operation summary>"},
                    "notes": "force-stops the task immediately",
                },
                "sandbox_processes": {
                    "url_query": "offset=0&limit=100",
                    "notes": "lists restricted Shell processes with aggregate resource usage",
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
                "When credentials have less than two days remaining, call credential_renew once and atomically replace both values in .openkapsel.env with the returned workspace_url and control_token. The bundled helpers perform this check and update automatically for directory-scoped configuration.",
                "Skill-capable REST clients should inspect skills.openkapsel_rest and may install its token-free SHA-256-verified archive or read the linked SKILL.md remotely before loading detailed endpoint contracts.",
                "Before changing the workspace, query context with type=plan&root_plans=true&status=in_progress. Reuse a suitable plan tree or create one root plan by POST /context with type=plan and no plan_id.",
                "At task start, read memory_project when project-wide knowledge is needed. When creating a plan, provide scope_paths and memory_tags when known; OpenKapsel returns related_memory using path overlap, exact tags, and text relevance.",
                "Decompose a root plan by creating sub-plans whose plan_id is the parent plan's integer id. Use context_plan_tree to inspect the depth-annotated hierarchy and its attached operations/notes.",
                "Every modifying REST or MCP operation must provide plan_id, taskname, and a short message. plan_id must identify the plan or sub-plan that owns the action; OpenKapsel rejects missing, nonexistent, non-plan, self-referential, and cyclic relationships before changing the workspace.",
                "Reads should normally omit taskname, message, and plan_id and are then not recorded. To record a read, provide taskname and message; plan_id is optional but recommended to attach it to the relevant plan.",
                "Use context_query to filter history by direct plan_id, root plans, text, integer id, exact taskname, anonymous actor_id, or exact recorded path. Plans update in place and move through in_progress, completed, or cancelled; replacing a note creates a newer id and removes the old row.",
                "Use memory_query for long-lived project knowledge. Memory semantics are one canonical path, content, and tags. New or rewritten content is limited to 256 characters; legacy longer content remains readable until rewritten. New Memory requires at least one exact indexed tag; prefer 4-16 specific reusable tags.",
                "Completing a plan requires debrief with items, outcome, memory_actions, memory_feedback, and memory_conflicts. " + PLAN_COMPLETION_MEMORY_GUIDANCE,
                "MCP clients should initialize the mcp endpoint, call tools/list, and then use tools/call; REST clients can use the endpoints below directly.",
                "Inspect the workspace first with fs_list and read_files/fs_read_files.",
                "Open the web_preview endpoint URL to preview workspace HTML and its relative CSS, JavaScript, images, fonts, or media in a sandboxed browser document.",
                "Implement registration, login, roles, cookies, sessions, CSRF, and access control directly in the workspace FastAPI application when the site needs them; OpenKapsel does not add an authentication layer.",
                "For persistent application data, define a FastAPI route in <app-directory>/api/app.py and use openkapsel_runtime.database.engine('main') or database.session('main') with portable SQLAlchemy APIs; each app gets private runtime-managed storage, while browser code calls /<app-path>/api/* and never accesses database storage directly.",
                "Use fs_find for recursive filename discovery, fs_grep for cross-file content grep, and fs_tree for a bounded recursive overview.",
                "Request sha256 explicitly from fs_stat only when content verification is needed.",
                "Use fs_stat before transferring files, then stream binary or large downloads through fs_content with HTTP Range.",
                "Use direct fs_content PUT for small binary files, or create an upload session for large files and send raw bytes in chunks.",
                "Uploads never overwrite. To replace a file, first use fs_mutate with path.delete so its previous version is retained in private recycle storage, then upload the new file.",
                "Create directories with fs_mkdir, and move or rename paths with fs_move.",
                "For ordinary files up to 32 MiB, use fs_mutate for content changes; existing paths require exact ETags and all items are preflighted before publication. MCP fs_write, fs_edit_text, and fs_delete are convenience wrappers over the same transaction engine.",
                "Files above 32 MiB are large files: inspect them only through fs_read_large with explicit offset+length, and mutate them only through fs_replace_large using exact ETag + range SHA-256 and equal-length bytes.",
                "Use fs_mutate path.delete (or MCP fs_delete) for recoverable transactional deletion, recycle_list to inspect deleted items, and recycle_restore to recover them.",
                "For cross-workspace transfer, share_create copies one file or directory and returns a one-day random share_id. The recipient can inspect it with the public share_query endpoint and import it with share_import using only that ID plus the recipient workspace's own control token; imports never overwrite.",
                "Run tests or builds with shell_exec; list tasks, read output incrementally, and send input to interactive tasks.",
                "When schedules permission is enabled, use persistent once, interval, or six-field cron schedules for background Shell work. Every dispatched run records Context under its configured plan_id; use run-now instead of creating sub-three-minute schedules.",
                "Use GET, PUT, or DELETE env to inspect, replace, or clear server Shell variables and POSIX initialization. PUT and DELETE require mutation Context.",
                "For restricted Shell, inspect this token's live sandbox processes and aggregate resource usage with sandbox_processes.",
                "Use task_interrupt for normal termination; reserve task_kill for an unresponsive task that must stop immediately.",
            ],
        }

        from openkapsel.mapping.mapping_transport import (
            FILE_API_OPERATIONS,
            MAPPING_HANDSHAKE_VERSION,
            MAPPING_HELLO_TIMEOUT_SECONDS,
            MINIMUM_MAPPING_CLIENT_VERSION,
            SERVER_SOURCE_FINGERPRINT,
            MAX_MESSAGE,
        )
        payload["capabilities"]["mappings"] = {
            "enabled": self.server.config.mappings_enabled,
            "handshake": {
                "authentication": "mapping Bearer credential is verified during the HTTP WebSocket Upgrade",
                "server_first": True,
                "handshake_version": MAPPING_HANDSHAKE_VERSION,
                "server_version": SERVER_VERSION,
                "server_fingerprint": SERVER_SOURCE_FINGERPRINT,
                "minimum_client_version": MINIMUM_MAPPING_CLIENT_VERSION,
                "client_hello_timeout_seconds": MAPPING_HELLO_TIMEOUT_SECONDS,
                "ready_required_for_online": True,
                "client_fingerprint": "change detector only; fingerprint equality is not a compatibility requirement",
            },
            "native_mounts": {
                "enabled": self.server.config.mapping_fuse_enabled,
                "max_active": self.server.config.max_active_mapping_mounts,
                "idle_seconds": self.server.config.mapping_mount_idle_seconds,
                "policy": "Only server Shell and FastAPI dependencies acquire native mounts. Provider connections and all file APIs remain RPC-only.",
            },
            "file_stream": {"version": 1, "descriptor_stat": True, "directory_details": True},
            "list": "./mapping", "storage": "client-local; excluded from workspace image quota",
            "offline": "mapped operations fail; never fall back to a local directory",
            "client_execution": "requires control authorization, Shell/write permissions, mapping allow_exec, and client-local opt-in",
            "rpc": {
                "states": ["available", "unsupported", "disabled", "offline"],
                "routing": "Core file RPC is always enabled; rpc.file is not a client setting. Plugin families are advertised only when enabled and runtime-supported; absent families are not callable. Use the mapping name returned by GET /mapping in mapped RPC paths. File and plugin RPC operations never fall back to native mounts.",
                "configuration": "Client config rpc.<family>=true|false overrides each plugin's default activation. Mapping families self-describe with description plus operation_specs.<operation>.description/input_schema/write/execution in GET /mapping. execution is sync or task; omitted plugin metadata defaults to sync for reads and task for writes.",
                "families": {
                    "file": {
                        "version": 4, "fallback": None, "operations": sorted(FILE_API_OPERATIONS),
                        "max_message_bytes": MAX_MESSAGE,
                        "batching": "Same-mapping batches execute on the client. Mixed-root batches use the guarded local/RPC backend and never require FUSE.",
                        "errors": "For mapping_response_too_large (413), reduce limit, depth, or batch size. Never blindly replay a mutation after an ambiguous timeout.",
                    },
                    "git": {"version": 2, "fallback": "none", "generic_rpc_exposed": True, "server_rpc": True, "sync_reads": ["status", "diff", "log", "show", "ls_files", "diff_stat"], "task_writes": ["add", "commit", "restore", "checkout", "fetch", "pull", "clone"]},
                    "archive": {"version": 1, "fallback": "none", "generic_rpc_exposed": True, "server_rpc": True, "sync_reads": ["list", "read"], "task_writes": ["create", "extract"],
                                "formats": "Runtime-advertised Python standard-library archive extensions."},
                    "structured": {"version": 1, "fallback": "none",
                                   "sync_reads": ["read", "validate", "preview"],
                                   "task_writes": ["write", "patch"],
                                   "formats": "JSON; YAML/TOML when the client's optional parsers are installed.",
                                   "write_precondition": "exact expected_etag for replacement; no ETag means create-only"},
                    "tabular": {"version": 1, "fallback": "none", "read_only": True,
                                "sync_reads": ["inspect", "read"], "task_reads": ["scan"],
                                "formats": "CSV/TSV; Excel when the client's optional parsers are installed.",
                                "csv_pagination": "file-bound seek cursors; no deep row-offset rescans",
                                "scan_results": "bounded segment results; resume next_cursor and merge completed segments"},
                    "ssh": {"version": 2, "fallback": "none", "privileged": True,
                            "sync_operations": ["profiles", "status", "close", "stat", "listdir", "read"],
                            "task_operations": ["exec", "upload", "download"],
                            "connection_reuse": "reuse the returned connection_id; idle connections expire after 60 seconds",
                            "proxy_types": ["socks4", "socks5", "http", "https"]},
                },
            },
        }
        payload["endpoints"].update({
            "recycle_purge": {"body": {"root": ". or mapping name", "recycle_id": "entry ID", "confirm": True, "plan_id": "required", "taskname": "required", "message": "required"}, "description": "Permanently delete one recycle entry. Not recoverable; explicit confirm=true required."},
            "fs_copy": {"body": {"source": "source-path", "destination": "destination-path", "plan_id": "required", "taskname": "required", "message": "required"},
                "description": "Start a bounded, resumable file/directory copy. Destination parent must exist. No overwrite; return 202 and transfer id. Staging remains on destination storage."},
            "file_transfer": {"description": "GET returns progress/state. POST ./fs/transfer/cancel/<id> or ./fs/transfer/resume/<id> requires mutation context. Cross-mapping fs/move also returns a transfer id: copy is verified before source recycling; copied_source_retained means the destination exists but the source was not recycled."},
            "server_rpc": {
                "body": {"args": "<plugin-specific object>", "timeout_seconds": "optional for execution=task", "plan_id": "required when operation write=true", "taskname": "required when operation write=true", "message": "required when operation write=true"},
                "description": "Invoke one server RPC family operation against the token workspace. Built-in server families include Git and Archive. execution=sync returns directly; execution=task returns 202 plus a normal server task_id. write=false requires read permission; write=true requires control authorization, write permission, and Plan Context. Git fetch/pull/clone also obey the token network policy."},
            "mapping_list": {"description": "List mapping names/roots, online/write state, and client capabilities. Use each mapping name in RPC paths. RPC operation_specs include description, JSON input_schema, write, and execution=sync|task."},
            "mapping_rpc": {
                "body": {"args": "<plugin-specific object>", "timeout_seconds": "optional for execution=task", "plan_id": "required when operation write=true", "taskname": "required when operation write=true", "message": "required when operation write=true"},
                "description": "Invoke one advertised client RPC operation using the mapping name returned by GET /mapping. execution=sync returns the result. execution=task returns 202 plus a unified client task_id immediately; the task survives provider reconnects while the client process remains alive and is polled/controlled through ordinary /task/* routes. Never replay an uncertain write task start. write=false requires read permission; write=true requires control authorization, token write permission, a writable mapping, and Plan Context. No generic RPC operation falls back to server/FUSE."},
        })
        payload["endpoints"]["recycle_list"]["mapping_root"] = "Query root=. for workspace recycle or root=<mapping-name> for client-local recycle."
        payload["endpoints"]["recycle_restore"]["mapping_root"] = "JSON root selects the recycle store; default '.'. IDs are scoped by root."
        endpoint_permissions = {
            "recycle_purge": ("Bearer control token + write", control_authorized and self.token_record.can_write),
            "fs_copy": ("Bearer control token + read + write", control_authorized and self.token_record.can_read and self.token_record.can_write),
            "file_transfer": ("Bearer control token", control_authorized),
            "server_rpc": ("write=false: files.read; write=true: Bearer control token + write + Plan Context", read_enabled or (control_authorized and self.token_record.can_write)),
            "mapping_list": ("read", self.token_record.can_read),
            "mapping_rpc": ("write=false: files.read; write=true: Bearer control token + write + writable mapping + Plan Context", read_enabled or (control_authorized and self.token_record.can_write)),
            "discovery_section": ("URL token", True),
            "credential_renew": ("Bearer control token", control_authorized),
            "environment_get": ("Bearer control token", control_authorized),
            "environment_replace": ("Bearer control token", control_authorized),
            "environment_clear": ("Bearer control token", control_authorized),
            "conversation_query": (
                "Bearer control token + files.read",
                control_authorized and read_enabled,
            ),
            "conversation_create": ("Bearer control token", control_authorized),
            "conversation_append": ("Bearer control token", control_authorized),
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
            "fs_stat": ("files.read", read_enabled),
            "fs_manifest": ("files.read", read_enabled),
            "fs_read_files": ("files.read", read_enabled),
            "fs_grep": ("files.read", read_enabled),
            "fs_find": ("files.read", read_enabled),
            "fs_tree": ("files.read", read_enabled),
            "fs_content": ("files.read", read_enabled),
            "fs_content_put": ("Bearer control token + files.write", write_enabled),
            "fs_mutate": ("Bearer control token + files.write", write_enabled),
            "fs_read_large": ("files.read", read_enabled),
            "fs_replace_large": ("Bearer control token + files.write", write_enabled),
            "fs_mkdir": ("Bearer control token + files.write", write_enabled),
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
            "schedule_list": ("Bearer control token + schedules + shell", schedules_enabled),
            "schedule_create": ("Bearer control token + schedules + shell", schedules_enabled),
            "schedule_get": ("Bearer control token + schedules + shell", schedules_enabled),
            "schedule_update": ("Bearer control token + schedules + shell", schedules_enabled),
            "schedule_delete": ("Bearer control token + schedules + shell", schedules_enabled),
            "schedule_execute": ("Bearer control token + schedules + shell", schedules_enabled),
            "schedule_pause": ("Bearer control token + schedules + shell", schedules_enabled),
            "schedule_resume": ("Bearer control token + schedules + shell", schedules_enabled),
            "schedule_run_list": ("Bearer control token + schedules + shell", schedules_enabled),
            "schedule_run_get": ("Bearer control token + schedules + shell", schedules_enabled),
            "task_list": ("Bearer control token + shell", shell_enabled),
            "task_get": ("Bearer control token + shell", shell_enabled),
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
            route_metadata = discovery_route_metadata(name)
            if route_metadata is not None:
                endpoint["method"] = route_metadata["method"]
                if "methods" in route_metadata:
                    endpoint["methods"] = route_metadata["methods"]
                else:
                    endpoint.pop("methods", None)
                endpoint["route"] = route_metadata["route"]
                query_example = endpoint.pop("url_query", None)
                endpoint["url"] = f"{base}{route_metadata['route']}"
                if isinstance(query_example, str) and query_example:
                    endpoint["url"] += "?" + query_example
            capability, available = endpoint_permissions.get(name, ("token", True))
            endpoint["required_capability"] = capability
            endpoint["available"] = available
        if not control_authorized:
            privileged_endpoints = {
                "recycle_purge",
                "fs_copy", "file_transfer",
                "credential_renew",
                "environment_get",
                "environment_replace",
                "environment_clear",
                "fs_content_put",
                "fs_mutate",
                "fs_replace_large",
                "conversation_query",
                "conversation_create",
                "conversation_append",
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
                "fs_mkdir",
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
                "schedule_list",
                "schedule_create",
                "schedule_get",
                "schedule_update",
                "schedule_delete",
                "schedule_execute",
                "schedule_pause",
                "schedule_resume",
                "schedule_run_list",
                "schedule_run_get",
                "task_list",
                "task_get",
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
        payload["endpoint_defaults"] = {
            "available": True,
            "required_capability": "token",
            "inheritance": "operation > family > endpoint_defaults",
        }
        payload["endpoints"] = self._compact_endpoint_families(payload["endpoints"])
        missing_contract_docs = discovery_keys() - payload["endpoints"].keys()
        if missing_contract_docs:
            raise RuntimeError(
                "endpoint family contract is missing Discovery entries: "
                + ", ".join(sorted(missing_contract_docs))
            )
        return payload

    def _mcp_discovery(self, section: str = "main") -> dict[str, Any]:
        """Return Discovery metadata without echoing the capability token into MCP logs."""
        payload = self._discovery(section)
        base = self._base_path()
        payload["authentication"]["control_authorized"] = True
        payload["index_url"] = "./"
        payload["full_url"] = "./discovery/full"
        web = payload.get("endpoints", {}).get("web")
        if isinstance(web, dict):
            if self.server.config.preview_base_url:
                preview_root = (
                    f"{self.server.config.preview_base_url.rstrip('/')}/"
                    "<PREVIEW_TOKEN>"
                )
            else:
                preview_root = "../<PREVIEW_TOKEN>"
            web["path"] = f"{preview_root}/<workspace-relative-path>"
            operations = web.get("operations")
            if isinstance(operations, dict):
                api = operations.get("api")
                if isinstance(api, dict):
                    api["path"] = f"{preview_root}/<app-path>/api/<route>"
        cid = getattr(self, "oauth_connection_id", None)
        static_cid = getattr(self, "static_mcp_connection_id", None)
        if cid or static_cid:
            payload["authentication"] = {
                "mode": "oauth2",
                "control_authorized": True,
                "authorization": "Authorization: Bearer <OAUTH_ACCESS_TOKEN>",
                "resource": self._oauth_resource(cid) if cid else self._public_base_url().rstrip('/') + '/mcp-connect/' + static_cid + '/mcp',
                "scope": "openkapsel",
                "renewal": "The MCP client refreshes OAuth credentials through the token endpoint; do not call credential/renew.",
                "rest_access": "OAuth grants use the MCP endpoint directly; capability_call family=credential operation=get exports the linked configuration's portable REST workspace URL and control token when cross-platform REST access is needed.",
                "workspace_credentials": {
                    "tool": "capability_call",
                    "export": {"family": "credential", "operation": "get"},
                    "renew": {"family": "credential", "operation": "renew"},
                    "renewal_window_seconds": 2 * 24 * 60 * 60,
                    "rotation": "read URL token and control token rotate atomically; old REST credentials become invalid; MCP connection credentials are unchanged",
                },
            }
            if cid:
                payload["authentication"]["consent"] = consent_metadata()
            if static_cid:
                conn = self.server.static_mcp.get(static_cid)
                payload["authentication"].update(
                    mode="static_mcp", authorization="Authorization: Bearer <MCP_CONNECTION_SECRET>",
                    expires_at=conn["expires_at"],
                    renewal="An administrator can extend this Static MCP connection's own expiration; workspace REST credential renewal is separate.",
                    rest_access="This MCP credential can export or renew the linked configuration's portable REST workspace URL and control token through MCP tools.",
                )
            payload.get("endpoints", {}).pop("credential", None)
            if "mcp" in payload.get("endpoints", {}):
                payload["endpoints"]["mcp"]["path"] = payload["authentication"]["resource"]
            payload.get("token", {}).pop("credentials_expires_at", None)
            mcp_capability = payload.get("capabilities", {}).get("mcp")
            if isinstance(mcp_capability, dict):
                mcp_capability["authentication"] = "Bearer MCP connection secret" if static_cid else "Bearer OAuth access token"
            # Existing REST examples may be nested inside Discovery sections.
            # Do not let their capability URLs escape through OAuth tool results.
            def redact(value):
                if isinstance(value, str):
                    for secret in (self.token_record.token, self.token_record.control_token, self.token_record.preview_token):
                        value = value.replace(secret, "<redacted>")
                    return value
                if isinstance(value, list):
                    return [redact(item) for item in value]
                if isinstance(value, dict):
                    return {key: redact(item) for key, item in value.items()}
                return value
            payload = redact(payload)
        return payload

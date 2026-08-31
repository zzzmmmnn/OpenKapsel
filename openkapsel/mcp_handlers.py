"""Streamable-HTTP MCP transport and tool adapters."""

from __future__ import annotations

import base64
import binascii
import hmac
import io
import json
import logging
import mimetypes
import os
import secrets
import stat
import traceback
from http import HTTPStatus
from typing import Any
from urllib.parse import quote, urlsplit

from .errors import ApiError, McpError
from .mcp import (
    MCP_PROTOCOL_VERSION,
    PUBLIC_SERVER_VERSION,
    SUPPORTED_PROTOCOL_VERSIONS,
    tools_for,
    validate_arguments,
)
from .uploads import UploadError


LOGGER = logging.getLogger("openkapsel")


class McpHandlersMixin:
    """MCP-domain methods mixed into the main request handler."""
    def _handle_mcp_method_not_allowed(self) -> None:
        try:
            self._validate_mcp_origin()
        except ApiError as exc:
            self._send_mcp_error(None, -32000, exc.message, status=exc.status)
            return
        self._send_empty(HTTPStatus.METHOD_NOT_ALLOWED, {"Allow": "POST"})

    def _handle_mcp_post(self) -> None:
        request_id: str | int | None = None
        try:
            self._validate_mcp_origin()
            accept = self.headers.get("Accept", "")
            if accept and "application/json" not in accept.lower() and "*/*" not in accept:
                raise ApiError(
                    HTTPStatus.NOT_ACCEPTABLE,
                    "not_acceptable",
                    "MCP POST responses require Accept: application/json (normally alongside text/event-stream)",
                )
            message = self._read_json()
            if message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
                raise McpError(-32600, "Invalid Request")
            method = message["method"]
            mirrored_method = self.headers.get("Mcp-Method")
            if mirrored_method is not None and mirrored_method != method:
                raise McpError(-32600, "Mcp-Method header does not match the JSON-RPC method")
            if "id" in message:
                candidate_id = message["id"]
                if isinstance(candidate_id, bool) or not isinstance(candidate_id, (str, int)):
                    raise McpError(-32600, "JSON-RPC id must be a string or integer")
                request_id = candidate_id
            params = message.get("params", {})
            if not isinstance(params, dict):
                raise McpError(-32602, "params must be an object")

            if request_id is None:
                # Notifications never receive JSON-RPC response bodies.
                self._send_empty(HTTPStatus.ACCEPTED)
                return

            if method != "initialize":
                protocol_header = self.headers.get("MCP-Protocol-Version")
                if protocol_header is not None and protocol_header not in SUPPORTED_PROTOCOL_VERSIONS:
                    raise McpError(
                        -32600,
                        "Unsupported MCP-Protocol-Version",
                        {"supported": sorted(SUPPORTED_PROTOCOL_VERSIONS)},
                    )

            if method == "initialize":
                result = self._mcp_initialize(params)
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                cursor = params.get("cursor")
                if cursor is not None:
                    raise McpError(-32602, "tools/list cursor is not recognized")
                result = {
                    "tools": tools_for(
                        self.token_record,
                        self.token_scope_root != self.server.config.root,
                        self.server.config.mcp_binary_chunk_bytes,
                    )
                }
            elif method == "tools/call":
                result = self._mcp_call_tool(params)
            else:
                raise McpError(-32601, "Method not found", {"method": method})
            self._send_mcp_json(
                HTTPStatus.OK,
                {"jsonrpc": "2.0", "id": request_id, "result": result},
            )
        except McpError as exc:
            self._send_mcp_error(request_id, exc.code, exc.message, exc.data)
        except ApiError as exc:
            self._send_mcp_error(
                request_id,
                -32000,
                exc.message,
                {"code": exc.code, "details": exc.details},
                status=exc.status,
            )
        except Exception:
            request_reference = secrets.token_hex(6)
            LOGGER.error("unhandled MCP error %s\n%s", request_reference, traceback.format_exc())
            self._send_mcp_error(
                request_id,
                -32603,
                "Internal error",
                {"request_id": request_reference},
            )

    def _mcp_initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        requested = params.get("protocolVersion")
        if not isinstance(requested, str):
            raise McpError(-32602, "initialize requires protocolVersion")
        client_info = params.get("clientInfo")
        capabilities = params.get("capabilities")
        if not isinstance(client_info, dict) or not isinstance(capabilities, dict):
            raise McpError(-32602, "initialize requires object clientInfo and capabilities")
        negotiated = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else MCP_PROTOCOL_VERSION
        return {
            "protocolVersion": negotiated,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {
                "name": "OpenKapsel",
                "title": self.server.config.name,
                "version": PUBLIC_SERVER_VERSION,
                "description": "Token-scoped filesystem, recycle bin, and asynchronous shell tools",
            },
            "instructions": (
                "Paths are relative to this token's child workspace. Prefer replace_text for focused edits. "
                "Before modifying the workspace, use query_context with type=plan and root_plans=true to find an active root, or use add_context to create a root plan without plan_id. When creating a plan, provide scope_paths and memory_tags when known; its response pushes related_memory and previously existing unfinished_root_plans (excluding the new plan). Create sub-plans with their parent plan_id. Every modifying tool requires a valid owning plan_id, taskname of at most 32 characters, and message of at most 200 characters. Use get_plan_tree to inspect the hierarchy and attached operations/notes. Reads are recorded only when taskname and message are both supplied; plan_id is optional for recorded reads. Use get_project_memory and query_memory for long-lived overview, architecture, conventions, decisions, and known issues. Tags and paths are primary Memory relevance signals. Use add_memory/update_memory during work, or complete a plan with debrief containing summary, outcome, and memory_actions; an empty memory_actions array explicitly retains nothing. Use update_plan for parent/content/status changes and replace_note with an owning plan_id. "
                "Pass expected_etag to write_file or replace_text to prevent concurrent overwrites. Uploads only create new files; recycle an existing destination before uploading its replacement. "
                "Use read_binary_chunk and Base64 upload_chunk for small binary chunks; for large files call prepare_download or use the raw_transfer URLs returned by start_upload. "
                "Call get_web_preview_url when a workspace page should be opened in a browser. "
                "delete_path is recoverable through list_recycle and restore_recycle. "
                "run_shell returns a task_id; poll get_task until status is finished. "
                "When schedule tools are available, use create_schedule for persistent once, interval, or strict six-field cron Shell work; use run_schedule_now for explicit immediate execution. "
                "Use interrupt_task for normal termination and kill_task only for immediate forced termination."
            ),
        }

    def _mcp_call_tool(self, params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(name, str) or not isinstance(arguments, dict):
            raise McpError(-32602, "tools/call requires string name and object arguments")
        mirrored_name = self.headers.get("Mcp-Name")
        if mirrored_name is not None and mirrored_name != name:
            raise McpError(-32600, "Mcp-Name header does not match the tool name")
        available = {
            tool["name"]: tool
            for tool in tools_for(
                self.token_record,
                self.token_scope_root != self.server.config.root,
                self.server.config.mcp_binary_chunk_bytes,
            )
        }
        tool = available.get(name)
        if tool is None:
            raise McpError(-32602, "Unknown or unauthorized tool", {"name": name})
        try:
            validate_arguments(tool, arguments)
        except ValueError as exc:
            raise McpError(-32602, str(exc), {"name": name}) from None

        context_tools = {
            "query_context",
            "get_plan_tree",
            "add_context",
            "update_plan",
            "replace_note",
            "query_memory",
            "get_memory",
            "get_project_memory",
            "add_memory",
            "update_memory",
            "archive_memory",
        }
        track_operation = name not in context_tools and (
            not tool["annotations"]["readOnlyHint"]
            or bool(str(arguments.get("message", "")).strip())
            or bool(str(arguments.get("taskname", "")).strip())
        )
        try:
            if track_operation:
                self._begin_context_operation(
                    f"mcp.{name}",
                    arguments.get("taskname"),
                    arguments.get("message"),
                    arguments.get("plan_id"),
                    self._context_request_details(arguments),
                    plan_required=not tool["annotations"]["readOnlyHint"],
                )
            self._mcp_context_status = HTTPStatus.OK
            payload = self._execute_mcp_tool(name, arguments)
        except ApiError as exc:
            error: dict[str, Any] = {"code": exc.code, "message": exc.message}
            if exc.details is not None:
                error["details"] = exc.details
            context_id = self._finalize_context_operation(exc.status, {"error": error})
            if context_id is not None:
                error["context_id"] = context_id
            return {
                "content": [{"type": "text", "text": json.dumps(error, ensure_ascii=False)}],
                "structuredContent": {"error": error},
                "isError": True,
            }
        except McpError as exc:
            self._finalize_context_operation(
                HTTPStatus.BAD_REQUEST,
                {"error": {"code": exc.code, "message": exc.message}},
            )
            raise
        except Exception:
            self._finalize_context_operation(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": {"code": "internal_error"}},
            )
            raise
        context_id = self._finalize_context_operation(
            int(getattr(self, "_mcp_context_status", HTTPStatus.OK)),
            payload,
        )
        if context_id is not None:
            payload = dict(payload)
            payload["context_id"] = context_id
        text_result = json.dumps(payload, ensure_ascii=False, indent=2)
        return {
            "content": [{"type": "text", "text": text_result}],
            "structuredContent": payload,
            "isError": False,
        }

    def _execute_mcp_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "workspace_info":
            return self._mcp_workspace_info(str(arguments.get("section", "main")))
        if name == "query_context":
            self._require_permission(
                self.token_record.can_read,
                "read permission is not granted",
            )
            try:
                entries, total = self.server.context_for(self.token_scope_root).query(
                    entry_id=int(arguments["id"]) if "id" in arguments else None,
                    query=str(arguments.get("query", "")),
                    entry_type=str(arguments.get("type", "")).strip() or None,
                    entry_status=str(arguments.get("status", "")).strip() or None,
                    taskname=str(arguments.get("taskname", "")).strip() or None,
                    actor_id=str(arguments.get("actor_id", "")).strip() or None,
                    path=str(arguments.get("path", "")).strip() or None,
                    plan_id=(
                        int(arguments["plan_id"])
                        if "plan_id" in arguments
                        else None
                    ),
                    root_plans=bool(arguments.get("root_plans", False)),
                    before_id=(
                        int(arguments["before_id"])
                        if "before_id" in arguments
                        else None
                    ),
                    limit=int(arguments.get("limit", 100)),
                )
            except ValueError as exc:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_context_query",
                    str(exc),
                ) from None
            return {
                "entries": entries,
                "limit": int(arguments.get("limit", 100)),
                "total": total,
                "truncated": len(entries) < total,
                "next_before_id": entries[-1]["id"] if len(entries) < total else None,
            }
        if name == "get_plan_tree":
            self._require_permission(
                self.token_record.can_read,
                "read permission is not granted",
            )
            try:
                return self.server.context_for(self.token_scope_root).plan_tree(
                    int(arguments["plan_id"]),
                    max_depth=int(arguments.get("max_depth", 8)),
                    limit=int(arguments.get("limit", 200)),
                )
            except ValueError as exc:
                message = str(exc)
                status = (
                    HTTPStatus.NOT_FOUND
                    if message == "plan_id does not exist"
                    else HTTPStatus.BAD_REQUEST
                )
                raise ApiError(
                    status,
                    "context_plan_not_found"
                    if status == HTTPStatus.NOT_FOUND
                    else "invalid_context_plan",
                    message,
                ) from None
        if name == "add_context":
            entry_type = str(arguments["type"])
            if entry_type not in {"plan", "note"}:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_context_type",
                    "manually added context type must be plan or note",
                )
            try:
                plan_id = (
                    int(arguments["plan_id"])
                    if "plan_id" in arguments
                    else None
                )
                if entry_type == "note" and plan_id is None:
                    raise ValueError("notes must reference a plan_id")
                plan_status = (
                    str(arguments["status"])
                    if "status" in arguments
                    else None
                )
                if entry_type == "note" and plan_status is not None:
                    raise ValueError("note context cannot have a plan status")
                entry_id = self.server.context_for(self.token_scope_root).add(
                    entry_type,
                    str(arguments["content"]),
                    taskname=str(arguments["taskname"]),
                    actor_id=self.token_record.actor_id,
                    plan_status=plan_status,
                    plan_id=plan_id,
                )
            except ValueError as exc:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_context_entry",
                    str(exc),
                ) from None
            entries, _ = self.server.context_for(self.token_scope_root).query(
                entry_id=entry_id,
            )
            entry = entries[0]
            if entry_type == "plan":
                scope_paths = arguments.get("scope_paths")
                memory_tags = arguments.get("memory_tags")
                entry["scope_paths"] = scope_paths or []
                entry["memory_tags"] = memory_tags or []
                entry["related_memory"] = self._related_memories(
                    str(arguments["content"]),
                    scope_paths,
                    memory_tags,
                )
                unfinished = self.server.context_for(
                    self.token_scope_root
                ).unfinished_root_plan_hints(exclude_plan_id=entry_id)
                entry["unfinished_root_plans"] = unfinished["plans"]
                entry["unfinished_root_plans_total"] = unfinished["total"]
                entry["unfinished_root_plans_truncated"] = unfinished["truncated"]
            return entry
        if name == "update_plan":
            try:
                changes: dict[str, Any] = {
                    "taskname": str(arguments["taskname"]),
                    "content": (
                        str(arguments["content"])
                        if "content" in arguments
                        else None
                    ),
                    "plan_status": (
                        str(arguments["status"])
                        if "status" in arguments
                        else None
                    ),
                }
                completed_debrief: dict[str, Any] | None = None
                if changes["plan_status"] == "completed":
                    existing_entries, _ = self.server.context_for(self.token_scope_root).query(
                        entry_id=int(arguments["id"]),
                    )
                    if not existing_entries or existing_entries[0]["type"] != "plan":
                        raise KeyError("context entry does not exist")
                    if existing_entries[0]["status"] == "completed":
                        raise ValueError("plan is already completed")
                    completed_debrief = self._apply_memory_debrief(
                        int(arguments["id"]),
                        str(arguments["taskname"]),
                        arguments.get("debrief"),
                    )
                    changes["debrief"] = completed_debrief
                    changes["actor_id"] = self.token_record.actor_id
                elif "debrief" in arguments:
                    raise ValueError("plan debrief is only valid when status is completed")
                if "plan_id" in arguments:
                    changes["plan_id"] = arguments["plan_id"]
                entry = self.server.context_for(self.token_scope_root).update_plan(
                    int(arguments["id"]),
                    **changes,
                )
                if completed_debrief is not None:
                    entry["debrief"] = completed_debrief
                return entry
            except KeyError as exc:
                raise ApiError(
                    HTTPStatus.NOT_FOUND,
                    "context_not_found",
                    str(exc.args[0]),
                ) from None
            except ValueError as exc:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_context_entry",
                    str(exc),
                ) from None
        if name == "replace_note":
            try:
                return self.server.context_for(self.token_scope_root).replace_note(
                    int(arguments["id"]),
                    taskname=str(arguments["taskname"]),
                    content=str(arguments["content"]),
                    actor_id=self.token_record.actor_id,
                    plan_id=int(arguments["plan_id"]),
                )
            except KeyError as exc:
                raise ApiError(
                    HTTPStatus.NOT_FOUND,
                    "context_not_found",
                    str(exc.args[0]),
                ) from None
            except ValueError as exc:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_context_entry",
                    str(exc),
                ) from None
        if name == "query_memory":
            self._require_permission(
                self.token_record.can_read,
                "read permission is not granted",
            )
            try:
                entries, total = self.server.memory_for(self.token_scope_root).query(
                    query=str(arguments.get("query", "")),
                    category=str(arguments["category"]) if "category" in arguments else None,
                    status=str(arguments["status"]) if "status" in arguments else None,
                    severity=str(arguments["severity"]) if "severity" in arguments else None,
                    tag=str(arguments["tag"]) if "tag" in arguments else None,
                    path=str(arguments["path"]) if "path" in arguments else None,
                    include_archived=bool(arguments.get("include_archived", False)),
                    limit=int(arguments.get("limit", 100)),
                )
            except ValueError as exc:
                raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_memory_query", str(exc)) from None
            return {
                "memories": entries,
                "limit": int(arguments.get("limit", 100)),
                "total": total,
                "truncated": len(entries) < total,
            }
        if name == "get_memory":
            self._require_permission(
                self.token_record.can_read,
                "read permission is not granted",
            )
            memory_id = str(arguments["memory_id"])
            try:
                entry = self.server.memory_for(self.token_scope_root).get(memory_id)
                if bool(arguments.get("include_revisions", False)):
                    entry["revisions"] = self.server.memory_for(self.token_scope_root).revisions(
                        memory_id,
                        limit=int(arguments.get("revision_limit", 100)),
                    )
                return entry
            except KeyError as exc:
                raise ApiError(HTTPStatus.NOT_FOUND, "memory_not_found", str(exc.args[0])) from None
            except ValueError as exc:
                raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_memory_query", str(exc)) from None
        if name == "get_project_memory":
            self._require_permission(
                self.token_record.can_read,
                "read permission is not granted",
            )
            return self.server.memory_for(self.token_scope_root).project()
        if name == "add_memory":
            plan_id = self._require_existing_plan(arguments.get("plan_id"))
            try:
                return self.server.memory_for(self.token_scope_root).create(
                    category=arguments.get("category"),
                    key=arguments.get("key"),
                    title=arguments.get("title"),
                    content=arguments.get("content"),
                    status=arguments.get("status"),
                    severity=arguments.get("severity"),
                    tags=arguments.get("tags"),
                    paths=arguments.get("paths"),
                    plan_id=plan_id,
                    actor_id=self._memory_actor_id(),
                    message=str(arguments["message"]),
                )
            except (ValueError, RuntimeError) as exc:
                raise self._memory_error(exc) from None
        if name == "update_memory":
            plan_id = self._require_existing_plan(arguments.get("plan_id"))
            ignored = {
                "memory_id", "expected_revision", "plan_id", "taskname", "message"
            }
            changes = {key: value for key, value in arguments.items() if key not in ignored}
            try:
                return self.server.memory_for(self.token_scope_root).update(
                    str(arguments["memory_id"]),
                    changes=changes,
                    expected_revision=arguments["expected_revision"],
                    plan_id=plan_id,
                    actor_id=self._memory_actor_id(),
                    message=str(arguments["message"]),
                )
            except (KeyError, ValueError, RuntimeError) as exc:
                raise self._memory_error(exc) from None
        if name == "archive_memory":
            plan_id = self._require_existing_plan(arguments.get("plan_id"))
            try:
                return self.server.memory_for(self.token_scope_root).archive(
                    str(arguments["memory_id"]),
                    expected_revision=arguments["expected_revision"],
                    plan_id=plan_id,
                    actor_id=self._memory_actor_id(),
                    message=str(arguments["message"]),
                )
            except (KeyError, ValueError, RuntimeError) as exc:
                raise self._memory_error(exc) from None
        query_tools = {
            "list_files": self._handle_fs_list,
            "read_file": self._handle_fs_read,
            "stat_file": self._handle_fs_stat,
            "search_files": self._handle_fs_search,
            "list_tree": self._handle_fs_tree,
            "list_recycle": self._handle_recycle_list,
        }
        body_tools = {
            "write_file": self._handle_fs_write,
            "replace_text": self._handle_fs_replace,
            "create_directory": self._handle_fs_mkdir,
            "move_path": self._handle_fs_move,
            "delete_path": self._handle_fs_delete,
            "restore_recycle": self._handle_recycle_restore,
            "run_shell": self._handle_shell_exec,
            "create_schedule": self._handle_schedule_create,
            "start_upload": self._handle_upload_create,
            "create_share": self._handle_share_create,
        }
        self._capturing_mcp_tool = True
        self._mcp_tool_response: tuple[int, dict[str, Any]] | None = None
        try:
            if name in query_tools:
                query = {key: [str(value)] for key, value in arguments.items()}
                query_tools[name](query)
            elif name in body_tools:
                self._mcp_tool_arguments = arguments
                body_tools[name]()
            elif name == "read_binary_chunk":
                return self._mcp_read_binary_chunk(arguments)
            elif name == "prepare_download":
                return self._mcp_prepare_download(arguments)
            elif name == "get_web_preview_url":
                return self._mcp_web_preview_url(arguments)
            elif name == "inspect_share":
                query = {
                    key: [str(value)]
                    for key, value in arguments.items()
                    if key not in {"share_id", "plan_id", "taskname", "message"}
                }
                self._handle_share_query(str(arguments["share_id"]), query)
            elif name == "import_share":
                self._mcp_tool_arguments = arguments
                self._handle_share_import(str(arguments["share_id"]))
            elif name == "delete_share":
                self._handle_share_delete(str(arguments["share_id"]))
            elif name == "upload_chunk":
                return self._mcp_upload_chunk(arguments)
            elif name == "get_upload":
                return self._mcp_upload_transfer(
                    self._upload_record(str(arguments["upload_id"])).public(
                        self._upload_chunk_recommendation()
                    )
                )
            elif name == "finish_upload":
                self._handle_upload_commit(str(arguments["upload_id"]))
            elif name == "abort_upload":
                upload_id = str(arguments["upload_id"])
                try:
                    self.server.uploads.cancel(upload_id, self.token_record.token)
                except UploadError as exc:
                    self._raise_upload_error(exc)
                return {"upload_id": upload_id, "cancelled": True}
            elif name == "list_schedules":
                self._handle_schedule_list({})
            elif name == "get_schedule":
                self._handle_schedule_get(str(arguments["schedule_id"]))
            elif name == "update_schedule":
                self._mcp_tool_arguments = arguments
                self._handle_schedule_update(str(arguments["schedule_id"]))
            elif name == "delete_schedule":
                self._mcp_tool_arguments = arguments
                self._handle_schedule_delete(str(arguments["schedule_id"]))
            elif name == "run_schedule_now":
                self._mcp_tool_arguments = arguments
                self._handle_schedule_run(str(arguments["schedule_id"]))
            elif name == "pause_schedule":
                self._mcp_tool_arguments = arguments
                self._handle_schedule_pause(str(arguments["schedule_id"]))
            elif name == "resume_schedule":
                self._mcp_tool_arguments = arguments
                self._handle_schedule_resume(str(arguments["schedule_id"]))
            elif name == "list_schedule_runs":
                query = {"limit": [str(arguments.get("limit", 50))]}
                self._handle_schedule_runs(str(arguments["schedule_id"]), query)
            elif name == "get_schedule_run":
                self._handle_schedule_run_get(str(arguments["run_id"]))
            elif name == "list_tasks":
                query = {key: [str(value)] for key, value in arguments.items()}
                self._handle_task_list(query)
            elif name == "list_sandbox_processes":
                query = {key: [str(value)] for key, value in arguments.items()}
                self._handle_sandbox_processes(query)
            elif name == "read_task_output":
                task_id = str(arguments["task_id"])
                query = {
                    key: [str(value)]
                    for key, value in arguments.items()
                    if key != "task_id"
                }
                self._handle_task_output(task_id, query)
            elif name == "send_task_input":
                self._mcp_tool_arguments = arguments
                self._handle_task_stdin(str(arguments["task_id"]))
            elif name == "interrupt_task":
                self._handle_task_interrupt(str(arguments["task_id"]))
            elif name == "kill_task":
                self._handle_task_kill(str(arguments["task_id"]))
            elif name == "get_task":
                self._handle_task(str(arguments["task_id"]))
            else:
                raise McpError(-32602, "Unknown tool", {"name": name})
            if self._mcp_tool_response is None:
                raise RuntimeError("tool did not produce a response")
            status, payload = self._mcp_tool_response
            self._mcp_context_status = status
            if name == "start_upload":
                payload = self._mcp_upload_transfer(payload)
            return payload
        finally:
            self._capturing_mcp_tool = False
            self._mcp_tool_response = None
            if hasattr(self, "_mcp_tool_arguments"):
                del self._mcp_tool_arguments

    def _mcp_read_binary_chunk(self, arguments: dict[str, Any]) -> dict[str, Any]:
        self._require_permission(self.token_record.can_read, "read permission is not granted")
        path = self._resolve_path(str(arguments["path"]))
        offset = int(arguments.get("offset", 0))
        length = int(arguments.get("length", self.server.config.mcp_binary_chunk_bytes))
        if length > self.server.config.mcp_binary_chunk_bytes:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "chunk_too_large",
                f"MCP binary chunks are limited to {self.server.config.mcp_binary_chunk_bytes} bytes",
            )
        descriptor = self._safe_open_descriptor(path, os.O_RDONLY)
        with os.fdopen(descriptor, "rb") as handle:
            file_stat = os.fstat(handle.fileno())
            if not stat.S_ISREG(file_stat.st_mode):
                raise ApiError(HTTPStatus.BAD_REQUEST, "not_a_file", "path is not a regular file")
            size = file_stat.st_size
            if offset > size:
                raise ApiError(
                    HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE,
                    "invalid_offset",
                    "offset is beyond the end of the file",
                    {"size": size},
                )
            handle.seek(offset)
            data = handle.read(length)
        next_offset = offset + len(data)
        return {
            "path": str(path),
            "data_base64": base64.b64encode(data).decode("ascii"),
            "offset": offset,
            "bytes_read": len(data),
            "next_offset": next_offset,
            "size": size,
            "eof": next_offset >= size,
        }

    def _mcp_prepare_download(self, arguments: dict[str, Any]) -> dict[str, Any]:
        self._require_permission(self.token_record.can_read, "read permission is not granted")
        requested = str(arguments["path"])
        path = self._resolve_path(requested)
        descriptor = self._safe_open_descriptor(path, os.O_RDONLY)
        try:
            file_stat = os.fstat(descriptor)
            if not stat.S_ISREG(file_stat.st_mode):
                raise ApiError(HTTPStatus.BAD_REQUEST, "not_a_file", "path is not a regular file")
        finally:
            os.close(descriptor)
        return {
            "path": str(path),
            "size": file_stat.st_size,
            "etag": self._stat_etag(file_stat),
            "content_type": mimetypes.guess_type(path.name)[0] or "application/octet-stream",
            "transfer": {
                "url": (
                    f"{self._public_base_url().rstrip('/')}/transfer/fs/content"
                    f"?path={quote(requested, safe='')}"
                ),
                "methods": ["GET", "HEAD"],
                "authorization": "reuse_mcp_bearer",
                "request_headers": {
                    "Range": "bytes=<start>-<end>",
                    "If-None-Match": "<optional-etag>",
                },
                "response_headers": [
                    "Content-Length",
                    "Content-Range",
                    "ETag",
                    "Last-Modified",
                ],
            },
        }

    def _mcp_web_preview_url(self, arguments: dict[str, Any]) -> dict[str, Any]:
        self._require_permission(self.token_record.can_read, "read permission is not granted")
        self._require_permission(
            self.token_record.can_preview,
            "web preview permission is not granted",
        )
        requested = str(arguments.get("path", "."))
        path = self._resolve_path(requested)
        try:
            relative = path.relative_to(self.token_scope_root)
        except ValueError:
            raise ApiError(
                HTTPStatus.FORBIDDEN,
                "preview_outside_workspace",
                "web preview only serves files inside the token workspace",
            ) from None
        encoded_path = quote(relative.as_posix(), safe="/") if relative.parts else ""
        url = (
            f"{self._preview_public_base_url().rstrip('/')}/"
            f"{quote(self.token_record.preview_token, safe='')}"
        )
        if encoded_path:
            url += "/" + encoded_path
        else:
            url += "/"
        descriptor: int | None = None
        try:
            descriptor = self._safe_open_descriptor(path, os.O_RDONLY)
            file_stat = os.fstat(descriptor)
            exists = True
            kind = "directory" if stat.S_ISDIR(file_stat.st_mode) else "file" if stat.S_ISREG(file_stat.st_mode) else None
        except ApiError as exc:
            if exc.code != "path_not_found":
                raise
            exists = False
            kind = None
        finally:
            if descriptor is not None:
                os.close(descriptor)
        if kind == "directory" and not url.endswith("/"):
            url += "/"
        return {
            "path": str(path),
            "url": url,
            "exists": exists,
            "type": kind,
            "directory_index": "index.html",
            "preview_token_scope": "web_preview_only",
        }

    def _mcp_upload_transfer(self, payload: dict[str, Any]) -> dict[str, Any]:
        upload_id = str(payload["upload_id"])
        transfer_base = f"{self._public_base_url().rstrip('/')}/transfer/uploads/{quote(upload_id, safe='')}"
        result = dict(payload)
        result["raw_transfer"] = {
            "url": transfer_base,
            "status_methods": ["GET", "HEAD"],
            "append_method": "PATCH",
            "append_content_type": "application/octet-stream",
            "append_headers": {
                "Upload-Offset": "<current offset>",
                "OpenKapsel-Plan-Id": "<required owning plan id>",
                "OpenKapsel-Taskname": "<required task grouping name>",
                "OpenKapsel-Message": "<required brief operation summary>",
            },
            "commit_url": transfer_base + "/commit",
            "commit_method": "POST",
            "abort_method": "DELETE",
            "commit_and_abort_headers": {
                "OpenKapsel-Plan-Id": "<required owning plan id>",
                "OpenKapsel-Taskname": "<required task grouping name>",
                "OpenKapsel-Message": "<required brief operation summary>"
            },
            "authorization": "reuse_mcp_bearer",
            "recommended_chunk_size": self.server.config.upload_chunk_bytes,
        }
        return result

    def _mcp_upload_chunk(self, arguments: dict[str, Any]) -> dict[str, Any]:
        self._require_permission(self.token_record.can_write, "write permission is not granted")
        encoded = str(arguments["data_base64"])
        try:
            data = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_base64", "data_base64 is not valid Base64") from None
        if len(data) > self.server.config.mcp_binary_chunk_bytes:
            raise ApiError(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "chunk_too_large",
                f"MCP binary chunks are limited to {self.server.config.mcp_binary_chunk_bytes} bytes",
            )
        try:
            record = self.server.uploads.append(
                str(arguments["upload_id"]),
                self.token_record.token,
                int(arguments["offset"]),
                io.BytesIO(data),
                len(data),
            )
        except UploadError as exc:
            self._raise_upload_error(exc)
        return record.public(self._upload_chunk_recommendation())

    def _validate_mcp_origin(self) -> None:
        origin = self.headers.get("Origin")
        if origin is None:
            return
        public = urlsplit(self._public_base_url())
        expected = f"{public.scheme}://{public.netloc}"
        if not hmac.compare_digest(origin.rstrip("/"), expected):
            raise ApiError(HTTPStatus.FORBIDDEN, "invalid_origin", "Origin is not allowed")

    def _send_mcp_error(
        self,
        request_id: str | int | None,
        code: int,
        message: str,
        data: Any = None,
        *,
        status: int = HTTPStatus.OK,
    ) -> None:
        error: dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            error["data"] = data
        self._send_mcp_json(status, {"jsonrpc": "2.0", "id": request_id, "error": error})

    def _send_mcp_json(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if status >= 400:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        self.wfile.write(data)

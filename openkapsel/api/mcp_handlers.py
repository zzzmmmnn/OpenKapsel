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

from openkapsel.errors import ApiError, McpError
from openkapsel.api.mcp import (
    MCP_PROTOCOL_VERSION,
    PUBLIC_SERVER_VERSION,
    SUPPORTED_PROTOCOL_VERSIONS,
    resolve_auxiliary_operation,
    tools_for,
    validate_arguments,
)
from openkapsel.context.conversation import (
    DEFAULT_RECENT_CONVERSATION_COUNT,
    MAX_RECENT_CONVERSATION_PAGES,
)
from openkapsel.files.uploads import UploadError
from openkapsel.auth.tokens import CredentialRenewalNotDue


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
                redact_linked_secrets=not (
                    method == "tools/call"
                    and (
                        params.get("name") in {"credential_get", "credential_renew"}
                        or (
                            params.get("name") == "capability_call"
                            and isinstance(params.get("arguments"), dict)
                            and params["arguments"].get("family") == "credential"
                            and params["arguments"].get("operation") in {"get", "renew"}
                        )
                    )
                ),
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
                "File paths are workspace-relative unless the selected tool accepts an authorized absolute path. "
                "On first use of a workspace, query the most recent Conversation context first and use it to restore recent user/AI context before planning or modifying anything. "
                "Query or reuse an active root Plan before writes and load relevant Memory when durable cross-task facts matter. "
                "Attach every modifying tool to its owning plan_id, taskname, and message; reads are recorded only when taskname and message are supplied. "
                "Low-frequency Shell, Task, Schedule, Sharing, Web, and Credential operations use capability_call; load the matching Discovery section for operation schemas (Shell and Task share discovery/shell)."
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
        operation_requirements = {
            ("fs_edit_text", "replace"): ("old", "new"),
            ("fs_edit_text", "insert_before"): ("match", "content"),
            ("fs_edit_text", "insert_after"): ("match", "content"),
        }
        required = operation_requirements.get((name, arguments.get("operation")), ())
        missing = [key for key in required if key not in arguments]
        if missing:
            raise McpError(
                -32602,
                f"{name} operation={arguments.get('operation')} requires: "
                + ", ".join(missing),
                {"name": name},
            )

        effective_name = name
        effective_arguments = arguments
        effective_tool = tool
        if name == "capability_call":
            family = str(arguments["family"])
            operation = str(arguments["operation"])
            try:
                effective_tool, effective_name, injected_operation, args_schema = (
                    resolve_auxiliary_operation(
                        self.token_record,
                        self.token_scope_root != self.server.config.root,
                        family,
                        operation,
                    )
                )
            except (KeyError, PermissionError):
                raise McpError(
                    -32602,
                    "Unknown or unauthorized capability operation",
                    {"family": family, "operation": operation},
                ) from None
            inner_args = dict(arguments.get("args", {}))
            try:
                validate_arguments({"inputSchema": args_schema}, inner_args)
            except ValueError as exc:
                raise McpError(
                    -32602,
                    str(exc),
                    {"family": family, "operation": operation},
                ) from None
            if injected_operation is not None:
                inner_args["operation"] = injected_operation
            inner_properties = effective_tool["inputSchema"]["properties"]
            for field in ("plan_id", "taskname", "message"):
                if field in arguments and field in inner_properties:
                    inner_args[field] = arguments[field]
            try:
                validate_arguments(effective_tool, inner_args)
            except ValueError as exc:
                raise McpError(
                    -32602,
                    str(exc),
                    {"family": family, "operation": operation},
                ) from None
            effective_arguments = inner_args

        context_tools = {
            "conversation_create",
            "conversation_append",
            "conversation_query",
            "context_query",
            "context_plan_tree",
            "context_add",
            "context_plan_update",
            "context_note_replace",
            "memory_query",
            "memory_get",
            "memory_project",
            "memory_add",
            "memory_update",
            "memory_archive",
            "credential_get",
            "credential_renew",
        }
        track_operation = effective_name not in context_tools and effective_name != "rpc_call" and (
            not effective_tool["annotations"]["readOnlyHint"]
            or bool(str(effective_arguments.get("message", "")).strip())
            or bool(str(effective_arguments.get("taskname", "")).strip())
        )
        try:
            if track_operation:
                plan_required = not effective_tool["annotations"]["readOnlyHint"]
                schedule_lifecycle_exception = (
                    effective_name == "schedule_control"
                    and str(effective_arguments.get("operation", "")) in {"resume", "end"}
                )
                self._begin_context_operation(
                    f"mcp.{effective_name}",
                    effective_arguments.get("taskname"),
                    effective_arguments.get("message"),
                    effective_arguments.get("plan_id"),
                    self._context_request_details(effective_arguments),
                    plan_required=plan_required,
                    require_plan_in_progress=(
                        plan_required and not schedule_lifecycle_exception
                    ),
                )
            self._mcp_context_status = HTTPStatus.OK
            payload = self._execute_mcp_tool(effective_name, effective_arguments)
        except ApiError as exc:
            error: dict[str, Any] = {"code": exc.code, "message": exc.message}
            if exc.details is not None:
                error["details"] = exc.details
            context_id = self._finalize_context_operation(exc.status, {"error": error})
            if context_id is not None:
                error["context_id"] = context_id
            return {
                "content": [{"type": "text", "text": json.dumps(error, ensure_ascii=False, separators=(",", ":"))}],
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
        text_result = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        return {
            "content": [{"type": "text", "text": text_result}],
            "structuredContent": payload,
            "isError": False,
        }

    def _mcp_workspace_credential_binding(self):
        oauth_cid = getattr(self, "oauth_connection_id", None)
        static_cid = getattr(self, "static_mcp_connection_id", None)
        if oauth_cid:
            connection = self.server.oauth.get(oauth_cid)
        elif static_cid:
            connection = self.server.static_mcp.get(static_cid)
        else:
            raise ApiError(
                HTTPStatus.FORBIDDEN,
                "mcp_connection_required",
                "workspace credentials can be exported only from an authenticated OAuth or Static MCP connection",
            )
        record = self.server.tokens.get_by_app_id(connection["app_id"])
        if record is None or not record.valid or record.path_prefix != connection["workspace"]:
            raise ApiError(
                HTTPStatus.FORBIDDEN,
                "workspace_configuration_unavailable",
                "linked workspace configuration is unavailable or changed",
            )
        return connection, record

    def _mcp_workspace_credentials(self, record, *, rotated: bool) -> dict[str, Any]:
        return {
            "workspace_url": (
                f"{self._public_base_url().rstrip('/')}/w/"
                f"{quote(record.token, safe='')}/"
            ),
            "control_token": record.control_token,
            "credentials_expires_at": record.credentials_expires_at,
            "credentials_valid": record.credentials_valid,
            "rotated": rotated,
        }

    def _execute_mcp_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "credential_get":
            _, record = self._mcp_workspace_credential_binding()
            return self._mcp_workspace_credentials(record, rotated=False)
        if name == "credential_renew":
            connection, _ = self._mcp_workspace_credential_binding()
            try:
                record = self.server.tokens.renew_credentials_for_app_if_due(
                    connection["app_id"], connection["workspace"]
                )
            except CredentialRenewalNotDue as exc:
                raise ApiError(
                    HTTPStatus.CONFLICT,
                    "credentials_renewal_not_due",
                    str(exc),
                    details={
                        "credentials_expires_at": exc.expires_at,
                        "remaining_seconds": exc.remaining_seconds,
                        "renewal_window_seconds": 2 * 24 * 60 * 60,
                    },
                ) from None
            except ValueError as exc:
                raise ApiError(
                    HTTPStatus.CONFLICT,
                    "credentials_cannot_be_renewed",
                    str(exc),
                ) from None
            # Keep this request internally coherent after rotating the TokenStore.
            self.token_record = record
            self.token_scope_root = self.server.tokens.scope_root(record)
            return self._mcp_workspace_credentials(record, rotated=True)
        if name == "discovery":
            return self._mcp_discovery(str(arguments.get("section", "main")))
        if name == "conversation_create":
            try:
                return self.server.context_for(self.token_scope_root).create_conversation(
                    arguments["conversation_id"],
                    arguments["entries"],
                    request_id=arguments.get("request_id"),
                    actor_id=self.token_record.actor_id,
                )
            except ConversationRequestConflict as exc:
                raise ApiError(HTTPStatus.CONFLICT, exc.code, str(exc)) from None
            except ValueError as exc:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_conversation",
                    str(exc),
                ) from None
        if name == "conversation_append":
            try:
                return self.server.context_for(self.token_scope_root).append_conversation(
                    conversation_id=arguments["conversation_id"],
                    writer_nonce=arguments["writer_nonce"],
                    entries=arguments["entries"],
                )
            except KeyError as exc:
                raise ApiError(
                    HTTPStatus.NOT_FOUND,
                    "conversation_not_found",
                    str(exc.args[0]),
                ) from None
            except PermissionError as exc:
                raise ApiError(
                    HTTPStatus.FORBIDDEN,
                    "conversation_writer_nonce_mismatch",
                    str(exc),
                ) from None
            except ValueError as exc:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_conversation",
                    str(exc),
                ) from None
        if name == "conversation_query":
            self._require_permission(
                self.token_record.can_read,
                "read permission is not granted",
            )
            try:
                conversation_id = (
                    int(arguments["conversation_id"])
                    if "conversation_id" in arguments
                    else None
                )
                if conversation_id is not None and "page" in arguments:
                    raise ValueError("page is only available without conversation_id")
                page = int(arguments.get("page", 1))
                conversations, total, next_conversation_id = self.server.context_for(
                    self.token_scope_root
                ).conversation_query(
                    conversation_id=conversation_id,
                    start_sub_id=(
                        int(arguments["start_sub_id"])
                        if "start_sub_id" in arguments
                        else None
                    ),
                    end_sub_id=(
                        int(arguments["end_sub_id"])
                        if "end_sub_id" in arguments
                        else None
                    ),
                    page=page,
                )
            except ValueError as exc:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_conversation_query",
                    str(exc),
                ) from None
            if conversation_id is None:
                return {
                    "conversations": conversations,
                    "next_conversation_id": next_conversation_id,
                    "page": page,
                    "total_conversations": total,
                    "has_more": (
                        page < MAX_RECENT_CONVERSATION_PAGES
                        and page * DEFAULT_RECENT_CONVERSATION_COUNT < total
                    ),
                }
            returned_entries = sum(len(item["entries"]) for item in conversations)
            return {
                "conversations": conversations,
                "next_conversation_id": next_conversation_id,
                "total_entries": total,
                "truncated": returned_entries < total,
            }
        if name == "context_query":
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
        if name == "context_plan_tree":
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
        if name == "context_add":
            return self._create_context_entry(arguments)
        if name == "context_plan_update":
            try:
                store = self.server.context_for(self.token_scope_root)
                entry_id = int(arguments["id"])
                expected_revision = arguments["expected_revision"]
                changes: dict[str, Any] = {
                    "expected_revision": expected_revision,
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
                changes["conversation_id"] = (
                    int(arguments["conversation_id"])
                    if "conversation_id" in arguments
                    else None
                )
                changes["writer_nonce"] = (
                    str(arguments["writer_nonce"])
                    if "writer_nonce" in arguments
                    else None
                )
                changes["conversation_entries"] = arguments.get("conversation_entries")
                changes["require_conversation"] = True
                completed_debrief: dict[str, Any] | None = None
                if changes["plan_status"] == "completed":
                    with store.plan_completion_transaction(
                        entry_id, expected_revision
                    ) as (connection, existing):
                        if existing["status"] == "completed":
                            raise ValueError("plan is already completed")
                        dry_run_changes = dict(changes)
                        dry_run_changes["debrief"] = {
                            "items": [],
                            "outcome": "no_change",
                            "memory_refs": [],
                            "memory_feedback": [],
                            "memory_conflicts": [],
                        }
                        dry_run_changes["actor_id"] = self.token_record.actor_id
                        store.update_plan(
                            entry_id,
                            **dry_run_changes,
                            _connection=connection,
                            _dry_run=True,
                        )
                        completed_debrief = self._apply_memory_debrief(
                            entry_id,
                            str(arguments["taskname"]),
                            arguments.get("debrief"),
                        )
                        changes["debrief"] = completed_debrief
                        changes["actor_id"] = self.token_record.actor_id
                        entry = store.update_plan(
                            entry_id,
                            **changes,
                            _connection=connection,
                        )
                else:
                    if "debrief" in arguments:
                        raise ValueError(
                            "plan debrief is only valid when status is completed"
                        )
                    entry = store.update_plan(entry_id, **changes)
                if completed_debrief is not None:
                    entry["debrief"] = completed_debrief
                return entry
            except KeyError as exc:
                raise ApiError(
                    HTTPStatus.NOT_FOUND,
                    "context_not_found",
                    str(exc.args[0]),
                ) from None
            except PermissionError as exc:
                raise ApiError(
                    HTTPStatus.FORBIDDEN,
                    "conversation_writer_nonce_mismatch",
                    str(exc),
                ) from None
            except RuntimeError as exc:
                raise ApiError(
                    HTTPStatus.PRECONDITION_FAILED,
                    "context_plan_revision_conflict",
                    str(exc),
                ) from None
            except ValueError as exc:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_context_entry",
                    str(exc),
                ) from None
        if name == "context_note_replace":
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
        if name == "memory_query":
            self._require_permission(
                self.token_record.can_read,
                "read permission is not granted",
            )
            try:
                entries, total = self.server.memory_for(self.token_scope_root).query(
                    query=str(arguments.get("query", "")),
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
        if name == "memory_get":
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
        if name == "memory_project":
            self._require_permission(
                self.token_record.can_read,
                "read permission is not granted",
            )
            return self.server.memory_for(self.token_scope_root).project()
        if name == "memory_add":
            plan_id = self._require_in_progress_plan(arguments.get("plan_id"))
            try:
                return self.server.memory_for(self.token_scope_root).create(
                    content=arguments.get("content"),
                    tags=arguments.get("tags"),
                    path=arguments.get("path"),
                    plan_id=plan_id,
                    actor_id=self._memory_actor_id(),
                    message=str(arguments["message"]),
                )
            except (ValueError, RuntimeError) as exc:
                raise self._memory_error(exc) from None
        if name == "memory_update":
            plan_id = self._require_in_progress_plan(arguments.get("plan_id"))
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
        if name == "memory_archive":
            plan_id = self._require_in_progress_plan(arguments.get("plan_id"))
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
            "fs_list": self._handle_fs_list,
            "fs_stat": self._handle_fs_stat,
            "fs_find": self._handle_fs_find,
            "fs_grep": self._handle_fs_grep,
            "fs_tree": self._handle_fs_tree,
            "recycle_list": self._handle_recycle_list,
        }
        body_tools = {
            "fs_read_files": self._handle_fs_read_files,
            "fs_manifest": self._handle_fs_manifest,
            "fs_mutate": self._handle_fs_mutate,
            "fs_read_large": self._handle_fs_read_large,
            "fs_replace_large": self._handle_fs_replace_large,
            "fs_mkdir": self._handle_fs_mkdir,
            "fs_move": self._handle_fs_move,
            "recycle_restore": self._handle_recycle_restore,
            "shell_exec": self._handle_shell_exec,
            "upload_create": self._handle_upload_create,
            "share_create": self._handle_share_create,
        }
        self._capturing_mcp_tool = True
        self._mcp_tool_response: tuple[int, dict[str, Any]] | None = None
        try:
            if name == "rpc_call":
                self._mcp_tool_arguments = {
                    key: value
                    for key, value in arguments.items()
                    if key in {"args", "timeout_seconds", "plan_id", "taskname", "message"}
                }
                if arguments.get("mapping_id"):
                    target = f"{arguments['mapping_id']}/rpc/{arguments['family']}/{arguments['operation']}"
                    self._handle_mapping_rpc(target)
                else:
                    target = f"{arguments['family']}/{arguments['operation']}"
                    self._handle_server_rpc(target)
            elif name in query_tools:
                query = {key: [str(item) for item in value] if isinstance(value, list) else [str(value)] for key, value in arguments.items()}
                query_tools[name](query)
            elif name in {"fs_write", "fs_edit_text", "fs_delete"}:
                context = {
                    key: arguments[key]
                    for key in ("plan_id", "taskname", "message")
                    if key in arguments
                }
                if name == "fs_write":
                    expected_etag = arguments.get("expected_etag")
                    item = {
                        "op": "file.replace" if expected_etag is not None else "file.create",
                        "path": arguments["path"],
                        "content": arguments["content"],
                        "encoding": arguments.get("encoding", "utf-8"),
                    }
                    if expected_etag is not None:
                        item["expected_etag"] = expected_etag
                elif name == "fs_edit_text":
                    operation = str(arguments["operation"])
                    if operation == "replace":
                        item = {
                            "op": "text.replace",
                            "path": arguments["path"],
                            "encoding": arguments.get("encoding", "utf-8"),
                            "expected_etag": arguments["expected_etag"],
                            "replacements": [{
                                "old": arguments["old"],
                                "new": arguments["new"],
                                "expected_count": arguments.get("expected_matches", 1),
                            }],
                        }
                    else:
                        item = {
                            "op": f"text.{operation}",
                            "path": arguments["path"],
                            "encoding": arguments.get("encoding", "utf-8"),
                            "expected_etag": arguments["expected_etag"],
                            "match": arguments["match"],
                            "content": arguments["content"],
                            "expected_count": arguments.get("expected_matches", 1),
                        }
                    if "start_line" in arguments:
                        item["start_line"] = arguments["start_line"]
                    if "end_line" in arguments:
                        item["end_line"] = arguments["end_line"]
                    if "start_text" in arguments:
                        item["start_text"] = arguments["start_text"]
                    if "end_text" in arguments:
                        item["end_text"] = arguments["end_text"]
                else:
                    item = {
                        "op": "path.delete",
                        "path": arguments["path"],
                        "expected_etag": arguments["expected_etag"],
                    }
                self._mcp_tool_arguments = {**context, "items": [item]}
                self._handle_fs_mutate()
            elif name in body_tools:
                self._mcp_tool_arguments = arguments
                body_tools[name]()
            elif name == "fs_read_binary":
                return self._mcp_read_binary_chunk(arguments)
            elif name == "fs_download":
                return self._mcp_prepare_download(arguments)
            elif name == "web_preview_url":
                return self._mcp_web_preview_url(arguments)
            elif name == "share_query":
                query = {
                    key: [str(value)]
                    for key, value in arguments.items()
                    if key not in {"share_id", "plan_id", "taskname", "message"}
                }
                self._handle_share_query(str(arguments["share_id"]), query)
            elif name == "share_import":
                self._mcp_tool_arguments = arguments
                self._handle_share_import(str(arguments["share_id"]))
            elif name == "share_delete":
                self._handle_share_delete(str(arguments["share_id"]))
            elif name == "upload_chunk":
                return self._mcp_upload_chunk(arguments)
            elif name == "upload_status":
                return self._mcp_upload_transfer(
                    self._upload_record(str(arguments["upload_id"])).public(
                        self._upload_chunk_recommendation()
                    )
                )
            elif name == "upload_commit":
                self._handle_upload_commit(str(arguments["upload_id"]))
            elif name == "upload_cancel":
                upload_id = str(arguments["upload_id"])
                try:
                    self.server.uploads.cancel(upload_id, self.token_record.token)
                except UploadError as exc:
                    self._raise_upload_error(exc)
                return {"upload_id": upload_id, "cancelled": True}
            elif name == "schedule_read":
                operation = str(arguments["operation"])
                if operation == "list":
                    self._handle_schedule_list({})
                elif operation == "get":
                    self._handle_schedule_get(str(arguments["schedule_id"]))
                elif operation == "run_list":
                    query = {"limit": [str(arguments.get("limit", 50))]}
                    self._handle_schedule_runs(str(arguments["schedule_id"]), query)
                else:
                    self._handle_schedule_run_get(str(arguments["run_id"]))
            elif name == "schedule_write":
                operation = str(arguments["operation"])
                body = {key: value for key, value in arguments.items() if key != "operation"}
                self._mcp_tool_arguments = body
                if operation == "create":
                    self._handle_schedule_create()
                else:
                    self._handle_schedule_update(str(arguments["schedule_id"]))
            elif name == "schedule_control":
                operation = str(arguments["operation"])
                schedule_id = str(arguments["schedule_id"])
                self._mcp_tool_arguments = {
                    key: value for key, value in arguments.items() if key != "operation"
                }
                if operation == "end":
                    self._handle_schedule_end(schedule_id)
                elif operation == "execute":
                    self._handle_schedule_run(schedule_id)
                elif operation == "pause":
                    self._handle_schedule_pause(schedule_id)
                else:
                    self._handle_schedule_resume(schedule_id)
            elif name == "task_list":
                query = {key: [str(value)] for key, value in arguments.items()}
                self._handle_task_list(query)
            elif name == "sandbox_processes":
                query = {key: [str(value)] for key, value in arguments.items()}
                self._handle_sandbox_processes(query)
            elif name == "task_output":
                task_id = str(arguments["task_id"])
                query = {
                    key: [str(value)]
                    for key, value in arguments.items()
                    if key != "task_id"
                }
                self._handle_task_output(task_id, query)
            elif name == "task_stdin":
                self._mcp_tool_arguments = arguments
                self._handle_task_stdin(str(arguments["task_id"]))
            elif name == "task_interrupt":
                self._handle_task_interrupt(str(arguments["task_id"]))
            elif name == "task_kill":
                self._handle_task_kill(str(arguments["task_id"]))
            elif name == "task_get":
                self._handle_task(str(arguments["task_id"]))
            else:
                raise McpError(-32602, "Unknown tool", {"name": name})
            if self._mcp_tool_response is None:
                raise RuntimeError("tool did not produce a response")
            status, payload = self._mcp_tool_response
            self._mcp_context_status = status
            if name == "upload_create":
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
        with self._open_binary(path) as handle:
            file_stat = self._stream_stat(handle)
            if not stat.S_ISREG(file_stat.st_mode):
                raise ApiError(HTTPStatus.BAD_REQUEST, "not_a_file", "path is not a regular file")
            from openkapsel.files.mutation import require_standard_file_size
            require_standard_file_size(file_stat, operation="fs_read_binary")
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
        file_stat = self._file_stat(path)
        if not stat.S_ISREG(file_stat.st_mode):
            raise ApiError(HTTPStatus.BAD_REQUEST, "not_a_file", "path is not a regular file")
        return {
            "path": str(path),
            "size": file_stat.st_size,
            "etag": self._path_etag(path, file_stat),
            "content_type": mimetypes.guess_type(path.name)[0] or "application/octet-stream",
            "transfer": {
                "url": (
                    f"{self._mcp_transfer_base()}/fs/content"
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
        try:
            file_stat = self._file_stat(path)
            exists = True
            kind = "directory" if stat.S_ISDIR(file_stat.st_mode) else "file" if stat.S_ISREG(file_stat.st_mode) else None
        except ApiError as exc:
            if exc.code != "path_not_found":
                raise
            exists = False
            kind = None
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
        transfer_base = self._mcp_transfer_base()
        encoded_id = quote(upload_id, safe="")
        result = dict(payload)
        result["raw_transfer"] = {
            "status_url": f"{transfer_base}/upload/status/{encoded_id}",
            "status_methods": ["GET", "HEAD"],
            "chunk_url": f"{transfer_base}/upload/chunk/{encoded_id}",
            "chunk_method": "PATCH",
            "chunk_content_type": "application/octet-stream",
            "chunk_headers": {
                "Upload-Offset": "<current offset>",
                "OpenKapsel-Plan-Id": "<required owning plan id>",
                "OpenKapsel-Taskname": "<required task grouping name>",
                "OpenKapsel-Message": "<required brief operation summary>",
            },
            "commit_url": f"{transfer_base}/upload/commit/{encoded_id}",
            "commit_method": "POST",
            "cancel_url": f"{transfer_base}/upload/cancel/{encoded_id}",
            "cancel_method": "POST",
            "commit_and_cancel_headers": {
                "OpenKapsel-Plan-Id": "<required owning plan id>",
                "OpenKapsel-Taskname": "<required task grouping name>",
                "OpenKapsel-Message": "<required brief operation summary>"
            },
            "authorization": "reuse_mcp_bearer",
            "recommended_chunk_size": self.server.config.upload_chunk_bytes,
        }
        return result

    def _mcp_transfer_base(self) -> str:
        base = self._public_base_url().rstrip("/")
        static_cid = getattr(self, "static_mcp_connection_id", None)
        if static_cid:
            return f"{base}/mcp-connect/{static_cid}/transfer"
        cid = getattr(self, "oauth_connection_id", None)
        return f"{base}/connect/{cid}/transfer" if cid else f"{base}/transfer"

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

    def _send_mcp_json(
        self,
        status: int,
        payload: dict[str, Any],
        *,
        redact_linked_secrets: bool = True,
    ) -> None:
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if redact_linked_secrets and (
            getattr(self, "oauth_connection_id", None)
            or getattr(self, "static_mcp_connection_id", None)
        ):
            for secret in (self.token_record.token, self.token_record.control_token):
                data = data.replace(secret.encode("utf-8"), b"<redacted>")
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

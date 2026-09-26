"""Mapping administration, discovery and authorized client tasks."""

from __future__ import annotations

import errno
import copy
import json
import os
import re
import sqlite3
from datetime import datetime
from pathlib import Path

from openkapsel.random_ids import token_urlsafe_alnum
from openkapsel.errors import ApiError


class MappingHandlersMixin:
    @staticmethod
    def _raise_mapping_rpc_unavailable(capability):
        details = capability.public()
        if capability.state == "offline":
            raise ApiError(503, "mapping_offline", "mapping client is offline", details)
        if capability.state == "disabled":
            code = "mapping_disabled" if capability.reason == "mapping_disabled" else "mapping_rpc_disabled"
            raise ApiError(403, code, "mapping RPC capability is disabled", details)
        raise ApiError(409, "mapping_rpc_unsupported", "mapping RPC capability is unsupported", details)

    def _path_etag(self, path, details):
        # Both direct RPC and binary streams now use provider device/inode/ns.
        return getattr(details, "_mapping_etag", None) or self._stat_etag(details)

    def _try_mapping_file_api(self, operation, *, query=None, body=None):
        """Route a complete same-mapping operation before touching its FUSE path."""
        from openkapsel.mapping.mapping_transport import FILE_API_WRITE_OPERATIONS

        query = copy.deepcopy(query or {})
        original = body or {}
        body = copy.deepcopy(original)
        write = operation in FILE_API_WRITE_OPERATIONS
        targets = []
        if operation in {"fs_list", "fs_stat", "fs_read", "fs_tree", "fs_search"}:
            value = self._query_one(query, "path", "." if operation in {"fs_list", "fs_tree", "fs_search"} else "")
            if not value:
                return False
            targets.append((query, "path", value, True))
        elif operation == "fs_manifest" and body.get("recursive") is True:
            targets.append((body, "path", body.get("path", "."), False))
        elif operation == "fs_mutate":
            items = body.get("items")
            if not isinstance(items, list) or not items or len(items) > self.server.config.max_batch_file_operations:
                return False
            if any(not isinstance(item, dict) or not isinstance(item.get("path"), str) for item in items):
                return False
            targets.extend((item, "path", item["path"], False) for item in items)
        elif operation == "fs_manifest":
            items = body.get("items")
            if not isinstance(items, list) or not items or len(items) > self.server.config.max_batch_file_operations:
                return False
            if any(not isinstance(item, dict) or not isinstance(item.get("path"), str) for item in items):
                return False
            targets.extend((item, "path", item["path"], False) for item in items)
        elif operation == "fs_read_many":
            paths = body.get("paths")
            if not isinstance(paths, list) or not paths or len(paths) > self.server.config.max_batch_file_operations:
                return False
            targets.extend((paths, index, value, False) for index, value in enumerate(paths))
        else:
            keys = ("source", "destination") if operation == "fs_move" else ("path",)
            targets.extend((body, key, body.get(key), False) for key in keys)

        selected = None
        for container, key, value, is_query in targets:
            if not isinstance(value, str) or not value or "\x00" in value:
                return False
            candidate = Path(value).expanduser()
            if not candidate.is_absolute():
                candidate = self.token_scope_root / candidate
            # Let the existing resolver handle aliases and non-mapping paths.
            candidate = Path(os.path.abspath(candidate))
            row = self.server.mappings.at_path(candidate)
            if row is None:
                candidate = candidate.resolve(strict=False)
                row = self.server.mappings.at_path(candidate)
            if row is None or (selected and selected["id"] != row["id"]):
                return False
            self._assert_inside_root(candidate)
            if write:
                self._assert_path_writable(candidate)
            try:
                self.server.mappings.check_path(candidate, write=write, protect_root=write)
            except OSError as exc:
                if exc.errno == errno.EHOSTDOWN:
                    raise ApiError(503, "mapping_offline", "mapping client is offline") from None
                if exc.errno == errno.EACCES:
                    raise ApiError(403, "mapping_disabled", "mapping is disabled") from None
                raise ApiError(403 if exc.errno in {errno.EROFS, errno.EBUSY} else 503,
                               "mapping_unavailable", "mapping is protected or read-only") from None
            mount = self.server.mappings.mount_path(row)
            relative = candidate.relative_to(mount)
            if ".openkapsel" in relative.parts or any(self._is_internal_transfer_name(p) for p in relative.parts):
                raise ApiError(403, "reserved_path", "workspace internal paths are not available")
            container[key] = [relative.as_posix()] if is_query else relative.as_posix()
            selected = row
        min_version = 2 if (operation == "fs_read_many" or
                            operation == "fs_manifest" and body.get("recursive") is True or
                            operation == "fs_search" and ("include" in query or "exclude" in query)) else 1
        if operation in {"fs_read", "fs_read_many"}:
            min_version = 3  # Explicit codecs and literal newline preservation.
        if operation in {"fs_read_large", "fs_replace_large", "fs_mutate"}:
            min_version = 4
        if selected is None:
            return False
        status, payload = self._call_mapping_file_api(
            selected, operation, query=query, body=body, min_version=min_version)
        if operation in {"fs_manifest", "fs_mutate", "fs_read_many"} and not original.get("recursive"):
            originals = original.get("paths") if operation == "fs_read_many" else [item["path"] for item in original["items"]]
            for item in payload.get("items", []):
                index = item.get("index")
                if isinstance(index, int) and 0 <= index < len(originals):
                    item["path"] = originals[index]
                if operation == "fs_mutate" and item.get("recycled"):
                    item["root"] = selected["name"]
        self._send_json(status, payload)
        return True

    def _call_mapping_file_api(self, selected, operation, *, query=None, body=None,
                               min_version=1, limits_override=None, search_prefix=None):
        """Return a coarse RPC result, also usable inside mixed-root traversal."""
        from openkapsel.client_runtime.client_file_api import FILE_API_LIMITS
        from openkapsel.mapping.mapping_transport import encode

        query, body = copy.deepcopy(query or {}), copy.deepcopy(body or {})
        capability = self.server.mappings.rpc_capability(
            selected["id"],
            "file",
            operation=operation,
            min_version=min_version,
            max_version=4,
        )
        if not capability.available:
            self._raise_mapping_rpc_unavailable(capability)
        limits = {name: getattr(self.server.config, name) for name in FILE_API_LIMITS}
        limits.update(limits_override or {})
        if any(value > FILE_API_LIMITS[name] for name, value in limits.items()):
            raise ApiError(409, "mapping_limits_incompatible", "server file limits exceed client RPC capabilities")
        for key in ("plan_id", "taskname", "message"):
            body.pop(key, None)
            query.pop(key, None)
        arguments = {"query": query, "body": body, "limits": limits,
                     "display_root": str(self.server.mappings.mount_path(selected))}
        if search_prefix is not None:
            with self.server.mappings.lock:
                session = self.server.mappings.sessions.get(selected["id"])
                features = session.capabilities.get("file_stream", {}) if session else {}
            if not isinstance(features, dict) or features.get("search_prefix") is not True:
                raise ApiError(409, "mapping_client_upgrade_required",
                               "update the mapping client for workspace-relative search filters")
            arguments["search_prefix"] = search_prefix
        try:
            encode({"id": "0" * 24, "op": "api_" + operation, "args": arguments})
        except OSError:
            raise ApiError(413, "mapping_request_too_large", "use binary upload or a smaller file request; no native fallback") from None
        result = self._mapping_rpc(selected, "api_" + operation, arguments)
        if not isinstance(result, dict) or not isinstance(result.get("status"), int):
            raise ApiError(502, "invalid_mapping_response", "client returned an invalid file API response")
        if "error" in result:
            error = result["error"]
            if not isinstance(error, dict) or not 400 <= result["status"] <= 599:
                raise ApiError(502, "invalid_mapping_response", "client returned an invalid error")
            raise ApiError(result["status"], error.get("code", "mapping_operation_failed"),
                           error.get("message", "client operation failed"), error.get("details"))
        payload = result.get("body")
        if not isinstance(payload, dict) or result["status"] not in {200, 201, 207}:
            raise ApiError(502, "invalid_mapping_response", "client returned an invalid file API result")
        return result["status"], payload

    def _handle_mapping_provider(self, method, path):
        match = re.fullmatch(r"/mapping-connect/([A-Za-z0-9_-]{24})", path)
        if method != "GET" or not match or not self.server.config.mappings_enabled:
            raise ApiError(404, "not_found", "mapping endpoint is unavailable")
        headers = self.headers.get_all("Authorization") or []
        if len(headers) != 1 or not headers[0].startswith("Bearer "):
            raise ApiError(401, "mapping_credential_required", "mapping Bearer credential required")
        if self.headers.get("Origin") or self.headers.get("Upgrade", "").lower() != "websocket":
            raise ApiError(400, "mapping_websocket_required", "non-browser WebSocket connection required")
        if self.headers.get("Transfer-Encoding") or self.headers.get("Content-Length", "0") != "0":
            raise ApiError(400, "invalid_request", "WebSocket upgrade cannot contain a request body")
        try:
            row = self.server.mappings.store.authenticate(match[1], headers[0][7:])
            # Workspace expiration applies even though provider credentials are independent.
            if not any(record.valid and record.path_prefix == row["workspace"] for record in self.server.tokens.list()):
                raise PermissionError("workspace is unavailable")
            self.server.mappings.accept(self, row)
        except PermissionError:
            raise ApiError(401, "invalid_mapping_credential", "mapping credential or workspace is unavailable") from None
        except (ValueError, OSError):
            raise ApiError(409, "mapping_unavailable", "mapping could not accept the provider; check reservation and active session") from None

    def _handle_mapping_list(self):
        self._require_permission(self.token_record.can_read, "read permission is not granted")
        self._send_json(200, {"mappings": self.server.mappings.list(self.token_record.path_prefix)})

    def _rpc_args_with_policy(self, family, operation, args):
        payload = dict(args)
        if family == "git" and operation in {"fetch", "pull", "clone"}:
            if self.token_record.network_mode == "none":
                raise ApiError(403, "git_network_denied", "Git network access is not granted")
            payload["_network_mode"] = self.token_record.network_mode
            payload["_allowed_domains"] = list(self.token_record.allowed_domains)
        return payload

    def _handle_server_rpc(self, target):
        match = re.fullmatch(
            r"([a-z][a-z0-9_]{0,31})/([a-z][a-z0-9_]{0,31})",
            target,
        )
        if not match:
            raise ApiError(404, "not_found", "server RPC operation does not exist")
        family, operation = match.groups()
        if family == "file":
            raise ApiError(400, "invalid_rpc_family", "file RPC uses the normal file APIs")
        capability = self.server.rpc_capabilities.get(family, {})
        spec = self.server.rpc_registry.operation_spec(family, operation)
        if capability.get("state") != "available" or spec is None:
            raise ApiError(
                409,
                "server_rpc_unsupported",
                "server RPC capability is unavailable or unsupported",
                {"family": family, "operation": operation, "capability": capability},
            )
        write = bool(spec["write"])
        execution = spec["execution"]
        if write:
            self._require_control_token()
            self._require_permission(self.token_record.can_write, "write permission is not granted")
        else:
            self._require_permission(self.token_record.can_read, "read permission is not granted")

        body = self._read_json()
        if (
            set(body) - {"args", "plan_id", "taskname", "message", "timeout_seconds"}
            or not isinstance(body.get("args", {}), dict)
        ):
            raise ApiError(400, "invalid_request", "body must contain args plus optional Context/task timeout fields")
        timeout = body.get("timeout_seconds")
        if timeout is not None and (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not 0 < float(timeout) <= 86400
        ):
            raise ApiError(400, "invalid_request", "timeout_seconds must be between 0 and 86400")
        if write:
            self._begin_context_operation(
                "server.rpc",
                body.get("taskname", self._context_header_taskname()),
                body.get("message", self._context_header_message()),
                body.get("plan_id", self._context_header_plan_id()),
                self._context_request_details(body),
                plan_required=True,
            )

        from openkapsel.client_runtime.client_files import ClientFiles

        files = ClientFiles(
            self.token_scope_root,
            writable=self.token_record.can_write,
            rpc_registry=self.server.rpc_registry,
            rpc_capabilities=self.server.rpc_capabilities,
        )
        rpc_args = self._rpc_args_with_policy(family, operation, body.get("args", {}))
        if execution == "task":
            task = self.server.tasks.start_rpc(
                family=family,
                operation=operation,
                cwd=self.token_scope_root,
                timeout_seconds=float(timeout) if timeout is not None else 600.0,
                owner_token=self.token_record.token,
                write=write,
                network_access=(family == "git" and operation in {"fetch", "pull", "clone"}),
                runner=lambda context: self.server.rpc_registry.dispatch_task(
                    files, family, operation, rpc_args, context
                ),
            )
            self._send_json(202, {
                "task_id": task.id,
                "status": task.status,
                "location": "server",
                "family": family,
                "operation": operation,
                "execution": "task",
                "status_url": f"{self._base_path()}/tasks/{task.id}",
            })
            return

        response = self.server.rpc_registry.dispatch(files, family + "_" + operation, rpc_args)
        if not isinstance(response, dict) or type(response.get("status")) is not int:
            raise ApiError(502, "invalid_server_rpc_response", "server RPC plugin returned an invalid response")
        if "error" in response:
            error = response["error"]
            if not isinstance(error, dict) or not 400 <= response["status"] <= 599:
                raise ApiError(502, "invalid_server_rpc_response", "server RPC plugin returned an invalid error")
            raise ApiError(
                response["status"],
                error.get("code", "server_rpc_failed"),
                error.get("message", "server RPC plugin failed"),
                error.get("details"),
            )
        result = response.get("body")
        if response["status"] != 200 or not isinstance(result, dict):
            raise ApiError(502, "invalid_server_rpc_response", "server RPC plugin returned an invalid result")
        self._send_json(200, {
            "location": "server",
            "family": family,
            "operation": operation,
            "result": result,
        })

    def _handle_mapping_rpc(self, target):
        match = re.fullmatch(
            r"([A-Za-z0-9_-]{24})/rpc/([a-z][a-z0-9_]{0,31})/([a-z][a-z0-9_]{0,31})",
            target,
        )
        if not match:
            raise ApiError(404, "not_found", "mapping RPC operation does not exist")
        mid, family, operation = match.groups()
        if family == "file":
            raise ApiError(400, "invalid_rpc_family", "file RPC uses the normal file APIs")
        row = self._mapping_for_caller(mid)
        capability = self.server.mappings.rpc_capability(
            mid,
            family,
            operation=operation,
            min_version=1,
        )
        if not capability.available:
            self._raise_mapping_rpc_unavailable(capability)
        if (
            capability.operation_spec is None
            or not isinstance(capability.operation_spec.get("write"), bool)
            or capability.operation_spec.get("execution") not in {"sync", "task"}
        ):
            raise ApiError(
                409,
                "mapping_rpc_metadata_required",
                "mapping RPC operation does not advertise write/execution metadata",
                capability.public(),
            )
        write = capability.operation_spec["write"]
        execution = capability.operation_spec["execution"]
        if write:
            self._require_control_token()
            self._require_permission(self.token_record.can_write, "write permission is not granted")
            if not row["writable"]:
                raise ApiError(403, "mapping_read_only", "mapping is read-only")
        else:
            self._require_permission(self.token_record.can_read, "read permission is not granted")

        body = self._read_json()
        if (
            set(body) - {"args", "plan_id", "taskname", "message", "timeout_seconds"}
            or not isinstance(body.get("args", {}), dict)
        ):
            raise ApiError(400, "invalid_request", "body must contain args plus optional Context/task timeout fields")
        timeout = body.get("timeout_seconds")
        if timeout is not None and (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not 0 < float(timeout) <= 86400
        ):
            raise ApiError(400, "invalid_request", "timeout_seconds must be between 0 and 86400")
        if write:
            self._begin_context_operation(
                "mapping.rpc",
                body.get("taskname", self._context_header_taskname()),
                body.get("message", self._context_header_message()),
                body.get("plan_id", self._context_header_plan_id()),
                self._context_request_details(body),
                plan_required=True,
            )
        rpc_args = self._rpc_args_with_policy(family, operation, body.get("args", {}))
        if execution == "task":
            from openkapsel.execution.shell_routing import client_summary

            raw_task_id = token_urlsafe_alnum(18)
            task_args = {
                "task_id": raw_task_id,
                "rpc": {
                    "family": family,
                    "operation": operation,
                    "args": rpc_args,
                },
            }
            if timeout is not None:
                task_args["timeout_seconds"] = float(timeout)
            try:
                started = self._mapping_rpc(row, "task_start", task_args)
            except ApiError as exc:
                ambiguous_errnos = {
                    errno.ETIMEDOUT,
                    errno.EHOSTDOWN,
                    errno.EPIPE,
                    errno.ECONNRESET,
                    errno.ECONNABORTED,
                }
                details = dict(exc.details) if isinstance(exc.details, dict) else {}
                may_have_started = details.get("errno") in ambiguous_errnos
                details.update({
                    "candidate_task_id": f"client.{mid}.{raw_task_id}",
                    "task_start_confirmed": False,
                    "task_may_have_started": may_have_started,
                })
                if "recovery" not in details:
                    details["recovery"] = (
                        "Reconnect and query/list the candidate task before retrying a write task start."
                        if may_have_started
                        else "Resolve the reported client condition, then retry; this task start was not dispatched."
                    )
                raise ApiError(exc.status, exc.code, exc.message, details, exc.headers) from None
            task = client_summary(mid, started)
            task.update(
                family=family,
                operation=operation,
                execution="task",
                status_url=f"{self._base_path()}/tasks/{task['task_id']}",
            )
            self._send_json(202, task)
            return
        result = self._mapping_rpc(row, family + "_" + operation, rpc_args)
        if not isinstance(result, dict) or type(result.get("status")) is not int:
            raise ApiError(502, "invalid_mapping_response", "invalid RPC plugin response")
        if "error" in result:
            error = result["error"]
            if not isinstance(error, dict) or not 400 <= result["status"] <= 599:
                raise ApiError(502, "invalid_mapping_response", "invalid RPC plugin error")
            raise ApiError(
                result["status"],
                error.get("code", "mapping_rpc_failed"),
                error.get("message", "mapping RPC plugin failed"),
                error.get("details"),
            )
        payload = result.get("body")
        if result["status"] != 200 or not isinstance(payload, dict):
            raise ApiError(502, "invalid_mapping_response", "invalid RPC plugin result")
        self._send_json(200, {
            "mapping_id": mid,
            "family": family,
            "operation": operation,
            "result": payload,
        })

    def _start_file_transfer(self, source, destination, *, move=False):
        self._require_permission(self.token_record.can_read and self.token_record.can_write, "read and write permissions are required")
        try:
            source.relative_to(self.token_scope_root)
            destination.relative_to(self.token_scope_root)
        except ValueError:
            raise ApiError(403, "path_outside_root", "transfers are restricted to this workspace and its mappings") from None
        if source == self.token_scope_root or destination == self.token_scope_root or source == destination or source in destination.parents:
            raise ApiError(400, "invalid_transfer", "cannot transfer workspace root or copy a directory into itself")
        try:
            self.server.mappings.check_path(source, write=move, protect_root=True)
            self.server.mappings.check_path(destination, write=True, protect_root=True)
            result = self.server.file_transfers.start(source, destination, self.token_scope_root,
                move=move, max_nodes=self.server.config.max_tree_nodes)
        except (ValueError, OSError) as exc:
            raise ApiError(409, "transfer_unavailable", str(exc)) from None
        self._send_json(202, result)

    def _handle_file_copy(self):
        body = self._read_json()
        if "overwrite" in body:
            raise ApiError(400, "overwrite_not_supported", "recycle the existing destination before copying")
        source = self._resolve_path(self._required_string(body, "source"))
        destination = self._resolve_path(self._required_string(body, "destination"), write=True)
        self._start_file_transfer(source, destination)

    def _handle_file_transfer(self, target):
        tid, *actions = target.split("/")
        try:
            job = self.server.file_transfers.get(tid, self.token_scope_root)
        except KeyError:
            raise ApiError(404, "transfer_not_found", "transfer does not exist") from None
        if self.command == "POST":
            self._read_json()
            self._require_permission(self.token_record.can_read and self.token_record.can_write, "read and write permissions are required")
            # Re-authorize current paths on every explicit resume.
            self._resolve_path(job["source"], write=job["move"])
            self._resolve_path(job["destination"], write=True)
            if actions == ["cancel"]:
                job["cancel"].set()
            elif actions == ["resume"]:
                try:
                    self.server.file_transfers.resume(job)
                except ValueError as exc:
                    raise ApiError(409, "transfer_busy", str(exc)) from None
            else:
                raise ApiError(404, "not_found", "unknown transfer action")
        self._send_json(200, self.server.file_transfers.public(job))

    def _mapping_for_caller(self, mid):
        try:
            row = self.server.mappings.store.get(mid)
        except KeyError:
            raise ApiError(404, "mapping_not_found", "mapping does not exist") from None
        if row["workspace"] != self.token_record.path_prefix:
            raise ApiError(404, "mapping_not_found", "mapping does not exist")
        return row

    def _mapping_rpc(self, row, operation, args):
        try:
            return self.server.mappings.call(row["id"], operation, args)
        except OSError as exc:
            status = {errno.EROFS: 403, errno.EACCES: 403, errno.EINVAL: 400, errno.ENOENT: 404,
                      errno.E2BIG: 413, errno.EPIPE: 409, errno.ENOTDIR: 400,
                      errno.EEXIST: 409, errno.EBUSY: 409, errno.ESTALE: 409}.get(exc.errno, 503)
            client_message = exc.strerror if isinstance(exc.strerror, str) else ""
            details = {"errno": exc.errno}
            if client_message:
                details["client_message"] = client_message[:200]
            if exc.errno == errno.EBUSY and client_message == "client task or retained-result limit reached":
                details["recovery"] = (
                    "List completed client tasks and read each task output through its final offset "
                    "so retained results are collected, then retry."
                )
                raise ApiError(
                    409,
                    "client_task_capacity_reached",
                    "client task capacity is full because running tasks or uncollected completed results are retained",
                    details,
                ) from None
            raise ApiError(
                status,
                "mapping_operation_failed",
                client_message or "client operation failed",
                details,
            ) from None

    def _handle_mapping_tasks(self, mid, query):
        row = self._mapping_for_caller(mid)
        self._require_permission(self.token_record.shell_mode != "none", "Shell permission is required for client tasks")
        if self.command == "GET":
            tasks = [
                task
                for task in self._mapping_rpc(row, "task_list", {})
                if task.get("kind", "shell") == "shell"
            ]
            self._send_json(200, {"tasks": tasks})
            return
        body = self._read_json()
        if not row["writable"] or not self.token_record.can_write:
            raise ApiError(403, "client_execution_requires_write", "client execution requires a writable mapping and caller")
        args = {"task_id": token_urlsafe_alnum(18), "argv": body.get("argv"), "cwd": body.get("cwd", ".")}
        if "timeout_seconds" in body:
            args["timeout_seconds"] = body["timeout_seconds"]
        self._send_json(202, self._mapping_rpc(row, "task_start", args))

    def _handle_mapping_task(self, target, query):
        mid, _tasks, tid, *action_parts = target.split("/")
        row = self._mapping_for_caller(mid)
        self._require_permission(self.token_record.shell_mode != "none", "Shell permission is required for client tasks")
        action = action_parts[0] if action_parts else "get"
        task_meta = self._mapping_rpc(row, "task_get", {"task_id": tid, "offset": 0})
        if task_meta.get("kind", "shell") != "shell":
            raise ApiError(404, "task_not_found", "task does not exist")
        if self.command == "GET" and action == "get":
            args = {"task_id": tid, "offset": self._query_int(query, "offset", 0, minimum=0)}
        elif self.command == "POST" and action in {"stdin", "interrupt", "kill"}:
            body = self._read_json()
            args = {"task_id": tid, "data": body.get("data", ""), "eof": body.get("eof", False)}
        else:
            raise ApiError(404, "not_found", "task operation does not exist")
        self._send_json(200, self._mapping_rpc(row, "task_" + action, args))

    def _mapped_recycle_root(self, root):
        if root in {"", "."}:
            return None
        if not isinstance(root, str) or "/" in root or "\\" in root:
            raise ApiError(400, "invalid_recycle_root", "root must be '.' or a mapping name")
        return next((r for r in self.server.mappings.store.list(self.token_record.path_prefix) if r["name"] == root), None) or self._missing_mapping()

    def _handle_recycle_purge(self):
        self._require_permission(self.token_record.can_write, "write permission is not granted")
        body = self._read_json()
        if body.get("confirm") is not True:
            raise ApiError(400, "confirmation_required", "permanent purge requires confirm=true")
        rid = self._required_string(body, "recycle_id")
        row = self._mapped_recycle_root(body.get("root", "."))
        if row:
            result = self._mapping_rpc(row, "recycle_purge", {"recycle_id": rid})
        else:
            from openkapsel.files.recycle import RecycleError
            try:
                result = self.server.recycle_for(self.token_scope_root).purge(rid)
            except RecycleError as exc:
                raise ApiError(exc.status, exc.code, exc.message) from None
        self._send_json(200, result)

    @staticmethod
    def _missing_mapping():
        raise ApiError(404, "mapping_not_found", "recycle root does not exist")

    def _recycle_path(self, path):
        row = self.server.mappings.at_path(path)
        if row:
            self.server.mappings.check_path(path, write=True, protect_root=True)
            result = self._mapping_rpc(row, "recycle", {"path": path.relative_to(self.server.mappings.mount_path(row)).as_posix()})
            result["root"] = row["name"]
            return result
        return self.server.recycle_for(self.token_scope_root).recycle(path)

    def _handle_admin_mappings(self, method):
        session = self._require_admin_session()
        if session is None:
            return
        message = ""
        if method == "POST":
            form = self._read_form()
            if not self._valid_csrf(session, form):
                raise ApiError(403, "csrf", "CSRF validation failed")
            action = self._form_one(form, "action")
            manager = self.server.mappings
            try:
                if action == "create":
                    app_id = self._form_one(form, "app_id")
                    record = self.server.tokens.get_by_app_id(app_id)
                    if not record or not record.valid:
                        raise ValueError("select an active workspace")
                    name = self._form_one(form, "name")
                    scope = self.server.tokens.scope_root(record)
                    if self.server.storage_providers.path_reserved(record.path_prefix, name):
                        raise ValueError("mapping name is reserved by a Storage Provider")
                    if (scope / name).exists() or (scope / name).is_symlink():
                        raise ValueError("mapping name already exists in the workspace")
                    row, secret = manager.store.create(record.path_prefix, name,
                        comment=self._form_one(form, "comment"), writable=self._form_one(form, "writable") == "on",
                        allow_exec=self._form_one(form, "allow_exec") == "on")
                    try:
                        manager.prepare(row)
                    except BaseException:
                        manager.store.delete(row["id"])
                        raise
                    message = self._mapping_client_config(row, secret)
                else:
                    mid = self._form_one(form, "id")
                    row = manager.store.get(mid)
                    manager.require_idle(mid)
                    manager.disconnect(mid)
                    if action == "delete":
                        manager.unmount(row)
                        manager.store.delete(mid)
                        manager.mount_path(row).rmdir()
                    elif action in {"update", "rotate"}:
                        if action == "update":
                            name = self._form_one(form, "name") or row["name"]
                            workspace = self._form_one(form, "workspace") or row["workspace"]
                            if not any(record.valid and record.path_prefix == workspace for record in self.server.tokens.list()):
                                raise ValueError("select an active workspace")
                            if self.server.storage_providers.path_reserved(workspace, name):
                                raise ValueError("mapping name is reserved by a Storage Provider")
                            row = manager.relocate(mid, workspace, name)
                        row, secret = manager.store.update(mid, rotate=action == "rotate", **({
                            "comment": self._form_one(form, "comment"), "writable": self._form_one(form, "writable") == "on",
                            "allow_exec": self._form_one(form, "allow_exec") == "on", "enabled": self._form_one(form, "enabled") == "on"
                        } if action == "update" else {}))
                        if secret:
                            message = self._mapping_client_config(row, secret)
                    else:
                        raise ValueError("invalid mapping action")
            except (ValueError, OSError, KeyError, sqlite3.IntegrityError) as exc:
                message = "Mapping operation failed: " + str(exc)
        elif method != "GET":
            raise ApiError(405, "method_not_allowed", "use GET or POST")
        self._send_admin_dashboard(session, active_panel="mappings", mapping_message=message)

    def _mapping_client_config(self, row, secret):
        base = self._public_base_url().rstrip("/")
        url = base.replace("https://", "wss://", 1).replace("http://", "ws://", 1).rstrip("/")
        return "Save this credential now; it is shown only once.\n" + json.dumps({
            "url": url + "/mapping-connect/" + row["id"], "token": secret,
            "root": "/path/to/export", "writable": row["writable"], "allow_exec": False,
            "auto_reload": False,
            "transport_timeout_seconds": 60,
            "rpc": {"git": True, "archive": True},
            "rpc_plugins": [],
            "sandbox": True, "proxy": None}, indent=2)

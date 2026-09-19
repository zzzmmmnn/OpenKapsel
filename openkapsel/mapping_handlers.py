"""Mapping administration, discovery and authorized client tasks."""

from __future__ import annotations

import errno
import json
import re
import secrets
import sqlite3

from .errors import ApiError


class MappingHandlersMixin:
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
            raise ApiError(409, "mapping_unavailable", "mapping could not accept the provider; check mount and active session") from None

    def _handle_mapping_list(self):
        self._require_permission(self.token_record.can_read, "read permission is not granted")
        self._send_json(200, {"mappings": self.server.mappings.list(self.token_record.path_prefix)})

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
                      errno.EEXIST: 409, errno.EBUSY: 409, errno.ESTALE: 409}.get(exc.errno, 503)
            raise ApiError(status, "mapping_operation_failed", "client operation failed", {"errno": exc.errno}) from None

    def _handle_mapping_tasks(self, mid, query):
        row = self._mapping_for_caller(mid)
        self._require_permission(self.token_record.shell_mode != "none", "Shell permission is required for client tasks")
        if self.command == "GET":
            self._send_json(200, {"tasks": self._mapping_rpc(row, "task_list", {})})
            return
        body = self._read_json()
        if not row["writable"] or not self.token_record.can_write:
            raise ApiError(403, "client_execution_requires_write", "client execution requires a writable mapping and caller")
        args = {"task_id": secrets.token_urlsafe(18), "argv": body.get("argv"), "cwd": body.get("cwd", ".")}
        if "timeout_seconds" in body:
            args["timeout_seconds"] = body["timeout_seconds"]
        self._send_json(202, self._mapping_rpc(row, "task_start", args))

    def _handle_mapping_task(self, target, query):
        mid, _tasks, tid, *action_parts = target.split("/")
        row = self._mapping_for_caller(mid)
        self._require_permission(self.token_record.shell_mode != "none", "Shell permission is required for client tasks")
        action = action_parts[0] if action_parts else "get"
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
            from .recycle import RecycleError
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
                    if len(manager.store.list()) >= 16:
                        raise ValueError("mapping limit is 16")
                    name = self._form_one(form, "name")
                    scope = self.server.tokens.scope_root(record)
                    if (scope / name).exists():
                        raise ValueError("mapping name already exists in the workspace")
                    row, secret = manager.store.create(record.path_prefix, name,
                        comment=self._form_one(form, "comment"), writable=self._form_one(form, "writable") == "on",
                        allow_exec=self._form_one(form, "allow_exec") == "on")
                    manager.mount(row)
                    message = self._mapping_client_config(row, secret)
                else:
                    mid = self._form_one(form, "id")
                    row = manager.store.get(mid)
                    manager.disconnect(mid)
                    if action == "delete":
                        manager.unmount(row)
                        manager.store.delete(mid)
                        manager.mount_path(row).rmdir()
                    elif action in {"update", "rotate"}:
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
            "sandbox": True, "proxy": None}, indent=2)

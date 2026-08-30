"""HTTP handlers for short-lived cross-workspace shares."""

from __future__ import annotations

import os
from http import HTTPStatus
from typing import Any

from .errors import ApiError
from .share_store import ShareError


class ShareHandlersMixin:
    def _handle_share_create(self) -> None:
        self._require_permission(self.token_record.can_read, "read permission is not granted")
        body = self._read_json()
        requested = self._required_string(body, "path")
        path = self._resolve_path(requested)
        try:
            relative = path.relative_to(self.token_scope_root)
        except ValueError:
            raise ApiError(
                HTTPStatus.FORBIDDEN,
                "share_outside_workspace",
                "only a file or directory inside the token workspace can be shared",
            ) from None
        if not relative.parts:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "share_workspace_root_forbidden",
                "share one file or one directory, not the entire workspace root",
            )
        descriptor = self._safe_open_descriptor(path, os.O_RDONLY)
        try:
            record, evicted = self.server.shares.create(
                descriptor,
                path.name,
                self.token_record.app_id,
            )
        except ShareError as exc:
            self._raise_share_error(exc)
        finally:
            os.close(descriptor)
        payload = record.public()
        payload["query_url"] = self._share_query_url(record.id)
        if evicted is not None:
            payload["evicted_oldest"] = True
        self._send_json(HTTPStatus.CREATED, payload)

    def _handle_share_query(
        self,
        share_id: str,
        query: dict[str, list[str]],
    ) -> None:
        relative_path = self._query_one(query, "path", "")
        depth = self._query_int(
            query,
            "depth",
            1,
            minimum=0,
            maximum=self.server.config.max_recursion_depth,
        )
        try:
            payload = self.server.shares.inspect(share_id, relative_path, depth)
        except ShareError as exc:
            self._raise_share_error(exc)
        self._send_json(
            HTTPStatus.OK,
            payload,
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        )

    def _handle_share_import(self, share_id: str) -> None:
        self._require_permission(self.token_record.can_write, "write permission is not granted")
        body = self._read_json()
        destination_value = self._required_string(body, "destination")
        create_parents = self._optional_bool(body, "create_parents", False)
        destination = self._resolve_path(destination_value, write=True)
        try:
            relative = destination.relative_to(self.token_scope_root)
        except ValueError:
            raise ApiError(
                HTTPStatus.FORBIDDEN,
                "share_import_outside_workspace",
                "shared content can only be imported into the token workspace",
            ) from None
        if not relative.parts:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "share_import_workspace_root_forbidden",
                "destination must name a new file or directory inside the workspace",
            )
        with self._safe_parent(destination, create_parents=create_parents) as parent:
            try:
                record = self.server.shares.import_into(share_id, parent.fd, parent.name)
            except ShareError as exc:
                self._raise_share_error(exc)
        self._send_json(
            HTTPStatus.CREATED,
            {
                "share_id": record.id,
                "destination": str(destination),
                "name": record.name,
                "type": record.kind,
                "size_bytes": record.size_bytes,
                "file_count": record.file_count,
            },
        )

    def _handle_share_delete(self, share_id: str) -> None:
        try:
            self.server.shares.delete(share_id, self.token_record.app_id)
        except ShareError as exc:
            self._raise_share_error(exc)
        self._send_empty(HTTPStatus.NO_CONTENT)

    def _share_query_url(self, share_id: str) -> str:
        return (
            f"{self._public_base_url().rstrip('/')}"
            f"/shares/{share_id}"
        )

    @staticmethod
    def _raise_share_error(exc: ShareError) -> None:
        raise ApiError(exc.status, exc.code, exc.message, exc.details) from None

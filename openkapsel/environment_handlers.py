"""Authenticated REST handlers for per-app Shell environments."""

from __future__ import annotations

from http import HTTPStatus

from .environment_store import EnvironmentConfigError, EnvironmentStore
from .errors import ApiError


class EnvironmentHandlersMixin:
    def _environment_store(self) -> EnvironmentStore:
        return EnvironmentStore(self.token_scope_root)

    @staticmethod
    def _environment_error(exc: Exception) -> ApiError:
        if isinstance(exc, EnvironmentConfigError):
            return ApiError(HTTPStatus.BAD_REQUEST, "invalid_environment", str(exc))
        return ApiError(
            HTTPStatus.SERVICE_UNAVAILABLE,
            "environment_unavailable",
            "environment configuration is unavailable",
        )

    def _handle_environment_get(self) -> None:
        try:
            config = self._environment_store().load(self.token_record.app_id)
        except (EnvironmentConfigError, OSError) as exc:
            raise self._environment_error(exc) from None
        self._send_json(
            HTTPStatus.OK,
            config.public(include_values=True),
            headers={"Cache-Control": "no-store"},
        )

    def _handle_environment_replace(self) -> None:
        body = self._read_json()
        try:
            config = self._environment_store().replace(
                self.token_record.app_id,
                body.get("variables", {}),
                body.get("rc", ""),
            )
        except (EnvironmentConfigError, OSError) as exc:
            raise self._environment_error(exc) from None
        self._send_json(
            HTTPStatus.OK,
            config.public(include_values=False),
            headers={"Cache-Control": "no-store"},
        )

    def _handle_environment_clear(self) -> None:
        body = self._read_json()
        try:
            cleared = self._environment_store().clear(self.token_record.app_id)
        except (EnvironmentConfigError, OSError) as exc:
            raise self._environment_error(exc) from None
        self._send_json(
            HTTPStatus.OK,
            {
                "cleared": cleared,
                "configured": False,
                "variable_names": [],
                "variable_count": 0,
                "rc_configured": False,
            },
            headers={"Cache-Control": "no-store"},
        )

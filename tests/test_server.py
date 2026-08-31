from __future__ import annotations

import base64
import contextlib
import hashlib
import http.client
import io
import json
import os
import re
import socket
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlencode

from openkapsel.security import (
    LEGACY_PASSWORD_SALT,
    hash_password,
    password_hash_needs_upgrade,
    verify_password,
)
from openkapsel.cgroups import TokenCgroupManager
from openkapsel.server import (
    AdminLoginLimiter,
    ApiError,
    ServerConfig,
    TaskRegistry,
    WorkspaceRequestHandler,
    create_server,
)
from openkapsel.tokens import PathGrant, TokenStore
from openkapsel.tasks import BoundedOutput
from openkapsel.uploads import UploadRegistry
from openkapsel.workspace_images import WorkspaceImage


class WorkspaceServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "workspace"
        self.root.mkdir()
        (self.root / "project").mkdir()
        (self.root / "project" / "hello.txt").write_text("hello world\nsecond line\n", encoding="utf-8")
        self.config_path = Path(self.temp.name) / "config.json"
        admin_hash = hash_password("correct-horse-battery")
        self.config_path.write_text(
            json.dumps(
                {
                    "admin": {
                        "username": "admin",
                        "password_hash": admin_hash,
                    }
                }
            ),
            encoding="utf-8",
        )
        self.config_path.chmod(0o600)
        self.fake_bwrap = Path(self.temp.name) / "fake-bwrap"
        self.fake_bwrap.write_text(
            "#!/bin/sh\n"
            "sandbox_cwd=/\n"
            "while [ \"$#\" -gt 0 ]; do\n"
            "  case \"$1\" in\n"
            "    --bind|--ro-bind) shift 3 ;;\n"
            "    --dev|--proc|--tmpfs|--cap-drop|--dir) shift 2 ;;\n"
            "    --symlink|--file) shift 3 ;;\n"
            "    --setenv) export \"$2=$3\"; shift 3 ;;\n"
            "    --chdir) sandbox_cwd=$2; shift 2 ;;\n"
            "    --) shift; break ;;\n"
            "    *) shift ;;\n"
            "  esac\n"
            "done\n"
            "cd \"$sandbox_cwd\" || exit $?\n"
            "exec \"$@\"\n",
            encoding="utf-8",
        )
        self.fake_bwrap.chmod(0o700)
        self.fake_rootlesskit = Path(self.temp.name) / "fake-rootlesskit"
        self.fake_rootlesskit.write_text(
            "#!/bin/sh\n"
            "while [ \"$#\" -gt 0 ]; do\n"
            "  case \"$1\" in\n"
            "    --) shift; break ;;\n"
            "    --*) shift ;;\n"
            "    *) break ;;\n"
            "  esac\n"
            "done\n"
            "exec \"$@\"\n",
            encoding="utf-8",
        )
        self.fake_rootlesskit.chmod(0o700)
        config = ServerConfig(
            root=self.root,
            token="test-token",
            name="Test Workspace",
            max_task_output_bytes=1024 * 1024,
            token_data_file=Path(self.temp.name) / "tokens.json",
            admin_username="admin",
            admin_password_hash=admin_hash,
            public_base_url="https://ws.example.test",
            preview_base_url="https://preview.ws.example.test",
            url_base_path="/kapsel",
            config_file=self.config_path,
            bubblewrap_path=self.fake_bwrap,
            rootlesskit_path=self.fake_rootlesskit,
            max_concurrent_shell_tasks=3,
            max_concurrent_shell_tasks_per_token=2,
            max_sse_streams=2,
            max_sse_streams_per_token=1,
            max_sse_duration_seconds=0.2,
            mcp_binary_chunk_bytes=128 * 1024,
        )
        self.server = create_server("127.0.0.1", 0, config)
        self.server.tokens.update("test-token", can_preview=True)
        self._test_plan_ids: dict[str, int] = {}
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def request(self, method: str, path: str, body: dict | None = None):
        encoded = None
        headers = {}
        if body is not None:
            encoded = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        status, raw, _ = self.raw_request(method, path, encoded, headers)
        return status, json.loads(raw.decode("utf-8"))

    def _ensure_test_plan(self, token: str) -> int:
        existing = self._test_plan_ids.get(token)
        if existing is not None:
            return existing
        record = self.server.tokens.get(token)
        plan_id = self.server.context_for(
            (self.server.config.root / record.path_prefix).resolve()
        ).add(
            "plan",
            "Test operation root plan",
            taskname="test-task",
            actor_id=record.actor_id,
        )
        self._test_plan_ids[token] = plan_id
        return plan_id

    def raw_request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        *,
        authorize: bool = True,
    ):
        request_headers = dict(headers or {})
        route_path = path.split("?", 1)[0]
        if (
            method in {"POST", "PUT", "PATCH", "DELETE"}
            and (
                route_path.startswith("/kapsel/w/")
                or route_path.startswith("/kapsel/transfer/")
            )
            and not route_path.endswith("/mcp")
            and "/context" not in route_path
        ):
            record = None
            if route_path.startswith("/kapsel/w/"):
                read_token = route_path.split("/", 4)[3]
                try:
                    record = self.server.tokens.get(read_token)
                except KeyError:
                    pass
            else:
                authorization = request_headers.get("Authorization", "")
                if authorization.startswith("Bearer "):
                    record = self.server.tokens.authenticate_control(
                        authorization.removeprefix("Bearer ").strip()
                    )
            if record is not None:
                request_headers.setdefault(
                    "OpenKapsel-Plan-Id",
                    str(self._ensure_test_plan(record.token)),
                )
            request_headers.setdefault("OpenKapsel-Taskname", "test-task")
            request_headers.setdefault("OpenKapsel-Message", "test operation")
        if authorize and "Authorization" not in request_headers and path.startswith("/kapsel/w/"):
            read_token = path.split("?", 1)[0].split("/", 4)[3]
            try:
                record = self.server.tokens.get(read_token)
            except KeyError:
                pass
            else:
                request_headers["Authorization"] = f"Bearer {record.control_token}"
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        payload = response.read()
        status = response.status
        response_headers = dict(response.getheaders())
        connection.close()
        return status, payload, response_headers

    def endpoint(self, suffix: str = "") -> str:
        return f"/kapsel/w/test-token{suffix}"

    def preview_endpoint(self, suffix: str = "", token: str = "test-token") -> str:
        preview_token = self.server.tokens.get(token).preview_token
        return f"/{preview_token}{suffix}"

    def raw_preview_request(
        self,
        method: str,
        suffix: str = "",
        *,
        token: str = "test-token",
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ):
        preview_headers = {"Host": "preview.ws.example.test"}
        preview_headers.update(headers or {})
        return self.raw_request(
            method,
            self.preview_endpoint(suffix, token),
            body,
            preview_headers,
        )

    def preview_request(self, method: str, suffix: str = "", *, token: str = "test-token"):
        status, raw, _ = self.raw_preview_request(method, suffix, token=token)
        return status, json.loads(raw.decode("utf-8"))

    def test_schedule_rest_and_mcp_use_separate_permission(self) -> None:
        denied_status, denied = self.request("GET", self.endpoint("/schedules"))
        self.assertEqual(HTTPStatus.FORBIDDEN, denied_status)
        self.assertEqual("schedule_permission_denied", denied["error"]["code"])

        self.server.tokens.update("test-token", can_schedule=True)
        plan_id = self._ensure_test_plan("test-token")
        create_status, created = self.request(
            "POST",
            self.endpoint("/schedules"),
            {
                "name": "test schedule",
                "schedule": {"type": "interval", "minutes": 3, "timezone": "UTC"},
                "command": "printf scheduled",
                "cwd": ".",
                "plan_id": plan_id,
                "taskname": "scheduler",
                "message": "Create test schedule",
            },
        )
        self.assertEqual(HTTPStatus.CREATED, create_status)
        schedule_id = created["schedule_id"]
        self.assertEqual(3, created["schedule"]["minutes"])

        run_status, run = self.request(
            "POST", self.endpoint(f"/schedules/{schedule_id}/run"), {}
        )
        self.assertEqual(HTTPStatus.ACCEPTED, run_status)
        self.assertIsNotNone(run["task_id"])
        deadline = time.monotonic() + 3
        while run["status"] in {"claimed", "running"} and time.monotonic() < deadline:
            time.sleep(0.02)
            item_status, run = self.request(
                "GET", self.endpoint(f"/schedule-runs/{run['run_id']}")
            )
            self.assertEqual(HTTPStatus.OK, item_status)
        self.assertEqual("succeeded", run["status"])

        list_status, runs = self.request(
            "GET", self.endpoint(f"/schedules/{schedule_id}/runs")
        )
        self.assertEqual(HTTPStatus.OK, list_status)
        self.assertEqual(1, runs["count"])

        tools = self.mcp_request("test-token", 90, "tools/list")[1]["result"]["tools"]
        self.assertIn("create_schedule", {tool["name"] for tool in tools})

    def mcp_request(
        self,
        token: str,
        request_id: int,
        method: str,
        params: dict | None = None,
        extra_headers: dict[str, str] | None = None,
    ):
        body = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            params = dict(params)
            if method == "tools/call" and isinstance(params.get("arguments"), dict):
                name = params.get("name")
                modifying_tools = {
                    "write_file",
                    "replace_text",
                    "create_directory",
                    "move_path",
                    "delete_path",
                    "restore_recycle",
                    "start_upload",
                    "upload_chunk",
                    "finish_upload",
                    "abort_upload",
                    "run_shell",
                    "send_task_input",
                    "interrupt_task",
                    "kill_task",
                    "create_share",
                    "import_share",
                    "delete_share",
                }
                if name in modifying_tools:
                    arguments = dict(params["arguments"])
                    arguments.setdefault("plan_id", self._ensure_test_plan(token))
                    arguments.setdefault("taskname", "test-task")
                    arguments.setdefault("message", "test MCP operation")
                    params["arguments"] = arguments
            body["params"] = params
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2025-11-25",
        }
        headers.update(extra_headers or {})
        status, raw, response_headers = self.raw_request(
            "POST",
            f"/kapsel/w/{token}/mcp",
            json.dumps(body).encode("utf-8"),
            headers,
        )
        return status, json.loads(raw.decode("utf-8")), response_headers

    def test_discovery_is_self_describing_and_bad_token_is_hidden(self) -> None:
        status, main = self.request("GET", self.endpoint("/"))
        self.assertEqual(200, status)
        self.assertEqual("main", main["section"])
        self.assertEqual(
            {"files", "context", "memory", "shell", "schedules", "web", "sharing", "full"},
            set(main["sections"]),
        )
        self.assertEqual(
            {
                "discovery", "discovery_section", "credentials_renew",
                "environment_get", "environment_replace", "environment_clear", "mcp",
            },
            set(main["endpoints"]),
        )
        self.assertEqual([".openkapsel"], main["path_rules"]["private_directories"])
        self.assertNotIn("available_tools", main["capabilities"]["mcp"])
        skill = main["skills"]["openkapsel_rest"]
        self.assertEqual("openkapsel-rest", skill["name"])
        self.assertEqual("none", skill["authentication"])
        self.assertEqual(
            "https://ws.example.test/kapsel/skills/openkapsel-rest/SKILL.md",
            skill["entrypoint_url"],
        )
        self.assertNotIn("test-token", json.dumps(skill))

        status, files = self.request("GET", self.endpoint("/discovery/files"))
        self.assertEqual(200, status)
        self.assertEqual("files", files["section"])
        self.assertIn("fs_list", files["endpoints"])
        self.assertIn("upload_create", files["endpoints"])
        self.assertNotIn("context_query", files["endpoints"])

        status, missing_section = self.request(
            "GET", self.endpoint("/discovery/unknown")
        )
        self.assertEqual(404, status)
        self.assertEqual(
            "discovery_section_not_found", missing_section["error"]["code"]
        )

        status, payload = self.request("GET", self.endpoint("/discovery/full"))
        self.assertEqual(200, status)
        self.assertEqual("full", payload["section"])
        self.assertLess(len(json.dumps(main)) * 3, len(json.dumps(payload)))
        section_endpoint_sets = []
        for section_name in ("files", "context", "memory", "shell", "schedules", "web", "sharing"):
            section_status, section_payload = self.request(
                "GET", self.endpoint(f"/discovery/{section_name}")
            )
            self.assertEqual(200, section_status, section_name)
            self.assertEqual(skill, section_payload["skills"]["openkapsel_rest"])
            section_endpoint_sets.append(set(section_payload["endpoints"]))
        self.assertEqual(
            set(payload["endpoints"])
            - {
                "discovery", "discovery_section", "credentials_renew", "mcp",
            },
            set().union(*section_endpoint_sets),
        )
        self.assertEqual(
            sum(len(items) for items in section_endpoint_sets),
            len(set().union(*section_endpoint_sets)),
        )
        storage = payload["limits"]["workspace_storage"]
        self.assertEqual("directory", storage["backend"])
        self.assertFalse(storage["hard_quota_enforced"])
        self.assertIsNone(storage["quota_bytes"])
        self.assertEqual("openkapsel/1", payload["protocol"])
        self.assertEqual(str(self.root.resolve()), payload["root"])
        self.assertEqual("POST", payload["endpoints"]["shell_exec"]["method"])
        self.assertEqual("POST", payload["endpoints"]["fs_mkdir"]["method"])
        self.assertEqual("POST", payload["endpoints"]["fs_manifest"]["method"])
        self.assertEqual("POST", payload["endpoints"]["fs_delete"]["method"])
        self.assertEqual("POST", payload["endpoints"]["fs_delete_batch"]["method"])
        self.assertEqual("POST", payload["endpoints"]["fs_move"]["method"])
        self.assertEqual("GET", payload["endpoints"]["recycle_list"]["method"])
        self.assertEqual("POST", payload["endpoints"]["recycle_restore"]["method"])
        self.assertEqual("POST", payload["endpoints"]["task_kill"]["method"])
        self.assertEqual("POST", payload["endpoints"]["share_create"]["method"])
        self.assertEqual("GET", payload["endpoints"]["share_query"]["method"])
        self.assertEqual(86400, payload["limits"]["share_ttl_seconds"])
        self.assertEqual(10, payload["limits"]["max_share_entries"])
        self.assertEqual(256 * 1024 * 1024, payload["limits"]["max_share_bytes"])
        self.assertEqual(1000, payload["limits"]["max_batch_file_operations"])
        self.assertTrue(payload["endpoints"]["web_preview"]["available"])
        self.assertEqual(
            "files.read + web_preview",
            payload["endpoints"]["web_preview"]["required_capability"],
        )
        self.assertTrue(payload["endpoints"]["task_kill"]["available"])
        self.assertEqual(
            "Bearer control token + shell",
            payload["endpoints"]["task_kill"]["required_capability"],
        )
        self.assertFalse(payload["endpoints"]["fs_delete"]["available"])
        self.assertTrue(
            payload["capabilities"]["web_preview"]["sandboxed_document_origin"]
        )
        self.assertTrue(payload["capabilities"]["web_preview"]["dedicated_origin"])
        self.assertFalse(payload["capabilities"]["web_preview"]["opaque_origin"])
        self.assertTrue(payload["capabilities"]["web_preview"]["allow_same_origin"])
        self.assertFalse(payload["capabilities"]["web_preview"]["cross_origin_readable"])
        self.assertTrue(payload["capabilities"]["web_preview"]["es_modules"])
        database = payload["capabilities"]["web_app_api"]["database"]
        web_app = payload["capabilities"]["web_app_api"]
        self.assertEqual("<app-directory>/api/app.py", web_app["entrypoint"])
        self.assertTrue(web_app["multiple_apps"])
        self.assertIn("first api path component", web_app["routing"])
        self.assertTrue(web_app["pid_namespace"])
        self.assertFalse(web_app["host_proc_visible"])
        self.assertEqual(
            "/opt/openkapsel/venv (read-only)", web_app["runtime_mount"]
        )
        self.assertEqual(
            {
                "fastapi", "sqlalchemy", "python-multipart", "jinja2", "httpx",
                "numpy", "numba", "pandas", "matplotlib", "scipy", "cryptography", "lxml",
                "pillow", "pyyaml", "beautifulsoup4",
            },
            set(web_app["available_libraries"]),
        )
        self.assertIn("network permission", web_app["available_libraries"]["httpx"])
        self.assertEqual("application-defined", web_app["authentication"])
        self.assertFalse(web_app["built_in_users"])
        self.assertFalse(web_app["built_in_sessions"])
        self.assertFalse(web_app["default_documentation_routes"]["public"])
        self.assertEqual(
            ["/docs", "/redoc", "/openapi.json"],
            web_app["default_documentation_routes"]["blocked_paths"],
        )
        self.assertNotIn("anonymous_session_cookie", web_app)
        self.assertNotIn("authenticated_cookie", web_app)
        self.assertIn(
            "adds no users, cookies, sessions, or auth routes",
            payload["endpoints"]["web_app_api"]["authentication"],
        )
        self.assertTrue(database["enabled"])
        self.assertEqual("openkapsel_runtime.database", database["runtime_module"])
        self.assertEqual("SQLAlchemy", database["library"])
        self.assertIn("parent directory", database["scope"])
        public_database_contract = json.dumps(database, ensure_ascii=False)
        self.assertNotIn("SQLite", public_database_contract)
        self.assertNotIn("sqlite3", public_database_contract)
        self.assertNotIn("PRAGMA", public_database_contract)
        self.assertTrue(database["storage"]["managed_by_runtime"])
        self.assertFalse(database["storage"]["application_paths_exposed"])
        self.assertTrue(database["storage"]["do_not_construct_storage_paths"])
        self.assertFalse(database["storage"]["workspace_file_api_access"])
        self.assertFalse(database["storage"]["static_preview_access"])
        self.assertFalse(database["storage"]["restricted_shell_access"])
        self.assertEqual("^[A-Za-z0-9_-]{1,64}$", database["database_id"]["pattern"])
        self.assertEqual(
            "database.engine(database_id='main')",
            database["python_api"]["engine"]["call"],
        )
        self.assertEqual(
            "with database.session(database_id='main') as session:",
            database["python_api"]["session"]["call"],
        )
        self.assertEqual(
            "commit and close", database["python_api"]["session"]["success"]
        )
        self.assertEqual(
            "rollback and close, then re-raise",
            database["python_api"]["session"]["exception"],
        )
        self.assertFalse(database["portability"]["backend_details_exposed"])
        self.assertIn("do not depend", database["portability"]["recommendation"])
        self.assertEqual(128 * 1024, payload["limits"]["max_mcp_binary_chunk_bytes"])
        self.assertEqual(200, payload["limits"]["max_context_query_entries"])
        self.assertEqual(100000, payload["limits"]["max_context_entries"])
        self.assertEqual(1000, payload["limits"]["context_trim_oldest_entries"])
        self.assertTrue(payload["capabilities"]["context"]["mutation_message_required"])
        self.assertTrue(payload["capabilities"]["context"]["mutation_taskname_required"])
        self.assertTrue(payload["capabilities"]["context"]["mutation_plan_id_required"])
        self.assertTrue(
            payload["capabilities"]["context"]
            ["plan_creation_returns_unfinished_root_plans"]
        )
        self.assertEqual(
            20,
            payload["capabilities"]["context"]["unfinished_root_plan_hint_limit"],
        )
        self.assertEqual(
            ["memory"],
            payload["capabilities"]["context"]["families"]["long_term"],
        )
        self.assertEqual(
            "capabilities.memory",
            payload["capabilities"]["context"]["memory_capability"],
        )
        memory_capability = payload["capabilities"]["memory"]
        self.assertTrue(memory_capability["enabled"])
        self.assertEqual("memory", memory_capability["type"])
        self.assertEqual("memory_id", memory_capability["identifier_field"])
        self.assertEqual(
            {"create", "update", "resolve", "archive"},
            set(memory_capability["memory_action_enum"]),
        )
        action_variants = memory_capability["memory_actions_schema"]["items"]["oneOf"]
        variants_by_action = {
            item["properties"]["action"]["const"]: item for item in action_variants
        }
        self.assertEqual(
            {"create", "update", "resolve", "archive"},
            set(variants_by_action),
        )
        self.assertEqual(
            {"action", "category", "title", "content"},
            set(variants_by_action["create"]["required"]),
        )
        self.assertEqual(
            {"action", "memory_id", "expected_revision"},
            set(variants_by_action["update"]["required"]),
        )
        self.assertIn("anyOf", variants_by_action["update"])
        self.assertNotIn("status", variants_by_action["resolve"]["properties"])
        self.assertEqual(
            memory_capability["memory_actions_schema"],
            payload["endpoints"]["context_plan_update"]["json"]["debrief"]
            ["properties"]["memory_actions"],
        )
        self.assertEqual(
            "plan_id",
            payload["capabilities"]["context"]["plan_hierarchy"]["relation_field"],
        )
        workflow_text = "\n".join(payload["workflow"])
        self.assertIn("root_plans=true", workflow_text)
        self.assertIn("Every modifying REST or MCP operation must provide plan_id", workflow_text)
        self.assertIn("get_plan_tree", workflow_text)
        self.assertIn("Uploads never overwrite", workflow_text)
        upload_contract = payload["endpoints"]["upload_create"]["json"]
        self.assertNotIn("overwrite", upload_contract)
        self.assertNotIn("expected_etag", upload_contract)
        direct_upload = payload["endpoints"]["fs_content_put"]
        self.assertNotIn("overwrite", direct_upload["url"])
        self.assertNotIn("If-Match", direct_upload["request_headers"])
        self.assertEqual(
            {"in_progress", "completed", "cancelled"},
            set(payload["capabilities"]["context"]["plan_statuses"]),
        )
        self.assertFalse(payload["capabilities"]["context"]["unmessaged_reads_recorded"])
        recordable_read_endpoints = {
            "fs_list",
            "fs_read",
            "fs_stat",
            "fs_search",
            "fs_tree",
            "fs_content",
            "recycle_list",
            "upload_status",
            "task_list",
            "task_status",
            "task_output",
            "task_stream",
            "sandbox_processes",
        }
        for endpoint_name in recordable_read_endpoints:
            query = payload["endpoints"][endpoint_name]["query"]
            self.assertIn("plan_id", query, endpoint_name)
            self.assertIn("taskname", query, endpoint_name)
            self.assertIn("message", query, endpoint_name)
            self.assertIn("optional", query["plan_id"], endpoint_name)
            self.assertIn("together", query["taskname"], endpoint_name)
            self.assertIn("together", query["message"], endpoint_name)
        self.assertEqual(4, payload["limits"]["max_finished_tasks_per_token"])
        self.assertEqual(60 * 60, payload["limits"]["finished_task_retention_seconds"])
        self.assertEqual("disk", payload["limits"]["finished_task_storage"])
        self.assertEqual("1", payload["server_version"])
        self.assertEqual(
            f"https://preview.ws.example.test/"
            f"{self.server.tokens.get('test-token').preview_token}/"
            "<workspace-relative-path>",
            payload["endpoints"]["web_preview"]["url"],
        )
        self.assertEqual("rejected", payload["path_rules"]["symlink_escape"])
        self.assertIn(".openkapsel", payload["path_rules"]["private_directory"])
        environment = payload["capabilities"]["environment"]
        self.assertTrue(environment["enabled"])
        self.assertFalse(environment["configured"])
        self.assertEqual("stable app_id within this token record", environment["scope"])
        self.assertEqual(["full", "bubblewrap", "podman"], environment["injected_into"])
        self.assertFalse(environment["service_environment_inherited"])
        self.assertFalse(environment["values_in_launcher_arguments"])
        self.assertIn("PATH", environment["reserved_names"])
        self.assertEqual(["OPENKAPSEL_"], environment["reserved_prefixes"])
        self.assertEqual(256, payload["limits"]["max_environment_variables"])
        self.assertEqual(128, payload["limits"]["max_environment_name_characters"])
        self.assertEqual(65536, payload["limits"]["max_environment_value_characters"])
        self.assertEqual(262144, payload["limits"]["max_environment_total_characters"])
        self.assertEqual(131072, payload["limits"]["max_environment_rc_characters"])
        self.assertTrue(payload["capabilities"]["task_control"]["force_kill"])
        self.assertIn("kill_task", payload["capabilities"]["mcp"]["available_tools"])
        self.assertIn("shell_task_token_limit_reached", payload["errors"]["shell_limit_codes"])
        self.assertTrue(
            all(
                "available" in endpoint and "required_capability" in endpoint
                for endpoint in payload["endpoints"].values()
            )
        )
        self.assertEqual(
            {
                "discovery",
                "discovery_section",
                "credentials_renew",
                "environment_get",
                "environment_replace",
                "environment_clear",
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
                "web_preview",
                "web_app_api",
                "fs_list",
                "fs_read",
                "fs_stat",
                "fs_manifest",
                "fs_search",
                "fs_tree",
                "fs_content",
                "fs_content_put",
                "fs_write",
                "fs_replace",
                "fs_replace_batch",
                "fs_mkdir",
                "fs_delete",
                "fs_delete_batch",
                "fs_move",
                "recycle_list",
                "recycle_restore",
                "share_create",
                "share_query",
                "share_import",
                "share_delete",
                "upload_create",
                "upload_status",
                "upload_chunk",
                "upload_commit",
                "upload_cancel",
                "mcp",
                "shell_exec",
                "schedule_list",
                "schedule_create",
                "schedule_get",
                "schedule_update",
                "schedule_delete",
                "schedule_run",
                "schedule_pause",
                "schedule_resume",
                "schedule_runs",
                "schedule_run_item",
                "task_list",
                "task_status",
                "task_output",
                "task_stream",
                "task_stdin",
                "task_interrupt",
                "task_kill",
                "sandbox_processes",
            },
            set(payload["endpoints"]),
        )
        self.assertFalse(payload["capabilities"]["recycle"])
        self.assertTrue(payload["capabilities"]["network"])
        self.assertEqual([], payload["capabilities"]["extra_paths"])
        self.assertTrue(payload["capabilities"]["shell_outside_workspace"])
        self.assertEqual(3, payload["limits"]["max_concurrent_shell_tasks"])
        self.assertEqual(2, payload["limits"]["max_concurrent_shell_tasks_per_token"])
        self.assertEqual(2, payload["limits"]["max_sse_streams"])
        self.assertEqual(1, payload["limits"]["max_sse_streams_per_token"])
        self.assertEqual(0.2, payload["limits"]["max_sse_duration_seconds"])
        self.assertEqual(
            ["output", "done", "reconnect"],
            payload["endpoints"]["task_stream"]["events"],
        )
        self.assertEqual(64, payload["limits"]["sandbox_max_processes"])
        self.assertEqual(256 * 1024 * 1024, payload["limits"]["sandbox_memory_bytes"])
        self.assertEqual(100, payload["limits"]["sandbox_cpu_percent"])
        workflow = " ".join(payload["workflow"])
        self.assertIn("skills.openkapsel_rest", workflow)
        self.assertIn(".openkapsel.env", workflow)
        self.assertIn("MCP clients", workflow)
        self.assertIn("fs_mkdir", workflow)
        self.assertIn("fs_move", workflow)
        self.assertIn("recycle_list", workflow)
        self.assertIn("restore_recycle", workflow)
        self.assertIn("share_id", workflow)
        self.assertIn("kill_task", workflow)
        self.assertIn("web_preview endpoint", workflow)
        self.assertIn("openkapsel_runtime.database", workflow)
        self.assertIn("portable SQLAlchemy APIs", workflow)
        self.assertIn("never accesses database storage directly", workflow)
        self.assertIn("OpenKapsel does not add an authentication layer", workflow)

        status, payload = self.request("GET", "/kapsel/w/wrong-token/")
        self.assertEqual(404, status)
        self.assertEqual("not_found", payload["error"]["code"])

    def test_public_rest_skill_manifest_files_and_dynamic_archive(self) -> None:
        status, raw_manifest, _ = self.raw_request(
            "GET", "/kapsel/skills/openkapsel-rest", authorize=False
        )
        self.assertEqual(200, status)
        manifest = json.loads(raw_manifest.decode("utf-8"))
        self.assertEqual("openkapsel-rest", manifest["name"])
        self.assertEqual("none", manifest["authentication"])
        self.assertNotIn("administration", manifest["description"].lower())
        self.assertIn("except MCP and administration", manifest["scope"])
        self.assertEqual(
            "https://ws.example.test/kapsel/skills/openkapsel-rest/archive.zip"
            f"?sha256={manifest['archive_sha256']}",
            manifest["archive_url"],
        )
        serialized = json.dumps(manifest, ensure_ascii=False)
        record = self.server.tokens.get("test-token")
        self.assertNotIn(record.token, serialized)
        self.assertNotIn(record.control_token, serialized)
        self.assertNotIn(record.preview_token, serialized)

        expected_names = set()
        for item in manifest["files"]:
            file_status, content, headers = self.raw_request(
                "GET",
                item["url"].removeprefix("https://ws.example.test"),
                authorize=False,
            )
            self.assertEqual(200, file_status, item["path"])
            self.assertEqual(item["bytes"], len(content))
            self.assertEqual(item["sha256"], hashlib.sha256(content).hexdigest())
            self.assertIn("ETag", headers)
            expected_names.add(f"openkapsel-rest/{item['path']}")

        archive_status, archive, archive_headers = self.raw_request(
            "GET", "/kapsel/skills/openkapsel-rest/archive.zip", authorize=False
        )
        self.assertEqual(200, archive_status)
        self.assertEqual("application/zip", archive_headers["Content-Type"])
        self.assertEqual(manifest["archive_bytes"], len(archive))
        self.assertEqual(manifest["archive_sha256"], hashlib.sha256(archive).hexdigest())
        with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
            self.assertEqual(expected_names, set(bundle.namelist()))
            self.assertTrue(bundle.read("openkapsel-rest/SKILL.md").startswith(b"---\n"))
            self.assertIn(
                "openkapsel-rest/scripts/openkapsel_upload_tree.py", bundle.namelist()
            )
            self.assertNotIn(
                "openkapsel-rest/references/administration.md", bundle.namelist()
            )
            self.assertNotIn(
                b"/admin", bundle.read("openkapsel-rest/references/endpoint-index.md")
            )

        head_status, head_body, head_headers = self.raw_request(
            "HEAD", "/kapsel/skills/openkapsel-rest/archive.zip", authorize=False
        )
        self.assertEqual(200, head_status)
        self.assertEqual(b"", head_body)
        self.assertEqual(str(len(archive)), head_headers["Content-Length"])
        cached_status, cached_body, _ = self.raw_request(
            "GET",
            "/kapsel/skills/openkapsel-rest/archive.zip",
            headers={"If-None-Match": archive_headers["ETag"]},
            authorize=False,
        )
        self.assertEqual(304, cached_status)
        self.assertEqual(b"", cached_body)

        missing_status, missing, _ = self.raw_request(
            "GET", "/kapsel/skills/openkapsel-rest/../config.json", authorize=False
        )
        self.assertEqual(404, missing_status)
        self.assertEqual(
            "skill_file_not_found",
            json.loads(missing.decode("utf-8"))["error"]["code"],
        )
        self.assertFalse(
            (Path(__file__).resolve().parents[1] / "skills/openkapsel-rest/archive.zip").exists()
        )

    def test_read_url_and_bearer_control_token_are_separate(self) -> None:
        record = self.server.tokens.get("test-token")
        status, raw, headers = self.raw_request(
            "GET",
            self.endpoint("/discovery/full"),
            authorize=False,
        )
        self.assertEqual(200, status)
        discovery = json.loads(raw)
        self.assertFalse(discovery["authentication"]["control_authorized"])
        self.assertEqual("<redacted>", discovery["authentication"]["control_token"])
        self.assertEqual(
            record.credentials_expires_at,
            discovery["authentication"]["read_token_expires_at"],
        )
        self.assertEqual(
            record.credentials_expires_at,
            discovery["authentication"]["control_token_expires_at"],
        )
        self.assertEqual(record.expires_at, discovery["authentication"]["preview_token_expires_at"])
        self.assertTrue(discovery["authentication"]["preview_token_uses_workspace_lifetime"])
        self.assertEqual(
            record.credentials_expires_at,
            discovery["token"]["credentials_expires_at"],
        )
        self.assertNotIn(record.control_token, raw.decode("utf-8"))
        self.assertTrue(discovery["capabilities"]["files"]["read"])
        self.assertFalse(discovery["capabilities"]["files"]["write"])
        self.assertFalse(discovery["capabilities"]["context"]["enabled"])
        self.assertEqual("none", discovery["capabilities"]["shell"])
        self.assertTrue(discovery["capabilities"]["extra_paths_redacted"])
        self.assertFalse(discovery["endpoints"]["mcp"]["available"])
        self.assertFalse(discovery["endpoints"]["context_query"]["available"])
        self.assertIn("redacted", discovery["endpoints"]["context_query"]["details"])
        self.assertFalse(discovery["endpoints"]["context_plan_tree"]["available"])
        self.assertIn("redacted", discovery["endpoints"]["context_plan_tree"]["details"])
        self.assertNotIn("json", discovery["endpoints"]["fs_write"])
        self.assertIn("redacted", discovery["endpoints"]["fs_write"]["details"])
        self.assertEqual("Authorization", headers["Vary"])

        status, raw, _ = self.raw_request(
            "GET",
            self.endpoint("/discovery/files"),
            authorize=False,
        )
        self.assertEqual(200, status)
        file_discovery = json.loads(raw)
        self.assertTrue(file_discovery["endpoints"]["fs_read"]["available"])
        self.assertFalse(file_discovery["endpoints"]["fs_write"]["available"])
        self.assertIn("redacted", file_discovery["endpoints"]["fs_write"]["details"])

        status, raw, _ = self.raw_request(
            "GET",
            self.endpoint("/fs/read?path=project/hello.txt"),
            authorize=False,
        )
        self.assertEqual(200, status)
        self.assertIn("hello world", json.loads(raw)["content"])

        status, raw, _ = self.raw_request(
            "GET",
            self.endpoint(
                "/fs/read?path=project/hello.txt&taskname=anonymous-read&message=record"
            ),
            authorize=False,
        )
        self.assertEqual(401, status)
        self.assertEqual("control_token_required", json.loads(raw)["error"]["code"])

        body = json.dumps({"path": "project/no-auth.txt", "content": "blocked"}).encode()
        status, raw, headers = self.raw_request(
            "POST",
            self.endpoint("/fs/write"),
            body,
            {"Content-Type": "application/json"},
            authorize=False,
        )
        self.assertEqual(401, status)
        self.assertEqual("control_token_required", json.loads(raw)["error"]["code"])

        self.assertEqual('Bearer realm="OpenKapsel"', headers["WWW-Authenticate"])
        self.assertFalse((self.root / "project" / "no-auth.txt").exists())

        status, raw, headers = self.raw_request(
            "GET",
            self.endpoint("/fs/read?path=project/hello.txt"),
            headers={"Authorization": "Bearer invalid-control-token"},
            authorize=False,
        )
        self.assertEqual(401, status)
        self.assertEqual("invalid_control_token", json.loads(raw)["error"]["code"])
        self.assertIn('error="invalid_token"', headers["WWW-Authenticate"])

        other = self.server.tokens.create(
            name="Other control",
            expires_at=None,
            path_prefix="other-control",
            can_read=True,
            can_write=True,
            shell_mode="none",
        )
        status, raw, _ = self.raw_request(
            "GET",
            self.endpoint("/fs/read?path=project/hello.txt"),
            headers={"Authorization": f"Bearer {other.control_token}"},
            authorize=False,
        )
        self.assertEqual(403, status)
        self.assertEqual("token_binding_mismatch", json.loads(raw)["error"]["code"])

        status, raw, _ = self.raw_request(
            "POST",
            self.endpoint("/mcp"),
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).encode(),
            {
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
            authorize=False,
        )
        self.assertEqual(401, status)
        self.assertEqual("control_token_required", json.loads(raw)["error"]["code"])

        status, privileged = self.request("GET", self.endpoint("/discovery/full"))
        self.assertEqual(200, status)
        self.assertTrue(privileged["authentication"]["control_authorized"])
        self.assertTrue(privileged["capabilities"]["files"]["write"])
        self.assertTrue(privileged["endpoints"]["mcp"]["available"])
        self.assertIn("json", privileged["endpoints"]["fs_write"])
        self.assertNotIn(record.control_token, json.dumps(privileged))

    def test_workspace_credentials_self_renew_only_inside_two_day_window(self) -> None:
        current = self.server.tokens.get("test-token")
        old_read = current.token
        old_control = current.control_token
        old_preview = current.preview_token
        old_actor = current.actor_id

        status, payload = self.request(
            "POST", self.endpoint("/credentials/renew")
        )
        self.assertEqual(409, status)
        self.assertEqual("credentials_renewal_not_due", payload["error"]["code"])
        self.assertEqual(old_read, self.server.tokens.get(old_read).token)

        due_at = datetime.now(timezone.utc) + timedelta(hours=47)
        current = self.server.tokens.update(
            old_read,
            credentials_expires_at=due_at.isoformat(),
        )
        status, raw, headers = self.raw_request(
            "POST",
            f"/kapsel/w/{old_read}/credentials/renew",
            headers={"Authorization": f"Bearer {current.control_token}"},
            authorize=False,
        )
        self.assertEqual(200, status)
        self.assertEqual("no-store", headers["Cache-Control"])

        renewed = json.loads(raw)
        self.assertNotEqual(old_read, renewed["read_token"])
        self.assertNotEqual(old_control, renewed["control_token"])
        self.assertEqual(
            f"https://ws.example.test/kapsel/w/{renewed['read_token']}/",
            renewed["workspace_url"],
        )
        renewed_record = self.server.tokens.get(renewed["read_token"])
        self.assertEqual(old_preview, renewed_record.preview_token)
        self.assertEqual(renewed["control_token"], renewed_record.control_token)
        self.assertEqual(old_actor, renewed_record.actor_id)
        expiry = datetime.fromisoformat(renewed["credentials_expires_at"])
        remaining = expiry - datetime.now(timezone.utc)
        self.assertGreater(remaining, timedelta(days=2, hours=23, minutes=59))
        self.assertLessEqual(remaining, timedelta(days=3))

        status, _raw, _headers = self.raw_request(
            "GET", f"/kapsel/w/{old_read}/", authorize=False
        )
        self.assertEqual(404, status)
        status, _raw, _headers = self.raw_request(
            "GET",
            f"/kapsel/w/{renewed['read_token']}/",
            headers={"Authorization": f"Bearer {renewed['control_token']}"},
            authorize=False,
        )
        self.assertEqual(200, status)

    def test_per_token_environment_rest_storage_validation_and_context_redaction(self) -> None:
        record = self.server.tokens.get("test-token")
        plan_id = self._ensure_test_plan(record.token)
        endpoint = lambda suffix: f"/kapsel/w/{record.token}{suffix}"

        status, raw, _ = self.raw_request(
            "GET", endpoint("/env"), authorize=False
        )
        self.assertEqual(401, status)
        self.assertEqual("control_token_required", json.loads(raw)["error"]["code"])

        status, replaced = self.request(
            "PUT",
            endpoint("/env"),
            {
                "variables": {"API_KEY": "very-secret", "APP_MODE": "test"},
                "rc": "export PROJECT_READY=yes\n",
                "plan_id": plan_id,
                "taskname": "environment-test",
                "message": "Configure the test Shell environment",
            },
        )
        self.assertEqual(200, status)
        self.assertEqual(["API_KEY", "APP_MODE"], replaced["variable_names"])
        self.assertNotIn("variables", replaced)
        self.assertNotIn("rc", replaced)
        path = (
            self.root
            / ".openkapsel"
            / "env"
            / f"{record.app_id}.json"
        )
        self.assertTrue(path.is_file())
        self.assertEqual(0o600, path.stat().st_mode & 0o777)

        status, discovery = self.request("GET", endpoint("/discovery/shell"))
        self.assertEqual(200, status)
        self.assertTrue(discovery["capabilities"]["environment"]["configured"])
        self.assertNotIn("very-secret", json.dumps(discovery))
        self.assertIn("environment_get", discovery["endpoints"])
        self.assertIn("environment_replace", discovery["endpoints"])
        self.assertIn("environment_clear", discovery["endpoints"])

        context_entries, total = self.server.context_for(self.root).query(
            entry_id=replaced["context_id"]
        )
        self.assertEqual(1, total)
        self.assertNotIn("variables", context_entries[0]["request"])
        self.assertNotIn("rc", context_entries[0]["request"])
        self.assertNotIn("very-secret", json.dumps(context_entries[0]))

        status, raw, headers = self.raw_request("GET", endpoint("/env"))
        self.assertEqual(200, status)
        loaded = json.loads(raw)
        self.assertEqual("very-secret", loaded["variables"]["API_KEY"])
        self.assertEqual("export PROJECT_READY=yes\n", loaded["rc"])
        self.assertEqual("no-store", headers["Cache-Control"])

        previous_host_secret = os.environ.get("OPENKAPSEL_HOST_SECRET")
        os.environ["OPENKAPSEL_HOST_SECRET"] = "must-not-leak"
        try:
            status, task = self.request(
                "POST",
                endpoint("/shell/exec"),
                {
                    "command": (
                        "printf '%s|%s|%s|%s' \"$API_KEY\" \"$PROJECT_READY\" "
                        "\"$OPENKAPSEL_HOST_SECRET\" \"$OPENKAPSEL_WORKSPACE\""
                    ),
                    "plan_id": plan_id,
                    "taskname": "environment-test",
                    "message": "Verify Shell environment injection",
                },
            )
            self.assertEqual(202, status)
            finished = self.wait_for_task(task["task_id"])
        finally:
            if previous_host_secret is None:
                os.environ.pop("OPENKAPSEL_HOST_SECRET", None)
            else:
                os.environ["OPENKAPSEL_HOST_SECRET"] = previous_host_secret
        self.assertEqual(0, finished["exit_code"])
        self.assertEqual(
            f"very-secret|yes||{self.root.resolve()}",
            finished["stdout"],
        )

        status, invalid = self.request(
            "PUT",
            endpoint("/env"),
            {
                "variables": {"HTTP_PROXY": "http://bypass.invalid"},
                "rc": "",
                "plan_id": plan_id,
                "taskname": "environment-test",
                "message": "Verify reserved environment validation",
            },
        )
        self.assertEqual(400, status)
        self.assertEqual("invalid_environment", invalid["error"]["code"])

        status, cleared = self.request(
            "DELETE",
            endpoint("/env"),
            {
                "plan_id": plan_id,
                "taskname": "environment-test",
                "message": "Clear the test Shell environment",
            },
        )
        self.assertEqual(200, status)
        self.assertTrue(cleared["cleared"])
        self.assertFalse(path.exists())
        status, empty = self.request("GET", endpoint("/env"))
        self.assertEqual(200, status)
        self.assertFalse(empty["configured"])

        secondary = self.server.tokens.create(
            name="Environment deletion token",
            expires_at=None,
            path_prefix="environment-delete",
            can_read=True,
            can_write=True,
            shell_mode="none",
        )
        secondary_plan = self._ensure_test_plan(secondary.token)
        secondary_endpoint = f"/kapsel/w/{secondary.token}/env"
        status, _ = self.request(
            "PUT",
            secondary_endpoint,
            {
                "variables": {"DELETE_WITH_TOKEN": "yes"},
                "rc": "",
                "plan_id": secondary_plan,
                "taskname": "environment-test",
                "message": "Create environment slated for token deletion",
            },
        )
        self.assertEqual(200, status)
        secondary_path = (
            self.root
            / "environment-delete"
            / ".openkapsel"
            / "env"
            / f"{secondary.app_id}.json"
        )
        self.assertTrue(secondary_path.is_file())
        self.server.tokens.delete(secondary.token)
        self.assertFalse(secondary_path.exists())

    def test_bodyless_endpoints_drain_unexpected_body_on_keepalive(self) -> None:
        def request_then_discovery(method: str, path: str, expected_status: int) -> None:
            connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
            try:
                connection.request(
                    method,
                    path,
                    body=b"{}",
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": (
                            "Bearer "
                            + self.server.tokens.get("test-token").control_token
                        ),
                        "OpenKapsel-Plan-Id": str(
                            self._ensure_test_plan("test-token")
                        ),
                        "OpenKapsel-Taskname": "keepalive-test",
                        "OpenKapsel-Message": "test bodyless operation",
                    },
                )
                response = connection.getresponse()
                self.assertEqual(expected_status, response.status)
                response.read()

                connection.request(
                    "GET",
                    self.endpoint("/"),
                    headers={
                        "Authorization": (
                            "Bearer "
                            + self.server.tokens.get("test-token").control_token
                        )
                    },
                )
                response = connection.getresponse()
                self.assertEqual(200, response.status)
                self.assertEqual("openkapsel/1", json.loads(response.read())["protocol"])
            finally:
                connection.close()

        status, upload = self.request(
            "POST",
            self.endpoint("/uploads"),
            {"path": "project/empty.bin", "size": 0},
        )
        self.assertEqual(201, status)
        request_then_discovery(
            "POST", self.endpoint(f"/uploads/{upload['upload_id']}/commit"), 201
        )

        status, upload = self.request(
            "POST",
            self.endpoint("/uploads"),
            {"path": "project/cancelled.bin", "size": 1},
        )
        self.assertEqual(201, status)
        request_then_discovery(
            "DELETE", self.endpoint(f"/uploads/{upload['upload_id']}"), 204
        )

        for action in ("interrupt", "kill"):
            status, task = self.request(
                "POST", self.endpoint("/shell/exec"), {"command": "sleep 30"}
            )
            self.assertEqual(202, status)
            request_then_discovery(
                "POST", self.endpoint(f"/tasks/{task['task_id']}/{action}"), 200
            )
            self.wait_for_task(task["task_id"])

    def test_browser_discovery_is_html_and_errors_keep_real_status(self) -> None:
        browser_headers = {"Accept": "text/html,application/xhtml+xml"}
        status, body, headers = self.raw_request(
            "GET",
            self.endpoint("/"),
            headers=browser_headers,
            authorize=False,
        )
        self.assertEqual(200, status)
        self.assertTrue(headers["Content-Type"].startswith("text/html"))
        page = body.decode("utf-8")
        self.assertIn("OpenKapsel Discovery", page)
        self.assertIn("openkapsel/1", page)
        self.assertIn("Machine-readable Discovery JSON", page)
        self.assertNotIn(self.server.tokens.get("test-token").control_token, page)
        self.assertIn("control_authorized", page)

        status, body, headers = self.raw_request(
            "GET",
            "/kapsel/w/invalid-browser-token/",
            headers=browser_headers,
        )
        self.assertEqual(404, status)
        self.assertTrue(headers["Content-Type"].startswith("text/html"))
        error_page = body.decode("utf-8")
        self.assertIn("HTTP 404", error_page)
        self.assertIn("not_found", error_page)

        status, payload = self.request("GET", self.endpoint("/"))
        self.assertEqual(200, status)
        self.assertEqual("openkapsel/1", payload["protocol"])

    def test_binary_stat_range_and_atomic_direct_upload(self) -> None:
        record = self.server.tokens.create(
            name="Binary upload workspace",
            expires_at=None,
            path_prefix="binary-upload",
            can_read=True,
            can_write=True,
            shell_mode="none",
            allowed_commands=(),
        )
        scope = self.root / "binary-upload"
        endpoint = lambda suffix: f"/kapsel/w/{record.token}{suffix}"
        content = bytes(range(256)) * 8
        query = urlencode({"path": "blob.bin"})
        digest = hashlib.sha256(content).hexdigest()
        status, raw, headers = self.raw_request(
            "PUT",
            endpoint(f"/fs/content?{query}"),
            content,
            {"Content-Type": "application/octet-stream", "X-Content-SHA256": digest},
        )
        self.assertEqual(201, status)
        written = json.loads(raw)
        self.assertEqual(digest, written["sha256"])
        self.assertEqual(content, (scope / "blob.bin").read_bytes())

        status, stat_payload = self.request("GET", endpoint(f"/fs/stat?{query}"))
        self.assertEqual(200, status)
        self.assertEqual(len(content), stat_payload["size"])
        self.assertEqual("application/octet-stream", stat_payload["content_type"])
        etag = stat_payload["etag"]

        status, body, headers = self.raw_request(
            "GET",
            endpoint(f"/fs/content?{query}"),
            headers={"Range": "bytes=100-299"},
        )
        self.assertEqual(206, status)
        self.assertEqual(content[100:300], body)
        self.assertEqual(f"bytes 100-299/{len(content)}", headers["Content-Range"])
        self.assertEqual("bytes", headers["Accept-Ranges"])

        status, body, headers = self.raw_request("HEAD", endpoint(f"/fs/content?{query}"))
        self.assertEqual(200, status)
        self.assertEqual(b"", body)
        self.assertEqual(str(len(content)), headers["Content-Length"])
        self.assertEqual(etag, headers["ETag"])

        status, payload = self.request(
            "PUT",
            endpoint(f"/fs/content?{query}"),
            None,
        )
        self.assertEqual(409, status)
        self.assertEqual("path_exists", payload["error"]["code"])

        replacement = b"replacement\x00binary"
        status, rejected, _ = self.raw_request(
            "PUT",
            endpoint(f"/fs/content?{query}&overwrite=true"),
            replacement,
            {"Content-Type": "application/octet-stream"},
        )
        self.assertEqual(400, status)
        self.assertEqual("overwrite_not_supported", json.loads(rejected)["error"]["code"])
        self.assertEqual(content, (scope / "blob.bin").read_bytes())

        status, recycled = self.request(
            "POST", endpoint("/fs/delete"), {"path": "blob.bin"}
        )
        self.assertEqual(200, status, recycled)
        self.assertEqual("blob.bin", recycled["original_path"])
        status, raw, _ = self.raw_request(
            "PUT",
            endpoint(f"/fs/content?{query}"),
            replacement,
            {"Content-Type": "application/octet-stream"},
        )
        self.assertEqual(201, status)
        self.assertEqual(replacement, (scope / "blob.bin").read_bytes())
        status, recycle = self.request("GET", endpoint("/recycle/list"))
        self.assertEqual(200, status)
        self.assertIn("blob.bin", [item["original_path"] for item in recycle["entries"]])

    def test_resumable_upload_offset_checksum_and_reload(self) -> None:
        content = (b"large-binary\x00" * 1000) + b"done"
        digest = hashlib.sha256(content).hexdigest()
        status, upload = self.request(
            "POST",
            self.endpoint("/uploads"),
            {
                "path": "project/resumable.bin",
                "size": len(content),
                "sha256": digest,
            },
        )
        self.assertEqual(201, status)
        self.assertEqual(self.server.config.upload_chunk_bytes, upload["recommended_chunk_size"])
        upload_id = upload["upload_id"]
        first = content[:5000]
        status, raw, _ = self.raw_request(
            "PATCH",
            self.endpoint(f"/uploads/{upload_id}"),
            first,
            {"Content-Type": "application/octet-stream", "Upload-Offset": "0"},
        )
        self.assertEqual(200, status)
        self.assertEqual(len(first), json.loads(raw)["offset"])

        status, payload = self.request("GET", self.endpoint(f"/uploads/{upload_id}"))
        self.assertEqual(200, status)
        self.assertEqual(len(first), payload["offset"])
        status, _, headers = self.raw_request("HEAD", self.endpoint(f"/uploads/{upload_id}"))
        self.assertEqual(200, status)
        self.assertEqual(str(len(first)), headers["Upload-Offset"])

        self.server.uploads = UploadRegistry(
            self.server.config.upload_state_dir,
            ttl_seconds=self.server.config.upload_ttl_seconds,
            max_file_bytes=self.server.config.max_file_bytes,
            max_incomplete_bytes=self.server.config.max_incomplete_upload_bytes,
            recommended_chunk_size=self.server.config.upload_chunk_bytes,
        )
        status, wrong, _ = self.raw_request(
            "PATCH",
            self.endpoint(f"/uploads/{upload_id}"),
            b"wrong",
            {"Content-Type": "application/octet-stream", "Upload-Offset": "0"},
        )
        self.assertEqual(409, status)
        self.assertEqual(len(first), json.loads(wrong)["error"]["details"]["expected"])

        status, raw, _ = self.raw_request(
            "PATCH",
            self.endpoint(f"/uploads/{upload_id}"),
            content[len(first) :],
            {"Content-Type": "application/octet-stream", "Upload-Offset": str(len(first))},
        )
        self.assertEqual(200, status)
        self.assertTrue(json.loads(raw)["complete"])
        status, committed = self.request("POST", self.endpoint(f"/uploads/{upload_id}/commit"), {})
        self.assertEqual(201, status)
        self.assertEqual(digest, committed["sha256"])
        self.assertEqual(content, (self.root / "project" / "resumable.bin").read_bytes())
        status, missing = self.request("GET", self.endpoint(f"/uploads/{upload_id}"))
        self.assertEqual(404, status)
        self.assertEqual("upload_not_found", missing["error"]["code"])

        status, duplicate = self.request(
            "POST",
            self.endpoint("/uploads"),
            {"path": "project/resumable.bin", "size": 1},
        )
        self.assertEqual(409, status)
        self.assertEqual("path_exists", duplicate["error"]["code"])
        status, forbidden_overwrite = self.request(
            "POST",
            self.endpoint("/uploads"),
            {"path": "project/resumable.bin", "size": 1, "overwrite": True},
        )
        self.assertEqual(400, status)
        self.assertEqual("overwrite_not_supported", forbidden_overwrite["error"]["code"])

        status, pending = self.request(
            "POST", self.endpoint("/uploads"), {"path": "project/race.bin", "size": 4}
        )
        self.assertEqual(201, status)
        status, _, _ = self.raw_request(
            "PATCH",
            self.endpoint(f"/uploads/{pending['upload_id']}"),
            b"new!",
            {"Content-Type": "application/octet-stream", "Upload-Offset": "0"},
        )
        self.assertEqual(200, status)
        (self.root / "project" / "race.bin").write_bytes(b"keep")
        status, conflict = self.request(
            "POST", self.endpoint(f"/uploads/{pending['upload_id']}/commit"), {}
        )
        self.assertEqual(409, status)
        self.assertEqual("path_exists", conflict["error"]["code"])
        self.assertEqual(b"keep", (self.root / "project" / "race.bin").read_bytes())

        outside = Path(self.temp.name) / "outside-sensitive.bin"
        outside.write_bytes(b"untouched")
        status, attacked = self.request(
            "POST",
            self.endpoint("/uploads"),
            {"path": "project/attacked.bin", "size": 4},
        )
        self.assertEqual(201, status)
        attacked_id = attacked["upload_id"]
        attacked_record = self.server.uploads.get(attacked_id, "test-token")
        Path(attacked_record.temp_path).unlink()
        Path(attacked_record.temp_path).symlink_to(outside)
        status, raw, _ = self.raw_request(
            "PATCH",
            self.endpoint(f"/uploads/{attacked_id}"),
            b"evil",
            {"Content-Type": "application/octet-stream", "Upload-Offset": "0"},
        )
        self.assertEqual(409, status)
        self.assertEqual("upload_temp_changed", json.loads(raw)["error"]["code"])
        self.assertEqual(b"untouched", outside.read_bytes())

    def test_skill_batch_upload_filters_resumes_and_overwrites_explicitly(self) -> None:
        scripts = Path(__file__).resolve().parents[1] / "skills" / "openkapsel-rest" / "scripts"
        sys.path.insert(0, str(scripts))
        try:
            import openkapsel_upload
            import openkapsel_upload_tree
        finally:
            sys.path.remove(str(scripts))

        local = Path(self.temp.name) / "bundle"
        (local / "nested").mkdir(parents=True)
        (local / "empty").mkdir()
        (local / "cache").mkdir()
        (local / "small.txt").write_text("small-v1", encoding="utf-8")
        large = b"large-block\x00" * 700_000
        (local / "large.bin").write_bytes(large)
        (local / "nested" / "keep.txt").write_text("keep", encoding="utf-8")
        (local / "ignored.tmp").write_text("ignore", encoding="utf-8")
        (local / "cache" / "ignored.txt").write_text("ignore", encoding="utf-8")

        record = self.server.tokens.create(
            name="Batch upload test",
            expires_at=None,
            path_prefix="batch-upload",
            can_read=True,
            can_write=True,
            shell_mode="none",
        )
        base = f"http://127.0.0.1:{self.port}/kapsel/w/{record.token}"
        state_file = Path(self.temp.name) / "batch-state.json"
        common = [
            str(local),
            "--destination", "imports",
            "--base-url", base,
            "--control-token", record.control_token,
            "--plan-id", str(self._ensure_test_plan(record.token)),
            "--taskname", "batch-upload",
            "--message", "Upload filtered test tree",
            "--exclude", "*.tmp",
            "--exclude", "cache",
            "--force-resumable",
            "--state-file", str(state_file),
            "--retries", "0",
            "--retry-delay", "0",
        ]
        real_api_request = openkapsel_upload.api_request
        patch_calls = 0

        def interrupt_second_chunk(*args, **kwargs):
            nonlocal patch_calls
            if args[0] == "PATCH" and "uploads/" in args[1]:
                patch_calls += 1
                if patch_calls == 2:
                    raise KeyboardInterrupt
            return real_api_request(*args, **kwargs)

        with (
            patch.object(openkapsel_upload, "api_request", side_effect=interrupt_second_chunk),
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(130, openkapsel_upload_tree.main(common))
        self.assertTrue(state_file.exists())
        serialized_state = state_file.read_text(encoding="utf-8")
        self.assertNotIn(record.token, serialized_state)
        self.assertNotIn(record.control_token, serialized_state)
        self.assertNotIn(base, serialized_state)
        interrupted = json.loads(serialized_state)
        large_state = interrupted["files"]["imports/bundle/large.bin"]
        self.assertTrue(large_state["upload_id"].startswith("upload_"))
        self.assertGreater(large_state["offset"], 0)
        self.assertLess(large_state["offset"], len(large))

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(0, openkapsel_upload_tree.main(common))
        summary = json.loads(stdout.getvalue())
        self.assertTrue(summary["complete"])
        self.assertGreaterEqual(summary["resumed"], 1)
        self.assertEqual(2, summary["filtered"])
        self.assertFalse(state_file.exists())
        remote = self.root / "batch-upload" / "imports" / "bundle"
        self.assertEqual(large, (remote / "large.bin").read_bytes())
        self.assertEqual("small-v1", (remote / "small.txt").read_text(encoding="utf-8"))
        self.assertEqual("keep", (remote / "nested" / "keep.txt").read_text(encoding="utf-8"))
        self.assertTrue((remote / "empty").is_dir())
        self.assertFalse((remote / "ignored.tmp").exists())
        self.assertFalse((remote / "cache").exists())

        unchanged_stdout = io.StringIO()
        with contextlib.redirect_stdout(unchanged_stdout), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(0, openkapsel_upload_tree.main(common))
        unchanged_summary = json.loads(unchanged_stdout.getvalue())
        self.assertEqual(0, unchanged_summary["uploaded"])
        self.assertEqual(3, unchanged_summary["already_present"])

        (local / "small.txt").write_text("small-v2", encoding="utf-8")
        replace_state = Path(self.temp.name) / "replace-state.json"
        replace = [
            *common[: common.index("--force-resumable")],
            "--include", "small.txt",
            "--state-file", str(replace_state),
            "--retries", "0",
            "--retry-delay", "0",
        ]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(1, openkapsel_upload_tree.main(replace))
        self.assertEqual("small-v1", (remote / "small.txt").read_text(encoding="utf-8"))

        overwrite = [*replace, "--overwrite"]
        overwrite_state = Path(self.temp.name) / "overwrite-state.json"
        overwrite[overwrite.index(str(replace_state))] = str(overwrite_state)
        overwrite_stdout = io.StringIO()
        overwrite_stderr = io.StringIO()
        with contextlib.redirect_stdout(overwrite_stdout), contextlib.redirect_stderr(overwrite_stderr):
            overwrite_status = openkapsel_upload_tree.main(overwrite)
        self.assertEqual(
            0,
            overwrite_status,
            overwrite_stderr.getvalue() + overwrite_stdout.getvalue(),
        )
        self.assertEqual("small-v2", (remote / "small.txt").read_text(encoding="utf-8"))
        recycle_entries, _total = self.server.recycle_for(
            self.root / "batch-upload"
        ).list_items(0, 100)
        self.assertIn(
            "imports/bundle/small.txt",
            [entry["original_path"] for entry in recycle_entries],
        )

    def test_skill_upload_retries_transient_status_with_configured_delay(self) -> None:
        scripts = Path(__file__).resolve().parents[1] / "skills" / "openkapsel-rest" / "scripts"
        sys.path.insert(0, str(scripts))
        try:
            import openkapsel_upload
            from openkapsel_http import HttpResult
        finally:
            sys.path.remove(str(scripts))
        sleeps: list[float] = []
        client = openkapsel_upload.UploadClient(
            base_url="https://workspace.invalid/w/read-token",
            control_token="control-token",
            plan_id=1,
            taskname="retry",
            message="Retry a transient request",
            retries=2,
            retry_delay=0.25,
            sleep=sleeps.append,
        )
        responses = [
            HttpResult(503, {}, b"{}"),
            HttpResult(429, {"Retry-After": "0.5"}, b"{}"),
            HttpResult(200, {}, b"{}"),
        ]
        with patch.object(openkapsel_upload, "api_request", side_effect=responses):
            result = client.request("GET", "discovery/files")
        self.assertEqual(200, result.status)
        self.assertEqual([0.25, 0.5], sleeps)

    def test_large_text_byte_cursor_preserves_utf8_boundaries(self) -> None:
        path = self.root / "project" / "unicode.txt"
        content = "áé🙂çø\n" * 100
        path.write_text(content, encoding="utf-8")
        collected = []
        offset = 0
        while True:
            query = urlencode({"path": "project/unicode.txt", "byte_offset": offset, "limit": 7})
            status, payload = self.request("GET", self.endpoint(f"/fs/read?{query}"))
            self.assertEqual(200, status)
            collected.append(payload["content"])
            if not payload["truncated"]:
                break
            self.assertGreater(payload["next_byte_offset"], offset)
            offset = payload["next_byte_offset"]
        self.assertEqual(content, "".join(collected))

        query = urlencode({"path": "project/unicode.txt", "byte_offset": 1, "limit": 10})
        status, payload = self.request("GET", self.endpoint(f"/fs/read?{query}"))
        self.assertEqual(400, status)
        self.assertEqual("invalid_utf8_boundary", payload["error"]["code"])

    def test_file_manifest_and_batch_recycle_delete(self) -> None:
        record = self.server.tokens.create(
            name="Batch file APIs",
            expires_at=None,
            path_prefix="batch-files",
            can_read=True,
            can_write=True,
            shell_mode="none",
        )
        scope = self.root / "batch-files"
        same_content = b"same content\n"
        (scope / "same.txt").write_bytes(same_content)
        (scope / "conflict.txt").write_text("remote", encoding="utf-8")
        (scope / "exists.txt").write_text("exists", encoding="utf-8")
        (scope / "folder").mkdir()
        endpoint = lambda suffix: f"/kapsel/w/{record.token}{suffix}"

        manifest_body = {
            "items": [
                {
                    "path": "same.txt",
                    "size": len(same_content),
                    "sha256": hashlib.sha256(same_content).hexdigest(),
                },
                {"path": "conflict.txt", "size": 1},
                {"path": "missing.txt", "size": 0},
                {"path": "exists.txt"},
                {"path": "folder", "size": 0},
            ],
            "include_sha256": True,
        }
        status, raw, _headers = self.raw_request(
            "POST",
            endpoint("/fs/manifest"),
            json.dumps(manifest_body).encode("utf-8"),
            {"Content-Type": "application/json"},
            authorize=False,
        )
        self.assertEqual(200, status)
        manifest = json.loads(raw)
        self.assertEqual(
            ["same", "conflict", "missing", "exists", "conflict"],
            [item["status"] for item in manifest["items"]],
        )
        self.assertEqual(1, manifest["counts"]["same"])
        self.assertEqual(
            hashlib.sha256(same_content).hexdigest(),
            manifest["items"][0]["sha256"],
        )

        (scope / "delete-a.txt").write_text("a", encoding="utf-8")
        (scope / "delete-b").mkdir()
        (scope / "delete-b" / "nested.txt").write_text("b", encoding="utf-8")
        status, rejected_raw, _headers = self.raw_request(
            "POST",
            endpoint("/fs/delete/batch"),
            json.dumps({"paths": ["delete-a.txt"]}).encode("utf-8"),
            {"Content-Type": "application/json"},
            authorize=False,
        )
        self.assertEqual(401, status)
        self.assertEqual("control_token_required", json.loads(rejected_raw)["error"]["code"])

        status, rejected = self.request(
            "POST",
            endpoint("/fs/delete/batch"),
            {"paths": ["delete-a.txt", "missing.txt"]},
        )
        self.assertEqual(409, status)
        self.assertEqual("batch_precondition_failed", rejected["error"]["code"])
        self.assertTrue((scope / "delete-a.txt").exists())

        status, rejected = self.request(
            "POST",
            endpoint("/fs/delete/batch"),
            {"paths": ["delete-b", "delete-b/nested.txt"]},
        )
        self.assertEqual(400, status)
        self.assertEqual("overlapping_paths", rejected["error"]["code"])
        self.assertTrue((scope / "delete-b" / "nested.txt").exists())

        status, deleted = self.request(
            "POST",
            endpoint("/fs/delete/batch"),
            {"paths": ["delete-a.txt", "delete-b"]},
        )
        self.assertEqual(200, status)
        self.assertTrue(deleted["complete"])
        self.assertEqual(2, deleted["deleted"])
        self.assertEqual(0, deleted["failed"])
        self.assertFalse((scope / "delete-a.txt").exists())
        self.assertFalse((scope / "delete-b").exists())
        entries, _total = self.server.recycle_for(scope).list_items(0, 100)
        self.assertTrue(
            {"delete-a.txt", "delete-b"}.issubset(
                {entry["original_path"] for entry in entries}
            )
        )

    def test_selective_metadata_search_and_directory_tree(self) -> None:
        project = self.root / "project"
        nested = project / "src" / "deep"
        nested.mkdir(parents=True)
        (project / "root.txt").write_text("Needle at root\n", encoding="utf-8")
        (project / "src" / "one.py").write_text("print('needle one')\n", encoding="utf-8")
        (nested / "two.py").write_text("NEEDLE two\n", encoding="utf-8")
        (nested / "binary.bin").write_bytes(b"needle\x00binary")

        query = urlencode({"path": "project/root.txt", "fields": "size,modified_at,sha256"})
        status, metadata = self.request("GET", self.endpoint(f"/fs/stat?{query}"))
        self.assertEqual(200, status)
        self.assertEqual({"size", "modified_at", "sha256"}, set(metadata["fields"]))
        self.assertEqual(hashlib.sha256(b"Needle at root\n").hexdigest(), metadata["sha256"])
        self.assertNotIn("type", metadata)
        self.assertNotIn("created_at", metadata)

        query = urlencode(
            {
                "path": "project",
                "query": "needle",
                "depth": 1,
                "case_sensitive": "false",
            }
        )
        status, searched = self.request("GET", self.endpoint(f"/fs/search?{query}"))
        self.assertEqual(200, status)
        self.assertEqual(2, searched["match_count"])
        self.assertFalse(any(item["path"].endswith("two.py") for item in searched["matches"]))

        query = urlencode(
            {
                "path": "project",
                "query": "needle\\s+two",
                "depth": 2,
                "regex": "true",
                "case_sensitive": "false",
            }
        )
        status, searched = self.request("GET", self.endpoint(f"/fs/search?{query}"))
        self.assertEqual(200, status)
        self.assertEqual(1, searched["match_count"])
        self.assertGreaterEqual(searched["skipped_binary"], 1)

        query = urlencode({"path": "project", "depth": 2})
        status, tree = self.request("GET", self.endpoint(f"/fs/tree?{query}"))
        self.assertEqual(200, status)
        src = next(item for item in tree["tree"]["children"] if item["name"] == "src")
        self.assertIn("children", src)
        deep = next(item for item in src["children"] if item["name"] == "deep")
        self.assertNotIn("children", deep)

    def test_task_listing_interrupt_and_streaming_input_output(self) -> None:
        status, started = self.request(
            "POST",
            self.endpoint("/shell/exec"),
            {
                "command": (
                    "python3 -u -c 'import sys; print(\"ready\", flush=True); "
                    "line=sys.stdin.readline(); print(\"got:\"+line.strip(), flush=True)'"
                ),
                "interactive": True,
                "timeout_seconds": 10,
            },
        )
        self.assertEqual(202, status)
        task_id = started["task_id"]
        query = urlencode({"stdout_offset": 0, "stderr_offset": 0, "wait_seconds": 3})
        status, output = self.request("GET", self.endpoint(f"/tasks/{task_id}/output?{query}"))
        self.assertEqual(200, status)
        self.assertIn("ready", output["stdout"]["data"], output)
        next_stdout = output["stdout"]["next_offset"]

        deadline = time.monotonic() + 3
        while True:
            status, input_result = self.request(
                "POST",
                self.endpoint(f"/tasks/{task_id}/stdin"),
                {"data": "hello stream\n", "close": True},
            )
            if status == 200:
                break
            self.assertEqual("stdin_closed", input_result["error"]["code"])
            if time.monotonic() >= deadline:
                self.fail("interactive stdin did not become ready")
            time.sleep(0.02)
        query = urlencode(
            {"stdout_offset": next_stdout, "stderr_offset": 0, "wait_seconds": 3}
        )
        status, output = self.request("GET", self.endpoint(f"/tasks/{task_id}/output?{query}"))
        self.assertEqual(200, status)
        self.assertIn("got:hello stream", output["stdout"]["data"])
        finished = self.wait_for_task(task_id)
        self.assertEqual(0, finished["exit_code"])
        self.assertTrue(finished["interactive"])

        status, listed = self.request("GET", self.endpoint("/tasks?limit=10"))
        self.assertEqual(200, status)
        listed_task = next(item for item in listed["tasks"] if item["task_id"] == task_id)
        self.assertNotIn("stdout", listed_task)
        self.assertNotIn("stderr", listed_task)

        status, sleeping = self.request(
            "POST",
            self.endpoint("/shell/exec"),
            {"command": "sleep 30", "timeout_seconds": 60},
        )
        self.assertEqual(202, status)
        sleeping_id = sleeping["task_id"]
        status, interrupted = self.request(
            "POST", self.endpoint(f"/tasks/{sleeping_id}/interrupt"), {}
        )
        self.assertEqual(200, status)
        self.assertTrue(interrupted["interrupted"])
        stopped = self.wait_for_task(sleeping_id)
        self.assertTrue(stopped["interrupted"])
        self.assertFalse(stopped["force_killed"])
        self.assertNotEqual(0, stopped["exit_code"])

        status, killable = self.request(
            "POST",
            self.endpoint("/shell/exec"),
            {"command": "sleep 30", "timeout_seconds": 60},
        )
        self.assertEqual(202, status)
        status, killed = self.request(
            "POST", self.endpoint(f"/tasks/{killable['task_id']}/kill"), {}
        )
        self.assertEqual(200, status)
        self.assertTrue(killed["interrupted"])
        self.assertTrue(killed["force_killed"])
        forced = self.wait_for_task(killable["task_id"])
        self.assertTrue(forced["force_killed"])
        self.assertNotEqual(0, forced["exit_code"])

        status, sse_task = self.request(
            "POST", self.endpoint("/shell/exec"), {"command": "printf sse-ok"}
        )
        status, body, headers = self.raw_request(
            "GET", self.endpoint(f"/tasks/{sse_task['task_id']}/stream")
        )
        self.assertEqual(200, status)
        self.assertTrue(headers["Content-Type"].startswith("text/event-stream"))
        stream = body.decode("utf-8")
        self.assertIn("event: output", stream)
        self.assertIn("sse-ok", stream)
        self.assertIn("event: done", stream)

    def test_sse_limits_duplicate_token_streams_and_requests_reconnect(self) -> None:
        status, task = self.request(
            "POST",
            self.endpoint("/shell/exec"),
            {"command": "sleep 30", "timeout_seconds": 60},
        )
        self.assertEqual(202, status)
        task_id = task["task_id"]
        record = self.server.tokens.get("test-token")
        first = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        first.request(
            "GET",
            self.endpoint(f"/tasks/{task_id}/stream"),
            headers={"Authorization": f"Bearer {record.control_token}"},
        )
        first_response = first.getresponse()
        self.assertEqual(200, first_response.status)

        status, raw, headers = self.raw_request(
            "GET",
            self.endpoint(f"/tasks/{task_id}/stream"),
        )
        self.assertEqual(429, status)
        self.assertEqual("1", headers["Retry-After"])
        error = json.loads(raw)["error"]
        self.assertEqual("too_many_streams", error["code"])
        self.assertEqual("token", error["details"]["scope"])

        stream = first_response.read().decode("utf-8")
        first.close()
        self.assertIn("event: reconnect", stream)
        self.assertIn('"reason":"stream_duration_limit"', stream)
        self.assertIn('"stdout_offset":0', stream)

        status, _killed = self.request(
            "POST",
            self.endpoint(f"/tasks/{task_id}/kill"),
            {},
        )
        self.assertEqual(200, status)

    def test_http_connection_limit_rejects_before_starting_another_thread(self) -> None:
        isolated_root = Path(self.temp.name) / "http-limit-workspace"
        isolated_root.mkdir()
        server = create_server(
            "127.0.0.1",
            0,
            ServerConfig(
                root=isolated_root,
                max_http_connections=1,
                http_socket_timeout_seconds=0.2,
            ),
        )
        first_server, first_client = socket.socketpair()
        second_server, second_client = socket.socketpair()
        try:
            server.process_request(first_server, ("local", 1))
            server.process_request(second_server, ("local", 2))
            second_client.settimeout(1)
            response = second_client.recv(4096)
            self.assertTrue(
                response.startswith(b"HTTP/1.1 503 Service Unavailable"),
                response,
            )
            self.assertIn(b"Retry-After: 1\r\n", response)
        finally:
            first_client.close()
            second_client.close()
            server.server_close()

    def test_task_registry_close_terminates_processes_and_rejects_new_tasks(self) -> None:
        config = ServerConfig(
            root=self.root,
            task_history_dir=Path(self.temp.name) / "shutdown-task-history",
            max_concurrent_shell_tasks=2,
            max_concurrent_shell_tasks_per_token=2,
        )
        registry = TaskRegistry(config, TokenCgroupManager(enabled=False))
        task = registry.start(
            "sleep 30",
            self.root,
            30,
            owner_token="shutdown-token",
        )
        deadline = time.monotonic() + 2
        while task.process is None and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertIsNotNone(task.process)

        registry.close()

        self.assertEqual("finished", task.status)
        self.assertTrue(task.interrupted)
        self.assertIsNotNone(task.process)
        self.assertIsNotNone(task.process.poll())
        with self.assertRaises(ApiError) as context:
            registry.start(
                "true",
                self.root,
                5,
                owner_token="shutdown-token",
            )
        self.assertEqual("shell_registry_closing", context.exception.code)

    def test_sandbox_launcher_command_is_redacted_from_task_stderr(self) -> None:
        target = BoundedOutput(1024 * 1024)
        stream = tempfile.TemporaryFile()
        stream.write(
            b"ordinary application error\n"
            b"bwrap --ro-bind /opt/openkapsel/venv /opt/openkapsel/venv "
            b"--unshare-user --unshare-pid --cap-drop ALL /bin/sh\n"
        )
        stream.seek(0)
        TaskRegistry._copy_stream(stream, target, True)
        stderr, _ = target.snapshot()
        self.assertIn("ordinary application error", stderr)
        self.assertIn("sandbox launcher error details redacted", stderr)
        self.assertNotIn("--ro-bind", stderr)
        self.assertNotIn("/opt/openkapsel/venv", stderr)

    def test_shell_task_limits_apply_per_token_and_globally(self) -> None:
        other = self.server.tokens.create(
            name="Other shell workspace",
            expires_at=None,
            path_prefix="other-shell",
            can_read=True,
            can_write=True,
            shell_mode="full",
            allowed_commands=(),
        )
        task_ids: list[tuple[str, str]] = []
        try:
            for _ in range(2):
                status, started = self.request(
                    "POST",
                    self.endpoint("/shell/exec"),
                    {"command": "sleep 30", "timeout_seconds": 60},
                )
                self.assertEqual(202, status)
                task_ids.append(("test-token", started["task_id"]))

            status, rejected = self.request(
                "POST",
                self.endpoint("/shell/exec"),
                {"command": "sleep 30", "timeout_seconds": 60},
            )
            self.assertEqual(429, status)
            self.assertEqual("shell_task_token_limit_reached", rejected["error"]["code"])
            self.assertEqual(
                {"scope": "token", "limit": 2, "running": 2},
                rejected["error"]["details"],
            )

            status, started = self.request(
                "POST",
                f"/kapsel/w/{other.token}/shell/exec",
                {"command": "sleep 30", "timeout_seconds": 60},
            )
            self.assertEqual(202, status)
            task_ids.append((other.token, started["task_id"]))

            status, rejected = self.request(
                "POST",
                f"/kapsel/w/{other.token}/shell/exec",
                {"command": "sleep 30", "timeout_seconds": 60},
            )
            self.assertEqual(429, status)
            self.assertEqual("shell_task_global_limit_reached", rejected["error"]["code"])
            self.assertEqual(
                {"scope": "global", "limit": 3, "running": 3},
                rejected["error"]["details"],
            )

            first_token, first_task = task_ids.pop(0)
            status, _ = self.request(
                "POST",
                f"/kapsel/w/{first_token}/tasks/{first_task}/interrupt",
                {},
            )
            self.assertEqual(200, status)
            self.wait_for_task(first_task, token=first_token)

            status, started = self.request(
                "POST",
                f"/kapsel/w/{other.token}/shell/exec",
                {"command": "sleep 30", "timeout_seconds": 60},
            )
            self.assertEqual(202, status)
            task_ids.append((other.token, started["task_id"]))
        finally:
            for token, task_id in task_ids:
                self.request(
                    "POST",
                    f"/kapsel/w/{token}/tasks/{task_id}/interrupt",
                    {},
                )
            for token, task_id in task_ids:
                self.wait_for_task(task_id, token=token)

    def test_restricted_token_exposes_sandbox_process_discovery_and_mcp(self) -> None:
        record = self.server.tokens.update("test-token", shell_mode="restricted")
        status, payload = self.request(
            "GET", f"/kapsel/w/{record.token}/sandbox/processes?offset=0&limit=10"
        )
        self.assertEqual(200, status)
        self.assertFalse(payload["available"])
        self.assertEqual(64, payload["limits"]["max_processes"])
        self.assertEqual(16, payload["limits"]["process_overhead"])
        self.assertEqual(80, payload["limits"]["effective_max_processes"])
        self.assertEqual(256 * 1024 * 1024, payload["limits"]["memory_bytes"])
        self.assertEqual(100, payload["limits"]["cpu_percent"])

        status, tools, _ = self.mcp_request(
            record.token,
            41,
            "tools/list",
            {},
        )
        self.assertEqual(200, status)
        names = {item["name"] for item in tools["result"]["tools"]}
        self.assertIn("list_sandbox_processes", names)
        status, listed, _ = self.mcp_request(
            record.token,
            42,
            "tools/call",
            {"name": "list_sandbox_processes", "arguments": {"limit": 10}},
        )
        self.assertEqual(200, status)
        self.assertFalse(listed["result"]["structuredContent"]["available"])

    def test_streamable_http_mcp_full_workspace_loop(self) -> None:
        record = self.server.tokens.create(
            name="MCP workspace",
            expires_at=None,
            path_prefix="mcp-project",
            can_read=True,
            can_write=True,
            shell_mode="full",
            allowed_commands=(),
        )
        token = record.token
        scope = self.root / "mcp-project"
        (scope / "hello.txt").write_text("hello MCP", encoding="utf-8")

        status, initialized, headers = self.mcp_request(
            token,
            1,
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "OpenKapsel tests", "version": "1"},
            },
            {"Origin": "https://ws.example.test"},
        )
        self.assertEqual(200, status)
        self.assertTrue(headers["Content-Type"].startswith("application/json"))
        self.assertEqual("2025-11-25", initialized["result"]["protocolVersion"])
        self.assertEqual({"listChanged": False}, initialized["result"]["capabilities"]["tools"])
        self.assertEqual("1", initialized["result"]["serverInfo"]["version"])

        notification = json.dumps(
            {"jsonrpc": "2.0", "method": "notifications/initialized"}
        ).encode("utf-8")
        status, body, _ = self.raw_request(
            "POST",
            f"/kapsel/w/{token}/mcp",
            notification,
            {
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "MCP-Protocol-Version": "2025-11-25",
            },
        )
        self.assertEqual(202, status)
        self.assertEqual(b"", body)

        status, listed, _ = self.mcp_request(token, 2, "tools/list", {})
        self.assertEqual(200, status)
        binary_tool = next(
            tool for tool in listed["result"]["tools"] if tool["name"] == "read_binary_chunk"
        )
        length_schema = binary_tool["inputSchema"]["properties"]["length"]
        self.assertEqual(self.server.config.mcp_binary_chunk_bytes, length_schema["maximum"])
        self.assertEqual(self.server.config.mcp_binary_chunk_bytes, length_schema["default"])
        _, oversized_binary_read, _ = self.mcp_request(
            token,
            201,
            "tools/call",
            {
                "name": "read_binary_chunk",
                "arguments": {
                    "path": "hello.txt",
                    "length": self.server.config.mcp_binary_chunk_bytes + 1,
                },
            },
        )
        self.assertEqual(-32602, oversized_binary_read["error"]["code"])
        names = {tool["name"] for tool in listed["result"]["tools"]}
        self.assertTrue(
            {
                "workspace_info",
                "list_files",
                "read_file",
                "stat_file",
                "read_binary_chunk",
                "search_files",
                "list_tree",
                "write_file",
                "replace_text",
                "create_directory",
                "move_path",
                "delete_path",
                "list_recycle",
                "restore_recycle",
                "start_upload",
                "upload_chunk",
                "get_upload",
                "finish_upload",
                "abort_upload",
                "run_shell",
                "get_task",
                "list_tasks",
                "read_task_output",
                "send_task_input",
                "interrupt_task",
                "kill_task",
            }.issubset(names)
        )
        delete_tool = next(tool for tool in listed["result"]["tools"] if tool["name"] == "delete_path")
        self.assertTrue(delete_tool["annotations"]["destructiveHint"])

        status, workspace_info, _ = self.mcp_request(
            token,
            200,
            "tools/call",
            {"name": "workspace_info", "arguments": {}},
        )
        self.assertEqual(200, status)
        self.assertFalse(workspace_info["result"]["isError"])
        workspace_payload = workspace_info["result"]["structuredContent"]
        self.assertNotIn(token, json.dumps(workspace_info["result"], ensure_ascii=False))
        self.assertEqual("main", workspace_payload["section"])
        self.assertIn("files", workspace_payload["sections"])
        self.assertNotIn("fs_write", workspace_payload["endpoints"])
        self.assertEqual(
            "directory",
            workspace_payload["limits"]["workspace_storage"]["backend"],
        )
        self.assertFalse(
            workspace_payload["limits"]["workspace_storage"]["hard_quota_enforced"]
        )
        self.assertEqual("./mcp", workspace_payload["endpoints"]["mcp"]["url"])

        _, invalid_section, _ = self.mcp_request(
            token,
            203,
            "tools/call",
            {"name": "workspace_info", "arguments": {"section": "unknown"}},
        )
        self.assertEqual(-32602, invalid_section["error"]["code"])

        status, workspace_info, _ = self.mcp_request(
            token,
            202,
            "tools/call",
            {"name": "workspace_info", "arguments": {"section": "full"}},
        )
        self.assertEqual(200, status)
        self.assertFalse(workspace_info["result"]["isError"])
        workspace_payload = workspace_info["result"]["structuredContent"]
        self.assertEqual("full", workspace_payload["section"])
        self.assertNotIn(token, json.dumps(workspace_info["result"], ensure_ascii=False))
        self.assertEqual(
            "https://preview.ws.example.test/"
            "<PREVIEW_TOKEN>/<workspace-relative-path>",
            workspace_payload["endpoints"]["web_preview"]["url"],
        )
        self.assertEqual(
            "https://preview.ws.example.test/"
            "<PREVIEW_TOKEN>/<app-path>/api/<route>",
            workspace_payload["endpoints"]["web_app_api"]["url"],
        )
        for name, endpoint in workspace_payload["endpoints"].items():
            if name in {"web_preview", "web_app_api"}:
                continue
            self.assertTrue(endpoint["url"].startswith("./"))

        status, called, _ = self.mcp_request(
            token,
            3,
            "tools/call",
            {"name": "list_files", "arguments": {"path": "."}},
        )
        self.assertEqual(200, status)
        self.assertFalse(called["result"]["isError"])
        self.assertEqual("hello.txt", called["result"]["structuredContent"]["entries"][0]["name"])

        status, written, _ = self.mcp_request(
            token,
            4,
            "tools/call",
            {
                "name": "write_file",
                "arguments": {"path": "generated/data.txt", "content": "created by MCP", "create_parents": True},
            },
        )
        self.assertEqual(200, status)
        self.assertFalse(written["result"]["isError"])
        self.assertEqual("created by MCP", (scope / "generated" / "data.txt").read_text())

        status, deleted, _ = self.mcp_request(
            token,
            5,
            "tools/call",
            {"name": "delete_path", "arguments": {"path": "generated"}},
        )
        self.assertEqual(200, status)
        recycle_id = deleted["result"]["structuredContent"]["recycle_id"]
        self.assertFalse((scope / "generated").exists())

        status, recycle_listing, _ = self.mcp_request(
            token,
            6,
            "tools/call",
            {"name": "list_recycle", "arguments": {}},
        )
        self.assertEqual(200, status)
        self.assertEqual(recycle_id, recycle_listing["result"]["structuredContent"]["entries"][0]["recycle_id"])

        status, restored, _ = self.mcp_request(
            token,
            7,
            "tools/call",
            {"name": "restore_recycle", "arguments": {"recycle_id": recycle_id}},
        )
        self.assertEqual(200, status)
        self.assertTrue(restored["result"]["structuredContent"]["restored"])
        self.assertTrue((scope / "generated" / "data.txt").is_file())

        binary = b"\x00MCP-binary\xff" * 100
        binary_digest = hashlib.sha256(binary).hexdigest()
        status, started, _ = self.mcp_request(
            token,
            70,
            "tools/call",
            {
                "name": "start_upload",
                "arguments": {
                    "path": "generated/data.bin",
                    "size": len(binary),
                    "sha256": binary_digest,
                },
            },
        )
        self.assertEqual(200, status)
        started_upload = started["result"]["structuredContent"]
        self.assertEqual(
            self.server.config.mcp_binary_chunk_bytes,
            started_upload["recommended_chunk_size"],
        )
        binary_upload_id = started_upload["upload_id"]
        split = 333
        for request_id, offset, chunk in (
            (71, 0, binary[:split]),
            (72, split, binary[split:]),
        ):
            status, uploaded, _ = self.mcp_request(
                token,
                request_id,
                "tools/call",
                {
                    "name": "upload_chunk",
                    "arguments": {
                        "upload_id": binary_upload_id,
                        "offset": offset,
                        "data_base64": base64.b64encode(chunk).decode("ascii"),
                    },
                },
            )
            self.assertEqual(200, status)
            self.assertFalse(uploaded["result"]["isError"])
            self.assertEqual(
                self.server.config.mcp_binary_chunk_bytes,
                uploaded["result"]["structuredContent"]["recommended_chunk_size"],
            )
        _, upload_status, _ = self.mcp_request(
            token,
            73,
            "tools/call",
            {"name": "get_upload", "arguments": {"upload_id": binary_upload_id}},
        )
        upload_status_content = upload_status["result"]["structuredContent"]
        self.assertTrue(upload_status_content["complete"])
        self.assertEqual(
            self.server.config.mcp_binary_chunk_bytes,
            upload_status_content["recommended_chunk_size"],
        )
        _, finished, _ = self.mcp_request(
            token,
            74,
            "tools/call",
            {"name": "finish_upload", "arguments": {"upload_id": binary_upload_id}},
        )
        self.assertEqual(binary_digest, finished["result"]["structuredContent"]["sha256"])

        _, binary_stat, _ = self.mcp_request(
            token,
            75,
            "tools/call",
            {"name": "stat_file", "arguments": {"path": "generated/data.bin"}},
        )
        self.assertEqual(len(binary), binary_stat["result"]["structuredContent"]["size"])
        _, binary_read, _ = self.mcp_request(
            token,
            76,
            "tools/call",
            {
                "name": "read_binary_chunk",
                "arguments": {"path": "generated/data.bin", "offset": 0, "length": len(binary)},
            },
        )
        binary_payload = binary_read["result"]["structuredContent"]
        self.assertTrue(binary_payload["eof"])
        self.assertEqual(binary, base64.b64decode(binary_payload["data_base64"]))

        status, shell, _ = self.mcp_request(
            token,
            8,
            "tools/call",
            {"name": "run_shell", "arguments": {"command": "printf mcp-ok"}},
        )
        self.assertEqual(200, status)
        task_id = shell["result"]["structuredContent"]["task_id"]
        task_payload = None
        for request_id in range(9, 100):
            _, polled, _ = self.mcp_request(
                token,
                request_id,
                "tools/call",
                {"name": "get_task", "arguments": {"task_id": task_id}},
            )
            task_payload = polled["result"]["structuredContent"]
            if task_payload["status"] == "finished":
                break
            time.sleep(0.02)
        self.assertEqual("finished", task_payload["status"])
        self.assertEqual("mcp-ok", task_payload["stdout"])

        _, task_listing, _ = self.mcp_request(
            token,
            90,
            "tools/call",
            {"name": "list_tasks", "arguments": {"limit": 10}},
        )
        self.assertTrue(
            any(item["task_id"] == task_id for item in task_listing["result"]["structuredContent"]["tasks"])
        )
        _, incremental, _ = self.mcp_request(
            token,
            91,
            "tools/call",
            {
                "name": "read_task_output",
                "arguments": {"task_id": task_id, "stdout_offset": 0, "stderr_offset": 0},
            },
        )
        self.assertEqual("mcp-ok", incremental["result"]["structuredContent"]["stdout"]["data"])

        _, long_running, _ = self.mcp_request(
            token,
            95,
            "tools/call",
            {"name": "run_shell", "arguments": {"command": "sleep 30"}},
        )
        force_task_id = long_running["result"]["structuredContent"]["task_id"]
        _, killed, _ = self.mcp_request(
            token,
            96,
            "tools/call",
            {"name": "kill_task", "arguments": {"task_id": force_task_id}},
        )
        self.assertTrue(killed["result"]["structuredContent"]["force_killed"])
        self.assertTrue(self.wait_for_task(force_task_id, token=token)["force_killed"])

        _, metadata, _ = self.mcp_request(
            token,
            92,
            "tools/call",
            {
                "name": "stat_file",
                "arguments": {"path": "hello.txt", "fields": "size,sha256"},
            },
        )
        self.assertEqual(
            hashlib.sha256(b"hello MCP").hexdigest(),
            metadata["result"]["structuredContent"]["sha256"],
        )
        _, searched, _ = self.mcp_request(
            token,
            93,
            "tools/call",
            {"name": "search_files", "arguments": {"query": "hello", "depth": 2}},
        )
        self.assertGreaterEqual(searched["result"]["structuredContent"]["match_count"], 1)
        _, tree, _ = self.mcp_request(
            token,
            94,
            "tools/call",
            {"name": "list_tree", "arguments": {"path": ".", "depth": 2}},
        )
        self.assertEqual("directory", tree["result"]["structuredContent"]["tree"]["type"])

        status, missing, _ = self.mcp_request(
            token,
            101,
            "tools/call",
            {"name": "read_file", "arguments": {"path": "missing.txt"}},
        )
        self.assertEqual(200, status)
        self.assertTrue(missing["result"]["isError"])
        self.assertEqual("path_not_found", missing["result"]["structuredContent"]["error"]["code"])

        status, unknown, _ = self.mcp_request(
            token,
            102,
            "tools/call",
            {"name": "unknown_tool", "arguments": {}},
        )
        self.assertEqual(200, status)
        self.assertEqual(-32602, unknown["error"]["code"])

        status, body, headers = self.raw_request(
            "GET",
            f"/kapsel/w/{token}/mcp",
            headers={"Accept": "text/event-stream"},
        )
        self.assertEqual(405, status)
        self.assertEqual("POST", headers["Allow"])
        self.assertEqual(b"", body)

        status, rejected, _ = self.mcp_request(
            token,
            103,
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "bad origin", "version": "1"},
            },
            {"Origin": "https://attacker.example"},
        )
        self.assertEqual(403, status)
        self.assertEqual(-32000, rejected["error"]["code"])

        read_only = self.server.tokens.create(
            name="Read-only MCP workspace",
            expires_at=None,
            path_prefix="mcp-read-only",
            can_read=True,
            can_write=False,
            shell_mode="none",
            allowed_commands=(),
        )
        status, read_tools, _ = self.mcp_request(read_only.token, 104, "tools/list", {})
        self.assertEqual(200, status)
        read_names = {tool["name"] for tool in read_tools["result"]["tools"]}
        self.assertTrue({"workspace_info", "list_files", "read_file", "list_recycle"}.issubset(read_names))
        self.assertTrue(
            {"write_file", "delete_path", "restore_recycle", "run_shell"}.isdisjoint(read_names)
        )
        status, read_discovery = self.request(
            "GET", f"/kapsel/w/{read_only.token}/discovery/full"
        )
        self.assertEqual(200, status)
        self.assertTrue(read_discovery["endpoints"]["fs_read"]["available"])
        self.assertFalse(read_discovery["endpoints"]["fs_write"]["available"])
        self.assertFalse(read_discovery["endpoints"]["task_kill"]["available"])

    def test_mcp_conditional_writes_preview_and_raw_large_file_transfer(self) -> None:
        record = self.server.tokens.create(
            name="MCP transfer workspace",
            expires_at=None,
            path_prefix="mcp-transfer",
            can_read=True,
            can_write=True,
            can_preview=True,
            shell_mode="none",
            allowed_commands=(),
        )
        token = record.token
        scope = self.root / "mcp-transfer"
        target = scope / "conditional.txt"
        target.write_text("original", encoding="utf-8")
        site = scope / "site"
        site.mkdir()
        (site / "index.html").write_text("<h1>preview</h1>", encoding="utf-8")

        _, listed, _ = self.mcp_request(token, 300, "tools/list", {})
        tools = {tool["name"]: tool for tool in listed["result"]["tools"]}
        self.assertIn("prepare_download", tools)
        self.assertIn("get_web_preview_url", tools)
        self.assertIn("expected_etag", tools["write_file"]["inputSchema"]["properties"])
        self.assertNotIn("expected_etag", tools["start_upload"]["inputSchema"]["properties"])
        self.assertNotIn("overwrite", tools["start_upload"]["inputSchema"]["properties"])

        _, metadata, _ = self.mcp_request(
            token,
            301,
            "tools/call",
            {
                "name": "stat_file",
                "arguments": {"path": "conditional.txt", "fields": "etag,size"},
            },
        )
        etag = metadata["result"]["structuredContent"]["etag"]
        _, rejected, _ = self.mcp_request(
            token,
            302,
            "tools/call",
            {
                "name": "write_file",
                "arguments": {
                    "path": "conditional.txt",
                    "content": "must not replace",
                    "expected_etag": '"stale"',
                },
            },
        )
        self.assertTrue(rejected["result"]["isError"])
        self.assertEqual(
            "etag_mismatch",
            rejected["result"]["structuredContent"]["error"]["code"],
        )
        self.assertEqual("original", target.read_text(encoding="utf-8"))

    def test_workspace_context_messages_queries_and_mcp(self) -> None:
        record = self.server.tokens.create(
            name="Context workspace",
            expires_at=None,
            path_prefix="context-workspace",
            can_read=True,
            can_write=True,
            can_preview=True,
            shell_mode="none",
            allowed_commands=(),
        )
        endpoint = lambda suffix: f"/kapsel/w/{record.token}{suffix}"
        scope = self.root / "context-workspace"

        status, root_plan = self.request(
            "POST",
            endpoint("/context"),
            {
                "type": "plan",
                "taskname": "context-integration",
                "content": "Complete the context integration test.",
            },
        )
        self.assertEqual(201, status)
        self.assertIsNone(root_plan["plan_id"])
        self.assertEqual(0, root_plan["unfinished_root_plans_total"])
        self.assertFalse(root_plan["unfinished_root_plans_truncated"])
        self.assertEqual([], root_plan["unfinished_root_plans"])
        status, sub_plan = self.request(
            "POST",
            endpoint("/context"),
            {
                "type": "plan",
                "taskname": "context-integration",
                "plan_id": root_plan["id"],
                "content": "Exercise recorded file operations.",
            },
        )
        self.assertEqual(201, status)
        self.assertEqual(root_plan["id"], sub_plan["plan_id"])
        self.assertEqual(1, sub_plan["unfinished_root_plans_total"])
        self.assertEqual(
            [root_plan["id"]],
            [item["id"] for item in sub_plan["unfinished_root_plans"]],
        )
        self._test_plan_ids[record.token] = sub_plan["id"]

        status, raw, _ = self.raw_request(
            "GET",
            endpoint("/context?limit=1"),
            authorize=False,
        )
        self.assertEqual(401, status)
        self.assertEqual("control_token_required", json.loads(raw)["error"]["code"])

        missing_plan_body = json.dumps(
            {
                "path": "missing-plan.txt",
                "content": "blocked",
                "taskname": "context-integration",
                "message": "Attempt a write without a plan",
            }
        ).encode("utf-8")
        status, raw, _ = self.raw_request(
            "POST",
            endpoint("/fs/write"),
            missing_plan_body,
            {
                "Content-Type": "application/json",
                "OpenKapsel-Plan-Id": "",
            },
        )
        self.assertEqual(400, status)
        self.assertEqual(
            "context_plan_id_required",
            json.loads(raw)["error"]["code"],
        )
        self.assertFalse((scope / "missing-plan.txt").exists())

        status, invalid_plan = self.request(
            "POST",
            endpoint("/fs/write"),
            {
                "path": "invalid-plan.txt",
                "content": "blocked",
                "plan_id": 999999,
                "taskname": "context-integration",
                "message": "Attempt a write with an unknown plan",
            },
        )
        self.assertEqual(400, status)
        self.assertEqual("invalid_context_plan", invalid_plan["error"]["code"])
        self.assertFalse((scope / "invalid-plan.txt").exists())

        missing_taskname_body = json.dumps(
            {
                "path": "missing-taskname.txt",
                "content": "blocked",
                "message": "Attempt a write without a task group",
            }
        ).encode("utf-8")
        status, raw, _ = self.raw_request(
            "POST",
            endpoint("/fs/write"),
            missing_taskname_body,
            {
                "Content-Type": "application/json",
                "OpenKapsel-Taskname": "",
            },
        )
        self.assertEqual(400, status)
        self.assertEqual(
            "context_taskname_required",
            json.loads(raw)["error"]["code"],
        )
        self.assertFalse((scope / "missing-taskname.txt").exists())

        missing_body = json.dumps(
            {"path": "missing-message.txt", "content": "blocked"}
        ).encode("utf-8")
        status, raw, _ = self.raw_request(
            "POST",
            endpoint("/fs/write"),
            missing_body,
            {
                "Content-Type": "application/json",
                "OpenKapsel-Message": "",
            },
        )
        self.assertEqual(400, status)
        self.assertEqual(
            "context_message_required",
            json.loads(raw)["error"]["code"],
        )
        self.assertFalse((scope / "missing-message.txt").exists())

        status, written = self.request(
            "POST",
            endpoint("/fs/write"),
            {
                "path": "tracked.txt",
                "content": "tracked content",
                "taskname": "context-integration",
                "message": "Create the tracked context fixture",
            },
        )
        self.assertEqual(201, status)
        operation_id = written["context_id"]
        self.assertTrue(
            (scope / ".openkapsel" / "context" / "context.sqlite3").is_file()
        )

        unicode_taskname = "résumé-integration"
        unicode_message = "Upload the naïve binary fixture"
        status, raw_response, _ = self.raw_request(
            "PUT",
            endpoint("/fs/content?path=raw.bin"),
            b"raw-context-data",
            {
                "Content-Type": "application/octet-stream",
                # http.client only accepts latin-1 header strings. This is the
                # byte-preserving form produced when curl sends a UTF-8 value.
                "OpenKapsel-Taskname": unicode_taskname.encode("utf-8").decode("latin-1"),
                "OpenKapsel-Message": unicode_message.encode("utf-8").decode("latin-1"),
            },
        )
        self.assertEqual(201, status)
        self.assertIn("context_id", json.loads(raw_response))
        status, unicode_result = self.request(
            "GET",
            endpoint("/context?query=binary%20fixture&limit=200"),
        )
        self.assertEqual(1, unicode_result["total"])
        self.assertEqual(unicode_message, unicode_result["entries"][0]["content"])
        self.assertEqual(unicode_taskname, unicode_result["entries"][0]["taskname"])

        status, _ = self.request("GET", endpoint("/fs/read?path=tracked.txt"))
        self.assertEqual(200, status)
        status, initial = self.request(
            "GET",
            endpoint("/context?type=operation&limit=200"),
        )
        self.assertEqual(2, initial["total"])

        status, named_read = self.request(
            "GET",
            endpoint("/fs/read?path=tracked.txt&taskname=context-integration&message=Verify%20the%20tracked%20file"),
        )
        self.assertEqual(200, status)
        self.assertIn("context_id", named_read)

        status, failed = self.request(
            "POST",
            endpoint("/fs/delete"),
            {
                "path": "does-not-exist",
                "taskname": "context-integration",
                "message": "Remove an obsolete fixture",
            },
        )
        self.assertEqual(404, status)
        status, failed_context = self.request(
            "GET",
            endpoint(f"/context?id={failed['context_id']}"),
        )
        self.assertEqual("failed", failed_context["entries"][0]["status"])
        self.assertIn("path_not_found", failed_context["entries"][0]["result_summary"])

        status, note = self.request(
            "POST",
            endpoint("/context"),
            {
                "type": "note",
                "taskname": "context-integration",
                "plan_id": sub_plan["id"],
                "content": "The tracked file is ready.",
            },
        )
        self.assertEqual(201, status)
        self.assertEqual("note", note["type"])
        original_note_id = note["id"]

        status, replacement_note = self.request(
            "PATCH",
            endpoint(f"/context/notes/{original_note_id}"),
            {
                "taskname": "context-integration",
                "plan_id": sub_plan["id"],
                "content": "The tracked file and raw upload are ready.",
            },
        )
        self.assertEqual(201, status)
        self.assertGreater(replacement_note["id"], original_note_id)
        status, removed_note = self.request(
            "GET",
            endpoint(f"/context?id={original_note_id}"),
        )
        self.assertEqual(0, removed_note["total"])

        status, rest_plan = self.request(
            "POST",
            endpoint("/context"),
            {
                "type": "plan",
                "taskname": "rest-plan",
                "plan_id": root_plan["id"],
                "content": "Exercise the REST plan update endpoint.",
            },
        )
        self.assertEqual(201, status)
        self.assertEqual("in_progress", rest_plan["status"])
        status, rest_plan_updated = self.request(
            "PATCH",
            endpoint(f"/context/plans/{rest_plan['id']}"),
            {"taskname": "rest-plan", "status": "cancelled"},
        )
        self.assertEqual(200, status)
        self.assertEqual(rest_plan["id"], rest_plan_updated["id"])
        self.assertEqual("cancelled", rest_plan_updated["status"])
        self.assertEqual(root_plan["id"], rest_plan_updated["plan_id"])
        status, cancelled = self.request(
            "GET",
            endpoint("/context?type=plan&status=cancelled&taskname=rest-plan"),
        )
        self.assertEqual(1, cancelled["total"])
        status, direct_plan_entries = self.request(
            "GET",
            endpoint(f"/context?plan_id={sub_plan['id']}&type=operation&limit=200"),
        )
        self.assertEqual(200, status)
        self.assertGreaterEqual(direct_plan_entries["total"], 3)
        status, rest_tree = self.request(
            "GET",
            endpoint(f"/context/plans/{root_plan['id']}/tree?max_depth=8&limit=200"),
        )
        self.assertEqual(200, status)
        self.assertEqual(root_plan["id"], rest_tree["root_plan_id"])
        self.assertEqual(root_plan["id"], rest_tree["plans"][0]["id"])
        self.assertIn(
            sub_plan["id"],
            {item["id"] for item in rest_tree["plans"]},
        )
        status, roots = self.request(
            "GET",
            endpoint("/context?type=plan&root_plans=true&status=in_progress&limit=200"),
        )
        self.assertEqual(200, status)
        self.assertIn(root_plan["id"], {item["id"] for item in roots["entries"]})
        self.assertNotIn(sub_plan["id"], {item["id"] for item in roots["entries"]})

        status, exact = self.request("GET", endpoint(f"/context?id={operation_id}"))
        self.assertEqual(200, status)
        self.assertEqual(1, exact["total"])
        self.assertEqual("operation", exact["entries"][0]["type"])
        self.assertEqual("succeeded", exact["entries"][0]["status"])
        self.assertEqual("fs.write", exact["entries"][0]["operation"])
        self.assertEqual("context-integration", exact["entries"][0]["taskname"])
        self.assertEqual(sub_plan["id"], exact["entries"][0]["plan_id"])
        actor_id = record.actor_id
        self.assertEqual(actor_id, exact["entries"][0]["actor_id"])
        self.assertNotIn("content", exact["entries"][0]["request"])

        status, by_actor_and_path = self.request(
            "GET",
            endpoint(f"/context?actor_id={actor_id}&path=tracked.txt&limit=200"),
        )
        self.assertEqual(200, status)
        self.assertGreaterEqual(by_actor_and_path["total"], 2)
        self.assertTrue(
            all(item["actor_id"] == actor_id for item in by_actor_and_path["entries"])
        )

        status, searched = self.request(
            "GET", endpoint("/context?query=tracked&limit=200")
        )
        self.assertEqual(200, status)
        self.assertGreaterEqual(searched["total"], 2)
        status, too_many = self.request("GET", endpoint("/context?limit=201"))
        self.assertEqual(400, status)
        self.assertEqual("invalid_request", too_many["error"]["code"])

        status, blocked = self.request(
            "GET", endpoint("/fs/read?path=.openkapsel/context/context.sqlite3")
        )
        self.assertEqual(403, status)
        self.assertEqual("reserved_path", blocked["error"]["code"])
        status, listing = self.request("GET", endpoint("/fs/list?path=."))
        self.assertNotIn(".openkapsel", {entry["name"] for entry in listing["entries"]})
        status, preview = self.preview_request(
            "GET",
            "/.openkapsel/context/context.sqlite3",
            token=record.token,
        )
        self.assertEqual(404, status)

        status, listed, _ = self.mcp_request(record.token, 801, "tools/list", {})
        self.assertEqual(200, status)
        tools = {tool["name"]: tool for tool in listed["result"]["tools"]}
        self.assertIn("query_context", tools)
        self.assertIn("add_context", tools)
        self.assertIn("update_plan", tools)
        self.assertIn("replace_note", tools)
        self.assertIn("get_plan_tree", tools)
        self.assertIn(
            "actor_id",
            tools["query_context"]["inputSchema"]["properties"],
        )
        self.assertIn(
            "path",
            tools["query_context"]["inputSchema"]["properties"],
        )
        self.assertTrue(tools["update_plan"]["annotations"]["idempotentHint"])
        self.assertTrue(tools["replace_note"]["annotations"]["destructiveHint"])
        self.assertIn(
            "taskname",
            tools["write_file"]["inputSchema"]["required"],
        )
        self.assertIn(
            "message",
            tools["write_file"]["inputSchema"]["required"],
        )
        self.assertIn(
            "plan_id",
            tools["write_file"]["inputSchema"]["required"],
        )
        for tool_name, tool in tools.items():
            if tool["annotations"]["readOnlyHint"] or tool_name in {
                "add_context",
                "update_plan",
            }:
                continue
            self.assertIn(
                "plan_id",
                tool["inputSchema"].get("required", []),
                tool_name,
            )
        self.assertNotIn(
            "message",
            tools["read_file"]["inputSchema"].get("required", []),
        )
        self.assertIn("message", tools["read_file"]["inputSchema"]["properties"])

        status, mcp_written, _ = self.mcp_request(
            record.token,
            804,
            "tools/call",
            {
                "name": "write_file",
                "arguments": {
                    "path": "mcp-context.txt",
                    "content": "created through MCP",
                    "taskname": "context-integration",
                    "message": "Create the MCP context fixture",
                },
            },
        )
        self.assertFalse(mcp_written["result"]["isError"])
        mcp_context_id = mcp_written["result"]["structuredContent"]["context_id"]
        status, mcp_context = self.request(
            "GET",
            endpoint(f"/context?id={mcp_context_id}"),
        )
        self.assertIn("HTTP 201", mcp_context["entries"][0]["result_summary"])
        status, mcp_path_query, _ = self.mcp_request(
            record.token,
            806,
            "tools/call",
            {
                "name": "query_context",
                "arguments": {
                    "actor_id": actor_id,
                    "path": "mcp-context.txt",
                    "limit": 200,
                },
            },
        )
        self.assertFalse(mcp_path_query["result"]["isError"])
        self.assertEqual(1, mcp_path_query["result"]["structuredContent"]["total"])
        status, mcp_tree, _ = self.mcp_request(
            record.token,
            807,
            "tools/call",
            {
                "name": "get_plan_tree",
                "arguments": {"plan_id": root_plan["id"], "limit": 200},
            },
        )
        self.assertFalse(mcp_tree["result"]["isError"])
        self.assertEqual(
            [root_plan["id"], sub_plan["id"]],
            [item["id"] for item in mcp_tree["result"]["structuredContent"]["plans"][:2]],
        )

        status, planned, _ = self.mcp_request(
            record.token,
            802,
            "tools/call",
            {
                "name": "add_context",
                "arguments": {
                    "type": "plan",
                    "taskname": "release-checks",
                    "plan_id": root_plan["id"],
                    "content": "Run the final checks.",
                },
            },
        )
        self.assertFalse(planned["result"]["isError"])
        plan_id = planned["result"]["structuredContent"]["id"]
        self.assertEqual(
            "in_progress",
            planned["result"]["structuredContent"]["status"],
        )
        self.assertEqual(
            [root_plan["id"]],
            [
                item["id"]
                for item in planned["result"]["structuredContent"]
                ["unfinished_root_plans"]
            ],
        )
        status, updated_plan, _ = self.mcp_request(
            record.token,
            805,
            "tools/call",
            {
                "name": "update_plan",
                "arguments": {
                    "id": plan_id,
                    "taskname": "release-checks",
                    "status": "completed",
                    "debrief": {
                        "summary": "Final checks completed without reusable project knowledge.",
                        "outcome": "succeeded",
                        "memory_actions": [],
                    },
                },
            },
        )
        self.assertFalse(updated_plan["result"]["isError"])
        self.assertEqual(
            "completed",
            updated_plan["result"]["structuredContent"]["status"],
        )
        status, queried, _ = self.mcp_request(
            record.token,
            803,
            "tools/call",
            {
                "name": "query_context",
                "arguments": {
                    "query": "final checks",
                    "taskname": "release-checks",
                    "limit": 200,
                },
            },
        )
        self.assertFalse(queried["result"]["isError"])
        self.assertEqual(1, queried["result"]["structuredContent"]["total"])

        # Continue the raw-transfer coverage that shares MCP setup with this
        # section, using a separate workspace from the context assertions.
        record = self.server.tokens.create(
            name="MCP transfer continuation",
            expires_at=None,
            path_prefix="mcp-transfer-continuation",
            can_read=True,
            can_write=True,
            can_preview=True,
            shell_mode="none",
            allowed_commands=(),
        )
        token = record.token
        scope = self.root / "mcp-transfer-continuation"
        target = scope / "conditional.txt"
        target.write_text("original", encoding="utf-8")
        site = scope / "site"
        site.mkdir()
        (site / "index.html").write_text("<h1>preview</h1>", encoding="utf-8")
        _, metadata, _ = self.mcp_request(
            token,
            800,
            "tools/call",
            {
                "name": "stat_file",
                "arguments": {"path": "conditional.txt", "fields": "etag,size"},
            },
        )
        etag = metadata["result"]["structuredContent"]["etag"]
        _, written, _ = self.mcp_request(
            token,
            303,
            "tools/call",
            {
                "name": "write_file",
                "arguments": {
                    "path": "conditional.txt",
                    "content": "updated",
                    "expected_etag": etag,
                },
            },
        )
        self.assertFalse(written["result"]["isError"])
        updated_etag = written["result"]["structuredContent"]["etag"]
        self.assertNotEqual(etag, updated_etag)
        self.assertEqual("updated", target.read_text(encoding="utf-8"))

        _, upload_rejected, _ = self.mcp_request(
            token,
            307,
            "tools/call",
            {
                "name": "start_upload",
                "arguments": {
                    "path": "conditional.txt",
                    "size": 1,
                },
            },
        )
        self.assertTrue(upload_rejected["result"]["isError"])
        self.assertEqual(
            "path_exists",
            upload_rejected["result"]["structuredContent"]["error"]["code"],
        )

        _, preview, _ = self.mcp_request(
            token,
            304,
            "tools/call",
            {"name": "get_web_preview_url", "arguments": {"path": "site"}},
        )
        preview_payload = preview["result"]["structuredContent"]
        self.assertEqual(
            f"https://preview.ws.example.test/{record.preview_token}/site/",
            preview_payload["url"],
        )
        self.assertNotIn(record.control_token, json.dumps(preview_payload))
        status, raw, _ = self.raw_preview_request("GET", "/site/", token=token)
        self.assertEqual(200, status)
        self.assertEqual(b"<h1>preview</h1>", raw)

        _, prepared, _ = self.mcp_request(
            token,
            305,
            "tools/call",
            {"name": "prepare_download", "arguments": {"path": "conditional.txt"}},
        )
        download = prepared["result"]["structuredContent"]
        self.assertEqual(
            "https://ws.example.test/kapsel/transfer/fs/content?path=conditional.txt",
            download["transfer"]["url"],
        )
        self.assertEqual("reuse_mcp_bearer", download["transfer"]["authorization"])
        self.assertNotIn(record.token, json.dumps(download))
        self.assertNotIn(record.control_token, json.dumps(download))
        status, raw, headers = self.raw_request(
            "GET",
            "/kapsel/transfer/fs/content?path=conditional.txt",
            headers={
                "Authorization": f"Bearer {record.control_token}",
                "Range": "bytes=1-3",
            },
            authorize=False,
        )
        self.assertEqual(206, status)
        self.assertEqual(b"pda", raw)
        self.assertEqual("bytes 1-3/7", headers["Content-Range"])

        binary = os.urandom(1024 * 1024 + 123)
        digest = hashlib.sha256(binary).hexdigest()
        _, started, _ = self.mcp_request(
            token,
            306,
            "tools/call",
            {
                "name": "start_upload",
                "arguments": {
                    "path": "large.bin",
                    "size": len(binary),
                    "sha256": digest,
                },
            },
        )
        upload = started["result"]["structuredContent"]
        raw_transfer = upload["raw_transfer"]
        self.assertEqual("reuse_mcp_bearer", raw_transfer["authorization"])
        self.assertEqual(
            self.server.config.upload_chunk_bytes,
            raw_transfer["recommended_chunk_size"],
        )
        upload_path = f"/kapsel/transfer/uploads/{upload['upload_id']}"
        status, raw, _ = self.raw_request(
            "PATCH",
            upload_path,
            binary,
            {
                "Content-Type": "application/octet-stream",
                "Upload-Offset": "0",
                "Authorization": f"Bearer {record.control_token}",
            },
            authorize=False,
        )
        self.assertEqual(200, status)
        self.assertEqual(len(binary), json.loads(raw)["offset"])
        status, raw, _ = self.raw_request(
            "POST",
            upload_path + "/commit",
            headers={"Authorization": f"Bearer {record.control_token}"},
            authorize=False,
        )
        committed = json.loads(raw)
        self.assertEqual(201, status)
        self.assertEqual(digest, committed["sha256"])
        self.assertEqual(binary, (scope / "large.bin").read_bytes())

        status, unauthorized, _ = self.raw_request(
            "GET",
            "/kapsel/transfer/fs/content?path=conditional.txt",
            authorize=False,
        )
        self.assertEqual(401, status)
        self.assertEqual("control_token_required", json.loads(unauthorized)["error"]["code"])

    def test_recorded_html_read_error_finishes_context_operation(self) -> None:
        plan_id = self._ensure_test_plan("test-token")
        query = urlencode(
            {
                "path": "missing-html-read.txt",
                "plan_id": plan_id,
                "taskname": "html-read-error",
                "message": "Read a missing file from a browser-like client",
            }
        )
        status, body, headers = self.raw_request(
            "GET",
            self.endpoint(f"/fs/read?{query}"),
            headers={"Accept": "text/html"},
        )
        self.assertEqual(404, status)
        self.assertIn("text/html", headers["Content-Type"])
        self.assertIn(b"404", body)

        status, payload = self.request(
            "GET",
            self.endpoint("/context?taskname=html-read-error&limit=10"),
        )
        self.assertEqual(200, status)
        self.assertEqual(1, payload["total"])
        operation = payload["entries"][0]
        self.assertEqual("fs.read", operation["operation"])
        self.assertEqual("failed", operation["status"])
        self.assertEqual(plan_id, operation["plan_id"])

    def test_main_responses_hide_runtime_version_and_disable_referrers(self) -> None:
        status, _, headers = self.raw_request(
            "GET",
            self.endpoint("/"),
            authorize=False,
        )
        self.assertEqual(200, status)
        self.assertEqual("no-referrer", headers["Referrer-Policy"])
        self.assertEqual("OpenKapsel", headers["Server"])
        self.assertNotIn("Python", headers["Server"])
        self.assertNotIn("BaseHTTP", headers["Server"])

        status, _, headers = self.raw_request(
            "GET",
            "/kapsel/w/invalid-token/",
            authorize=False,
        )
        self.assertEqual(404, status)
        self.assertEqual("no-referrer", headers["Referrer-Policy"])

    def test_list_and_paginated_read(self) -> None:
        query = urlencode({"path": "project"})
        status, payload = self.request("GET", self.endpoint(f"/fs/list?{query}"))
        self.assertEqual(200, status)
        self.assertEqual("hello.txt", payload["entries"][0]["name"])
        self.assertEqual("file", payload["entries"][0]["type"])

        query = urlencode({"path": "project/hello.txt", "offset": 6, "limit": 5})
        status, payload = self.request("GET", self.endpoint(f"/fs/read?{query}"))
        self.assertEqual(200, status)
        self.assertEqual("world", payload["content"])
        self.assertTrue(payload["truncated"])
        self.assertEqual(11, payload["next_offset"])

    def test_write_create_and_safe_replace(self) -> None:
        status, payload = self.request(
            "POST",
            self.endpoint("/fs/write"),
            {"path": "new/answer.py", "content": "answer = 41\n", "create_parents": True},
        )
        self.assertEqual(201, status)
        self.assertTrue(payload["created"])
        self.assertEqual("answer = 41\n", (self.root / "new" / "answer.py").read_text())

        status, payload = self.request(
            "POST",
            self.endpoint("/fs/replace"),
            {"path": "new/answer.py", "old": "41", "new": "42"},
        )
        self.assertEqual(200, status)
        self.assertEqual(1, payload["replacements"])
        self.assertEqual("answer = 42\n", (self.root / "new" / "answer.py").read_text())

        (self.root / "duplicate.txt").write_text("x x", encoding="utf-8")
        status, payload = self.request(
            "POST",
            self.endpoint("/fs/replace"),
            {"path": "duplicate.txt", "old": "x", "new": "y"},
        )
        self.assertEqual(409, status)
        self.assertEqual("match_count_mismatch", payload["error"]["code"])
        self.assertEqual("x x", (self.root / "duplicate.txt").read_text())

    def test_batch_replace_supports_multiple_original_text_edits_per_file(self) -> None:
        first = self.root / "project" / "batch-first.txt"
        second = self.root / "project" / "batch-second.txt"
        overlap = self.root / "project" / "batch-overlap.txt"
        first.write_text("alpha beta alpha\n", encoding="utf-8")
        second.write_text("left right\n", encoding="utf-8")
        overlap.write_text("abcdef\n", encoding="utf-8")

        status, rejected = self.request(
            "POST",
            self.endpoint("/fs/replace/batch"),
            {
                "items": [
                    {
                        "path": "project/batch-first.txt",
                        "replacements": [
                            {"old": "alpha", "new": "changed", "expected_matches": 2}
                        ],
                    },
                    {
                        "path": "project/batch-second.txt",
                        "replacements": [{"old": "missing", "new": "value"}],
                    },
                ]
            },
        )
        self.assertEqual(409, status)
        self.assertEqual("match_count_mismatch", rejected["error"]["code"])
        self.assertEqual("alpha beta alpha\n", first.read_text(encoding="utf-8"))
        self.assertEqual("left right\n", second.read_text(encoding="utf-8"))

        status, rejected = self.request(
            "POST",
            self.endpoint("/fs/replace/batch"),
            {
                "items": [
                    {
                        "path": "project/batch-overlap.txt",
                        "replacements": [
                            {"old": "abc", "new": "one"},
                            {"old": "bc", "new": "two"},
                        ],
                    }
                ]
            },
        )
        self.assertEqual(400, status)
        self.assertEqual("overlapping_replacements", rejected["error"]["code"])
        self.assertEqual("abcdef\n", overlap.read_text(encoding="utf-8"))

        status, updated = self.request(
            "POST",
            self.endpoint("/fs/replace/batch"),
            {
                "items": [
                    {
                        "path": "project/batch-first.txt",
                        "replacements": [
                            {"old": "alpha", "new": "beta", "expected_matches": 2},
                            {"old": "beta", "new": "gamma"},
                        ],
                    },
                    {
                        "path": "project/batch-second.txt",
                        "replacements": [
                            {"old": "left", "new": "up"},
                            {"old": "right", "new": "down"},
                        ],
                    },
                ]
            },
        )
        self.assertEqual(200, status)
        self.assertTrue(updated["complete"])
        self.assertEqual(2, updated["updated"])
        self.assertEqual(5, updated["replacements"])
        self.assertEqual("beta gamma beta\n", first.read_text(encoding="utf-8"))
        self.assertEqual("up down\n", second.read_text(encoding="utf-8"))

    def test_file_reads_and_writes_reject_parent_symlink_swap(self) -> None:
        race = self.root / "race"
        race.mkdir()
        (race / "secret.txt").write_text("inside", encoding="utf-8")
        outside = Path(self.temp.name) / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_text("outside", encoding="utf-8")
        original_resolve = WorkspaceRequestHandler._resolve_path

        def swapped_resolve(handler, value, *, write=False):
            resolved = original_resolve(handler, value, write=write)
            if (
                value in {"race/secret.txt", "race/new.txt"}
                and race.is_dir()
                and not race.is_symlink()
            ):
                race.rename(self.root / "race-original")
                race.symlink_to(outside, target_is_directory=True)
            return resolved

        try:
            with patch.object(WorkspaceRequestHandler, "_resolve_path", swapped_resolve):
                query = urlencode({"path": "race/secret.txt"})
                status, payload = self.request("GET", self.endpoint(f"/fs/read?{query}"))
                self.assertEqual(409, status)
                self.assertEqual("path_changed", payload["error"]["code"])
            race.unlink()
            (self.root / "race-original").rename(race)
            with patch.object(WorkspaceRequestHandler, "_resolve_path", swapped_resolve):
                status, payload = self.request(
                    "POST",
                    self.endpoint("/fs/write"),
                    {"path": "race/new.txt", "content": "must stay inside"},
                )
                self.assertEqual(409, status)
                self.assertEqual("path_changed", payload["error"]["code"])
            self.assertFalse((outside / "new.txt").exists())
        finally:
            if race.is_symlink():
                race.unlink()
            original = self.root / "race-original"
            if original.exists() and not race.exists():
                original.rename(race)

    def test_cross_workspace_share_rest_mcp_and_discovery(self) -> None:
        source = self.root / "project" / "handoff"
        (source / "nested").mkdir(parents=True)
        (source / "readme.txt").write_text("shared text", encoding="utf-8")
        (source / "nested" / "data.bin").write_bytes(b"\x00\x01\x02")
        destination_token = self.server.tokens.create(
            name="Destination",
            expires_at=None,
            path_prefix="destination",
            can_read=True,
            can_write=True,
            shell_mode="none",
        )

        status, created = self.request(
            "POST",
            self.endpoint("/shares"),
            {"path": "project/handoff"},
        )
        self.assertEqual(201, status)
        share_id = created["share_id"]
        self.assertRegex(share_id, r"^[A-Za-z0-9_-]{22}$")
        self.assertEqual("directory", created["type"])
        self.assertNotIn("test-token", created["query_url"])
        self.assertEqual(
            f"https://ws.example.test/kapsel/shares/{share_id}",
            created["query_url"],
        )

        status, listing = self.request(
            "GET",
            f"/kapsel/shares/{share_id}?depth=2",
        )
        self.assertEqual(200, status)
        self.assertEqual(
            ["handoff", "handoff/nested", "handoff/nested/data.bin", "handoff/readme.txt"],
            [item["path"] for item in listing["entries"]],
        )

        destination = f"/kapsel/w/{destination_token.token}/shares/{share_id}/import"
        status, imported = self.request(
            "POST",
            destination,
            {"destination": "incoming/handoff", "create_parents": True},
        )
        self.assertEqual(201, status)
        self.assertEqual(share_id, imported["share_id"])
        imported_root = self.root / "destination" / "incoming" / "handoff"
        self.assertEqual("shared text", (imported_root / "readme.txt").read_text())
        self.assertEqual(b"\x00\x01\x02", (imported_root / "nested" / "data.bin").read_bytes())

        status, duplicate = self.request(
            "POST",
            destination,
            {"destination": "incoming/handoff", "create_parents": True},
        )
        self.assertEqual(409, status)
        self.assertEqual("destination_exists", duplicate["error"]["code"])

        status, mcp_listing, _ = self.mcp_request(
            destination_token.token,
            70,
            "tools/call",
            {"name": "inspect_share", "arguments": {"share_id": share_id, "depth": 0}},
        )
        self.assertEqual(200, status)
        self.assertFalse(mcp_listing["result"]["isError"])
        self.assertEqual(share_id, mcp_listing["result"]["structuredContent"]["share_id"])

        headers = {
            "Authorization": f"Bearer {self.server.tokens.get('test-token').control_token}"
        }
        status, raw, _ = self.raw_request(
            "DELETE",
            self.endpoint(f"/shares/{share_id}"),
            headers=headers,
        )
        self.assertEqual(204, status)
        self.assertEqual(b"", raw)
        status, missing = self.request("GET", f"/kapsel/shares/{share_id}")
        self.assertEqual(404, status)
        self.assertEqual("share_not_found", missing["error"]["code"])

    def test_mkdir_move_rename_and_delete(self) -> None:
        record = self.server.tokens.create(
            name="Operations token",
            expires_at=None,
            path_prefix="operations",
            can_read=True,
            can_write=True,
            shell_mode="none",
            allowed_commands=(),
        )
        scope = self.root / "operations"
        endpoint = lambda suffix: f"/kapsel/w/{record.token}{suffix}"
        self.assertTrue((scope / ".openkapsel" / "recycle").is_dir())
        self.assertTrue((scope / ".openkapsel" / "context").is_dir())

        status, payload = self.request(
            "POST",
            endpoint("/fs/mkdir"),
            {"path": "assets/generated", "parents": True},
        )
        self.assertEqual(201, status)
        self.assertTrue(payload["created"])
        self.assertTrue((scope / "assets" / "generated").is_dir())

        source = scope / "assets" / "generated" / "draft.txt"
        source.write_text("draft", encoding="utf-8")
        status, payload = self.request(
            "POST",
            endpoint("/fs/move"),
            {"source": "assets/generated/draft.txt", "destination": "assets/final.txt"},
        )
        self.assertEqual(200, status)
        self.assertTrue(payload["moved"])
        self.assertFalse(source.exists())
        self.assertEqual("draft", (scope / "assets" / "final.txt").read_text())

        status, payload = self.request(
            "POST",
            endpoint("/fs/move"),
            {"source": "assets/final.txt", "destination": "assets/renamed.txt"},
        )
        self.assertEqual(200, status)
        self.assertTrue((scope / "assets" / "renamed.txt").is_file())

        status, payload = self.request(
            "POST",
            endpoint("/fs/delete"),
            {"path": "assets"},
        )
        self.assertEqual(200, status)
        self.assertTrue(payload["recycled"])
        recycle_id = payload["recycle_id"]
        self.assertRegex(recycle_id, r"^\d{8}T\d{6}\.\d{6}Z-[0-9a-f]{8}$")
        self.assertFalse((scope / "assets").exists())
        self.assertTrue((scope / payload["stored_path"]).is_dir())

        status, listing = self.request("GET", endpoint("/recycle/list"))
        self.assertEqual(200, status)
        self.assertEqual(1, listing["total"])
        self.assertEqual("assets", listing["entries"][0]["original_path"])

        (scope / "assets").mkdir()
        status, conflict = self.request(
            "POST", endpoint("/recycle/restore"), {"recycle_id": recycle_id}
        )
        self.assertEqual(409, status)
        self.assertEqual("restore_target_exists", conflict["error"]["code"])
        (scope / "assets").rmdir()

        status, payload = self.request(
            "POST", endpoint("/recycle/restore"), {"recycle_id": recycle_id}
        )
        self.assertEqual(200, status)
        self.assertTrue(payload["restored"])
        self.assertTrue((scope / "assets" / "renamed.txt").is_file())

        status, listing = self.request("GET", endpoint("/recycle/list"))
        self.assertEqual(200, status)
        self.assertEqual(0, listing["total"])
        status, listing = self.request("GET", endpoint("/fs/list?path="))
        self.assertEqual(200, status)
        self.assertNotIn(".openkapsel", [item["name"] for item in listing["entries"]])
        status, payload = self.request("GET", endpoint("/fs/list?path=.openkapsel"))
        self.assertEqual(403, status)
        self.assertEqual("reserved_path", payload["error"]["code"])

        # A cached recycle bin must recover if a trusted host/full Shell removes
        # its directory. A replacement file or symlink must never be followed.
        recycle_root = scope / ".openkapsel" / "recycle"
        recycle_root.rmdir()
        status, listing = self.request("GET", endpoint("/recycle/list"))
        self.assertEqual(200, status)
        self.assertEqual(0, listing["total"])
        self.assertTrue(recycle_root.is_dir())
        self.assertEqual(0o700, recycle_root.stat().st_mode & 0o777)

        recycle_root.rmdir()
        victim = scope / "recreate-recycle.txt"
        victim.write_text("recoverable", encoding="utf-8")
        status, recreated = self.request(
            "POST", endpoint("/fs/delete"), {"path": victim.name}
        )
        self.assertEqual(200, status)
        self.assertTrue(recreated["recycled"])
        self.assertTrue(recycle_root.is_dir())
        status, restored = self.request(
            "POST",
            endpoint("/recycle/restore"),
            {"recycle_id": recreated["recycle_id"]},
        )
        self.assertEqual(200, status)
        self.assertTrue(restored["restored"])

        recycle_root.rmdir()
        outside_recycle = Path(self.temp.name) / "outside-recycle"
        outside_recycle.mkdir()
        recycle_root.symlink_to(outside_recycle, target_is_directory=True)
        protected = scope / "must-not-move.txt"
        protected.write_text("keep", encoding="utf-8")
        status, rejected = self.request(
            "POST", endpoint("/fs/delete"), {"path": protected.name}
        )
        self.assertEqual(409, status)
        self.assertEqual("recycle_unavailable", rejected["error"]["code"])
        self.assertTrue(protected.is_file())
        self.assertEqual([], list(outside_recycle.iterdir()))
        recycle_root.unlink()
        recycle_root.mkdir(mode=0o700)

        other = self.server.tokens.create(
            name="Other workspace",
            expires_at=None,
            path_prefix="other-operations",
            can_read=True,
            can_write=True,
            shell_mode="none",
            allowed_commands=(),
        )
        status, listing = self.request("GET", f"/kapsel/w/{other.token}/recycle/list")
        self.assertEqual(200, status)
        self.assertEqual(0, listing["total"])

    def test_mutating_file_operations_are_safe_by_default(self) -> None:
        (self.root / "source.txt").write_text("source", encoding="utf-8")
        (self.root / "target.txt").write_text("target", encoding="utf-8")
        status, payload = self.request(
            "POST",
            self.endpoint("/fs/move"),
            {"source": "source.txt", "destination": "target.txt"},
        )
        self.assertEqual(409, status)
        self.assertEqual("path_exists", payload["error"]["code"])
        self.assertEqual("source", (self.root / "source.txt").read_text())
        self.assertEqual("target", (self.root / "target.txt").read_text())

        status, payload = self.request(
            "POST",
            self.endpoint("/fs/delete"),
            {"path": ".", "recursive": True},
        )
        self.assertEqual(403, status)
        self.assertEqual("root_protected", payload["error"]["code"])

        status, payload = self.request(
            "POST",
            self.endpoint("/fs/mkdir"),
            {"path": "../escape"},
        )
        self.assertEqual(403, status)
        self.assertEqual("path_outside_root", payload["error"]["code"])

    def test_parent_and_symlink_escape_are_rejected(self) -> None:
        query = urlencode({"path": "../outside.txt"})
        status, payload = self.request("GET", self.endpoint(f"/fs/read?{query}"))
        self.assertEqual(403, status)
        self.assertEqual("path_outside_root", payload["error"]["code"])

        outside = Path(self.temp.name).parent / f"outside-{os.getpid()}.txt"
        outside.write_text("secret", encoding="utf-8")
        try:
            (self.root / "escape").symlink_to(outside)
            query = urlencode({"path": "escape"})
            status, payload = self.request("GET", self.endpoint(f"/fs/read?{query}"))
            self.assertEqual(403, status)
            self.assertEqual("path_outside_root", payload["error"]["code"])
        finally:
            outside.unlink(missing_ok=True)

    def test_nul_paths_return_client_errors_instead_of_internal_errors(self) -> None:
        status, payload = self.request(
            "GET",
            self.endpoint("/fs/read?path=%00"),
        )
        self.assertEqual(400, status)
        self.assertEqual("invalid_path", payload["error"]["code"])

        record = self.server.tokens.update("test-token", can_preview=True)
        status, raw, _ = self.raw_request(
            "GET",
            f"/{record.preview_token}/%00",
            headers={"Host": "preview.ws.example.test"},
        )
        payload = json.loads(raw)
        self.assertEqual(400, status)
        self.assertEqual("invalid_preview_path", payload["error"]["code"])
        self.assertNotIn("request_id", payload["error"])

        status, payload = self.request(
            "POST",
            self.endpoint("/fs/mkdir"),
            {"path": "bad\x00directory"},
        )
        self.assertEqual(400, status)
        self.assertEqual("invalid_path", payload["error"]["code"])

        status, payload = self.request(
            "POST",
            self.endpoint("/shell/exec"),
            {"command": "pwd", "cwd": "bad\x00directory"},
        )
        self.assertEqual(400, status)
        self.assertEqual("invalid_path", payload["error"]["code"])

    def test_extra_accessible_path_and_full_shell_cwd(self) -> None:
        published = Path(self.temp.name) / "published"
        published.mkdir()
        page = published / "index.html"
        page.write_text("old", encoding="utf-8")
        logs = Path(self.temp.name) / "published-logs"
        logs.mkdir()
        log_file = logs / "app.log"
        log_file.write_text("log", encoding="utf-8")
        query = urlencode({"path": str(page)})

        status, payload = self.request("GET", self.endpoint(f"/fs/read?{query}"))
        self.assertEqual(403, status)
        self.assertEqual("path_outside_root", payload["error"]["code"])

        self.server.tokens.update(
            "test-token",
            allowed_paths=(
                PathGrant(path=str(published), read_only=False),
                PathGrant(path=str(logs), read_only=True),
            ),
        )
        status, payload = self.request("GET", self.endpoint(f"/fs/read?{query}"))
        self.assertEqual(200, status)
        self.assertEqual("old", payload["content"])

        status, payload = self.request(
            "POST",
            self.endpoint("/fs/write"),
            {"path": str(page), "content": "published"},
        )
        self.assertEqual(200, status)
        self.assertEqual("published", page.read_text(encoding="utf-8"))

        log_query = urlencode({"path": str(log_file)})
        status, payload = self.request("GET", self.endpoint(f"/fs/read?{log_query}"))
        self.assertEqual(200, status)
        self.assertEqual("log", payload["content"])
        status, payload = self.request(
            "POST",
            self.endpoint("/fs/write"),
            {"path": str(log_file), "content": "blocked"},
        )
        self.assertEqual(403, status)
        self.assertEqual("read_only_path", payload["error"]["code"])
        self.assertEqual("log", log_file.read_text(encoding="utf-8"))

        status, payload = self.request(
            "POST",
            self.endpoint("/fs/delete"),
            {"path": str(page)},
        )
        self.assertEqual(403, status)
        self.assertEqual("outside_delete_not_supported", payload["error"]["code"])
        self.assertTrue(page.exists())

        status, payload = self.request(
            "POST",
            self.endpoint("/shell/exec"),
            {"command": "pwd", "cwd": str(published)},
        )
        self.assertEqual(202, status)
        task = self.wait_for_task(payload["task_id"])
        self.assertFalse(task["sandboxed"])
        self.assertTrue(task["network_access"])
        self.assertEqual(str(published.resolve()), task["stdout"].strip())

    def test_shell_is_async_and_returns_output_and_exit_code(self) -> None:
        status, payload = self.request(
            "POST",
            self.endpoint("/shell/exec"),
            {"command": "printf 'hello'; printf 'warning' >&2; exit 3", "cwd": "project"},
        )
        self.assertEqual(202, status)
        task_id = payload["task_id"]
        self.assertTrue(task_id.startswith("task_"))

        task = self.wait_for_task(task_id)
        self.assertEqual(3, task["exit_code"])
        self.assertEqual("hello", task["stdout"])
        self.assertEqual("warning", task["stderr"])
        self.assertEqual(str((self.root / "project").resolve()), task["cwd"])

    def test_shell_timeout_terminates_task(self) -> None:
        status, payload = self.request(
            "POST",
            self.endpoint("/shell/exec"),
            {"command": "sleep 2", "timeout_seconds": 0.1},
        )
        self.assertEqual(202, status)
        task = self.wait_for_task(payload["task_id"], timeout=4)
        self.assertTrue(task["timed_out"])
        self.assertIn("timed out", task["stderr"])

    def test_finished_tasks_are_disk_backed_and_capped_per_token(self) -> None:
        task_ids = []
        for index in range(5):
            status, started = self.request(
                "POST",
                self.endpoint("/shell/exec"),
                {"command": f"printf archived-{index}"},
            )
            self.assertEqual(202, status)
            task_ids.append(started["task_id"])
            self.wait_for_task(started["task_id"])

        deadline = time.monotonic() + 5
        while any(task_id in self.server.tasks._tasks for task_id in task_ids) and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(all(task_id not in self.server.tasks._tasks for task_id in task_ids))

        history_root = self.server.config.task_history_dir
        self.assertIsNotNone(history_root)
        token_key = hashlib.sha256(b"test-token").hexdigest()[:32]
        token_dir = history_root / token_key
        retained = sorted(path.name for path in token_dir.iterdir() if path.is_dir())
        self.assertEqual(4, len(retained))
        self.assertNotIn("test-token", str(token_dir))
        for directory in token_dir.iterdir():
            if not directory.is_dir():
                continue
            self.assertEqual(0o600, (directory / "meta.json").stat().st_mode & 0o777)
            self.assertEqual(0o600, (directory / "stdout.bin").stat().st_mode & 0o777)
            self.assertEqual(0o600, (directory / "stderr.bin").stat().st_mode & 0o777)

        status, missing = self.request("GET", self.endpoint(f"/tasks/{task_ids[0]}"))
        self.assertEqual(404, status)
        self.assertEqual("task_not_found", missing["error"]["code"])
        status, newest = self.request("GET", self.endpoint(f"/tasks/{task_ids[-1]}"))
        self.assertEqual(200, status)
        self.assertEqual("archived-4", newest["stdout"])
        status, listing = self.request("GET", self.endpoint("/tasks?status=finished"))
        self.assertEqual(200, status)
        self.assertEqual(4, listing["total"])

    def test_finished_task_retention_expires_from_disk(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            workspace = base / "workspace"
            workspace.mkdir()
            config = ServerConfig(
                root=workspace,
                task_history_dir=base / "tasks",
                finished_task_retention_seconds=1,
                max_finished_tasks_per_token=4,
            )
            registry = TaskRegistry(config, TokenCgroupManager(enabled=False))
            try:
                task = registry.start("printf ttl", workspace, 5, owner_token="ttl-token")
                deadline = time.monotonic() + 5
                while task.id in registry._tasks and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertNotIn(task.id, registry._tasks)
                self.assertEqual("ttl", registry.get(task.id, "ttl-token").serialize()["stdout"])
                registry.close()
                registry = TaskRegistry(config, TokenCgroupManager(enabled=False))
                self.assertEqual("ttl", registry.get(task.id, "ttl-token").serialize()["stdout"])
                time.sleep(1.05)
                with self.assertRaises(ApiError) as raised:
                    registry.get(task.id, "ttl-token")
                self.assertEqual("task_not_found", raised.exception.code)
            finally:
                registry.close()

    def test_complete_read_fix_execute_loop(self) -> None:
        demo = self.root / "demo"
        demo.mkdir()
        (demo / "calculator.py").write_text(
            "def add(left, right):\n    return left - right\n", encoding="utf-8"
        )
        (demo / "test_calculator.py").write_text(
            "import unittest\n"
            "from calculator import add\n\n"
            "class TestCalculator(unittest.TestCase):\n"
            "    def test_add(self):\n"
            "        self.assertEqual(5, add(2, 3))\n\n"
            "if __name__ == '__main__':\n"
            "    unittest.main()\n",
            encoding="utf-8",
        )

        status, payload = self.request(
            "POST",
            self.endpoint("/shell/exec"),
            {"command": "python3 -m unittest -v", "cwd": "demo"},
        )
        self.assertEqual(202, status)
        failed = self.wait_for_task(payload["task_id"])
        self.assertNotEqual(0, failed["exit_code"])
        self.assertIn("FAILED", failed["stderr"])

        query = urlencode({"path": "demo/calculator.py"})
        status, source = self.request("GET", self.endpoint(f"/fs/read?{query}"))
        self.assertEqual(200, status)
        self.assertIn("left - right", source["content"])

        status, payload = self.request(
            "POST",
            self.endpoint("/fs/replace"),
            {"path": "demo/calculator.py", "old": "left - right", "new": "left + right"},
        )
        self.assertEqual(200, status)
        self.assertEqual(1, payload["replacements"])

        status, payload = self.request(
            "POST",
            self.endpoint("/shell/exec"),
            {"command": "python3 -m unittest -v", "cwd": "demo"},
        )
        self.assertEqual(202, status)
        fixed = self.wait_for_task(payload["task_id"])
        self.assertEqual(0, fixed["exit_code"])
        self.assertIn("OK", fixed["stderr"])

    def test_admin_login_create_permissions_and_expiration(self) -> None:
        status, body, _ = self.raw_request("GET", "/kapsel/admin")
        self.assertEqual(200, status)
        self.assertIn("Workspace Administration", body.decode("utf-8"))

        bad_form = urlencode({"username": "admin", "password": "wrong-password"}).encode()
        status, _, _ = self.raw_request(
            "POST",
            "/kapsel/admin/login",
            bad_form,
            {"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(401, status)

        login_form = urlencode(
            {"username": "admin", "password": "correct-horse-battery"}
        ).encode()
        status, _, headers = self.raw_request(
            "POST",
            "/kapsel/admin/login",
            login_form,
            {"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(303, status)

        cookie = headers["Set-Cookie"].split(";", 1)[0]
        self.assertIn("HttpOnly", headers["Set-Cookie"])
        self.assertIn("Secure", headers["Set-Cookie"])
        self.assertIn("Path=/kapsel/admin", headers["Set-Cookie"])

        status, dashboard, _ = self.raw_request("GET", "/kapsel/admin", headers={"Cookie": cookie})
        self.assertEqual(200, status)
        dashboard_text = dashboard.decode("utf-8")
        self.assertIn('data-initial-panel="tokens"', dashboard_text)
        self.assertIn('data-admin-tab="tokens"', dashboard_text)
        self.assertIn('data-admin-tab="password"', dashboard_text)
        self.assertIn('data-admin-panel="tokens"', dashboard_text)
        self.assertIn('data-admin-panel="password" hidden', dashboard_text)
        self.assertIn("function setAdminPanel", dashboard_text)
        self.assertIn('<details class="card token-card">', dashboard_text)
        self.assertNotIn('<details class="card token-card" open', dashboard_text)
        self.assertIn('<strong>Workspace</strong><span>.</span>', dashboard_text)
        self.assertIn('<strong>Workspace lifetime</strong><span>Never expires</span>', dashboard_text)
        self.assertIn('class="summary-toggle"', dashboard_text)
        self.assertLess(
            dashboard_text.index("Existing tokens (1)"),
            dashboard_text.index("<h2>Create token</h2>"),
        )

        self.assertIn("https://ws.example.test/kapsel/w/test-token/", dashboard_text)
        self.assertIn("https://ws.example.test/kapsel/w/test-token/mcp", dashboard_text)
        self.assertIn("Copy MCP URL", dashboard_text)
        self.assertIn("Copy MCP URL + control token", dashboard_text)
        self.assertIn(
            "copyUrlAndToken('mcp-testtoken','control-testtoken',this)",
            dashboard_text,
        )
        mcp_address_position = dashboard_text.index('id="mcp-testtoken"')
        mcp_copy_position = dashboard_text.index(">Copy MCP URL</button>")
        preview_label_position = dashboard_text.index(
            "<label>Web preview URL (independent read-only credential)</label>"
        )
        self.assertLess(mcp_address_position, mcp_copy_position)
        self.assertLess(mcp_copy_position, preview_label_position)
        self.assertIn(
            f"https://preview.ws.example.test/"
            f"{self.server.tokens.get('test-token').preview_token}/",
            dashboard_text,
        )
        self.assertIn("Copy web preview URL", dashboard_text)
        self.assertIn("Copy Authorization header", dashboard_text)
        self.assertIn("Copy URL + control token", dashboard_text)
        self.assertIn("function copyUrlAndToken", dashboard_text)
        self.assertIn("writeClipboard(url+'\\n'+control,button)", dashboard_text)
        self.assertIn(
            "copyUrlAndToken('url-testtoken','control-testtoken',this)",
            dashboard_text,
        )
        self.assertIn("Regenerate control token", dashboard_text)
        self.assertIn("Regenerate read-only URL token", dashboard_text)
        self.assertIn("Renew read + control tokens", dashboard_text)
        self.assertIn('name="renew_days" value="3" min="1" max="30"', dashboard_text)
        self.assertIn("Renewal does not change the preview token or workspace lifetime", dashboard_text)
        self.assertNotIn("Regenerate primary token", dashboard_text)
        self.assertIn(
            self.server.tokens.get("test-token").control_token,
            dashboard_text,
        )
        self.assertIn("Regenerate preview token", dashboard_text)
        self.assertIn('name="network_mode"', dashboard_text)
        self.assertIn('name="allowed_domains"', dashboard_text)
        self.assertIn('<option value="domain_allowlist" selected>Allowed domains only</option>', dashboard_text)
        self.assertIn("github.com", dashboard_text)
        self.assertIn('name="can_preview"', dashboard_text)
        self.assertIn('name="sandbox_backend"', dashboard_text)
        self.assertIn("<label>Workspace expiration</label>", dashboard_text)
        self.assertNotIn("Workspace expiration (UTC; blank means never)", dashboard_text)
        create_token_position = dashboard_text.index("<h2>Create token</h2>")
        for form_markup in (
            dashboard_text[:create_token_position],
            dashboard_text[create_token_position:],
        ):
            self.assertLess(
                form_markup.index("<label>Shell permission</label>"),
                form_markup.index("<label>Network mode</label>"),
            )
        self.assertNotIn("Web App username", dashboard_text)
        self.assertNotIn('name="web_password"', dashboard_text)
        self.assertNotIn("revoke_web_sessions", dashboard_text)
        self.assertIn('name="allowed_path"', dashboard_text)
        self.assertIn('name="allowed_path_mode"', dashboard_text)
        self.assertIn('<option value="2184">91 days</option>', dashboard_text)
        self.assertIn('<option value="8760">365 days</option>', dashboard_text)
        self.assertIn('<option value="17520">730 days</option>', dashboard_text)
        self.assertNotIn('value="1">1 hour', dashboard_text)
        csrf_match = re.search(r'name="csrf" value="([^"]+)"', dashboard_text)
        self.assertIsNotNone(csrf_match)
        csrf = csrf_match.group(1)

        admin_read_only = Path(self.temp.name) / "admin-read-only"
        admin_read_only.mkdir()
        create_form = urlencode(
            {
                "csrf": csrf,
                "action": "create",
                "name": "Restricted project token",
                "ttl_hours": "24",
                "path_prefix": "new-project",
                "can_read": "on",
                "can_preview": "on",
                "shell_mode": "restricted",
                "allowed_path": str(admin_read_only),
                "allowed_path_mode": "ro",
                "sandbox_max_processes": "72",
                "sandbox_memory_mb": "768",
                "sandbox_cpu_percent": "150",
            }
        ).encode()
        status, _, _ = self.raw_request(
            "POST",
            "/kapsel/admin/tokens",
            create_form,
            {"Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie},
        )
        self.assertEqual(303, status)
        record = next(item for item in self.server.tokens.list() if item.name == "Restricted project token")
        self.assertFalse(record.can_write)
        self.assertTrue(record.can_preview)
        self.assertEqual("restricted", record.shell_mode)
        self.assertEqual("auto", record.sandbox_backend)
        self.assertEqual("none", record.network_mode)
        self.assertEqual(72, record.sandbox_max_processes)
        self.assertEqual(768, record.sandbox_memory_mb)
        self.assertEqual(150, record.sandbox_cpu_percent)
        self.assertEqual(
            (PathGrant(path=str(admin_read_only.resolve()), read_only=True),),
            record.allowed_paths,
        )
        self.assertTrue((self.root / "new-project" / ".openkapsel" / "recycle").is_dir())
        self.assertTrue((self.root / "new-project" / ".openkapsel" / "context").is_dir())
        token_file = Path(self.temp.name) / "tokens.json"
        self.assertEqual(0o600, token_file.stat().st_mode & 0o777)
        self.assertNotIn("correct-horse-battery", token_file.read_text(encoding="utf-8"))

        old_preview_token = record.preview_token
        rotate_form = urlencode(
            {"csrf": csrf, "action": "rotate_preview", "token": record.token}
        ).encode()
        status, _, _ = self.raw_request(
            "POST",
            "/kapsel/admin/tokens",
            rotate_form,
            {"Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie},
        )
        self.assertEqual(303, status)
        record = self.server.tokens.get(record.token)
        self.assertNotEqual(old_preview_token, record.preview_token)
        status, raw, _ = self.raw_request(
            "GET",
            f"/{old_preview_token}/missing.html",
            headers={"Host": "preview.ws.example.test"},
        )
        old_preview = json.loads(raw.decode("utf-8"))
        self.assertEqual(404, status)
        self.assertEqual("not_found", old_preview["error"]["code"])
        status, raw, _ = self.raw_request(
            "GET",
            f"/{record.preview_token}/missing.html",
            headers={"Host": "preview.ws.example.test"},
        )
        new_preview = json.loads(raw.decode("utf-8"))
        self.assertEqual(404, status)
        self.assertEqual("preview_not_found", new_preview["error"]["code"])

        old_record = record
        old_control_token = record.control_token
        rotate_control_form = urlencode(
            {"csrf": csrf, "action": "rotate_control", "token": record.token}
        ).encode()
        status, _, headers = self.raw_request(
            "POST",
            "/kapsel/admin/tokens",
            rotate_control_form,
            {"Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie},
        )
        self.assertEqual(303, status)
        self.assertEqual("/kapsel/admin?control_token_rotated=1", headers["Location"])
        record = self.server.tokens.get(record.token)
        self.assertNotEqual(old_control_token, record.control_token)
        self.assertEqual(old_record.token, record.token)
        old_values = old_record.to_dict()
        new_values = record.to_dict()
        old_values.pop("control_token")
        new_values.pop("control_token")
        self.assertEqual(old_values, new_values)
        self.assertIsNone(self.server.tokens.authenticate_control(old_control_token))
        self.assertEqual(record, self.server.tokens.authenticate_control(record.control_token))
        self.assertEqual(record, self.server.tokens.authenticate(record.token))
        self.assertEqual(record, self.server.tokens.authenticate_preview(record.preview_token))
        self.assertNotIn(old_control_token, token_file.read_text(encoding="utf-8"))

        old_token = record.token
        control_token = record.control_token
        rotate_read_form = urlencode(
            {"csrf": csrf, "action": "rotate_read", "token": old_token}
        ).encode()
        status, _, headers = self.raw_request(
            "POST",
            "/kapsel/admin/tokens",
            rotate_read_form,
            {"Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie},
        )
        self.assertEqual(303, status)
        self.assertEqual("/kapsel/admin?read_token_rotated=1", headers["Location"])
        record = next(item for item in self.server.tokens.list() if item.name == "Restricted project token")
        self.assertNotEqual(old_token, record.token)
        self.assertEqual(control_token, record.control_token)
        self.assertIsNone(self.server.tokens.authenticate(old_token))
        status, old_main = self.request("GET", f"/kapsel/w/{old_token}/")
        self.assertEqual(404, status)
        self.assertEqual("not_found", old_main["error"]["code"])

        old_read_token = record.token
        old_control_token = record.control_token
        preview_token = record.preview_token
        renew_started = datetime.now(timezone.utc)
        renew_form = urlencode(
            {
                "csrf": csrf,
                "action": "renew",
                "token": record.token,
                "renew_days": "5",
            }
        ).encode()
        status, _, headers = self.raw_request(
            "POST",
            "/kapsel/admin/tokens",
            renew_form,
            {"Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie},
        )
        self.assertEqual(303, status)
        self.assertEqual("/kapsel/admin?credentials_renewed=1", headers["Location"])
        record = next(
            item
            for item in self.server.tokens.list()
            if item.name == "Restricted project token"
        )
        self.assertNotEqual(old_read_token, record.token)
        self.assertNotEqual(old_control_token, record.control_token)
        self.assertEqual(preview_token, record.preview_token)
        renewed_until = datetime.fromisoformat(record.credentials_expires_at)
        self.assertGreaterEqual(renewed_until, renew_started + timedelta(days=5))
        self.assertLess(renewed_until, renew_started + timedelta(days=5, seconds=5))
        self.assertIsNone(self.server.tokens.authenticate(old_read_token))
        self.assertIsNone(self.server.tokens.authenticate_control(old_control_token))
        self.assertEqual(record, self.server.tokens.authenticate(record.token))
        self.assertEqual(record, self.server.tokens.authenticate_control(record.control_token))
        self.assertEqual(record, self.server.tokens.authenticate_preview(preview_token))

        rejected_renew = urlencode(
            {
                "csrf": csrf,
                "action": "renew",
                "token": record.token,
                "renew_days": "31",
            }
        ).encode()
        status, rejected_dashboard, _ = self.raw_request(
            "POST",
            "/kapsel/admin/tokens",
            rejected_renew,
            {"Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie},
        )
        self.assertEqual(400, status)
        self.assertIn("credential lifetime must be between 1 and 30 days", rejected_dashboard.decode())
        self.assertEqual(record, self.server.tokens.get(record.token))

        status, discovery = self.request(
            "GET", f"/kapsel/w/{record.token}/discovery/full"
        )
        self.assertEqual(200, status)
        self.assertEqual(str((self.root / "new-project").resolve()), discovery["root"])
        self.assertFalse(discovery["capabilities"]["files"]["write"])
        self.assertTrue(discovery["capabilities"]["recycle"])
        self.assertTrue(discovery["capabilities"]["web_preview"]["enabled"])
        self.assertEqual("restricted", discovery["capabilities"]["shell"])
        self.assertEqual("bubblewrap", discovery["capabilities"]["shell_sandbox"])
        self.assertEqual("auto", discovery["capabilities"]["shell_sandbox_requested"])
        self.assertIn("bubblewrap", discovery["capabilities"]["sandbox_backends"])
        self.assertFalse(discovery["capabilities"]["network"])
        self.assertEqual(
            record.credentials_expires_at,
            discovery["authentication"]["read_token_expires_at"],
        )
        self.assertEqual(
            record.credentials_expires_at,
            discovery["authentication"]["control_token_expires_at"],
        )
        self.assertEqual(record.credentials_expires_at, discovery["token"]["credentials_expires_at"])
        self.assertEqual(
            [{"path": str(admin_read_only.resolve()), "read_only": True}],
            discovery["capabilities"]["extra_paths"],
        )

        record = self.server.tokens.update(
            record.token,
            sandbox_backend="podman",
            sandbox_image="docker.io/library/python:3.14-slim-trixie",
        )
        status, discovery = self.request(
            "GET", f"/kapsel/w/{record.token}/discovery/shell"
        )
        self.assertEqual(200, status)
        self.assertEqual("podman", discovery["capabilities"]["shell_sandbox"])
        self.assertEqual(
            "docker.io/library/python:3.14-slim-trixie",
            discovery["capabilities"]["shell_sandbox_image"],
        )
        self.assertEqual(
            "docker.io/library/python:3.14-slim-trixie",
            discovery["capabilities"]["shell_sandbox_image_requested"],
        )
        record = self.server.tokens.update(
            record.token,
            sandbox_backend="auto",
            sandbox_image=None,
        )

        record = self.server.tokens.update(
            record.token,
            network_mode="domain_allowlist",
            allowed_domains=("github.com", ".githubusercontent.com"),
        )
        status, discovery = self.request(
            "GET", f"/kapsel/w/{record.token}/discovery/shell"
        )
        self.assertEqual(200, status)
        self.assertTrue(discovery["capabilities"]["network"])
        self.assertEqual(
            "domain_allowlist", discovery["capabilities"]["network_mode"]
        )
        self.assertEqual(
            ["github.com", ".githubusercontent.com"],
            discovery["capabilities"]["network_domains"],
        )
        record = self.server.tokens.update(record.token, network_mode="none")

        status, payload = self.request(
            "POST",
            f"/kapsel/w/{record.token}/fs/write",
            {"path": "blocked.txt", "content": "no"},
        )
        self.assertEqual(403, status)
        self.assertEqual("permission_denied", payload["error"]["code"])

        status, payload = self.request(
            "POST",
            f"/kapsel/w/{record.token}/shell/exec",
            {"command": "python3 --version"},
        )
        self.assertEqual(202, status)
        launch_argv = self.server.tasks._tasks[payload["task_id"]].argv
        restricted_task = self.wait_for_task(payload["task_id"], token=record.token)
        self.assertEqual(0, restricted_task["exit_code"])
        self.assertTrue(restricted_task["sandboxed"])
        self.assertFalse(restricted_task["network_access"])
        self.assertIsNotNone(launch_argv)
        self.assertIn("--unshare-user", launch_argv)
        self.assertIn("--unshare-pid", launch_argv)
        self.assertIn("--unshare-net", launch_argv)
        self.assertEqual(("/bin/sh", "-c", "python3 --version"), launch_argv[-3:])
        launch_mounts = tuple(zip(launch_argv, launch_argv[1:], launch_argv[2:]))
        self.assertNotIn(("--ro-bind", "/", "/"), launch_mounts)
        self.assertIn(("--ro-bind", "/usr", "/usr"), launch_mounts)
        self.assertIn(("--proc", "/proc"), tuple(zip(launch_argv, launch_argv[1:])))
        self.assertNotIn(
            ("--ro-bind", "/proc", "/proc"),
            launch_mounts,
        )
        self.assertIn(
            ("--ro-bind", str((self.root / "new-project").resolve()), str((self.root / "new-project").resolve())),
            launch_mounts,
        )
        self.assertIn(
            ("--tmpfs", str((self.root / "new-project" / ".openkapsel").resolve())),
            tuple(zip(launch_argv, launch_argv[1:])),
        )

        external_path = Path(self.temp.name) / "restricted-extra"
        external_path.mkdir()
        read_only_external = Path(self.temp.name) / "restricted-read-only"
        read_only_external.mkdir()
        record = self.server.tokens.update(
            record.token,
            can_write=True,
            network_mode="full",
            allowed_paths=(
                PathGrant(path=str(external_path), read_only=False),
                PathGrant(path=str(read_only_external), read_only=True),
            ),
        )
        status, payload = self.request(
            "POST",
            f"/kapsel/w/{record.token}/shell/exec",
            {"command": "python3 --version"},
        )
        self.assertEqual(202, status)
        enabled_argv = self.server.tasks._tasks[payload["task_id"]].argv
        enabled_task = self.wait_for_task(payload["task_id"], token=record.token)
        self.assertTrue(enabled_task["sandboxed"])
        self.assertTrue(enabled_task["network_access"])
        self.assertEqual(str(self.fake_rootlesskit.resolve()), enabled_argv[0])
        self.assertIn("--copy-up=/etc", enabled_argv)
        self.assertIn("--net=slirp4netns", enabled_argv)
        self.assertIn("--disable-host-loopback", enabled_argv)
        bwrap_index = enabled_argv.index(str(self.fake_bwrap.resolve()))
        sandbox_argv = enabled_argv[bwrap_index:]
        self.assertIn("--unshare-user", sandbox_argv)
        self.assertIn("--unshare-pid", sandbox_argv)
        self.assertNotIn("--unshare-net", sandbox_argv)
        self.assertNotIn("--pidns", enabled_argv[:bwrap_index])
        mounts = tuple(zip(enabled_argv, enabled_argv[1:], enabled_argv[2:]))
        self.assertNotIn(("--ro-bind", "/", "/"), mounts)
        self.assertIn(("--ro-bind", "/usr", "/usr"), mounts)
        resolved_external = str(external_path.resolve())
        self.assertIn(("--bind", resolved_external, resolved_external), mounts)
        resolved_read_only = str(read_only_external.resolve())
        self.assertIn(
            ("--ro-bind", resolved_read_only, resolved_read_only),
            mounts,
        )

        status, payload = self.request(
            "POST",
            f"/kapsel/w/{record.token}/shell/exec",
            {"command": "printf first; printf second"},
        )
        self.assertEqual(202, status)
        shell_syntax_task = self.wait_for_task(payload["task_id"], token=record.token)
        self.assertEqual(0, shell_syntax_task["exit_code"])
        self.assertEqual("firstsecond", shell_syntax_task["stdout"])

        status, payload = self.request(
            "POST",
            f"/kapsel/w/{record.token}/shell/exec",
            {"command": "uname -a"},
        )
        self.assertEqual(202, status)
        arbitrary_task = self.wait_for_task(payload["task_id"], token=record.token)
        self.assertEqual(0, arbitrary_task["exit_code"])
        self.assertTrue(arbitrary_task["stdout"].strip())

        self.server.tokens.update(record.token, expires_at="2000-01-01T00:00:00+00:00")
        status, payload = self.request("GET", f"/kapsel/w/{record.token}/")
        self.assertEqual(404, status)
        self.assertEqual("not_found", payload["error"]["code"])

    def test_admin_dashboard_derives_public_url_behind_proxy(self) -> None:
        session = self.server.admin_sessions.create()
        original_public_base_url = self.server.config.public_base_url
        object.__setattr__(self.server.config, "public_base_url", None)
        try:
            status, dashboard, _ = self.raw_request(
                "GET",
                "/kapsel/admin",
                headers={
                    "Cookie": f"ws_admin={session.id}",
                    "Host": "workspace.example.test",
                    "X-Forwarded-Proto": "https",
                },
            )
        finally:
            object.__setattr__(
                self.server.config,
                "public_base_url",
                original_public_base_url,
            )
        self.assertEqual(200, status)
        self.assertIn(
            "https://workspace.example.test/kapsel/w/test-token",
            dashboard.decode("utf-8"),
        )

    def test_admin_login_limiter_uses_last_forwarded_address_from_loopback_proxy(self) -> None:
        body = urlencode({"username": "admin", "password": "wrong"}).encode("utf-8")
        with patch.object(
            self.server.admin_login_limiter,
            "retry_after",
            return_value=60,
        ) as retry_after:
            status, _, _ = self.raw_request(
                "POST",
                "/kapsel/admin/login",
                body,
                {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-Forwarded-For": "192.0.2.10, 198.51.100.27",
                },
                authorize=False,
            )
        self.assertEqual(429, status)
        retry_after.assert_called_once_with("198.51.100.27")

    def test_admin_login_limiter_escalates_windows_and_success_clears(self) -> None:
        limiter = AdminLoginLimiter()
        address = "198.51.100.40"
        for now in (0.0, 1.0, 2.0):
            with patch("openkapsel.server.time.time", return_value=now):
                self.assertEqual(0, limiter.retry_after(address))
                limiter.failed(address)
        with patch("openkapsel.server.time.time", return_value=2.0):
            self.assertEqual(58, limiter.retry_after(address))
        with patch("openkapsel.server.time.time", return_value=60.0):
            self.assertEqual(0, limiter.retry_after(address))
            limiter.failed(address)
            self.assertEqual(60, limiter.retry_after(address))
        with patch("openkapsel.server.time.time", return_value=120.0):
            self.assertEqual(0, limiter.retry_after(address))
            limiter.failed(address)
            self.assertEqual(60, limiter.retry_after(address))
            limiter.succeeded(address)
            self.assertEqual(0, limiter.retry_after(address))

    def test_admin_login_rejects_short_password_without_recording_failure(self) -> None:
        status, login, _ = self.raw_request("GET", "/kapsel/admin")
        self.assertEqual(200, status)
        self.assertIn('minlength="8"', login.decode("utf-8"))
        body = urlencode({"username": "admin", "password": "short"}).encode("utf-8")
        with patch.object(self.server.admin_login_limiter, "failed") as failed:
            status, _, _ = self.raw_request(
                "POST",
                "/kapsel/admin/login",
                body,
                {"Content-Type": "application/x-www-form-urlencoded"},
                authorize=False,
            )
        self.assertEqual(400, status)
        failed.assert_not_called()

    def test_admin_login_returns_429_after_three_failures(self) -> None:
        body = urlencode({"username": "admin", "password": "wrong-password"}).encode("utf-8")
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Forwarded-For": "198.51.100.41",
        }
        for _ in range(3):
            status, _, _ = self.raw_request(
                "POST", "/kapsel/admin/login", body, headers, authorize=False
            )
            self.assertEqual(401, status)
        status, _, response_headers = self.raw_request(
            "POST", "/kapsel/admin/login", body, headers, authorize=False
        )
        self.assertEqual(429, status)
        self.assertGreaterEqual(int(response_headers["Retry-After"]), 1)

    def test_web_preview_serves_index_assets_ranges_and_safe_errors(self) -> None:
        site = self.root / "project" / "site"
        site.mkdir()
        index = (
            "<!doctype html><meta charset=utf-8><title>Preview works</title>"
            '<link rel="stylesheet" href="style.css">'
            '<h1 id="status">loading</h1>'
            '<script src="app.js"></script>'
        )
        (site / "index.html").write_text(index, encoding="utf-8")
        (site / "style.css").write_text("h1 { color: rgb(12, 34, 56); }", encoding="utf-8")
        (site / "app.js").write_text(
            "document.querySelector('#status').textContent = 'preview-ready';",
            encoding="utf-8",
        )
        (site / "data.bin").write_bytes(b"0123456789")
        (self.root / "index.html").write_text("preview root", encoding="utf-8")

        status, hidden = self.request(
            "GET", self.endpoint("/web/project/site/index.html")
        )
        self.assertEqual(404, status)
        self.assertEqual("not_found", hidden["error"]["code"])
        for method, path in (
            ("GET", "/kapsel/admin"),
            ("GET", "/test-token/fs/list"),
            ("POST", self.preview_endpoint("/project/site/index.html")),
        ):
            status, raw, _ = self.raw_request(
                method,
                path,
                headers={"Host": "preview.ws.example.test"},
            )
            self.assertEqual(404, status)
            self.assertEqual("not_found", json.loads(raw)["error"]["code"])
        preview_token = self.server.tokens.get("test-token").preview_token
        status, hidden = self.request(
            "GET", f"/kapsel/w/{preview_token}/fs/list?path=."
        )
        self.assertEqual(404, status)
        self.assertEqual("not_found", hidden["error"]["code"])
        status, hidden = self.preview_request("GET", "/fs/list?path=.")
        self.assertEqual(404, status)
        self.assertEqual("preview_not_found", hidden["error"]["code"])

        preview_root = self.preview_endpoint()
        status, _, headers = self.raw_preview_request("GET")
        self.assertEqual(308, status)
        self.assertEqual(preview_root + "/", headers["Location"])
        status, body, _ = self.raw_preview_request("GET", "/")
        self.assertEqual(200, status)
        self.assertEqual(b"preview root", body)

        status, body, headers = self.raw_preview_request(
            "GET", "/project/site/index.html"
        )
        self.assertEqual(200, status)
        self.assertEqual(index, body.decode("utf-8"))
        self.assertTrue(headers["Content-Type"].startswith("text/html"))
        self.assertEqual("no-referrer", headers["Referrer-Policy"])
        self.assertIn(
            "sandbox allow-scripts allow-same-origin",
            headers["Content-Security-Policy"],
        )
        self.assertNotIn("Access-Control-Allow-Origin", headers)
        self.assertEqual("same-origin", headers["Cross-Origin-Resource-Policy"])
        self.assertEqual("DENY", headers["X-Frame-Options"])
        self.assertNotIn("Set-Cookie", headers)

        status, _, headers = self.raw_preview_request("GET", "/project/site?mode=test")
        self.assertEqual(308, status)
        self.assertEqual(
            self.preview_endpoint("/project/site/?mode=test"),
            headers["Location"],
        )
        status, body, _ = self.raw_preview_request("GET", "/project/site/")
        self.assertEqual(200, status)
        self.assertEqual(index, body.decode("utf-8"))

        status, body, headers = self.raw_preview_request(
            "GET", "/project/site/data.bin", headers={"Range": "bytes=2-5"}
        )
        self.assertEqual(206, status)
        self.assertEqual(b"2345", body)
        self.assertEqual("bytes 2-5/10", headers["Content-Range"])

        status, body, headers = self.raw_preview_request(
            "HEAD", "/project/site/style.css"
        )
        self.assertEqual(200, status)
        self.assertEqual(b"", body)
        self.assertTrue(headers["Content-Type"].startswith("text/css"))

        status, missing = self.preview_request("GET", "/project/site/missing.html")
        self.assertEqual(404, status)
        self.assertEqual("preview_not_found", missing["error"]["code"])
        status, escaped = self.preview_request("GET", "/%2e%2e/config.json")
        self.assertEqual(403, status)
        self.assertEqual("path_outside_root", escaped["error"]["code"])

        self.server.tokens.update("test-token", can_preview=False)
        status, denied = self.preview_request("GET", "/project/site/index.html")
        self.assertEqual(403, status)
        self.assertEqual("permission_denied", denied["error"]["code"])
        status, discovery = self.request("GET", self.endpoint("/discovery/web"))
        self.assertEqual(200, status)
        self.assertFalse(discovery["capabilities"]["web_preview"]["enabled"])
        self.assertFalse(discovery["endpoints"]["web_preview"]["available"])
        self.assertFalse(discovery["capabilities"]["web_app_api"]["database"]["enabled"])
        self.assertFalse(discovery["endpoints"]["web_app_api"]["available"])

    def test_nested_api_directories_mount_independent_fastapi_apps(self) -> None:
        site_a = self.root / "project" / "site-a"
        site_b = self.root / "project" / "site-b"
        for site in (site_a, site_b):
            (site / "api").mkdir(parents=True)
            (site / "api" / "app.py").write_text("app = object()\n", encoding="utf-8")
            (site / "index.html").write_text(site.name, encoding="utf-8")
        (site_a / ".openkapsel" / "sql").mkdir(parents=True)
        (site_a / ".openkapsel" / "sql" / "secret.txt").write_text("private", encoding="utf-8")
        (site_a / "database-alias").symlink_to(".openkapsel/sql", target_is_directory=True)
        (self.root / "project" / "orphan" / "api").mkdir(parents=True)
        (self.root / "api").mkdir()
        (self.root / "api" / "app.py").write_text("app = object()\n", encoding="utf-8")

        calls: list[dict[str, object]] = []

        class StubResponse:
            status = 200

            @staticmethod
            def read(_limit: int) -> bytes:
                return b'{"proxied":true}'

            @staticmethod
            def getheaders() -> list[tuple[str, str]]:
                return [("Content-Type", "application/json")]

        class StubConnection:
            def __init__(self, call: dict[str, object]):
                self.call = call

            def request(
                self,
                method: str,
                target: str,
                body: bytes | None = None,
                headers: dict[str, str] | None = None,
            ) -> None:
                self.call.update(
                    method=method,
                    target=target,
                    body=body,
                    headers=headers,
                )

            @staticmethod
            def getresponse() -> StubResponse:
                return StubResponse()

            @staticmethod
            def close() -> None:
                return None

        def connection(record, workspace, root_path, worker_key):
            call = {
                "record": record,
                "workspace": workspace,
                "root_path": root_path,
                "worker_key": worker_key,
            }
            calls.append(call)
            return StubConnection(call)

        preview_token = self.server.tokens.get("test-token").preview_token
        with patch.object(self.server.api_workers, "connection", side_effect=connection):
            body = b'{"name":"one"}'
            status, response, _ = self.raw_preview_request(
                "POST",
                "/project/site-a/api/items?draft=1",
                body=body,
                headers={"Content-Type": "application/json"},
            )
            self.assertEqual(200, status)
            self.assertEqual(b'{"proxied":true}', response)
            self.assertEqual(site_a.resolve(), calls[-1]["workspace"])
            self.assertEqual(
                f"/{preview_token}/project/site-a/api",
                calls[-1]["root_path"],
            )
            self.assertEqual("/items?draft=1", calls[-1]["target"])
            self.assertEqual(body, calls[-1]["body"])

            call_count = len(calls)
            for documentation_path in (
                "/docs",
                "/docs/",
                "/docs/oauth2-redirect",
                "/redoc",
                "/openapi.json",
            ):
                status, blocked = self.preview_request(
                    "GET", f"/project/site-a/api{documentation_path}"
                )
                self.assertEqual(404, status)
                self.assertEqual("api_not_found", blocked["error"]["code"])
            self.assertEqual(call_count, len(calls))

            status, _, _ = self.raw_preview_request(
                "GET", "/project/site-b/api/status"
            )
            self.assertEqual(200, status)
            self.assertEqual(site_b.resolve(), calls[-1]["workspace"])
            self.assertEqual(
                f"/{preview_token}/project/site-b/api",
                calls[-1]["root_path"],
            )
            self.assertNotEqual(calls[-2]["worker_key"], calls[-1]["worker_key"])

            status, _, _ = self.raw_preview_request(
                "GET", "/project/site-a/api/nested/api/value"
            )
            self.assertEqual(200, status)
            self.assertEqual(site_a.resolve(), calls[-1]["workspace"])
            self.assertEqual("/nested/api/value", calls[-1]["target"])

            status, _, _ = self.raw_preview_request(
                "GET", "/project/site-a/api/app.py"
            )
            self.assertEqual(200, status)
            self.assertEqual("/app.py", calls[-1]["target"])

            control_token = self.server.tokens.get("test-token").control_token
            status, _, _ = self.raw_request(
                "GET",
                self.endpoint("/api/private"),
                headers={"Authorization": f"Bearer {control_token}"},
                authorize=False,
            )
            self.assertEqual(200, status)
            self.assertNotIn("Authorization", calls[-1]["headers"])

            status, _, _ = self.raw_preview_request(
                "GET",
                "/project/site-a/api/private",
                headers={"Authorization": "Bearer application-user-token"},
            )
            self.assertEqual(200, status)
            self.assertEqual(
                "Bearer application-user-token",
                calls[-1]["headers"]["Authorization"],
            )

        status, payload = self.preview_request("GET", "/project/orphan/api/value")
        self.assertEqual(404, status)
        self.assertEqual("api_not_found", payload["error"]["code"])
        status, payload = self.preview_request(
            "GET", "/project/site-a/.openkapsel/sql/secret.txt"
        )
        self.assertEqual(404, status)
        self.assertEqual("preview_not_found", payload["error"]["code"])
        status, payload = self.preview_request(
            "GET", "/project/site-a/database-alias/secret.txt"
        )
        self.assertEqual(404, status)
        self.assertEqual("preview_not_found", payload["error"]["code"])
        status, payload = self.request(
            "GET",
            self.endpoint("/fs/read?path=project/site-a/.openkapsel/sql/secret.txt"),
        )
        self.assertEqual(403, status)
        self.assertEqual("reserved_path", payload["error"]["code"])
        status, payload = self.request(
            "GET",
            self.endpoint("/fs/read?path=project/site-a/database-alias/secret.txt"),
        )
        self.assertEqual(403, status)
        self.assertEqual("reserved_path", payload["error"]["code"])
        status, listing = self.request(
            "GET", self.endpoint("/fs/list?path=project/site-a")
        )
        self.assertEqual(200, status)
        self.assertNotIn(".openkapsel", [entry["name"] for entry in listing["entries"]])
        status, body, _ = self.raw_preview_request("GET", "/project/site-a/index.html")
        self.assertEqual(200, status)
        self.assertEqual(b"site-a", body)

    def test_admin_requires_csrf(self) -> None:
        login_form = urlencode(
            {"username": "admin", "password": "correct-horse-battery"}
        ).encode()
        _, _, headers = self.raw_request(
            "POST",
            "/kapsel/admin/login",
            login_form,
            {"Content-Type": "application/x-www-form-urlencoded"},
        )
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        form = urlencode({"action": "delete", "token": "test-token", "csrf": "wrong"}).encode()
        status, _, _ = self.raw_request(
            "POST",
            "/kapsel/admin/tokens",
            form,
            {"Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie},
        )
        self.assertEqual(403, status)
        self.assertIsNotNone(self.server.tokens.authenticate("test-token"))

    def test_admin_can_change_password_online(self) -> None:
        legacy_hash = hashlib.sha256(
            f"{LEGACY_PASSWORD_SALT}\0correct-horse-battery".encode("utf-8")
        ).hexdigest()
        config_payload = json.loads(self.config_path.read_text(encoding="utf-8"))
        config_payload["admin"] = {
            "username": "admin",
            "password_sha256": legacy_hash,
        }
        self.config_path.write_text(json.dumps(config_payload), encoding="utf-8")
        self.config_path.chmod(0o600)
        self.server.admin_password_hash = legacy_hash
        login_form = urlencode(
            {"username": "admin", "password": "correct-horse-battery"}
        ).encode()
        status, _, headers = self.raw_request(
            "POST",
            "/kapsel/admin/login",
            login_form,
            {"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(303, status)
        migrated_admin = json.loads(self.config_path.read_text(encoding="utf-8"))["admin"]
        self.assertIn("password_hash", migrated_admin)
        self.assertNotIn("password_sha256", migrated_admin)
        self.assertFalse(password_hash_needs_upgrade(migrated_admin["password_hash"]))
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        status, dashboard, _ = self.raw_request(
            "GET", "/kapsel/admin", headers={"Cookie": cookie}
        )
        self.assertEqual(200, status)
        dashboard_text = dashboard.decode("utf-8")
        self.assertIn("Change administrator password", dashboard_text)
        csrf = re.search(r'name="csrf" value="([^"]+)"', dashboard_text).group(1)

        wrong_old = urlencode(
            {
                "csrf": csrf,
                "old_password": "wrong-old-password",
                "new_password": "new-password-12345",
                "confirm_password": "new-password-12345",
            }
        ).encode()
        status, body, _ = self.raw_request(
            "POST",
            "/kapsel/admin/password",
            wrong_old,
            {"Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie},
        )
        self.assertEqual(400, status)
        wrong_old_page = body.decode("utf-8")
        self.assertIn("The current password is incorrect", wrong_old_page)
        self.assertIn('data-initial-panel="password"', wrong_old_page)
        self.assertIn('data-admin-panel="tokens" hidden', wrong_old_page)
        self.assertIn('data-admin-panel="password"', wrong_old_page)

        mismatch = urlencode(
            {
                "csrf": csrf,
                "old_password": "correct-horse-battery",
                "new_password": "new-password-12345",
                "confirm_password": "different-password-12345",
            }
        ).encode()
        status, body, _ = self.raw_request(
            "POST",
            "/kapsel/admin/password",
            mismatch,
            {"Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie},
        )
        self.assertEqual(400, status)
        self.assertIn("The new password entries do not match", body.decode("utf-8"))

        valid = urlencode(
            {
                "csrf": csrf,
                "old_password": "correct-horse-battery",
                "new_password": "new-password-12345",
                "confirm_password": "new-password-12345",
            }
        ).encode()
        status, _, headers = self.raw_request(
            "POST",
            "/kapsel/admin/password",
            valid,
            {"Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie},
        )
        self.assertEqual(303, status)
        self.assertEqual("/kapsel/admin?password_changed=1", headers["Location"])
        status, body, _ = self.raw_request(
            "GET",
            "/kapsel/admin?password_changed=1",
            headers={"Cookie": cookie},
        )
        self.assertEqual(200, status)
        password_success_page = body.decode("utf-8")
        self.assertIn('data-initial-panel="password"', password_success_page)
        self.assertIn("Administrator password updated", password_success_page)
        saved = self.config_path.read_text(encoding="utf-8")
        self.assertNotIn("new-password-12345", saved)
        saved_admin = json.loads(saved)["admin"]
        saved_hash = saved_admin["password_hash"]
        self.assertNotIn("password_sha256", saved_admin)
        self.assertTrue(verify_password("new-password-12345", saved_hash))
        self.assertEqual(0o600, self.config_path.stat().st_mode & 0o777)

        old_login = urlencode(
            {"username": "admin", "password": "correct-horse-battery"}
        ).encode()
        status, _, _ = self.raw_request(
            "POST",
            "/kapsel/admin/login",
            old_login,
            {"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(401, status)
        new_login = urlencode(
            {"username": "admin", "password": "new-password-12345"}
        ).encode()
        status, _, _ = self.raw_request(
            "POST",
            "/kapsel/admin/login",
            new_login,
            {"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(303, status)

    def test_admin_workspace_image_lifecycle_and_token_binding(self) -> None:
        class FakeImages:
            enabled = True

            def __init__(fake_self):
                fake_self.items: dict[str, WorkspaceImage] = {}

            def list(fake_self):
                return list(fake_self.items.values())

            def create(fake_self, name, size_bytes):
                (self.root / name).mkdir()
                image = WorkspaceImage(name, size_bytes, 4096, True)
                fake_self.items[name] = image
                return image

            def grow(fake_self, name, size_bytes):
                current = fake_self.items[name]
                image = WorkspaceImage(name, size_bytes, current.allocated_bytes, True)
                fake_self.items[name] = image
                return image

            def delete(fake_self, name):
                fake_self.items.pop(name)

        self.server.workspace_images = FakeImages()
        login = urlencode(
            {"username": "admin", "password": "correct-horse-battery"}
        ).encode()
        status, _, headers = self.raw_request(
            "POST", "/kapsel/admin/login", login,
            {"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(303, status)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        status, dashboard, _ = self.raw_request(
            "GET", "/kapsel/admin", headers={"Cookie": cookie}
        )
        self.assertEqual(200, status)
        page = dashboard.decode()
        self.assertIn('data-admin-tab="images"', page)
        self.assertIn('name="workspace_type"', page)
        self.assertIn('<option value="image">Workspace image</option>', page)
        self.assertIn('name="size_mib" value="256"', page)
        self.assertGreaterEqual(
            page.count('class="token-name-field"><label>Name</label>'),
            2,
        )
        match = re.search(r'name="csrf" value="([^"]+)"', page)
        self.assertIsNotNone(match)
        csrf = match.group(1)

        status, _, headers = self.raw_request(
            "POST", "/kapsel/admin/images",
            urlencode({"csrf": csrf, "action": "create", "name": "disk-site", "size_mib": "128"}).encode(),
            {"Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie},
        )
        self.assertEqual(303, status)
        self.assertIn("image_created=1", headers["Location"])
        status, _, headers = self.raw_request(
            "POST", "/kapsel/admin/images",
            urlencode({"csrf": csrf, "action": "grow", "name": "disk-site", "size_mib": "256"}).encode(),
            {"Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie},
        )
        self.assertEqual(303, status)
        self.assertIn("image_grown=1", headers["Location"])
        self.assertEqual(256 * 1024 * 1024, self.server.workspace_images.items["disk-site"].size_bytes)

        create_token = {
            "csrf": csrf, "action": "create", "name": "Disk site token",
            "ttl_hours": "168", "workspace_type": "image",
            "workspace_image": "disk-site", "can_read": "on", "can_write": "on",
            "shell_mode": "none", "sandbox_max_processes": "64",
            "sandbox_memory_mb": "256", "sandbox_cpu_percent": "100",
        }
        status, _, _ = self.raw_request(
            "POST", "/kapsel/admin/tokens", urlencode(create_token).encode(),
            {"Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie},
        )
        self.assertEqual(303, status)
        record = next(item for item in self.server.tokens.list() if item.name == "Disk site token")
        self.assertEqual("disk-site", record.path_prefix)
        self.assertEqual("disk-site", record.workspace_image)
        status, discovery = self.request("GET", f"/kapsel/w/{record.token}/")
        self.assertEqual(200, status)
        storage = discovery["limits"]["workspace_storage"]
        self.assertEqual("ext4_image", storage["backend"])
        self.assertEqual("disk-site", storage["image_name"])
        self.assertTrue(storage["hard_quota_enforced"])
        self.assertEqual(256 * 1024 * 1024, storage["quota_bytes"])

        delete_image = urlencode(
            {"csrf": csrf, "action": "delete", "name": "disk-site"}
        ).encode()
        status, error_page, _ = self.raw_request(
            "POST", "/kapsel/admin/images", delete_image,
            {"Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie},
        )
        self.assertEqual(400, status)
        self.assertIn("Disk site token", error_page.decode())
        self.assertIn("disk-site", self.server.workspace_images.items)

        status, _, _ = self.raw_request(
            "POST", "/kapsel/admin/tokens",
            urlencode({"csrf": csrf, "action": "delete", "token": record.token}).encode(),
            {"Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie},
        )
        self.assertEqual(303, status)
        status, _, headers = self.raw_request(
            "POST", "/kapsel/admin/images", delete_image,
            {"Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie},
        )
        self.assertEqual(303, status)
        self.assertIn("image_deleted=1", headers["Location"])

    def test_short_lived_credentials_and_preview_independence(self) -> None:
        started = datetime.now(timezone.utc)
        record = self.server.tokens.create(
            name="Short credentials",
            expires_at=None,
            path_prefix="short-credentials",
            can_read=True,
            can_write=True,
            can_preview=True,
            shell_mode="none",
        )
        initial_expiry = datetime.fromisoformat(record.credentials_expires_at)
        self.assertGreaterEqual(initial_expiry, started + timedelta(days=3))
        self.assertLess(initial_expiry, started + timedelta(days=3, seconds=5))

        expired = self.server.tokens.update(
            record.token,
            credentials_expires_at="2000-01-01T00:00:00+00:00",
        )
        self.assertIsNone(self.server.tokens.authenticate(expired.token))
        self.assertIsNone(
            self.server.tokens.authenticate_control(expired.control_token)
        )
        self.assertEqual(
            expired,
            self.server.tokens.authenticate_preview(expired.preview_token),
        )

        old_read_token = expired.token
        old_control_token = expired.control_token
        old_preview_token = expired.preview_token
        renewed_started = datetime.now(timezone.utc)
        renewed = self.server.tokens.renew_credentials(expired.token, 7)
        self.assertNotEqual(old_read_token, renewed.token)
        self.assertNotEqual(old_control_token, renewed.control_token)
        self.assertEqual(old_preview_token, renewed.preview_token)
        renewed_expiry = datetime.fromisoformat(renewed.credentials_expires_at)
        self.assertGreaterEqual(renewed_expiry, renewed_started + timedelta(days=7))
        self.assertLess(renewed_expiry, renewed_started + timedelta(days=7, seconds=5))
        self.assertIsNone(self.server.tokens.authenticate(old_read_token))
        self.assertIsNone(self.server.tokens.authenticate_control(old_control_token))
        self.assertEqual(renewed, self.server.tokens.authenticate(renewed.token))
        self.assertEqual(
            renewed,
            self.server.tokens.authenticate_control(renewed.control_token),
        )
        self.assertEqual(
            renewed,
            self.server.tokens.authenticate_preview(old_preview_token),
        )
        with self.assertRaisesRegex(ValueError, "between 1 and 30 days"):
            self.server.tokens.renew_credentials(renewed.token, 0)
        with self.assertRaisesRegex(ValueError, "between 1 and 30 days"):
            self.server.tokens.renew_credentials(renewed.token, 31)

        reloaded = TokenStore(
            self.root,
            Path(self.temp.name) / "tokens.json",
            bootstrap_token=None,
        )
        restored = reloaded.get(renewed.token)
        self.assertEqual(renewed.credentials_expires_at, restored.credentials_expires_at)
        self.assertEqual(old_preview_token, restored.preview_token)

    def test_token_registry_survives_reload(self) -> None:
        with self.assertRaisesRegex(ValueError, "direct child directory name"):
            self.server.tokens.create(
                name="Invalid root token",
                expires_at=None,
                path_prefix=".",
                can_read=True,
                can_write=False,
                shell_mode="none",
                allowed_commands=(),
            )
        persistent_extra = Path(self.temp.name) / "persistent-extra"
        persistent_extra.mkdir()
        record = self.server.tokens.create(
            name="Persistent token",
            expires_at=None,
            path_prefix="project",
            can_read=True,
            can_write=False,
            shell_mode="none",
            allowed_commands=(),
            can_preview=True,
            sandbox_backend="podman",
            sandbox_image="docker.io/library/python:3.14-slim-trixie",
            network_mode="full",
            allowed_paths=(PathGrant(path=str(persistent_extra), read_only=True),),
        )
        token_file = Path(self.temp.name) / "tokens.json"
        payload = json.loads(token_file.read_text(encoding="utf-8"))
        saved_record = next(item for item in payload["tokens"] if item["token"] == record.token)
        saved_record.update(
            {
                "web_username": "legacy-user",
                "web_password_hash": "legacy-hash",
                "web_session_ttl_seconds": 3600,
                "web_auth_version": 7,
            }
        )
        token_file.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "filesystem root"):
            self.server.tokens.update(
                record.token,
                allowed_paths=(PathGrant(path="/", read_only=True),),
            )
        with self.assertRaisesRegex(ValueError, "cannot contain Workspace Root"):
            self.server.tokens.update(
                record.token,
                allowed_paths=(PathGrant(path=self.temp.name, read_only=True),),
            )
        reloaded = TokenStore(
            self.root,
            token_file,
            bootstrap_token=None,
        )
        migrated_payload = json.loads(token_file.read_text(encoding="utf-8"))
        self.assertTrue(
            all(
                not {
                    "web_username",
                    "web_password_hash",
                    "web_session_ttl_seconds",
                    "web_auth_version",
                }.intersection(item)
                for item in migrated_payload["tokens"]
            )
        )
        restored = reloaded.authenticate(record.token)
        self.assertIsNotNone(restored)
        self.assertEqual(record, reloaded.authenticate_preview(record.preview_token))
        self.assertIsNone(reloaded.authenticate_preview(record.token))
        self.assertEqual(16, len(record.preview_token))
        self.assertRegex(record.preview_token, r"^[A-Za-z0-9_-]{16}$")
        self.assertNotEqual(record.token[:16], record.preview_token)
        self.assertEqual("Persistent token", restored.name)
        self.assertEqual("project", restored.path_prefix)
        self.assertFalse(restored.can_write)
        self.assertTrue(restored.can_preview)
        self.assertEqual("podman", restored.sandbox_backend)
        self.assertEqual(
            "docker.io/library/python:3.14-slim-trixie",
            restored.sandbox_image,
        )
        self.assertEqual("full", restored.network_mode)
        self.assertEqual(
            (PathGrant(path=str(persistent_extra.resolve()), read_only=True),),
            restored.allowed_paths,
        )

        with patch(
            "openkapsel.tokens.secrets.token_urlsafe",
            side_effect=[
                "read-token-safe-generated",
                "PreviewToken0001",
                "control-token-safe-generated",
            ],
        ) as generator:
            unique = reloaded.create(
                name="Independent preview token",
                expires_at=None,
                path_prefix="unique-preview",
                can_read=True,
                can_write=False,
                shell_mode="none",
            )
        self.assertEqual("PreviewToken0001", unique.preview_token)
        self.assertEqual("control-token-safe-generated", unique.control_token)
        self.assertEqual(3, generator.call_count)
        self.assertEqual(unique, reloaded.authenticate_preview("PreviewToken0001"))
        self.assertEqual(unique, reloaded.authenticate_control(unique.control_token))

        old_preview_token = unique.preview_token
        with patch(
            "openkapsel.tokens.secrets.token_urlsafe",
            side_effect=[old_preview_token, "PreviewToken0002"],
        ) as generator:
            rotated = reloaded.rotate_preview_token(unique.token)
        self.assertEqual(2, generator.call_count)
        self.assertEqual("PreviewToken0002", rotated.preview_token)
        self.assertIsNone(reloaded.authenticate_preview(old_preview_token))
        self.assertEqual(rotated, reloaded.authenticate_preview(rotated.preview_token))
        self.assertEqual(unique.token, rotated.token)

        old_control_token = rotated.control_token
        with patch(
            "openkapsel.tokens.secrets.token_urlsafe",
            side_effect=[rotated.preview_token, "new-full-token-safe-generated"],
        ) as generator:
            main_rotated = reloaded.rotate_control_token(rotated.token)
        self.assertEqual(2, generator.call_count)
        self.assertEqual("new-full-token-safe-generated", main_rotated.control_token)
        self.assertEqual(rotated.token, main_rotated.token)
        self.assertEqual(rotated.preview_token, main_rotated.preview_token)
        self.assertIsNone(reloaded.authenticate_control(old_control_token))
        self.assertEqual(main_rotated, reloaded.authenticate_control(main_rotated.control_token))
        self.assertEqual(main_rotated, reloaded.authenticate(main_rotated.token))
        self.assertEqual(main_rotated, reloaded.authenticate_preview(main_rotated.preview_token))
        rotated_values = rotated.to_dict()
        main_rotated_values = main_rotated.to_dict()
        rotated_values.pop("control_token")
        main_rotated_values.pop("control_token")
        self.assertEqual(rotated_values, main_rotated_values)

        old_read_token = main_rotated.token
        with patch(
            "openkapsel.tokens.secrets.token_urlsafe",
            side_effect=[main_rotated.control_token, "new-read-token-safe-generated"],
        ) as generator:
            read_rotated = reloaded.rotate_read_token(old_read_token)
        self.assertEqual(2, generator.call_count)
        self.assertEqual("new-read-token-safe-generated", read_rotated.token)
        self.assertEqual(main_rotated.control_token, read_rotated.control_token)
        self.assertIsNone(reloaded.authenticate(old_read_token))
        self.assertEqual(read_rotated, reloaded.authenticate(read_rotated.token))
        rotated_reloaded = TokenStore(
            self.root,
            Path(self.temp.name) / "tokens.json",
            bootstrap_token=None,
        )
        self.assertIsNone(rotated_reloaded.authenticate(old_read_token))
        self.assertIsNone(rotated_reloaded.authenticate_control(old_control_token))
        self.assertEqual(read_rotated, rotated_reloaded.authenticate(read_rotated.token))
        self.assertEqual(
            read_rotated,
            rotated_reloaded.authenticate_control(read_rotated.control_token),
        )

        legacy_file = Path(self.temp.name) / "legacy-tokens.json"
        legacy_payload = json.loads(
            (Path(self.temp.name) / "tokens.json").read_text(encoding="utf-8")
        )
        for item in legacy_payload["tokens"]:
            item.pop("preview_token", None)
            item.pop("control_token", None)
            item.pop("credentials_expires_at", None)
            item.pop("sandbox_image", None)
        migration_started = datetime.now(timezone.utc)
        legacy_file.write_text(json.dumps(legacy_payload), encoding="utf-8")
        migrated = TokenStore(self.root, legacy_file, bootstrap_token=None)
        migrated_records = migrated.list()
        self.assertTrue(migrated_records)
        self.assertTrue(all(len(item.preview_token) == 16 for item in migrated_records))
        self.assertTrue(all(item.control_token for item in migrated_records))
        saved_legacy = json.loads(legacy_file.read_text(encoding="utf-8"))
        self.assertTrue(
            all(len(item["preview_token"]) == 16 for item in saved_legacy["tokens"])
        )
        self.assertTrue(all(item["control_token"] for item in saved_legacy["tokens"]))
        self.assertTrue(
            all(item["credentials_expires_at"] for item in saved_legacy["tokens"])
        )
        self.assertTrue(all("sandbox_image" in item for item in saved_legacy["tokens"]))
        for item in migrated_records:
            migrated_expiry = datetime.fromisoformat(item.credentials_expires_at)
            self.assertGreaterEqual(
                migrated_expiry, migration_started + timedelta(days=3)
            )
            self.assertLess(
                migrated_expiry, migration_started + timedelta(days=3, seconds=5)
            )

    def test_project_memory_rest_mcp_relevance_revisions_and_debrief(self) -> None:
        record = self.server.tokens.create(
            name="Memory workspace",
            expires_at=None,
            path_prefix="memory-workspace",
            can_read=True,
            can_write=True,
            shell_mode="none",
        )
        endpoint = lambda suffix: f"/kapsel/w/{record.token}{suffix}"
        status, source_plan = self.request(
            "POST",
            endpoint("/context"),
            {
                "type": "plan",
                "taskname": "auth-memory",
                "content": "Investigate login failures.",
                "scope_paths": ["frontend/auth"],
                "memory_tags": ["auth"],
            },
        )
        self.assertEqual(201, status)
        self.assertEqual([], source_plan["related_memory"])

        status, memory = self.request(
            "POST",
            endpoint("/memory"),
            {
                "category": "known_issue",
                "key": "auth/form-reset",
                "title": "Login form reset race",
                "content": "Wait for the async request before resetting the form.",
                "severity": "high",
                "tags": ["auth", "frontend"],
                "paths": ["frontend/auth"],
                "plan_id": source_plan["id"],
                "taskname": "auth-memory",
                "message": "Record the reusable login failure",
            },
        )
        self.assertEqual(201, status)
        self.assertEqual(1, memory["revision"])
        self.assertIn("memory_id", memory)
        self.assertNotIn("id", memory)
        self.assertTrue(
            (
                self.root
                / "memory-workspace"
                / ".openkapsel"
                / "context"
                / "memory.sqlite3"
            ).is_file()
        )

        status, tagged = self.request("GET", endpoint("/memory?tag=auth"))
        self.assertEqual(200, status)
        self.assertEqual(1, tagged["total"])
        self.assertEqual(memory["memory_id"], tagged["memories"][0]["memory_id"])
        self.assertNotIn("id", tagged["memories"][0])
        status, next_plan = self.request(
            "POST",
            endpoint("/context"),
            {
                "type": "plan",
                "taskname": "auth-followup",
                "content": "Change the login page.",
                "scope_paths": ["frontend/auth/login.js"],
                "memory_tags": ["auth"],
            },
        )
        self.assertEqual(201, status)
        related = next_plan["related_memory"]
        self.assertEqual(memory["memory_id"], related[0]["memory_id"])
        self.assertEqual(["auth"], related[0]["matched_tags"])

        status, raw_memory, memory_headers = self.raw_request(
            "GET",
            endpoint(f"/memory/{memory['memory_id']}"),
        )
        self.assertEqual(200, status)
        self.assertEqual(
            memory["memory_id"], json.loads(raw_memory)["memory_id"]
        )
        current_etag = memory_headers["ETag"]
        revised_body = json.dumps(
            {
                "content": "The verified fix waits for the async request before reset.",
                "plan_id": next_plan["id"],
                "taskname": "auth-followup",
                "message": "Update the verified login fix",
            }
        ).encode("utf-8")
        status, raw_revised, _ = self.raw_request(
            "PATCH",
            endpoint(f"/memory/{memory['memory_id']}"),
            revised_body,
            {
                "Content-Type": "application/json",
                "If-Match": current_etag,
            },
        )
        self.assertEqual(200, status)
        revised = json.loads(raw_revised)
        self.assertEqual(2, revised["revision"])
        status, history = self.request(
            "GET",
            endpoint(f"/memory/{memory['memory_id']}/revisions"),
        )
        self.assertEqual(200, status)
        self.assertEqual([2, 1], [item["revision"] for item in history["revisions"]])

        status, completed = self.request(
            "PATCH",
            endpoint(f"/context/plans/{next_plan['id']}"),
            {
                "taskname": "auth-followup",
                "status": "completed",
                "debrief": {
                    "summary": "Verified the login lifecycle fix.",
                    "outcome": "succeeded",
                    "memory_actions": [
                        {
                            "action": "resolve",
                            "memory_id": memory["memory_id"],
                            "expected_revision": 2,
                            "content": "Always await login completion before resetting the form.",
                        }
                    ],
                },
            },
        )
        self.assertEqual(200, status)
        self.assertEqual("completed", completed["status"])
        self.assertEqual(
            memory["memory_id"],
            completed["debrief"]["memory_refs"][0]["memory_id"],
        )

        status, mcp_payload, _ = self.mcp_request(
            record.token,
            990,
            "tools/call",
            {"name": "query_memory", "arguments": {"tag": "auth"}},
        )
        self.assertEqual(200, status)
        self.assertFalse(mcp_payload["result"]["isError"])
        self.assertEqual(1, mcp_payload["result"]["structuredContent"]["total"])
        self.assertEqual(
            memory["memory_id"],
            mcp_payload["result"]["structuredContent"]["memories"][0]["memory_id"],
        )

        status, raw, _ = self.raw_request(
            "GET",
            endpoint("/memory/project"),
            authorize=False,
        )
        self.assertEqual(401, status)
        self.assertEqual("control_token_required", json.loads(raw)["error"]["code"])

    def test_shared_workspace_survives_token_deletion_and_valid_tokens_sort_first(self) -> None:
        first = self.server.tokens.create(
            name="Disabled shared token",
            expires_at=None,
            path_prefix="shared-project",
            can_read=True,
            can_write=True,
            shell_mode="none",
        )
        second = self.server.tokens.create(
            name="Active shared token",
            expires_at=None,
            path_prefix="shared-project",
            can_read=True,
            can_write=False,
            shell_mode="none",
        )
        marker = self.root / "shared-project" / "keep.txt"
        marker.write_text("keep", encoding="utf-8")
        first = self.server.tokens.update(first.token, enabled=False)

        records = self.server.tokens.list()
        self.assertLess(records.index(second), records.index(first))

        self.server.tokens.delete(first.token)
        self.assertTrue(marker.is_file())
        self.assertEqual(
            (self.root / "shared-project").resolve(),
            self.server.tokens.scope_root(second),
        )

    def wait_for_task(self, task_id: str, timeout: float = 5, token: str = "test-token") -> dict:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status, payload = self.request("GET", f"/kapsel/w/{token}/tasks/{task_id}")
            self.assertEqual(200, status)
            if payload["status"] == "finished":
                return payload
            time.sleep(0.02)
        self.fail(f"task {task_id} did not finish")




if __name__ == "__main__":
    unittest.main()

"""Declarative HTTP endpoint contracts used by dispatch and context tracking."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal, Pattern


Invocation = Literal["none", "query", "query_head", "param", "param_query", "param_head"]
ContextMode = Literal["none", "deferred", "header", "optional_query"]


@dataclass(frozen=True)
class EndpointSpec:
    name: str
    methods: frozenset[str]
    pattern: Pattern[str]
    handler: str
    invocation: Invocation = "none"
    parameter: str | None = None
    control_required: bool = False
    request_body: bool = False
    transfer_slot: bool = False
    context_mode: ContextMode = "none"
    context_operations: tuple[tuple[str, str], ...] = ()
    discovery_key: str | None = None

    def match(self, method: str, route: str) -> re.Match[str] | None:
        if method not in self.methods:
            return None
        return self.pattern.fullmatch(route)

    def context_operation(self, method: str) -> str | None:
        operations = dict(self.context_operations)
        return operations.get(method) or operations.get("*")


def _exact(
    name: str,
    methods: tuple[str, ...],
    route: str,
    handler: str,
    **kwargs: object,
) -> EndpointSpec:
    return EndpointSpec(
        name=name,
        methods=frozenset(methods),
        pattern=re.compile(re.escape(route)),
        handler=handler,
        **kwargs,
    )


ENDPOINTS: tuple[EndpointSpec, ...] = (
    _exact(
        "credentials_renew", ("POST",), "/credentials/renew", "_handle_credentials_renew",
        control_required=True, discovery_key="credentials_renew",
    ),
    _exact(
        "environment_get", ("GET",), "/env", "_handle_environment_get",
        control_required=True, discovery_key="environment_get",
    ),
    _exact(
        "environment_replace", ("PUT",), "/env", "_handle_environment_replace",
        control_required=True, request_body=True, context_mode="deferred",
        context_operations=(("PUT", "environment.replace"),),
        discovery_key="environment_replace",
    ),
    _exact(
        "environment_clear", ("DELETE",), "/env", "_handle_environment_clear",
        control_required=True, request_body=True, context_mode="deferred",
        context_operations=(("DELETE", "environment.clear"),),
        discovery_key="environment_clear",
    ),
    EndpointSpec(
        "discovery_section", frozenset(("GET",)),
        re.compile(r"/discovery/(?P<section>[A-Za-z0-9_-]+)"),
        "_handle_discovery_section", invocation="param", parameter="section",
        discovery_key="discovery_section",
    ),
    _exact(
        "share_create", ("POST",), "/shares", "_handle_share_create",
        control_required=True, request_body=True, transfer_slot=True,
        context_mode="deferred", context_operations=(("POST", "share.create"),),
        discovery_key="share_create",
    ),
    EndpointSpec(
        "share_import", frozenset(("POST",)),
        re.compile(r"/shares/(?P<share_id>[A-Za-z0-9_-]+)/import"),
        "_handle_share_import", invocation="param", parameter="share_id",
        control_required=True, request_body=True, transfer_slot=True,
        context_mode="deferred", context_operations=(("POST", "share.import"),),
        discovery_key="share_import",
    ),
    EndpointSpec(
        "share_delete", frozenset(("DELETE",)),
        re.compile(r"/shares/(?P<share_id>[A-Za-z0-9_-]+)"),
        "_handle_share_delete", invocation="param", parameter="share_id",
        control_required=True, context_mode="header",
        context_operations=(("DELETE", "share.delete"),),
        discovery_key="share_delete",
    ),
    _exact(
        "fs_list", ("GET",), "/fs/list", "_handle_fs_list",
        invocation="query", context_mode="optional_query",
        context_operations=(("GET", "fs.list"),), discovery_key="fs_list",
    ),
    _exact(
        "fs_read", ("GET",), "/fs/read", "_handle_fs_read",
        invocation="query", context_mode="optional_query",
        context_operations=(("GET", "fs.read"),), discovery_key="fs_read",
    ),
    _exact(
        "fs_stat", ("GET",), "/fs/stat", "_handle_fs_stat",
        invocation="query", transfer_slot=True, context_mode="optional_query",
        context_operations=(("GET", "fs.stat"),), discovery_key="fs_stat",
    ),
    _exact(
        "fs_manifest", ("POST",), "/fs/manifest", "_handle_fs_manifest",
        request_body=True, transfer_slot=True, discovery_key="fs_manifest",
    ),
    _exact(
        "fs_search", ("GET",), "/fs/search", "_handle_fs_search",
        invocation="query", transfer_slot=True, context_mode="optional_query",
        context_operations=(("GET", "fs.search"),), discovery_key="fs_search",
    ),
    _exact(
        "fs_tree", ("GET",), "/fs/tree", "_handle_fs_tree",
        invocation="query", context_mode="optional_query",
        context_operations=(("GET", "fs.tree"),), discovery_key="fs_tree",
    ),
    _exact(
        "fs_content", ("GET", "HEAD"), "/fs/content", "_handle_fs_content",
        invocation="query_head", transfer_slot=True, context_mode="optional_query",
        context_operations=(("GET", "fs.content.get"), ("HEAD", "fs.content.head")),
        discovery_key="fs_content",
    ),
    _exact(
        "fs_content_put", ("PUT",), "/fs/content", "_handle_fs_content_put",
        invocation="query", control_required=True, request_body=True, transfer_slot=True,
        context_mode="header", context_operations=(("PUT", "fs.content.put"),),
        discovery_key="fs_content_put",
    ),
    _exact(
        "fs_write", ("POST",), "/fs/write", "_handle_fs_write",
        control_required=True, request_body=True, context_mode="deferred",
        context_operations=(("POST", "fs.write"),), discovery_key="fs_write",
    ),
    _exact(
        "fs_replace", ("POST",), "/fs/replace", "_handle_fs_replace",
        control_required=True, request_body=True, context_mode="deferred",
        context_operations=(("POST", "fs.replace"),), discovery_key="fs_replace",
    ),
    _exact(
        "fs_replace_batch", ("POST",), "/fs/replace/batch", "_handle_fs_replace_batch",
        control_required=True, request_body=True, context_mode="deferred",
        context_operations=(("POST", "fs.replace.batch"),),
        discovery_key="fs_replace_batch",
    ),
    _exact(
        "fs_mkdir", ("POST",), "/fs/mkdir", "_handle_fs_mkdir",
        control_required=True, request_body=True, context_mode="deferred",
        context_operations=(("POST", "fs.mkdir"),), discovery_key="fs_mkdir",
    ),
    _exact(
        "fs_delete", ("POST",), "/fs/delete", "_handle_fs_delete",
        control_required=True, request_body=True, context_mode="deferred",
        context_operations=(("POST", "fs.delete"),), discovery_key="fs_delete",
    ),
    _exact(
        "fs_delete_batch", ("POST",), "/fs/delete/batch", "_handle_fs_delete_batch",
        control_required=True, request_body=True, context_mode="deferred",
        context_operations=(("POST", "fs.delete.batch"),),
        discovery_key="fs_delete_batch",
    ),
    _exact(
        "fs_move", ("POST",), "/fs/move", "_handle_fs_move",
        control_required=True, request_body=True, context_mode="deferred",
        context_operations=(("POST", "fs.move"),), discovery_key="fs_move",
    ),
    _exact(
        "recycle_list", ("GET",), "/recycle/list", "_handle_recycle_list",
        invocation="query", context_mode="optional_query",
        context_operations=(("GET", "recycle.list"),), discovery_key="recycle_list",
    ),
    _exact(
        "recycle_restore", ("POST",), "/recycle/restore", "_handle_recycle_restore",
        control_required=True, request_body=True, context_mode="deferred",
        context_operations=(("POST", "recycle.restore"),), discovery_key="recycle_restore",
    ),
    _exact(
        "upload_create", ("POST",), "/uploads", "_handle_upload_create",
        control_required=True, request_body=True, context_mode="deferred",
        context_operations=(("POST", "upload.create"),), discovery_key="upload_create",
    ),
    EndpointSpec(
        "upload_status", frozenset(("GET", "HEAD")),
        re.compile(r"/uploads/(?P<upload_id>[^/]+)"), "_handle_upload_status",
        invocation="param_head", parameter="upload_id", control_required=True,
        context_mode="optional_query",
        context_operations=(("GET", "upload.status"), ("HEAD", "upload.status")),
        discovery_key="upload_status",
    ),
    EndpointSpec(
        "upload_chunk", frozenset(("PATCH",)),
        re.compile(r"/uploads/(?P<upload_id>[^/]+)"), "_handle_upload_append",
        invocation="param", parameter="upload_id", control_required=True,
        request_body=True, transfer_slot=True, context_mode="header",
        context_operations=(("PATCH", "upload.chunk"),), discovery_key="upload_chunk",
    ),
    EndpointSpec(
        "upload_cancel", frozenset(("DELETE",)),
        re.compile(r"/uploads/(?P<upload_id>[^/]+)"), "_handle_upload_cancel",
        invocation="param", parameter="upload_id", control_required=True,
        context_mode="header", context_operations=(("DELETE", "upload.cancel"),),
        discovery_key="upload_cancel",
    ),
    EndpointSpec(
        "upload_commit", frozenset(("POST",)),
        re.compile(r"/uploads/(?P<upload_id>[^/]+)/commit"), "_handle_upload_commit",
        invocation="param", parameter="upload_id", control_required=True,
        transfer_slot=True, context_mode="header",
        context_operations=(("POST", "upload.commit"),), discovery_key="upload_commit",
    ),
    EndpointSpec(
        "mcp_post", frozenset(("POST",)), re.compile(r"/mcp/?"),
        "_handle_mcp_post", control_required=True, request_body=True, discovery_key="mcp",
    ),
    EndpointSpec(
        "mcp_method_not_allowed", frozenset(("GET", "DELETE")), re.compile(r"/mcp/?"),
        "_handle_mcp_method_not_allowed", control_required=True, discovery_key="mcp",
    ),
    _exact(
        "shell_exec", ("POST",), "/shell/exec", "_handle_shell_exec",
        control_required=True, request_body=True, context_mode="deferred",
        context_operations=(("POST", "shell.exec"),), discovery_key="shell_exec",
    ),
    _exact(
        "schedule_list", ("GET",), "/schedules", "_handle_schedule_list",
        invocation="query", control_required=True, discovery_key="schedule_list",
    ),
    _exact(
        "schedule_create", ("POST",), "/schedules", "_handle_schedule_create",
        control_required=True, request_body=True, context_mode="deferred",
        context_operations=(("POST", "schedule.create"),), discovery_key="schedule_create",
    ),
    EndpointSpec(
        "schedule_runs", frozenset(("GET",)),
        re.compile(r"/schedules/(?P<schedule_id>[^/]+)/runs"), "_handle_schedule_runs",
        invocation="param_query", parameter="schedule_id", control_required=True,
        discovery_key="schedule_runs",
    ),
    EndpointSpec(
        "schedule_run", frozenset(("POST",)),
        re.compile(r"/schedules/(?P<schedule_id>[^/]+)/run"), "_handle_schedule_run",
        invocation="param", parameter="schedule_id", control_required=True,
        request_body=True, context_mode="deferred",
        context_operations=(("POST", "schedule.run_now"),), discovery_key="schedule_run",
    ),
    EndpointSpec(
        "schedule_pause", frozenset(("POST",)),
        re.compile(r"/schedules/(?P<schedule_id>[^/]+)/pause"), "_handle_schedule_pause",
        invocation="param", parameter="schedule_id", control_required=True,
        request_body=True, context_mode="deferred",
        context_operations=(("POST", "schedule.pause"),), discovery_key="schedule_pause",
    ),
    EndpointSpec(
        "schedule_resume", frozenset(("POST",)),
        re.compile(r"/schedules/(?P<schedule_id>[^/]+)/resume"), "_handle_schedule_resume",
        invocation="param", parameter="schedule_id", control_required=True,
        request_body=True, context_mode="deferred",
        context_operations=(("POST", "schedule.resume"),), discovery_key="schedule_resume",
    ),
    EndpointSpec(
        "schedule_get", frozenset(("GET",)),
        re.compile(r"/schedules/(?P<schedule_id>[^/]+)"), "_handle_schedule_get",
        invocation="param", parameter="schedule_id", control_required=True,
        discovery_key="schedule_get",
    ),
    EndpointSpec(
        "schedule_update", frozenset(("PATCH",)),
        re.compile(r"/schedules/(?P<schedule_id>[^/]+)"), "_handle_schedule_update",
        invocation="param", parameter="schedule_id", control_required=True,
        request_body=True, context_mode="deferred",
        context_operations=(("PATCH", "schedule.update"),), discovery_key="schedule_update",
    ),
    EndpointSpec(
        "schedule_delete", frozenset(("DELETE",)),
        re.compile(r"/schedules/(?P<schedule_id>[^/]+)"), "_handle_schedule_delete",
        invocation="param", parameter="schedule_id", control_required=True,
        request_body=True, context_mode="deferred",
        context_operations=(("DELETE", "schedule.delete"),), discovery_key="schedule_delete",
    ),
    EndpointSpec(
        "schedule_run_item", frozenset(("GET",)),
        re.compile(r"/schedule-runs/(?P<run_id>[^/]+)"), "_handle_schedule_run_get",
        invocation="param", parameter="run_id", control_required=True,
        discovery_key="schedule_run_item",
    ),
    _exact(
        "task_list", ("GET",), "/tasks", "_handle_task_list",
        invocation="query", control_required=True, context_mode="optional_query",
        context_operations=(("GET", "task.list"),), discovery_key="task_list",
    ),
    _exact(
        "sandbox_processes", ("GET",), "/sandbox/processes", "_handle_sandbox_processes",
        invocation="query", control_required=True, context_mode="optional_query",
        context_operations=(("GET", "sandbox.processes"),), discovery_key="sandbox_processes",
    ),
    _exact(
        "context_query", ("GET",), "/context", "_handle_context_query",
        invocation="query", control_required=True, discovery_key="context_query",
    ),
    _exact(
        "context_add", ("POST",), "/context", "_handle_context_add",
        control_required=True, request_body=True, discovery_key="context_add",
    ),
    EndpointSpec(
        "context_plan_tree", frozenset(("GET",)),
        re.compile(r"/context/plans/(?P<context_id>[^/]+)/tree"),
        "_handle_context_plan_tree", invocation="param_query", parameter="context_id",
        control_required=True, discovery_key="context_plan_tree",
    ),
    EndpointSpec(
        "context_plan_update", frozenset(("PATCH",)),
        re.compile(r"/context/plans/(?P<context_id>[^/]+)"),
        "_handle_context_plan_update", invocation="param", parameter="context_id",
        control_required=True, request_body=True, discovery_key="context_plan_update",
    ),
    EndpointSpec(
        "context_note_replace", frozenset(("PATCH",)),
        re.compile(r"/context/notes/(?P<context_id>[^/]+)"),
        "_handle_context_note_replace", invocation="param", parameter="context_id",
        control_required=True, request_body=True, discovery_key="context_note_replace",
    ),
    _exact(
        "memory_query", ("GET",), "/memory", "_handle_memory_query",
        invocation="query", control_required=True, discovery_key="memory_query",
    ),
    _exact(
        "memory_add", ("POST",), "/memory", "_handle_memory_add",
        control_required=True, request_body=True, discovery_key="memory_add",
    ),
    _exact(
        "memory_project", ("GET",), "/memory/project", "_handle_memory_project",
        control_required=True, discovery_key="memory_project",
    ),
    EndpointSpec(
        "memory_revisions", frozenset(("GET",)),
        re.compile(r"/memory/(?P<memory_id>[^/]+)/revisions"),
        "_handle_memory_revisions", invocation="param_query", parameter="memory_id",
        control_required=True, discovery_key="memory_revisions",
    ),
    EndpointSpec(
        "memory_item", frozenset(("GET",)),
        re.compile(r"/memory/(?P<memory_id>[^/]+)"),
        "_handle_memory_item", invocation="param", parameter="memory_id",
        control_required=True, discovery_key="memory_item",
    ),
    EndpointSpec(
        "memory_item_mutate", frozenset(("PATCH", "DELETE")),
        re.compile(r"/memory/(?P<memory_id>[^/]+)"),
        "_handle_memory_item", invocation="param", parameter="memory_id",
        control_required=True, request_body=True, discovery_key="memory_item",
    ),
    EndpointSpec(
        "task_output", frozenset(("GET",)),
        re.compile(r"/tasks/(?P<task_id>[^/]+)/output"), "_handle_task_output",
        invocation="param_query", parameter="task_id", control_required=True,
        context_mode="optional_query", context_operations=(("GET", "task.output"),),
        discovery_key="task_output",
    ),
    EndpointSpec(
        "task_stream", frozenset(("GET",)),
        re.compile(r"/tasks/(?P<task_id>[^/]+)/stream"), "_handle_task_stream",
        invocation="param_query", parameter="task_id", control_required=True,
        context_mode="optional_query", context_operations=(("GET", "task.stream"),),
        discovery_key="task_stream",
    ),
    EndpointSpec(
        "task_stdin", frozenset(("POST",)),
        re.compile(r"/tasks/(?P<task_id>[^/]+)/stdin"), "_handle_task_stdin",
        invocation="param", parameter="task_id", control_required=True, request_body=True,
        context_mode="deferred", context_operations=(("POST", "task.stdin"),),
        discovery_key="task_stdin",
    ),
    EndpointSpec(
        "task_interrupt", frozenset(("POST",)),
        re.compile(r"/tasks/(?P<task_id>[^/]+)/interrupt"), "_handle_task_interrupt",
        invocation="param", parameter="task_id", control_required=True,
        context_mode="header", context_operations=(("POST", "task.interrupt"),),
        discovery_key="task_interrupt",
    ),
    EndpointSpec(
        "task_kill", frozenset(("POST",)),
        re.compile(r"/tasks/(?P<task_id>[^/]+)/kill"), "_handle_task_kill",
        invocation="param", parameter="task_id", control_required=True,
        context_mode="header", context_operations=(("POST", "task.kill"),),
        discovery_key="task_kill",
    ),
    EndpointSpec(
        "task_status", frozenset(("GET",)),
        re.compile(r"/tasks/(?P<task_id>[^/]+)"), "_handle_task",
        invocation="param", parameter="task_id", control_required=True,
        context_mode="optional_query", context_operations=(("GET", "task.get"),),
        discovery_key="task_status",
    ),
)


def match_endpoint(method: str, route: str) -> tuple[EndpointSpec, re.Match[str]] | None:
    for endpoint in ENDPOINTS:
        matched = endpoint.match(method, route)
        if matched is not None:
            return endpoint, matched
    return None


def discovery_keys() -> frozenset[str]:
    return frozenset(
        endpoint.discovery_key
        for endpoint in ENDPOINTS
        if endpoint.discovery_key is not None
    )

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
    _exact("recycle_purge", ("POST",), "/recycle/purge", "_handle_recycle_purge", control_required=True,
        request_body=True, context_mode="deferred", context_operations=(("POST", "recycle.purge"),), discovery_key="recycle"),
    _exact("fs_copy", ("POST",), "/fs/write/copy", "_handle_file_copy", control_required=True,
        request_body=True, context_mode="deferred", context_operations=(("POST", "fs.copy"),), discovery_key="fs_write"),
    EndpointSpec("file_transfer", frozenset(("GET", "POST")),
        re.compile(r"/fs/transfers/(?P<target>[A-Za-z0-9_-]{24}(?:/(?:cancel|resume))?)"),
        "_handle_file_transfer", invocation="param", parameter="target", control_required=True,
        request_body=True, context_mode="deferred", context_operations=(("POST", "fs.transfer.control"), ("GET", "fs.transfer.get")), discovery_key="transfers"),
    EndpointSpec("server_rpc", frozenset(("POST",)),
        re.compile(r"/rpc/(?P<target>[a-z][a-z0-9_]{0,31}/[a-z][a-z0-9_]{0,31})"),
        "_handle_server_rpc", invocation="param", parameter="target",
        request_body=True, transfer_slot=True, discovery_key="rpc"),
    _exact("mapping_list", ("GET",), "/mappings", "_handle_mapping_list", discovery_key="mappings"),
    EndpointSpec("mapping_rpc", frozenset(("POST",)),
        re.compile(r"/mappings/(?P<target>[A-Za-z0-9][A-Za-z0-9_-]{0,63}/rpc/[a-z][a-z0-9_]{0,31}/[a-z][a-z0-9_]{0,31})"),
        "_handle_mapping_rpc", invocation="param", parameter="target",
        request_body=True, transfer_slot=True, discovery_key="rpc"),
    _exact(
        "credentials_renew", ("POST",), "/credentials/renew", "_handle_credentials_renew",
        control_required=True, discovery_key="credentials",
    ),
    _exact(
        "environment_get", ("GET",), "/env", "_handle_environment_get",
        control_required=True, discovery_key="environment",
    ),
    _exact(
        "environment_replace", ("PUT",), "/env", "_handle_environment_replace",
        control_required=True, request_body=True, context_mode="deferred",
        context_operations=(("PUT", "environment.replace"),),
        discovery_key="environment",
    ),
    _exact(
        "environment_clear", ("DELETE",), "/env", "_handle_environment_clear",
        control_required=True, request_body=True, context_mode="deferred",
        context_operations=(("DELETE", "environment.clear"),),
        discovery_key="environment",
    ),
    EndpointSpec(
        "discovery_section", frozenset(("GET",)),
        re.compile(r"/discovery/(?P<section>[A-Za-z0-9_-]+)"),
        "_handle_discovery_section", invocation="param", parameter="section",
        discovery_key="discovery",
    ),
    _exact(
        "share_create", ("POST",), "/shares", "_handle_share_create",
        control_required=True, request_body=True, transfer_slot=True,
        context_mode="deferred", context_operations=(("POST", "share.create"),),
        discovery_key="sharing",
    ),
    EndpointSpec(
        "share_import", frozenset(("POST",)),
        re.compile(r"/shares/(?P<share_id>[A-Za-z0-9_-]+)/import"),
        "_handle_share_import", invocation="param", parameter="share_id",
        control_required=True, request_body=True, transfer_slot=True,
        context_mode="deferred", context_operations=(("POST", "share.import"),),
        discovery_key="sharing",
    ),
    EndpointSpec(
        "share_delete", frozenset(("DELETE",)),
        re.compile(r"/shares/(?P<share_id>[A-Za-z0-9_-]+)"),
        "_handle_share_delete", invocation="param", parameter="share_id",
        control_required=True, context_mode="header",
        context_operations=(("DELETE", "share.delete"),),
        discovery_key="sharing",
    ),
    _exact(
        "fs_list", ("GET",), "/fs/query/list", "_handle_fs_list",
        invocation="query", context_mode="optional_query",
        context_operations=(("GET", "fs.list"),), discovery_key="fs_query",
    ),
    _exact(
        "fs_read", ("GET",), "/fs/read/text", "_handle_fs_read",
        invocation="query", context_mode="optional_query",
        context_operations=(("GET", "fs.read"),), discovery_key="fs_read",
    ),
    _exact(
        "fs_stat", ("GET",), "/fs/query/stat", "_handle_fs_stat",
        invocation="query", transfer_slot=True, context_mode="optional_query",
        context_operations=(("GET", "fs.stat"),), discovery_key="fs_query",
    ),
    _exact(
        "fs_manifest", ("POST",), "/fs/query/manifest", "_handle_fs_manifest",
        request_body=True, transfer_slot=True, discovery_key="fs_query",
    ),
    _exact(
        "fs_read_many", ("POST",), "/fs/read/many", "_handle_fs_read_many",
        request_body=True, transfer_slot=True, discovery_key="fs_read",
    ),
    _exact(
        "fs_find", ("GET",), "/fs/query/find", "_handle_fs_find",
        invocation="query", transfer_slot=True, context_mode="optional_query",
        context_operations=(("GET", "fs.find"),), discovery_key="fs_query",
    ),
    _exact(
        "fs_grep", ("GET",), "/fs/query/grep", "_handle_fs_grep",
        invocation="query", transfer_slot=True, context_mode="optional_query",
        context_operations=(("GET", "fs.grep"),), discovery_key="fs_query",
    ),
    _exact(
        "fs_search", ("GET",), "/fs/query/search", "_handle_fs_grep",
        invocation="query", transfer_slot=True, context_mode="optional_query",
        context_operations=(("GET", "fs.grep"),), discovery_key="fs_query",
    ),
    _exact(
        "fs_tree", ("GET",), "/fs/query/tree", "_handle_fs_tree",
        invocation="query", context_mode="optional_query",
        context_operations=(("GET", "fs.tree"),), discovery_key="fs_query",
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
        discovery_key="fs_content",
    ),
    _exact(
        "fs_mutate", ("POST",), "/fs/write/mutate", "_handle_fs_mutate",
        control_required=True, request_body=True, context_mode="deferred",
        context_operations=(("POST", "fs.mutate"),), discovery_key="fs_write",
    ),
    _exact(
        "fs_read_large", ("POST",), "/fs/read/large", "_handle_fs_read_large",
        request_body=True, transfer_slot=True, discovery_key="fs_read",
    ),
    _exact(
        "fs_replace_large", ("POST",), "/fs/write/large", "_handle_fs_replace_large",
        control_required=True, request_body=True, context_mode="deferred",
        context_operations=(("POST", "fs.large.replace"),), discovery_key="fs_write",
    ),
    _exact(
        "fs_mkdir", ("POST",), "/fs/write/mkdir", "_handle_fs_mkdir",
        control_required=True, request_body=True, context_mode="deferred",
        context_operations=(("POST", "fs.mkdir"),), discovery_key="fs_write",
    ),
    _exact(
        "fs_move", ("POST",), "/fs/write/move", "_handle_fs_move",
        control_required=True, request_body=True, context_mode="deferred",
        context_operations=(("POST", "fs.move"),), discovery_key="fs_write",
    ),
    _exact(
        "recycle_list", ("GET",), "/recycle/list", "_handle_recycle_list",
        invocation="query", context_mode="optional_query",
        context_operations=(("GET", "recycle.list"),), discovery_key="recycle",
    ),
    _exact(
        "recycle_restore", ("POST",), "/recycle/restore", "_handle_recycle_restore",
        control_required=True, request_body=True, context_mode="deferred",
        context_operations=(("POST", "recycle.restore"),), discovery_key="recycle",
    ),
    _exact(
        "upload_create", ("POST",), "/uploads", "_handle_upload_create",
        control_required=True, request_body=True, context_mode="deferred",
        context_operations=(("POST", "upload.create"),), discovery_key="uploads",
    ),
    EndpointSpec(
        "upload_status", frozenset(("GET", "HEAD")),
        re.compile(r"/uploads/(?P<upload_id>[^/]+)"), "_handle_upload_status",
        invocation="param_head", parameter="upload_id", control_required=True,
        context_mode="optional_query",
        context_operations=(("GET", "upload.status"), ("HEAD", "upload.status")),
        discovery_key="uploads",
    ),
    EndpointSpec(
        "upload_chunk", frozenset(("PATCH",)),
        re.compile(r"/uploads/(?P<upload_id>[^/]+)"), "_handle_upload_append",
        invocation="param", parameter="upload_id", control_required=True,
        request_body=True, transfer_slot=True, context_mode="header",
        context_operations=(("PATCH", "upload.chunk"),), discovery_key="uploads",
    ),
    EndpointSpec(
        "upload_cancel", frozenset(("DELETE",)),
        re.compile(r"/uploads/(?P<upload_id>[^/]+)"), "_handle_upload_cancel",
        invocation="param", parameter="upload_id", control_required=True,
        context_mode="header", context_operations=(("DELETE", "upload.cancel"),),
        discovery_key="uploads",
    ),
    EndpointSpec(
        "upload_commit", frozenset(("POST",)),
        re.compile(r"/uploads/(?P<upload_id>[^/]+)/commit"), "_handle_upload_commit",
        invocation="param", parameter="upload_id", control_required=True,
        transfer_slot=True, context_mode="header",
        context_operations=(("POST", "upload.commit"),), discovery_key="uploads",
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
        context_operations=(("POST", "shell.exec"),), discovery_key="shell",
    ),
    _exact(
        "schedule_list", ("GET",), "/schedules", "_handle_schedule_list",
        invocation="query", control_required=True, discovery_key="schedules",
    ),
    _exact(
        "schedule_create", ("POST",), "/schedules", "_handle_schedule_create",
        control_required=True, request_body=True, context_mode="deferred",
        context_operations=(("POST", "schedule.create"),), discovery_key="schedules",
    ),
    EndpointSpec(
        "schedule_runs", frozenset(("GET",)),
        re.compile(r"/schedules/(?P<schedule_id>[^/]+)/runs"), "_handle_schedule_runs",
        invocation="param_query", parameter="schedule_id", control_required=True,
        discovery_key="schedules",
    ),
    EndpointSpec(
        "schedule_run", frozenset(("POST",)),
        re.compile(r"/schedules/(?P<schedule_id>[^/]+)/run"), "_handle_schedule_run",
        invocation="param", parameter="schedule_id", control_required=True,
        request_body=True, context_mode="deferred",
        context_operations=(("POST", "schedule.run_now"),), discovery_key="schedules",
    ),
    EndpointSpec(
        "schedule_pause", frozenset(("POST",)),
        re.compile(r"/schedules/(?P<schedule_id>[^/]+)/pause"), "_handle_schedule_pause",
        invocation="param", parameter="schedule_id", control_required=True,
        request_body=True, context_mode="deferred",
        context_operations=(("POST", "schedule.pause"),), discovery_key="schedules",
    ),
    EndpointSpec(
        "schedule_resume", frozenset(("POST",)),
        re.compile(r"/schedules/(?P<schedule_id>[^/]+)/resume"), "_handle_schedule_resume",
        invocation="param", parameter="schedule_id", control_required=True,
        request_body=True, context_mode="deferred",
        context_operations=(("POST", "schedule.resume"),), discovery_key="schedules",
    ),
    EndpointSpec(
        "schedule_get", frozenset(("GET",)),
        re.compile(r"/schedules/(?P<schedule_id>[^/]+)"), "_handle_schedule_get",
        invocation="param", parameter="schedule_id", control_required=True,
        discovery_key="schedules",
    ),
    EndpointSpec(
        "schedule_update", frozenset(("PATCH",)),
        re.compile(r"/schedules/(?P<schedule_id>[^/]+)"), "_handle_schedule_update",
        invocation="param", parameter="schedule_id", control_required=True,
        request_body=True, context_mode="deferred",
        context_operations=(("PATCH", "schedule.update"),), discovery_key="schedules",
    ),
    EndpointSpec(
        "schedule_delete", frozenset(("DELETE",)),
        re.compile(r"/schedules/(?P<schedule_id>[^/]+)"), "_handle_schedule_delete",
        invocation="param", parameter="schedule_id", control_required=True,
        request_body=True, context_mode="deferred",
        context_operations=(("DELETE", "schedule.delete"),), discovery_key="schedules",
    ),
    EndpointSpec(
        "schedule_run_item", frozenset(("GET",)),
        re.compile(r"/schedule-runs/(?P<run_id>[^/]+)"), "_handle_schedule_run_get",
        invocation="param", parameter="run_id", control_required=True,
        discovery_key="schedules",
    ),
    _exact(
        "task_list", ("GET",), "/tasks", "_handle_task_list",
        invocation="query", control_required=True, context_mode="optional_query",
        context_operations=(("GET", "task.list"),), discovery_key="tasks",
    ),
    _exact(
        "sandbox_processes", ("GET",), "/sandbox/processes", "_handle_sandbox_processes",
        invocation="query", control_required=True, context_mode="optional_query",
        context_operations=(("GET", "sandbox.processes"),), discovery_key="shell",
    ),
    _exact(
        "context_query", ("GET",), "/context", "_handle_context_query",
        invocation="query", control_required=True, discovery_key="context",
    ),
    _exact(
        "context_add", ("POST",), "/context", "_handle_context_add",
        control_required=True, request_body=True, discovery_key="context",
    ),
    EndpointSpec(
        "context_plan_tree", frozenset(("GET",)),
        re.compile(r"/context/plans/(?P<context_id>[^/]+)/tree"),
        "_handle_context_plan_tree", invocation="param_query", parameter="context_id",
        control_required=True, discovery_key="context",
    ),
    EndpointSpec(
        "context_plan_update", frozenset(("PATCH",)),
        re.compile(r"/context/plans/(?P<context_id>[^/]+)"),
        "_handle_context_plan_update", invocation="param", parameter="context_id",
        control_required=True, request_body=True, discovery_key="context",
    ),
    EndpointSpec(
        "context_note_replace", frozenset(("PATCH",)),
        re.compile(r"/context/notes/(?P<context_id>[^/]+)"),
        "_handle_context_note_replace", invocation="param", parameter="context_id",
        control_required=True, request_body=True, discovery_key="context",
    ),
    _exact(
        "memory_query", ("GET",), "/memory", "_handle_memory_query",
        invocation="query", control_required=True, discovery_key="memory",
    ),
    _exact(
        "memory_add", ("POST",), "/memory", "_handle_memory_add",
        control_required=True, request_body=True, discovery_key="memory",
    ),
    _exact(
        "memory_project", ("GET",), "/memory/project", "_handle_memory_project",
        control_required=True, discovery_key="memory",
    ),
    EndpointSpec(
        "memory_revisions", frozenset(("GET",)),
        re.compile(r"/memory/(?P<memory_id>[^/]+)/revisions"),
        "_handle_memory_revisions", invocation="param_query", parameter="memory_id",
        control_required=True, discovery_key="memory",
    ),
    EndpointSpec(
        "memory_item", frozenset(("GET",)),
        re.compile(r"/memory/(?P<memory_id>[^/]+)"),
        "_handle_memory_item", invocation="param", parameter="memory_id",
        control_required=True, discovery_key="memory",
    ),
    EndpointSpec(
        "memory_item_mutate", frozenset(("PATCH", "DELETE")),
        re.compile(r"/memory/(?P<memory_id>[^/]+)"),
        "_handle_memory_item", invocation="param", parameter="memory_id",
        control_required=True, request_body=True, discovery_key="memory",
    ),
    EndpointSpec(
        "task_output", frozenset(("GET",)),
        re.compile(r"/tasks/(?P<task_id>[^/]+)/output"), "_handle_task_output",
        invocation="param_query", parameter="task_id", control_required=True,
        context_mode="optional_query", context_operations=(("GET", "task.output"),),
        discovery_key="tasks",
    ),
    EndpointSpec(
        "task_stream", frozenset(("GET",)),
        re.compile(r"/tasks/(?P<task_id>[^/]+)/stream"), "_handle_task_stream",
        invocation="param_query", parameter="task_id", control_required=True,
        context_mode="optional_query", context_operations=(("GET", "task.stream"),),
        discovery_key="tasks",
    ),
    EndpointSpec(
        "task_stdin", frozenset(("POST",)),
        re.compile(r"/tasks/(?P<task_id>[^/]+)/stdin"), "_handle_task_stdin",
        invocation="param", parameter="task_id", control_required=True, request_body=True,
        context_mode="deferred", context_operations=(("POST", "task.stdin"),),
        discovery_key="tasks",
    ),
    EndpointSpec(
        "task_interrupt", frozenset(("POST",)),
        re.compile(r"/tasks/(?P<task_id>[^/]+)/interrupt"), "_handle_task_interrupt",
        invocation="param", parameter="task_id", control_required=True,
        context_mode="header", context_operations=(("POST", "task.interrupt"),),
        discovery_key="tasks",
    ),
    EndpointSpec(
        "task_kill", frozenset(("POST",)),
        re.compile(r"/tasks/(?P<task_id>[^/]+)/kill"), "_handle_task_kill",
        invocation="param", parameter="task_id", control_required=True,
        context_mode="header", context_operations=(("POST", "task.kill"),),
        discovery_key="tasks",
    ),
    EndpointSpec(
        "task_status", frozenset(("GET",)),
        re.compile(r"/tasks/(?P<task_id>[^/]+)"), "_handle_task",
        invocation="param", parameter="task_id", control_required=True,
        context_mode="optional_query", context_operations=(("GET", "task.get"),),
        discovery_key="tasks",
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

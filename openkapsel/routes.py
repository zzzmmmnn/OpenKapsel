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
    route_template: str | None = None
    invocation: Invocation = "none"
    parameter: str | None = None
    control_required: bool = False
    request_body: bool = False
    transfer_slot: bool = False
    context_mode: ContextMode = "none"
    context_operations: tuple[tuple[str, str], ...] = ()
    context_plan_in_progress_required: bool = True
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
        route_template=route,
        **kwargs,
    )


ENDPOINTS: tuple[EndpointSpec, ...] = (
    _exact("recycle_purge", ("POST",), "/recycle/purge", "_handle_recycle_purge", control_required=True,
        request_body=True, context_mode="deferred", context_operations=(("POST", "recycle.purge"),), discovery_key="recycle"),
    _exact("fs_copy", ("POST",), "/fs/write/copy", "_handle_file_copy", control_required=True,
        request_body=True, context_mode="deferred", context_operations=(("POST", "fs.copy"),), discovery_key="fs_write"),
    EndpointSpec("file_transfer", frozenset(("GET", "POST")),
        re.compile(r"/fs/transfer/(?P<target>(?:[A-Za-z0-9_-]{24}|(?:cancel|resume)/[A-Za-z0-9_-]{24}))"),
        "_handle_file_transfer", invocation="param", parameter="target", control_required=True,
        request_body=True, context_mode="deferred", context_operations=(("POST", "fs.transfer.control"), ("GET", "fs.transfer.get")), discovery_key="transfer"),
    EndpointSpec("server_rpc", frozenset(("POST",)),
        re.compile(r"/rpc/(?P<target>[a-z][a-z0-9_]{0,31}/[a-z][a-z0-9_]{0,31})"),
        "_handle_server_rpc", route_template="/rpc/<family>/<operation>", invocation="param", parameter="target",
        request_body=True, transfer_slot=True, discovery_key="rpc"),
    _exact("mapping_list", ("GET",), "/mapping", "_handle_mapping_list", discovery_key="mapping"),
    EndpointSpec("mapping_rpc", frozenset(("POST",)),
        re.compile(r"/mapping/(?P<target>[A-Za-z0-9][A-Za-z0-9_-]{0,63}/rpc/[a-z][a-z0-9_]{0,31}/[a-z][a-z0-9_]{0,31})"),
        "_handle_mapping_rpc", route_template="/mapping/<mapping_name>/rpc/<family>/<operation>", invocation="param", parameter="target",
        request_body=True, transfer_slot=True, discovery_key="rpc"),
    _exact(
        "credential_renew", ("POST",), "/credential/renew", "_handle_credential_renew",
        control_required=True, discovery_key="credential",
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
    _exact(
        "transport_hmac", ("GET",), "/transport/hmac", "_handle_transport_hmac",
        invocation="query", discovery_key="transport",
    ),
    EndpointSpec(
        "discovery_section", frozenset(("GET",)),
        re.compile(r"/discovery/(?P<section>[A-Za-z0-9_-]+)"),
        "_handle_discovery_section", invocation="param", parameter="section",
        discovery_key="discovery",
    ),
    _exact(
        "share_create", ("POST",), "/share/create", "_handle_share_create",
        control_required=True, request_body=True, transfer_slot=True,
        context_mode="deferred", context_operations=(("POST", "share.create"),),
        discovery_key="share",
    ),
    EndpointSpec(
        "share_import", frozenset(("POST",)),
        re.compile(r"/share/import/(?P<share_id>[A-Za-z0-9_-]+)"),
        "_handle_share_import", invocation="param", parameter="share_id",
        control_required=True, request_body=True, transfer_slot=True,
        context_mode="deferred", context_operations=(("POST", "share.import"),),
        discovery_key="share",
    ),
    EndpointSpec(
        "share_delete", frozenset(("DELETE",)),
        re.compile(r"/share/(?P<share_id>[A-Za-z0-9_-]+)"),
        "_handle_share_delete", invocation="param", parameter="share_id",
        control_required=True, context_mode="header",
        context_operations=(("DELETE", "share.delete"),),
        discovery_key="share",
    ),
    _exact(
        "fs_list", ("GET",), "/fs/query/list", "_handle_fs_list",
        invocation="query", context_mode="optional_query",
        context_operations=(("GET", "fs.list"),), discovery_key="fs_query",
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
        "fs_read_files", ("POST",), "/fs/read/files", "_handle_fs_read_files",
        request_body=True, transfer_slot=True, context_mode="optional_query",
        context_operations=(("POST", "fs.read_files"),), discovery_key="fs_read",
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
        "fs_replace_large", ("POST",), "/fs/write/replace_large", "_handle_fs_replace_large",
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
        "upload_create", ("POST",), "/upload/create", "_handle_upload_create",
        control_required=True, request_body=True, context_mode="deferred",
        context_operations=(("POST", "upload.create"),), discovery_key="upload",
    ),
    EndpointSpec(
        "upload_status", frozenset(("GET", "HEAD")),
        re.compile(r"/upload/status/(?P<upload_id>[^/]+)"), "_handle_upload_status",
        invocation="param_head", parameter="upload_id", control_required=True,
        context_mode="optional_query",
        context_operations=(("GET", "upload.status"), ("HEAD", "upload.status")),
        discovery_key="upload",
    ),
    EndpointSpec(
        "upload_chunk", frozenset(("PATCH",)),
        re.compile(r"/upload/chunk/(?P<upload_id>[^/]+)"), "_handle_upload_append",
        invocation="param", parameter="upload_id", control_required=True,
        request_body=True, transfer_slot=True, context_mode="header",
        context_operations=(("PATCH", "upload.chunk"),), discovery_key="upload",
    ),
    EndpointSpec(
        "upload_cancel", frozenset(("POST",)),
        re.compile(r"/upload/cancel/(?P<upload_id>[^/]+)"), "_handle_upload_cancel",
        invocation="param", parameter="upload_id", control_required=True,
        context_mode="header", context_operations=(("POST", "upload.cancel"),),
        discovery_key="upload",
    ),
    EndpointSpec(
        "upload_commit", frozenset(("POST",)),
        re.compile(r"/upload/commit/(?P<upload_id>[^/]+)"), "_handle_upload_commit",
        invocation="param", parameter="upload_id", control_required=True,
        transfer_slot=True, context_mode="header",
        context_operations=(("POST", "upload.commit"),), discovery_key="upload",
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
        "schedule_list", ("GET",), "/schedule", "_handle_schedule_list",
        invocation="query", control_required=True, discovery_key="schedule",
    ),
    _exact(
        "schedule_create", ("POST",), "/schedule", "_handle_schedule_create",
        control_required=True, request_body=True, context_mode="deferred",
        context_operations=(("POST", "schedule.create"),), discovery_key="schedule",
    ),
    EndpointSpec(
        "schedule_run_list", frozenset(("GET",)),
        re.compile(r"/schedule/run/list/(?P<schedule_id>[^/]+)"), "_handle_schedule_runs",
        invocation="param_query", parameter="schedule_id", control_required=True,
        discovery_key="schedule",
    ),
    EndpointSpec(
        "schedule_execute", frozenset(("POST",)),
        re.compile(r"/schedule/execute/(?P<schedule_id>[^/]+)"), "_handle_schedule_run",
        invocation="param", parameter="schedule_id", control_required=True,
        request_body=True, context_mode="deferred",
        context_operations=(("POST", "schedule.execute"),), discovery_key="schedule",
    ),
    EndpointSpec(
        "schedule_pause", frozenset(("POST",)),
        re.compile(r"/schedule/pause/(?P<schedule_id>[^/]+)"), "_handle_schedule_pause",
        invocation="param", parameter="schedule_id", control_required=True,
        request_body=True, context_mode="deferred",
        context_operations=(("POST", "schedule.pause"),), discovery_key="schedule",
    ),
    EndpointSpec(
        "schedule_resume", frozenset(("POST",)),
        re.compile(r"/schedule/resume/(?P<schedule_id>[^/]+)"), "_handle_schedule_resume",
        invocation="param", parameter="schedule_id", control_required=True,
        request_body=True, context_mode="deferred",
        context_operations=(("POST", "schedule.resume"),),
        context_plan_in_progress_required=False, discovery_key="schedule",
    ),
    EndpointSpec(
        "schedule_get", frozenset(("GET",)),
        re.compile(r"/schedule/(?P<schedule_id>[^/]+)"), "_handle_schedule_get",
        invocation="param", parameter="schedule_id", control_required=True,
        discovery_key="schedule",
    ),
    EndpointSpec(
        "schedule_update", frozenset(("PATCH",)),
        re.compile(r"/schedule/(?P<schedule_id>[^/]+)"), "_handle_schedule_update",
        invocation="param", parameter="schedule_id", control_required=True,
        request_body=True, context_mode="deferred",
        context_operations=(("PATCH", "schedule.update"),), discovery_key="schedule",
    ),
    EndpointSpec(
        "schedule_end", frozenset(("POST",)),
        re.compile(r"/schedule/end/(?P<schedule_id>[^/]+)"), "_handle_schedule_end",
        invocation="param", parameter="schedule_id", control_required=True,
        request_body=True, context_mode="deferred",
        context_operations=(("POST", "schedule.end"),),
        context_plan_in_progress_required=False, discovery_key="schedule",
    ),
    EndpointSpec(
        "schedule_run_get", frozenset(("GET",)),
        re.compile(r"/schedule/run/(?P<run_id>[^/]+)"), "_handle_schedule_run_get",
        invocation="param", parameter="run_id", control_required=True,
        discovery_key="schedule",
    ),
    _exact(
        "task_list", ("GET",), "/task/list", "_handle_task_list",
        invocation="query", control_required=True, context_mode="optional_query",
        context_operations=(("GET", "task.list"),), discovery_key="task",
    ),
    _exact(
        "sandbox_processes", ("GET",), "/sandbox/processes", "_handle_sandbox_processes",
        invocation="query", control_required=True, context_mode="optional_query",
        context_operations=(("GET", "sandbox.processes"),), discovery_key="shell",
    ),
    _exact(
        "conversation_query", ("GET",), "/conversation", "_handle_conversation_query",
        invocation="query", control_required=True, discovery_key="context",
    ),
    _exact(
        "conversation_create", ("POST",), "/conversation", "_handle_conversation_create",
        control_required=True, request_body=True, discovery_key="context",
    ),
    EndpointSpec(
        "conversation_append", frozenset(("POST",)),
        re.compile(r"/conversation/(?P<conversation_id>[^/]+)/entries"),
        "_handle_conversation_append", invocation="param", parameter="conversation_id",
        control_required=True, request_body=True, discovery_key="context",
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
        "_handle_context_plan_tree", route_template="/context/plans/<plan_id>/tree", invocation="param_query", parameter="context_id",
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
        re.compile(r"/task/output/(?P<task_id>[^/]+)"), "_handle_task_output",
        invocation="param_query", parameter="task_id", control_required=True,
        context_mode="optional_query", context_operations=(("GET", "task.output"),),
        discovery_key="task",
    ),
    EndpointSpec(
        "task_stream", frozenset(("GET",)),
        re.compile(r"/task/stream/(?P<task_id>[^/]+)"), "_handle_task_stream",
        invocation="param_query", parameter="task_id", control_required=True,
        context_mode="optional_query", context_operations=(("GET", "task.stream"),),
        discovery_key="task",
    ),
    EndpointSpec(
        "task_stdin", frozenset(("POST",)),
        re.compile(r"/task/stdin/(?P<task_id>[^/]+)"), "_handle_task_stdin",
        invocation="param", parameter="task_id", control_required=True, request_body=True,
        context_mode="deferred", context_operations=(("POST", "task.stdin"),),
        discovery_key="task",
    ),
    EndpointSpec(
        "task_interrupt", frozenset(("POST",)),
        re.compile(r"/task/interrupt/(?P<task_id>[^/]+)"), "_handle_task_interrupt",
        invocation="param", parameter="task_id", control_required=True,
        context_mode="header", context_operations=(("POST", "task.interrupt"),),
        discovery_key="task",
    ),
    EndpointSpec(
        "task_kill", frozenset(("DELETE",)),
        re.compile(r"/task/(?P<task_id>[^/]+)"), "_handle_task_kill",
        invocation="param", parameter="task_id", control_required=True,
        context_mode="header", context_operations=(("DELETE", "task.kill"),),
        discovery_key="task",
    ),
    EndpointSpec(
        "task_get", frozenset(("GET",)),
        re.compile(r"/task/get/(?P<task_id>[^/]+)"), "_handle_task",
        invocation="param", parameter="task_id", control_required=True,
        context_mode="optional_query", context_operations=(("GET", "task.get"),),
        discovery_key="task",
    ),
)


def _pattern_route_template(pattern: str) -> str:
    """Convert named regex groups to compact public <name> route placeholders."""
    result: list[str] = []
    index = 0
    while index < len(pattern):
        marker = pattern.find("(?P<", index)
        if marker < 0:
            result.append(pattern[index:])
            break
        result.append(pattern[index:marker])
        name_end = pattern.find(">", marker + 4)
        if name_end < 0:
            result.append(pattern[marker:])
            break
        name = pattern[marker + 4:name_end]
        depth = 1
        cursor = name_end + 1
        escaped = False
        in_class = False
        while cursor < len(pattern) and depth:
            char = pattern[cursor]
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == "[":
                in_class = True
            elif char == "]" and in_class:
                in_class = False
            elif not in_class and char == "(":
                depth += 1
            elif not in_class and char == ")":
                depth -= 1
            cursor += 1
        if depth:
            result.append(pattern[marker:])
            break
        result.append(f"<{name}>")
        index = cursor
    route = "".join(result)
    if route.endswith("/?"):
        route = route[:-2]
    return route


_DISCOVERY_ROUTE_ALIASES: dict[str, tuple[str, ...]] = {
    "memory_item": ("memory_item", "memory_item_mutate"),
    "mcp": ("mcp_post",),
}

_ENDPOINTS_BY_NAME = {endpoint.name: endpoint for endpoint in ENDPOINTS}
_METHOD_ORDER = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE")


def endpoint_route_template(name: str) -> str | None:
    endpoint = _ENDPOINTS_BY_NAME.get(name)
    if endpoint is None:
        return None
    return endpoint.route_template or _pattern_route_template(endpoint.pattern.pattern)


def discovery_route_metadata(name: str) -> dict[str, object] | None:
    """Return canonical route/method metadata for one Discovery endpoint."""
    route_names = _DISCOVERY_ROUTE_ALIASES.get(name, (name,))
    endpoints = [_ENDPOINTS_BY_NAME[item] for item in route_names if item in _ENDPOINTS_BY_NAME]
    if not endpoints:
        return None
    templates = {endpoint_route_template(endpoint.name) for endpoint in endpoints}
    templates.discard(None)
    if len(templates) != 1:
        return None
    methods = [
        method
        for method in _METHOD_ORDER
        if any(method in endpoint.methods for endpoint in endpoints)
    ]
    if not methods:
        return None
    if len(methods) == 1:
        method_label = methods[0]
    elif len(methods) == 2:
        method_label = f"{methods[0]} or {methods[1]}"
    else:
        method_label = ", ".join(methods[:-1]) + f", or {methods[-1]}"
    result: dict[str, object] = {"method": method_label, "route": next(iter(templates))}
    if len(methods) > 1:
        result["methods"] = methods
    return result


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

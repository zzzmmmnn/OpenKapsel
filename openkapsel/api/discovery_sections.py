"""Static grouping metadata and concise workflows for split Discovery documents."""

from __future__ import annotations

from openkapsel.contract import PLAN_COMPLETION_MEMORY_GUIDANCE
from openkapsel.context.conversation import (
    DEFAULT_RECENT_CONVERSATION_COUNT,
    MAX_RECENT_CONVERSATION_PAGES,
)


SECTION_NAMES = ("transport", "files", "context", "memory", "paths", "rpc", "network", "mcp", "shell", "schedules", "web", "sharing", "authentication", "errors")


SECTION_MCP_FAMILIES = {
    "authentication": {"credential"},
    "shell": {"shell", "task"},
    "schedules": {"schedule"},
    "web": {"web"},
    "sharing": {"sharing"},
}

SECTION_ENDPOINTS = {
    "transport": {"transport"},
    "files": {"fs_query", "fs_read", "fs_content", "fs_write", "transfer", "recycle", "upload"},
    "context": {"context", "conversation"},
    "memory": {"memory"},
    "paths": set(),
    "rpc": {"rpc", "mapping"},
    "network": set(),
    "mcp": {"mcp"},
    "shell": {"shell", "task", "environment"},
    "schedules": {"schedule"},
    "web": {"web"},
    "sharing": {"share"},
    "authentication": {"credential"},
    "errors": set(),
}

SECTION_CAPABILITIES = {
    "transport": set(),
    "files": {"files", "recycle", "file_operations", "binary_transfer"},
    "context": {"context"},
    "memory": {"memory"},
    "paths": {"extra_paths", "extra_paths_redacted"},
    "rpc": {"mappings"},
    "network": {"network", "network_mode", "network_domains", "network_protocols"},
    "mcp": {"mcp"},
    "shell": {
        "shell", "shell_sandbox", "shell_sandbox_requested", "sandbox_backends",
        "shell_pid_namespace", "shell_sandbox_image", "shell_sandbox_image_requested",
        "shell_outside_workspace", "tasks", "task_control", "process", "environment",
    },
    "schedules": {"schedules"},
    "web": {"web_preview", "web_app_api"},
    "sharing": {"sharing"},
    "authentication": set(),
    "errors": set(),
}

SECTION_LIMITS = {
    "transport": set(),
    "files": {
        "workspace_storage", "max_request_body_bytes", "max_read_chars",
        "default_read_chars", "max_direct_upload_bytes", "max_file_bytes",
        "recommended_upload_chunk_bytes", "max_mcp_binary_chunk_bytes",
        "upload_ttl_seconds", "max_incomplete_upload_bytes", "max_text_replace_bytes",
        "max_concurrent_transfers", "max_search_results", "max_search_file_bytes",
        "max_tree_nodes", "max_recursion_depth", "max_batch_file_operations",
    },
    "context": {
        "max_context_query_entries", "max_context_entries", "context_trim_oldest_entries",
        "max_unfinished_root_plan_hints", "max_plan_hint_content_characters",
        "max_operation_message_characters", "max_taskname_characters",
        "max_conversation_query_entries", "max_conversation_content_characters",
        "max_conversation_summary_characters",
    },
    "memory": {"max_memory_query_entries", "max_memory_content_characters"},
    "paths": set(),
    "rpc": {"mapping_rpc_timeout_seconds", "mapping_provider_idle_timeout_seconds"},
    "network": set(),
    "mcp": set(),
    "shell": {
        "max_task_output_bytes_per_stream", "max_finished_tasks_per_token",
        "finished_task_retention_seconds", "finished_task_storage",
        "max_concurrent_shell_tasks", "max_concurrent_shell_tasks_per_token",
        "max_sse_streams", "max_sse_streams_per_token", "max_sse_duration_seconds",
        "max_task_output_chunk_bytes", "max_task_input_bytes_per_request",
        "max_task_wait_seconds", "max_command_characters", "sandbox_max_processes",
        "sandbox_memory_bytes", "sandbox_cpu_percent",
        "max_environment_variables", "max_environment_name_characters",
        "max_environment_value_characters", "max_environment_total_characters",
        "max_environment_rc_characters",
    },
    "schedules": {
        "min_schedule_interval_minutes", "max_schedules_per_token",
        "schedule_misfire_grace_seconds", "max_schedule_runs_per_schedule",
        "schedule_run_retention_days",
    },
    "web": {
        "max_sse_streams", "max_sse_streams_per_token", "max_sse_duration_seconds",
        "http_socket_timeout_seconds",
    },
    "sharing": {
        "share_ttl_seconds", "max_share_entries", "max_share_bytes",
    },
    "authentication": set(),
    "errors": set(),
}

SECTION_SUMMARIES = {
    "transport": "GET-only query routing, HMAC calculation, and signed transport envelopes for constrained clients.",
    "files": "File operations, metadata, search, recycle, downloads, and uploads.",
    "context": "Append-only Conversation summaries plus operation history, hierarchical plans, notes, and required mutation context.",
    "memory": "Revisioned project-level long-term Memory and plan debrief integration.",
    "paths": "Shared workspace path, private-directory, and authorized extra-path rules.",
    "rpc": "Shared mapping inventory and generic RPC routing used by files and Shell workflows.",
    "network": "Shared network availability, mode, domain policy, and protocols for Shell and web applications.",
    "mcp": "MCP core-tool and capability_call dispatcher metadata; operation schemas live in their capability sections.",
    "shell": "Shell execution and Task polling/output/input/control together with sandbox and task limits.",
    "schedules": "Persistent once, interval, and six-field cron Shell schedules.",
    "web": "Static web preview, FastAPI applications, runtime libraries, and managed databases.",
    "sharing": "Temporary ID-addressed transfer of one file or directory between workspaces.",
    "authentication": "Credential inspection and renewal; load only when authentication state or rotation is needed.",
    "errors": "Shared API error envelope and error-code reference.",
}

SECTION_WORKFLOWS = {
    "transport": [
        "Prefer ordinary REST paths and Authorization: Bearer <CONTROL_TOKEN> whenever the client supports them.",
        "Use req at the exact workspace root only when the client cannot change the request path.",
        "Use the signed GET envelope only when the client also cannot send the required HTTP method or Authorization header.",
        "If the client also lacks HMAC-SHA256, call transport/hmac or ?req=transport/hmac with URL-encoded key and target, then use the returned base64url-no-padding result as signature.",
        "Generate a fresh random nonce for every signed envelope and never reuse it inside the timestamp acceptance window.",
    ],
    "files": [
        "Use /fs/query/<operation> for list/stat/tree/search/manifest inspection.",
        "Use /fs/read/<operation> for text, multi-file, or bounded large-file reads; keep /fs/content for raw Range streaming.",
        "Use /fs/write/<operation> for mutate, guarded large-range replace, mkdir, move, and asynchronous copy.",
        "Resumable uploads use explicit operation routes under /upload: create, status, chunk, commit, and cancel.",
        "Use generic RPC family=archive for archive list/read; load discovery/rpc only when RPC or client mappings are needed.",
        "Load discovery/paths only when absolute paths, extra directories, private-directory rules, or path-boundary behavior matters.",
        "Existing paths require exact ETags for guarded mutations; deletion remains recoverable through recycle.",
    ],
    "context": [
        "Before creating a new Conversation, use conversation_query.next_conversation_id exactly. IDs are caller-supplied non-negative integers starting at 0 and cannot skip; creation atomically records at least user then ai and returns writer_nonce.",
        f"Append materially new user/ai context with conversation_id plus writer_nonce. user/ai records are per-side context summaries (max 1000 chars) and may keep original wording without extra compression when it already fits. Summary cadence is dynamic: after 40 user/ai entries since the newest summary, append responses recommend summary via summary_status; after 49, another user/ai entry is blocked until summary is appended. The summary covers from the newest summary itself (or sub_id 1) through the latest entry. Without conversation_id, conversation_query pages through non-empty Conversations by last entry time, {DEFAULT_RECENT_CONVERSATION_COUNT} per page for up to {MAX_RECENT_CONVERSATION_PAGES} pages, and returns each grouped window from its newest summary (or sub_id 1) forward. With conversation_id it returns the newest at most 100 entries, optionally after a sub_id range filter. Returned entries are always in forward reading order.",
        "Plan creation and every non-cancellation-only Plan update append at least one Conversation entry using conversation_id plus the writer_nonce returned by conversation_create; completion must include at least one ai entry. Cancellation-only remains possible without writer_nonce.",
        "After creating any plan, inspect unfinished_root_plans in the response to avoid duplicating another in-progress root plan.",
        "Use plan_id for parent/sub-plan relationships and to attach every modifying operation and note to its owning plan. A mutation owner must be an in_progress Plan; completed or cancelled Plans cannot accept new mutations.",
        "Reads are not recorded unless taskname and message are supplied; plan completion also requires a debrief.",
    ],
    "memory": [
        "Memory semantics are one canonical path, content, and tags. New or rewritten content is limited to 256 characters; legacy longer content remains readable. New Memory requires at least one indexed tag; prefer 4-16 specific reusable tags.",
        "Mutation plan_id/taskname/message rules are shared with Context and are published in discovery/context; the owning Plan must be in_progress.",
        PLAN_COMPLETION_MEMORY_GUIDANCE,
    ],
    "paths": [
        "Relative paths are resolved from the token workspace; absolute paths are accepted only inside the workspace or an authorized extra directory.",
        "Use this section as the single authority for symlink escape, private-directory, and extra-path visibility rules.",
    ],
    "rpc": [
        "Load this section only when using client mappings or generic RPC families such as archive or git.",
        "Mapping inventory and RPC timeout policy are shared by file and Shell workflows and are defined here once.",
    ],
    "network": [
        "Load this section only when Shell or workspace web behavior depends on outbound network availability, mode, domains, or protocols.",
    ],
    "mcp": [
        "Keep Conversation, Plan, Memory, File, discovery, rpc_call, and capability_call schemas in the ordinary tools/list response.",
        "capability_call operation schemas are published in the matching capability section, not here: shell also covers task; schedules, web, sharing, and authentication each own their family schemas.",
        "When mutation_context=true, pass plan_id, taskname, and message outside args; plan_id must reference an in_progress Plan. Read operations may optionally use those outer fields when optional_read_context=true.",
    ],
    "shell": [
        "Use generic RPC family=git for Git reads and mutations on the server or a mapping; load discovery/rpc for mapping and RPC routing contracts. Read operations are synchronous and bounded; write operations run as tasks and require mutation Context.",
        "Use the env endpoint to inspect, completely replace, or clear app-identity-scoped Shell variables and POSIX initialization; writes require mutation Context.",
        "Start asynchronous Shell tasks only under an in_progress owning Plan, then poll status or read output incrementally; use SSE when the client supports it.",
        "Send stdin only to interactive tasks. Interrupt normally before using force-kill.",
        "Restricted Shell runs inside the configured sandbox and token resource limits; inspect sandbox processes when available. Load discovery/network only when network policy matters.",
    ],
    "schedules": [
        "Create schedules only when background execution is needed; use run-now for an explicit immediate execution.",
        "Use interval minutes of at least 3, a once timestamp at least 3 minutes ahead, or strict six-field cron with an explicit second and IANA timezone.",
        "Each schedule carries plan_id, taskname, and message so every dispatched run is attached to Context automatically. The run Plan must still be in_progress when dispatch occurs; otherwise the run is rejected.",
        "Pause before editing operational intent and use expected_revision for updates. Schedule run records link to Shell task IDs; concurrency and task-control limits live in discovery/shell.",
    ],
    "web": [
        "Use the independent preview URL for static files and relative browser assets. Load discovery/files for workspace storage/request-size limits and discovery/paths for path-boundary rules.",
        "A directory named api delegates that application subtree to its FastAPI app.py; each app owns private managed database storage.",
        "Use a GET StreamingResponse with media type text/event-stream for live updates; send periodic SSE comments below the published upstream idle timeout and let EventSource reconnect when the duration limit closes a stream.",
        "Implement application users, sessions, CSRF, and roles inside the workspace application; OpenKapsel does not provide them. Load discovery/network only when application network policy matters.",
    ],
    "sharing": [
        "Create a share from exactly one file or directory inside the source token workspace.",
        "The recipient can inspect by share ID without a workspace token, then imports with its own destination control token.",
        "Imports never overwrite, and shares expire or are evicted according to the published limits. Shared tree/transfer limits and path rules live in discovery/files and discovery/paths.",
    ],
    "authentication": [
        "Load this section only when credential state, expiry, or renewal is needed.",
    ],
    "errors": [
        "Load this section only when an API error needs interpretation; normal capability pages omit the shared error catalog.",
    ],
}

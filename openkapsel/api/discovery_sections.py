"""Static grouping metadata and concise workflows for split Discovery documents."""

from __future__ import annotations


SECTION_NAMES = ("transport", "files", "context", "memory", "shell", "schedules", "web", "sharing")

SECTION_ENDPOINTS = {
    "transport": {"transport"},
    "files": {
        "rpc", "mapping", "fs_query", "fs_read", "fs_content", "fs_write",
        "transfer", "recycle", "upload",
    },
    "context": {"context", "conversation"},
    "memory": {"memory"},
    "shell": {"rpc", "mapping", "shell", "task", "environment"},
    "schedules": {"schedule"},
    "web": {"web"},
    "sharing": {"share"},
}

SECTION_CAPABILITIES = {
    "transport": set(),
    "files": {
        "mappings",
        "files", "recycle", "file_operations", "binary_transfer", "extra_paths",
        "extra_paths_redacted",
    },
    "context": {"context"},
    "memory": {"memory"},
    "shell": {
        "mappings",
        "shell", "shell_sandbox", "shell_sandbox_requested", "sandbox_backends",
        "shell_pid_namespace", "shell_sandbox_image", "shell_sandbox_image_requested",
        "network", "network_mode", "network_domains",
        "network_protocols", "shell_outside_workspace", "tasks",
        "task_control", "process", "environment", "extra_paths", "extra_paths_redacted",
    },
    "schedules": {"schedules"},
    "web": {"web_preview", "web_app_api", "network", "network_mode", "network_domains", "network_protocols"},
    "sharing": {"sharing"},
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
        "mapping_rpc_timeout_seconds", "mapping_provider_idle_timeout_seconds",
    },
    "context": {
        "max_context_query_entries", "max_context_entries", "context_trim_oldest_entries",
        "max_unfinished_root_plan_hints", "max_plan_hint_content_characters",
        "max_operation_message_characters", "max_taskname_characters",
        "max_conversation_query_entries", "max_conversation_content_characters",
        "max_conversation_summary_characters",
    },
    "memory": {
        "max_memory_query_entries", "max_memory_content_characters",
        "max_operation_message_characters", "max_taskname_characters",
    },
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
        "max_environment_rc_characters", "mapping_rpc_timeout_seconds",
        "mapping_provider_idle_timeout_seconds",
    },
    "schedules": {
        "min_schedule_interval_minutes", "max_schedules_per_token",
        "schedule_misfire_grace_seconds", "max_concurrent_shell_tasks",
        "max_concurrent_shell_tasks_per_token", "max_schedule_runs_per_schedule",
        "schedule_run_retention_days",
    },
    "web": {
        "workspace_storage", "max_request_body_bytes", "max_sse_streams",
        "max_sse_streams_per_token", "max_sse_duration_seconds",
        "http_socket_timeout_seconds",
    },
    "sharing": {
        "share_ttl_seconds", "max_share_entries", "max_share_bytes",
        "max_recursion_depth", "max_tree_nodes", "max_concurrent_transfers",
    },
}

SECTION_SUMMARIES = {
    "transport": "GET-only query routing, HMAC calculation, and signed transport envelopes for constrained clients.",
    "files": "File operations, metadata, search, recycle, downloads, and uploads.",
    "context": "Append-only Conversation summaries plus operation history, hierarchical plans, notes, and required mutation context.",
    "memory": "Revisioned project-level long-term Memory and plan debrief integration.",
    "shell": "Generic RPC, Shell tasks, streaming input/output, termination, processes, and sandbox limits.",
    "schedules": "Persistent once, interval, and six-field cron Shell schedules.",
    "web": "Static web preview, FastAPI applications, runtime libraries, and managed databases.",
    "sharing": "Temporary ID-addressed transfer of one file or directory between workspaces.",
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
        "Use generic RPC family=archive for archive list/read; archive-specific REST wrappers are not exposed.",
        "Existing paths require exact ETags for guarded mutations; deletion remains recoverable through recycle.",
    ],
    "context": [
        "Query Conversation history before creation and use conversation_query.next_conversation_id exactly. IDs are caller-supplied non-negative integers starting at 0 and cannot skip; creation atomically records at least user then ai and returns writer_nonce.",
        "Append materially new user/ai context with conversation_id plus writer_nonce. user/ai records are per-side context summaries (max 1000 chars) and may keep original wording without extra compression when it already fits. Summary cadence is dynamic: after 20 user/ai entries since the newest summary, append responses recommend summary via summary_status; after 30, another user/ai entry is blocked until summary is appended. The summary covers from the newest summary itself (or sub_id 1) through the latest entry. Cross-conversation query defaults to the newest summary plus later entries.",
        "Query active root plans first, then create a root plan only when no suitable plan exists.",
        "Plan creation and every non-cancellation-only Plan update atomically append at least one Conversation entry using conversation_id plus writer_nonce; completion must include at least one ai entry. writer_nonce is a plaintext writer nonce, not an authentication token. Cancellation-only remains possible without it.",
        "After creating any plan, inspect unfinished_root_plans in the response to avoid duplicating another in-progress root plan.",
        "Use plan_id for parent/sub-plan relationships and to attach every modifying operation and note to its owning plan.",
        "Reads are not recorded unless taskname and message are supplied; plan completion also requires a debrief.",
    ],
    "memory": [
        "Read project Memory when starting work that depends on durable cross-task facts.",
        "Memory semantics are one canonical path, content, and tags. New or rewritten content is limited to 256 characters; legacy longer content remains readable. New Memory requires at least one indexed tag; prefer 4-16 specific reusable tags.",
        "On plan completion, OpenKapsel first holds the Context SQLite write lock with BEGIN IMMEDIATE and dry-runs the full Plan+Conversation update in a SAVEPOINT. The SAVEPOINT is rolled back while the outer lock stays held; Memory is then applied, followed by the final Plan+Conversation update and Context commit on the same connection. Every debrief.items entry directly creates one new Memory from content plus tags; multiple entries create multiple Memories. The server derives one common path from successful writes directly owned by the Plan; server, mapping IDs, and storage-provider IDs are separate namespaces and mixed targets collapse to server:.; Shell contributes only cwd. memory_actions only updates or archives existing Memory. memory_feedback records only Memory that materially helped; conflicts require content update or archive.",
    ],
    "shell": [
        "Use generic RPC family=git for Git reads and mutations on the server or a mapping. Read operations are synchronous and bounded; write operations run as tasks and require mutation Context.",
        "Use the env endpoint to inspect, completely replace, or clear app-identity-scoped Shell variables and POSIX initialization; writes require mutation Context.",
        "Start asynchronous Shell tasks, then poll status or read output incrementally; use SSE when the client supports it.",
        "Send stdin only to interactive tasks. Interrupt normally before using force-kill.",
        "Restricted Shell runs inside the configured sandbox and token resource limits; inspect sandbox processes when available.",
    ],
    "schedules": [
        "Create schedules only when background execution is needed; use run-now for an explicit immediate execution.",
        "Use interval minutes of at least 3, a once timestamp at least 3 minutes ahead, or strict six-field cron with an explicit second and IANA timezone.",
        "Each schedule carries plan_id, taskname, and message so every dispatched run is attached to Context automatically.",
        "Pause before editing operational intent and use expected_revision for updates. Schedule run records link to Shell task IDs; load discovery/shell only when task output or control details are needed.",
    ],
    "web": [
        "Use the independent preview URL for static files and relative browser assets.",
        "A directory named api delegates that application subtree to its FastAPI app.py; each app owns private managed database storage.",
        "Use a GET StreamingResponse with media type text/event-stream for live updates; send periodic SSE comments below the published upstream idle timeout and let EventSource reconnect when the duration limit closes a stream.",
        "Implement application users, sessions, CSRF, and roles inside the workspace application; OpenKapsel does not provide them.",
    ],
    "sharing": [
        "Create a share from exactly one file or directory inside the source token workspace.",
        "The recipient can inspect by share ID without a workspace token, then imports with its own destination control token.",
        "Imports never overwrite, and shares expire or are evicted according to the published limits.",
    ],
}

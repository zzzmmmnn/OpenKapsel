"""Static grouping metadata and concise workflows for split Discovery documents."""

from __future__ import annotations


SECTION_NAMES = ("files", "context", "memory", "shell", "schedules", "web", "sharing")

SECTION_ENDPOINTS = {
    "files": {
        "fs_list", "fs_read", "fs_stat", "fs_manifest", "fs_search", "fs_tree", "fs_content",
        "fs_content_put", "fs_write", "fs_replace", "fs_replace_batch", "fs_mkdir", "fs_delete",
        "fs_delete_batch", "fs_move", "recycle_list", "recycle_restore", "upload_create",
        "upload_status", "upload_chunk", "upload_commit", "upload_cancel",
    },
    "context": {
        "context_query", "context_plan_tree", "context_add", "context_plan_update",
        "context_note_replace",
    },
    "memory": {
        "memory_query", "memory_project", "memory_add", "memory_item",
        "memory_revisions",
    },
    "shell": {
        "shell_exec", "task_list", "task_status", "task_output", "task_stream",
        "task_stdin", "task_interrupt", "task_kill", "sandbox_processes",
        "environment_get", "environment_replace", "environment_clear",
    },
    "schedules": {
        "schedule_list", "schedule_create", "schedule_get", "schedule_update",
        "schedule_delete", "schedule_run", "schedule_pause", "schedule_resume",
        "schedule_runs", "schedule_run_item",
    },
    "web": {"web_preview", "web_app_api"},
    "sharing": {"share_create", "share_query", "share_import", "share_delete"},
}

SECTION_CAPABILITIES = {
    "files": {
        "files", "recycle", "file_operations", "binary_transfer", "extra_paths",
        "extra_paths_redacted",
    },
    "context": {"context"},
    "memory": {"memory"},
    "shell": {
        "shell", "shell_sandbox", "shell_sandbox_requested", "sandbox_backends",
        "shell_pid_namespace", "shell_sandbox_image", "shell_sandbox_image_requested",
        "network", "network_mode", "network_domains",
        "network_protocols", "shell_outside_workspace", "tasks",
        "task_control", "process", "environment", "extra_paths", "extra_paths_redacted",
    },
    "schedules": {"schedules", "shell", "tasks", "environment"},
    "web": {"web_preview", "web_app_api", "network", "network_mode", "network_domains", "network_protocols"},
    "sharing": {"sharing"},
}

SECTION_LIMITS = {
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
        "max_environment_rc_characters",
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
    "files": "File operations, metadata, search, recycle, downloads, and uploads.",
    "context": "Operation history, hierarchical plans, notes, and required mutation context.",
    "memory": "Revisioned project-level long-term Memory and plan debrief integration.",
    "shell": "Shell tasks, streaming input/output, termination, processes, and sandbox limits.",
    "schedules": "Persistent once, interval, and six-field cron Shell schedules.",
    "web": "Static web preview, FastAPI applications, runtime libraries, and managed databases.",
    "sharing": "Temporary ID-addressed transfer of one file or directory between workspaces.",
}

SECTION_WORKFLOWS = {
    "files": [
        "Inspect with fs_list/list_files, fs_tree/list_tree, fs_stat/stat_file, and fs_search/search_files before editing.",
        "Use expected_etag for conditional text writes; use fs_replace_batch for multiple exact, non-overlapping edits across one or more files.",
        "Binary uploads create new files only, so recycle an existing destination before uploading a replacement.",
        "Use fs_manifest for bounded multi-file synchronization preflight, and fs_delete_batch when explicitly recycling multiple independent paths.",
        "Create directories and move paths explicitly; file API deletion is recoverable through the workspace recycle bin.",
    ],
    "context": [
        "Query active root plans first, then create a root plan only when no suitable plan exists.",
        "After creating any plan, inspect unfinished_root_plans in the response to avoid duplicating another in-progress root plan.",
        "Use plan_id for parent/sub-plan relationships and to attach every modifying operation and note to its owning plan.",
        "Reads are not recorded unless taskname and message are supplied; plan completion requires a debrief.",
    ],
    "memory": [
        "Read project Memory when starting work that depends on durable architecture, conventions, decisions, or known issues.",
        "Use indexed tags and overlapping paths for retrieval; revisions require the current expected revision.",
        "On plan completion, create, update, resolve, archive, or explicitly retain no Memory through memory_actions.",
    ],
    "shell": [
        "Use the env endpoint to inspect, completely replace, or clear app-identity-scoped Shell variables and POSIX initialization; writes require mutation Context.",
        "Start asynchronous Shell tasks, then poll status or read output incrementally; use SSE when the client supports it.",
        "Send stdin only to interactive tasks. Interrupt normally before using force-kill.",
        "Restricted Shell runs inside the configured sandbox and token resource limits; inspect sandbox processes when available.",
    ],
    "schedules": [
        "Create schedules only when background execution is needed; use run-now for an explicit immediate execution.",
        "Use interval minutes of at least 3, a once timestamp at least 3 minutes ahead, or strict six-field cron with an explicit second and IANA timezone.",
        "Each schedule carries plan_id, taskname, and message so every dispatched run is attached to Context automatically.",
        "Pause before editing operational intent, use expected_revision for updates, and inspect run history plus the linked Shell task for output.",
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

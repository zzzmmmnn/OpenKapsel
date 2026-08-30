# Shell tasks, streaming I/O, and process inspection

Read `GET /discovery/shell` before use. It states whether Shell is `none`, `restricted`, or `full`, the active sandbox backend, network access, task limits, timeout limits, and cgroup availability.

Restricted Shell and full Shell have different boundaries. Restricted Shell is confined by its configured backend, mounts, network setting, and available cgroup limits. Full Shell runs as the OpenKapsel service user and is not constrained by token path grants or the network flag.

## Start and inspect tasks

`POST /shell/exec` returns `202` with `task_id`:

```json
{
  "command": "python3 -m unittest",
  "cwd": ".",
  "timeout_seconds": 3600,
  "interactive": false,
  "plan_id": 42,
  "taskname": "tests",
  "message": "Run the test suite"
}
```

The command runs asynchronously. `timeout_seconds` may be `null` or within the published bounds. `interactive: true` keeps stdin available.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/tasks?offset=0&limit=100&status=running` | List this token's running/finished tasks; omit `status` for all |
| `GET` | `/tasks/<task_id>` | Current state and exit metadata |
| `GET` | `/tasks/<task_id>/output` | Incremental stdout/stderr by byte cursor |
| `GET` | `/tasks/<task_id>/stream` | SSE output until `done` |
| `POST` | `/tasks/<task_id>/stdin` | Send UTF-8/Base64 input or close stdin |
| `POST` | `/tasks/<task_id>/interrupt` | SIGTERM, then SIGKILL after grace period |
| `POST` | `/tasks/<task_id>/kill` | Immediate SIGKILL of the process group |
| `GET` | `/sandbox/processes` | Token cgroup process/resource view for restricted Shell |

## Output polling

Call:

```text
GET /tasks/<id>/output?stdout_offset=0&stderr_offset=0&limit=65536&wait_seconds=20
```

Advance each cursor to its returned `next_offset`. A `gap` means older bytes fell outside the bounded stream and the response tells where retained output begins. `wait_seconds` supports long polling up to the published maximum.

SSE uses `text/event-stream` with `output` and `done` events:

```text
GET /tasks/<id>/stream?stdout_offset=<n>&stderr_offset=<n>
```

The generic helper writes SSE directly rather than buffering it:

```bash
python3 scripts/openkapsel_http.py GET tasks/<id>/stream --stream
```

## Interactive input and termination

`POST /tasks/<id>/stdin` JSON accepts exactly one of `data` (UTF-8) or `data_base64`, plus optional `close`. Include JSON Context fields. The task must have been created with `interactive: true`.

Interrupt and kill have no JSON body, so send all three `OpenKapsel-*` Context headers. Prefer interrupt; use force-kill when graceful termination is inappropriate or failed.

`GET /sandbox/processes?offset=0&limit=100` is available only for restricted Shell when server cgroup support is enabled. It reports aggregate memory/CPU/PID/OOM counters and process rows. A task limit, PID limit, memory limit, or CPU limit is independent; consult Discovery rather than assuming defaults.

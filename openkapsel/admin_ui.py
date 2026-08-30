"""Small dependency-free HTML renderer for the administration console."""

from __future__ import annotations

import html
import json
from datetime import timezone
from urllib.parse import quote

from .tokens import PathGrant, TokenRecord, parse_datetime
from .workspace_images import WorkspaceImage


STYLE = """
:root{color-scheme:light;--bg:#f3f6fa;--card:#fff;--text:#172033;--muted:#657085;--line:#dce2ea;--brand:#315efb;--danger:#bb2436}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 system-ui,-apple-system,sans-serif}
main{max-width:1180px;margin:32px auto;padding:0 20px}.top{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:22px}
h1{font-size:25px;margin:0}h2{font-size:18px;margin:0 0 16px}.muted{color:var(--muted)}.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;margin-bottom:18px;box-shadow:0 3px 16px #23314d0a}
.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}.span2{grid-column:span 2}.span4{grid-column:span 4}.token-name-field{grid-column:span 1}
label{display:block;font-weight:600;margin-bottom:5px}input,select,textarea{width:100%;border:1px solid #cbd3df;border-radius:7px;padding:9px 10px;background:#fff;color:var(--text)}textarea{min-height:76px;resize:vertical;font:13px/1.4 ui-monospace,SFMono-Regular,monospace}
input[type=checkbox]{width:auto;margin-right:6px}.checks{display:flex;align-items:center;gap:18px;padding-top:27px}.checks label{font-weight:500;margin:0}
button,.button{border:0;border-radius:7px;padding:9px 13px;background:var(--brand);color:#fff;font-weight:650;cursor:pointer;text-decoration:none;display:inline-block}
button.secondary{background:#e8edff;color:#2747ae}button.danger{background:#fff0f1;color:var(--danger);border:1px solid #f2c7cd}.actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.token{font:12px/1.4 ui-monospace,SFMono-Regular,monospace;background:#f4f6fa;border:1px solid var(--line);padding:9px;border-radius:7px;word-break:break-all;margin:10px 0}
.badge{display:inline-block;border-radius:99px;padding:3px 8px;font-size:12px;font-weight:700;background:#e8f7ee;color:#17713b}.badge.off{background:#f4e8e9;color:#9d2533}
.login{max-width:420px;margin:12vh auto}.error{background:#fff0f1;border:1px solid #f2c7cd;color:#9d2533;padding:10px;border-radius:7px;margin-bottom:14px}
.success{background:#eaf8ef;border:1px solid #b9e1c7;color:#176738;padding:10px;border-radius:7px;margin-bottom:14px}
.notice{background:#fff8db;border:1px solid #eadb91;padding:10px;border-radius:7px;margin-top:12px}.token-card{border-left:4px solid #aab8d2}.token-card.invalid{border-left-color:#c95161}
.path-grant-row{display:grid;grid-template-columns:minmax(0,1fr) 130px;gap:10px;margin-bottom:8px}.path-grant-row input,.path-grant-row select{margin:0}
.admin-shell{display:grid;grid-template-columns:220px minmax(0,1fr);min-height:100vh}.admin-sidebar{position:sticky;top:0;height:100vh;background:#111b32;color:#dce5f6;padding:22px 14px;display:flex;flex-direction:column;gap:22px;overflow:hidden}.admin-brand{display:flex;align-items:center;gap:11px;padding:0 9px}.brand-mark{display:grid;place-items:center;flex:0 0 34px;height:34px;border-radius:9px;background:var(--brand);color:#fff;font-size:17px;font-weight:800}.brand-copy{min-width:0}.brand-copy strong,.brand-copy span{display:block;white-space:nowrap}.brand-copy span{color:#96a5bf;font-size:12px;margin-top:2px}.admin-nav{display:flex;flex-direction:column;gap:7px}.nav-item{width:100%;display:flex;align-items:center;gap:11px;background:transparent;color:#b9c5da;padding:11px 12px;text-align:left;border-radius:9px;white-space:nowrap}.nav-item:hover{background:#1d2944;color:#fff}.nav-item.active{background:#27468f;color:#fff}.nav-icon{display:grid;place-items:center;flex:0 0 24px;font-size:16px}.sidebar-spacer{flex:1}.logout-button{background:transparent;color:#b9c5da}.admin-main{width:100%;max-width:1280px;margin:0 auto;padding:30px 34px}.admin-panel[hidden]{display:none}.panel-heading{margin-bottom:18px}.panel-heading h2{margin-bottom:4px}
details.token-card{padding:0;overflow:hidden}details.token-card>summary{list-style:none}details.token-card>summary::-webkit-details-marker{display:none}.token-summary{display:grid;grid-template-columns:minmax(220px,1.5fr) minmax(150px,1fr) minmax(180px,1fr) minmax(220px,1.2fr) auto;align-items:center;gap:16px;padding:17px 19px;cursor:pointer;user-select:none}.token-summary:hover{background:#f8faff}.token-summary-title{font-size:16px;font-weight:750;min-width:0}.token-summary-title>span:first-child{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.token-summary-meta{min-width:0}.token-summary-meta strong,.token-summary-meta span{display:block}.token-summary-meta strong{font-size:12px;color:var(--muted);margin-bottom:2px}.token-summary-meta span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.summary-toggle{color:var(--brand);font-weight:700;white-space:nowrap}.summary-toggle::after{content:'Show settings'}.summary-toggle::before{content:'+';display:inline-block;margin-right:6px;font-size:18px;line-height:1}details[open] .summary-toggle::after{content:'Hide settings'}details[open] .summary-toggle::before{content:'−'}.token-details{border-top:1px solid var(--line);padding:20px}.token-details>.top{margin-bottom:14px}
@media(max-width:980px){.token-summary{grid-template-columns:minmax(180px,1.4fr) minmax(130px,1fr) minmax(160px,1fr) auto}.token-summary-meta.permissions{display:none}}
@media(max-width:800px){.admin-shell{grid-template-columns:68px minmax(0,1fr)}.admin-sidebar{padding:18px 8px}.brand-copy,.nav-label{display:none}.admin-brand{padding:0 9px}.nav-item{justify-content:center;padding:11px}.admin-main{padding:24px 20px}.grid{grid-template-columns:1fr}.span2,.span4{grid-column:span 1}.top{align-items:flex-start}.checks{padding-top:4px;flex-wrap:wrap}.token-summary{grid-template-columns:minmax(150px,1fr) minmax(120px,.8fr) auto;padding:15px}.token-summary-meta.expires{display:none}}
@media(max-width:520px){.admin-shell{grid-template-columns:58px minmax(0,1fr)}.admin-sidebar{padding:14px 5px}.admin-main{padding:18px 12px}.top{flex-direction:column}.token-summary{grid-template-columns:minmax(0,1fr) auto}.token-summary-meta{display:none}.summary-toggle::after{content:'Show'}details[open] .summary-toggle::after{content:'Hide'}.card{padding:16px}.token-details{padding:16px}.path-grant-row{grid-template-columns:1fr}}
"""


def _page(title: str, body: str) -> str:
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(title)}</title><style>{STYLE}</style></head><body>{body}</body></html>"""


def render_discovery(payload: dict) -> str:
    pretty_json = html.escape(json.dumps(payload, ensure_ascii=False, indent=2))
    capabilities = payload["capabilities"]
    files = capabilities["files"]
    body = f"""<main><header class="top"><div><h1>{html.escape(payload['name'])}</h1><div class="muted">OpenKapsel Discovery · {html.escape(payload['protocol'])}</div></div><span class="badge">Token valid</span></header><section class="card"><h2>Workspace</h2><div class="grid"><div class="span2"><label>Root</label><div class="token">{html.escape(payload['root'])}</div></div><div><label>File permissions</label><p>Read: {'allowed' if files['read'] else 'denied'}<br>Write: {'allowed' if files['write'] else 'denied'}</p></div><div><label>Shell</label><p>{html.escape(str(capabilities['shell']))}</p></div></div></section><section class="card"><h2>Machine-readable Discovery JSON</h2><p class="muted">API clients can send <code>Accept: application/json</code> or use curl to retrieve JSON directly.</p><pre style="margin:0;overflow:auto;background:#111827;color:#e5e7eb;padding:16px;border-radius:8px;white-space:pre-wrap;word-break:break-word">{pretty_json}</pre></section></main>"""
    return _page(f"{payload['name']} · Workspace", body)


def render_http_error(status: int, code: str, message: str, request_id: str | None = None) -> str:
    request_html = (
        f'<p class="muted">Request ID: <code>{html.escape(request_id)}</code></p>'
        if request_id
        else ""
    )
    body = f"""<main class="login"><section class="card"><span class="badge off">HTTP {status}</span><h1 style="margin-top:14px">Request failed</h1><p>{html.escape(message)}</p><div class="token">{html.escape(code)}</div>{request_html}</section></main>"""
    return _page(f"HTTP {status} · {code}", body)


def render_login(admin_path: str, error: str | None = None) -> str:
    error_html = f'<div class="error">{html.escape(error)}</div>' if error else ""
    return _page(
        "Workspace Admin Login",
        f"""<main class="login"><section class="card"><h1>Workspace Administration</h1><p class="muted">Enter your administrator credentials.</p>{error_html}<form method="post" action="{html.escape(admin_path, quote=True)}/login"><label for="username">Username</label><input id="username" name="username" autocomplete="username" required><div style="height:12px"></div><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" minlength="8" required><div style="height:18px"></div><button type="submit">Sign in</button></form></section></main>""",
    )


def _local_expiry(record: TokenRecord) -> str:
    parsed = parse_datetime(record.expires_at)
    if parsed is None:
        return ""
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M")


def _credential_expiry_label(record: TokenRecord) -> str:
    parsed = parse_datetime(record.credentials_expires_at)
    if parsed is None:
        return "No separate expiration"
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _token_status(record: TokenRecord) -> tuple[str, bool]:
    if not record.enabled:
        return "Disabled", False
    if record.expired:
        return "Workspace expired", False
    if record.credentials_expired:
        return "Credentials expired", False
    return "Valid", True


def _selected(value: str, expected: str) -> str:
    return " selected" if value == expected else ""


def _checked(value: bool) -> str:
    return " checked" if value else ""


def _shell_fields_before_network(markup: str) -> str:
    """Place each token form's Shell controls before its network controls."""
    network_marker = '<div><label>Network mode</label>'
    shell_marker = '<div><label>Shell permission</label>'
    cpu_marker = '<div><label>CPU limit (% of one core)</label>'
    cursor = 0
    while True:
        network_start = markup.find(network_marker, cursor)
        if network_start < 0:
            return markup
        shell_start = markup.find(shell_marker, network_start)
        if shell_start < 0:
            return markup
        form_end = markup.find("</form>", network_start)
        if 0 <= form_end < shell_start:
            cursor = network_start + len(network_marker)
            continue
        cpu_start = markup.find(cpu_marker, shell_start)
        if cpu_start < 0 or (0 <= form_end < cpu_start):
            cursor = network_start + len(network_marker)
            continue
        cpu_end = markup.find("</div>", cpu_start)
        if cpu_end < 0:
            return markup
        cpu_end += len("</div>")
        network_fields = markup[network_start:shell_start]
        shell_fields = markup[shell_start:cpu_end]
        markup = (
            markup[:network_start]
            + shell_fields
            + network_fields
            + markup[cpu_end:]
        )
        cursor = network_start + len(shell_fields) + len(network_fields)


def _path_grant_rows(grants: tuple[PathGrant, ...]) -> str:
    items = grants or (PathGrant(path="", read_only=True),)
    rows = []
    for grant in items:
        escaped_path = html.escape(grant.path, quote=True)
        ro_selected = " selected" if grant.read_only else ""
        rw_selected = "" if grant.read_only else " selected"
        rows.append(
            f'<div class="path-grant-row"><input name="allowed_path" value="{escaped_path}" '
            'placeholder="/var/www/html"><select name="allowed_path_mode">'
            f'<option value="ro"{ro_selected}>Read only</option>'
            f'<option value="rw"{rw_selected}>Writable</option></select></div>'
        )
    return "".join(rows)


def _image_options(images: list[WorkspaceImage], selected: str | None = None) -> str:
    names = [item.name for item in images]
    if selected and selected not in names:
        names.append(selected)
    if not names:
        return '<option value="">No images available</option>'
    return "".join(
        f'<option value="{html.escape(name, quote=True)}"{_selected(selected or "", name)}>{html.escape(name)}.img</option>'
        for name in names
    )


def _workspace_fields(record: TokenRecord | None, images: list[WorkspaceImage]) -> str:
    image_mode = record is not None and record.workspace_image is not None
    path_prefix = record.path_prefix if record is not None else ""
    selected_image = record.workspace_image if record is not None else None
    mode = "image" if image_mode else "directory"
    return (
        '<div><label>Workspace type</label><select name="workspace_type">'
        f'<option value="directory"{_selected(mode, "directory")}>Regular directory</option>'
        f'<option value="image"{_selected(mode, "image")}>Workspace image</option></select></div>'
        f'<div data-workspace-mode="directory"{" hidden" if image_mode else ""}><label>Directory name</label>'
        f'<input name="path_prefix" value="{html.escape(path_prefix, quote=True)}" placeholder="e.g. project" required></div>'
        f'<div data-workspace-mode="image"{"" if image_mode else " hidden"}><label>Workspace image</label>'
        f'<select name="workspace_image" required>{_image_options(images, selected_image)}</select></div>'
    )


def _format_bytes(value: int) -> str:
    amount = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or unit == "TiB":
            return f"{amount:.0f} {unit}" if unit in {"B", "KiB", "MiB"} else f"{amount:.2f} {unit}"
        amount /= 1024
    return f"{value} B"


def _workspace_image_card(image: WorkspaceImage, csrf: str, admin_path: str) -> str:
    name = html.escape(image.name, quote=True)
    logical_mib = image.size_bytes // (1024 * 1024)
    status = "Mounted" if image.mounted else "Not mounted"
    badge = "" if image.mounted else " off"
    return f'''<section class="card"><div class="top"><div><h2>{name}.img <span class="badge{badge}">{status}</span></h2><div class="muted">Mount directory: {name}/ · Logical size {_format_bytes(image.size_bytes)} · Currently allocated {_format_bytes(image.allocated_bytes)}</div></div></div><div class="actions"><form method="post" action="{admin_path}/images"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="grow"><input type="hidden" name="name" value="{name}"><label>New total size (MiB)</label><input type="number" name="size_mib" value="{logical_mib}" min="{logical_mib}" max="16777216" required><button type="submit">Expand / Retry</button></form><form method="post" action="{admin_path}/images" onsubmit="return confirm('This permanently deletes the image and all of its data. This action cannot be undone. Continue?')"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="delete"><input type="hidden" name="name" value="{name}"><button class="danger" type="submit">Permanently delete image</button></form></div></section>'''


def _sandbox_backend_options(
    sandbox_backends: tuple[str, ...],
    sandbox_default_backend: str,
    podman_default_image: str,
    podman_images: tuple[str, ...],
    *,
    selected_backend: str = "auto",
    selected_image: str | None = None,
) -> str:
    backend_labels = {"bubblewrap": "Bubblewrap", "podman": "Podman"}
    default_label = backend_labels[sandbox_default_backend]
    if sandbox_default_backend == "podman":
        default_label += f" · {podman_default_image}"
    options = [
        f'<option value="auto"{_selected(selected_backend,"auto")}>Auto (default: {html.escape(default_label)})</option>'
    ]
    if "bubblewrap" in sandbox_backends:
        options.append(
            f'<option value="bubblewrap"{_selected(selected_backend,"bubblewrap")}>Bubblewrap</option>'
        )
    selected_podman_image = (
        (selected_image or podman_default_image)
        if selected_backend == "podman"
        else None
    )
    if "podman" in sandbox_backends:
        images = list(podman_images)
        if selected_podman_image and selected_podman_image not in images:
            images.append(selected_podman_image)
        for image in images:
            selected = selected_backend == "podman" and image == selected_podman_image
            unavailable = image not in podman_images
            suffix = " (not installed)" if unavailable else ""
            value = html.escape(f"podman::{image}", quote=True)
            label = html.escape(f"Podman · {image}{suffix}")
            selected_attribute = " selected" if selected else ""
            options.append(
                f'<option value="{value}"{selected_attribute}>{label}</option>'
            )
        if not images:
            options.append('<option value="" disabled>Podman · no installed images</option>')
    return "".join(options)


def render_dashboard(
    records: list[TokenRecord],
    csrf: str,
    public_base_url: str,
    preview_base_url: str,
    workspace_name: str,
    admin_path: str,
    sandbox_resources_available: bool,
    sandbox_resources_reason: str,
    sandbox_backends: tuple[str, ...],
    sandbox_default_backend: str,
    podman_default_image: str,
    podman_images: tuple[str, ...],
    workspace_images: list[WorkspaceImage],
    workspace_images_error: str | None,
    error: str | None = None,
    success: str | None = None,
    active_panel: str = "tokens",
    default_network_domains: tuple[str, ...] = (),
) -> str:
    esc_csrf = html.escape(csrf, quote=True)
    error_html = f'<div class="error">{html.escape(error)}</div>' if error else ""
    success_html = f'<div class="success">{html.escape(success)}</div>' if success else ""
    escaped_admin_path = html.escape(admin_path, quote=True)
    create_path_rows = _path_grant_rows(())
    create_domains = html.escape("\n".join(default_network_domains), quote=True)
    create_backend_options = _sandbox_backend_options(
        sandbox_backends,
        sandbox_default_backend,
        podman_default_image,
        podman_images,
    )
    cards = "".join(
        _token_card(
            item,
            esc_csrf,
            public_base_url,
            preview_base_url,
            escaped_admin_path,
            sandbox_backends,
            sandbox_default_backend,
            podman_default_image,
            podman_images,
            workspace_images,
        )
        for item in records
    )
    if not cards:
        cards = '<section class="card"><p class="muted">No tokens exist yet. Create one to get started.</p></section>'
    sandbox_status = (
        '<span class="badge">cgroup v2 resource limits available</span>'
        if sandbox_resources_available
        else '<span class="badge off">cgroup v2 resource limits unavailable</span>'
    )
    sandbox_reason = (
        ""
        if sandbox_resources_available
        else f'<span class="muted"> · {html.escape(sandbox_resources_reason)}</span>'
    )
    active_panel = active_panel if active_panel in {"tokens", "images", "password"} else "tokens"
    tokens_hidden = " hidden" if active_panel != "tokens" else ""
    images_hidden = " hidden" if active_panel != "images" else ""
    password_hidden = " hidden" if active_panel != "password" else ""
    image_status = (
        f'<div class="error">{html.escape(workspace_images_error)}</div>'
        if workspace_images_error
        else ""
    )
    image_cards = "".join(
        _workspace_image_card(item, esc_csrf, escaped_admin_path)
        for item in workspace_images
    ) or '<section class="card"><p class="muted">No workspace images exist yet.</p></section>'
    create_workspace_fields = _workspace_fields(None, workspace_images)
    body = f"""
<div class="admin-shell" data-initial-panel="{active_panel}">
<aside class="admin-sidebar"><div class="admin-brand"><span class="brand-mark">K</span><div class="brand-copy"><strong>OpenKapsel</strong><span>Administration</span></div></div><nav class="admin-nav" aria-label="Administration"><button type="button" class="nav-item" data-admin-tab="tokens" aria-controls="panel-tokens" title="Token management"><span class="nav-icon" aria-hidden="true">◆</span><span class="nav-label">Token management</span></button><button type="button" class="nav-item" data-admin-tab="images" aria-controls="panel-images" title="Workspace images"><span class="nav-icon" aria-hidden="true">▣</span><span class="nav-label">Workspace images</span></button><button type="button" class="nav-item" data-admin-tab="password" aria-controls="panel-password" title="Change password"><span class="nav-icon" aria-hidden="true">●</span><span class="nav-label">Change password</span></button></nav><div class="sidebar-spacer"></div><form method="post" action="{escaped_admin_path}/logout"><input type="hidden" name="csrf" value="{esc_csrf}"><button class="nav-item logout-button" title="Sign out"><span class="nav-icon" aria-hidden="true">↪</span><span class="nav-label">Sign out</span></button></form></aside>
<main class="admin-main"><header class="top"><div><h1>{html.escape(workspace_name)} · Administration</h1><div class="muted">Tokens, expiration, and capability grants</div></div></header>{error_html}{success_html}
<section id="panel-tokens" class="admin-panel" data-admin-panel="tokens"{tokens_hidden}><div class="panel-heading"><h2>Token management</h2><div class="muted">Valid tokens appear first. Expand an entry to edit advanced settings.</div></div>
<h2>Existing tokens ({len(records)})</h2>{cards}
<section class="card"><h2>Create token</h2><form method="post" action="{escaped_admin_path}/tokens"><input type="hidden" name="csrf" value="{esc_csrf}"><input type="hidden" name="action" value="create"><div class="grid"><div class="token-name-field"><label>Name</label><input name="name" placeholder="e.g. ChatGPT demo project" required maxlength="200"></div><div><label>Lifetime</label><select name="ttl_hours"><option value="24">1 day</option><option value="168" selected>7 days</option><option value="720">30 days</option><option value="2184">91 days</option><option value="8760">365 days</option><option value="17520">730 days</option><option value="">Never expires</option></select></div><div><label>Workspace directory</label><input name="path_prefix" placeholder="e.g. project" required></div><div class="span2 checks"><label><input type="checkbox" name="can_read" checked>Read</label><label><input type="checkbox" name="can_write">Write</label><label><input type="checkbox" name="can_preview">Web preview</label></div><div><label>Network mode</label><select name="network_mode"><option value="none">Disabled</option><option value="domain_allowlist" selected>Allowed domains only</option><option value="full">Full network</option></select></div><div class="span2"><label>Allowed network domains</label><textarea name="allowed_domains" placeholder="One exact domain or .suffix rule per line">{create_domains}</textarea></div><div><label>Shell permission</label><select name="shell_mode"><option value="none">Disabled</option><option value="restricted" selected>Restricted (Bubblewrap)</option><option value="full">Full (dangerous)</option></select></div><div><label>Process/thread limit</label><input type="number" name="sandbox_max_processes" value="64" min="1" max="4096" required></div><div><label>Memory limit (MiB)</label><input type="number" name="sandbox_memory_mb" value="256" min="16" max="1048576" required></div><div><label>CPU limit (% of one core)</label><input type="number" name="sandbox_cpu_percent" value="100" min="1" max="4096" required></div><div class="span4"><label>Additional accessible directories</label><div id="create-path-grants">{create_path_rows}</div><button class="secondary" type="button" onclick="addPathGrant('create-path-grants')">Add directory</button></div><div class="span4 actions"><button type="submit">Create token</button></div></div></form><div class="notice">{sandbox_status}{sandbox_reason}<br>Allowed-domain networking supports HTTP, HTTPS, WebSocket, and HTTPS Git operations. Direct IP, SSH, Git protocol, and UDP access remain blocked. Full Shell inherits OpenKapsel privileges directly and does not treat token network settings as a security boundary.</div></section></section>
<section id="panel-password" class="admin-panel" data-admin-panel="password"{password_hidden}><div class="panel-heading"><h2>Change password</h2><div class="muted">Update administration login credentials.</div></div><section class="card"><h2>Change administrator password</h2><form method="post" action="{escaped_admin_path}/password"><input type="hidden" name="csrf" value="{esc_csrf}"><div class="grid"><div><label for="old-password">Current password</label><input id="old-password" name="old_password" type="password" autocomplete="current-password" required></div><div><label for="new-password">New password</label><input id="new-password" name="new_password" type="password" autocomplete="new-password" minlength="12" required></div><div><label for="confirm-password">Repeat new password</label><input id="confirm-password" name="confirm_password" type="password" autocomplete="new-password" minlength="12" required></div><div class="checks"><button type="submit">Change password</button></div></div></form><p class="muted">The new password must contain at least 12 characters. Other administration sessions are invalidated immediately after a successful change.</p></section></section>
</main></div><script>function setAdminPanel(name,updateHash){{if(name!=='tokens'&&name!=='password')name='tokens';document.querySelectorAll('[data-admin-tab]').forEach(button=>{{const active=button.dataset.adminTab===name;button.classList.toggle('active',active);button.setAttribute('aria-selected',active?'true':'false')}});document.querySelectorAll('[data-admin-panel]').forEach(panel=>{{panel.hidden=panel.dataset.adminPanel!==name}});if(updateHash)history.replaceState(null,'','#'+name)}}document.querySelectorAll('[data-admin-tab]').forEach(button=>button.addEventListener('click',()=>setAdminPanel(button.dataset.adminTab,true)));const requested=location.hash.slice(1);const initial=(requested==='tokens'||requested==='password')?requested:document.querySelector('.admin-shell').dataset.initialPanel;setAdminPanel(initial,false);async function writeClipboard(text,button){{await navigator.clipboard.writeText(text);const old=button.textContent;button.textContent='Copied';setTimeout(()=>button.textContent=old,1200)}}function copyToken(id,button){{return writeClipboard(document.getElementById(id).textContent,button)}}function copyUrlAndToken(urlId,controlId,button){{const url=document.getElementById(urlId).textContent;const control=document.getElementById(controlId).textContent;return writeClipboard(url+'\\n'+control,button)}}function addPathGrant(id){{document.getElementById(id).insertAdjacentHTML('beforeend','<div class="path-grant-row"><input name="allowed_path" placeholder="/var/www/html"><select name="allowed_path_mode"><option value="ro">Read only</option><option value="rw">Writable</option></select></div>')}} </script>"""
    body = body.replace(
        '<div><label>Workspace directory</label><input name="path_prefix" placeholder="e.g. project" required></div>',
        create_workspace_fields,
        1,
    )
    images_panel = f'''<section id="panel-images" class="admin-panel" data-admin-panel="images"{images_hidden}><div class="panel-heading"><h2>Workspace images</h2><div class="muted">Sparse ext4 images mount at same-named workspace directories. Images can only be expanded.</div></div>{image_status}<h2>Existing images ({len(workspace_images)})</h2>{image_cards}<section class="card"><h2>Create workspace image</h2><form method="post" action="{escaped_admin_path}/images"><input type="hidden" name="csrf" value="{esc_csrf}"><input type="hidden" name="action" value="create"><div class="grid"><div><label>Name</label><input name="name" placeholder="e.g. project" pattern="[A-Za-z0-9][A-Za-z0-9_-]{{0,63}}" required></div><div><label>Size (MiB)</label><input type="number" name="size_mib" value="256" min="64" max="16777216" required></div><div class="checks"><button type="submit"{' disabled' if workspace_images_error else ''}>Create and mount</button></div></div></form><p class="muted">The image file is <code>name.img</code> and mounts at the same-named directory under Workspace Root. Its logical capacity allocates host disk space on demand.</p></section></section>'''
    body = body.replace(
        '<section id="panel-password"', images_panel + '<section id="panel-password"', 1
    )
    body = body.replace(
        "if(name!=='tokens'&&name!=='password')name='tokens'",
        "if(!['tokens','images','password'].includes(name))name='tokens'",
        1,
    ).replace(
        "const initial=(requested==='tokens'||requested==='password')?requested:",
        "const initial=['tokens','images','password'].includes(requested)?requested:",
        1,
    ).replace(
        "async function writeClipboard",
        "function setWorkspaceType(select){const form=select.closest('form');form.querySelectorAll('[data-workspace-mode]').forEach(group=>{const active=group.dataset.workspaceMode===select.value;group.hidden=!active;group.querySelectorAll('input,select').forEach(input=>input.disabled=!active)})}document.querySelectorAll('select[name=workspace_type]').forEach(select=>{select.addEventListener('change',()=>setWorkspaceType(select));setWorkspaceType(select)});async function writeClipboard",
        1,
    )
    create_shell = (
        '<div><label>Shell permission</label><select name="shell_mode"><option value="none">Disabled</option>'
        '<option value="restricted" selected>Restricted (Bubblewrap)</option>'
        '<option value="full">Full (dangerous)</option></select></div>'
    )
    body = body.replace(
        create_shell,
        create_shell.replace("Restricted (Bubblewrap)", "Restricted")
        + f'<div><label>Restricted Shell backend</label><select name="sandbox_backend">{create_backend_options}</select></div>',
        1,
    )
    body = body.replace(
        "Workspace expiration (UTC; blank means never)",
        "Workspace expiration",
    )
    body = _shell_fields_before_network(body)
    return _page("Workspace Administration", body)


def _token_card(
    record: TokenRecord,
    csrf: str,
    public_base_url: str,
    preview_base_url: str,
    admin_path: str,
    sandbox_backends: tuple[str, ...],
    sandbox_default_backend: str,
    podman_default_image: str,
    podman_images: tuple[str, ...],
    workspace_images: list[WorkspaceImage],
) -> str:
    """Add independent read/control credential controls to the token card."""
    backend_options = _sandbox_backend_options(
        sandbox_backends,
        sandbox_default_backend,
        podman_default_image,
        podman_images,
        selected_backend=record.sandbox_backend,
        selected_image=record.sandbox_image,
    )
    card = _token_card_base(
        record, csrf, public_base_url, preview_base_url, admin_path,
        sandbox_backends, sandbox_default_backend, podman_default_image,
        podman_images, workspace_images,
    )
    card = card.replace(
        f'<div><label>Workspace directory</label><input name="path_prefix" value="{html.escape(record.path_prefix, quote=True)}" required></div>',
        _workspace_fields(record, workspace_images),
        1,
    )
    card = card.replace(
        f'<option value="restricted"{_selected(record.shell_mode,"restricted")}>Restricted</option>',
        f'<option value="restricted"{_selected(record.shell_mode,"restricted")}>Restricted (Bubblewrap)</option>',
        1,
    )
    shell_select = (
        '<div><label>Shell permission</label><select name="shell_mode">'
        f'<option value="none"{_selected(record.shell_mode,"none")}>Disabled</option>'
        f'<option value="restricted"{_selected(record.shell_mode,"restricted")}>Restricted (Bubblewrap)</option>'
        f'<option value="full"{_selected(record.shell_mode,"full")}>Full (dangerous)</option>'
        '</select></div>'
    )
    card = card.replace(
        shell_select,
        shell_select.replace("Restricted (Bubblewrap)", "Restricted")
        + f'<div><label>Restricted Shell backend</label><select name="sandbox_backend">{backend_options}</select></div>',
        1,
    )
    token_key = "".join(char for char in record.token if char.isalnum())[:18]
    workspace_url_id = "url-" + token_key
    mcp_url_id = "mcp-" + token_key
    control_id = "control-" + token_key
    control_header = html.escape(f"Authorization: Bearer {record.control_token}")
    credential_expiry_label = html.escape(_credential_expiry_label(record))
    escaped_token = html.escape(record.token, quote=True)
    renew_block = (
        '<div class="notice"><strong>Read/control credential expiration</strong><br>'
        f'{credential_expiry_label}<form method="post" action="{admin_path}/tokens" '
        'class="actions" style="margin-top:10px" '
        'onsubmit="return confirm(\'Renewing replaces both the read-only URL token and control token immediately. The preview token stays unchanged. Continue?\')">'
        f'<input type="hidden" name="csrf" value="{csrf}">'
        f'<input type="hidden" name="token" value="{escaped_token}">'
        '<input type="hidden" name="action" value="renew">'
        '<label style="margin:0">Renew for <input type="number" name="renew_days" value="3" min="1" max="30" required style="width:82px"> days</label>'
        '<button type="submit">Renew read + control tokens</button></form>'
        '<span class="muted">Renewal does not change the preview token or workspace lifetime.</span></div>'
    )
    control_block = (
        renew_block
        + '<label>Control token (write, upload, Shell, and MCP)</label>'
        f'<div class="token" id="{control_id}">{control_header}</div>'
        '<div class="actions">'
        f'<button type="button" class="secondary" onclick="copyToken(\'{control_id}\',this)">'
        "Copy Authorization header</button>"
        f'<button type="button" class="secondary" onclick="copyUrlAndToken(\'{workspace_url_id}\',\'{control_id}\',this)">'
        "Copy URL + control token</button></div>"
    )
    card = card.replace(
        '<label>MCP Streamable HTTP URL</label>',
        control_block
        + '<label style="margin-top:12px">MCP Streamable HTTP URL (send the header above with every request)</label>',
        1,
    )
    mcp_actions = (
        '<div class="actions" style="margin:10px 0 12px">'
        f'<button type="button" class="secondary" onclick="copyToken(\'{mcp_url_id}\',this)">'
        "Copy MCP URL</button>"
        f'<button type="button" class="secondary" onclick="copyUrlAndToken(\'{mcp_url_id}\',\'{control_id}\',this)">'
        "Copy MCP URL + control token</button></div>"
    )
    card = card.replace(
        '<label>Web preview URL (independent read-only credential)</label>',
        mcp_actions + '<label>Web preview URL (independent read-only credential)</label>',
        1,
    )
    card = card.replace('name="action" value="rotate_token"', 'name="action" value="rotate_read"', 1)
    card = card.replace("Regenerate primary token", "Regenerate read-only URL token", 1)
    card = card.replace(
        "Regenerating immediately invalidates the previous Workspace and MCP URLs; workspace and permission settings remain unchanged.",
        "Regenerating immediately invalidates the previous read-only Workspace and MCP URLs; the control token and settings remain unchanged.",
        1,
    )
    control_form = (
        f'<form method="post" action="{admin_path}/tokens" '
        "onsubmit=\"return confirm('Regenerating immediately invalidates the previous control token; read-only and preview URLs and settings remain unchanged. Continue?')\">"
        f'<input type="hidden" name="csrf" value="{csrf}">'
        f'<input type="hidden" name="token" value="{escaped_token}">'
        '<input type="hidden" name="action" value="rotate_control">'
        '<button class="secondary" type="submit">Regenerate control token</button></form>'
    )
    card = card.replace(
        '<div class="actions" style="margin:10px 0">',
        '<div class="actions" style="margin:10px 0">' + control_form,
        1,
    )
    return _collapsible_token_card(card, record)


def _collapsible_token_card(card: str, record: TokenRecord) -> str:
    status, usable = _token_status(record)
    invalid_class = "" if usable else " invalid"
    badge_class = "" if usable else " off"
    expires = _local_expiry(record)
    expires_label = expires.replace("T", " ") + " UTC" if expires else "Never expires"
    capabilities = []
    if record.can_read:
        capabilities.append("Read")
    if record.can_write:
        capabilities.append("Write")
    if record.can_preview:
        capabilities.append("Preview")
    network_labels = {
        "none": "Network Disabled",
        "domain_allowlist": "Domain Network",
        "full": "Full Network",
    }
    capabilities.append(network_labels.get(record.network_mode, record.network_mode))
    shell_labels = {"none": "Shell Disabled", "restricted": "Restricted Shell", "full": "Full Shell"}
    capabilities.append(shell_labels.get(record.shell_mode, record.shell_mode))
    _, separator, remainder = card.partition(">")
    if not separator or not remainder.endswith("</section>"):
        return card
    content = remainder.removesuffix("</section>")
    return f"""<details class="card token-card{invalid_class}"><summary class="token-summary"><div class="token-summary-title"><span>{html.escape(record.name)}</span><span class="badge{badge_class}">{status}</span></div><div class="token-summary-meta"><strong>Workspace</strong><span>{html.escape(record.path_prefix)}</span></div><div class="token-summary-meta expires"><strong>Workspace lifetime</strong><span>{html.escape(expires_label)}</span></div><div class="token-summary-meta permissions"><strong>Permissions</strong><span>{html.escape(' · '.join(capabilities))}</span></div><span class="summary-toggle" aria-hidden="true"></span></summary><div class="token-details">{content}</div></details>"""


def _token_card_base(
    record: TokenRecord,
    csrf: str,
    public_base_url: str,
    preview_base_url: str,
    admin_path: str,
    sandbox_backends: tuple[str, ...],
    sandbox_default_backend: str,
    podman_default_image: str,
    podman_images: tuple[str, ...],
    workspace_images: list[WorkspaceImage],
) -> str:
    token_escaped = html.escape(record.token, quote=True)
    token_url = f"{public_base_url.rstrip('/')}/w/{quote(record.token, safe='')}/"
    token_url_escaped = html.escape(token_url)
    mcp_url_escaped = html.escape(token_url + "mcp")
    preview_url = (
        f"{preview_base_url.rstrip('/')}/{quote(record.preview_token, safe='')}/"
    )
    preview_url_escaped = html.escape(preview_url)
    element_id = "url-" + "".join(char for char in record.token if char.isalnum())[:18]
    mcp_element_id = "mcp-" + "".join(char for char in record.token if char.isalnum())[:18]
    preview_element_id = "preview-" + "".join(char for char in record.token if char.isalnum())[:18]
    status, usable = _token_status(record)
    invalid_class = "" if usable else " invalid"
    badge_class = "" if usable else " off"
    path_container_id = "paths-" + "".join(char for char in record.token if char.isalnum())[:18]
    path_rows = _path_grant_rows(record.allowed_paths)
    domain_text = html.escape("\n".join(record.allowed_domains))
    return f"""<section class="card token-card{invalid_class}"><div class="top"><div><h2>{html.escape(record.name)} <span class="badge{badge_class}">{status}</span></h2><div class="muted">Created {html.escape(record.created_at)} · The full token is shown only on this administration page</div></div><div class="actions"><button type="button" class="secondary" onclick="copyToken('{element_id}',this)">Copy Workspace URL</button><button type="button" class="secondary" onclick="copyToken('{preview_element_id}',this)">Copy web preview URL</button></div></div><label>Workspace URL</label><div class="token" id="{element_id}">{token_url_escaped}</div><label>MCP Streamable HTTP URL</label><div class="token" id="{mcp_element_id}">{mcp_url_escaped}</div><label>Web preview URL (independent read-only credential)</label><div class="token" id="{preview_element_id}">{preview_url_escaped}</div><div class="actions" style="margin:10px 0"><form method="post" action="{admin_path}/tokens" onsubmit="return confirm('Regenerating immediately invalidates the previous Workspace and MCP URLs; workspace and permission settings remain unchanged. Continue?')"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="token" value="{token_escaped}"><input type="hidden" name="action" value="rotate_token"><button class="secondary" type="submit">Regenerate primary token</button></form><form method="post" action="{admin_path}/tokens" onsubmit="return confirm('Regenerating immediately invalidates the previous preview URL. Continue?')"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="token" value="{token_escaped}"><input type="hidden" name="action" value="rotate_preview"><button class="secondary" type="submit">Regenerate preview token</button></form></div><form method="post" action="{admin_path}/tokens"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="token" value="{token_escaped}"><input type="hidden" name="action" value="update"><div class="grid"><div class="token-name-field"><label>Name</label><input name="name" value="{html.escape(record.name, quote=True)}" required maxlength="200"></div><div><label>Workspace expiration (UTC; blank means never)</label><input type="datetime-local" name="expires_at" value="{_local_expiry(record)}"></div><div><label>Workspace directory</label><input name="path_prefix" value="{html.escape(record.path_prefix, quote=True)}" required></div><div class="span2 checks"><label><input type="checkbox" name="can_read"{_checked(record.can_read)}>Read</label><label><input type="checkbox" name="can_write"{_checked(record.can_write)}>Write</label><label><input type="checkbox" name="can_preview"{_checked(record.can_preview)}>Web preview</label><label><input type="checkbox" name="enabled"{_checked(record.enabled)}>Enabled</label></div><div><label>Network mode</label><select name="network_mode"><option value="none"{_selected(record.network_mode,'none')}>Disabled</option><option value="domain_allowlist"{_selected(record.network_mode,'domain_allowlist')}>Allowed domains only</option><option value="full"{_selected(record.network_mode,'full')}>Full network</option></select></div><div class="span2"><label>Allowed network domains</label><textarea name="allowed_domains" placeholder="One exact domain or .suffix rule per line">{domain_text}</textarea></div><div><label>Shell permission</label><select name="shell_mode"><option value="none"{_selected(record.shell_mode,'none')}>Disabled</option><option value="restricted"{_selected(record.shell_mode,'restricted')}>Restricted</option><option value="full"{_selected(record.shell_mode,'full')}>Full (dangerous)</option></select></div><div><label>Process/thread limit</label><input type="number" name="sandbox_max_processes" value="{record.sandbox_max_processes}" min="1" max="4096" required></div><div><label>Memory limit (MiB)</label><input type="number" name="sandbox_memory_mb" value="{record.sandbox_memory_mb}" min="16" max="1048576" required></div><div><label>CPU limit (% of one core)</label><input type="number" name="sandbox_cpu_percent" value="{record.sandbox_cpu_percent}" min="1" max="4096" required></div><div class="span4"><label>Additional accessible directories</label><div id="{path_container_id}">{path_rows}</div><button class="secondary" type="button" onclick="addPathGrant('{path_container_id}')">Add directory</button></div><div class="span4 actions"><button type="submit">Save changes</button></div></div></form><form method="post" action="{admin_path}/tokens" class="actions" style="margin-top:10px" onsubmit="return confirm('Permanently delete this token?')"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="token" value="{token_escaped}"><input type="hidden" name="action" value="delete"><button class="danger" type="submit">Permanently delete</button></form></section>"""

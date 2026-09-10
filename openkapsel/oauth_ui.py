"""Administrative OAuth connection cards (never display bearer credentials)."""

import html
import json
import time
from datetime import datetime, timezone


def render_connections(connections, records, csrf, admin_path, public_base_url, *, static=False):
    esc = html.escape

    def stamp(value):
        return datetime.fromtimestamp(value, timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if value else "Never"

    common = f'<input type="hidden" name="csrf" value="{esc(csrf, quote=True)}">'
    records_by_id = {record.app_id: record for record in records}
    groups = {}
    action_path = admin_path + ("/static-mcp" if static else "/oauth")
    panel = "static-mcp" if static else "connections"
    title = "Static MCP connections" if static else "OAuth connections"
    from .static_mcp import EXPIRY_DAYS
    days_options = ''.join(f'<option value="{days}"' + (' selected' if days == 365 else '') + f'>{days} days</option>' for days in EXPIRY_DAYS)
    available_records = [record for record in records if record.valid and record.path_prefix != "."]

    def workspace_options(selected=None):
        return "".join(
            f'<option value="{esc(record.app_id)}"{(" selected" if record.app_id == selected else "")}>{esc(record.name)} — {esc(record.path_prefix)}</option>'
            for record in available_records
        )

    for conn in connections:
        cid = conn["id"]
        record = records_by_id.get(conn["app_id"])
        status = "Authenticated" if conn.get("authenticated_at") else "Awaiting token exchange" if conn.get("client_id") else "Pending authorization"
        if record is None or not record.valid or record.path_prefix != conn["workspace"]:
            status = "Unavailable"
        metadata = json.loads(conn["metadata"]) if conn.get("metadata") else {}
        callbacks = "<br>".join(esc(uri) for uri in metadata.get("redirect_uris", [])) or "Not registered"
        url = public_base_url.rstrip("/") + "/connect/" + cid + "/mcp"
        if static:
            status = "Active" if conn["expires_at"] > time.time() else "Expired"
            if record is None or not record.valid or record.path_prefix != conn["workspace"]:
                status = "Unavailable"
            url = public_base_url.rstrip("/") + "/mcp-connect/" + cid + "/mcp"
        comment_class = "" if static else "span2"
        edit = f'''<form method="post" action="{esc(action_path)}">{common}<input type="hidden" name="action" value="update"><input type="hidden" name="connection_id" value="{cid}"><div class="grid"><div class="{comment_class}"><label>Comment</label><input name="comment" value="{esc(conn['comment'], quote=True)}" maxlength="200" required></div><div><label>Workspace configuration</label><select name="app_id" required>{workspace_options(conn['app_id'])}</select></div>'''
        if static:
            edit += '<div><label>Reset expiration from now</label><select name="days"><option value="" selected>Keep current expiration</option>' + days_options.replace(' selected', '') + '</select></div>'
        edit += '<div class="checks"><button>Save changes</button></div></div></form>'
        copy_json = ''
        if static:
            config = json.dumps({"mcpServers": {"openkapsel": {"type": "http", "url": url, "headers": {"Authorization": "Bearer " + conn["secret"]}}}}, indent=2)
            copy_json = f'''<pre id="json-{cid}" hidden>{esc(config)}</pre><button type="button" onclick="copyToken('json-{cid}',this)">Copy MCP JSON</button>'''
            status_class = "" if status == "Active" else " off"
            status_line = f'''<div class="connection-status-row"><span class="badge{status_class}">{status}</span><span class="muted">Expires: {stamp(conn['expires_at'])}</span></div>'''
        else:
            status_class = " off" if status == "Unavailable" else ""
            status_line = f'''<div class="connection-status-row"><span class="badge{status_class}">{status}</span></div>'''
        group = groups.setdefault(conn['workspace'], [])
        group.append(f'''<section class="card"><h3>{esc(conn['comment'])}</h3>
            {status_line}
            <code id="oauth-{cid}" style="overflow-wrap:anywhere">{esc(url)}</code>
            <div class="actions"><button type="button" onclick="copyToken('oauth-{cid}',this)">Copy MCP URL</button>{copy_json}</div>
            {edit}
            <p class="muted">Created: {stamp(conn['created_at'])}<br>Last used: {stamp(conn['last_used_at'])}</p>
            <details><summary>Client registration</summary><p>First authorized: {stamp(conn.get('authenticated_at'))}<br>Last authorized: {stamp(conn.get('last_authorized_at'))}<br>Client: {esc(metadata.get('client_name', 'Not bound'))}<br>Client ID: {esc(conn.get('client_id') or 'Not bound')}</p><p style="overflow-wrap:anywhere">Redirect URIs:<br>{callbacks}</p></details>
            <form method="post" action="{esc(action_path)}" onsubmit="return confirm('Delete this connection and revoke its credentials?')">{common}<input type="hidden" name="action" value="delete"><input type="hidden" name="connection_id" value="{cid}"><button class="danger">Delete connection</button></form></section>''')
        if static:
            start = group[-1].index('<details>')
            end = group[-1].index('</details>', start) + len('</details>')
            group[-1] = group[-1][:start] + group[-1][end:]
    options = workspace_options()
    cards = ''.join(f'<section class="connection-group"><h3>Project: {esc(workspace)}</h3>{"".join(items)}</section>' for workspace, items in sorted(groups.items()))
    expiry_field = '<div><label>Expiration from now</label><select name="days">' + days_options + '</select></div>' if static else ''
    return f'''<section id="panel-{panel}" class="admin-panel" data-admin-panel="{panel}" hidden>
        <div class="panel-heading"><h2>{title}</h2><p class="muted">Each connection inherits its linked workspace configuration's permissions. Deletion revokes access without deleting workspace files.</p></div>
        {cards or '<p>No connections yet.</p>'}
        <section class="card"><h3>Create connection</h3><form method="post" action="{esc(action_path)}">{common}<input type="hidden" name="action" value="create"><div class="grid"><div><label>Comment</label><input name="comment" maxlength="200" required placeholder="e.g. Personal client"></div><div><label>Workspace configuration</label><select name="app_id" required>{options}</select></div>{expiry_field}<div class="checks"><button>Create connection</button></div></div></form></section></section>'''

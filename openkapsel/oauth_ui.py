"""Administrative OAuth connection cards (never display bearer credentials)."""

import html
import json
from datetime import datetime, timezone


def render_connections(connections, records, csrf, admin_path, public_base_url):
    esc = html.escape

    def stamp(value):
        return datetime.fromtimestamp(value, timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if value else "Never"

    common = f'<input type="hidden" name="csrf" value="{esc(csrf, quote=True)}">'
    records_by_id = {record.app_id: record for record in records}
    cards = []
    for conn in connections:
        cid = conn["id"]
        record = records_by_id.get(conn["app_id"])
        status = "Authenticated" if conn["authenticated_at"] else "Awaiting token exchange" if conn["client_id"] else "Pending authorization"
        if record is None or not record.valid or record.path_prefix != conn["workspace"]:
            status = "Unavailable"
        metadata = json.loads(conn["metadata"]) if conn.get("metadata") else {}
        callbacks = "<br>".join(esc(uri) for uri in metadata.get("redirect_uris", [])) or "Not registered"
        url = public_base_url.rstrip("/") + "/connect/" + cid + "/mcp"
        cards.append(f'''<section class="card"><h3>{esc(conn['comment'])}</h3>
            <p>{esc(conn['workspace'])} · {status}</p>
            <code id="oauth-{cid}" style="overflow-wrap:anywhere">{esc(url)}</code>
            <div class="actions"><button type="button" onclick="copyToken('oauth-{cid}',this)">Copy MCP URL</button></div>
            <p class="muted">Created: {stamp(conn['created_at'])}<br>First authorized: {stamp(conn['authenticated_at'])}<br>Last authorized: {stamp(conn['last_authorized_at'])}<br>Last used: {stamp(conn['last_used_at'])}</p>
            <details><summary>Client registration</summary><p>Client: {esc(metadata.get('client_name', 'Not bound'))}<br>Client ID: {esc(conn['client_id'] or 'Not bound')}</p><p style="overflow-wrap:anywhere">Redirect URIs:<br>{callbacks}</p></details>
            <form method="post" action="{esc(admin_path)}/oauth" onsubmit="return confirm('Delete this connection and revoke all its OAuth credentials?')">{common}<input type="hidden" name="action" value="delete"><input type="hidden" name="connection_id" value="{cid}"><button class="danger">Delete connection</button></form></section>''')
    options = "".join(f'<option value="{esc(r.app_id)}">{esc(r.name)} — {esc(r.path_prefix)}</option>' for r in records if r.valid and r.path_prefix != ".")
    return f'''<section id="panel-connections" class="admin-panel" data-admin-panel="connections" hidden>
        <div class="panel-heading"><h2>OAuth connections</h2><p class="muted">Connect a remote MCP client to a workspace. Each connection binds one client and inherits its linked token configuration's permissions. Deletion revokes access without deleting workspace files.</p></div>
        {''.join(cards) or '<p>No connections yet.</p>'}
        <section class="card"><h3>Create connection</h3><form method="post" action="{esc(admin_path)}/oauth">{common}<input type="hidden" name="action" value="create"><div class="grid"><div><label>Comment</label><input name="comment" maxlength="200" required placeholder="e.g. Claude personal"></div><div><label>Workspace configuration</label><select name="app_id" required>{options}</select></div><div class="checks"><button>Create connection</button></div></div></form></section></section>'''

"""Client mapping panel using the administration console's shared components."""

import html


def render_mappings(rows, records, csrf, admin_path, message="", enabled=False):
    esc = html.escape
    action = esc(admin_path + "/mappings", quote=True)
    hidden = f'<input type="hidden" name="csrf" value="{esc(csrf, quote=True)}">'
    workspace_records = {}
    for record in records:
        if record.valid and record.path_prefix not in workspace_records:
            workspace_records[record.path_prefix] = record
    cards = []
    for row in rows:
        fields = hidden + f'<input type="hidden" name="id" value="{esc(row["id"], quote=True)}">'
        checks = "".join(
            f'<label><input type="checkbox" name="{key}" {"checked" if row[key] else ""}>{label}</label>'
            for key, label in (("enabled", "Enabled"), ("writable", "Writable (files + RPC writes)"), ("allow_exec", "Client execution")))
        online = row["online"] and row["enabled"]
        status = "Online" if online else "Offline" if row["enabled"] else "Disabled"
        workspace_options = "".join(
            f'<option value="{esc(path, quote=True)}" {"selected" if path == row["workspace"] else ""}>{esc(record.name)} — {esc(path)}</option>'
            for path, record in workspace_records.items()
        )
        cards.append(f'''<details class="card token-card"><summary class="token-summary">
<div class="token-summary-title"><span>{esc(row["name"])}</span><span class="badge{'' if online else ' off'}">{status}</span></div>
<div class="token-summary-meta"><strong>Workspace</strong><span>{esc(row["workspace"])}</span></div>
<div class="token-summary-meta expires"><strong>Access</strong><span>{'Writable' if row['writable'] else 'Read only'}</span></div>
<div class="token-summary-meta permissions"><strong>Comment</strong><span>{esc(row['comment']) or '—'}</span></div>
<span class="summary-toggle" aria-hidden="true"></span></summary><div class="token-details">
<form method="post" action="{action}">{fields}<div class="grid"><div><label>Workspace</label><select name="workspace" required>{workspace_options}</select></div><div><label>Directory name</label><input name="name" value="{esc(row['name'], quote=True)}" required pattern="[A-Za-z0-9][A-Za-z0-9_-]{{0,63}}"></div><div><label>Comment</label><input name="comment" maxlength="200" value="{esc(row['comment'], quote=True)}"></div>
<div class="span2 checks">{checks}</div><div class="span4 actions"><button name="action" value="update">Save changes</button>
<button class="secondary" name="action" value="rotate" onclick="return confirm('Replace the provider credential and disconnect the client?')">Rotate credential</button>
<button class="danger" name="action" value="delete" onclick="return confirm('Detach this mapping? Client files are not deleted.')">Delete mapping</button></div></div></form></div></details>''')
    options = "".join(f'<option value="{esc(r.app_id, quote=True)}">{esc(r.name)} — {esc(r.path_prefix)}</option>' for r in records if r.valid)
    notice = '<div class="notice">Client mappings are disabled. Enable mappings_enabled in the server configuration first.</div>' if not enabled else ''
    if message:
        if message.startswith("Mapping operation failed:"):
            notice += f'<div class="error">{esc(message)}</div>'
        else:
            _, _, configuration = message.partition("\n")
            notice += f'''<section class="card"><h2>Client configuration</h2><p class="muted">Save this credential now; it is shown only once.</p><pre class="token" id="mapping-client-config" style="white-space:pre-wrap">{esc(configuration)}</pre><button type="button" class="secondary" onclick="copyToken('mapping-client-config',this)">Copy client JSON</button></section>'''
    return f'''<section id="panel-mappings" class="admin-panel" data-admin-panel="mappings" hidden>
<div class="panel-heading"><h2>Client mappings</h2><div class="muted">Connect client directories to workspaces. Provider credentials are independent of REST tokens.</div></div>{notice}
<h2>Existing mappings ({len(rows)})</h2>{''.join(cards) or '<section class="card"><p class="muted">No client mappings yet.</p></section>'}
<section class="card"><h2>Create mapping</h2><form method="post" action="{action}">{hidden}<div class="grid">
<div class="span2"><label>Workspace</label><select name="app_id" required>{options}</select></div>
<div><label>Directory name</label><input name="name" placeholder="e.g. laptop" required pattern="[A-Za-z0-9][A-Za-z0-9_-]{{0,63}}"></div>
<div><label>Comment</label><input name="comment" maxlength="200"></div>
<div class="span4 checks"><label><input type="checkbox" name="writable">Writable (files + RPC writes)</label><label><input type="checkbox" name="allow_exec">Client execution</label></div>
<div class="span4 actions"><button name="action" value="create"{'' if enabled else ' disabled'}>Create mapping</button></div></div></form>
<p class="muted">Writable allows file mutations and RPC operations that advertise write=true. Client execution also requires local opt-in. Editing or rotating a mapping disconnects its client. Deleting a mapping does not delete client files.</p></section></section>'''

"""Storage Provider administration panel."""

from __future__ import annotations

import html


_KIND_LABELS = {
    "google_drive": "Google Drive",
    "dropbox": "Dropbox",
    "sftp": "SFTP",
    "smb": "SMB",
}


def _credentials_fields(kind: str, *, prefix: str, oauth_callback: str = "") -> str:
    esc = html.escape
    if kind in {"google_drive", "dropbox"}:
        label = _KIND_LABELS[kind]
        callback = esc(oauth_callback)
        client_label = "OAuth client ID" if kind == "google_drive" else "App client ID"
        secret_label = "OAuth client secret" if kind == "google_drive" else "App client secret"
        manual_note = (
            "For Dropbox, client fields may be left blank only when the pasted token was created "
            "with rclone's shared app."
            if kind == "dropbox"
            else "The token must match the client ID and secret above."
        )
        return f'''
<div data-storage-kind="{kind}" class="span4 storage-credentials">
<div class="grid">
<div><label>{client_label}</label><input name="client_id" autocomplete="off"></div>
<div><label>{secret_label}</label><input name="client_secret" type="password" autocomplete="new-password"></div>
<div class="span4 notice"><strong>OAuth redirect URI</strong><br><code>{callback}</code><br><span class="muted">Register this exact URI in your {label} OAuth application.</span></div>
<div class="span4 actions"><button type="submit" name="action" value="oauth_start" formnovalidate>Connect {label}</button></div>
<div class="span4"><details><summary>Advanced: paste rclone OAuth token JSON</summary>
<label>rclone OAuth token JSON</label><textarea name="oauth_token" rows="5" autocomplete="off" placeholder='{{"access_token":"…","token_type":"Bearer","refresh_token":"…","expiry":"…"}}'></textarea>
<p class="muted">{manual_note}</p></details></div>
</div></div>'''
    if kind == "sftp":
        return f'''
<div data-storage-kind="sftp" class="span4 storage-credentials"><div class="grid">
<div><label>Host</label><input name="host" autocomplete="off"></div>
<div><label>Port</label><input name="port" type="number" min="1" max="65535" value="22"></div>
<div><label>User</label><input name="user" autocomplete="off"></div>
<div><label>Password (or private key)</label><input name="password" type="password" autocomplete="new-password"></div>
<div class="span4"><label>Private key PEM (instead of password)</label><textarea name="private_key" rows="5" autocomplete="off"></textarea></div>
<div class="span4 actions"><button type="button" class="secondary" onclick="storageDetectSftpKey(this)">Detect SSH host key</button></div>
<div class="span4 notice" data-sftp-key-result hidden></div>
<div class="span4"><details data-sftp-known-hosts><summary>Advanced: known_hosts entry</summary>
<label>known_hosts entry</label><textarea name="known_hosts" rows="4" autocomplete="off" placeholder="[host]:port ssh-ed25519 AAAA…"></textarea>
<p class="muted">Detection only retrieves the key presented to this OpenKapsel server. Verify the SHA256 fingerprint independently with the SFTP server administrator before trusting it. You may also paste a verified known_hosts entry manually.</p>
</details></div>
<div class="span4 checks"><label><input type="checkbox" name="host_key_confirmed" required> I verified the displayed/pasted SSH host-key fingerprint and trust this key.</label></div>
</div></div>'''
    return f'''
<div data-storage-kind="smb" class="span4 storage-credentials"><div class="grid">
<div><label>Host</label><input name="host" autocomplete="off"></div>
<div><label>Port</label><input name="port" type="number" min="1" max="65535" value="445"></div>
<div><label>User</label><input name="user" autocomplete="off"></div>
<div><label>Password</label><input name="password" type="password" autocomplete="new-password"></div>
<div><label>Domain / workgroup</label><input name="domain" value="WORKGROUP" autocomplete="off"></div>
</div></div>'''


def render_storage_providers(
    providers,
    records,
    csrf,
    admin_path,
    public_base_url,
    message="",
    capability=None,
    delete_warning=None,
):
    esc = html.escape
    capability = capability or {"available": False, "reason": "storage provider support unavailable"}
    action = esc(admin_path + "/storage-providers", quote=True)
    oauth_callback = public_base_url.rstrip("/") + "/admin/storage-providers/oauth/callback"
    hidden = f'<input type="hidden" name="csrf" value="{esc(csrf, quote=True)}">'
    workspaces = []
    seen = set()
    for record in records:
        if record.valid and record.path_prefix not in seen:
            seen.add(record.path_prefix)
            workspaces.append((record.path_prefix, record.name))
    workspace_options = "".join(
        f'<option value="{esc(path, quote=True)}">{esc(name)} — {esc(path)}</option>'
        for path, name in workspaces
    )
    cards = []
    for provider in providers:
        status = provider.get("status") or {}
        mounted = bool(status.get("mounted"))
        configured = bool(status.get("configured"))
        enabled = bool(provider["enabled"])
        badge = "Mounted" if mounted and enabled else "Disabled" if not enabled else "Unavailable"
        badge_class = "" if mounted and enabled else " off"
        mapping_cards = []
        for mapping in provider.get("mappings", []):
            mapped = bool((status.get("mappings") or {}).get(mapping["id"]))
            mapping_cards.append(
                f'''<div class="notice"><strong>{esc(mapping["workspace"])}/{esc(mapping["name"])}</strong> · {'Mounted' if mapped else 'Not mounted'}
<form method="post" action="{action}" style="display:inline">{hidden}<input type="hidden" name="mapping_id" value="{esc(mapping["id"], quote=True)}"><button class="danger" name="action" value="delete_mapping" onclick="return confirm('Remove this workspace mapping? Remote data is not deleted.')">Remove mapping</button></form></div>'''
            )
        credentials = _credentials_fields(
            provider["kind"], prefix=provider["id"], oauth_callback=oauth_callback
        )
        delete_warning_html = ""
        if delete_warning and delete_warning.get("provider_id") == provider["id"]:
            queued = int(delete_warning.get("uploads_queued") or 0)
            uploading = int(delete_warning.get("uploads_in_progress") or 0)
            cache_bytes = int(delete_warning.get("cache_bytes") or 0)
            uncertain = bool(delete_warning.get("uncertain"))
            reason = str(delete_warning.get("reason") or "")
            if uncertain:
                detail = "OpenKapsel cannot verify whether the local VFS cache is fully synchronized."
                if reason:
                    detail += " " + reason + "."
            else:
                detail = f"rclone reports {queued} queued and {uploading} in-progress upload(s)."
                if cache_bytes:
                    detail += f" Current VFS cache usage is about {cache_bytes / (1024**2):.1f} MiB."
            delete_warning_html = f'''<div class="error"><strong>Delete paused.</strong> {esc(detail)}
<form method="post" action="{action}" style="margin-top:.75rem">{hidden}<input type="hidden" name="id" value="{esc(provider["id"], quote=True)}"><button class="danger" name="action" value="force_delete" onclick="return confirm('Force delete this provider now? Pending local cached writes may be permanently lost.')">Force delete and discard local pending cache</button></form></div>'''
        cards.append(f'''<details class="card token-card"><summary class="token-summary">
<div class="token-summary-title"><span>{esc(provider["name"])}</span><span class="badge{badge_class}">{badge}</span></div>
<div class="token-summary-meta"><strong>Provider</strong><span>{esc(_KIND_LABELS.get(provider["kind"], provider["kind"]))}</span></div>
<div class="token-summary-meta"><strong>Remote path</strong><span>{esc(provider["remote_path"]) or '/'}</span></div>
<div class="token-summary-meta"><strong>Access</strong><span>{'Writable' if provider["writable"] else 'Read only'}</span></div>
<span class="summary-toggle" aria-hidden="true"></span></summary><div class="token-details">
{delete_warning_html}
<form method="post" action="{action}">{hidden}<input type="hidden" name="id" value="{esc(provider["id"], quote=True)}"><div class="grid">
<div><label>Name</label><input name="name" value="{esc(provider["name"], quote=True)}" required maxlength="64"></div>
<div><label>Remote path</label><input name="remote_path" value="{esc(provider["remote_path"], quote=True)}"></div>
<div><label>VFS cache limit (GiB)</label><input name="cache_gib" type="number" min="1" max="1024" value="{max(1, provider["cache_max_bytes"] // (1024**3))}"></div>
<div><label>Comment</label><input name="comment" maxlength="200" value="{esc(provider["comment"], quote=True)}"></div>
<div class="span4 checks"><label><input type="checkbox" name="enabled" {'checked' if provider["enabled"] else ''}>Enabled</label><label><input type="checkbox" name="writable" {'checked' if provider["writable"] else ''}>Writable remote</label></div>
<div class="span4 actions"><button name="action" value="update">Save and reconcile</button><button class="secondary" name="action" value="reconcile">Reconcile mount</button><button class="danger" name="action" value="delete" onclick="return confirm('Delete this provider? OpenKapsel will refuse if cached uploads are pending or cannot be verified.')">Delete provider</button></div>
</div></form>
<details><summary>Replace credentials</summary><form method="post" action="{action}">{hidden}<input type="hidden" name="id" value="{esc(provider["id"], quote=True)}"><div class="grid">{credentials}<div class="span4 actions"><button name="action" value="replace_credentials">Replace credentials</button></div></div></form><p class="muted">Stored credentials are never displayed by OpenKapsel.</p></details>
<h3>Workspace mappings</h3>{''.join(mapping_cards) or '<p class="muted">Not mapped into a workspace.</p>'}
<form method="post" action="{action}">{hidden}<input type="hidden" name="provider_id" value="{esc(provider["id"], quote=True)}"><div class="grid"><div><label>Workspace</label><select name="workspace" required>{workspace_options}</select></div><div><label>Directory name</label><input name="mapping_name" required pattern="[A-Za-z0-9][A-Za-z0-9_-]{{0,63}}"></div><div class="actions"><button name="action" value="add_mapping">Add mapping</button></div></div></form>
</div></details>''')
    notice = ""
    if not capability.get("available"):
        notice += f'<div class="error">Storage Providers unavailable: {esc(str(capability.get("reason") or "unknown reason"))}</div>'
    if message:
        cls = "error" if message.startswith((
            "Storage provider operation failed:",
            "Storage provider deletion paused:",
            "Storage provider OAuth failed:",
        )) else "success"
        notice += f'<div class="{cls}">{esc(message)}</div>'
    kind_options = "".join(f'<option value="{kind}">{esc(label)}</option>' for kind, label in _KIND_LABELS.items())
    all_credentials = "".join(
        _credentials_fields(kind, prefix="create", oauth_callback=oauth_callback)
        for kind in _KIND_LABELS
    )
    return f'''<section id="panel-storage" class="admin-panel" data-admin-panel="storage" hidden>
<div class="panel-heading"><h2>Storage Providers</h2><div class="muted">Server-managed rclone mounts. Remote data is read on demand; the VFS cache does not pre-download the whole drive.</div></div>{notice}
<h2>Existing providers ({len(providers)})</h2>{''.join(cards) or '<section class="card"><p class="muted">No storage providers configured.</p></section>'}
<section class="card"><h2>Create provider</h2><form method="post" action="{action}" data-storage-create>{hidden}<div class="grid">
<div><label>Name</label><input name="name" required maxlength="64" placeholder="e.g. Google Drive"></div>
<div><label>Type</label><select name="kind" onchange="storageKind(this.form,this.value)">{kind_options}</select></div>
<div><label>Remote path</label><input name="remote_path" placeholder="Optional subdirectory/share"></div>
<div><label>VFS cache limit (GiB)</label><input name="cache_gib" type="number" min="1" max="1024" value="1"></div>
<div class="span4"><label>Comment</label><input name="comment" maxlength="200"></div>
<div class="span4 checks"><label><input type="checkbox" name="writable">Writable remote</label></div>
{all_credentials}<div class="span4 actions"><button name="action" value="create"{'' if capability.get("available") else ' disabled'}>Create and mount</button></div></div></form>
<p class="muted">Google Drive and Dropbox can be connected in the browser after registering the displayed redirect URI with your OAuth application. Manual rclone token JSON remains available under Advanced. For SFTP, OpenKapsel can detect the public SSH host key, but detection is not identity proof: verify the displayed SHA256 fingerprint independently before confirming and saving it. Manual <code>known_hosts</code> entry remains available under Advanced. Credentials live outside the workspace under a dedicated service account and are never exposed through Files or MCP.</p></section>
<script>
function storageKind(form,kind){{form.querySelectorAll('[data-storage-kind]').forEach(el=>{{const on=el.dataset.storageKind===kind;el.hidden=!on;el.querySelectorAll('input,textarea,select,button').forEach(x=>x.disabled=!on)}})}}
async function storageDetectSftpKey(button){{
  const form=button.form;
  const block=button.closest('[data-storage-kind="sftp"]');
  const result=block.querySelector('[data-sftp-key-result]');
  const known=block.querySelector('textarea[name="known_hosts"]');
  const confirm=block.querySelector('input[name="host_key_confirmed"]');
  const details=block.querySelector('[data-sftp-known-hosts]');
  const host=block.querySelector('input[name="host"]').value;
  const port=block.querySelector('input[name="port"]').value||'22';
  result.hidden=false;
  result.className='span4 notice';
  result.textContent='Detecting SSH host key…';
  button.disabled=true;
  try {{
    const data=new FormData();
    data.set('csrf',form.elements.csrf.value);
    data.set('action','detect_sftp_host_key');
    data.set('host',host);
    data.set('port',port);
    const response=await fetch(form.action,{{method:'POST',body:data,credentials:'same-origin',headers:{{'Accept':'application/json'}}}});
    const payload=await response.json();
    if(!response.ok) throw new Error(payload.message||payload.error||'Host-key detection failed');
    known.value=payload.known_hosts||'';
    confirm.checked=false;
    details.open=true;
    const lines=(payload.keys||[]).map(k=>k.type+'  '+k.fingerprint_sha256);
    result.textContent='Detected for '+payload.host+':'+payload.port+'\n'+lines.join('\n')+'\nVerify these fingerprints independently before checking the trust confirmation.';
  }} catch(error) {{
    known.value='';
    confirm.checked=false;
    result.className='span4 error';
    result.textContent='SSH host-key detection failed: '+error.message;
  }} finally {{
    button.disabled=false;
  }}
}}
document.querySelectorAll('form[data-storage-create]').forEach(f=>storageKind(f,f.elements.kind.value));
document.querySelectorAll('[data-storage-kind="sftp"]').forEach(block=>{{
  const confirm=block.querySelector('input[name="host_key_confirmed"]');
  ['host','port','known_hosts'].forEach(name=>{{
    const field=block.querySelector('[name="'+name+'"]');
    if(field) field.addEventListener('input',()=>{{confirm.checked=false}});
  }});
}});
</script>
</section>'''

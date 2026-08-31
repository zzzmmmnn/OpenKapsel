# OpenKapsel REST Skill

[Back to README](../README.md)

`skills/openkapsel-rest` is a portable AI-agent Skill for the non-MCP HTTP interface. Administrator operations are intentionally excluded.

Its short `SKILL.md` routes an AI to focused references for files, Context, Memory, Shell, preview applications, and sharing. Runtime focused Discovery remains authoritative, so routine work does not need to load `discovery/full`.

## Installation and discovery

The Skill is server-agnostic. It does not embed a deployment URL or token. A source checkout can install it by copying `skills/openkapsel-rest` into the AI client's Skill directory.

Production installation serves a dynamically packaged copy at:

```text
<url_base_path>/skills/openkapsel-rest
```

Discovery advertises public, credential-free manifest, entrypoint, archive, and SHA-256 URLs. The ZIP is generated and cached by the server rather than stored in Git. An AI can read the files remotely or verify and install the archive.

The served Skill is under `/opt/openkapsel/skills/openkapsel-rest`; it is not mounted into restricted Shell or application workers.

## Project configuration

Run the installed helper by its absolute Skill path while the current directory is the local controlling project:

```bash
python3 /path/to/openkapsel-rest/scripts/openkapsel_config.py \
  init https://ws.example.com/kapsel/w/<READ_TOKEN>/ <CONTROL_TOKEN>
```

It creates a mode-`0600` `.openkapsel.env` without echoing credentials. Repeating identical initialization is idempotent; replacing a different configuration requires `--force`.

Helpers locate the nearest `.openkapsel.env` from the current directory. Explicit arguments and the original process environment variables remain supported, so one Skill installation can operate any number of OpenKapsel deployments. Separate local project directories naturally select separate Workspace records.

## Credential renewal

Helpers cache the credential expiration. When less than two days remain, they call the conditional self-renewal endpoint, rotate both Workspace credentials for another three days, and atomically rewrite `.openkapsel.env`.

Renewal never changes the preview token or workspace lifetime. A renewal outside the allowed window is rejected by the server.

## Upload workflows

The single-file helper:

- selects direct or resumable transfer from file size and Discovery limits
- retries bounded transient failures with delays
- resumes from the server upload offset
- defaults to create-only behavior
- when explicitly asked to overwrite, first recycles the existing remote file

The batch helper:

- accepts multiple files and directory trees
- creates destination directories
- uses native manifest preflight when available
- chooses the transfer method per file
- resumes interrupted work from a credential-free local state file
- supports include and exclude filters
- reports multi-file state for interrupted batches

Directory traversal skips hidden files and directories by default. Explicitly naming a hidden source or matching it with an include rule opts it in. `.openkapsel.env` is always excluded.

The Skill also provides batch exact-replacement workflows, including multiple non-overlapping replacements in one file. It does not change the server's mutation-context, ETag, permission, or recycle requirements.


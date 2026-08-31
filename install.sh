#!/usr/bin/env bash
set -Eeuo pipefail

SERVICE_NAME=openkapsel
SERVICE_USER=openkapsel
SERVICE_GROUP=openkapsel
INSTALL_DIR=/opt/openkapsel
DATA_DIR=/var/lib/openkapsel
CONFIG_FILE=/var/lib/openkapsel/config.json
WORKSPACE_ROOT=/var/lib/openkapsel/workspace
TASK_HISTORY_DIR=/var/lib/openkapsel/tasks
IMAGE_DIR=/var/lib/openkapsel-images
SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
MIGRATE_FROM=
START_SERVICE=1
INSTALL_PACKAGES=1
VERIFY_ONLY=0
ENABLE_PODMAN=0
declare -a READ_ONLY_GRANTS=()
declare -a READ_WRITE_GRANTS=()

usage() {
    printf '%s\n' \
        "Usage: sudo ./install.sh [options]" \
        "" \
        "Options:" \
        "  --source DIR          project source directory (default: script directory)" \
        "  --migrate-from DIR    migrate DIR/state and move DIR/workspace" \
        "  --grant-ro DIR        expose an existing directory read-only (repeatable)" \
        "  --grant-rw DIR        expose an existing directory read/write (repeatable)" \
        "  --no-package-install  do not run apt-get" \
        "  --with-podman        install and enable the Podman Shell backend" \
        "  --no-start            install and verify without starting the service" \
        "  --verify-only         verify an existing installation" \
        "  -h, --help            show this help"
}

die() {
    printf 'install.sh: %s\n' "$*" >&2
    exit 1
}

while (($#)); do
    case "$1" in
        --source)
            (($# >= 2)) || die "--source requires a directory"
            SOURCE_DIR=$2
            shift 2
            ;;
        --migrate-from)
            (($# >= 2)) || die "--migrate-from requires a directory"
            MIGRATE_FROM=$2
            shift 2
            ;;
        --grant-ro)
            (($# >= 2)) || die "--grant-ro requires a directory"
            READ_ONLY_GRANTS+=("$2")
            shift 2
            ;;
        --grant-rw)
            (($# >= 2)) || die "--grant-rw requires a directory"
            READ_WRITE_GRANTS+=("$2")
            shift 2
            ;;
        --no-package-install)
            INSTALL_PACKAGES=0
            shift
            ;;
        --with-podman)
            ENABLE_PODMAN=1
            shift
            ;;
        --no-start)
            START_SERVICE=0
            shift
            ;;
        --verify-only)
            VERIFY_ONLY=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *) die "unknown argument: $1" ;;
    esac
done

[[ ${EUID} -eq 0 ]] || die "run this installer as root"

canonical_dir() {
    [[ -d $1 ]] || die "directory does not exist: $1"
    realpath -e -- "$1"
}

verify_installation() {
    local failed=0
    for command in python3 bwrap rootlesskit slirp4netns newuidmap newgidmap systemd-run mkfs.ext4 resize2fs losetup mount umount findmnt fc-list fc-match curl git; do
        if ! command -v "$command" >/dev/null 2>&1; then
            printf 'missing command: %s\n' "$command" >&2
            failed=1
        fi
    done
    id "$SERVICE_USER" >/dev/null 2>&1 || { printf 'missing user: %s\n' "$SERVICE_USER" >&2; failed=1; }
    [[ $(id -u "$SERVICE_USER" 2>/dev/null || printf 0) -ne 0 ]] || {
        printf '%s must not be root\n' "$SERVICE_USER" >&2
        failed=1
    }
    [[ -f $INSTALL_DIR/openkapsel/server.py ]] || { printf 'missing installed code\n' >&2; failed=1; }
    [[ -f $INSTALL_DIR/skills/openkapsel-rest/SKILL.md ]] || { printf 'missing installed OpenKapsel REST skill\n' >&2; failed=1; }
    [[ -f $INSTALL_DIR/docs/installation.md ]] || { printf 'missing installed documentation\n' >&2; failed=1; }
    [[ -x $INSTALL_DIR/venv/bin/python ]] || { printf 'missing installed Python environment\n' >&2; failed=1; }
    [[ -f $CONFIG_FILE ]] || { printf 'missing config: %s\n' "$CONFIG_FILE" >&2; failed=1; }
    [[ -d $WORKSPACE_ROOT ]] || { printf 'missing workspace: %s\n' "$WORKSPACE_ROOT" >&2; failed=1; }
    [[ -d $TASK_HISTORY_DIR ]] || { printf 'missing task history: %s\n' "$TASK_HISTORY_DIR" >&2; failed=1; }
    [[ -d $DATA_DIR/shares ]] || { printf 'missing share store: %s\n' "$DATA_DIR/shares" >&2; failed=1; }
    [[ -d $DATA_DIR/network-proxies ]] || { printf 'missing network proxy store: %s\n' "$DATA_DIR/network-proxies" >&2; failed=1; }
    [[ $(stat -c '%U:%G:%a' "$DATA_DIR/shares" 2>/dev/null) == "$SERVICE_USER:$SERVICE_GROUP:700" ]] || {
        printf 'share store must be %s:%s mode 0700\n' "$SERVICE_USER" "$SERVICE_GROUP" >&2
        failed=1
    }
    [[ -d $IMAGE_DIR ]] || { printf 'missing workspace image store: %s\n' "$IMAGE_DIR" >&2; failed=1; }
    [[ $(stat -c '%U:%G:%a' "$IMAGE_DIR" 2>/dev/null) == root:root:700 ]] || {
        printf 'workspace image store must be root:root mode 0700\n' >&2
        failed=1
    }
    [[ -f /sys/fs/cgroup/cgroup.controllers ]] || {
        printf 'cgroup v2 is required for token sandbox resource limits\n' >&2
        failed=1
    }
    [[ -s /etc/subuid ]] && grep -q "^${SERVICE_USER}:" /etc/subuid || {
        printf 'missing subuid allocation for %s\n' "$SERVICE_USER" >&2
        failed=1
    }
    [[ -s /etc/subgid ]] && grep -q "^${SERVICE_USER}:" /etc/subgid || {
        printf 'missing subgid allocation for %s\n' "$SERVICE_USER" >&2
        failed=1
    }
    systemd-analyze verify "/etc/systemd/system/${SERVICE_NAME}.service"
    systemd-analyze verify "/etc/systemd/system/${SERVICE_NAME}-images.service"
    (cd "$INSTALL_DIR" && "$INSTALL_DIR/venv/bin/python" -m compileall -q openkapsel openkapsel_runtime)
    "$INSTALL_DIR/venv/bin/python" -c 'import PIL, bs4, cryptography, fastapi, httpx, jinja2, lxml, matplotlib, multipart, numba, numpy, pandas, scipy, sqlalchemy, uvicorn, openkapsel_runtime, yaml; from matplotlib import font_manager; assert font_manager.findfont("DejaVu Sans")'
    fc-list ':family=DejaVu Sans' | grep -q . || { printf 'missing DejaVu Sans font\n' >&2; failed=1; }
    fc-list ':family=Noto Sans CJK SC' | grep -q . || { printf 'missing Noto Sans CJK SC font\n' >&2; failed=1; }
    if "$INSTALL_DIR/venv/bin/python" - "$CONFIG_FILE" <<'PY'
import json, sys
payload = json.load(open(sys.argv[1], encoding="utf-8"))
raise SystemExit(0 if "podman" in payload.get("sandbox_backends", []) else 1)
PY
    then
        command -v podman >/dev/null 2>&1 || { printf 'missing command: podman\n' >&2; failed=1; }
        if command -v podman >/dev/null 2>&1; then
            local podman_runtime
            podman_runtime=$("$INSTALL_DIR/venv/bin/python" - "$CONFIG_FILE" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8")).get("podman_runtime", "crun"))
PY
)
            (
                cd "$DATA_DIR"
                runuser -u "$SERVICE_USER" -- env \
                    HOME="$DATA_DIR/home" XDG_RUNTIME_DIR="$DATA_DIR/run" \
                    podman --runtime="$podman_runtime" info >/dev/null
            ) || failed=1
        fi
    fi
    if command -v bwrap >/dev/null 2>&1 \
        && command -v rootlesskit >/dev/null 2>&1 \
        && command -v systemd-run >/dev/null 2>&1 \
        && id "$SERVICE_USER" >/dev/null 2>&1; then
        systemd-run --quiet --wait --collect --pipe \
            --unit="${SERVICE_NAME}-sandbox-verify-$$" \
            --property="User=$SERVICE_USER" \
            --property="Group=$SERVICE_GROUP" \
            --property=ProtectProc=invisible \
            --property=ProtectKernelTunables=false \
            --property=ProtectKernelModules=true \
            --property=ProtectKernelLogs=false \
            --property=ProtectClock=true \
            -- \
            "$INSTALL_DIR/venv/bin/python" -m openkapsel.sandbox_verify \
            --workspace-root "$WORKSPACE_ROOT" \
            --worker-root "$DATA_DIR/api-workers" \
            --bubblewrap /usr/bin/bwrap \
            --rootlesskit /usr/bin/rootlesskit || failed=1
    fi
    if ((failed)); then
        return 1
    fi
    printf 'OpenKapsel installation verification passed.\n'
}

if ((VERIFY_ONLY)); then
    verify_installation
    exit
fi

SOURCE_DIR=$(canonical_dir "$SOURCE_DIR")
[[ -f $SOURCE_DIR/openkapsel/server.py ]] || die "source does not contain openkapsel/server.py: $SOURCE_DIR"
[[ -f $SOURCE_DIR/systemd/openkapsel.service ]] || die "source is missing systemd/openkapsel.service"
[[ -f $SOURCE_DIR/systemd/openkapsel-images.service ]] || die "source is missing systemd/openkapsel-images.service"

if [[ -n $MIGRATE_FROM ]]; then
    MIGRATE_FROM=$(canonical_dir "$MIGRATE_FROM")
fi
EXISTING_PATHS_FILE="/etc/systemd/system/${SERVICE_NAME}.service.d/paths.conf"
if ((${#READ_ONLY_GRANTS[@]} == 0 && ${#READ_WRITE_GRANTS[@]} == 0)) && [[ -f $EXISTING_PATHS_FILE ]]; then
    mapfile -t READ_ONLY_GRANTS < <(sed -n 's/^ReadOnlyPaths=//p' "$EXISTING_PATHS_FILE")
    mapfile -t READ_WRITE_GRANTS < <(sed -n 's/^ReadWritePaths=//p' "$EXISTING_PATHS_FILE")
fi
for index in "${!READ_ONLY_GRANTS[@]}"; do
    READ_ONLY_GRANTS[$index]=$(canonical_dir "${READ_ONLY_GRANTS[$index]}")
done
for index in "${!READ_WRITE_GRANTS[@]}"; do
    READ_WRITE_GRANTS[$index]=$(canonical_dir "${READ_WRITE_GRANTS[$index]}")
done

if ((INSTALL_PACKAGES)); then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends \
        python3 python3-venv bubblewrap rootlesskit slirp4netns uidmap acl ca-certificates curl git e2fsprogs util-linux \
        fontconfig fonts-dejavu-core fonts-noto-core fonts-noto-cjk
    if ((ENABLE_PODMAN)); then
        apt-get install -y --no-install-recommends podman crun fuse-overlayfs
    fi
fi

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --create-home --home-dir "$DATA_DIR/home" --shell /usr/sbin/nologin \
        --user-group "$SERVICE_USER"
fi
[[ $(id -u "$SERVICE_USER") -ne 0 ]] || die "$SERVICE_USER unexpectedly has uid 0"

# Debian's useradd normally allocates subordinate IDs for regular users. If a
# locally customized login.defs did not, allocate the next non-overlapping block.
allocate_subids() {
    local file=$1 option=$2
    if grep -q "^${SERVICE_USER}:" "$file" 2>/dev/null; then
        return
    fi
    local start
    start=$(awk -F: 'BEGIN { next_id=100000 } NF>=3 { end=$2+$3; if (end>next_id) next_id=end } END { print next_id }' "$file" 2>/dev/null || printf 100000)
    usermod "$option" "${start}-$((start + 65535))" "$SERVICE_USER"
}
allocate_subids /etc/subuid --add-subuids
allocate_subids /etc/subgid --add-subgids

systemctl stop "$SERVICE_NAME" 2>/dev/null || true
systemctl stop "${SERVICE_NAME}-images" 2>/dev/null || true

STAGING_DIR=$(mktemp -d /opt/.openkapsel-install.XXXXXX)
cleanup() {
    [[ -z $STAGING_DIR ]] || rm -rf -- "$STAGING_DIR"
}
trap cleanup EXIT
install -d -m 0755 "$STAGING_DIR/systemd"
cp -a -- "$SOURCE_DIR/openkapsel" "$SOURCE_DIR/openkapsel_runtime" "$SOURCE_DIR/tests" \
    "$SOURCE_DIR/skills" "$SOURCE_DIR/docs" "$STAGING_DIR/"
cp -a -- "$SOURCE_DIR/README.md" "$SOURCE_DIR/config.example.json" \
    "$SOURCE_DIR/pyproject.toml" "$SOURCE_DIR/set_password.py" "$SOURCE_DIR/install.sh" \
    "$STAGING_DIR/"
cp -a -- "$SOURCE_DIR/systemd/openkapsel.service" "$SOURCE_DIR/systemd/openkapsel-images.service" "$STAGING_DIR/systemd/"
find "$STAGING_DIR" -type d -name __pycache__ -prune -exec rm -rf -- {} +
find "$STAGING_DIR" -type f -name '*.pyc' -delete
find "$STAGING_DIR" -type f \( -name '._*' -o -name '.DS_Store' \) -delete
chown -R root:root "$STAGING_DIR"
find "$STAGING_DIR" -type d -exec chmod 0755 {} +
find "$STAGING_DIR" -type f -exec chmod 0644 {} +
chmod 0755 "$STAGING_DIR/install.sh" "$STAGING_DIR/set_password.py"
find "$STAGING_DIR/skills" -type f -path '*/scripts/*.py' -exec chmod 0755 {} +

if [[ -d $INSTALL_DIR ]]; then
    backup="${INSTALL_DIR}.previous.$(date -u +%Y%m%dT%H%M%SZ)"
    mv -- "$INSTALL_DIR" "$backup"
fi
mv -- "$STAGING_DIR" "$INSTALL_DIR"
STAGING_DIR=

/usr/bin/python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --disable-pip-version-check --no-cache-dir "$INSTALL_DIR"

install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0700 "$DATA_DIR"
install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0700 "$DATA_DIR/home"
install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0700 "$DATA_DIR/run"
install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0700 "$DATA_DIR/uploads"
install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0700 "$DATA_DIR/shares"
install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0700 "$DATA_DIR/network-proxies"
install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0700 "$TASK_HISTORY_DIR"
install -d -o root -g root -m 0700 "$IMAGE_DIR"

OLD_CONFIG=
if [[ -n $MIGRATE_FROM ]]; then
    for candidate in "$MIGRATE_FROM/state/config.json" "$MIGRATE_FROM/config.json"; do
        if [[ -f $candidate ]]; then
            OLD_CONFIG=$candidate
            break
        fi
    done
fi
if [[ ! -f $CONFIG_FILE ]]; then
    if [[ -n $OLD_CONFIG ]]; then
        install -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0600 "$OLD_CONFIG" "$CONFIG_FILE"
    else
        install -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0600 \
            "$INSTALL_DIR/config.example.json" "$CONFIG_FILE"
    fi
fi

if [[ -n $MIGRATE_FROM && -f $MIGRATE_FROM/state/tokens.json && ! -f $DATA_DIR/tokens.json ]]; then
    install -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0600 \
        "$MIGRATE_FROM/state/tokens.json" "$DATA_DIR/tokens.json"
fi

if [[ -n $MIGRATE_FROM && -d $MIGRATE_FROM/workspace && $MIGRATE_FROM/workspace != "$WORKSPACE_ROOT" ]]; then
    if [[ -e $WORKSPACE_ROOT ]]; then
        [[ -d $WORKSPACE_ROOT && -z $(find "$WORKSPACE_ROOT" -mindepth 1 -print -quit) ]] \
            || die "refusing to replace non-empty workspace: $WORKSPACE_ROOT"
        rmdir -- "$WORKSPACE_ROOT"
    fi
    mv -- "$MIGRATE_FROM/workspace" "$WORKSPACE_ROOT"
else
    install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0700 "$WORKSPACE_ROOT"
fi

if [[ -n $MIGRATE_FROM && -d $MIGRATE_FROM/state/uploads && -z $(find "$DATA_DIR/uploads" -mindepth 1 -print -quit) ]]; then
    cp -a -- "$MIGRATE_FROM/state/uploads/." "$DATA_DIR/uploads/"
fi

if [[ -n $MIGRATE_FROM && -d $MIGRATE_FROM/state/tasks && -z $(find "$TASK_HISTORY_DIR" -mindepth 1 -print -quit) ]]; then
    cp -a -- "$MIGRATE_FROM/state/tasks/." "$TASK_HISTORY_DIR/"
fi

/usr/bin/python3 - "$CONFIG_FILE" "$WORKSPACE_ROOT" "$ENABLE_PODMAN" <<'PY'
import json
import os
import sys
import tempfile
from pathlib import Path

path = Path(sys.argv[1])
workspace = sys.argv[2]
enable_podman = sys.argv[3] == "1"
payload = json.loads(path.read_text(encoding="utf-8"))
payload["workspace_name"] = payload.get("workspace_name") or "OpenKapsel"
payload["workspace_root"] = workspace
payload["token_data_file"] = "/var/lib/openkapsel/tokens.json"
payload["upload_state_dir"] = "/var/lib/openkapsel/uploads"
payload["share_dir"] = "/var/lib/openkapsel/shares"
payload["network_proxy_dir"] = "/var/lib/openkapsel/network-proxies"
payload.setdefault("share_ttl_hours", 24)
payload.setdefault("max_share_entries", 10)
payload.setdefault("max_share_mb", 256)
payload["task_history_dir"] = "/var/lib/openkapsel/tasks"
payload["workspace_image_socket"] = "/run/openkapsel-images/control.sock"
payload.setdefault("finished_task_retention_minutes", 60)
payload.setdefault("max_finished_tasks_per_token", 4)
payload.setdefault("max_http_connections", 128)
payload.setdefault("http_socket_timeout_seconds", 30)
payload.setdefault("max_sse_streams", 16)
payload.setdefault("max_sse_streams_per_token", 4)
payload.setdefault("schedule_misfire_grace_seconds", 300)
payload.setdefault("max_sse_duration_seconds", 3600)
payload.setdefault("max_network_proxy_connections", 64)
payload.setdefault("max_network_proxy_connections_per_instance", 16)
payload.setdefault("network_proxy_header_timeout_seconds", 15)
payload["bubblewrap_path"] = "/usr/bin/bwrap"
payload["rootlesskit_path"] = "/usr/bin/rootlesskit"
payload["podman_path"] = "/usr/bin/podman"
payload.setdefault("podman_image", "docker.io/library/python:3.12-slim")
payload.setdefault("podman_runtime", "crun")
backends = payload.setdefault("sandbox_backends", ["bubblewrap"])
if enable_podman and "podman" not in backends:
    backends.append("podman")
payload.setdefault("sandbox_default_backend", "bubblewrap")
payload.setdefault("sandbox_cgroup_enabled", True)
payload.setdefault("listen_host", "127.0.0.1")
payload.setdefault("listen_port", 8765)
payload.setdefault("url_base_path", "/kapsel")
admin = payload.setdefault("admin", {})
admin.setdefault("username", "admin")
fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
finally:
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
PY

if ! "$INSTALL_DIR/venv/bin/python" - "$CONFIG_FILE" <<'PY'
import json, sys
sys.path.insert(0, "/opt/openkapsel")
from openkapsel.security import is_password_hash_supported
admin = json.load(open(sys.argv[1], encoding="utf-8")).get("admin", {})
value = admin.get("password_hash", admin.get("password_sha256", ""))
raise SystemExit(0 if isinstance(value, str) and is_password_hash_supported(value) else 1)
PY
then
    (cd "$INSTALL_DIR" && "$INSTALL_DIR/venv/bin/python" set_password.py \
        --config "$CONFIG_FILE" --generate-username --generate)
fi

# Do not traverse mounted workspace images during upgrades; their filesystem
# roots and contents already belong to the service user.
find "$DATA_DIR" -xdev -exec chown -h "$SERVICE_USER:$SERVICE_GROUP" {} +
chmod 0700 "$DATA_DIR" "$DATA_DIR/home" "$DATA_DIR/run" "$DATA_DIR/uploads" "$DATA_DIR/shares" "$DATA_DIR/network-proxies" "$TASK_HISTORY_DIR" "$WORKSPACE_ROOT"
chmod 0600 "$CONFIG_FILE"
[[ ! -f $DATA_DIR/tokens.json ]] || chmod 0600 "$DATA_DIR/tokens.json"

grant_parent_traverse() {
    local path=$1 parent
    parent=$(dirname -- "$path")
    while [[ $parent != / ]]; do
        setfacl -m "u:${SERVICE_USER}:--x" "$parent"
        parent=$(dirname -- "$parent")
    done
}
for path in "${READ_ONLY_GRANTS[@]}"; do
    grant_parent_traverse "$path"
    setfacl -R -m "u:${SERVICE_USER}:r-X" "$path"
done
for path in "${READ_WRITE_GRANTS[@]}"; do
    grant_parent_traverse "$path"
    setfacl -R -m "u:${SERVICE_USER}:rwX" "$path"
    find "$path" -type d -exec setfacl -m "d:u:${SERVICE_USER}:rwX" {} +
done

install -o root -g root -m 0644 "$INSTALL_DIR/systemd/openkapsel.service" \
    "/etc/systemd/system/${SERVICE_NAME}.service"
install -o root -g root -m 0644 "$INSTALL_DIR/systemd/openkapsel-images.service" \
    "/etc/systemd/system/${SERVICE_NAME}-images.service"
DROP_IN_DIR="/etc/systemd/system/${SERVICE_NAME}.service.d"
install -d -o root -g root -m 0755 "$DROP_IN_DIR"
DROP_IN_FILE="$DROP_IN_DIR/paths.conf"
{
    printf '%s\n' '[Service]'
    for path in "${READ_ONLY_GRANTS[@]}"; do
        printf 'ReadOnlyPaths=%s\n' "$path"
    done
    for path in "${READ_WRITE_GRANTS[@]}"; do
        printf 'ReadWritePaths=%s\n' "$path"
    done
} >"$DROP_IN_FILE"
chmod 0644 "$DROP_IN_FILE"

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}-images"
systemctl enable "$SERVICE_NAME"
verify_installation
if ((START_SERVICE)); then
    systemctl start "${SERVICE_NAME}-images"
    systemctl start "$SERVICE_NAME"
    systemctl is-active --quiet "${SERVICE_NAME}-images"
    systemctl is-active --quiet "$SERVICE_NAME"
    if [[ -n ${backup:-} ]]; then
        find /opt -maxdepth 1 -type d -name 'openkapsel.previous.*' \
            ! -path "$backup" -exec rm -rf -- {} +
    fi
    printf 'OpenKapsel is active. Admin URL path: /kapsel/admin\n'
else
    printf 'Installation completed without starting OpenKapsel.\n'
fi

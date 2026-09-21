"""Narrow host-namespace launcher used by the existing privileged helper.

The helper only asks systemd to run a fixed FUSE worker as the service UID. No
caller-supplied executable, unit property, absolute path or mount option is used.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

from openkapsel.workspace.workspace_images import WorkspaceImageError, validate_image_name


class HostMappingMounts:
    def __init__(self, root, uid, gid):
        self.root, self.uid, self.gid = root, uid, gid
        self.socket = root.parent / "mapping-run" / "broker.sock"
        self.lock = threading.RLock()

    @staticmethod
    def mounted(path, mid):
        # Read mountinfo rather than stat: root is intentionally not allow_other
        # on a FUSE connection owned by the non-root service account.
        for line in Path("/proc/self/mountinfo").read_text().splitlines():
            fields = line.split()
            split = fields.index("-")
            if fields[4] == str(path).replace(" ", "\\040"):
                if fields[split + 1] != "fuse.openkapsel" or fields[split + 2] != "openkapsel-" + mid:
                    raise WorkspaceImageError("mapping mountpoint is occupied by another filesystem")
                return True
        return False

    def dispatch(self, request):
        if request.get("action") not in {"mapping_mount", "mapping_unmount"}:
            raise WorkspaceImageError("invalid mapping action")
        mid = request.get("id")
        if not isinstance(mid, str) or not re.fullmatch(r"[A-Za-z0-9_-]{24}", mid):
            raise WorkspaceImageError("invalid mapping id")
        workspace = request.get("workspace")
        if (not isinstance(workspace, str) or not workspace or workspace in {".", "..", ".openkapsel"}
                or len(workspace) > 255 or any(c in workspace for c in "/\\\x00\n\r\t")):
            raise WorkspaceImageError("invalid workspace name")
        name = validate_image_name(str(request.get("name", "")))
        parent = self.root / workspace
        if parent.is_symlink() or not parent.is_dir() or parent.resolve().parent != self.root.resolve():
            raise WorkspaceImageError("mapping workspace must be an existing direct child")
        path = parent / name
        unit = "openkapsel-mapping-" + mid + ".service"
        with self.lock:
            mounted = self.mounted(path, mid)
            if request["action"] == "mapping_unmount":
                self.run(["systemctl", "stop", unit], check=False)
                if self.mounted(path, mid):
                    raise WorkspaceImageError("mapping worker stopped but mount remains attached; unmount as its owner")
                return {"mounted": False}
            if mounted:
                return {"mounted": True}
            if path.is_symlink() or not path.is_dir() or path.stat().st_uid != self.uid:
                raise WorkspaceImageError("mapping mountpoint must be an owned real directory")
            if next(path.iterdir(), None) is not None:
                raise WorkspaceImageError("mapping mountpoint is not empty")
            if not self.socket.is_socket() or self.socket.is_symlink() or self.socket.parent.is_symlink():
                raise WorkspaceImageError("mapping broker socket is unavailable")
            if self.socket.stat().st_uid != self.uid:
                raise WorkspaceImageError("invalid mapping broker owner")
            self.run(["systemd-run", "--quiet", "--collect", "--unit", unit,
                "--uid", str(self.uid), "--gid", str(self.gid),
                "--property=PrivateMounts=no", "--property=RestrictAddressFamilies=AF_UNIX",
                "--property=UMask=0077", "--property=TimeoutStopSec=5",
                "--property=DevicePolicy=closed", "--property=DeviceAllow=/dev/fuse rw",
                # `--working-directory` is a newer systemd-run option. Use
                # the unit property instead so the privileged helper also
                # works on EL8's systemd 239.
                "--property=WorkingDirectory=" + str(Path(__file__).resolve().parents[2]),
                sys.executable, "-m", "openkapsel.mapping.mapping_fuse", "--socket", str(self.socket),
                f"--id={mid}", "--mount", str(path)])
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                if self.mounted(path, mid):
                    return {"mounted": True}
                time.sleep(.05)
            self.run(["systemctl", "stop", unit], check=False)
            raise WorkspaceImageError("host FUSE worker failed to mount; inspect its systemd unit")

    @staticmethod
    def run(argv, check=True):
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, timeout=15)
        if check and result.returncode:
            raise WorkspaceImageError("mapping worker systemd operation failed: " + result.stderr[-500:])
        return result

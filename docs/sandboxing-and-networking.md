# Sandboxing and networking

[Back to README](../README.md)

## Restricted backends

Restricted Shell uses a pluggable backend:

- Bubblewrap provides mount, user, network, and PID namespaces.
- Podman uses a rootless container runtime with the same token path grants.
- `auto` resolves to the configured restricted backend and never falls back to full Shell.

Only the token workspace and explicit host-path grants are mounted. FastAPI workers receive the application workspace and the read-only runtime venv; the complete `/opt/openkapsel` directory is not exposed. Restricted processes have private PID namespaces and cannot inspect host `/proc`, other workspaces, configuration, or token data.

Per-token cgroups enforce aggregate process/thread, memory, and CPU limits. The process API reports the restricted token's cgroup PIDs, commands, memory, CPU, and OOM counters.

Full Shell is not a sandbox. It runs as the `openkapsel` service account and can reach every path and network resource available to that operating-system user. Token mounts and network modes do not constrain it.

## Network modes

Restricted tasks support:

- `disabled`: a private network namespace without external connectivity.
- `domains`: only configured public hostnames through a token-scoped proxy.
- `full`: RootlessKit/slirp4netns or the rootless Podman network, with host loopback blocked.

Domain mode gives the sandbox no direct external route. It mounts one private Unix proxy socket and runs a loopback relay inside the namespace. Ignoring proxy environment variables or connecting directly to an IP cannot bypass the allowlist.

Exact hosts such as `github.com` and explicit suffix rules such as `.githubusercontent.com` are supported. New records are prefilled from `default_network_domains`, which covers common GitHub, GitLab, Bitbucket, Codeberg, Gitee, SourceHut, PyPI, npm, Yarn, and Node.js download hosts. Redirect targets are checked independently.

Domain mode supports HTTP, HTTPS, WebSocket, HTTPS Git clone, package installation, and release downloads. It blocks:

- SSH clone URLs and the unauthenticated Git protocol
- UDP and QUIC
- direct IP destinations and private addresses
- ports other than 80 and 443

The proxy does not decrypt TLS. HTTPS `CONNECT` verifies the requested hostname and port; certificate validation remains end-to-end between the sandboxed client and destination. Plain HTTP accepts one strictly framed request per connection and rejects ambiguous `Content-Length`, `Transfer-Encoding`, pipelining, and unverified follow-up requests. WebSocket tunneling begins only after a valid upstream `101` response.

Each Shell task and FastAPI worker receives a separate proxy instance with the token's current rules. Global and per-instance connection limits are described in [Installation and reverse proxy](installation.md#recommended-caddy-connection-limits).

Browser preview requests do not use the restricted-task allowlist. External preview resources are governed by the preview Content Security Policy.

## Podman images

The administration console lists images in the rootless Podman store owned by `openkapsel`. Each token can select a different image. Podman uses `--pull=never`, so a Shell request cannot download an image implicitly. If a selected image is removed, launch fails instead of silently choosing another image.

Pull an image into the service account's store:

```bash
sudo -u openkapsel env HOME=/var/lib/openkapsel/home XDG_RUNTIME_DIR=/var/lib/openkapsel/run \
  podman pull docker.io/library/python:3.14-slim-trixie
```

The included `containers/python-3.14-git/Containerfile` adds Git, curl, wget, and CA certificates:

```bash
cd /opt/openkapsel
sudo -u openkapsel env HOME=/var/lib/openkapsel/home XDG_RUNTIME_DIR=/var/lib/openkapsel/run \
  podman --cgroup-manager=cgroupfs build --pull=never --network=slirp4netns \
  --tag localhost/openkapsel-python:3.14-git containers/python-3.14-git
```

Bubblewrap sees host tools installed by `install.sh`. Podman sees only tools contained in its selected image.

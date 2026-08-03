# DevBox repository instructions

## Host and scope

- This checkout is `/home/me/src/tools/secret-gate` on `secret-gate.example.com`.
- Verify `pwd`, `hostname`, `id -un`, and `git status --short --branch` before changing files.
- Work as `nerveband`. Preserve unrelated changes and never print, persist, or commit secret values.

## Linux build and test

Use task-local writable caches. Integration tests create loopback TCP listeners and Unix sockets, so the execution sandbox must allow both.

```bash
mkdir -p /tmp/secret-gate-go-cache /tmp/secret-gate-go-mod /tmp/secret-gate-build
env GOCACHE=/tmp/secret-gate-go-cache GOMODCACHE=/tmp/secret-gate-go-mod go mod download
env GOCACHE=/tmp/secret-gate-go-cache GOMODCACHE=/tmp/secret-gate-go-mod go test -count=1 -race ./...
env GOCACHE=/tmp/secret-gate-go-cache GOMODCACHE=/tmp/secret-gate-go-mod go vet ./...
env GOCACHE=/tmp/secret-gate-go-cache GOMODCACHE=/tmp/secret-gate-go-mod CGO_ENABLED=0 go build -o /tmp/secret-gate-build/secret-gate ./cmd/client
env GOCACHE=/tmp/secret-gate-go-cache GOMODCACHE=/tmp/secret-gate-go-mod CGO_ENABLED=0 go build -o /tmp/secret-gate-build/secret-gate-server ./cmd/server
```

The local daemon uses `$XDG_RUNTIME_DIR/secret-gate.{sock,pid}` when that variable is set. It otherwise uses `/tmp/secret-gate-<uid>.{sock,pid}`. The socket and PID file must be mode `0600`.

Linux and macOS are the supported client platforms. Darwin artifacts built on DevBox are cross-builds; native macOS behavior is verified only by the macOS CI job. Windows is unsupported because the daemon and command executor require Unix sockets and POSIX process behavior.

## Local Docker stack

- Docker is a system service on DevBox. Use `sudo docker` and `sudo docker compose` for daemon operations.
- `docker-compose.local.yml` publishes Secret Gate on `127.0.0.1:18080` and 1Password Connect on `127.0.0.1:18081` through the host port mappings. Do not expose either service publicly.
- The local stack requires mode-`0600` `.env` and `1password-credentials.json` files. Do not create, copy, inspect, or commit those files during build-only validation.
- Validate Compose without secrets by supplying placeholder interpolation values to `docker compose config --quiet`. Only start the stack when the real local credential files already exist and the task authorizes using them.
- `scripts/local-connect-doctor.sh` checks the published ports after the stack starts.

## Cleanup

Generated Go caches and binaries belong under task-specific `/tmp/secret-gate-*` paths and can be deleted after verification. Before removing repository files, inspect `git status --ignored` and `git clean -ndX`. Preserve `.env`, `1password-credentials.json`, database volumes, source files, and unclear untracked work.

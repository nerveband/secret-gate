# Secret Gate repository instructions

## Host and scope

- This checkout is `/path/to/secret-gate` on `mac-server`. The Linux devbox was retired.
- Verify `pwd`, `hostname`, `id -un`, and `git status --short --branch` before changing files.
- Work as `nerveband`. Preserve unrelated changes and never print, persist, or commit secret values.

## Build and test

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

Linux and macOS are the supported client platforms. Run native macOS tests here. GitHub CI tests Linux and tests macOS on release tags and manual runs. Linux artifacts built here are cross-builds. Windows is unsupported because the daemon and command executor require Unix sockets and POSIX process behavior.

## CLI contract (0.4.0+)

- The client is noun-verb: `secret-gate item search|fields|read`, `exec`, `ssh`,
  `otp show|exec`, `write create|update`, `request submit|status|wait|cancel`,
  `daemon status|start|flush|stop`, `agent-context`, `schema`, `version`, `mcp`.
- One JSON envelope per invocation on stdout; errors are JSON on stderr.
  Exit codes are frozen — see docs/exit-codes.md.
- Guardrails for agents working on or with this CLI:
  - Always prefer `exec`/`ssh`/`otp exec` over `item read --reveal`.
  - Always run `daemon flush` without `--commit` first (it is a dry run).
  - Use `request submit --no-wait` + `request wait <token>` for long approvals.
  - Never add flags outside the canonical vocabulary; `TestManifestVocabulary`
    in internal/cli enforces the banned list mechanically.
  - `skills/secret-gate/SKILL.md` examples are validated against the live
    manifest by `TestSkillCommandsExistInManifest` — update both together.

## Deployment on mac-server

- Docker runs in Colima with CLI context `colima`. Use `docker` and the installed standalone `docker-compose`, without sudo. Never start Docker Desktop or change Docker context.
- The live Compose owner is `/path/to/deploy/compose.yaml`, in the server control workspace. Read that workspace's instructions before deploying.
- Follow [deploy/README.md](deploy/README.md). Deploy only the `secret-gate` service with `--no-deps`; preserve Connect containers, credentials, volumes, and the existing webhook URL.
- The live service publishes only `127.0.0.1:18080`. Connect has no host port. Credentials remain in the existing restricted files under `~/.config`; never inspect or copy their contents.
- Validate Compose without printing resolved environment values using `docker-compose ... config --quiet`. Build contexts must exclude `.env` and `1password-credentials.json`.
- `docker-compose.local.yml` is an optional local stack, not the live deployment owner. The DevBox systemd helpers are historical and must not be installed on mac-server.
- Release tags use `vMAJOR.MINOR.PATCH`. Update `internal/version`, its version test, and `CHANGELOG.md` together. Push the commit and tag only when authorized; verify CI and GitHub release assets, and report unavailable checks accurately.

## Cleanup

Generated Go caches and binaries belong under task-specific `/tmp/secret-gate-*` paths and can be deleted after verification. Before removing repository files, inspect `git status --ignored` and `git clean -ndX`. Preserve `.env`, `1password-credentials.json`, database volumes, source files, and unclear untracked work.

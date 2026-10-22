# Deployment and releases

Secret Gate runs on `mac-server` in Colima, using Docker context `colima`.
The Linux devbox was retired. The live Compose configuration belongs to the
server control workspace:

`/path/to/deploy/compose.yaml`

That file builds this checkout for Linux ARM64 and preserves the existing
Connect services, credential mounts, and webhook URL. Secret Gate listens on
`127.0.0.1:18080`; Connect has no published host port. Runtime credentials stay
in their existing restricted files under `~/.config`.

## Deploy on mac-server

Run from a clean, tested release checkout as `nerveband`. Read the server
workspace's `AGENTS.md` before deploying. Use the installed standalone
`docker-compose` command; do not start Docker Desktop or switch Docker context.

```sh
hostname
docker context show
git status --short --branch
compose=/path/to/deploy/compose.yaml
docker-compose -f "$compose" config --quiet
docker tag secret-gate-secret-gate secret-gate:pre-release
docker-compose -f "$compose" build secret-gate
docker-compose -f "$compose" up -d --no-deps --no-build secret-gate
curl -fsS http://127.0.0.1:18080/health
docker inspect secret-gate-secret-gate-1 --format '{{.State.Health.Status}}'
```

Wait for container health to report `healthy`. Keep the previous image until
verification succeeds. To roll back the server:

```sh
compose=/path/to/deploy/compose.yaml
docker tag secret-gate:pre-release secret-gate-secret-gate
docker-compose -f "$compose" up -d --no-deps --no-build secret-gate
curl -fsS http://127.0.0.1:18080/health
```

Build the native client with the task-local caches documented in
[AGENTS.md](../AGENTS.md). Preserve the installed client before replacing
`~/.local/bin/secret-gate` atomically, then run `secret-gate version`.
Existing MCP processes load the new binary when next started.

## Publish a release

Update `internal/version/version.go`, its test, and `CHANGELOG.md` together.
Run race tests, vet, builds, and a vulnerability scan before committing. Push
`main` and the matching `vMAJOR.MINOR.PATCH` tag only after release authorization.

The [release workflow](../.github/workflows/release.yml) publishes four client
binaries (Linux and macOS, AMD64 and ARM64), a GHCR image, and GitHub release
notes. The [test workflow](../.github/workflows/test.yml) runs Linux checks and
native macOS client tests on release tags. Check both workflows and the uploaded
assets. If GitHub Actions cannot start, report the cause and which local checks
ran. Do not describe unavailable CI checks as passed.

Deploy the same tagged source on mac-server. Pushing a tag does not update the
live service automatically.

## Historical DevBox files

`scripts/deploy-devbox-release`, `scripts/install-devbox-release-deployer`, and
`deploy/systemd/` remain for historical reference. They target the retired Linux
host and must not be installed or run on mac-server. The optional
`docker-compose.local.yml` is separate from the live server workspace.

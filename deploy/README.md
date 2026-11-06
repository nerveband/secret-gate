# Deployment and releases

Secret Gate deploys as a container next to 1Password Connect. Keep the Compose
file that owns your live deployment outside this repository, so credentials,
hostnames, and webhook URLs never land in source control. Point its
`secret-gate` build context at a checkout of this repository.

Recommended shape:

- Publish Secret Gate on loopback only (for example `127.0.0.1:18080`) and reach
  it through a reverse proxy or tailnet.
- Give 1Password Connect no published host port.
- Keep runtime credentials in restricted files (mode `0600`) and exclude `.env`
  and `1password-credentials.json` from the build context.

Maintainers keep host-specific notes in `deploy/LOCAL.md`, which is gitignored.

## Deploy

Run from a clean, tested release checkout. Validate Compose without printing
resolved environment values, and deploy only the `secret-gate` service so
Connect containers, credentials, and volumes stay untouched.

```sh
git status --short --branch
compose=/path/to/deploy/compose.yaml
docker-compose -f "$compose" config --quiet
docker tag secret-gate-secret-gate secret-gate:pre-release
docker-compose -f "$compose" build secret-gate
docker-compose -f "$compose" up -d --no-deps --no-build secret-gate
curl -fsS http://127.0.0.1:18080/health
docker inspect secret-gate-secret-gate-1 --format '{{.State.Health.Status}}'
```

Image and container names follow your Compose project name. Wait for container
health to report `healthy`. Keep the previous image until verification
succeeds. To roll back:

```sh
docker tag secret-gate:pre-release secret-gate-secret-gate
docker-compose -f "$compose" up -d --no-deps --no-build secret-gate
curl -fsS http://127.0.0.1:18080/health
```

Build the native client with the task-local caches documented in
[AGENTS.md](../AGENTS.md). Preserve the installed client before replacing
`~/.local/bin/secret-gate` atomically, then run `secret-gate version`.
Existing MCP processes load the new binary when next started.

`docker-compose.local.yml` is an optional self-contained local stack
(Connect plus Secret Gate) for development.

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

Pushing a tag does not update a running deployment; deploy the same tagged
source yourself.

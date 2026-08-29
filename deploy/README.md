# DevBox release deployment

The systemd timer deploys the highest `vMAJOR.MINOR.PATCH` tag reachable from
`origin/main`. The root-owned helper uses the existing DevBox GitHub CLI login
to clone the private, hard-coded GitHub origin into
`/var/lib/secret-gate-release`, archives the verified tag there, and runs
`docker-compose.local.yml`. Runtime credentials remain in their existing
mode-restricted files outside the repository. Published ports stay bound to
loopback. The archived release contains links to those protected files so the
same helper can deploy v0.5.0, whose Compose file still uses conventional local
filenames.

One root installation is required. From the repository checkout on DevBox:

```sh
sudo ./scripts/install-devbox-release-deployer
```

From another Tailscale-connected machine, update the checkout and install it in
one command:

```sh
ssh nerveband@100.64.0.2 'cd /home/me/src/tools/secret-gate && git pull --ff-only && sudo ./scripts/install-devbox-release-deployer'
```

Check the result without reading environment or credential files:

```sh
systemctl status secret-gate-release-deploy.service --no-pager
curl -fsS http://127.0.0.1:18080/health
```

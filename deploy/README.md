# DevBox release deployment

The systemd timer deploys the highest `vMAJOR.MINOR.PATCH` tag reachable from
`origin/main`. The root-owned helper clones the hard-coded GitHub origin into
`/var/lib/secret-gate-release`, archives the verified tag there, and runs
`docker-compose.local.yml`. Runtime credentials remain in their existing
mode-restricted files outside the repository. Published ports stay bound to
loopback. The archived release contains links to those protected files so the
same helper can deploy v0.5.0, whose Compose file still uses conventional local
filenames.

One root installation is required:

```sh
sudo install -o root -g root -m 0755 scripts/deploy-devbox-release /usr/local/sbin/deploy-devbox-secret-gate
sudo install -o root -g root -m 0644 deploy/systemd/secret-gate-release-deploy.service /etc/systemd/system/secret-gate-release-deploy.service
sudo install -o root -g root -m 0644 deploy/systemd/secret-gate-release-deploy.timer /etc/systemd/system/secret-gate-release-deploy.timer
sudo systemctl daemon-reload
sudo systemctl disable secret-gate.service
sudo systemctl enable --now secret-gate-release-deploy.timer
sudo systemctl start secret-gate-release-deploy.service
```

Check the result without reading environment or credential files:

```sh
systemctl status secret-gate-release-deploy.service --no-pager
curl -fsS http://127.0.0.1:18080/health
```

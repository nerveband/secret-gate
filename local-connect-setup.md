# Local Secret Gate + 1Password Connect Setup

This local setup runs:

- `op-connect-api` on `http://localhost:18081`
- `op-connect-sync`
- `secret-gate` on `http://localhost:18080`

Required 1Password artifacts:

- `1password-credentials.json` in this directory
- `OP_CONNECT_TOKEN` in `.env`

Both `.env` and `1password-credentials.json` must have mode `0600`:

```bash
chmod 600 .env 1password-credentials.json
```

Start:

```bash
sudo docker compose --env-file .env -f docker-compose.local.yml up -d
```

Verify 1Password Connect:

```bash
curl -fsS \
  -H "Accept: application/json" \
  -H "Authorization: Bearer $OP_CONNECT_TOKEN" \
  http://localhost:18081/v1/vaults
```

Verify Secret Gate:

```bash
curl -fsS http://localhost:18080/health
```

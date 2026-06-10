# Local Secret Gate + 1Password Connect Setup

This local setup runs:

- `op-connect-api` on `http://localhost:8081`
- `op-connect-sync`
- `secret-gate` on `http://localhost:8080`

Required 1Password artifacts:

- `1password-credentials.json` in this directory
- `OP_CONNECT_TOKEN` in `.env`

Start:

```bash
docker compose --env-file .env -f docker-compose.local.yml up -d
```

Verify 1Password Connect:

```bash
curl -fsS \
  -H "Accept: application/json" \
  -H "Authorization: Bearer $OP_CONNECT_TOKEN" \
  http://localhost:8081/v1/vaults
```

Verify Secret Gate:

```bash
curl -fsS http://localhost:8080/health
```

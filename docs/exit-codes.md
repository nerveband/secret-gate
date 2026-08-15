# secret-gate exit codes (frozen contract, schema_version 1.0)

| Code | Meaning | Typical `error.code` |
|---|---|---|
| 0 | success | — |
| 1 | internal error, or child process exited non-zero (see `data.exit_code`) | `internal` |
| 2 | usage or validation error | `usage`, `validation` |
| 3 | approval denied | `denied` |
| 4 | approval expired or wait timed out | `expired`, `timeout` |
| 5 | network or server error | `network`, `server` |
| 6 | item, field, token, or cache entry not found | `not_found`, `not_cached` |

Success envelope on stdout; error envelope on stderr. See
`secret-gate agent-context --json` for the machine-readable version.

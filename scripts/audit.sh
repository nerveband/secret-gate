#!/usr/bin/env bash
# Runnable subset of Ashraf Ali's 85-point Agent CLI Audit against the
# built secret-gate binary. Network-dependent checks use an unroutable
# server so they exercise the error contract deterministically.
set -u

BIN="${1:-/tmp/secret-gate-build/secret-gate}"
export XDG_RUNTIME_DIR="$(mktemp -d)"
export SECRET_GATE_STATE_DIR="$(mktemp -d)"
export SECRET_GATE_URL="http://127.0.0.1:9"
export HOME="$(mktemp -d)"

pass=0; fail=0

check() { # <name> <want_exit> <want_stream:stdout|stderr> <want_pattern> -- cmd...
  local name="$1" want_exit="$2" stream="$3" pattern="$4"; shift 5
  local out err code
  out="$("$@" 2>/tmp/audit-stderr)"; code=$?
  err="$(cat /tmp/audit-stderr)"
  local hay="$out"; [ "$stream" = "stderr" ] && hay="$err"
  if [ "$code" -eq "$want_exit" ] && printf '%s' "$hay" | grep -q -e "$pattern"; then
    pass=$((pass+1)); printf 'PASS %s\n' "$name"
  else
    fail=$((fail+1)); printf 'FAIL %s (exit=%s want=%s)\n' "$name" "$code" "$want_exit"
  fi
}

# 1.x discoverability
check "1.1 root help lists subcommands" 0 stdout "item search"        -- "$BIN" --help
check "1.6 machine-readable manifest"   0 stdout '"commands"'          -- "$BIN" schema
check "1.7 version queryable"           0 stdout '"version"'           -- "$BIN" version
# 2.x structured output
check "2.1 JSON envelope"               0 stdout '"schema_version"'    -- "$BIN" version
check "2.4 structured errors"           2 stderr '"code"'              -- "$BIN" frobnicate
check "2.5a usage exit code"            2 stderr '"usage"'             -- "$BIN" item read --item x
check "2.5b network exit code"          5 stderr '"network"'           -- "$BIN" item search --query deploy
check "2.5c not-found exit code"        6 stderr '"not_found"'         -- "$BIN" exec --item ghost --field f --env V -- true
# 3.x input flexibility
check "3.2 stdin required for writes"   2 stderr "stdin"               -- "$BIN" write create --item x --vault v --reason r
# 4.x safety rails
check "4.1 flush is dry-run by default" 0 stdout '"message"'           -- "$BIN" daemon flush
check "4.4 commit flag exists"          0 stdout '"flushed"\|"message"' -- "$BIN" daemon flush --commit
# 5.x error handling
check "5.4 errors carry hints"          6 stderr '"hint"'              -- "$BIN" exec --item ghost --field f --env V -- true
# security: legacy leak closed, reveal gate
check "S1 legacy flag mode refused"     2 stderr "removed in 0.4.0"    -- "$BIN" --secret deploy-key
check "S2 reveal gate on item read"     2 stderr "--reveal"            -- "$BIN" item read --item x
check "S3 reveal gate on otp show"      2 stderr "--reveal"            -- "$BIN" otp show --item x
# introspection
check "T1 agent-context"                0 stdout '"visibility_classes"' -- "$BIN" agent-context --json

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]

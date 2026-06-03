#!/usr/bin/env bash
#
# seadog-wrapper — the kanibako-side thin client. Forwards a seadog verb
# (and its args) over SSH to the testenv login shell on the host. The
# host is $SEADOG_HOST (default blue). Output is the front-end's JSON.
#
# Examples:
#   seadog-wrapper create --image loom --ttl 1h
#   seadog-wrapper ls
#   SEADOG_HOST=blue2 seadog-wrapper destroy g-1a2b

set -euo pipefail

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  # SC2016: the literal $SEADOG_HOST is intended as documentation here.
  # shellcheck disable=SC2016
  printf 'usage: %s <verb> [args...]\n  forwards to ssh testenv@$SEADOG_HOST (default blue)\n' "$(basename "$0")"
  exit 0
fi

exec ssh "testenv@${SEADOG_HOST:-blue}" -- "$@"

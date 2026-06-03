#!/usr/bin/env bash
# Fake `seadog-priv` for the seadog front-end integration tests.
#
# The real helper is Phase 3a; this stand-in lets the front-end's
# privileged path (elevate + spawn_watcher) be exercised end-to-end with
# `$SEADOG_SUDO=""` (no real sudo) and `$SEADOG_PRIV_BIN` pointed here.
#
# Behavior is selected by the first arg (the verb) and tuned by env vars:
#   $SEADOG_FAKE_LOG       - append the full argv (one line) for assertions.
#   $SEADOG_FAKE_FAIL      - if non-empty, provision/teardown exit non-zero
#                            (with a stderr message) to test rollback.
#   $SEADOG_WATCHER_LOCK   - flock path; `watch` grabs it to prove at-most-one.
#   $SEADOG_WATCHER_MARKER - `watch` appends one line here ONLY if it won
#                            the flock (proves the singleton guard).
#
# JSON-only on stdout for provision/teardown (the front-end parses it).

verb="$1"

# Record the invocation for argv assertions (best-effort).
if [ -n "$SEADOG_FAKE_LOG" ]; then
  printf '%s\n' "$*" >>"$SEADOG_FAKE_LOG"
fi

case "$verb" in
  provision)
    if [ -n "$SEADOG_FAKE_FAIL" ]; then
      echo "fake provision failure (forced)" >&2
      exit 7
    fi
    echo '{"ok":true,"verb":"provision"}'
    ;;
  teardown)
    if [ -n "$SEADOG_FAKE_FAIL" ]; then
      echo "fake teardown failure (forced)" >&2
      exit 7
    fi
    echo '{"ok":true,"verb":"teardown"}'
    ;;
  watch)
    # Prove at-most-one: grab the flock; only the winner appends a marker
    # line. A concurrent invocation that can't get the lock (flock -n)
    # exits 0 without appending. We hold the lock across a short sleep so a
    # racing second invocation overlaps and is rejected.
    lock="${SEADOG_WATCHER_LOCK:-/tmp/seadog-fake-watch.lock}"
    marker="${SEADOG_WATCHER_MARKER:-/tmp/seadog-fake-watch.marker}"
    exec 9>"$lock"
    if flock -n 9; then
      printf 'watch %s\n' "$$" >>"$marker"
      sleep 0.5
    fi
    exit 0
    ;;
  *)
    echo "{\"error\":\"fake seadog-priv: unknown verb '$verb'\"}" >&2
    exit 2
    ;;
esac

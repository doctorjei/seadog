# fake-kento — a fake `kento` for exercising `RealKento`

This harness stands in for the real `kento` CLI so seadog's feature-gated
`RealKento` backend (which shells **only** `kento` — every guest op routes
through it) can be driven through a full lifecycle with **no real backend in
the loop**. It maintains a single JSON instance-table state file and
reproduces the exact command shapes + output formats `RealKento` invokes and
parses (`crates/core/src/kento.rs`, the source of truth).

> seadog is kento-native: ALL guest operations route through `kento` (which
> itself runs on raw lxc/qemu OR PVE backends). There is no PVE — and no
> `qm`/`pct`/`pvesh` — in this harness; it is kento-only.

The end-to-end driver that uses it is `../pseudo-soak.sh`.

## Files

| File        | Stands in for | Subcommands implemented |
|-------------|---------------|--------------------------|
| `kento`     | `kento`       | `list`, `inspect … --json`, `<lxc\|vm> create`, `<lxc\|vm> destroy -f` |
| `_lib.sh`   | (shared lib)  | sourced by the shim; owns the state file + formatters |

Anything outside the surface `RealKento` actually calls hits a loud
`unsupported` error so future drift in `RealKento` is caught.

## The command contract (what `RealKento` invokes)

Derived directly from `crates/core/src/kento.rs`. kento is backend-neutral and
addresses instances **by name** (never a vmid); the live `kento list` IS the
set seadog observes (kento only knows kento-managed instances), and the seadog
identity anchor rides in injected env.

- **`list_instances`** → `kento list` (columnar table, NAME first column; the
  empty-set sentinel `(no instances found)` when none), then per instance
  `kento inspect <name> --json` to read the realized signals.
- **`provision`** → `kento <lxc|vm> create --name <n> --network bridge=<b>
  --ip <ip>/<prefix> --gateway <gw> --ssh-host-keys --start --env
  SEADOG_GUID=<g> --env SEADOG_OWNER=<o> [--ssh-key <f> --ssh-key-user <u>
  --config-mode auto] [--mac <m> for VM ONLY] [--allow-nesting] <image-ref>`
  (kento owns networking / ssh-host-key injection / start). The seadog
  identity anchor is the injected `SEADOG_GUID` / `SEADOG_OWNER` env —
  create-time-immutable, replacing the old PVE description marker. Then the
  realized signals are read back via `kento inspect <name> --json`. kento
  reports a realized MAC for **VM modes only** (present-only); an LXC has no
  MAC, so the `mac` field is omitted entirely (`parse_kento_inspect` maps
  absence to `None` — the LXC sentinel).
- **`teardown`** → `kento <lxc|vm> destroy -f <name>` (removes **by instance
  name**, so kento's overlay state is cleaned alongside the backend guest;
  `-f` forces a running instance).

## State file

One JSON object at `$FAKE_KENTO_STATE` (default `/tmp/fake-kento/state.json`),
keyed on the instance **name** (kento's primary key):

```json
{
  "instances": [
    {
      "name": "seadog-jei-loom-ab12",
      "mode": "lxc",
      "type": "LXC",
      "image": "registry.example.com/loom:1.0",
      "status": "running",
      "environment": [
        "SEADOG_GUID=<guid>",
        "SEADOG_OWNER=<owner>"
      ],
      "ssh_host_key_fingerprints": {
        "ed25519": "SHA256:fp-ed25519-seadog-jei-loom-ab12",
        "rsa": "SHA256:fp-rsa-seadog-jei-loom-ab12"
      }
    }
  ]
}
```

This is exactly the dict `kento inspect --json` reports, so `RealKento`'s
`parse_kento_inspect` consumes it unchanged. The `type` field is the
authoritative family signal kento ALWAYS emits from inspect (`VM` for
vm/pve-vm modes, else `LXC`) and is what seadog collapses the family on; the
shim stores it at create time and synthesizes it from `mode` for any injected
fixture row that omits it. Fields kento leaves unset are simply **absent** (a
vanilla `lxc`/`vm` instance carries no `vmid`, so the field is omitted and
`parse_kento_inspect` maps absence to `None`; an LXC likewise carries no
`mac`, since kento reports a MAC for VM modes only — the example above is an
LXC and so has no `mac` field). A row that DOES carry a PVE backend mode
(`pve` for PVE-LXC — kento promotes it to bare `pve`, NOT `pve-lxc`, which
exists only in the `list` TYPE column; `pve-vm` for PVE-VM) and a numeric
`vmid` is replayed verbatim by inspect/list, so the fake can exercise
`parse_kento_inspect`'s type-driven family collapse and `vmid` extraction
(present-only — absent for the vanilla modes, so other scenarios are
unchanged).

Semantics:

- **create / provision** (`kento <lxc|vm> create`) → records an instance row
  with the injected `environment[]` anchor + stable host-key fingerprints. The
  `mac` is present-only: a VM keeps the passed `--mac`; an LXC has none (and
  `--mac` is REJECTED for LXC), so the field is omitted.
- **list / inspect** → render the columnar table (or one instance's JSON dict)
  in the exact shape the real `kento` produces, so the `RealKento` parsers
  consume them unchanged.
- **destroy / teardown** → removes the instance row **by name**.
- A missing instance → non-zero exit with a realistic "does not exist"
  message.

The state file is kept world-writable (`0666`): `RealKento::run()`
`env_clear()`s before exec, so the shim may run under whatever uid invoked the
helper (often root via sudo) while an unprivileged driver also rewrites the
table to inject instances — both must be able to replace it.

## Environment knobs

| Var | Default | Effect |
|-----|---------|--------|
| `FAKE_KENTO_STATE` | `/tmp/fake-kento/state.json` | Path to the instance-table state file. **Note:** `RealKento::run()` env-clears before exec, so a helper-spawned shim only ever sees the default; pin both sides to the same path. |
| `FAKE_KENTO_QUORUM_LOST` | unset | When set (e.g. `=1`), the shim emits `cfs-locked operation - Read-only file system (no quorum?)` on stderr and exits non-zero. The "Read-only file system" substring matches `RealKento`'s quorum markers, so this drives the reaper's quorum-loss path. (kento runs on PVE backends too, where a corosync partition still drops pmxcfs to read-only and surfaces the same wording through the failing `kento` invocation.) |

## Conventions

`#!/usr/bin/env bash`, `set -euo pipefail`, single-line commands (no
backslash continuations). `jq` is required. `shellcheck` + `bash -n` clean.

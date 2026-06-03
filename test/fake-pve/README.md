# fake-pve — a simulated Proxmox node for exercising `RealKento`

These four shell shims stand in for the real Proxmox tools so seadog's
feature-gated `RealKento` backend (which shells `qm`/`pct`/`kento`/`pvesh`)
can be driven through a full lifecycle with **no real PVE in the loop**. They
maintain a single JSON "guest table" state file and reproduce the exact
command shapes + output formats `RealKento` invokes and parses
(`crates/core/src/kento.rs`).

The end-to-end driver that uses them is `../pseudo-soak.sh`.

## Files

| File        | Stands in for | Subcommands implemented |
|-------------|---------------|--------------------------|
| `pvesh`     | `pvesh`       | `get /cluster/resources --output-format json` |
| `qm`        | `qm` (VMs)    | `config`, `set`, `create`, `destroy` |
| `pct`       | `pct` (LXC)   | `config`, `set`, `create`, `destroy`, `exec` |
| `kento`     | `kento`       | `create` |
| `_lib.sh`   | (shared lib)  | sourced by the shims; owns the state file + formatters |

## The command contract (what `RealKento` invokes)

Derived directly from `crates/core/src/kento.rs`:

- **`list_guests`** → `pvesh get /cluster/resources --output-format json`
  (enumerate vmid+type), then per in-range guest `qm config <vmid>` (VM) /
  `pct config <vmid>` (LXC).
- **`teardown`** → `pct destroy <vmid> --purge` / `qm destroy <vmid> --purge`.
- **`provision`** → `kento create --vmid <v> --mode <lxc|vm> --image-ref
  <ref> --name <n> --mac <m> --ip <ip>`, then `pct set <v> --hostname <n>
  --description <d>` / `qm set <v> --name <n> --description <d>`.
- **`set_meta`** → `pct set <v> [--description <d>] [--tags seadog-ttl-<ts>]`
  / `qm set …`.
- **`start_sshd`** → `pct exec <v> -- systemctl start ssh`.

## State file

One JSON object at `$FAKE_PVE_STATE` (default `/tmp/fake-pve/state.json`):

```json
{
  "guests": [
    {
      "vmid": 10010,
      "mode": "lxc",
      "name": "seadog-jei-proj-ab12",
      "description": "seadog-guid:<guid>\nseadog-owner:<owner>",
      "mac": "aa:bb:cc:dd:ee:ff",
      "tags": "seadog-ttl-1700000000",
      "bridge": "vmbr0",
      "model": "veth",
      "vlan": null,
      "machine": "",
      "bios": "",
      "scsihw": "",
      "memory": 1024,
      "cores": 2,
      "disk_geometry": "local:10010/vm-10010-disk-0.raw",
      "disk_size": 8589934592
    }
  ]
}
```

`description` is stored decoded (real newlines). On a `config` read it is
emitted **percent-encoded** (`:` → `%3A`, newline → `%0A`) exactly as real
PVE round-trips a `--description` body — which exercises `RealKento`'s
`pve_unescape` path so the `seadog-guid:`/`seadog-owner:` markers re-split.

Semantics:

- **create / provision** (`kento create`, or `qm`/`pct create`) → adds a
  guest row with realistic hardware/fingerprint defaults; `qm`/`pct set`
  then stamp the seadog name/description markers.
- **set** → mutates `name`/`hostname`, `description`, or appends a tag.
- **config / list / `pvesh get /cluster/resources`** → renders the table (or
  one guest's config) in the same `key: value` / JSON-array shape the real
  tools produce, so the `RealKento` parser consumes it unchanged.
- **destroy / teardown** → removes the guest row.
- A missing guest → non-zero exit with a realistic "does not exist" message.

The state file is kept world-writable (`0666`): `RealKento::run()`
`env_clear()`s before exec, so a shim may run under whatever uid invoked the
helper (often root via sudo) while an unprivileged driver also rewrites the
table to inject guests — both must be able to replace it.

## Environment knobs

| Var | Default | Effect |
|-----|---------|--------|
| `FAKE_PVE_STATE` | `/tmp/fake-pve/state.json` | Path to the guest-table state file. **Note:** `RealKento::run()` env-clears before exec, so a helper-spawned shim only ever sees the default; pin both sides to the same path. |
| `FAKE_PVE_QUORUM_LOST` | unset | When set (e.g. `=1`), every shim emits `cfs-locked operation - Read-only file system (no quorum?)` on stderr and exits non-zero. The "Read-only file system" substring matches `RealKento`'s quorum markers, so this drives the reaper's quorum-loss path. |

## Conventions

`#!/usr/bin/env bash`, `set -euo pipefail`, single-line commands (no
backslash continuations). `jq` is required. `shellcheck` + `bash -n` clean.

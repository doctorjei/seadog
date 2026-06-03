# seadog

**seadog** is an ephemeral test-environment provisioner for the Flamingo
Proxmox cluster. You SSH to a locked-down `testenv` login shell, run one
verb, and get back JSON. It hands you short-lived LXC containers and VMs
that **reap themselves** when their lease expires — so a forgotten test
box can't quietly live forever and exhaust the cluster.

## Model

- **One connection, one verb.** `testenv`'s login shell *is* the seadog
  front-end (the git-shell pattern). sshd hands it your command; it runs
  exactly one verb and exits. There is no interactive shell.
- **JSON output.** Every verb prints pretty JSON on stdout; errors are a
  JSON `{ "error": "…" }` object on stderr with a non-zero exit. Pipe it
  straight into `jq`.
- **Identity comes from your key, not your command.** Each authorized
  key carries a forced `command=".../seadog --owner <name>"`, so the
  trusted *owner* of every env is decided by which key authenticated.

## Usage

```sh
# Provision a 1-hour LXC from the `loom` image:
ssh testenv@blue create --image loom --ttl 1h

# List your active envs / show one / extend a lease / tear one down:
ssh testenv@blue ls
ssh testenv@blue show g-1a2b3c
ssh testenv@blue extend g-1a2b3c 30m
ssh testenv@blue destroy g-1a2b3c

# Operator + introspection verbs:
ssh testenv@blue health           # binary version, reaper heartbeat, counts
ssh testenv@blue stats            # env counts by status / owner
ssh testenv@blue history 24h      # terminal envs in a window
ssh testenv@blue ack 10010        # acknowledge a vmid notification
```

A thin client wrapper, `deploy/seadog-wrapper.sh`, is what kanibako
shells out to — it just forwards args to `ssh testenv@$SEADOG_HOST`
(default `blue`):

```sh
SEADOG_HOST=blue seadog-wrapper create --image stuffer --ttl 2h
```

### Image allowlist

`create` never takes an OCI ref — only an allowlisted image **name** from
`/etc/seadog/config.yaml`. The cluster ships three:

| image      | modes        |
| ---------- | ------------ |
| `loom`     | LXC          |
| `stuffer`  | VM           |
| `kanibako` | LXC or VM    |

The first allowed mode is the default when you omit `--mode`.

## Architecture

seadog is **two static-musl binaries split by privilege**, over a shared
`core` library:

- `seadog` — the unprivileged front-end / login shell. Tokenizes your
  command without ever spawning a shell, resolves the trusted owner from
  sshd context, serves DB-only verbs directly, and routes the two
  elevated verbs (`create`/`destroy`) through a **sudo bridge**.
- `seadog-priv` — the root helper, reached only via
  `sudo seadog-priv <verb> …`. It **trusts nothing** from the front-end:
  it re-loads its own config and re-validates every argument, guards on
  `euid 0`, and for a teardown re-triangulates the target against **live
  PVE** rather than the DB.

Auto-reaping is conservative by design: an env is only auto-destroyed
when **identity triangulation reaches unanimous agreement** that the
guest on the cluster is the one seadog created (DB record, live PVE
signals, and hardware fingerprint all concur). Anything ambiguous is
flagged, never reaped. Reaping runs through **two diverse mechanisms** —
a fast in-process watcher loop spawned while envs are active, and an
always-on systemd timer backstop — so a failure in one can't disable
reaping. All privileged operations are logged to **journald**.

## Build

```sh
cargo build --release --target x86_64-unknown-linux-musl
cargo test
```

Both binaries link statically against musl so they drop onto a Proxmox
host with no runtime dependencies.

## Install

Run the installer **on blue, as root** — it creates the `testenv` user
and `seadog` group, installs the binaries, sudoers/tmpfiles/systemd
units, the sshd snippet, and an initial config:

```sh
sudo ./deploy/install.sh
```

See `deploy/install.sh` for the bootstrap-key arguments that authorize
the first owner.

## License

GPL-3.0-or-later. See [LICENSE.md](LICENSE.md).

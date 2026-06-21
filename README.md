# seadog

**seadog** is an ephemeral test-environment provisioner. You SSH to a
locked-down `testenv` login shell, run one verb, and get back JSON. It
hands you short-lived LXC containers and VMs that **reap themselves**
when their lease expires — so a forgotten test box can't quietly live
forever and exhaust the host.

Guests are provisioned through [**kento**](https://github.com/doctorjei/kento),
which composes OCI images into LXC system containers or QEMU VMs over
overlayfs. seadog shells the `kento` CLI only and is **backend-neutral**:
kento runs on raw `lxc`/`qemu` as well as Proxmox `pve-lxc`/`pve-vm`, and
seadog never touches `pvesh`/`qm`/`pct` directly. Proxmox is the common
deployment, but seadog runs on any host running kento.

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

Each env is identified by its env-id, a uuid-style GUID returned by
`create` (e.g. `4dc67469-3031-4f0a-9b21-0c7e8a2f1d44`). The same id is
what `show`/`extend`/`destroy`/`ack` take.

```sh
# Provision a 1-hour LXC from the `loom` image:
ssh testenv@<kento-host> create --image loom --ttl 1h

# List your active envs / show one / extend a lease / tear one down:
ssh testenv@<kento-host> ls
ssh testenv@<kento-host> show 4dc67469-3031-4f0a-9b21-0c7e8a2f1d44
ssh testenv@<kento-host> extend 4dc67469-3031-4f0a-9b21-0c7e8a2f1d44 30m
ssh testenv@<kento-host> destroy 4dc67469-3031-4f0a-9b21-0c7e8a2f1d44

# Operator + introspection verbs:
ssh testenv@<kento-host> ls --all       # every env (operator view), not just yours
ssh testenv@<kento-host> health         # binary version, reaper heartbeat, counts
ssh testenv@<kento-host> stats          # env counts by status / owner
ssh testenv@<kento-host> history 24h    # terminal envs in a window
ssh testenv@<kento-host> ack 4dc67469-3031-4f0a-9b21-0c7e8a2f1d44  # ack an env's notification
ssh testenv@<kento-host> images         # the served image catalog (valid --image names)
ssh testenv@<kento-host> help           # plain-text usage (also --help / <verb> --help)
```

`create` flags: `--image <name>` (required, an allowlist name — never an
OCI ref), `--mode lxc|vm` (defaults to the image's first allowed mode),
`--ttl <dur>` (hard-kill override), `--duration <dur>` (soft "expected
done" override), `--memory <MB>` / `--cores <N>` (explicit guest sizing,
both modes; clamped to `allocation.caps.max_memory_mb` / `max_cores`).
Durations are humantime strings (`30m`, `1h`, `2h30m`). Omit `--memory` /
`--cores` and kento applies its own default sizing — seadog imposes none.

A thin client wrapper, `deploy/seadog-wrapper.sh`, lets a caller shell out
to seadog — it just forwards args to `ssh testenv@$SEADOG_HOST`:

```sh
SEADOG_HOST=<kento-host> seadog-wrapper create --image stuffer --ttl 2h
```

### Image allowlist

`create` never takes an OCI ref — only an allowlisted image **name** from
`/etc/seadog/config.yaml`. Each entry maps a name to
`{ ref, modes, [user], [allow_nesting] }`. seadog is
**image-source-agnostic**: the allowlist is a generic operator catalog,
not tied to any one image source (the example refs happen to come from
[droste](https://github.com/doctorjei/droste), but that's just one source
— configure your own and pin exact tags/digests, never `:latest`).

The shipped example (`deploy/config.yaml.example`):

| image            | modes      | nesting |
| ---------------- | ---------- | ------- |
| `loom`           | LXC        | no      |
| `stuffer`        | VM         | no      |
| `stuffer-nested` | VM         | yes     |
| `ci`             | LXC or VM  | no      |

The first allowed mode is the default when you omit `--mode`.

`allow_nesting` (optional, per-alias, default false) permits nesting and
is mode-agnostic: an LXC guest may run nested containers; a VM guest is
exposed CPU virt extensions (vmx/svm) for hardware-accelerated nesting.
Nesting is gated by the alias, re-validated across the privilege boundary
by OCI ref — so the **same** ref may be listed under two aliases with
different nesting policies (e.g. `stuffer` and `stuffer-nested` above both
point at the same image).

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
  `euid 0`, and shells `kento` for the actual guest operations. For a
  teardown it re-validates the target against **live kento** (not the DB
  alone, and never raw PVE).

Every env carries an injected, create-time-immutable identity anchor —
`SEADOG_GUID` (plus `SEADOG_OWNER`) — in its environment, and auto-reap
is keyed on that GUID with a **DB-authoritative deadline** (SQLite).
Confirmers are checked only when present: the env **name**, its **MAC**
(VM only — an LXC MAC is unobservable, so it's recorded as an empty
sentinel), and **ssh host-key fingerprints** (soft). A confirmer
**mismatch flags the env — it is never reaped.** There is no hardware
fingerprint and no live-PVE triangulation. seadog classifies each
observed instance as *foreign* (no GUID → ignored), *orphan* (GUID but no
DB row → re-adopted on a fresh lease and flagged), *vanished* (an Active
DB row with no live instance → marked terminal), or *reap-eligible* (past
deadline + grace). A backend vmid is informational only (PVE-only, may be
absent) — never an identity key.

A teardown (`destroy` / `seadog-priv teardown`) re-validates that the
requesting owner matches the env's DB row **and** that a live kento
instance carries the matching GUID, then tears down **by name**
(re-validated against live kento). Reaping runs through **two diverse
mechanisms** — a fast in-process watcher loop spawned while envs are
active, and an always-on systemd timer backstop — so a failure in one
can't disable reaping. All privileged operations are logged to
**journald**.

## Build

```sh
cargo build --release --target x86_64-unknown-linux-musl
cargo test
```

Both binaries link statically against musl so they drop onto the kento
host (often Proxmox/Debian) with no runtime dependencies.

## Install

Releases ship versioned `.deb`, `.rpm`, and tarball assets on the
[Releases page](https://github.com/doctorjei/seadog/releases). Every method
installs the same two static-musl binaries plus the sudoers/sshd/systemd/
sysusers/tmpfiles plumbing, creates the `testenv` user + `seadog` group, and
drops an initial `/etc/seadog/config.yaml`. **Review that config and
authorize owners (below) before use.** Deeper detail — what each package
creates, conffile behavior, uninstall vs. purge — is in [INSTALL.md](INSTALL.md).

### Debian / Proxmox — `.deb` (recommended)

The kento host is commonly Proxmox, which is Debian, so the `.deb` is the
practical primary package:

```sh
sudo apt install ./seadog_<ver>-1_amd64.deb
```

(`dpkg -i` works too; `apt` additionally pulls the `systemd` dependency.)
`/etc/seadog/config.yaml` is a conffile, so your edits survive upgrades.
Remove with `sudo apt remove seadog` (keeps config + data) or
`sudo apt purge seadog` (removes everything, including the user/group).

### Fedora / RHEL — `.rpm`

```sh
sudo dnf install ./seadog-<ver>-1.x86_64.rpm
```

RPM has no remove/purge split, so `sudo dnf remove seadog` is a full
teardown (the equivalent of `apt purge`).

### Tarball + installer (any host / air-gapped)

For hosts without apt/dnf, unpack the release tarball and run the bundled
installer **on the kento host, as root**:

```sh
tar -xzf seadog-<ver>-x86_64-musl.tar.gz
sudo ./seadog-<ver>-x86_64-musl/deploy/install.sh
```

`install.sh --uninstall` reverses an install (keeping config + data);
add `--purge` to wipe everything. `install.sh --version` prints the version.
Or bootstrap in one line — downloads the latest release tarball, verifies
its SHA256, and runs the installer:

```sh
curl -fsSL https://raw.githubusercontent.com/doctorjei/seadog/main/deploy/get-seadog.sh | bash
```

### From source

Build the binaries (see [Build](#build)) and run the same installer:

```sh
sudo ./deploy/install.sh
```

`install.sh` also takes bootstrap-key arguments to authorize the first
owner in one shot (`sudo ./deploy/install.sh [BUILD_DIR] <key-line> <owner>`);
see its `--help`.

### Managing owners

Each owner is a key in the root-owned `/etc/seadog/authorized_keys`,
carrying its forced `command=".../seadog --owner <name>"`. Rather than
hand-editing that file, use `seadog-priv` (it validates the name, writes
the line atomically, and re-asserts `root:root 0644`):

```sh
sudo /usr/lib/seadog/seadog-priv add-owner --owner alice --key "ssh-ed25519 AAAA... alice@host"
sudo /usr/lib/seadog/seadog-priv list-owners
sudo /usr/lib/seadog/seadog-priv remove-owner --owner alice
```

`add-owner` is idempotent on the key blob: re-adding the same key for the
same owner is a no-op, and a key already mapped to a *different* owner is
rejected.

## License

GPL-3.0-or-later. See [LICENSE.md](LICENSE.md).

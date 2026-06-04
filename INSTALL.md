# Installing seadog — packaging notes

User-facing install instructions live in the README. This file documents
what the packages actually do, the conffile/data semantics, removal vs.
purge, and how the packages are built — for operators and maintainers.

seadog ships as **two static-musl binaries** (`seadog`, `seadog-priv`) with
no shared-library dependencies; `systemd` is the only runtime requirement
(units, `sysusers.d`, `tmpfiles.d`). The `.deb`, `.rpm`, tarball, and
`install.sh` all converge on the same end-state.

## What an install creates

| Path | Purpose | Owner / mode |
|------|---------|--------------|
| `/usr/lib/seadog/seadog` | unprivileged front-end / login shell | `root:root` 0755 |
| `/usr/lib/seadog/seadog-priv` | root helper (sudo target) | `root:root` 0755 |
| `/usr/bin/seadog-wrapper` | thin client-side `ssh` wrapper | `root:root` 0755 |
| `/etc/seadog/config.yaml` | runtime config (**conffile**) | `root:root` 0644 |
| `/etc/seadog/authorized_keys` | owner key → forced-command map | `root:root` 0644 |
| `/etc/sudoers.d/seadog` | `testenv` → `seadog-priv` sudo rule | `root:root` 0440 |
| `/etc/ssh/sshd_config.d/seadog.conf` | sshd `Match User testenv` snippet | `root:root` 0644 |
| `/usr/lib/sysusers.d/seadog.conf` | declarative user/group | `root:root` 0644 |
| `/usr/lib/tmpfiles.d/seadog.conf` | `/run/seadog` + `/var/lib/seadog` | `root:root` 0644 |
| `/lib/systemd/system/seadog-sweeper.service` | one-shot backstop sweep | `root:root` 0644 |
| `/lib/systemd/system/seadog-sweeper-idle.timer` | idle backstop timer | `root:root` 0644 |
| `/var/lib/seadog/` | state dir (DB lives here) | `root:seadog` **2775** |
| `/var/lib/seadog/seadog.db` | SQLite state (deadlines, leases) | `testenv:seadog` 0664 |

Identity and policy:

- A **`seadog` group** and a **`testenv` system user** (home `/var/lib/seadog`,
  login shell `/usr/lib/seadog/seadog`) are created declaratively via
  `sysusers.d`. The front-end is registered in `/etc/shells`.
- `/var/lib/seadog` is **setgid `seadog`** so the root sweeper/helper and the
  `testenv` front-end can both write the DB and its `-wal`/`-shm` sidecars.
- `/etc/seadog/authorized_keys` is **root-owned** so `testenv` can never
  rewrite its own owner mapping. Manage it with the `seadog-priv` owner verbs
  (see the README "Managing owners" section), never by hand.

The package maintainer scripts also run `systemd-sysusers`,
`systemd-tmpfiles --create`, enable `seadog-sweeper-idle.timer`, and reload
sshd after `sshd -t` validates the merged config. The seed
`authorized_keys` and DB are created empty if absent.

## Config: conffile semantics

`/etc/seadog/config.yaml` is treated as configuration you own:

- **`.deb`** marks it a dpkg **conffile** — on upgrade dpkg preserves your
  edits (prompting only on a genuine three-way conflict).
- **`.rpm`** flags it **`%config(noreplace)`** — your edited file is kept and
  the package's version lands as `config.yaml.rpmnew`.
- **`install.sh`** writes the example config only if none exists; it never
  overwrites an existing one.

seadog itself never rewrites this file.

## Removal vs. purge

| Method | Keeps config + `authorized_keys` + DB + user/group | Removes everything |
|--------|---------------------------------|--------------------|
| `.deb` | `sudo apt remove seadog` | `sudo apt purge seadog` |
| `.rpm` | *(rpm has no split)* | `sudo dnf remove seadog` |
| tarball | `sudo ./deploy/install.sh --uninstall` | `sudo ./deploy/install.sh --uninstall --purge` |

The `.rpm` `%postun` runs only on final removal and matches the `apt purge`
behavior (full teardown), because RPM has no remove-vs-purge distinction.
A full purge removes the `testenv` user, the `seadog` group (if it has no
other members), `/etc/seadog`, `/var/lib/seadog`, and the `/etc/shells` entry.
`sshd` is left valid throughout (the snippet is removed and `sshd -t`
re-checked).

## Building the packages (maintainers)

The packages carry the **static-musl** binaries, so build those first:

```sh
cargo build --release --target x86_64-unknown-linux-musl

# .deb (cargo-deb rewrites the target/release asset paths to the musl dir):
cargo deb -p seadog --target x86_64-unknown-linux-musl
#   -> target/debian/seadog_<ver>-1_amd64.deb

# .rpm (NO --target: the asset source paths already point at the musl dir):
cargo generate-rpm -p crates/seadog
#   -> target/generate-rpm/seadog-<ver>-1.x86_64.rpm
```

Both read their metadata from `crates/seadog/Cargo.toml`
(`[package.metadata.deb]` / `[package.metadata.generate-rpm]`) and share the
same asset list; only the format glue differs (dpkg maintainer scripts in
`deploy/debian/` vs. rpm scriptlets in `deploy/rpm/`).

Releases are cut by the **rc-then-promote** pipeline in
`.github/workflows/release.yml`: pushing `v<ver>-rc<n>` builds the `.deb` +
`.rpm` + `seadog-<ver>-x86_64-musl.tar.gz` + `SHA256SUMS` and attaches them
to a draft prerelease; pushing `v<ver>` republishes those exact, checksum-
verified assets as the final release (no rebuild). CI (`ci.yml`) statically
inspects both packages and runs the `.rpm` through a Fedora-container
install/remove smoke (`test/rpm-smoke.sh`); the `.deb` is validated on a
real Proxmox node.

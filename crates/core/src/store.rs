//! SQLite persistence layer.
//!
//! [`open`] creates the DB file on cold start, switches it to WAL mode,
//! and runs idempotent migrations. The schema is three tables: `envs`
//! (the [`Env`] record, keyed by `guid` — DB-authoritative for
//! `ttl_deadline`), `notify_state` (per-env escalation state), and a
//! single-row `heartbeat` KV for the reaper dead-man's-switch. SQL is
//! inline; no ORM.

use rusqlite::{params, Connection, OptionalExtension};

use crate::models::{Env, EnvStatus, Mode, NotifyState};
use crate::Error;

/// Open (or create) the DB at `path`, enable WAL, and migrate.
///
/// Idempotent: safe to call on a cold (missing) file or an existing one.
/// WAL is required so the testenv front-end and the root reaper can
/// share the file without blocking each other.
pub fn open(path: impl AsRef<std::path::Path>) -> Result<Connection, Error> {
    let conn = Connection::open(path)?;
    init(conn)
}

/// Open an in-memory DB (tests only) with the same schema.
pub fn open_in_memory() -> Result<Connection, Error> {
    let conn = Connection::open_in_memory()?;
    init(conn)
}

fn init(conn: Connection) -> Result<Connection, Error> {
    // WAL: concurrent reader (testenv) + writer (root) without blocking.
    // `query_row` because PRAGMA journal_mode returns the new mode.
    let mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
    if mode.to_lowercase() != "wal" && mode.to_lowercase() != "memory" {
        return Err(Error::Store(format!(
            "failed to enable WAL (journal_mode = {mode})"
        )));
    }
    conn.pragma_update(None, "foreign_keys", "ON")?;
    migrate(&conn)?;
    Ok(conn)
}

/// Run schema migrations. Idempotent (`IF NOT EXISTS`).
fn migrate(conn: &Connection) -> Result<(), Error> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS envs (
            guid          TEXT    PRIMARY KEY,
            vmid          INTEGER NOT NULL,
            mode          TEXT    NOT NULL,
            owner         TEXT    NOT NULL,
            image         TEXT    NOT NULL,
            name          TEXT    NOT NULL,
            ip            TEXT    NOT NULL,
            mac           TEXT    NOT NULL,
            created_at    INTEGER NOT NULL,
            ttl_deadline  INTEGER NOT NULL,
            soft_deadline INTEGER NOT NULL,
            status        TEXT    NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_envs_owner  ON envs(owner);
        CREATE INDEX IF NOT EXISTS idx_envs_status ON envs(status);
        CREATE INDEX IF NOT EXISTS idx_envs_vmid   ON envs(vmid);

        -- `notify_state.guid` is NOT always an env guid, so this table has
        -- NO foreign key to `envs`: foreign in-range heads-ups key on
        -- "vmid-<N>" (see reap.rs/notify.rs) and the sweeper-degraded class
        -- keys on its own synthetic "sweeper" token. An FK with
        -- `PRAGMA foreign_keys = ON` would reject those inserts (the
        -- referenced env row doesn't exist), silently breaking notify dedup
        -- for everything that isn't an env. The env-keyed rows that DO
        -- correspond to an env are cleaned up explicitly in `prune_terminal`
        -- (the cascade the dropped FK used to provide).
        --
        -- Known follow-up (out of scope, low priority): foreign/sweeper rows
        -- now persist until explicitly cleared. A future enhancement should
        -- clear a "vmid-<N>" state once that vmid is no longer a foreign
        -- in-range guest, so a later DIFFERENT guest reusing that vmid
        -- re-notifies instead of being suppressed by the stale row.
        CREATE TABLE IF NOT EXISTS notify_state (
            guid            TEXT    PRIMARY KEY,
            last_severity   TEXT    NOT NULL,
            last_emitted_at INTEGER NOT NULL,
            acked           INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS heartbeat (
            id            INTEGER PRIMARY KEY CHECK (id = 0),
            last_sweep_at INTEGER NOT NULL
        );
        "#,
    )?;
    Ok(())
}

// --- env CRUD ---

/// Insert a new env row. Fails if `guid` already exists.
pub fn insert_env(conn: &Connection, env: &Env) -> Result<(), Error> {
    conn.execute(
        r#"INSERT INTO envs
            (guid, vmid, mode, owner, image, name, ip, mac,
             created_at, ttl_deadline, soft_deadline, status)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"#,
        params![
            env.guid,
            env.vmid,
            env.mode.as_str(),
            env.owner,
            env.image,
            env.name,
            env.ip,
            env.mac,
            env.created_at,
            env.ttl_deadline,
            env.soft_deadline,
            env.status.as_str(),
        ],
    )?;
    Ok(())
}

fn row_to_env(row: &rusqlite::Row) -> rusqlite::Result<Env> {
    let mode_s: String = row.get("mode")?;
    let status_s: String = row.get("status")?;
    Ok(Env {
        guid: row.get("guid")?,
        vmid: row.get("vmid")?,
        mode: Mode::from_str_opt(&mode_s).ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                format!("bad mode '{mode_s}'").into(),
            )
        })?,
        owner: row.get("owner")?,
        image: row.get("image")?,
        name: row.get("name")?,
        ip: row.get("ip")?,
        mac: row.get("mac")?,
        created_at: row.get("created_at")?,
        ttl_deadline: row.get("ttl_deadline")?,
        soft_deadline: row.get("soft_deadline")?,
        status: EnvStatus::from_str_opt(&status_s).ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                format!("bad status '{status_s}'").into(),
            )
        })?,
    })
}

const ENV_COLS: &str = "guid, vmid, mode, owner, image, name, ip, mac, \
     created_at, ttl_deadline, soft_deadline, status";

/// Fetch an env by its `guid` primary key. `None` if absent.
pub fn get_env(conn: &Connection, guid: &str) -> Result<Option<Env>, Error> {
    let sql = format!("SELECT {ENV_COLS} FROM envs WHERE guid = ?1");
    let env = conn.query_row(&sql, params![guid], row_to_env).optional()?;
    Ok(env)
}

/// Fetch an env by its leased `vmid`. `None` if absent.
///
/// Since vmids are reused once an env leaves `Active`, multiple terminal
/// rows can share a vmid; this returns the most recently created one.
pub fn get_env_by_vmid(conn: &Connection, vmid: u32) -> Result<Option<Env>, Error> {
    let sql = format!(
        "SELECT {ENV_COLS} FROM envs WHERE vmid = ?1 \
         ORDER BY created_at DESC LIMIT 1"
    );
    let env = conn.query_row(&sql, params![vmid], row_to_env).optional()?;
    Ok(env)
}

/// List all envs for `owner`, newest first.
pub fn list_by_owner(conn: &Connection, owner: &str) -> Result<Vec<Env>, Error> {
    let sql = format!(
        "SELECT {ENV_COLS} FROM envs WHERE owner = ?1 \
         ORDER BY created_at DESC"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![owner], row_to_env)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// List all envs with `status`, newest first.
pub fn list_by_status(conn: &Connection, status: EnvStatus) -> Result<Vec<Env>, Error> {
    let sql = format!(
        "SELECT {ENV_COLS} FROM envs WHERE status = ?1 \
         ORDER BY created_at DESC"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![status.as_str()], row_to_env)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

fn set_status(conn: &Connection, guid: &str, status: EnvStatus) -> Result<(), Error> {
    let n = conn.execute(
        "UPDATE envs SET status = ?1 WHERE guid = ?2",
        params![status.as_str(), guid],
    )?;
    if n == 0 {
        return Err(Error::NotFound(format!("env guid '{guid}'")));
    }
    Ok(())
}

/// Transition an env to `Reaped` (seadog killed it on deadline).
pub fn mark_reaped(conn: &Connection, guid: &str) -> Result<(), Error> {
    set_status(conn, guid, EnvStatus::Reaped)
}

/// Update an env's hard-kill `ttl_deadline` (the DB-authoritative kill
/// time). Used by the unprivileged `extend` verb — no PVE/root op is
/// needed since the deadline lives only in the DB. `NotFound` if the
/// `guid` has no row.
pub fn set_ttl_deadline(conn: &Connection, guid: &str, ttl_deadline: i64) -> Result<(), Error> {
    let n = conn.execute(
        "UPDATE envs SET ttl_deadline = ?1 WHERE guid = ?2",
        params![ttl_deadline, guid],
    )?;
    if n == 0 {
        return Err(Error::NotFound(format!("env guid '{guid}'")));
    }
    Ok(())
}

/// Update an env's recorded `mac` to the **effective** MAC the guest
/// actually carries after provision. For a VM this is the minted MAC. On the
/// LXC path the MAC is unobservable via `pct config`, so the helper reports
/// none and the front-end records `""` here ("no MAC recorded") rather than
/// the fictional allocated MAC — identity then treats MAC as
/// confirming-when-present. Mirrors [`set_ttl_deadline`].
/// `NotFound` if the `guid` has no row.
pub fn set_mac(conn: &Connection, guid: &str, mac: &str) -> Result<(), Error> {
    let n = conn.execute(
        "UPDATE envs SET mac = ?1 WHERE guid = ?2",
        params![mac, guid],
    )?;
    if n == 0 {
        return Err(Error::NotFound(format!("env guid '{guid}'")));
    }
    Ok(())
}

/// Transition an env to `Vanished` (guest disappeared from PVE).
pub fn mark_vanished(conn: &Connection, guid: &str) -> Result<(), Error> {
    set_status(conn, guid, EnvStatus::Vanished)
}

/// Prune **terminal** env rows (`Reaped`/`Vanished`) whose `created_at`
/// is older than `now_unix - retention_secs`. Live envs are NEVER pruned
/// no matter how overdue — only history ages out. Returns the number of
/// ENV rows removed. (Phase 1b addition: retention policy lives in `notify`/
/// `reap`, but the SQL belongs here next to the other env CRUD.)
///
/// `notify_state` no longer has an FK to `envs` (see the schema comment), so
/// the old `ON DELETE CASCADE` that auto-removed an env's notify_state row is
/// gone. We replicate it explicitly here: BEFORE deleting the env rows, drop
/// the env-keyed notify_state rows for exactly the envs about to be pruned
/// (same cutoff). Non-env keys ("vmid-<N>", "sweeper") are left untouched.
pub fn prune_terminal(
    conn: &Connection,
    now_unix: i64,
    retention_secs: i64,
) -> Result<usize, Error> {
    let cutoff = now_unix - retention_secs;
    // Replace the dropped FK cascade: clear notify_state for exactly the
    // terminal envs we're about to prune (env-keyed rows only).
    conn.execute(
        "DELETE FROM notify_state \
         WHERE guid IN ( \
             SELECT guid FROM envs \
             WHERE status IN ('reaped', 'vanished') AND created_at < ?1 \
         )",
        params![cutoff],
    )?;
    let n = conn.execute(
        "DELETE FROM envs \
         WHERE status IN ('reaped', 'vanished') AND created_at < ?1",
        params![cutoff],
    )?;
    Ok(n)
}

// --- notify state ---

/// Upsert per-env notify state.
pub fn put_notify_state(conn: &Connection, s: &NotifyState) -> Result<(), Error> {
    conn.execute(
        r#"INSERT INTO notify_state
              (guid, last_severity, last_emitted_at, acked)
           VALUES (?1, ?2, ?3, ?4)
           ON CONFLICT(guid) DO UPDATE SET
              last_severity   = excluded.last_severity,
              last_emitted_at = excluded.last_emitted_at,
              acked           = excluded.acked"#,
        params![s.guid, s.last_severity, s.last_emitted_at, s.acked as i64],
    )?;
    Ok(())
}

/// Read per-env notify state. `None` if none recorded yet.
pub fn get_notify_state(conn: &Connection, guid: &str) -> Result<Option<NotifyState>, Error> {
    let s = conn
        .query_row(
            "SELECT guid, last_severity, last_emitted_at, acked \
             FROM notify_state WHERE guid = ?1",
            params![guid],
            |row| {
                let acked: i64 = row.get("acked")?;
                Ok(NotifyState {
                    guid: row.get("guid")?,
                    last_severity: row.get("last_severity")?,
                    last_emitted_at: row.get("last_emitted_at")?,
                    acked: acked != 0,
                })
            },
        )
        .optional()?;
    Ok(s)
}

// --- heartbeat (reaper dead-man's-switch) ---

/// Write the "last sweep ran" timestamp (single-row KV).
pub fn write_heartbeat(conn: &Connection, now_unix: i64) -> Result<(), Error> {
    conn.execute(
        r#"INSERT INTO heartbeat (id, last_sweep_at) VALUES (0, ?1)
           ON CONFLICT(id) DO UPDATE SET last_sweep_at = excluded.last_sweep_at"#,
        params![now_unix],
    )?;
    Ok(())
}

/// Read the last-sweep timestamp. `None` before the first sweep.
pub fn read_heartbeat(conn: &Connection) -> Result<Option<i64>, Error> {
    let ts = conn
        .query_row(
            "SELECT last_sweep_at FROM heartbeat WHERE id = 0",
            [],
            |r| r.get(0),
        )
        .optional()?;
    Ok(ts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::notify::{decide, Event};

    fn env(guid: &str, status: EnvStatus, created_at: i64) -> Env {
        Env {
            guid: guid.into(),
            vmid: 10010,
            mode: Mode::Vm,
            owner: "alice".into(),
            image: "loom".into(),
            name: format!("seadog-alice-p-{guid}"),
            ip: "192.168.99.200".into(),
            mac: "aa:bb:cc:dd:ee:ff".into(),
            created_at,
            ttl_deadline: created_at + 100,
            soft_deadline: created_at + 50,
            status,
        }
    }

    fn notify_config() -> Config {
        let yaml = r#"
images:
  loom:
    ref: "r/loom:1"
    modes: [vm]
"#;
        Config::from_yaml_str(yaml).unwrap()
    }

    /// The core regression: `notify_state` keys that are NOT env guids (a
    /// foreign heads-up keys on "vmid-<N>") must persist. Pre-fix the
    /// `REFERENCES envs(guid)` FK rejected the INSERT under
    /// `PRAGMA foreign_keys = ON`, the error was swallowed by `route()`, and
    /// the dedup state never stuck → re-notify every tick.
    #[test]
    fn put_get_notify_state_for_non_env_key_persists() {
        let conn = open_in_memory().unwrap();
        let s = NotifyState {
            guid: "vmid-10001".into(),
            last_severity: "info".into(),
            last_emitted_at: 1000,
            acked: false,
        };
        put_notify_state(&conn, &s).unwrap();
        let got = get_notify_state(&conn, "vmid-10001").unwrap();
        assert_eq!(got, Some(s));
    }

    /// Dedup across ticks, wired through the DB exactly the way `route()`
    /// does: emit once, persist, reload, then suppress. This is what
    /// silently failed before the FK was dropped.
    #[test]
    fn foreign_headsup_dedups_across_ticks_through_db() {
        let conn = open_in_memory().unwrap();
        let cfg = notify_config();
        let ev = Event::ForeignHeadsUp {
            guid_or_vmid: "vmid-10001".into(),
            detail: "foreign".into(),
        };

        // First tick: no prior → emit, persist the new state.
        let prior = get_notify_state(&conn, "vmid-10001").unwrap();
        let first = decide(&ev, prior.as_ref(), &cfg, 1000);
        assert!(first.emit, "first foreign heads-up must emit");
        put_notify_state(&conn, &first.new_state).unwrap();

        // Second tick: reload the persisted state → suppress.
        let prior = get_notify_state(&conn, "vmid-10001").unwrap();
        assert!(prior.is_some(), "state must have persisted across ticks");
        let second = decide(&ev, prior.as_ref(), &cfg, 2000);
        assert!(!second.emit, "second tick must be suppressed by dedup");
    }

    /// `prune_terminal` must clear the env-keyed notify_state row for a
    /// pruned env (replacing the dropped FK cascade) while leaving a foreign
    /// "vmid-<N>" row untouched.
    #[test]
    fn prune_terminal_clears_env_notify_state_but_keeps_foreign() {
        let conn = open_in_memory().unwrap();
        let now = 100_000_000i64;
        let retention = 7 * 24 * 3600i64;

        // A terminal env older than retention + its env-keyed notify_state.
        insert_env(&conn, &env("g1", EnvStatus::Reaped, now - retention - 10)).unwrap();
        put_notify_state(
            &conn,
            &NotifyState {
                guid: "g1".into(),
                last_severity: "notice".into(),
                last_emitted_at: now - retention - 10,
                acked: false,
            },
        )
        .unwrap();
        // A foreign heads-up row keyed on a vmid token.
        put_notify_state(
            &conn,
            &NotifyState {
                guid: "vmid-9999".into(),
                last_severity: "info".into(),
                last_emitted_at: now,
                acked: false,
            },
        )
        .unwrap();

        let removed = prune_terminal(&conn, now, retention).unwrap();
        assert_eq!(removed, 1, "one env row pruned");

        assert!(
            get_notify_state(&conn, "g1").unwrap().is_none(),
            "env-keyed notify_state must be cleared with its env"
        );
        assert!(
            get_notify_state(&conn, "vmid-9999").unwrap().is_some(),
            "foreign notify_state must survive prune"
        );
    }
}

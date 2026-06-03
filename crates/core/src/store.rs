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

        CREATE TABLE IF NOT EXISTS notify_state (
            guid            TEXT    PRIMARY KEY
                            REFERENCES envs(guid) ON DELETE CASCADE,
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

/// Transition an env to `Vanished` (guest disappeared from PVE).
pub fn mark_vanished(conn: &Connection, guid: &str) -> Result<(), Error> {
    set_status(conn, guid, EnvStatus::Vanished)
}

/// Prune **terminal** env rows (`Reaped`/`Vanished`) whose `created_at`
/// is older than `now_unix - retention_secs`. Live envs are NEVER pruned
/// no matter how overdue — only history ages out. Returns the number of
/// rows removed. (Phase 1b addition: retention policy lives in `notify`/
/// `reap`, but the SQL belongs here next to the other env CRUD.)
pub fn prune_terminal(
    conn: &Connection,
    now_unix: i64,
    retention_secs: i64,
) -> Result<usize, Error> {
    let cutoff = now_unix - retention_secs;
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

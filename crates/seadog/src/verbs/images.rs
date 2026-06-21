//! `images` — list the served image catalog (valid `--image` names).

use anyhow::Result;
use serde_json::Value;

use super::Ctx;

/// `images`. Return the configured image allowlist as JSON so an owner over
/// SSH can discover the valid `--image <name>` values. Read-only and NOT
/// owner-scoped — the allowlist is global (`create` validates the requested
/// alias against this same `config.images`).
///
/// `Image` derives `Serialize` with `#[serde(rename = "ref")]` and skips
/// `None` `user`/`allow_nesting`, so the shape is
/// `{ "<alias>": { "ref": "…", "modes": […], ["user": "…"], ["allow_nesting": true] } }`.
/// The OCI `ref` is included by design (Jei, 2026-06-21).
pub fn run(ctx: &Ctx) -> Result<Value> {
    Ok(serde_json::to_value(&ctx.config.images)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use seadog_core::{store, Config};

    #[test]
    fn images_lists_alias_ref_and_modes() {
        let config = Config::from_yaml_str(
            r#"
images:
  loom: { ref: "ghcr.io/x/droste:loom", modes: [lxc] }
  ci:   { ref: "ghcr.io/x/ci:latest",   modes: [lxc, vm] }
"#,
        )
        .unwrap();
        let conn = store::open_in_memory().unwrap();
        let ctx = Ctx {
            owner: "alice".to_string(),
            conn: &conn,
            config: &config,
            now_unix: 0,
            db_path: ":memory:".to_string(),
        };

        let v = run(&ctx).unwrap();
        assert_eq!(v["loom"]["ref"], "ghcr.io/x/droste:loom");
        assert_eq!(v["loom"]["modes"][0], "lxc");
        assert_eq!(v["ci"]["ref"], "ghcr.io/x/ci:latest");
        let ci_modes = v["ci"]["modes"].as_array().unwrap();
        assert_eq!(ci_modes.len(), 2);
        assert_eq!(ci_modes[1], "vm");
    }
}

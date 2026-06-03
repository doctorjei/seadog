//! The root-privilege **bridge seam**.
//!
//! Root operations (`create`/`destroy` → PVE `qm`/`pct` via kento) cannot
//! run from this unprivileged binary. They are reached by shelling
//! `sudo /usr/lib/seadog/seadog-priv <verb> ...` — but the *front-end*
//! only ever calls [`elevate`], so the elevation primitive stays swappable
//! (real sudo in prod, a fake in tests). This file is the only place that
//! knows how elevation happens.
//!
//! **Phase 2a status:** stubbed. [`elevate`] returns a typed
//! [`ElevateError::NotWired`] so `create`/`destroy` parse + route their
//! args today (proving the argv mapping) and Phase 2b only has to fill in
//! the sudo exec. No `sudo` is invoked here yet.

use std::fmt;

/// Arguments handed to the privileged helper for one elevated verb.
///
/// Kept deliberately abstract: a verb name plus its already-validated,
/// positional+flag argv (the exact tokens `seadog-priv` will re-parse and
/// re-validate). The front-end builds this from clap-parsed values so the
/// untrusted SSH command text never reaches the helper unstructured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElevateArgs {
    /// The privileged verb (`provision`, `teardown`, …) as `seadog-priv`
    /// will see it.
    pub verb: String,
    /// The trusted, resolved owner the op runs on behalf of (passed
    /// through so the helper can attribute the row); never owner-supplied.
    pub owner: String,
    /// The validated argv tail (flags + positionals) for the helper.
    pub args: Vec<String>,
}

impl ElevateArgs {
    /// Construct an elevation request for `verb` on behalf of `owner`.
    pub fn new(verb: impl Into<String>, owner: impl Into<String>, args: Vec<String>) -> Self {
        ElevateArgs {
            verb: verb.into(),
            owner: owner.into(),
            args,
        }
    }
}

/// Error type for the elevation primitive. Phase 2a only produces
/// [`ElevateError::NotWired`]; Phase 2b adds spawn/exec/non-zero-exit
/// variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElevateError {
    /// The bridge to `seadog-priv` is not implemented yet (Phase 2b).
    NotWired { verb: String },
}

impl fmt::Display for ElevateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ElevateError::NotWired { verb } => write!(
                f,
                "verb '{verb}' requires the root bridge, which is not wired yet (Phase 2b)"
            ),
        }
    }
}

impl std::error::Error for ElevateError {}

/// JSON-serializable result of an elevated op (what `seadog-priv` will
/// hand back). Phase 2a never produces one — kept as the target shape so
/// the verb render path is ready.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ElevateOutcome {
    /// The verb that ran.
    pub verb: String,
    /// Raw JSON line the helper emitted, parsed back for re-rendering.
    pub result: serde_json::Value,
}

/// Run a privileged verb through the bridge.
///
/// **Phase 2a:** stub — always returns [`ElevateError::NotWired`]. The
/// signature is the abstract elevation primitive: in Phase 2b this becomes
/// `sudo /usr/lib/seadog/seadog-priv <verb> <args…>`, capturing the
/// helper's JSON stdout into an [`ElevateOutcome`]. The front-end depends
/// only on this signature, so swapping the implementation (or a test
/// fake) needs no caller changes.
pub fn elevate(args: &ElevateArgs) -> Result<ElevateOutcome, ElevateError> {
    Err(ElevateError::NotWired {
        verb: args.verb.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elevate_is_stubbed_not_wired() {
        let req = ElevateArgs::new(
            "provision",
            "kanibako",
            vec!["--image".into(), "loom".into()],
        );
        let err = elevate(&req).unwrap_err();
        assert_eq!(
            err,
            ElevateError::NotWired {
                verb: "provision".into()
            }
        );
        assert!(err.to_string().contains("Phase 2b"));
    }

    #[test]
    fn elevate_args_carries_owner_and_argv() {
        let req = ElevateArgs::new("teardown", "jei", vec!["g-123".into()]);
        assert_eq!(req.verb, "teardown");
        assert_eq!(req.owner, "jei");
        assert_eq!(req.args, vec!["g-123".to_string()]);
    }
}

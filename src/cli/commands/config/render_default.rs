//! `warden config render-default` — print the built-in scaffold config.
//!
//! Pure and side-effect-free: emits the exact TOML that `warden init
//! --yes` would write, sourced from the single [`init::default_config`]
//! template. The packaging build (`pkg/build.sh`) captures this into the
//! package's seed config so the shipped default can never drift from
//! `warden init`.
//!
//! [`init::default_config`]: crate::cli::commands::init::default_config

/// The scaffold config as a TOML string (identical to what
/// `warden init --yes` writes).
pub fn render_default_string() -> String {
    crate::cli::commands::init::default_config()
}

/// Print the scaffold config to stdout. Always exits 0.
pub fn run_render_default() {
    let s = render_default_string();
    print!("{s}");
    if !s.ends_with('\n') {
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_default_matches_scaffold_and_is_valid_toml() {
        let out = render_default_string();
        // Single source of truth: identical to `warden init`.
        assert_eq!(out, crate::cli::commands::init::default_config());
        // Must decode as the current strict schema — a generic TOML parse
        // would accept legacy rule fields that the runtime must refuse.
        let config: crate::config::schema::ConfigV5 =
            toml::from_str(&out).expect("render-default output must be valid schema-5 TOML");
        assert_eq!(
            config.schema_version,
            crate::config::schema::TARGET_SCHEMA_VERSION_V5
        );
        assert!(!out.trim().is_empty(), "scaffold config must not be empty");
    }
}

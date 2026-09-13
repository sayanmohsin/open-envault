//! Public API for open_envault.
//!
//! ```no_run
//! if let Ok(values) = open_envault::load_environment("dev") {
//!     let _ = values.contains_key("EXAMPLE");
//! }
//! ```

pub mod core;
pub mod crypto;
pub mod output;
pub mod runtime;
pub mod schema;

use anyhow::Context;
use std::collections::BTreeMap;

/// Discover the project rooted at the current directory, resolve `name`, and
/// decrypt + parse that environment profile into an in-memory map.
pub fn load_environment(name: &str) -> anyhow::Result<BTreeMap<String, String>> {
    let path = core::discover(&std::env::current_dir()?)?;
    let project = core::load(&path)?;
    let profile = core::environment(&project, name)?;
    let root = path.parent().unwrap_or(&path);
    let encrypted = core::resolve_path(&profile.file, root);
    let configured_key = profile
        .key_file
        .as_deref()
        .map(|key| core::resolve_path(key, root));
    let plaintext =
        crypto::decrypt_for_with_key_file(&encrypted, Some(name), configured_key.as_deref())
            .with_context(|| format!("decrypt environment {name}"))?;
    Ok(schema::parse_env(&plaintext))
}

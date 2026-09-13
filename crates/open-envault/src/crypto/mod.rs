//! Native SOPS-over-age encryption for open_envault.
//!
//! This crate implements the SOPS file format for dotenv documents with age
//! recipients, so `open_envault` needs no external `sops`/`rage` binaries and
//! files remain interchangeable with official SOPS. See [`store`] for the
//! format and [`keys`] for age key handling.

pub mod keys;
pub mod store;
pub mod util;
pub mod value;

use anyhow::{Context, Result};
use std::{
    env, fs,
    path::{Path, PathBuf},
};

pub use keys::{Identity, Recipient};

/// Default per-user key directory (relative to the config home).
pub fn default_key_dir() -> PathBuf {
    env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("APPDATA").map(PathBuf::from))
        .unwrap_or_else(|| {
            PathBuf::from(env::var("HOME").unwrap_or_else(|_| ".".into())).join(".config")
        })
        .join("open-envault")
        .join("keys")
}

fn legacy_key_dir() -> PathBuf {
    default_key_dir()
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("open_envault")
        .join("keys")
}

/// Atomic write: temp file in the same directory, fsync, rename.
fn atomic_write(path: &Path, content: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "out".into());
    let tmp = parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)?;
    std::io::Write::write_all(&mut file, content)?;
    file.sync_all()?;
    drop(file);
    replace_file(&tmp, path).inspect_err(|_error| {
        let _ = fs::remove_file(&tmp);
    })?;
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(not(windows))]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_REPLACE_EXISTING, MoveFileExW};
    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING,
        )
    } == 0
    {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Encrypt `content` and write it to `path` atomically for `recipients`.
pub fn encrypt(content: &str, path: &Path, recipients: &[String]) -> Result<()> {
    let text = store::encrypt(content, &store::recipients_from_strings(recipients)?)?;
    atomic_write(path, text.as_bytes())
}

/// Decrypt the file at `path` using identities from the environment and (when
/// `environment` is given) the default per-user key file for that environment.
pub fn decrypt_for(path: &Path, environment: Option<&str>) -> Result<String> {
    decrypt_for_with_key_file(path, environment, None)
}

/// Decrypt using environment identities plus an explicitly configured key file.
pub fn decrypt_for_with_key_file(
    path: &Path,
    environment: Option<&str>,
    configured_key_file: Option<&Path>,
) -> Result<String> {
    let mut identities = keys::identities_from_env();
    if let Some(key_path) = configured_key_file
        && key_path.is_file()
    {
        identities.push(keys::read_identity_file(key_path)?);
    }
    if let Some(name) = environment {
        for key_dir in [default_key_dir(), legacy_key_dir()] {
            let key_path = key_dir.join(format!("{name}.txt"));
            if key_path.is_file()
                && let Ok(identity) = keys::read_identity_file(&key_path)
            {
                identities.push(identity);
                break;
            }
        }
    }
    if identities.is_empty() {
        anyhow::bail!(
            "no age identity available; set OPENENVAULT_AGE_KEY or SOPS_AGE_KEY, configure a key file, or run `oenv setup`"
        );
    }
    let text = fs::read_to_string(path)
        .with_context(|| format!("read encrypted file {}", path.display()))?;
    store::decrypt(&text, &identities)
}

/// Decrypt the file at `path` using environment-supplied identities only.
pub fn decrypt(path: &Path) -> Result<String> {
    decrypt_for(path, None)
}

/// List the recipients recorded in the encrypted file at `path`.
pub fn recipients_of(path: &Path) -> Result<Vec<String>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("read encrypted file {}", path.display()))?;
    store::list_recipients(&text)
}

/// Generate a fresh age identity and write it to `path` (mode 0600).
/// Returns the full key-file text so callers can print the public key.
pub fn generate_key(path: &Path) -> Result<String> {
    let (text, _public) = keys::generate_identity()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| {
            if path.exists() {
                format!(
                    "key file already exists; refusing to overwrite {}",
                    path.display()
                )
            } else {
                format!("write key file {}", path.display())
            }
        })?;
    std::io::Write::write_all(&mut file, text.as_bytes())?;
    file.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod key file {}", path.display()))?;
    }
    Ok(text)
}

/// Reuse an existing identity or create a new one without overwriting files.
pub fn ensure_key(path: &Path) -> Result<(String, String, bool)> {
    if path.is_file() {
        let identity = keys::read_identity_file(path)
            .with_context(|| format!("validate existing age key {}", path.display()))?;
        return Ok((
            identity.to_public().to_string(),
            path.display().to_string(),
            false,
        ));
    }
    let text = generate_key(path)?;
    let identity = keys::identity_from_key_text(&text)?;
    Ok((
        identity.to_public().to_string(),
        path.display().to_string(),
        true,
    ))
}

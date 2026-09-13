use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub project: String,
    pub environments: BTreeMap<String, Environment>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Environment {
    pub file: String,
    #[serde(default = "default_schema")]
    pub schema: String,
    #[serde(default)]
    pub recipients: Vec<String>,
    #[serde(default)]
    pub key_file: Option<String>,
    #[serde(default)]
    pub editor: Option<String>,
}
fn default_schema() -> String {
    "config/env.schema.yaml".into()
}
pub fn discover(start: &Path) -> anyhow::Result<PathBuf> {
    let mut current = start.canonicalize()?;
    loop {
        let candidate = current.join("open-envault.yaml");
        if candidate.is_file() {
            return Ok(candidate);
        }
        if !current.pop() {
            bail!("open-envault.yaml not found")
        }
    }
}
pub fn load(path: &Path) -> anyhow::Result<Project> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let project: Project = yaml_serde::from_str(&text).context("parse open-envault.yaml")?;
    if project.project.trim().is_empty() {
        bail!("project name must not be empty")
    }
    if project.environments.is_empty() {
        bail!("project must define at least one environment")
    }
    for (name, profile) in &project.environments {
        if name.trim().is_empty() || name.contains('/') || name.contains('\\') {
            bail!("environment name is not path-safe: {name}")
        }
        if profile.file.trim().is_empty() || profile.schema.trim().is_empty() {
            bail!("environment {name} must define file and schema paths")
        }
        for recipient in &profile.recipients {
            crate::crypto::keys::parse_recipient(recipient)
                .with_context(|| format!("invalid recipient configured for {name}"))?;
        }
    }
    Ok(project)
}
pub fn environment<'a>(project: &'a Project, name: &str) -> anyhow::Result<&'a Environment> {
    project
        .environments
        .get(name)
        .with_context(|| format!("unknown environment: {name}"))
}
pub fn atomic_write(path: &Path, content: &[u8]) -> anyhow::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("out");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp = parent.join(format!(".{name}.{}.{}.tmp", std::process::id(), nonce));
    let mut file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
    file.write_all(content)?;
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

pub fn resolve_path(value: &str, base: &Path) -> PathBuf {
    let expanded = if let Some(rest) = value.strip_prefix("~/") {
        std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)
            .unwrap_or_default()
            .join(rest)
    } else {
        PathBuf::from(value)
    };
    if expanded.is_absolute() {
        expanded
    } else {
        base.join(expanded)
    }
}

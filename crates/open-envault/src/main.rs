use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use open_envault::core::{Project, discover, environment, load};
use open_envault::schema::{example, load as load_schema, parse_env, parse_env_strict, validate};
use std::{
    collections::BTreeMap,
    env, fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Debug, Parser)]
#[command(name = "oenv", version, about = "Secure encrypted environment files")]
struct Cli {
    #[command(subcommand)]
    command: CommandKind,
}
#[derive(Debug, Subcommand)]
enum CommandKind {
    Init,
    Setup {
        environment: String,
        #[arg(long)]
        key_file: Option<PathBuf>,
        #[arg(long, conflicts_with = "from_stdin")]
        from_file: Option<PathBuf>,
        #[arg(long, conflicts_with = "from_file")]
        from_stdin: bool,
        #[arg(long, value_enum, default_value_t = ImportFormat::Dotenv)]
        format: ImportFormat,
    },
    Env {
        #[command(subcommand)]
        command: EnvCommand,
    },
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
    Check {
        environment: String,
        #[arg(long, value_enum, default_value_t = Format::Human)]
        format: Format,
    },
    Example,
    Exec {
        environment: String,
        #[arg(long)]
        force: bool,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    Doctor {
        #[arg(long, value_enum, default_value_t = Format::Human)]
        format: Format,
    },
    Diff {
        left: String,
        right: String,
        #[arg(long, value_enum, default_value_t = Format::Human)]
        format: Format,
    },
    Rotate {
        environment: String,
    },
    Edit {
        environment: String,
    },
    Set {
        environment: String,
        variable: String,
    },
    Import {
        environment: String,
        #[arg(long, value_enum)]
        format: ImportFormat,
        #[arg(long, conflicts_with = "replace")]
        merge: bool,
        #[arg(long, conflicts_with = "merge")]
        replace: bool,
        #[arg(long)]
        allowlist: Option<PathBuf>,
        #[arg(long)]
        exclude: Option<PathBuf>,
    },
}
#[derive(Debug, Subcommand)]
enum EnvCommand {
    Create { environment: String },
}
#[derive(Debug, Subcommand)]
enum KeyCommand {
    Generate { environment: String },
}
#[derive(Debug, Clone, Copy, ValueEnum)]
enum Format {
    Human,
    Json,
}
#[derive(Debug, Clone, Copy, ValueEnum)]
enum ImportFormat {
    Json,
    Dotenv,
}

fn project() -> Result<(PathBuf, Project)> {
    let path = discover(&env::current_dir()?)?;
    Ok((path.clone(), load(&path)?))
}
fn profile(name: &str) -> Result<(PathBuf, open_envault::core::Environment)> {
    let (path, project) = project()?;
    Ok((path, environment(&project, name)?.clone()))
}
fn root(path: &Path) -> &std::path::Path {
    path.parent().unwrap_or(path)
}
fn profile_file(path: &Path, profile: &open_envault::core::Environment) -> PathBuf {
    open_envault::core::resolve_path(&profile.file, root(path))
}
fn schema_file(path: &Path, profile: &open_envault::core::Environment) -> PathBuf {
    open_envault::core::resolve_path(&profile.schema, root(path))
}
fn key_file(path: &Path, name: &str, profile: &open_envault::core::Environment) -> PathBuf {
    profile
        .key_file
        .as_deref()
        .map(|p| open_envault::core::resolve_path(p, root(path)))
        .unwrap_or_else(|| open_envault::crypto::default_key_dir().join(format!("{name}.txt")))
}
fn decrypt_profile(
    path: &Path,
    name: &str,
    profile: &open_envault::core::Environment,
) -> Result<String> {
    open_envault::crypto::decrypt_for_with_key_file(
        &profile_file(path, profile),
        Some(name),
        Some(&key_file(path, name, profile)),
    )
}

fn main() -> Result<()> {
    match Cli::parse().command {
        CommandKind::Init => init(),
        CommandKind::Setup {
            environment,
            key_file,
            from_file,
            from_stdin,
            format,
        } => setup(&environment, key_file, from_file, from_stdin, format),
        CommandKind::Check {
            environment,
            format,
        } => check(&environment, format),
        CommandKind::Example => {
            let (path, project) = project()?;
            let name = project
                .environments
                .keys()
                .next()
                .ok_or_else(|| anyhow::anyhow!("no environments configured"))?;
            let schema = load_schema(&schema_file(&path, environment(&project, name)?))?;
            fs::write(root(&path).join(".env.example"), example(&schema))?;
            Ok(())
        }
        CommandKind::Exec {
            environment,
            force,
            command,
        } => {
            let (path, p) = profile(&environment)?;
            let values = parse_env(&decrypt_profile(&path, &environment, &p)?);
            std::process::exit(open_envault::runtime::exec(&command, &values, force)?);
        }
        CommandKind::Doctor { format } => doctor(format),
        CommandKind::Edit { environment } => edit(&environment),
        CommandKind::Set {
            environment,
            variable,
        } => set(&environment, &variable),
        CommandKind::Import {
            environment,
            format,
            merge,
            replace,
            allowlist,
            exclude,
        } => import(&environment, format, !replace || merge, allowlist, exclude),
        CommandKind::Env {
            command: EnvCommand::Create { environment },
        } => create_environment(&environment),
        CommandKind::Key {
            command: KeyCommand::Generate { environment },
        } => generate_key(&environment),
        CommandKind::Diff {
            left,
            right,
            format,
        } => diff(&left, &right, format),
        CommandKind::Rotate { environment } => rotate(&environment),
    }
}
fn init() -> Result<()> {
    let r = env::current_dir()?;
    fs::create_dir_all(r.join("config"))?;
    fs::create_dir_all(r.join("secrets"))?;
    if !r.join("open-envault.yaml").exists() {
        fs::write(
            r.join("open-envault.yaml"),
            "project: my-project\nenvironments:\n  dev:\n    file: secrets/dev.env.enc\n    schema: config/env.schema.yaml\n    recipients: []\n",
        )?;
    }
    if !r.join("config/env.schema.yaml").exists() {
        fs::write(r.join("config/env.schema.yaml"), "variables: {}\n")?;
    }
    if !r.join(".sops.yaml").exists() {
        fs::write(r.join(".sops.yaml"), "creation_rules: []\n")?;
    }
    eprintln!("initialized open-envault project");
    Ok(())
}

fn generate_key(name: &str) -> Result<()> {
    let (path, profile) = profile(name)?;
    let key_path = key_file(&path, name, &profile);
    let key = open_envault::crypto::generate_key(&key_path)?;
    println!(
        "{}",
        key.lines()
            .find(|line| line.starts_with("# public key: "))
            .unwrap_or("# public key unavailable")
    );
    let _ = path;
    Ok(())
}

fn setup(
    name: &str,
    key_file: Option<PathBuf>,
    from_file: Option<PathBuf>,
    from_stdin: bool,
    format: ImportFormat,
) -> Result<()> {
    if name.trim().is_empty() || name.contains('/') || name.contains('\\') {
        anyhow::bail!("environment name must be a non-empty path-safe name")
    }
    if from_file.is_none() && !from_stdin {
        anyhow::bail!("setup requires --from-file PATH or --from-stdin")
    }
    let (config_path, mut project) = project()?;
    let config_root = root(&config_path).to_path_buf();
    let existing = project.environments.get(name).cloned();
    let mut profile = existing
        .clone()
        .unwrap_or_else(|| open_envault::core::Environment {
            file: format!("secrets/{name}.env.enc"),
            schema: "config/env.schema.yaml".into(),
            recipients: Vec::new(),
            key_file: None,
            editor: None,
        });
    let key_path = key_file
        .or_else(|| {
            profile
                .key_file
                .as_deref()
                .map(|p| open_envault::core::resolve_path(p, &config_root))
        })
        .unwrap_or_else(|| open_envault::crypto::default_key_dir().join(format!("{name}.txt")));
    let (recipient, key_display, created) = open_envault::crypto::ensure_key(&key_path)?;
    if !profile.recipients.iter().any(|r| r == &recipient) {
        profile.recipients.push(recipient.clone());
    }
    profile.recipients.sort();
    profile.recipients.dedup();
    profile.key_file = Some(key_path.to_string_lossy().into_owned());

    let schema_path = open_envault::core::resolve_path(&profile.schema, &config_root);
    let schema = load_schema(&schema_path)
        .with_context(|| format!("setup requires a valid schema at {}", schema_path.display()))?;
    let input = match from_file {
        Some(path) => fs::read_to_string(&path)
            .with_context(|| format!("read setup input {}", path.display()))?,
        None => read_stdin()?,
    };
    let incoming = match format {
        ImportFormat::Dotenv => parse_env_strict(&input)?,
        ImportFormat::Json => parse_json(&input)?,
    };
    if incoming.keys().any(|key| !valid_variable_name(key)) {
        anyhow::bail!("setup input contains an invalid environment variable name")
    }
    let encrypted_path = open_envault::core::resolve_path(&profile.file, &config_root);
    let mut values = if encrypted_path.is_file() {
        parse_env(&open_envault::crypto::decrypt_for_with_key_file(
            &encrypted_path,
            Some(name),
            Some(&key_path),
        )?)
    } else {
        BTreeMap::new()
    };
    values.extend(incoming);
    let findings = validate(&schema, &values, name);
    if !findings.is_empty() {
        for finding in findings {
            eprintln!("{}: {}", finding.variable, finding.message);
        }
        anyhow::bail!("setup failed schema validation")
    }
    let dotenv = values
        .into_iter()
        .map(|(key, value)| format!("{key}={value}\n"))
        .collect::<String>();
    open_envault::crypto::encrypt(&dotenv, &encrypted_path, &profile.recipients)?;
    project.environments.insert(name.into(), profile);
    let config_text = yaml_serde::to_string(&project)?;
    open_envault::core::atomic_write(&config_path, config_text.as_bytes())?;
    println!(
        "setup {name}: ok\n  encrypted profile: {}\n  age recipient: {recipient}\n  key: {} ({})\n  CI: set SOPS_AGE_KEY to the private key, then run `oenv check {name}`",
        encrypted_path.display(),
        key_display,
        if created { "created" } else { "reused" }
    );
    Ok(())
}
fn check(name: &str, format: Format) -> Result<()> {
    let (path, p) = profile(name)?;
    let values = parse_env(&decrypt_profile(&path, name, &p)?);
    let findings = validate(&load_schema(&schema_file(&path, &p))?, &values, name);
    match format {
        Format::Human => {
            if findings.is_empty() {
                println!("{name}: ok")
            } else {
                for f in &findings {
                    println!("{}: {}", f.variable, f.message)
                }
            }
        }
        Format::Json => println!(
            "{}",
            open_envault::output::json(&open_envault::output::CheckEnvelope {
                ok: findings.is_empty(),
                exit: if findings.is_empty() { 0 } else { 4 },
                findings: &findings,
            })?
        ),
    };
    if !findings.is_empty() {
        std::process::exit(4);
    }
    Ok(())
}

#[derive(Debug, serde::Serialize)]
struct DoctorEnvironment {
    file: String,
    schema: String,
    profile: &'static str,
    decrypt: &'static str,
    recipients: usize,
}

#[derive(Debug, serde::Serialize)]
struct DoctorEnvelope {
    ok: bool,
    exit: u8,
    environments: BTreeMap<String, DoctorEnvironment>,
    findings: Vec<String>,
}

fn doctor(format: Format) -> Result<()> {
    let (path, project) = project()?;
    let mut environments = BTreeMap::new();
    let mut findings = Vec::new();

    for (name, profile) in &project.environments {
        let encrypted = profile_file(&path, profile);
        let schema = schema_file(&path, profile);
        let profile_status = if encrypted.is_file() {
            "present"
        } else {
            "missing"
        };
        let decrypt_status = if encrypted.is_file() {
            match decrypt_profile(&path, name, profile) {
                Ok(_) => "ok",
                Err(_) => "failed",
            }
        } else {
            "not-checked"
        };
        if profile_status == "missing" {
            findings.push(format!("{name}: encrypted profile is missing"));
        }
        if !schema.is_file() {
            findings.push(format!("{name}: schema is missing"));
        } else if load_schema(&schema).is_err() {
            findings.push(format!("{name}: schema is invalid"));
        }
        if decrypt_status == "failed" {
            findings.push(format!("{name}: encrypted profile could not be decrypted"));
        }
        if profile.recipients.is_empty() {
            findings.push(format!("{name}: no encryption recipients configured"));
        }
        environments.insert(
            name.clone(),
            DoctorEnvironment {
                file: profile.file.clone(),
                schema: profile.schema.clone(),
                profile: profile_status,
                decrypt: decrypt_status,
                recipients: profile.recipients.len(),
            },
        );
    }

    let ok = findings.is_empty();
    match format {
        Format::Human => {
            if ok {
                println!("project: ok");
            } else {
                for finding in &findings {
                    println!("{finding}");
                }
            }
        }
        Format::Json => println!(
            "{}",
            open_envault::output::json(&DoctorEnvelope {
                ok,
                exit: if ok { 0 } else { 4 },
                environments,
                findings,
            })?
        ),
    }
    if !ok {
        std::process::exit(4);
    }
    Ok(())
}

#[derive(Debug, serde::Serialize)]
struct DiffVariable {
    status: &'static str,
    fingerprint: Option<String>,
}

fn diff(left: &str, right: &str, format: Format) -> Result<()> {
    let left_values = values_for(left)?;
    let right_values = values_for(right)?;
    let pepper = env::var("OPENENVAULT_DIFF_PEPPER")
        .context("set OPENENVAULT_DIFF_PEPPER for redacted diff fingerprints")?;
    let names = left_values
        .keys()
        .chain(right_values.keys())
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let mut variables = BTreeMap::new();
    let mut changed = false;
    for name in names {
        let left_value = left_values.get(&name);
        let right_value = right_values.get(&name);
        let status = match (left_value, right_value) {
            (Some(a), Some(b)) if a == b => "unchanged",
            (Some(_), Some(_)) => {
                changed = true;
                "changed"
            }
            (Some(_), None) => {
                changed = true;
                "removed"
            }
            (None, Some(_)) => {
                changed = true;
                "added"
            }
            (None, None) => unreachable!(),
        };
        let fingerprint = right_value
            .or(left_value)
            .map(|value| open_envault::output::fingerprint(&pepper, value));
        variables.insert(
            name,
            DiffVariable {
                status,
                fingerprint,
            },
        );
    }
    match format {
        Format::Human => {
            println!(
                "{left} vs {right}: {}",
                if changed { "changed" } else { "same" }
            );
            for (name, variable) in &variables {
                if variable.status != "unchanged" {
                    println!("  {name}: {}", variable.status);
                }
            }
        }
        Format::Json => println!(
            "{}",
            open_envault::output::json(&open_envault::output::DiffEnvelope {
                ok: !changed,
                exit: if changed { 4 } else { 0 },
                variables,
            })?
        ),
    }
    if changed {
        std::process::exit(4);
    }
    Ok(())
}

fn values_for(name: &str) -> Result<BTreeMap<String, String>> {
    let (path, profile) = profile(name)?;
    Ok(parse_env(&decrypt_profile(&path, name, &profile)?))
}

fn rotate(name: &str) -> Result<()> {
    let (path, profile) = profile(name)?;
    let encrypted = profile_file(&path, &profile);
    let plaintext = decrypt_profile(&path, name, &profile)?;
    open_envault::crypto::encrypt(&plaintext, &encrypted, &profile.recipients)?;
    println!("rotated {name}: ok");
    Ok(())
}
fn edit(name: &str) -> Result<()> {
    let (path, p) = profile(name)?;
    let tmp = env::temp_dir().join(format!(
        "open-envault-edit-{}-{}",
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
    use std::io::Write as _;
    file.write_all(decrypt_profile(&path, name, &p)?.as_bytes())?;
    file.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    }
    let editor = p
        .editor
        .clone()
        .or_else(|| env::var("EDITOR").ok())
        .unwrap_or_else(|| "vi".into());
    let status = Command::new(editor).arg(&tmp).status()?;
    if !status.success() {
        let _ = fs::remove_file(&tmp);
        anyhow::bail!("editor failed")
    }
    let content = fs::read_to_string(&tmp)?;
    let _ = fs::remove_file(&tmp);
    open_envault::crypto::encrypt(&content, &profile_file(&path, &p), &p.recipients)
}
fn set(name: &str, variable: &str) -> Result<()> {
    if !valid_variable_name(variable) {
        anyhow::bail!("invalid environment variable name: {variable}");
    }
    let (path, p) = profile(name)?;
    let encrypted = profile_file(&path, &p);
    let plain = if encrypted.exists() {
        decrypt_profile(&path, name, &p)?
    } else {
        String::new()
    };
    let mut values = parse_env(&plain);
    eprint!("value for {variable}: ");
    io::stderr().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    values.insert(variable.into(), value.trim_end().into());
    let text: String = values
        .into_iter()
        .map(|(k, v)| format!("{k}={v}\n"))
        .collect();
    open_envault::crypto::encrypt(&text, &encrypted, &p.recipients)
}

fn create_environment(name: &str) -> Result<()> {
    if name.trim().is_empty() || name.contains('/') || name.contains('\\') {
        anyhow::bail!("environment name must be a non-empty path-safe name")
    }
    let (path, mut project) = project()?;
    if project.environments.contains_key(name) {
        anyhow::bail!("environment already exists: {name}")
    }
    project.environments.insert(
        name.into(),
        open_envault::core::Environment {
            file: format!("secrets/{name}.env.enc"),
            schema: "config/env.schema.yaml".into(),
            recipients: Vec::new(),
            key_file: None,
            editor: None,
        },
    );
    let text = yaml_serde::to_string(&project)?;
    open_envault::core::atomic_write(&path, text.as_bytes())?;
    eprintln!("created environment {name}; add recipients before importing secrets");
    Ok(())
}

fn import(
    name: &str,
    format: ImportFormat,
    merge: bool,
    allowlist: Option<PathBuf>,
    exclude: Option<PathBuf>,
) -> Result<()> {
    let (path, project) = project()?;
    let profile = environment(&project, name)?.clone();
    let input = read_stdin()?;
    let mut incoming = match format {
        ImportFormat::Dotenv => parse_env_strict(&input)?,
        ImportFormat::Json => parse_json(&input)?,
    };
    if incoming.keys().any(|key| !valid_variable_name(key)) {
        anyhow::bail!("import contains an invalid environment variable name")
    }
    let allowed = load_names(allowlist)?;
    let excluded = load_names(exclude)?.unwrap_or_default();
    incoming.retain(|key, _| {
        allowed.as_ref().is_none_or(|names| names.contains(key)) && !excluded.contains(key)
    });
    if incoming.is_empty() {
        anyhow::bail!("import contained no allowed variables")
    }

    let encrypted = profile_file(&path, &profile);
    let mut values = if merge {
        if encrypted.exists() {
            parse_env(&decrypt_profile(&path, name, &profile)?)
        } else {
            BTreeMap::new()
        }
    } else {
        BTreeMap::new()
    };
    values.extend(incoming);
    let schema =
        load_schema(&schema_file(&path, &profile)).context("import requires a valid schema")?;
    let findings = validate(&schema, &values, name);
    if findings.iter().any(|finding| finding.kind == "invalid") {
        anyhow::bail!("import failed schema validation")
    }
    let dotenv = values
        .into_iter()
        .map(|(key, value)| format!("{key}={value}\n"))
        .collect::<String>();
    open_envault::crypto::encrypt(&dotenv, &encrypted, &profile.recipients)?;
    println!("imported variables: ok");
    Ok(())
}

fn read_stdin() -> Result<String> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    Ok(input)
}

fn parse_json(input: &str) -> Result<BTreeMap<String, String>> {
    let raw: serde_json::Value = serde_json::from_str(input).context("parse JSON import")?;
    let object = raw.as_object().context("JSON import must be an object")?;
    object
        .iter()
        .map(|(name, value)| {
            let value = value
                .get("computed")
                .unwrap_or(value)
                .as_str()
                .map(str::to_owned)
                .with_context(|| format!("JSON value for {name} must be a string"))?;
            Ok((name.clone(), value))
        })
        .collect()
}

fn load_names(path: Option<PathBuf>) -> Result<Option<std::collections::BTreeSet<String>>> {
    let Some(path) = path else { return Ok(None) };
    let names = fs::read_to_string(path)?
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect();
    Ok(Some(names))
}

fn valid_variable_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .enumerate()
            .all(|(index, ch)| ch == '_' || ch.is_ascii_alphanumeric() && (index > 0 || ch != '_'))
        && name
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
}

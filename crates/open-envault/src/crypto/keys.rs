//! Age key handling: recipients, identities, data-key wrapping, and key
//! generation.
//!
//! The data key is wrapped for every recipient individually and stored as an
//! ASCII-armored age file in the SOPS metadata (`enc` field), mirroring
//! `github.com/getsops/sops/v3/age.MasterKey.Encrypt`.

use age::{armor::ArmoredReader, secrecy::ExposeSecret};
use anyhow::{Context, Result, bail};
use std::{env, fs, io::Read, path::Path, str::FromStr};

pub use age::x25519::{Identity, Recipient};

/// Public recipient type (age1...).
pub type PublicKey = Recipient;

pub const SECRET_LINE_PREFIX: &str = "AGE-SECRET-KEY-";
const IDENTITY_VARS: [&str; 3] = ["OPENENVAULT_AGE_KEY", "OPENENCRYPT_AGE_KEY", "SOPS_AGE_KEY"];
const IDENTITY_FILE_VARS: [&str; 3] = [
    "OPENENVAULT_AGE_KEY_FILE",
    "OPENENCRYPT_AGE_KEY_FILE",
    "SOPS_AGE_KEY_FILE",
];

/// Parse a single public recipient string (`age1...`).
pub fn parse_recipient(input: &str) -> Result<Recipient> {
    let s = input.trim();
    Recipient::from_str(s).map_err(|_| anyhow::anyhow!("invalid age recipient: {s}"))
}

/// Parse a single secret identity line (`AGE-SECRET-KEY-1...`).
pub fn parse_identity(input: &str) -> Result<Identity> {
    let line = input.trim();
    if !line.starts_with(SECRET_LINE_PREFIX) {
        bail!("invalid age identity (expected a line starting with {SECRET_LINE_PREFIX})");
    }
    Identity::from_str(line).map_err(|_| anyhow::anyhow!("invalid age identity"))
}

/// Extract the first secret identity from key-file text (ignores `#` headers).
pub fn identity_from_key_text(text: &str) -> Result<Identity> {
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with(SECRET_LINE_PREFIX) {
            return parse_identity(line);
        }
    }
    bail!("no age secret key found in key material")
}

/// Read and parse a private key file.
pub fn read_identity_file(path: &Path) -> Result<Identity> {
    let text =
        fs::read_to_string(path).with_context(|| format!("read key file {}", path.display()))?;
    identity_from_key_text(&text).with_context(|| format!("parse key file {}", path.display()))
}

/// Collect identities from `OPENENVAULT_AGE_KEY` / compatibility aliases and the
/// corresponding `*_KEY_FILE` variables. Missing variables are skipped.
pub fn identities_from_env() -> Vec<Identity> {
    let mut identities = Vec::new();
    for var in IDENTITY_VARS {
        let Ok(value) = env::var(var) else { continue };
        if value.trim().is_empty() {
            continue;
        }
        if let Ok(identity) = parse_identity(&value) {
            identities.push(identity);
        }
    }
    for var in IDENTITY_FILE_VARS {
        let Ok(path) = env::var(var) else { continue };
        if path.is_empty() {
            continue;
        }
        if let Ok(identity) = read_identity_file(Path::new(&path)) {
            identities.push(identity);
        }
    }
    identities
}

/// Wrap the data key for a single recipient, returning the armored payload.
pub fn wrap_data_key(data_key: &[u8; 32], recipient: &Recipient) -> Result<String> {
    age::encrypt_and_armor(recipient, data_key).context("encrypt data key with age")
}

/// Try to unwrap the data key from one armored payload with any of `identities`.
fn unwrap_one(enc: &str, identities: &[Identity]) -> Result<Vec<u8>> {
    let ids: Vec<&dyn age::Identity> = identities.iter().map(|i| i as &dyn age::Identity).collect();
    if ids.is_empty() {
        bail!("no age identities available");
    }
    let decryptor = age::Decryptor::new_buffered(ArmoredReader::new(enc.as_bytes()))
        .context("parse age data key payload")?;
    let mut plain = Vec::new();
    decryptor
        .decrypt(ids.into_iter())
        .context("age identity cannot decrypt data key")?
        .read_to_end(&mut plain)
        .context("read decrypted data key")?;
    Ok(plain)
}

/// Unwrap the data key from any of the armored `enc` payloads.
pub fn unwrap_data_key(enc_values: &[String], identities: &[Identity]) -> Result<[u8; 32]> {
    for enc in enc_values {
        let Ok(bytes) = unwrap_one(enc, identities) else {
            continue;
        };
        if bytes.len() != 32 {
            continue;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        return Ok(key);
    }
    bail!("no configured identity can decrypt this file (wrong key?)")
}

/// Generate a fresh identity. Returns `(key file text, public recipient)`.
pub fn generate_identity() -> Result<(String, String)> {
    let identity = Identity::generate();
    let recipient = identity.to_public();
    let secret = identity.to_string();
    let text = format!(
        "# created: {}\n# public key: {}\n{}\n",
        super::util::date_utc_today(),
        recipient,
        secret.expose_secret()
    );
    Ok((text, recipient.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_roundtrip() {
        let (key_text, public) = generate_identity().unwrap();
        assert!(public.starts_with("age1"));
        let identity = identity_from_key_text(&key_text).unwrap();
        let data_key = [9u8; 32];
        let wrapped = wrap_data_key(&data_key, &parse_recipient(&public).unwrap()).unwrap();
        assert!(wrapped.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
        assert_eq!(unwrap_data_key(&[wrapped], &[identity]).unwrap(), data_key);
    }

    #[test]
    fn wrong_identity_fails() {
        let (_, public) = generate_identity().unwrap();
        let (other_text, _) = generate_identity().unwrap();
        let other = identity_from_key_text(&other_text).unwrap();
        let data_key = [1u8; 32];
        let wrapped = wrap_data_key(&data_key, &parse_recipient(&public).unwrap()).unwrap();
        assert!(unwrap_data_key(&[wrapped], &[other]).is_err());
    }
}

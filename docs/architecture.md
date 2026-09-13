# open-envault architecture

Local-first encrypted environment files. Ciphertext lives in Git; private keys
live only on authorized machines; secrets are decrypted in memory and injected
into child processes at runtime. There is no hosted service, database, or
telemetry.

## Principles

- **CLI-first, one canonical implementation.** All cryptography, schema,
  configuration, and runtime logic lives in the Rust workspace. Other
  ecosystems (Arqen, NestJS/npm, Go) integrate by invoking the CLI or by
  linking the facade crate; they never reimplement encryption.
- **Storage format is SOPS-compatible age.** Files produced by
  `open-envault` are plain SOPS files (age recipients + AES-256-GCM values +
  a SOPS metadata block). Any official `sops`/`age` tooling can decrypt them,
  and `open-envault` decrypts files produced by official `sops`.
  No custom encryption format is introduced.
- **Fail closed.** Invalid configuration, schema, key, or ciphertext abort the
  operation with a nonzero exit code and a redacted diagnostic.
- **Secrets stay in memory.** Decrypted values and data keys exist only in
  process memory, are zeroized, and are never logged or persisted. Encrypted
  writes are atomic (temp file + rename).

## Crate responsibilities

Single crate `open-envault` (`crates/open-envault`) provides the library + binary:

| Module | Responsibility |
|---|---|
| `open-envault::core` | Project config (`open-envault.yaml`), upward discovery, environment profiles, key-source resolution, atomic file IO. |
| `open-envault::crypto` | Native SOPS-over-age: data-key generation, age key wrapping per recipient, AES-256-GCM value encryption, SOPS metadata + MAC, key generation/parsing, permission enforcement. |
| `open-envault::schema` | Schema types, per-type validation, dotenv parse/write, `.env.example` generation. |
| `open-envault::runtime` | Child process execution, environment merging, signal forwarding, exit-code propagation. |
| `open-envault::output` | Redaction, one-way fingerprinting, JSON envelopes, shared error/exit-code contract. |

Public API: `open_envault::load_environment` (library, consumed by Arqen). Binary `oenv` (from `open-envault` crate) (`src/main.rs`) handles the CLI.

## Project layout on disk

```text
open-envault.yaml        project config (environments, recipients, key files)
config/env.schema.yaml   per-environment schema
secrets/*.env.enc        SOPS-encrypted env profiles
.env.example             generated documentation example
```

`init` also writes a `.sops.yaml` for optional interop with official SOPS
tooling; the runtime never reads it.

## Encryption flow

1. Encrypt: generate a fresh random 32-byte data key.
2. Wrap the data key with the age public key of every configured recipient
   (`secrets/*.env.enc` stores one wrapped copy per recipient).
3. Encrypt each plaintext value with AES-256-GCM under the data key, emitting
   SOPS `ENC[AES256_GCM,...]` strings.
4. Compute the SOPS metadata MAC (HMAC-SHA256 over the canonical tree under
   the data key) and encrypt it into the `mac` field.
5. Write the profile atomically (temp file + rename) with byte-compatible
   SOPS metadata (`version`, `age`, `mac`, `lastmodified`, empty KMS/PGP
   sections).

Decrypt reverses the steps: resolve the identity from the key source, unwrap
the data key with the private key, verify the MAC, decrypt values in memory.
A recipient the identity cannot satisfy, a bad key, or a MAC mismatch fails
closed.

## Key sources (resolution order)

1. `OPENENVAULT_AGE_KEY` — canonical explicit identity, CI-friendly (never echoed).
2. `OPENENCRYPT_AGE_KEY` — legacy compatibility alias.
3. `SOPS_AGE_KEY` — compatibility with SOPS-based CI workflows.
4. Profile `key_file` from `open-envault.yaml`.
5. Developer default:
   `$XDG_CONFIG_HOME|~/.config/open-envault/keys/<environment>.txt`.
6. Server/deploy key paths configured for deployment environments.

Key files are enforced mode 0600 and must live outside the repository.
Recipients are per environment and public; they belong in Git.

## Diagnostics and redaction

- Default output is redacted: variable names, statuses, and schema errors are
  shown; values never are.
- `check`, `doctor`, and `diff` also expose stable JSON envelopes and explicit
  exit codes (`docs/contract.md`). JSON structure and exit codes are a public
  contract; changes are breaking.
- `diff` and rotation report one-way fingerprints
  (`HMAC-SHA256(project_pepper, value)`, truncated) rather than values, so
  low-entropy secrets cannot be reversed. The pepper is a secret stored with
  the keys, outside Git.

## Runtime injection

`exec` resolves the environment, decrypts in memory, parses dotenv, merges
values with the inherited process environment, spawns the child with inherited
stdio, forwards signals, and propagates the child's exit status. Inherited
process environment wins over loaded values unless `--force` is given. No
plaintext `.env` file is created.

## Guided setup

`oenv setup <env>` validates the project and schema, resolves or creates a
no-clobber age identity, derives its public recipient, preserves existing
recipients, reads dotenv or JSON from a file or stdin, merges values, and
atomically writes the encrypted profile. Configuration is rewritten through
the typed `Project` model. Provider CLIs, GitHub APIs, and secret-manager APIs
are not called by the core.

The default key directory is `~/.config/open-envault/keys`. The historical
`~/.config/open_envault/keys` directory remains a read compatibility fallback.
Relative configured paths resolve from `open-envault.yaml`; `~` resolves from
`HOME` or `USERPROFILE`.

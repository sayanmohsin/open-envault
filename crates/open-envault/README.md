# open-envault

[![crates.io](https://img.shields.io/crates/v/open-envault.svg)](https://crates.io/crates/open-envault)
[![npm](https://img.shields.io/npm/v/open-envault.svg)](https://www.npmjs.com/package/open-envault)
[![CI](https://github.com/sayanmohsin/open-envault/actions/workflows/validate.yml/badge.svg)](https://github.com/sayanmohsin/open-envault/actions/workflows/validate.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg)](LICENSE)
[![Open Source](https://img.shields.io/badge/Open%20Source-Yes-brightgreen.svg)](https://github.com/sayanmohsin/open-envault)

**Open Source — Local-first, SOPS-compatible secrets for Git and Rust.** Push ciphertext to Git; keep private age keys on your machines; inject secrets into child processes only at runtime — no hosted service, no custom crypto. Free and open for everyone to use, learn, and extend.

Built for Rust projects and any language that spawns a child process (Arqen, NestJS, Go via CLI). Encrypted files are plain [SOPS](https://getsops.io) age files — `sops` can decrypt what `open-envault` encrypts and vice versa.

## Features

- **Rust-first, one binary** — native Rust, no `sops`/`rage` needed at runtime, byte-compatible with `sops` 3.13 age
- **Push to Git** — `open-envault.yaml`, `config/env.schema.yaml`, `secrets/*.enc` and public age recipients live in Git; private keys never do
- **Fail-closed** — bad config/schema/key/ciphertext → non-zero exit, redacted diagnostics
- **Memory-only secrets** — data keys and values are zeroized, never logged or written to disk (atomic writes, 0600 key files)
- **Schema & diagnostics** — `string`/`integer`/`boolean`/`url`/`enum`/`duration` + `required`/`secret`/`env` guards, human + stable JSON output
- **Guided setup** — `oenv setup` safely creates or reuses keys, derives recipients, validates schemas, and writes encrypted profiles
- **Runtime injection** — `oenv exec dev -- <cmd>` merges decrypted values into the child’s env and preserves exit codes/signals

## Install

```bash
# Rust (binary + library)
cargo install open-envault              # bin `oenv`
# or library for Arqen:
# cargo add open-envault

# Node (binary shim + TypeScript API, wraps the Rust binary)
npm i -D open-envault
# or pnpm / yarn / bun
```

Prebuilt binaries are attached to each [GitHub Release](https://github.com/sayanmohsin/open-envault/releases) (`oenv-<target>` + `checksums.txt`).

## Quick start

```bash
oenv init
oenv setup dev --key-file ~/.config/open-envault/keys/dev.txt --from-file ./dev.env
oenv check dev --format json
oenv exec dev -- npm start
```

Setup reuses existing keys without overwriting them, preserves configured
recipients, safely merges reruns, and writes only encrypted output. Provider
exports can be piped through stdin with `--from-stdin`.

`open-envault.yaml` example:

```yaml
project: my-app
environments:
  dev:
    file: secrets/dev.env.enc
    schema: config/env.schema.yaml
    recipients: [age1ql0...]
```

## CLI

```
oenv init
oenv setup <env> [--key-file <path>] (--from-file <path>|--from-stdin) [--format dotenv|json]
oenv env create <env>
oenv key generate <env>
open-envault set <env> <VAR>            # reads value from stdin
open-envault edit <env>                 # $EDITOR on a secure temp file
open-envault check <env> [--format human|json]
oenv doctor [--format json]
oenv diff <envA> <envB> [--format json]
oenv rotate <env>
oenv exec <env> -- <cmd> [args...]
oenv example                    # regenerate .env.example from schema
```

`set` never takes a value on the command line; `exec` forwards signals and preserves the child’s exit code; diagnostics never print secret values (one-way `HMAC-SHA256` fingerprints only).

## Configuration

```
open-envault.yaml
config/env.schema.yaml
secrets/dev.env.enc
secrets/prod.env.enc
.env.example
```

Key sources (first match wins): `OPENENVAULT_AGE_KEY` / `OPENENCRYPT_AGE_KEY` / `SOPS_AGE_KEY`, corresponding `*_FILE` variables, configured key file, then `~/.config/open-envault/keys/<env>.txt` (0600).

## TypeScript / NestJS

```ts
import { exec, check } from "open-envault";

await exec("dev", "node", ["server.js"]);
const { findings } = await check("dev");
```

The npm package is a thin wrapper — it locates the prebuilt `open-envault` binary in `prebuilds/<platform>-<arch>/` and spawns it; no crypto is reimplemented in JS.

## Rust / Arqen

```toml
[dependencies]
open-envault = "0.1"
```

```rust
let env = open_envault::load_environment("dev")?; // BTreeMap<String,String>, memory-only
```

## Security

See [`docs/architecture.md`](docs/architecture.md) and [`docs/contract.md`](docs/contract.md). Plaintext secrets, decrypted `.env` files, and private age keys must never be committed (`.gitignore` covers `.env*`, `*.key`, `target/`). Test fixtures under `crates/open-envault/tests/fixtures/` are throwaway and only decrypt fake data.

## Docs

- [Architecture](docs/architecture.md) — principles, crate map, storage format, key sources
- [Contract](docs/contract.md) — exit codes and stable JSON envelopes for wrappers
- [Usage](../../docs/usage.md) — setup, CI, recovery, and cross-platform workflows
- [CI guidance](../../docs/ci.md) — provider-neutral GitHub Actions guidance

## License

Code dual-licensed under Apache 2.0 or MIT, at your option. Documentation and course materials additionally available as OpenCourse under CC BY 4.0 — see `LICENSE`, `LICENSE-APACHE`, `LICENSE-MIT`.

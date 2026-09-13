# Usage

## Install

```bash
cargo install open-envault              # Rust binary `oenv` (package `open-envault`)
npm i -D open-envault     # Node wrapper (prebuilds/<platform>-<arch>/oenv)
```

## Project setup

```bash
oenv init
oenv setup dev \
  --key-file ~/.config/open-envault/keys/dev.txt \
  --from-file ./dev.env
oenv check dev
cat secrets/dev.env.enc            # ciphertext — safe to commit
oenv doctor --format json          # verify profiles, schemas, keys, and decryption
```

Setup creates or reuses the age key, derives its public recipient, validates
the schema, and writes only encrypted output. Existing keys are never
overwritten. Rerunning setup safely merges values; a failed validation leaves
the previous encrypted profile unchanged. On Windows, use a path such as
`%APPDATA%\\open-envault\\keys\\dev.txt`.

`oenv exec` is the runtime entrypoint:

```bash
oenv exec dev -- cargo run
oenv exec dev -- node server.js
oenv exec prod -- ./target/release/app
```

It decrypts `secrets/<env>.env.enc` with an age identity from the configured
key file, `~/.config/open-envault/keys/<env>.txt`, or
`OPENENVAULT_AGE_KEY`/`SOPS_AGE_KEY` in CI, parses dotenv, merges with the
parent env, and spawns the child with inherited stdio/signals.

For a gradual migration, an existing injector can remain in the parent
environment while selected open-envault values take precedence:

```bash
existing-secret-provider run -- oenv exec dev --force -- npm start
```

Bulk imports are stdin-only and do not create plaintext files:

```bash
some-secret-provider export --format=json |
  oenv setup dev --from-stdin --format json
```

Compare two profiles without printing values. Set the same private pepper for
all environments in the project:

```bash
OPENENVAULT_DIFF_PEPPER="$MIGRATION_PEPPER" oenv diff dev prd --format json
oenv rotate prd
```

## CI (GitHub Actions)

See [`docs/ci.md`](ci.md). Open Envault validates and decrypts profiles; it
does not create GitHub Environments or GitHub Secrets.

## Schema

`config/env.schema.yaml`:

```yaml
variables:
  DATABASE_URL:
    type: url
    required: true
    secret: true
  LOG_LEVEL:
    type: enum
    values: [debug, info, warn, error]
    default: info
```

`open-envault check` validates required, extra, and typed variables. `oenv doctor`
checks every configured profile, schema, recipient list, and decryption path.
`oenv example` regenerates `.env.example`.

## Rust

```rust
let env = open_envault::load_environment("dev")?;
```

## TypeScript

```ts
import { check, exec } from "open-envault";
await exec("dev", "node", ["server.js"]);
```

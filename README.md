# mpe-plugin-smtp

SMTP protocol sidecar plugin for MPE: connect / send / disconnect. Extracted
from the host built-in `flow-engine-smtp` crate; wire config fields and report
output names are unchanged, so existing `.mpf` flows keep working after
renaming node types `smtp_*` → `smtp:*`.

## Nodes

| Type | Ports | Purpose |
|------|-------|---------|
| `smtp:connect` | in/true/false | Build SMTP transport (implicit TLS / STARTTLS / plaintext), probe with `test_connection`, store in the per-execution pool |
| `smtp:send` | in/true/false | Build MIME message (plain text / HTML / attachments) and send via the selected connection |
| `smtp:disconnect` | in/out | Release the selected connection (never blocks the flow) |

`category: "Email"`, `color: #3b82f6`. `smtp:connect` declares
`capabilities.single_node` so the host's single-node path (`mpe run node`,
GUI test button) can probe reachability.

## Build / Test

```bash
cd plugins/smtp
cargo build --release          # → target/release/mpe_plugin_smtp
cargo test                     # offline: unit + stdio roundtrip (no server)
cargo test -- --ignored        # live integration tests (needs SMTP server)
```

### Live integration tests

`MPE_SMTP_URI` (default `smtp://localhost:587`, STARTTLS) points at any
reachable SMTP endpoint, e.g. the repo's `echo/` stack:

```bash
MPE_SMTP_URI=smtp://localhost:587 cargo test --release -- --ignored --test-threads=1
```

## Install

Place the built binary where the host can find it and set `MPE_PLUGIN_DIR`
to the `plugins/` directory, or adjust `plugin.json`'s `entry.command`
(absolute path; machine-specific). `capabilities.streaming: true` keeps the
process resident so the connection pool survives across executions.

## Connection selection

The pool keys connections by `(execution_id, connection_id)`. The connect
node registers under its own instance id (`node_instance_id` = the connect
node's uuid); operation nodes pick a connection via the `connection_id`
config field, which the host fills from the schema's `x-node-selector`
(`node_type: "smtp:connect"`). Same-target re-connect is idempotent; a
different target replaces the stale connection (warning logged). Disconnect
releases one connection; `flow_ended` releases the whole execution
(double-release is harmless — release on a missing entry is a no-op).

## Auth

Two wire shapes are accepted (both may appear in existing flows):

1. Current host shape: `auth: { "auth_type": "plain"|"login"|"xoauth2",
   "username", "password"?, "oauth2_tokens"?: { "access_token", ... } }` —
   plaintext.
2. Legacy `flow-engine-core::email_types::EmailAuthConfig` shape:
   `auth: { "type": "plain"|"login", "username", "encrypted_password" }` or
   `{ "type": "oauth2", ..., "encrypted_tokens" }` — AES-256-GCM encrypted,
   decrypted with the same keychain key as the host
   (`src/crypto.rs`, a standalone copy of `flow-engine-crypto`; the plugin
   never links host crates).

## Timeouts

The host wrapper owns `timeout_ms` / `execution_timeout_ms`; the plugin
ignores them and relies on the host to abort a hung execution.

## Notes

- OAuth2 token *refresh* is host-GUI territory (`email_oauth2_*` Tauri
  commands) and was not ported; the plugin uses the access token carried in
  the config.
- `echo/` SMTP service is part of the external (gitignored) echo stack, not
  this repo — integration tests default to localhost standard ports and are
  overridable via `MPE_SMTP_URI`.

## License

MIT — see [LICENSE](./LICENSE).

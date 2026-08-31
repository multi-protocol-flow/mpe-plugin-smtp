//! `smtp:connect` node — establishes an SMTP transport with a
//! `test_connection` verification and idempotent pool reuse.
//!
//! Config: `{ "host", "port", "tls_mode" ("implicit"|"starttls"|"none"),
//! "auth"?, "connect_timeout_ms" }`. Output mirrors the host
//! `SmtpConnectOutput` report shape: `{ success, connection_id,
//! server_greeting, request: { host, port, tls_mode }, timing: { connect_ms,
//! total_ms }, error }`.
//!
//! Idempotency: a second connect for the same `execution_id` with the SAME
//! host + port reuses the pooled transport — no rebuild, no probe. A
//! DIFFERENT target replaces the stale entry (surfaced via
//! `ctx.log("warn", …)`).

use std::time::Instant;

use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::{AsyncSmtpTransport, Tokio1Executor};

use crate::auth::{resolve_auth, AuthCredentials};
use crate::pool::{SmtpConnection, SmtpPool};
use mpe_plugin_sdk::prelude::*;

/// Default port per TLS mode when `port` is 0/missing (host
/// `SmtpConnectionManager::effective_port` semantics).
fn default_port(tls_mode: &str) -> u16 {
    match tls_mode {
        "starttls" => 587,
        "none" => 25,
        _ => 465,
    }
}

/// Parsed, validated connection target — the testable core of
/// [`connect_core`] (no network I/O here).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ConnectTarget {
    pub host: String,
    pub port: u16,
    pub tls_mode: String,
    pub auth: Option<AuthCredentials>,
}

/// Resolves and validates the connection target from the node config.
///
/// Empty `host` is a config error. An explicit `port` wins; otherwise the
/// TLS-mode default (465/587/25) applies. The `auth` JSON block is parsed
/// into credentials (see [`resolve_auth`]); `connect_timeout_ms` is
/// accepted for wire compatibility but the host wrapper owns execution
/// timeouts (see plugin README §timeouts).
pub(crate) fn resolve_target(config: &serde_json::Value) -> Result<ConnectTarget, String> {
    let host = config
        .get("host")
        .and_then(serde_json::Value::as_str)
        .filter(|h| !h.is_empty())
        .ok_or_else(|| crate::i18n::t("服务器地址必填", "Server address is required").to_string())?
        .to_string();
    let tls_mode = config
        .get("tls_mode")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("implicit")
        .to_string();
    let port = match config.get("port") {
        Some(serde_json::Value::Number(n)) => n
            .as_u64()
            .filter(|p| *p > 0 && *p <= u16::MAX as u64)
            .map(|p| p as u16)
            .ok_or_else(|| {
                crate::i18n::t("端口无效", "Invalid port").to_string() + &format!(": {n}")
            })?,
        Some(serde_json::Value::String(s)) => s.parse::<u16>().map_err(|_| {
            crate::i18n::t("端口无效", "Invalid port").to_string() + &format!(": {s}")
        })?,
        _ => default_port(&tls_mode),
    };
    let auth = resolve_auth(config.get("auth").unwrap_or(&serde_json::Value::Null))?;
    Ok(ConnectTarget {
        host,
        port,
        tls_mode,
        auth,
    })
}

/// Thin `ExecuteContext` adapter: extracts `execution_id` (fallback
/// `"default"` for SDK tests that send none), the node instance id as the
/// connection selector (`connection_id` — the host sends `node_instance_id`
/// = the connect node's own uuid, so operation nodes can pick THIS
/// connection via their `connection_id` config), and the resolved config,
/// then delegates to [`connect_core`]. Logs the failure so the host
/// surfaces it in the report.
pub async fn execute(ctx: &mut ExecuteContext, pool: &SmtpPool) -> ExecuteResult {
    let exec_id = ctx.execution_id().unwrap_or("default").to_string();
    let connection_id = ctx.node_instance_id().unwrap_or("default").to_string();
    let config = ctx.config().clone();
    match connect_core(pool, &exec_id, &connection_id, &config).await {
        Ok((result, replaced)) => {
            if replaced {
                ctx.log(
                    "warn",
                    crate::i18n::t(
                        "连接目标变化，已替换旧连接",
                        "Connection target changed; old connection replaced",
                    ),
                );
            }
            result
        }
        Err(msg) => {
            ctx.log("error", &msg);
            ExecuteResult::fail(msg)
        }
    }
}

/// Core connect logic, testable without an [`ExecuteContext`] (the SDK's
/// `ExecuteContext::from_params` is `pub(crate)`, so plugin tests cannot
/// construct one).
///
/// Returns `(result, replaced)`; `replaced` is `true` only when an existing
/// connection with a DIFFERENT target was swapped out.
async fn connect_core(
    pool: &SmtpPool,
    exec_id: &str,
    connection_id: &str,
    config: &serde_json::Value,
) -> Result<(ExecuteResult, bool), String> {
    let start = Instant::now();
    let target = resolve_target(config)?;

    // Build the lettre transport builder per TLS mode (host
    // `create_builder` semantics: relay → implicit, starttls_relay →
    // STARTTLS, builder_dangerous → plaintext).
    let mut builder = match target.tls_mode.as_str() {
        "starttls" => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&target.host)
            .map_err(|e| {
                format!(
                    "{}: {e}",
                    crate::i18n::t("构建 StartTLS transport Failed", "Failed to build StartTLS transport")
                )
            })?
            .port(target.port),
        "none" => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&target.host)
            .port(target.port),
        _ => AsyncSmtpTransport::<Tokio1Executor>::relay(&target.host)
            .map_err(|e| {
                format!(
                    "{}: {e}",
                    crate::i18n::t("构建 Implicit TLS transport Failed", "Failed to build Implicit TLS transport")
                )
            })?
            .port(target.port),
    };

    // Apply auth: PLAIN/LOGIN → credentials + mechanism; XOAUTH2 → SASL
    // string as the "password" (host `apply_auth` semantics).
    if let Some(auth) = &target.auth {
        builder = match auth {
            AuthCredentials::Plain { username, password } => builder
                .credentials(Credentials::new(username.clone(), password.clone()))
                .authentication(vec![Mechanism::Plain]),
            AuthCredentials::Login { username, password } => builder
                .credentials(Credentials::new(username.clone(), password.clone()))
                .authentication(vec![Mechanism::Login]),
            AuthCredentials::XOAuth2 { user, access_token } => {
                let sasl = crate::auth::xoauth2_string(user, access_token);
                builder
                    .credentials(Credentials::new(String::new(), sasl))
                    .authentication(vec![Mechanism::Xoauth2])
            }
        };
    }

    let transport = builder.build::<Tokio1Executor>();

    // test_connection probes the server BEFORE registering — this is where
    // an unreachable host fails, close to the connect node.
    match transport.test_connection().await {
        Ok(true) => {}
        Ok(false) => {
            return Err(crate::i18n::t("连接测试Failed", "Connection test failed").to_string());
        }
        Err(e) => {
            return Err(format!(
                "{}: {e}",
                crate::i18n::t("connection failed", "connection failed")
            ));
        }
    }

    let total_ms = start.elapsed().as_millis() as u64;
    let (_, replaced) = pool.connect(
        exec_id,
        connection_id,
        SmtpConnection {
            transport,
            host: target.host.clone(),
            port: target.port,
        },
        |existing, incoming| existing.host == incoming.host && existing.port == incoming.port,
    );
    Ok((
        crate::ok_result(serde_json::json!({
            "success": true,
            "connection_id": connection_id,
            "server_greeting": serde_json::Value::Null,
            "request": {
                "host": target.host,
                "port": target.port,
                "tls_mode": target.tls_mode,
            },
            "timing": {
                "connect_ms": total_ms,
                "total_ms": total_ms,
            },
            "error": serde_json::Value::Null,
        })),
        replaced,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_target_defaults() {
        let target = resolve_target(&serde_json::json!({
            "host": "smtp.example.com",
        }))
        .expect("host-only config is valid");
        assert_eq!(
            target,
            ConnectTarget {
                host: "smtp.example.com".to_string(),
                port: 465,
                tls_mode: "implicit".to_string(),
                auth: None,
            }
        );
    }

    #[test]
    fn resolve_target_explicit_port_and_tls() {
        let target = resolve_target(&serde_json::json!({
            "host": "smtp.example.com",
            "port": 2525,
            "tls_mode": "none",
        }))
        .expect("full config is valid");
        assert_eq!(target.port, 2525);
        assert_eq!(target.tls_mode, "none");
    }

    #[test]
    fn resolve_target_default_port_per_tls_mode() {
        assert_eq!(
            resolve_target(&serde_json::json!({ "host": "h", "tls_mode": "starttls" }))
                .expect("starttls")
                .port,
            587
        );
        assert_eq!(
            resolve_target(&serde_json::json!({ "host": "h", "tls_mode": "none" }))
                .expect("none")
                .port,
            25
        );
        assert_eq!(
            resolve_target(&serde_json::json!({ "host": "h", "tls_mode": "implicit" }))
                .expect("implicit")
                .port,
            465
        );
    }

    #[test]
    fn resolve_target_missing_host_fails() {
        assert!(resolve_target(&serde_json::json!({})).is_err());
        assert!(resolve_target(&serde_json::json!({ "host": "" })).is_err());
    }

    #[test]
    fn resolve_target_rejects_bad_port() {
        assert!(resolve_target(&serde_json::json!({ "host": "h", "port": "abc" })).is_err());
        assert!(resolve_target(&serde_json::json!({ "host": "h", "port": 0 })).is_err());
        assert!(resolve_target(&serde_json::json!({ "host": "h", "port": 70000 })).is_err());
    }
}

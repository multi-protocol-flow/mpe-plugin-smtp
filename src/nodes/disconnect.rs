//! `smtp:disconnect` node — releases the selected connection from the pool.
//!
//! Config: `{ "connection_id" }`. Output mirrors the host
//! `SmtpDisconnectOutput` report shape: `{ success, connection_id,
//! request: { connection_id }, timing: { disconnect_ms, total_ms }, error }`.
//!
//! Host semantics preserved: disconnect NEVER blocks the flow — success and
//! failure both route to the single `out` port (the plugin returns an `ok`
//! result either way; `output.success` reflects whether a connection was
//! actually removed). Missing connections are a silent `success: false`
//! with an error message, not a hard failure.

use std::time::Instant;

use crate::nodes::resolve_connection_id;
use crate::pool::SmtpPool;
use mpe_plugin_sdk::prelude::*;

/// Thin `ExecuteContext` adapter: extracts `execution_id` (fallback
/// `"default"`) and the resolved config, then delegates to
/// [`disconnect_core`]. A missing `connection_id` IS a hard failure (the
/// node cannot know which connection to release); releasing a missing
/// connection is not.
pub async fn execute(ctx: &mut ExecuteContext, pool: &SmtpPool) -> ExecuteResult {
    let exec_id = ctx.execution_id().unwrap_or("default").to_string();
    let config = ctx.config().clone();
    match disconnect_core(pool, &exec_id, &config) {
        Ok(result) => result,
        Err(msg) => {
            ctx.log("error", &msg);
            ExecuteResult::fail(msg)
        }
    }
}

/// Core disconnect logic, testable without an [`ExecuteContext`].
///
/// Releases the selected connection. Missing/empty `connection_id` in the
/// config is a hard error; a missing pooled entry is a non-blocking
/// `success: false` output (host `SmtpProvider::disconnect` semantics).
fn disconnect_core<C: std::any::Any + Send + Sync>(
    pool: &SmtpPool<C>,
    exec_id: &str,
    config: &serde_json::Value,
) -> Result<ExecuteResult, String> {
    let start = Instant::now();
    let connection_id = resolve_connection_id(config)?;
    let total_ms = start.elapsed().as_millis() as u64;

    let removed = pool.release_connection(exec_id, &connection_id);
    if removed {
        Ok(crate::close_ok_result(serde_json::json!({
            "success": true,
            "connection_id": connection_id,
            "request": { "connection_id": connection_id },
            "timing": { "disconnect_ms": total_ms, "total_ms": total_ms },
            "error": serde_json::Value::Null,
        })))
    } else {
        let msg = format!(
            "{} '{connection_id}'",
            crate::i18n::t("SMTP 连接", "SMTP connection")
        ) + " "
            + crate::i18n::t("不存在", "does not exist");
        Ok(crate::close_ok_result(serde_json::json!({
            "success": false,
            "connection_id": connection_id,
            "request": { "connection_id": connection_id },
            "timing": { "disconnect_ms": total_ms, "total_ms": total_ms },
            "error": msg,
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::SmtpPool;

    /// A connection payload for disconnect tests; the pool is exercised
    /// with a dummy type (keying-only, no SMTP server needed).
    #[derive(Default)]
    struct Dummy;

    fn seed(pool: &SmtpPool<Dummy>, exec_id: &str, uuid: &str) {
        pool.connect(exec_id, uuid, Dummy, |_, _| true);
    }

    /// A connected connection is removed; output reports success and routes
    /// to the `out` port.
    #[test]
    fn disconnect_releases_connection() {
        let pool = SmtpPool::<Dummy>::default();
        seed(&pool, "exec1", "conn-a");

        let result = disconnect_core(&pool, "exec1", &serde_json::json!({ "connection_id": "conn-a" }))
            .expect("disconnect succeeds");
        assert_eq!(result.next_ports, vec!["out".to_string()]);
        assert_eq!(
            result.output_data.as_ref().and_then(|o| o.get("success")),
            Some(&serde_json::json!(true))
        );

        assert!(pool.connection("exec1", "conn-a").is_none());
    }

    /// Disconnecting a missing connection is a non-blocking
    /// `success: false` — the flow keeps routing through `out`.
    #[test]
    fn disconnect_missing_connection_is_non_blocking() {
        let pool = SmtpPool::<Dummy>::default();

        let result =
            disconnect_core(&pool, "exec1", &serde_json::json!({ "connection_id": "ghost" }))
                .expect("disconnect succeeds");
        assert_eq!(result.next_ports, vec!["out".to_string()]);
        let output = result.output_data.as_ref().expect("output data");
        assert_eq!(output["success"], false);
        assert!(
            output["error"].as_str().unwrap_or_default().contains("ghost"),
            "error names the missing id"
        );
    }

    /// Missing/empty `connection_id` in the config is a hard error (the
    /// node cannot pick a connection).
    #[test]
    fn disconnect_without_connection_id_fails() {
        let pool = SmtpPool::<Dummy>::default();
        assert!(disconnect_core(&pool, "exec1", &serde_json::json!({})).is_err());
        assert!(disconnect_core(&pool, "exec1", &serde_json::json!({ "connection_id": "" })).is_err());
    }
}

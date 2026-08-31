//! SMTP sidecar plugin for MPE.
//!
//! Third-party plugin crate: depends only on `mpe-plugin-sdk` (which in turn
//! bundles the shared wire contract (`mpe-plugin-sdk::protocol`)). Never imports host
//! types (`flow-engine-core`, `flow-engine-plugin`, ...) — the plugin is a
//! separate process speaking JSON-RPC 2.0 over stdio.
//!
//! Node types: `smtp:connect` / `smtp:send` / `smtp:disconnect`.
//! `execute` dispatches to `nodes/*.rs` by the `config["type"]`
//! discriminator. The connect/send nodes declare `in`/`true`/`false`
//! tri-ports (success routes `true`, failure goes through the host
//! `on_error` strategy to `false`); `smtp:disconnect` keeps the single
//! `in`/`out` shape and never blocks the flow (host semantics).
//!
//! Connection selection: the pool keys connections by the composite
//! `(execution_id, connection_id)` — the connect node registers under its
//! own instance id (`ctx.node_instance_id()`), operation nodes pick their
//! connection via the `connection_id` field the host resolves into their
//! config from the schema's `x-node-selector` (pointing at `smtp:connect`
//! nodes).
//!
//! `smtp:connect` additionally declares `capabilities.single_node: true`:
//! the host's single-node execution path (`execute_single_node` /
//! `mpe run node`) consults that capability instead of a hardcoded
//! whitelist, so the plugin is testable for reachability without a host
//! code change.

use std::future::Future;

use mpe_plugin_sdk::prelude::*;

mod auth;
mod crypto;
mod i18n;
mod nodes;
mod pool;
use pool::SmtpPool;

/// Process-level plugin singleton: node registry + per-execution pool.
#[derive(Default)]
pub struct SmtpPlugin {
    pub pool: SmtpPool,
}

/// Builds one SMTP node description with host-facing metadata.
///
/// `default_config` is injected into a freshly added node; `properties` is
/// the JSON-Schema `properties` map (each value declares its own `type`)
/// and `required` the schema's required field list. `ports` declares the
/// node's input/output ports (see [`operation_ports`] / [`close_ports`]).
fn smtp_node(
    type_id: &str,
    display_name: &str,
    icon: &str,
    color: &str,
    default_config: serde_json::Value,
    properties: serde_json::Value,
    required: &[&str],
    ports: Vec<PortDescription>,
    capabilities: Option<PluginCapabilities>,
) -> NodeDescription {
    let mut node = NodeDescription::new(type_id, display_name);
    node.category = Some("Email".to_string());
    node.icon = Some(icon.to_string());
    node.color = Some(color.to_string());
    node.ports = ports;
    node.default_config = default_config;
    node.capabilities = capabilities.unwrap_or_default();
    node.config_schema = Some(serde_json::json!({
        "type": "object",
        "properties": properties,
        "required": required,
    }));
    node
}

/// 操作节点（connect/send）的双输出端口：`in`(输入) + `true`(成功) +
/// `false`(失败)。失败不在此路由：节点返回 `ExecuteResult::fail` 后宿主按
/// `on_error` 策略（默认 RouteToFalse）自动走 `false` 端口。
fn operation_ports() -> Vec<PortDescription> {
    vec![
        PortDescription::new("in", i18n::t("输入", "Input"), PORT_KIND_IN),
        PortDescription::new("true", i18n::t("成功", "Success"), PORT_KIND_OUT),
        PortDescription::new("false", i18n::t("失败", "Failure"), PORT_KIND_OUT),
    ]
}

/// `smtp:disconnect` 的单输出端口：`in`(输入) + `out`(输出)。
fn close_ports() -> Vec<PortDescription> {
    vec![
        PortDescription::new("in", i18n::t("输入", "Input"), PORT_KIND_IN),
        PortDescription::new("out", i18n::t("输出", "Output"), PORT_KIND_OUT),
    ]
}

/// 操作节点 config_schema 里的 `connection_id` 字段：宿主 `x-node-selector`
/// 渲染为对流程内 `smtp:connect` 节点的选择器，选中后把 connect 节点的
/// instance id 注入 config。
fn connection_id_property() -> serde_json::Value {
    serde_json::json!({
        "type": "string",
        "title": i18n::t("SMTP 连接", "SMTP Connection"),
        "x-node-selector": { "node_type": "smtp:connect" },
    })
}

/// 操作节点成功结果，显式选择 `true` 端口让宿主路由到下游成功分支。
///
/// 宿主把 execute 响应里的 `next_ports` 解析为连接路由
/// （flow-engine-plugin `wrapper.rs::resolve_next_node_ids`）：空列表意味着
/// "没有匹配的端口连接"，分支在此终止。因此所有成功路径都必须显式声明
/// `next_ports: ["true"]`，插件才能被宿主串联执行。失败不在此路由：返回
/// `ExecuteResult::fail` 后宿主按节点 `on_error` 策略处理（默认
/// RouteToFalse → `false` 端口），插件无需自报 false。
pub(crate) fn ok_result(output: serde_json::Value) -> ExecuteResult {
    ExecuteResult {
        next_ports: vec!["true".to_string()],
        ..ExecuteResult::ok(output)
    }
}

/// `smtp:disconnect` 成功结果：disconnect 只有单输出端口，路由到 `out`。
pub(crate) fn close_ok_result(output: serde_json::Value) -> ExecuteResult {
    ExecuteResult {
        next_ports: vec!["out".to_string()],
        ..ExecuteResult::ok(output)
    }
}

impl Plugin for SmtpPlugin {
    fn describe(&self) -> Vec<NodeDescription> {
        vec![
            // `smtp:connect` — 建立 SMTP transport（按 TLS 模式 + 认证）。
            // 声明 single_node capability：宿主单节点路径（
            // execute_single_node / mpe run node）据此放行本节点的
            // 连接性验证。
            smtp_node(
                "smtp:connect",
                "SMTP Connect",
                "plug",
                "#3b82f6",
                serde_json::json!({
                    "host": "smtp.gmail.com",
                    "port": 465,
                    "tls_mode": "implicit",
                    "connect_timeout_ms": 30000,
                }),
                serde_json::json!({
                    "host": { "type": "string", "title": i18n::t("服务器地址", "Server address") },
                    "port": { "type": "integer", "title": i18n::t("端口", "Port") },
                    "tls_mode": { "type": "string", "enum": ["none", "starttls", "implicit"], "title": i18n::t("TLS 模式", "TLS mode") },
                    "auth": { "type": "string", "format": "json", "title": i18n::t("认证配置", "Auth config") },
                    "connect_timeout_ms": { "type": "integer", "title": i18n::t("连接超时", "Connect timeout") },
                }),
                &["host"],
                operation_ports(),
                Some(PluginCapabilities {
                    single_node: true,
                    ..Default::default()
                }),
            ),
            // `smtp:send` — 通过所选连接发送邮件（纯文本/HTML/附件）。
            smtp_node(
                "smtp:send",
                "SMTP Send",
                "mail",
                "#3b82f6",
                serde_json::json!({
                    "connection_id": "",
                    "from": "",
                    "to": [],
                    "cc": [],
                    "bcc": [],
                    "subject": "",
                    "body_type": "text",
                    "body": "",
                    "html_body": "",
                    "attachments": [],
                    "timeout_ms": 30000,
                }),
                serde_json::json!({
                    "connection_id": connection_id_property(),
                    "from": { "type": "string", "title": i18n::t("发件人地址", "Sender address") },
                    "to": { "type": "string", "format": "json", "title": i18n::t("收件人地址", "Recipients") },
                    "cc": { "type": "string", "format": "json", "title": i18n::t("抄送", "CC") },
                    "bcc": { "type": "string", "format": "json", "title": i18n::t("密送", "BCC") },
                    "subject": { "type": "string", "title": i18n::t("邮件主题", "Subject") },
                    "body_type": { "type": "string", "enum": ["text", "html"], "title": i18n::t("内容类型", "Content type") },
                    "body": { "type": "string", "title": i18n::t("邮件正文", "Body") },
                    "html_body": { "type": "string", "title": i18n::t("HTML 正文", "HTML body") },
                    "attachments": { "type": "string", "format": "json", "title": i18n::t("附件", "Attachments") },
                    "timeout_ms": { "type": "integer", "title": i18n::t("发送超时", "Send timeout") },
                }),
                &["connection_id", "from", "to"],
                operation_ports(),
                None,
            ),
            // `smtp:disconnect` — 释放所选连接（非阻塞，始终走 out 端口）。
            smtp_node(
                "smtp:disconnect",
                "SMTP Disconnect",
                "unplug",
                "#3b82f6",
                serde_json::json!({
                    "connection_id": "",
                }),
                serde_json::json!({
                    "connection_id": connection_id_property(),
                }),
                &["connection_id"],
                close_ports(),
                None,
            ),
        ]
    }

    // The runtime spawns execute futures, so the future must be Send; an
    // `async fn` cannot express that bound on stable (see `Plugin`).
    #[allow(clippy::manual_async_fn)]
    fn execute(&self, ctx: &mut ExecuteContext) -> impl Future<Output = ExecuteResult> + Send {
        async move {
            let node_type = ctx
                .config()
                .get("type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            match node_type {
                "smtp:connect" => nodes::connect::execute(ctx, &self.pool).await,
                "smtp:send" => nodes::send::execute(ctx, &self.pool).await,
                "smtp:disconnect" => nodes::disconnect::execute(ctx, &self.pool).await,
                other => ExecuteResult::fail(
                    i18n::t("未知节点类型", "Unknown node type").to_string()
                        + &format!(" `{other}`"),
                ),
            }
        }
    }

    // Flow-completion hook — release path 1 of the README §5 double-release
    // design: the host broadcasts flowEnded when a flow execution finishes
    // (success, failure, or cancellation), and the plugin releases the
    // per-execution connections here. The `smtp:disconnect` node is release
    // path 2 for flows that disconnect mid-run; both may fire for one
    // execution, and `release` is a no-op on a missing entry, so
    // double-release is harmless.
    fn flow_ended(&self, execution_id: &str) {
        self.pool.release(execution_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Every node must be GUI-usable in the host config panel: it carries a
    /// category, a JSON-Schema `config_schema`, a schema-shaped
    /// `default_config` (no `type` discriminator key), and the correct port
    /// declarations.
    #[test]
    fn describe_metadata_shapes() {
        let nodes = SmtpPlugin::default().describe();
        assert_eq!(nodes.len(), 3, "all 3 smtp nodes must be described");

        let by_type: HashMap<&str, &NodeDescription> = nodes
            .iter()
            .map(|node| (node.type_id.as_str(), node))
            .collect();
        assert_eq!(by_type.len(), nodes.len(), "type_ids must be unique");

        for node in &nodes {
            assert_eq!(
                node.category.as_deref(),
                Some("Email"),
                "{} must carry category `Email`",
                node.type_id
            );
            assert!(
                node.icon.is_some(),
                "{} must declare an icon",
                node.type_id
            );
            assert_eq!(
                node.color.as_deref(),
                Some("#3b82f6"),
                "{} must declare the SMTP blue color",
                node.type_id
            );
            assert!(
                node.default_config.get("type").is_none(),
                "{} default_config must not contain a `type` key",
                node.type_id
            );
            assert!(
                node.config_schema.is_some(),
                "{} must declare a config_schema",
                node.type_id
            );
            assert!(
                !node.ports.is_empty(),
                "{} must declare ports",
                node.type_id
            );
        }
    }

    /// `smtp:connect` declares the single-node capability (host
    /// connectivity test path); operation nodes do not.
    #[test]
    fn connect_declares_single_node_capability() {
        let nodes = SmtpPlugin::default().describe();
        let connect = nodes
            .iter()
            .find(|n| n.type_id == "smtp:connect")
            .expect("smtp:connect is described");
        assert!(
            connect.capabilities.single_node,
            "smtp:connect must declare single_node capability"
        );

        for other in ["smtp:send", "smtp:disconnect"] {
            let node = nodes
                .iter()
                .find(|n| n.type_id == other)
                .expect("node is described");
            assert!(
                !node.capabilities.single_node,
                "{other} must NOT declare single_node capability"
            );
        }
    }

    /// Port shapes: connect/send are tri-port, disconnect is in/out.
    #[test]
    fn port_shapes_match_host() {
        let nodes = SmtpPlugin::default().describe();
        let by_type: HashMap<&str, &NodeDescription> = nodes
            .iter()
            .map(|node| (node.type_id.as_str(), node))
            .collect();

        for id in ["smtp:connect", "smtp:send"] {
            let ports = &by_type[id].ports;
            let ids: Vec<&str> = ports.iter().map(|p| p.id.as_str()).collect();
            assert_eq!(ids, vec!["in", "true", "false"], "{id} is tri-port");
        }
        let close = &by_type["smtp:disconnect"].ports;
        let ids: Vec<&str> = close.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["in", "out"], "smtp:disconnect is in/out");
    }

    /// Operation-node schemas require the connection selector; the connect
    /// schema does not expose it.
    #[test]
    fn connection_selector_required_on_operation_nodes() {
        let nodes = SmtpPlugin::default().describe();
        let by_type: HashMap<&str, &NodeDescription> = nodes
            .iter()
            .map(|node| (node.type_id.as_str(), node))
            .collect();

        let connect_schema = by_type["smtp:connect"].config_schema.as_ref().expect("schema");
        assert!(
            !connect_schema
                .get("properties")
                .and_then(|p| p.get("connection_id"))
                .is_some(),
            "smtp:connect schema must not expose connection_id"
        );

        for id in ["smtp:send", "smtp:disconnect"] {
            let schema = by_type[id].config_schema.as_ref().expect("schema");
            let required = schema.get("required").and_then(serde_json::Value::as_array).expect("required list");
            assert!(
                required.iter().any(|r| r == "connection_id"),
                "{id} requires connection_id"
            );
        }
    }
}

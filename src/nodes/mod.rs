//! SMTP operation nodes, dispatched from `SmtpPlugin::execute` by the
//! `config["type"]` discriminator.
pub mod connect;
pub mod disconnect;
pub mod send;

/// Resolves the `connection_id` an operation node targets, read from its
/// config's `connection_id` field (the host `x-node-selector` fills it with
/// the chosen `smtp:connect` node's instance id). Missing or empty → a
/// readable error telling the user to pick a connect node.
pub(crate) fn resolve_connection_id(config: &serde_json::Value) -> Result<String, String> {
    config
        .get("connection_id")
        .and_then(serde_json::Value::as_str)
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            crate::i18n::t(
                "请选择连接节点（缺少 connection_id，需先添加 smtp:connect 节点并选择）",
                "Please select a connection node (missing connection_id; add and select a smtp:connect node first)",
            )
            .to_string()
        })
}

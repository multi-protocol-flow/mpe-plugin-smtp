//! `smtp:send` node — builds and sends a MIME email through the pooled
//! transport of the selected `smtp:connect` node.
//!
//! Config: `{ "connection_id", "from", "to"[], "cc"?[], "bcc"?[],
//! "subject", "body_type" ("text"|"html"), "body", "html_body"?,
//! "attachments"?[], "timeout_ms" }`. Output mirrors the host
//! `SmtpSendOutput` report shape: `{ success, message_id, response_code,
//! error, request: { connection_id, from, to, cc, bcc, subject, body_type },
//! timing: { total_ms } }`.
//!
//! Message assembly follows the host `SmtpConnectionManager::send` /
//! `build_simple_message` / `build_body_multipart` /
//! `build_attachment_part`: plain-text default, `html` single-part,
//! attachments force `multipart/mixed` with base64-decoded parts.
//!
//! Variable substitution is the host's job (the plugin receives an
//! already-resolved config), so unlike the host executor there are no
//! `replace_variables` calls here.

use std::time::Instant;

use lettre::message::header::ContentType;
use lettre::message::{Attachment, MultiPart, SinglePart};
use lettre::{AsyncTransport, Message};

use crate::nodes::resolve_connection_id;
use crate::pool::SmtpPool;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use mpe_plugin_sdk::prelude::*;

/// Thin `ExecuteContext` adapter: extracts `execution_id` (fallback
/// `"default"`), the resolved config, then delegates to [`send_core`].
/// Logs the failure so the host surfaces it in the report.
pub async fn execute(ctx: &mut ExecuteContext, pool: &SmtpPool) -> ExecuteResult {
    let exec_id = ctx.execution_id().unwrap_or("default").to_string();
    let config = ctx.config().clone();
    match send_core(pool, &exec_id, &config).await {
        Ok(result) => result,
        Err(msg) => {
            ctx.log("error", &msg);
            ExecuteResult::fail(msg)
        }
    }
}

/// Core send logic, testable without an [`ExecuteContext`].
async fn send_core(
    pool: &SmtpPool,
    exec_id: &str,
    config: &serde_json::Value,
) -> Result<ExecuteResult, String> {
    let start = Instant::now();

    let connection_id = resolve_connection_id(config)?;
    let connection = pool.connection(exec_id, &connection_id).ok_or_else(|| {
        crate::i18n::t(
            "请先添加 smtp:connect 节点并选择连接",
            "Add and select a smtp:connect node first",
        )
        .to_string()
    })?;
    let transport = connection.transport.clone();

    let from = config
        .get("from")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_string();
    let to = parse_string_list(config.get("to"));
    let cc = parse_string_list(config.get("cc"));
    let bcc = parse_string_list(config.get("bcc"));
    let subject = config
        .get("subject")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_string();
    let body = config
        .get("body")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_string();
    let html_body = config
        .get("html_body")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_string();
    let body_type = config
        .get("body_type")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("text")
        .to_string();
    let attachments = parse_json_array(config.get("attachments"));

    // Basic validation (host executor semantics).
    if from.is_empty() {
        return Err(crate::i18n::t("发件人地址必填", "Sender address is required").to_string());
    }
    if to.is_empty() {
        return Err(crate::i18n::t(
            "收件人列表不能为空",
            "Recipient list cannot be empty",
        )
        .to_string());
    }

    // Build the MIME message.
    let from_addr = from
        .parse::<lettre::Address>()
        .map_err(|e| format!("{} '{}': {e}", crate::i18n::t("发件人地址格式Error", "Invalid sender address"), from))?;
    let mut builder = Message::builder()
        .from(from_addr.into())
        .subject(subject.clone());
    for addr in &to {
        let parsed: lettre::Address = addr
            .parse()
            .map_err(|e| format!("{} '{}': {e}", crate::i18n::t("收件人地址格式Error", "Invalid recipient address"), addr))?;
        builder = builder.to(parsed.into());
    }
    for addr in &cc {
        let parsed: lettre::Address = addr
            .parse()
            .map_err(|e| format!("{} '{}': {e}", crate::i18n::t("抄送地址格式Error", "Invalid CC address"), addr))?;
        builder = builder.cc(parsed.into());
    }
    for addr in &bcc {
        let parsed: lettre::Address = addr
            .parse()
            .map_err(|e| format!("{} '{}': {e}", crate::i18n::t("密送地址格式Error", "Invalid BCC address"), addr))?;
        builder = builder.bcc(parsed.into());
    }

    let message = if attachments.is_empty() {
        build_simple_message(builder, &body_type, &body, &html_body)?
    } else {
        let body_part = build_body_multipart(&body_type, &body, &html_body)?;
        let mut mixed = MultiPart::mixed().multipart(body_part);
        for attachment in &attachments {
            mixed = mixed.singlepart(build_attachment_part(attachment)?);
        }
        builder
            .multipart(mixed)
            .map_err(|e| format!("{}: {e}", crate::i18n::t("构建邮件Failed", "Failed to build message")))?
    };

    // Send through the pooled transport.
    match transport.send(message).await {
        Ok(response) => {
            let code_str = response.code().to_string();
            let code: u16 = code_str.parse().unwrap_or(0);
            let message_id = response.first_line().map(str::to_string);
            let total_ms = start.elapsed().as_millis() as u64;
            Ok(crate::ok_result(serde_json::json!({
                "success": true,
                "message_id": message_id,
                "response_code": code,
                "error": serde_json::Value::Null,
                "request": {
                    "connection_id": connection_id,
                    "from": from,
                    "to": to,
                    "cc": cc,
                    "bcc": bcc,
                    "subject": subject,
                    "body_type": body_type,
                },
                "timing": { "total_ms": total_ms },
            })))
        }
        Err(e) => Err(format!("{}: {e}", crate::i18n::t("发送Failed", "Send failed"))),
    }
}

/// Builds a message without attachments (host `build_simple_message`):
/// `html` → single HTML part, anything else → plain text.
fn build_simple_message(
    builder: lettre::message::MessageBuilder,
    body_type: &str,
    body: &str,
    html_body: &str,
) -> Result<Message, String> {
    match body_type {
        "html" => builder
            .singlepart(
                SinglePart::builder()
                    .header(ContentType::TEXT_HTML)
                    .body(html_body.to_string()),
            )
            .map_err(|e| format!("{}: {e}", crate::i18n::t("构建 HTML 邮件Failed", "Failed to build HTML message"))),
        _ => builder
            .singlepart(
                SinglePart::builder()
                    .header(ContentType::TEXT_PLAIN)
                    .body(body.to_string()),
            )
            .map_err(|e| format!("{}: {e}", crate::i18n::t("构建纯文本邮件Failed", "Failed to build plain-text message"))),
    }
}

/// Builds the body `MultiPart` for attachment-bearing messages (host
/// `build_body_multipart`).
fn build_body_multipart(
    body_type: &str,
    body: &str,
    html_body: &str,
) -> Result<MultiPart, String> {
    match body_type {
        "html" => Ok(MultiPart::alternative().singlepart(
            SinglePart::builder()
                .header(ContentType::TEXT_HTML)
                .body(html_body.to_string()),
        )),
        _ => Ok(MultiPart::alternative().singlepart(
            SinglePart::builder()
                .header(ContentType::TEXT_PLAIN)
                .body(body.to_string()),
        )),
    }
}

/// Builds one attachment `SinglePart` from `{ filename, content_base64,
/// content_type }` (host `build_attachment_part`).
fn build_attachment_part(attachment: &serde_json::Value) -> Result<SinglePart, String> {
    let filename = attachment
        .get("filename")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("attachment")
        .to_string();
    let content_base64 = attachment
        .get("content_base64")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let content_type_str = attachment
        .get("content_type")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("application/octet-stream");

    let content = BASE64.decode(content_base64).map_err(|e| {
        format!("{} '{}': {e}", crate::i18n::t("解码附件 base64 Failed", "Failed to decode attachment base64"), filename)
    })?;
    let content_type: ContentType = content_type_str
        .parse()
        .map_err(|e| format!("{} '{}': {e}", crate::i18n::t("解析附件 Content-Type Failed", "Failed to parse attachment Content-Type"), filename))?;

    Ok(Attachment::new(filename).body(content, content_type))
}

/// Parses string list from either a JSON array or a JSON-encoded string / comma-separated string.
/// Supports GUI `SchemaConfigPanel` (`format: "json"`) inputs.
pub(crate) fn parse_string_list(val: Option<&serde_json::Value>) -> Vec<String> {
    match val {
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect(),
        Some(serde_json::Value::String(s)) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return Vec::new();
            }
            if let Ok(serde_json::Value::Array(arr)) = serde_json::from_str::<serde_json::Value>(trimmed) {
                return arr
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect();
            }
            trimmed
                .split([',', ';'])
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_string)
                .collect()
        }
        _ => Vec::new(),
    }
}

/// Parses JSON array from either a JSON array or a JSON-encoded string.
pub(crate) fn parse_json_array(val: Option<&serde_json::Value>) -> Vec<serde_json::Value> {
    match val {
        Some(serde_json::Value::Array(arr)) => arr.clone(),
        Some(serde_json::Value::String(s)) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return Vec::new();
            }
            if let Ok(serde_json::Value::Array(arr)) = serde_json::from_str::<serde_json::Value>(trimmed) {
                return arr;
            }
            Vec::new()
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_simple_plain_message() {
        let builder = Message::builder()
            .from("sender@example.com".parse::<lettre::Address>().expect("from").into())
            .subject("Test")
            .to("recipient@example.com".parse::<lettre::Address>().expect("to").into());
        let msg = build_simple_message(builder, "text", "Hello", "")
            .expect("plain message builds");
        // Serialize and check the plain-text body survives.
        let raw = msg.formatted();
        let text = String::from_utf8_lossy(&raw);
        assert!(text.contains("Hello"));
    }

    #[test]
    fn build_simple_html_message() {
        let builder = Message::builder()
            .from("sender@example.com".parse::<lettre::Address>().expect("from").into())
            .subject("Test")
            .to("recipient@example.com".parse::<lettre::Address>().expect("to").into());
        let msg = build_simple_message(builder, "html", "", "<p>Hi</p>")
            .expect("html message builds");
        let raw = msg.formatted();
        let text = String::from_utf8_lossy(&raw);
        assert!(text.contains("<p>Hi</p>"));
        assert!(text.contains("text/html"));
    }

    #[test]
    fn build_body_multipart_html() {
        let mp = build_body_multipart("html", "", "<p>Hi</p>").expect("html body");
        let builder = Message::builder()
            .from("sender@example.com".parse::<lettre::Address>().expect("from").into())
            .subject("Test")
            .to("recipient@example.com".parse::<lettre::Address>().expect("to").into());
        let msg = builder.multipart(mp).expect("multipart message");
        let raw = msg.formatted();
        assert!(String::from_utf8_lossy(&raw).contains("<p>Hi</p>"));
    }

    #[test]
    fn build_attachment_part_valid() {
        let attachment = serde_json::json!({
            "filename": "test.txt",
            "content_base64": BASE64.encode(b"Hello, world!"),
            "content_type": "text/plain"
        });
        let part = build_attachment_part(&attachment).expect("valid attachment");
        let raw = part.formatted();
        assert!(String::from_utf8_lossy(&raw).contains("Hello, world!"));
    }

    #[test]
    fn build_attachment_part_invalid_base64() {
        let attachment = serde_json::json!({
            "filename": "test.txt",
            "content_base64": "!!!invalid!!!",
            "content_type": "text/plain"
        });
        let err = build_attachment_part(&attachment).expect_err("invalid base64 fails");
        assert!(err.contains("base64"), "names the failure: {err}");
    }

    #[test]
    fn build_attachment_part_defaults() {
        let attachment = serde_json::json!({ "content_base64": BASE64.encode(b"test") });
        assert!(build_attachment_part(&attachment).is_ok());
    }

    #[test]
    fn build_attachment_part_invalid_content_type() {
        let attachment = serde_json::json!({
            "filename": "t.txt",
            "content_base64": BASE64.encode(b"x"),
            "content_type": "invalid content type !!!"
        });
        assert!(build_attachment_part(&attachment).is_err());
    }

    #[test]
    fn parse_string_list_supports_array_and_json_string() {
        // JSON array
        let arr = serde_json::json!(["a@example.com", "b@example.com"]);
        assert_eq!(
            parse_string_list(Some(&arr)),
            vec!["a@example.com", "b@example.com"]
        );

        // JSON stringified array
        let json_str = serde_json::json!(r#"["sunanzhi@eolink.com"]"#);
        assert_eq!(
            parse_string_list(Some(&json_str)),
            vec!["sunanzhi@eolink.com"]
        );

        // Plain string / comma separated
        let plain_str = serde_json::json!("user1@example.com, user2@example.com; user3@example.com");
        assert_eq!(
            parse_string_list(Some(&plain_str)),
            vec!["user1@example.com", "user2@example.com", "user3@example.com"]
        );

        // Empty cases
        let empty_str = serde_json::json!("");
        assert!(parse_string_list(Some(&empty_str)).is_empty());
        let empty_json = serde_json::json!("[]");
        assert!(parse_string_list(Some(&empty_json)).is_empty());
        assert!(parse_string_list(None).is_empty());
    }
}

//! Live SMTP integration tests — ignored by default (require an SMTP
//! server), run with `cargo test -- --ignored`.
//!
//! Server override: `MPE_SMTP_URI` (default `smtp://localhost:587`,
//! STARTTLS). For a quick local server, the repo's `echo/` stack provides an
//! SMTP test service; otherwise point the variable at any reachable SMTP
//! endpoint. Every test spawns a FRESH plugin process, so pools never leak
//! between cases.
//!
//! Run recipe:
//! ```bash
//! cd plugins/smtp
//! cargo build --release
//! cargo test --release -- --ignored --test-threads=1
//! ```

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{json, Value};

/// Path to the compiled plugin binary (set by cargo for `[[bin]]` targets).
const PLUGIN_BIN: &str = env!("CARGO_BIN_EXE_mpe_plugin_smtp");

/// Effective SMTP server from `MPE_SMTP_URI` or the default.
fn smtp_uri() -> String {
    std::env::var("MPE_SMTP_URI").unwrap_or_else(|_| "smtp://localhost:587".to_string())
}

/// Host/port split of `smtp://host:port` for the connect config.
fn host_port(uri: &str) -> (String, u16) {
    let rest = uri
        .strip_prefix("smtp://")
        .expect("MPE_SMTP_URI must be smtp://host:port");
    match rest.rsplit_once(':') {
        Some((host, port)) => (host.to_string(), port.parse().expect("valid port")),
        None => (rest.to_string(), 587),
    }
}

/// A spawned plugin process with piped stdio (same harness as roundtrip.rs).
struct PluginProcess {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl PluginProcess {
    fn spawn() -> Result<Self, Box<dyn std::error::Error>> {
        let mut child = Command::new(PLUGIN_BIN)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "plugin stdin not available".to_string())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "plugin stdout not available".to_string())?;
        Ok(Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
        })
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = 1u64;
        let frame = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }))
        .expect("request serializes");
        writeln!(self.stdin, "{frame}").expect("request writes");
        self.stdin.flush().expect("request flushes");

        let mut line = String::new();
        loop {
            line.clear();
            let n = self.stdout.read_line(&mut line).expect("reads a frame");
            assert!(n > 0, "plugin closed stdout while awaiting response");
            let frame: Value =
                serde_json::from_str(&line).expect("frame is valid JSON-RPC JSON");
            if frame.get("id").is_some() {
                return frame;
            }
        }
    }
}

/// connect → send → disconnect roundtrip against the live server.
#[tokio::test]
#[ignore = "requires SMTP server"]
async fn connect_send_disconnect_roundtrip() {
    let uri = smtp_uri();
    let (host, port) = host_port(&uri);
    let mut process = PluginProcess::spawn().expect("plugin spawns");

    // connect
    let response = process.request(
        "execute",
        json!({
            "config": {
                "type": "smtp:connect",
                "host": host,
                "port": port,
                "tls_mode": "starttls",
            },
            "execution_id": "exec-roundtrip",
            "node_instance_id": "conn-1",
        }),
    );
    let result = &response["result"];
    assert_eq!(result["success"], true, "connect succeeds: {result}");
    assert_eq!(result["output"]["connection_id"], "conn-1");

    // send
    let response = process.request(
        "execute",
        json!({
            "config": {
                "type": "smtp:send",
                "connection_id": "conn-1",
                "from": "sender@example.com",
                "to": ["recipient@example.com"],
                "subject": "MPE plugin integration test",
                "body": "Hello from the SMTP plugin",
                "body_type": "text",
            },
            "execution_id": "exec-roundtrip",
        }),
    );
    let result = &response["result"];
    assert_eq!(result["success"], true, "send succeeds: {result}");

    // disconnect
    let response = process.request(
        "execute",
        json!({
            "config": {
                "type": "smtp:disconnect",
                "connection_id": "conn-1",
            },
            "execution_id": "exec-roundtrip",
        }),
    );
    let result = &response["result"];
    assert_eq!(result["success"], true, "disconnect succeeds: {result}");
    assert_eq!(result["output"]["success"], true);
}

/// A second connect with the same target reuses the pooled connection
/// (idempotent) — the output still reports the same connection_id.
#[tokio::test]
#[ignore = "requires SMTP server"]
async fn connect_is_idempotent() {
    let uri = smtp_uri();
    let (host, port) = host_port(&uri);
    let mut process = PluginProcess::spawn().expect("plugin spawns");

    let params = json!({
        "config": { "type": "smtp:connect", "host": host, "port": port, "tls_mode": "starttls" },
        "execution_id": "exec-idem",
        "node_instance_id": "conn-1",
    });
    let first = process.request("execute", params.clone());
    assert_eq!(first["result"]["success"], true, "first connect: {first}");

    let second = process.request("execute", params);
    assert_eq!(second["result"]["success"], true, "second connect: {second}");
    assert_eq!(
        second["result"]["output"]["connection_id"], "conn-1",
        "same connection id reused"
    );
}

/// Connecting to an unreachable host fails at the connect node with the
/// plugin's own connection error (no server on port 1).
#[tokio::test]
#[ignore = "requires SMTP server (unreachable host probe is firewalled-free)"]
async fn connect_to_unreachable_host_fails() {
    let mut process = PluginProcess::spawn().expect("plugin spawns");
    let response = process.request(
        "execute",
        json!({
            "config": {
                "type": "smtp:connect",
                "host": "127.0.0.1",
                "port": 1,
                "tls_mode": "none",
            },
            "execution_id": "exec-unreachable",
            "node_instance_id": "conn-1",
        }),
    );
    let result = &response["result"];
    assert_eq!(result["success"], false, "unreachable connect fails: {result}");
    let error = result["errors"][0]["message"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        !error.is_empty() && !error.contains("Unknown node type"),
        "failure is the plugin's own connection error: {error}"
    );
}

/// Executions are isolated: the same connection_id under different
/// execution_ids must not share a transport — connect under exec A, then
/// send under exec B with the same connection_id fails at the pool lookup.
#[tokio::test]
#[ignore = "requires SMTP server"]
async fn execution_id_isolation() {
    let uri = smtp_uri();
    let (host, port) = host_port(&uri);
    let mut process = PluginProcess::spawn().expect("plugin spawns");

    let connect = process.request(
        "execute",
        json!({
            "config": { "type": "smtp:connect", "host": host, "port": port, "tls_mode": "starttls" },
            "execution_id": "exec-a",
            "node_instance_id": "conn-shared",
        }),
    );
    assert_eq!(connect["result"]["success"], true, "connect under exec-a: {connect}");

    let send = process.request(
        "execute",
        json!({
            "config": {
                "type": "smtp:send",
                "connection_id": "conn-shared",
                "from": "sender@example.com",
                "to": ["recipient@example.com"],
                "subject": "isolation",
                "body": "x",
                "body_type": "text",
            },
            "execution_id": "exec-b",
        }),
    );
    assert_eq!(
        send["result"]["success"], false,
        "send under a different execution must not see exec-a's connection: {send}"
    );
}

//! Offline stdio JSON-RPC roundtrip tests against the compiled
//! `mpe_smtp_plugin` binary — the exact transport shape the host uses:
//! JSON-RPC 2.0 requests on stdin, LF-framed responses on stdout.
//!
//! Fully offline: no SMTP server, no network. Every `execute` case
//! short-circuits before any socket I/O — send-without-connect fails at the
//! pool lookup, unknown/missing type fails at the dispatch match, and
//! disconnect on an empty pool is an idempotent no-op routed to `out`.
//!
//! Wire notes mirrored from `mpe-plugin-sdk/tests/roundtrip.rs`:
//! - The runtime spawns one task per `execute` and correlates responses by
//!   request `id`; responses may interleave with other traffic.
//! - Failing node executions emit an id-less `log` notification frame on
//!   stdout *before* their response. Readers must skip id-less frames and
//!   collect only frames carrying an `id`.
//! - Notifications (no `id`) never produce a response.
//! - A clean EOF on stdin (dropped write end) exits the loop with code 0.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};

use serde_json::Value;

/// Path to the compiled plugin binary (set by cargo for `[[bin]]` targets).
const PLUGIN_BIN: &str = env!("CARGO_BIN_EXE_mpe_plugin_smtp");

/// The 3 node type_ids the plugin must describe (byte-sorted — the test
/// compares against a sorted copy).
const EXPECTED_TYPE_IDS: [&str; 3] = ["smtp:connect", "smtp:disconnect", "smtp:send"];

/// A spawned plugin process with piped stdio.
struct PluginProcess {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl PluginProcess {
    /// Spawns the plugin binary with piped stdio (stderr piped and ignored —
    /// malformed-frame diagnostics land there, never on stdout).
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

    /// Sends one request and reads frames until the matching response id
    /// arrives (skipping id-less notification frames). Panics on EOF.
    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = 1u64;
        let frame = serde_json::to_string(&serde_json::json!({
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
            // id-less frame: a log notification — skip.
        }
    }

    /// Closes stdin and waits for a clean exit (code 0).
    fn shutdown(mut self) -> ExitStatus {
        drop(self.stdin);
        self.child.wait().expect("plugin exits")
    }
}

/// `describe` returns exactly the 3 expected node types with the expected
/// capabilities (connect declares single_node).
#[test]
fn describe_lists_all_nodes() {
    let mut process = PluginProcess::spawn().expect("plugin spawns");
    let response = process.request("describe", serde_json::json!({}));
    assert_eq!(response["id"], 1);
    let nodes = response["result"].as_array().expect("nodes array");
    let mut ids: Vec<&str> = nodes.iter().map(|n| n["type_id"].as_str().unwrap()).collect();
    ids.sort_unstable();
    assert_eq!(ids, EXPECTED_TYPE_IDS, "all 3 smtp nodes are described");

    // `smtp:connect` declares single_node so the host's capability gate
    // admits it on the single-node path.
    let connect = nodes
        .iter()
        .find(|n| n["type_id"] == "smtp:connect")
        .expect("connect node present");
    assert_eq!(
        connect["capabilities"]["single_node"],
        true,
        "smtp:connect declares single_node capability"
    );

    // `smtp:disconnect` must be in/out (single output port); connect/send
    // are tri-port.
    let disconnect = nodes
        .iter()
        .find(|n| n["type_id"] == "smtp:disconnect")
        .expect("disconnect node present");
    let port_ids: Vec<&str> = disconnect["ports"]
        .as_array()
        .expect("ports array")
        .iter()
        .map(|p| p["id"].as_str().unwrap())
        .collect();
    assert_eq!(port_ids, vec!["in", "out"], "smtp:disconnect is in/out");
}

/// `smtp:send` without a preceding connect fails at the pool lookup — no
/// server needed, proves the pool gate runs before any socket I/O.
#[test]
fn send_without_connect_fails_offline() {
    let mut process = PluginProcess::spawn().expect("plugin spawns");
    let response = process.request(
        "execute",
        serde_json::json!({
            "config": {
                "type": "smtp:send",
                "connection_id": "nonexistent",
                "from": "sender@example.com",
                "to": ["recipient@example.com"],
                "subject": "Test",
                "body": "Hello",
                "body_type": "text"
            }
        }),
    );
    assert!(
        response["result"]["success"] == false,
        "send without connect must fail, got: {}",
        response
    );
    let error = response["result"]["errors"][0]
        .get("message")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    assert!(
        !error.is_empty(),
        "failure carries an error message"
    );
}

/// Unknown node type fails at the dispatch match with a readable error.
#[test]
fn unknown_node_type_fails() {
    let mut process = PluginProcess::spawn().expect("plugin spawns");
    let response = process.request(
        "execute",
        serde_json::json!({
            "config": { "type": "smtp:wat" }
        }),
    );
    let error = response["result"]["errors"][0]
        .get("message")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    assert!(
        error.contains("smtp:wat"),
        "unknown type is named in the error, got: {error}"
    );
}

/// `smtp:disconnect` on an empty pool is an idempotent success — release is
/// a no-op on a missing entry (offline-safe), still routed to `out`.
#[test]
fn disconnect_without_connect_is_idempotent() {
    let mut process = PluginProcess::spawn().expect("plugin spawns");
    let response = process.request(
        "execute",
        serde_json::json!({
            "config": { "type": "smtp:disconnect", "connection_id": "nonexistent" }
        }),
    );
    let result = &response["result"];
    assert!(
        result["success"] == true,
        "disconnect on empty pool succeeds (non-blocking): {result}"
    );
    assert!(
        result["next_ports"].as_array().is_some_and(|p| p.iter().any(|p| p == "out")),
        "disconnect routes to out: {result}"
    );
}

/// Clean shutdown: EOF on stdin exits with code 0.
#[test]
fn clean_shutdown_on_eof() {
    let process = PluginProcess::spawn().expect("plugin spawns");
    let status = process.shutdown();
    assert!(status.success(), "clean EOF exits 0");
}

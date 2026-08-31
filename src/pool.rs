//! Per-execution SMTP connection pool.
//!
//! Keys ready-to-use [`SmtpConnection`]s by the composite
//! `(execution_id, connection_uuid)` pair so that:
//!
//! - concurrent flow executions never share one SMTP transport (commands
//!   from unrelated executions would interleave on the same socket), and
//! - multiple `smtp:connect` nodes can coexist inside ONE execution —
//!   operation nodes pick their connection via the `connection_id` the host
//!   resolves into their config (the connect node's own instance id).
//!
//! The SDK's [`ConnectionPool`] stores values under opaque `String` keys and
//! exposes no key enumeration, so this crate keeps a small side registry
//! (`execution_id → set of connection_uuids`) to support releasing every
//! connection of one execution by prefix ([`SmtpPool::release`]).
//!
//! Design notes:
//! - The pool is generic over its payload (`C`). Production stores
//!   [`SmtpConnection`] (a ready lettre transport plus its target keys);
//!   unit tests store a dummy payload to exercise the keying logic without
//!   an SMTP server — a lettre transport cannot be built offline.
//! - The SDK's [`ConnectionPool::get_or_insert`] factory is a SYNC `FnOnce`,
//!   but building an SMTP transport is cheap and eager-connect only happens
//!   in `test_connection`. So manager creation happens in the `smtp:connect`
//!   node; the pool only receives a READY transport and stores it under the
//!   composite key.

use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

use lettre::{AsyncSmtpTransport, Tokio1Executor};

/// A ready-to-use SMTP transport bound to one flow execution.
///
/// `host`/`port` are stored alongside the transport so
/// [`SmtpPool::connect`] can tell when a later connect node targets a
/// different server and replace the entry instead of silently reusing a
/// stale connection.
pub struct SmtpConnection {
    /// Connected transport; send nodes clone it and run `send` through it.
    pub transport: AsyncSmtpTransport<Tokio1Executor>,
    /// Server address this connection was created for (idempotency key).
    pub host: String,
    /// Server port this connection was created for (idempotency key).
    pub port: u16,
}

/// Execution + connection-keyed pool of payloads, shared across executions
/// in this plugin process (the plugin is resident:
/// `capabilities.streaming: true`, so the pool lives for the process
/// lifetime).
///
/// Concurrency: the underlying [`ConnectionPool`] may run an insert factory
/// more than once under contention; that is benign here because `connect`
/// only inserts after checking the existing entry. The side registry uses a
/// plain [`Mutex`] and is only ever touched with short critical sections.
pub struct SmtpPool<C: Any + Send + Sync = SmtpConnection> {
    inner: mpe_plugin_sdk::pool::ConnectionPool,
    /// `execution_id → set of registered connection_uuids`, so
    /// [`SmtpPool::release`] can drop every connection of one execution even
    /// though the SDK pool exposes no key enumeration.
    connections: Mutex<HashMap<String, HashSet<String>>>,
    /// Keeps the payload type in the struct signature for typed accessors.
    _marker: PhantomData<fn() -> C>,
}

impl<C: Any + Send + Sync> Default for SmtpPool<C> {
    fn default() -> Self {
        Self {
            inner: mpe_plugin_sdk::pool::ConnectionPool::default(),
            connections: Mutex::new(HashMap::new()),
            _marker: PhantomData,
        }
    }
}

impl<C: Any + Send + Sync> SmtpPool<C> {
    /// Registers the ready `payload` for `(execution_id, connection_uuid)`.
    ///
    /// `key_match` decides whether an existing entry under the same
    /// `(execution_id, connection_uuid)` is the SAME target (reuse, no
    /// replacement) or a DIFFERENT one (drop stale + replace).
    ///
    /// Returns `(payload, replaced)` where `replaced` is `true` only when an
    /// entry with a DIFFERENT target existed and was replaced — the caller
    /// (connect node) can surface a warning via `ctx.log`. A fresh insertion
    /// reports `false`.
    pub fn connect(
        &self,
        execution_id: &str,
        connection_uuid: &str,
        payload: C,
        key_match: impl Fn(&C, &C) -> bool,
    ) -> (Arc<C>, bool) {
        let replaced = match self.connection(execution_id, connection_uuid) {
            Some(existing) if key_match(&existing, &payload) => {
                // Same target: reuse, do not touch the stored payload.
                return (existing, false);
            }
            Some(_) => {
                // Different target: drop the stale connection first so the
                // new one is the only entry under this key.
                self.inner.remove(&pool_key(execution_id, connection_uuid));
                true
            }
            None => false,
        };
        let created =
            self.inner
                .get_or_insert(pool_key(execution_id, connection_uuid), || payload);
        self.connections
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(execution_id.to_string())
            .or_default()
            .insert(connection_uuid.to_string());
        (created, replaced)
    }

    /// Returns the payload for `(execution_id, connection_uuid)`, or `None`
    /// when that connection has not been established (or already released).
    pub fn connection(&self, execution_id: &str, connection_uuid: &str) -> Option<Arc<C>> {
        self.inner
            .get::<C>(&pool_key(execution_id, connection_uuid))
    }

    /// Drops EVERY connection registered under `execution_id` (close node
    /// without a specific selection / `flow_ended` callback). A no-op when
    /// the execution has no entries.
    pub fn release(&self, execution_id: &str) {
        let uuids: Vec<String> = self
            .connections
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(execution_id)
            .map(|set| set.into_iter().collect())
            .unwrap_or_default();
        for uuid in uuids {
            self.inner.remove(&pool_key(execution_id, &uuid));
        }
    }

    /// Drops ONE connection of `execution_id` (disconnect node with a
    /// specific `connection_id` selection). Returns whether an entry was
    /// actually removed; a no-op (`false`) when the entry is missing.
    pub fn release_connection(&self, execution_id: &str, connection_uuid: &str) -> bool {
        let removed = self
            .inner
            .remove(&pool_key(execution_id, connection_uuid));
        if removed {
            self.connections
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .entry(execution_id.to_string())
                .or_default()
                .remove(connection_uuid);
        }
        removed
    }
}

/// Composite pool key: `execution_id` and `connection_uuid` are opaque host
/// strings, `:` is a safe separator because neither contains it (the host
/// generates both as plain uuids/ids).
fn pool_key(execution_id: &str, connection_uuid: &str) -> String {
    format!("{execution_id}:{connection_uuid}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cheap, server-free payload for keying tests (no SMTP needed).
    #[derive(Debug, Clone, PartialEq)]
    struct Dummy {
        host: String,
        port: u16,
    }

    fn same_target(a: &Dummy, b: &Dummy) -> bool {
        a == b
    }

    /// Same-target connect is idempotent: a second connect with identical
    /// target reuses the stored entry (replaced = false, same Arc).
    #[test]
    fn same_target_connect_reuses_entry() {
        let pool = SmtpPool::<Dummy>::default();
        let (first, replaced1) = pool.connect(
            "exec1",
            "conn-a",
            Dummy { host: "smtp.example.com".into(), port: 587 },
            same_target,
        );
        assert!(!replaced1, "first insert is not a replacement");

        let (second, replaced2) = pool.connect(
            "exec1",
            "conn-a",
            Dummy { host: "smtp.example.com".into(), port: 587 },
            same_target,
        );
        assert!(!replaced2, "same target reuses, never replaces");
        assert!(Arc::ptr_eq(&first, &second), "same Arc is reused");
    }

    /// Different target replaces the stale entry and reports it.
    #[test]
    fn different_target_replaces_entry() {
        let pool = SmtpPool::<Dummy>::default();
        pool.connect(
            "exec1",
            "conn-a",
            Dummy { host: "smtp.example.com".into(), port: 587 },
            same_target,
        );

        let (_conn, replaced) = pool.connect(
            "exec1",
            "conn-a",
            Dummy { host: "smtp.example.com".into(), port: 465 },
            same_target,
        );
        assert!(replaced, "different port is a replacement");

        let stored = pool.connection("exec1", "conn-a").expect("entry exists");
        assert_eq!(stored.port, 465, "stale entry was dropped");
    }

    /// Executions are isolated: the same connection_uuid under different
    /// execution_ids yields distinct entries.
    #[test]
    fn executions_are_isolated() {
        let pool = SmtpPool::<Dummy>::default();
        pool.connect(
            "exec1",
            "conn-a",
            Dummy { host: "smtp.example.com".into(), port: 587 },
            same_target,
        );
        pool.connect(
            "exec2",
            "conn-a",
            Dummy { host: "smtp.example.com".into(), port: 587 },
            same_target,
        );

        assert!(pool.connection("exec1", "conn-a").is_some());
        assert!(pool.connection("exec2", "conn-a").is_some());
    }

    /// `release` drops every connection of one execution; other executions
    /// are untouched.
    #[test]
    fn release_drops_only_one_execution() {
        let pool = SmtpPool::<Dummy>::default();
        pool.connect(
            "exec1",
            "conn-a",
            Dummy { host: "smtp.example.com".into(), port: 587 },
            same_target,
        );
        pool.connect(
            "exec1",
            "conn-b",
            Dummy { host: "smtp.example.com".into(), port: 465 },
            same_target,
        );
        pool.connect(
            "exec2",
            "conn-a",
            Dummy { host: "smtp.example.com".into(), port: 587 },
            same_target,
        );

        pool.release("exec1");

        assert!(pool.connection("exec1", "conn-a").is_none());
        assert!(pool.connection("exec1", "conn-b").is_none());
        assert!(pool.connection("exec2", "conn-a").is_some());
    }

    /// `release_connection` drops only the selected connection; release on a
    /// missing entry is a silent no-op.
    #[test]
    fn release_connection_selects_one() {
        let pool = SmtpPool::<Dummy>::default();
        pool.connect(
            "exec1",
            "conn-a",
            Dummy { host: "smtp.example.com".into(), port: 587 },
            same_target,
        );
        pool.connect(
            "exec1",
            "conn-b",
            Dummy { host: "smtp.example.com".into(), port: 465 },
            same_target,
        );

        assert!(pool.release_connection("exec1", "conn-a"));
        assert!(pool.connection("exec1", "conn-a").is_none());
        assert!(pool.connection("exec1", "conn-b").is_some());

        assert!(
            !pool.release_connection("exec1", "conn-a"),
            "second release of a missing entry reports false"
        );
    }
}

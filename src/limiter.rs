//! Bounds how many connections `main::accept_loop` will ever hand off to
//! `route::Router` at once, across both routes combined — the same role
//! nginx's `worker_connections` plays. Built on a `tokio::sync::Semaphore`
//! with one permit per `max_connections`: `acquire_slot` hands out an
//! RAII-style `ConnectionSlot` that keeps `Stats::connections` (the
//! "connections currently occupying a slot" counter, used both for the
//! `reprox_connections_available` metric and for `main`'s graceful-
//! shutdown drain) in sync with the semaphore automatically, no matter
//! how the connection's task ends.

use crate::metrics::Stats;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// RAII handle for one reserved connection slot. Holding one means one
/// permit is checked out of `ConnectionLimiter`'s semaphore and
/// `Stats::connections` has been incremented to account for it; dropping
/// it (for any reason — normal completion, early return, or a panic in
/// the connection task) releases the permit back to the pool and
/// decrements the counter again, so the two can never drift apart.
pub struct ConnectionSlot {
    _permit: OwnedSemaphorePermit,
    stats: Arc<Stats>,
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.stats.connections.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Bounds how many connections are ever in flight at once, across
/// both routes combined — the same role nginx's `worker_connections`
/// plays.
pub struct ConnectionLimiter {
    connection_slots: Arc<Semaphore>,
    stats: Arc<Stats>,
}

impl ConnectionLimiter {
    pub fn new(permits: usize, stats: Arc<Stats>) -> Self {
        Self {
            connection_slots: Arc::new(Semaphore::new(permits)),
            stats,
        }
    }

    /// Waits for a free connection slot (bounded by the configured
    /// `max_connections`) and returns a permit that releases it back to
    /// the pool when dropped — i.e. whenever the connection it was
    /// reserved for finishes being served, for any reason, including an
    /// early return or a panic in the connection task. `main::accept_loop`
    /// holds this permit for the entire lifetime of a connection, and
    /// acquires it *before* calling `accept()`, so that under a
    /// connection flood the process stops pulling new sockets off the
    /// kernel accept queue instead of accepting an unbounded number of
    /// them and running out of file descriptors or memory.
    pub async fn acquire_slot(&self) -> ConnectionSlot {
        let permit = self
            .connection_slots
            .clone()
            .acquire_owned()
            .await
            .expect("the connection-slot semaphore is never closed");

        let stats = self.stats.clone();

        stats.connections.fetch_add(1, Ordering::Relaxed);

        ConnectionSlot {
            _permit: permit,
            stats,
        }
    }
}

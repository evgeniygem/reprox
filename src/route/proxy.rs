//! Transparent TCP proxying to the local service instance.
//!
//! There is nothing TLS-specific here, and there shouldn't be: service
//! implements the handshake itself and is responsible for TLS
//! record sizing — we only forward bytes in both directions, starting
//! with the prefix already read during SNI sniffing (otherwise service
//! would see a ClientHello missing its first few bytes and couldn't
//! carry out its own handshake). Byte counters and connect-failure
//! counts are recorded into `Stats` along the way; connection count,
//! active-connection gauge, and duration are handled by the
//! `ActiveGuard` the caller holds for the lifetime of the connection.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::Context;
use bytes::Bytes;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::metrics::Stats;

pub async fn proxy(
    mut client: TcpStream,
    prefix: Bytes,
    endpoint: &str,
    stats: Arc<Stats>,
) -> anyhow::Result<()> {
    let mut upstream = match TcpStream::connect(endpoint).await {
        Ok(s) => s,
        Err(e) => {
            stats
                .proxy_service_connect_failures_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(e).with_context(|| format!("failed to connect to service at {endpoint}"));
        }
    };
    let _ = upstream.set_nodelay(true);

    if !prefix.is_empty() {
        upstream
            .write_all(&prefix)
            .await
            .context("failed to forward the buffered ClientHello to service")?;
        stats
            .proxy_bytes_client_to_service_total
            .fetch_add(prefix.len() as u64, Ordering::Relaxed);
    }

    match tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
        Ok((from_client, from_upstream)) => {
            stats
                .proxy_bytes_client_to_service_total
                .fetch_add(from_client, Ordering::Relaxed);
            stats
                .proxy_bytes_service_to_client_total
                .fetch_add(from_upstream, Ordering::Relaxed);
            tracing::debug!(from_client, from_upstream, "service session closed");
        }
        Err(e) => {
            // One side dropping the connection is normal for long-lived
            // proxied sessions, not an application error.
            tracing::debug!(error = %e, "service session ended with an I/O error");
        }
    }

    Ok(())
}

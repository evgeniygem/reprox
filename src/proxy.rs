//! Transparent TCP proxying to the local telemt instance.
//!
//! There is nothing TLS-specific here, and there shouldn't be: telemt
//! implements the FakeTLS handshake itself and is responsible for TLS
//! record sizing — we only forward bytes in both directions, starting
//! with the prefix already read during SNI sniffing (otherwise telemt
//! would see a ClientHello missing its first few bytes and couldn't
//! carry out its own handshake).

use anyhow::Context;
use bytes::Bytes;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

pub async fn route(mut client: TcpStream, prefix: Bytes, telemt_addr: &str) -> anyhow::Result<()> {
    let mut upstream = TcpStream::connect(telemt_addr)
        .await
        .with_context(|| format!("failed to connect to telemt at {telemt_addr}"))?;
    let _ = upstream.set_nodelay(true);

    if !prefix.is_empty() {
        upstream
            .write_all(&prefix)
            .await
            .context("failed to forward the buffered ClientHello to telemt")?;
    }

    match tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
        Ok((from_client, from_upstream)) => {
            tracing::debug!(from_client, from_upstream, "telemt session closed");
        }
        Err(e) => {
            // One side dropping the connection is normal for long-lived
            // MTProto sessions, not an application error.
            tracing::debug!(error = %e, "telemt session ended with an I/O error");
        }
    }

    Ok(())
}

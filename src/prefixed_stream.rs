//! `PrefixedStream` wraps an already-open `TcpStream` from which we've
//! already read a few bytes (the ClientHello) during SNI sniffing. To
//! any consumer above it (in our case, rustls via
//! `tokio_rustls::TlsAcceptor`) it looks like an ordinary stream where
//! those bytes simply haven't been read yet: first the `prefix` buffer
//! is handed out, then reads transparently continue from the real
//! socket. No byte of the original TLS handshake is ever lost.

use bytes::Bytes;
use std::io::{self, Cursor, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

pub struct PrefixedStream {
    prefix: Cursor<Bytes>,
    inner: TcpStream,
}

impl PrefixedStream {
    pub fn new(prefix: Bytes, inner: TcpStream) -> Self {
        Self {
            prefix: Cursor::new(prefix),
            inner,
        }
    }
}

impl AsyncRead for PrefixedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        let pos = this.prefix.position() as usize;
        let data = this.prefix.get_ref();
        if pos < data.len() {
            let remaining = &data[pos..];
            let n = std::cmp::min(remaining.len(), buf.remaining());
            buf.put_slice(&remaining[..n]);
            this.prefix.set_position((pos + n) as u64);
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

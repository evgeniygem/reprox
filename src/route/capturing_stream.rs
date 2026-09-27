//! An `AsyncRead + AsyncWrite` wrapper that transparently records every
//! byte read through it.
//!
//! `rustls`'s `LazyConfigAcceptor` consumes bytes off the socket while
//! parsing the ClientHello, before `reprox` has picked (or built) the
//! `ServerConfig` needed to complete the handshake. Those bytes can't
//! be un-read, so when the caller wants the *raw*, unencrypted
//! ClientHello bytes forwarded verbatim instead — as on the
//! `tls_passthrough` path, where `reprox` never terminates TLS at all —
//! this wrapper captures what was consumed during the peek so it can
//! be replayed via `PrefixedStream` ahead of the rest of the connection.

use bytes::{Bytes, BytesMut};
use pin_project::pin_project;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[pin_project]
pub struct ReadCapturingStream<S> {
    #[pin]
    stream: S,
    bytes: BytesMut,
}

impl<S> ReadCapturingStream<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            bytes: BytesMut::new(),
        }
    }

    pub fn take_captured(&mut self) -> Bytes {
        self.bytes.split().freeze()
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S> AsyncRead for ReadCapturingStream<S>
where
    S: AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.project();
        let before = buf.filled().len();

        let poll = this.stream.poll_read(cx, buf);

        if let Poll::Ready(Ok(())) = poll {
            let new_data = &buf.filled()[before..];
            this.bytes.extend_from_slice(new_data);
        }
        poll
    }
}

impl<S> AsyncWrite for ReadCapturingStream<S>
where
    S: AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().stream.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().stream.poll_shutdown(cx)
    }
}

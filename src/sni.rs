//! On-the-fly parsing of the SNI from a TLS ClientHello, without
//! establishing our own TLS session — the equivalent of nginx's
//! `ssl_preread`.
//!
//! We read raw bytes off the socket into a buffer until we have exactly
//! the first TLS record (`TLSPlaintext`) in full, parse the
//! Handshake::ClientHello inside it, and extract the `server_name`
//! extension (RFC 6066). The buffer of already-read bytes is returned to
//! the caller so it can be replayed further down the line — either into
//! the proxy connection to service, or into rustls (via `PrefixedStream`)
//! — without losing a single byte of the original stream.
//!
//! The result is classified into a `ProbeResult`, which both drives
//! main.rs's routing decision and doubles as a metrics label (see
//! metrics.rs's `clienthello_*_total` counters) — operationally it's
//! useful to be able to tell "browsers hitting the fallback site
//! without SNI" apart from "something sending us garbage".

use bytes::{Bytes, BytesMut};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// Maximum size we're willing to buffer while looking for the SNI —
/// matches the maximum TLS record size (2^14 bytes) plus the 5-byte
/// record header. This comfortably covers any real-world ClientHello,
/// including modern hybrid post-quantum key-share extensions.
const MAX_PROBE_BYTES: usize = 16 * 1024 + 5;

const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const EXTENSION_SERVER_NAME: u16 = 0x0000;
const SERVER_NAME_TYPE_HOST_NAME: u8 = 0x00;

/// Outcome of sniffing a ClientHello for its SNI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeResult {
    /// A structurally valid ClientHello was parsed and it carried an SNI.
    Sni(String),
    /// A structurally valid ClientHello was parsed, but it had no
    /// `server_name` extension.
    NoSni,
    /// The bytes received don't look like a TLS handshake at all (or
    /// are malformed in a way we don't attempt to recover from).
    NotTls,
    /// The peer closed the connection before we received enough data to
    /// decide (e.g. a bare TCP connect+close from a port scanner or
    /// health checker).
    ConnectionClosed,
}

enum ParseOutcome {
    /// Parsing finished: if the ClientHello is valid but has no SNI, `None`.
    Complete(Option<String>),
    /// Not enough data yet, need to read more from the socket.
    Incomplete,
    /// The data is definitely not a valid TLS ClientHello.
    Invalid,
}

/// Reads from `stream`, trying to recognize a TLS ClientHello in the
/// data and extract its SNI. Returns all bytes read (they will need to
/// be "replayed" further on — either into the proxy or into the TLS
/// acceptor) along with the classification.
///
/// Never fails on garbage/invalid data — in that case it simply returns
/// `ProbeResult::NotTls` together with whatever was read so far.
pub async fn probe_client_hello(stream: &mut TcpStream) -> std::io::Result<(Bytes, ProbeResult)> {
    let mut buf = BytesMut::with_capacity(4096);
    let mut tmp = [0u8; 4096];

    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Ok((buf.freeze(), ProbeResult::ConnectionClosed));
        }
        buf.extend_from_slice(&tmp[..n]);

        match parse_sni(&buf) {
            ParseOutcome::Complete(Some(host)) => {
                return Ok((buf.freeze(), ProbeResult::Sni(host)));
            }
            ParseOutcome::Complete(None) => return Ok((buf.freeze(), ProbeResult::NoSni)),
            ParseOutcome::Incomplete => {
                if buf.len() >= MAX_PROBE_BYTES {
                    // Past a reasonable limit — let the fallback TLS
                    // stack sort it out.
                    return Ok((buf.freeze(), ProbeResult::NotTls));
                }
                continue;
            }
            ParseOutcome::Invalid => return Ok((buf.freeze(), ProbeResult::NotTls)),
        }
    }
}

fn parse_sni(buf: &[u8]) -> ParseOutcome {
    // TLSPlaintext: content_type(1) + legacy_version(2) + length(2) + fragment
    if buf.len() < 5 {
        return ParseOutcome::Incomplete;
    }
    if buf[0] != CONTENT_TYPE_HANDSHAKE {
        return ParseOutcome::Invalid;
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if record_len == 0 || record_len > 16 * 1024 {
        return ParseOutcome::Invalid;
    }
    let record_end = 5 + record_len;
    if buf.len() < record_end {
        return ParseOutcome::Incomplete;
    }
    let payload = &buf[5..record_end];

    // Handshake: msg_type(1) + length(3) + body
    if payload.len() < 4 {
        return ParseOutcome::Invalid;
    }
    if payload[0] != HANDSHAKE_TYPE_CLIENT_HELLO {
        return ParseOutcome::Invalid;
    }
    let hs_len = u32::from_be_bytes([0, payload[1], payload[2], payload[3]]) as usize;
    if payload.len() < 4 + hs_len {
        // A ClientHello spread across multiple TLS records — a rare case
        // for real browsers/clients. We don't parse it specially and
        // defer to the full TLS stack on the fallback path.
        return ParseOutcome::Invalid;
    }
    let body = &payload[4..4 + hs_len];

    ParseOutcome::Complete(extract_sni(body))
}

/// Parses the body of the ClientHello (after the handshake header)
/// looking for the server_name extension. Returns `None` if the
/// structure doesn't match what's expected (in which case the caller
/// falls back to the fallback path).
fn extract_sni(body: &[u8]) -> Option<String> {
    let mut pos: usize = 0;

    // client_version(2) + random(32)
    if body.len() < pos + 34 {
        return None;
    }
    pos += 34;

    // session_id
    let sid_len = *body.get(pos)? as usize;
    pos += 1;
    if body.len() < pos + sid_len {
        return None;
    }
    pos += sid_len;

    // cipher_suites
    if body.len() < pos + 2 {
        return None;
    }
    let cs_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    if body.len() < pos + cs_len {
        return None;
    }
    pos += cs_len;

    // compression_methods
    if body.len() < pos + 1 {
        return None;
    }
    let cm_len = body[pos] as usize;
    pos += 1;
    if body.len() < pos + cm_len {
        return None;
    }
    pos += cm_len;

    // extensions (may be absent — in that case there is definitely no SNI)
    if body.len() < pos + 2 {
        return None;
    }
    let ext_total_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_total_len;
    if ext_end > body.len() {
        return None;
    }

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > ext_end {
            return None;
        }
        if ext_type == EXTENSION_SERVER_NAME {
            return parse_server_name_extension(&body[pos..pos + ext_len]);
        }
        pos += ext_len;
    }

    None
}

/// RFC 6066 §3: struct { ServerName server_name_list<1..2^16-1> }
fn parse_server_name_extension(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let end = (2 + list_len).min(data.len());
    let mut pos = 2usize;

    while pos + 3 <= end {
        let name_type = data[pos];
        let name_len = u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize;
        pos += 3;
        if pos + name_len > end {
            return None;
        }
        if name_type == SERVER_NAME_TYPE_HOST_NAME {
            return std::str::from_utf8(&data[pos..pos + name_len])
                .ok()
                .map(|s| s.trim_end_matches('.').to_ascii_lowercase());
        }
        pos += name_len;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal valid ClientHello with exactly one server_name
    /// extension, so parsing can be tested without a network stack.
    fn build_client_hello_with_sni(host: &str) -> Vec<u8> {
        let mut hs_body = Vec::new();
        hs_body.extend_from_slice(&[0x03, 0x03]); // client_version = TLS 1.2 (legacy)
        hs_body.extend_from_slice(&[0u8; 32]); // random
        hs_body.push(0); // session_id_len = 0
        hs_body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites_len
        hs_body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        hs_body.push(1); // compression_methods_len
        hs_body.push(0); // null compression

        let mut sni_ext = Vec::new();
        let name_bytes = host.as_bytes();
        sni_ext.extend_from_slice(&((name_bytes.len() + 3) as u16).to_be_bytes()); // server_name_list len
        sni_ext.push(0x00); // name_type = host_name
        sni_ext.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(name_bytes);

        push_client_hello(hs_body, Some(sni_ext))
    }

    /// Same as above, but with an empty extensions block — used to test
    /// the `NoSni`/`Complete(None)` classification path.
    fn build_client_hello_without_sni() -> Vec<u8> {
        let mut hs_body = Vec::new();
        hs_body.extend_from_slice(&[0x03, 0x03]);
        hs_body.extend_from_slice(&[0u8; 32]);
        hs_body.push(0);
        hs_body.extend_from_slice(&2u16.to_be_bytes());
        hs_body.extend_from_slice(&[0x13, 0x01]);
        hs_body.push(1);
        hs_body.push(0);

        push_client_hello(hs_body, None)
    }

    /// Wraps `hs_body` (everything up to, but not including, the
    /// extensions block) with an `extensions` block containing either a
    /// single server_name extension or none, then wraps the result in a
    /// Handshake header and a TLS record header.
    fn push_client_hello(mut hs_body: Vec<u8>, sni_ext: Option<Vec<u8>>) -> Vec<u8> {
        let mut ext = Vec::new();
        if let Some(sni_ext) = sni_ext {
            ext.extend_from_slice(&0u16.to_be_bytes()); // ext type = server_name
            ext.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
            ext.extend_from_slice(&sni_ext);
        }

        hs_body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hs_body.extend_from_slice(&ext);

        let mut handshake = Vec::new();
        handshake.push(HANDSHAKE_TYPE_CLIENT_HELLO);
        let len = hs_body.len() as u32;
        handshake.extend_from_slice(&len.to_be_bytes()[1..4]);
        handshake.extend_from_slice(&hs_body);

        let mut record = Vec::new();
        record.push(CONTENT_TYPE_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x01]); // legacy_record_version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn parses_sni_from_well_formed_client_hello() {
        let record = build_client_hello_with_sni("example.com");
        match parse_sni(&record) {
            ParseOutcome::Complete(Some(host)) => assert_eq!(host, "example.com"),
            _ => panic!("expected to parse SNI"),
        }
    }

    #[test]
    fn client_hello_without_sni_extension_is_complete_with_none() {
        let record = build_client_hello_without_sni();
        match parse_sni(&record) {
            ParseOutcome::Complete(None) => {}
            _ => panic!("expected a valid ClientHello with no SNI to map to Complete(None)"),
        }
    }

    #[test]
    fn incomplete_buffer_requests_more_data() {
        let record = build_client_hello_with_sni("example.com");
        assert!(matches!(parse_sni(&record[..10]), ParseOutcome::Incomplete));
    }

    #[test]
    fn garbage_is_invalid() {
        let garbage = vec![0xAA; 64];
        match parse_sni(&garbage) {
            ParseOutcome::Invalid => {}
            _ => panic!("expected garbage to be rejected"),
        }
    }

    #[test]
    fn plain_http_is_invalid() {
        let http = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        match parse_sni(&http) {
            ParseOutcome::Invalid => {}
            _ => panic!("expected plaintext HTTP to be rejected as non-TLS"),
        }
    }
}

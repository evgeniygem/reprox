# Reprox

An SNI router in front of service, built on the same principle
as `nginx` + `ssl_preread`:

- If the SNI of an incoming TLS connection matches service's
  secret domain, TLS is **not terminated** — the whole TCP stream
  (including the already-read ClientHello bytes) is transparently
  proxied to the local service instance.
- Otherwise (SNI doesn't match, is absent, or the handshake doesn't
  even look like TLS), the server performs a full TLS handshake itself
  on the real certificate and serves a static fallback site over HTTPS.

The connection is never dropped between these two steps: the bytes read
while determining the SNI are never lost — they get "replayed" either
into the service upstream or into the TLS acceptor.

## How it works

1. `main.rs` accepts a TCP connection and passes it to
   `sni::probe_client_hello`.
2. `probe_client_hello` reads bytes from the socket (up to ~16 KB, or
   until the first TLS record is complete) and parses a TLS
   `ClientHello` out of them, extracting the `server_name` extension
   (RFC 6066) — **without** establishing its own TLS connection. Any
   format error is simply treated as "no SNI found", not as a reason to
   close the connection itself.
3. The bytes that were read (`prefix`) are returned either way — they
   are still needed.
4. If `SNI ∈ secret_domains`, `route::proxy` opens a
   connection to `proxy_addr`, sends it `prefix`, and then shuttles
   bytes in both directions via `tokio::io::copy_bidirectional`. service
   itself thinks it's talking directly to the client — not a single
   byte of the FakeTLS handshake is altered or lost.
5. Otherwise, `route::serve` wraps the socket in a
   `PrefixedStream` (first hands out `prefix`, then reads from the real
   socket) and passes it to `tokio_rustls::TlsAcceptor`. After a
   successful handshake, ALPN picks HTTP/2 or HTTP/1.1, and hyper serves
   the static site from `static/`, which is loaded entirely into memory
   at startup.

Every step above updates counters/gauges in `metrics.rs` — connection
counts and routing decisions in `main.rs`, byte counts and connect
failures in `proxy.rs`, TLS/ALPN/HTTP outcomes in `serve.rs` — which
are then exposed over the internal, loopback-only API described below.

This is exactly how a real `nginx` behaves with `stream { ssl_preread
on; }` + a `map` on `$ssl_preread_server_name` to `proxy_pass`/`return
444` in one block, and a full `server { listen 443 ssl; }` in
another — except here it's two code paths in one process on one port.

## Building

```bash
cargo build --release
# binary: target/release/reprox
```

## Configuration

1. Copy `config.toml` to `/etc/reprox/config.toml` and edit it:
    - `proxy_addr` — where service actually listens (usually
      `127.0.0.1:PORT`).
    - `secret_domains` — the domain(s) from service's secret.
    - `tls_cert_path` / `tls_key_path` — a real certificate/key for the
      domain this server resolves to (see `certs/README.md`).
    - `static_dir` — path to the `static/` directory (or your own copy).
2. Replace the placeholders in `static/` (company name, e-mail, the
   domain in `robots.txt`) with your own — if several operators use
   this template verbatim and unmodified, the sites become easy to
   fingerprint by response bytes.
3. Make sure DNS is set up so that the domain in `secret_domains` **and**
   the certificate's domain both resolve to this server's IP (this
   should already be the case per the task description).

### Binding port 443 without root

```bash
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/reprox
```

The `systemd/reprox.service` unit is already set up with
`AmbientCapabilities=CAP_NET_BIND_SERVICE`, a dedicated unprivileged
user, `NoNewPrivileges`, `ProtectSystem=strict`, and so on — copy it
into `/etc/systemd/system/` and adjust the paths for your setup:

```bash
sudo useradd --system --no-create-home reprox
sudo cp target/release/reprox /usr/local/bin/
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/reprox
sudo cp -r config.toml static certs /etc/reprox/
sudo chown -R reprox:reprox /etc/reprox
sudo cp systemd/reprox.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now reprox
```

## Metrics &amp; internal API

If `metrics_addr` is set in the config (it must be a loopback address —
enforced both when the config loads and again right before the listener
binds), the process also serves a small plain-HTTP, GET-only API on that
address:

| Route               | Returns                           |
|---------------------|-----------------------------------|
| `GET /metrics`      | Prometheus text exposition format |
| `GET /metrics.json` | the same data as structured JSON  |
| `GET /healthz`      | `ok` — trivial liveness check     |

Anything else on that port returns 404; non-GET requests return 405.
Leaving `metrics_addr` unset disables all of this and opens no extra
port at all.

Everything below is tracked in-memory (reset on restart, not persisted)
and, other than the active-connection gauges, is monotonically
increasing — suitable for `rate()`/`increase()` in Prometheus.

| Metric                                         | Type    | Labels                                               | What it tells you                                                                                                  |
|------------------------------------------------|---------|------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------|
| `reprox_uptime_seconds`                        | gauge   | —                                                    | Time since the process started.                                                                                    |
| `reprox_connections_total`                     | counter | `route=proxied\|fallback`                            | TCP connections accepted, by route.                                                                                |
| `reprox_connections_active`                    | gauge   | `route=proxied\|fallback`                            | Connections currently being served.                                                                                |
| `reprox_connection_duration_ms_sum` / `_count` | counter | `route=proxied\|fallback`                            | Sum/count of completed connections — divide for the average duration per route.                                    |
| `reprox_connections_rejected_total`            | counter | `reason=probe_timeout\|probe_io_error\|closed_early` | Connections that never produced a usable ClientHello.                                                              |
| `reprox_clienthello_total`                     | counter | `result=sni_present\|sni_absent\|not_tls`            | ClientHello classification — `not_tls` spiking is a useful signal for scanning/probing traffic.                    |
| `reprox_proxy_bytes_total`                     | counter | `direction=client_to_service\|service_to_client`     | Bytes relayed between clients and service.                                                                         |
| `reprox_proxy_service_connect_failures_total`  | counter | —                                                    | Failed TCP connects from this process to service — a non-zero rate usually means service is down or misconfigured. |
| `reprox_tls_handshakes_total`                  | counter | `result=success\|failure`                            | Fallback-path TLS handshake outcomes.                                                                              |
| `reprox_alpn_selected_total`                   | counter | `protocol=h2\|http1\|none`                           | Negotiated ALPN protocol on the fallback path.                                                                     |
| `reprox_http_requests_total`                   | counter | `method=GET\|HEAD\|OPTIONS\|other`                   | Fallback-site requests by method.                                                                                  |
| `reprox_http_responses_total`                  | counter | `status=200\|204\|304\|404\|405\|other`              | Fallback-site responses by status code.                                                                            |
| `reprox_http_response_bytes_total`             | counter | —                                                    | Approximate response body bytes sent (from `Content-Length`).                                                      |
| `reprox_config_secret_domains`                 | gauge   | —                                                    | Number of configured service secret domains — a quick sanity check that config reloaded correctly after a restart. |

Sample check after enabling `metrics_addr = "127.0.0.1:9090"`:

```bash
curl -s http://127.0.0.1:9090/healthz
curl -s http://127.0.0.1:9090/metrics | head -30
curl -s http://127.0.0.1:9090/metrics.json | jq .connections
```

Since the whole point of this endpoint is operational visibility for
whoever runs the box, it's deliberately unauthenticated — access control
is the network boundary (loopback-only) itself. If you want to look at
these numbers from another machine, use an SSH tunnel
(`ssh -L 9090:127.0.0.1:9090 your-server`) or scrape it locally with a
Prometheus node/agent running on the same host, rather than widening
`metrics_addr` — the config loader will refuse a non-loopback address
outright.

## Environment variables (override config.toml)

| Variable                        | Corresponding field                    |
|---------------------------------|----------------------------------------|
| `REPROX_CONFIG`                 | path to the TOML file itself           |
| `REPROX_LISTEN_ADDR`            | `listen_addr`                          |
| `REPROX_PROXY_ADDR`             | `proxy_addr`                           |
| `REPROX_SECRET_DOMAINS`         | `secret_domains` (comma-separated)     |
| `REPROX_TLS_CERT_PATH`          | `tls_cert_path`                        |
| `REPROX_TLS_KEY_PATH`           | `tls_key_path`                         |
| `REPROX_STATIC_DIR`             | `static_dir`                           |
| `REPROX_SERVER_HEADER`          | `server_header`                        |
| `REPROX_HANDSHAKE_TIMEOUT_SECS` | `handshake_timeout_secs`               |
| `REPROX_TLS_MIN_VERSION`        | `tls_min_version`                      |
| `REPROX_METRICS_ADDR`           | `metrics_addr`                         |
| `RUST_LOG`                      | tracing log level (defaults to `info`) |

## Verifying after deployment

The fallback path (non-secret SNI) should serve the real site:

```bash
curl -v https://your-domain.example/
curl -I https://your-domain.example/no-such-page      # expect a 404 in the site's style
curl -I -X OPTIONS https://your-domain.example/        # expect 204 + Allow
openssl s_client -connect your-domain.example:443 -alpn h2,http/1.1 -servername your-domain.example </dev/null | grep -E "ALPN|subject|issuer"
```

The service path (secret SNI) should be transparently forwarded — the
easiest check is a real client configured with this proxy, or
eyeballing the TLS record lengths manually:

```bash
openssl s_client -connect your-domain.example:443 -servername www.example-fronting-domain.com </dev/null
# The handshake should NOT complete with your domain's real certificate —
# service answers with its own FakeTLS stream, not a genuine TLS ServerHello.
```

Invalid data should not cause an instant RST:

```bash
# a "garbage" ClientHello — the connection should close normally
# (FIN/alert), not drop instantly with an RST:
printf 'not a tls handshake at all' | timeout 3 openssl s_client -connect your-domain.example:443 -quiet
```

Technical endpoints are unreachable from outside by construction: the
only public port is `listen_addr` (443), and it has no paths like
`/metrics`/`/admin`; `metrics_addr` (if enabled) is validated twice and
must be a loopback address.

## Known limitations of this implementation (stated plainly, so nothing surprises you in production)

- The SNI parser handles a `ClientHello` that fits entirely within the
  first TLS record (true for the vast majority of real clients,
  including modern browsers with post-quantum key shares). Exotic
  clients that spread the `ClientHello` across multiple TLS records
  will end up on the fallback path, where the handshake still
  correctly fails at the rustls level — just as an ordinary TLS
  rejection rather than as "secret proxy".
- The certificate/key and the static site are read once at startup; to
  pick up a new certificate or new content, restart the process.
- There is no built-in HTTP→HTTPS redirect on port 80 — per the task
  description the service only listens on 443. If you need one, run a
  simple separate redirector on port 80 (or use nginx for that) instead.

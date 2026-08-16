# Reprox

An SNI router in front of service, built on the same principle
as `nginx` + `ssl_preread`:

- If the SNI of an incoming TLS connection matches service's
  secret domain, by default TLS is **not terminated** — the whole TCP
  stream (including the already-read ClientHello bytes) is transparently
  proxied to the local service instance. A route can opt out of this
  (`tls_passthrough = false`) and have `reprox` terminate TLS itself
  instead, handing the service plaintext.
- Otherwise (SNI doesn't match, is absent, or the handshake doesn't
  even look like TLS), the server performs a full TLS handshake itself
  on the real certificate and serves a static fallback site over HTTPS.

The connection is never dropped between these steps: the bytes read
while determining the SNI are never lost — they get "replayed" into
whichever of these three paths ends up handling the connection.

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
4. If the SNI matches one of the configured `routes` entries and that
   route uses the default `tls_passthrough = true`, `route::proxy`
   opens a connection to that route's `upstream` (retrying up to 3
   times with exponential backoff — 200ms, 400ms, 800ms between
   attempts, each capped at a 3s timeout — if the service is briefly
   unreachable, e.g. mid-restart), sends it `prefix`, and then shuttles
   bytes in both directions via `tokio::io::copy_bidirectional`. The
   matched service itself thinks it's talking directly to the client —
   not a single byte of the FakeTLS handshake is altered or lost.
   `routes` is a list, so a single `reprox` instance can front more than
   one hidden service, each behind its own SNI.
5. If the matched route instead sets `tls_passthrough = false`,
   `route::proxy::proxy_with_tls_termination` terminates TLS on this
   side — reusing the same certificate/`TlsAcceptor` as the fallback
   site below — and relays the *decrypted* plaintext to `upstream` over
   a new, unencrypted TCP connection. Use this for a hidden service that
   expects plain traffic rather than doing its own TLS.
6. Otherwise (no route matched), `route::serve` wraps the socket in a
   `PrefixedStream` (first hands out `prefix`, then reads from the real
   socket) and passes it to `tokio_rustls::TlsAcceptor`. After a
   successful handshake, ALPN picks HTTP/2 or HTTP/1.1, and hyper serves
   the static site from `static/`, which is loaded entirely into memory
   at startup.

Every step above updates counters/gauges in `metrics.rs` — connection
counts and routing decisions in `main.rs`, byte counts and connect
failures in `proxy.rs`, TLS/ALPN outcomes in both `proxy.rs` (for
`tls_passthrough = false` routes) and `serve.rs`, and HTTP outcomes in
`serve.rs` — which are then exposed over the internal, loopback-only
API described below.

This is exactly how a real `nginx` behaves with `stream { ssl_preread
on; }` + a `map` on `$ssl_preread_server_name` to `proxy_pass`/`return
444` in one block, and a full `server { listen 443 ssl; }` in
another — except here it's up to three code paths in one process on one
port (plain passthrough, TLS-terminating proxy, and the fallback site).

## Building

Requires Rust 1.88 or newer (edition 2024) — `config.rs` uses let-chains
(`if let ... && let ...`), which are only available on that edition.

```bash
cargo build --release
# binary: target/release/reprox
```

The first build resolves and pins exact dependency versions into
`Cargo.lock`; commit that file so subsequent builds (and deployments)
use the exact versions you tested against.

## Configuration

1. Copy `config.toml` to `/etc/reprox/config.toml` and edit it:
    - `routes` — one `[[routes]]` block per hidden service, each with:
        - `sni` — the secret domain for that service.
        - `upstream` — where that service actually listens (usually
          `127.0.0.1:PORT`).
        - `tls_passthrough` (optional, default `true`) — `true` is
          classic FakeTLS: the raw TLS bytes are forwarded to `upstream`
          untouched and it performs its own handshake. Set it to `false`
          to have `reprox` terminate TLS itself instead (reusing the
          same certificate as the fallback site) and forward the
          *decrypted* plaintext to `upstream` over a new TCP
          connection — use this when the hidden service expects plain,
          unencrypted traffic.

      A single `reprox` instance can front several services this way —
      just add another `[[routes]]` block:

      ```toml
      [[routes]]
      sni = "domain.com"
      upstream = "127.0.0.1:8080"

      [[routes]]
      sni = "api.domain.com"
      upstream = "127.0.0.1:4443"
      tls_passthrough = false
      ```

      Each `sni` must be unique (checked at startup) and is matched
      case-insensitively with any trailing dot ignored, exactly like a
      TLS `server_name` value would be. Each `upstream` is also checked
      at startup for being a syntactically valid `host:port` — a stray
      `https://` prefix, a missing/garbled port, or a trailing path will
      fail config loading with a clear error instead of silently only
      surfacing later as `reprox_proxy_service_connect_failures_total`
      once real traffic hits that route. This check does **not** resolve
      hostnames (a hostname upstream may simply not be resolvable yet at
      startup), so a typo'd-but-well-formed hostname will still only be
      caught at connect time.
    - `tls_cert_path` / `tls_key_path` — a real certificate/key for the
      domain this server resolves to (see `certs/README.md`).
    - `static_dir` — path to the `static/` directory (or your own copy).
    - `max_connections` (optional, default `10000`) — hard cap on
      connections handled at once, across both routes combined. Once
      this many connections are in flight, new ones simply queue in the
      kernel's accept backlog until a slot frees up, instead of being
      accepted without limit and exhausting file descriptors or memory —
      the same role nginx's `worker_connections` plays. Each proxied
      connection holds two sockets (client + upstream), so raise this
      with that in mind if you're also tuning the process's file
      descriptor limit (`ulimit -n` / `LimitNOFILE=` in the systemd
      unit). See "Per-IP connection limits" below for capping how much
      of that budget a single IP can take.
    - `max_connections_per_ip` - (optional) hard cap on concurrent
      connections from a single client IP, enforced in addition to
      max_connections. Bounds how many connections a single client IP
      may have open at once.
2. Replace the placeholders in `static/` (company name, e-mail, the
   domain in `robots.txt`) with your own — if several operators use
   this template verbatim and unmodified, the sites become easy to
   fingerprint by response bytes.
3. Make sure DNS is set up so that every `sni` in `routes` **and** the
   certificate's domain both resolve to this server's IP (this should
   already be the case per the task description).

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

### Per-IP connection limits

`max_connections` caps how many connections the whole process handles
at once, but says nothing about a *single* IP — one peer could still
open thousands of slow-drip connections (each just sitting in the
SNI-probe phase until `handshake_timeout_secs`) and starve every other
visitor out of the global cap. Two independent, opt-in limits guard
against that, both keyed by the client's IP address:

- `max_connections_per_ip` (optional, unset = disabled) — hard cap on
  how many connections a single IP may have **open at once**. Guards
  against one IP occupying an outsized share of `max_connections` just
  by holding sockets open.
- `connection_rate_per_ip` / `connection_burst_per_ip` (optional,
  unset = disabled) — a token-bucket cap on how fast a single IP may
  **open new connections**: `connection_rate_per_ip` connections/sec
  sustained, `connection_burst_per_ip` allowed back-to-back before
  throttling kicks in (defaults to `10` if a rate is set but a burst
  isn't). Guards against a fast scanner that never keeps enough
  connections open at once to trip the limit above.

```toml
max_connections_per_ip = 100
connection_rate_per_ip = 5
connection_burst_per_ip = 20
```

Both apply only to the public listener — loopback addresses (local
health checks, metrics scraping) are never throttled by either one.
Rejections show up in `reprox_connections_rejected_total` as
`reason="ip_limit"` and `reason="rate_limit"` respectively (see
Metrics below); a sustained non-zero rate there, separate from the
ordinary SNI-probe noise, is a good early signal of scanning or
abusive traffic worth looking into. Unlike `max_connections`, both of
these settings **are** picked up live by `SIGHUP` — see "Reloading
without a restart".

These limits key strictly on the TCP peer address. If `reprox` sits
behind something that already terminates/re-originates connections
(another load balancer, a CDN) every client will appear to share that
upstream's IP — either enable PROXY protocol upstream of `reprox` (not
currently supported) or apply IP-based limiting at whatever layer
actually sees the real client addresses instead.

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

| Metric                                         | Type    | Labels                                                                     | What it tells you                                                                                                                                                                                                              |
|------------------------------------------------|---------|----------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `reprox_uptime_seconds`                        | gauge   | —                                                                          | Time since the process started.                                                                                                                                                                                                |
| `reprox_connections_total`                     | counter | `route=proxied\|fallback`                                                  | TCP connections accepted, by route.                                                                                                                                                                                            |
| `reprox_connections_active`                    | gauge   | `route=proxied\|fallback`                                                  | Connections currently being served.                                                                                                                                                                                            |
| `reprox_connection_duration_ms_sum` / `_count` | counter | `route=proxied\|fallback`                                                  | Sum/count of completed connections — divide for the average duration per route.                                                                                                                                                |
| `reprox_connections_rejected_total`            | counter | `reason=probe_timeout\|probe_io_error\|closed_early\|ip_limit\|rate_limit` | Connections rejected before ever being routed. `probe_timeout`/`probe_io_error`/`closed_early` are SNI-probe outcomes; `ip_limit`/`rate_limit` are per-IP limiter rejections (see "Per-IP connection limits").                 |
| `reprox_connections_limit`                     | gauge   | —                                                                          | Configured `max_connections` cap on connections handled at once, across both routes.                                                                                                                                           |
| `reprox_connections_available`                 | gauge   | —                                                                          | Free connection slots out of `reprox_connections_limit` right now. A sustained `0` means `max_connections` is the current bottleneck — new connections are queuing instead of being served.                                    |
| `reprox_clienthello_total`                     | counter | `result=sni_present\|sni_absent\|not_tls`                                  | ClientHello classification — `not_tls` spiking is a useful signal for scanning/probing traffic.                                                                                                                                |
| `reprox_proxy_bytes_total`                     | counter | `direction=client_to_service\|service_to_client`                           | Bytes relayed between clients and service.                                                                                                                                                                                     |
| `reprox_proxy_service_connect_failures_total`  | counter | —                                                                          | Connections that couldn't reach service after exhausting connect retries (see below) — a non-zero rate usually means service is down or misconfigured.                                                                         |
| `reprox_proxy_service_connect_retries_total`   | counter | —                                                                          | Failed connect attempts to service that were retried with backoff (excludes each route's final, giving-up attempt). High relative to the failures counter above means service is usually just briefly slow, not actually down. |
| `reprox_tls_handshakes_total`                  | counter | `result=success\|failure`                                                  | Fallback-path TLS handshake outcomes.                                                                                                                                                                                          |
| `reprox_alpn_selected_total`                   | counter | `protocol=h2\|http1\|none`                                                 | Negotiated ALPN protocol on the fallback path.                                                                                                                                                                                 |
| `reprox_http_requests_total`                   | counter | `method=GET\|HEAD\|OPTIONS\|other`                                         | Fallback-site requests by method.                                                                                                                                                                                              |
| `reprox_http_responses_total`                  | counter | `status=200\|204\|304\|404\|405\|other`                                    | Fallback-site responses by status code.                                                                                                                                                                                        |
| `reprox_http_response_bytes_total`             | counter | —                                                                          | Approximate response body bytes sent (from `Content-Length`).                                                                                                                                                                  |
| `reprox_config_secret_domains`                 | gauge   | —                                                                          | Number of configured `routes` entries (kept under its original name for dashboard/alert compatibility) — a quick sanity check that config loaded correctly after a restart or a SIGHUP reload.                                 |

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

| Variable                         | Corresponding field                    |
|----------------------------------|----------------------------------------|
| `REPROX_CONFIG`                  | path to the TOML file itself           |
| `REPROX_LISTEN_ADDR`             | `listen_addr`                          |
| `REPROX_TLS_CERT_PATH`           | `tls_cert_path`                        |
| `REPROX_TLS_KEY_PATH`            | `tls_key_path`                         |
| `REPROX_STATIC_DIR`              | `static_dir`                           |
| `REPROX_SERVER_HEADER`           | `server_header`                        |
| `REPROX_HANDSHAKE_TIMEOUT_SECS`  | `handshake_timeout_secs`               |
| `REPROX_TLS_MIN_VERSION`         | `tls_min_version`                      |
| `REPROX_METRICS_ADDR`            | `metrics_addr`                         |
| `REPROX_MAX_CONNECTIONS`         | `max_connections`                      |
| `REPROX_MAX_CONNECTIONS_PER_IP`  | `max_connections_per_ip`               |
| `REPROX_CONNECTION_RATE_PER_IP`  | `connection_rate_per_ip`               |
| `REPROX_CONNECTION_BURST_PER_IP` | `connection_burst_per_ip`              |
| `RUST_LOG`                       | tracing log level (defaults to `info`) |

## Verifying after deployment

The fallback path (non-secret SNI) should serve the real site:

```bash
curl -v https://your-domain.example/
curl -I https://your-domain.example/no-such-page      # expect a 404 in the site's style
curl -I -X OPTIONS https://your-domain.example/        # expect 204 + Allow
openssl s_client -connect your-domain.example:443 -alpn h2,http/1.1 -servername your-domain.example </dev/null | grep -E "ALPN|subject|issuer"
```

The service path for a `tls_passthrough = true` route (the default)
should be transparently forwarded — the easiest check is a real client
configured with this proxy, or eyeballing the TLS record lengths
manually:

```bash
openssl s_client -connect your-domain.example:443 -servername www.example-fronting-domain.com </dev/null
# The handshake should NOT complete with your domain's real certificate —
# service answers with its own FakeTLS stream, not a genuine TLS ServerHello.
```

For a `tls_passthrough = false` route, the opposite should be true —
`reprox`'s own certificate terminates the handshake, and traffic
reaches `upstream` decrypted:

```bash
openssl s_client -connect your-domain.example:443 -servername api.domain.example </dev/null | grep -E "subject|issuer"
# The handshake SHOULD complete with your domain's real certificate this
# time — unlike the tls_passthrough = true case above.
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

## Shutdown behavior

`reprox` shuts down gracefully on either SIGINT (Ctrl+C in a terminal)
or SIGTERM (`systemd`'s default `KillSignal`, sent by `systemctl
stop`/`restart`): it immediately stops accepting new connections but
waits up to 30 seconds for connections it had already accepted (an
in-progress proxy session, a static file mid-download) to finish on
their own before exiting. If your systemd unit's `TimeoutStopSec` is
shorter than that, raise it (or lower the grace period in `main.rs`) so
a routine restart doesn't cut connections off mid-stream — `systemd`
escalates to SIGKILL once `TimeoutStopSec` elapses, which no
application-level handling can intercept.

## Reloading without a restart

Send `SIGHUP` to reload `config.toml`, the `routes` table (including
each route's `tls_passthrough`), the TLS certificate/key, and the per-IP
connection/rate limits — all without dropping a single in-flight
connection:

```
sudo systemctl reload reprox     # if your unit sets ExecReload, see below
# or directly:
kill -HUP $(systemctl show --property MainPID --value reprox)
```

A connection already being served keeps running against whatever
config/routes/certificate it had at the moment it was accepted; a
SIGHUP only changes what's used for connections accepted *after* the
reload completes — there's no window where one connection sees routes
from one version mixed with a certificate from another.

If a reload fails partway (invalid TOML, or a missing/mismatched cert
or key), it's logged and otherwise ignored: `reprox` keeps running on
whatever configuration it already had, rather than crashing or ending
up in a half-applied state. Watch the logs after sending SIGHUP for
either `"reload complete"` or a `"reload failed: ..."` line explaining
what went wrong.

**What SIGHUP does *not* reload** — `listen_addr`, `metrics_addr`,
`tls_min_version`, `max_connections`, and `static_dir`. Each is baked
into something the process only builds once at startup (a bound
listener, the `rustls::ServerConfig`'s negotiated TLS version set, a
fixed-size connection-slot semaphore, or — for `static_dir` — the
in-memory static site); changing one of these in `config.toml` and
sending SIGHUP logs a warning telling you a restart is needed, rather
than silently doing nothing or half-applying it. `max_connections_per_ip`,
`connection_rate_per_ip`, and `connection_burst_per_ip` are deliberately
*not* in this list — neither per-IP limiter is backed by a fixed-size
structure (just a threshold checked on each connection), so both apply
immediately on the next SIGHUP.

If your systemd unit doesn't already have one, add an `ExecReload` line
so `systemctl reload` works as shown above:

```ini
[Service]
ExecReload=/bin/kill -HUP $MAINPID
```

## Known limitations of this implementation (stated plainly, so nothing surprises you in production)

- The SNI parser handles a `ClientHello` that fits entirely within the
  first TLS record (true for the vast majority of real clients,
  including modern browsers with post-quantum key shares). Exotic
  clients that spread the `ClientHello` across multiple TLS records
  will end up on the fallback path, where the handshake still
  correctly fails at the rustls level — just as an ordinary TLS
  rejection rather than as "secret proxy".
- The certificate/key and `routes` (including each route's
  `tls_passthrough`) can be reloaded without a restart by sending
  `SIGHUP` — see "Reloading without a restart" below. `listen_addr`,
  `metrics_addr`, `tls_min_version`, `max_connections`, and `static_dir`
  still require a full restart: the first four are baked into something
  only built once at startup (a bound listener, the negotiated TLS
  version set, a fixed-size semaphore), and the static site is loaded
  into memory once and never re-read from disk afterwards.
- There is no built-in HTTP→HTTPS redirect on port 80 — per the task
  description the service only listens on 443. If you need one, run a
  simple separate redirector on port 80 (or use nginx for that) instead.
- Every route with `tls_passthrough = false` is terminated using the
  *same* `TlsAcceptor` as the fallback site, which always advertises
  ALPN `h2` then `http/1.1`. A client that doesn't send an ALPN
  extension at all negotiates fine either way, but a client that
  explicitly offers only some other protocol will fail the handshake
  against such a route. This is fine for hidden services that speak
  plain HTTP/1.1 or HTTP/2 once decrypted, but not for ones expecting a
  custom ALPN token.
- The optional `max_connections_per_ip` and `connection_rate_per_ip`
  limits (see "Per-IP connection limits") key on the raw TCP peer
  address. Behind a load balancer or CDN that already re-originates
  connections, every client looks like it shares that upstream's IP —
  these limits are only meaningful when `reprox` sees real client IPs
  directly.
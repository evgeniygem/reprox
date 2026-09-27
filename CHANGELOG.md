# Changelog

All notable changes to **Reprox** — an SNI router / FakeTLS proxy — are documented
in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/) (pre-1.0,
so minor bumps may contain breaking changes).

## [v0.7.0] - 2026-08-17

### Added

- TLS handshake outcome tracking on the proxy-termination path (`tls_passthrough = false`):
  new `proxy_tls_handshake_success_total` / `proxy_tls_handshake_failure_total`
  counters, exposed as the `reprox_proxy_tls_handshakes_total{result="success"|"failure"}`
  Prometheus metric. Previously these handshakes were only visible via debug logs.
- `/metrics.json`'s `TlsSnapshot` extended with the new `proxy_handshake_*` fields.

### Changed

- Renamed fallback-path metrics to make their scope explicit now that the proxy
  path has counterparts of its own:
    - `tls_handshake_success_total` / `tls_handshake_failure_total` →
      `fallback_tls_handshake_success_total` / `fallback_tls_handshake_failure_total`
    - `alpn_h2_total` / `alpn_http1_total` / `alpn_none_total` →
      `fallback_alpn_h2_total` / `fallback_alpn_http1_total` / `fallback_alpn_none_total`
    - Prometheus `reprox_tls_handshakes_total` / `reprox_alpn_selected_total` →
      `reprox_fallback_tls_handshakes_total` / `reprox_fallback_alpn_selected_total`

## [v0.6.0] - 2026-08-16

### Added

- Optional per-route TLS termination via a new `tls_passthrough` route config
  field (defaults to `true`, preserving prior FakeTLS behavior). When set to
  `false`, `reprox` terminates TLS itself — reusing the fallback site's
  certificate/`TlsAcceptor` — and relays decrypted plaintext to the upstream
  over a new TCP connection (`proxy_with_tls_termination`), routed per-request
  by `Router::route`.

### Fixed

- Removed stale comments/docs claiming SIGHUP reloads the static fallback
  site; it is loaded once at startup and handed to `Router::new`, never
  rebuilt on reload.
- `warn_about_unreloadable_changes` now also warns when `static_dir` changes
  on a SIGHUP reload, closing a gap where that change previously logged
  nothing.

### Changed

- README updated: routes config docs, "How it works" steps, post-deploy
  verification, and known-limitations sections; `config.toml` updated with a
  `tls_passthrough` example.

## [v0.5.0] - 2026-08-12

### Added

- Per-IP connection limits: new `max_connections_per_ip` config option backed
  by `IpLimiter`, on top of the existing global `max_connections`. Tracking
  entries are freed as soon as a connection ends.
- Per-IP rate limiting: new `connection_rate_per_ip` / `connection_burst_per_ip`
  config options implemented as a token-bucket `RateLimiter`, guarding against
  fast scanners that never hold enough connections open to trip the
  concurrency limit. A periodic janitor sweeps idle, fully-refilled buckets.
- New environment overrides: `REPROX_MAX_CONNECTIONS_PER_IP`,
  `REPROX_CONNECTION_RATE_PER_IP`, `REPROX_CONNECTION_BURST_PER_IP`.
- New `reprox_connections_rejected_total{reason="ip_limit"|"rate_limit"}` metric.
- README: new "Per-IP connection limits" section, metrics/env-var tables,
  SIGHUP reload notes, and known-limitations updates.

### Changed

- Both new limiters skip loopback addresses, are disabled by default
  (unset/`0`), and — unlike `max_connections` — are picked up live on SIGHUP
  since neither relies on a fixed-size structure.

## [v0.4.0] - 2026-07-26

### Added

- `max_connections` config option enforced by a semaphore-based
  `ConnectionLimiter`; new `reprox_connections_limit` / `..._available` metrics.
- Upstream address validation at config-load time (`config::validate_upstream`
  catches bad scheme, path, port, or whitespace before a connection is ever
  attempted).
- Exponential-backoff retries for upstream connects (4 attempts, 3s timeout
  each, 200/400/800ms delays); new
  `reprox_proxy_service_connect_retries_total` metric.
- SIGHUP hot-reload of config, routes, and TLS cert/key without dropping
  in-flight connections (`main::hot_reload`, `ReloadableCertResolver`,
  `Router`'s `RwLock<RouterState>` snapshot); `ExecReload` added to the
  systemd unit.

### Changed

- Changes to `listen_addr`, `metrics_addr`, `tls_min_version`, or
  `max_connections` now log a warning on reload instead of silently doing
  nothing (these still require a restart to take effect).
- Internal refactoring; updated the list of allowed dependency licenses.
- README and `config.toml` docs updated to match.

## [v0.3.0] - 2026-07-21

### Added

- `Router`: the per-connection dispatcher that inspects the TLS `ClientHello`
  SNI and routes each connection either to its matching upstream
  (transparent proxy) or to the local fallback HTTPS site.
- Graceful shutdown on SIGTERM as well as SIGINT (so `systemctl stop` triggers
  a clean shutdown), draining in-flight connections with a 30s grace period.
- Config validation rejecting duplicate route SNIs and
  `handshake_timeout_secs = 0`.

### Fixed

- A single transient `accept()` error no longer kills the whole listener —
  it's now logged, backed off, and serving continues.
- Metrics `override` config option is now applied only on successful parsing.
- `handshake_timeout_secs` now correctly covers the *entire* TLS handshake on
  the fallback path, not just part of it.

### Changed

- README rewritten to document the actual multi-route `[[routes]]`
  (`sni`/`upstream`) config in place of the stale `secret_domains`/
  `proxy_addr` docs, plus shutdown behavior and the Rust 1.88 / edition 2024
  build requirement.
- Further dependency, CI/CD, and `deny.toml` maintenance; metrics updates.

## [v0.2.0] - 2026-07-16

### Added

- CI/CD pipeline for GitHub (GitHub Actions).
- Project license.

### Changed

- `.gitignore` updated for the new pipeline/tooling.

## [v0.1.0] - 2026-07-15

Initial release.

### Added

- First commit of the `reprox` project: the initial SNI-based FakeTLS
  routing proxy.
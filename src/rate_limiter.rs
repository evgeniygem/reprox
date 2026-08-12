//! Per-IP token-bucket limiter for the *rate* of new connection
//! attempts. Complements `ip_limiter::IpLimiter`, which only caps
//! how many connections an IP can hold open *at once* — that does
//! nothing against a fast scanner that opens and immediately drops
//! thousands of short connections per second, since each one is gone
//! from the concurrent count before the next arrives.
//!
//! Classic token bucket, lazily refilled on each `allow()` call (no
//! background ticking needed for correctness — only for eventually
//! forgetting IPs that have gone quiet, see `run_janitor`).

use hashbrown::HashMap;
use rustc_hash::FxBuildHasher;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

struct Inner {
    buckets: Mutex<HashMap<IpAddr, Bucket, FxBuildHasher>>,
    capacity: AtomicU64,
    refill_per_sec_bits: AtomicU64,
}

#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Inner>,
}

impl RateLimiter {
    /// `rate_per_sec`: sustained new-connections/sec allowed per IP.
    /// `burst`: how many connections may arrive back-to-back before
    /// throttling kicks in (bucket capacity). `rate_per_sec <= 0.0`
    /// disables the limiter entirely — `allow()` always returns `true`
    /// and nothing is tracked.
    pub fn new(rate_per_sec: f64, burst: u64) -> Self {
        Self {
            inner: Arc::new(Inner {
                buckets: Mutex::new(HashMap::with_hasher(FxBuildHasher)),
                capacity: AtomicU64::new(burst),
                refill_per_sec_bits: AtomicU64::new(rate_per_sec.to_bits()),
            }),
        }
    }

    pub fn set_limit(&self, rate_per_sec: f64, burst: u64) {
        self.inner.capacity.store(burst, Ordering::Relaxed);
        self.inner
            .refill_per_sec_bits
            .store(rate_per_sec.to_bits(), Ordering::Relaxed);
    }

    /// Tries to consume one token from `ip`'s bucket. Returns `true`
    /// (and consumes a token) if one was available; `false` if `ip` is
    /// opening connections faster than its sustained rate allows.
    /// Loopback is always allowed — local health checks/scraping must
    /// never be throttled by a limit meant for the public listener.
    pub fn allow(&self, ip: IpAddr) -> bool {
        let capacity = self.inner.capacity.load(Ordering::Relaxed) as f64;
        let refill_per_sec = f64::from_bits(self.inner.refill_per_sec_bits.load(Ordering::Relaxed));

        if refill_per_sec <= 0.0 || ip.is_loopback() {
            return true;
        }

        let now = Instant::now();

        let mut buckets = self
            .inner
            .buckets
            .lock()
            .expect("rate limiter lock poisoned");

        let bucket = buckets.entry(ip).or_insert_with(|| Bucket {
            tokens: capacity,
            last_refill: now,
        });

        let elapsed = now
            .saturating_duration_since(bucket.last_refill)
            .as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * refill_per_sec).min(capacity);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Removes buckets that have fully refilled — a full bucket is
    /// indistinguishable from an IP that's never been seen, so
    /// forgetting it loses no state.
    pub fn sweep(&self) {
        let capacity = self.inner.capacity.load(Ordering::Relaxed) as f64;
        let refill_per_sec = f64::from_bits(self.inner.refill_per_sec_bits.load(Ordering::Relaxed));

        let now = Instant::now();

        let mut buckets = self
            .inner
            .buckets
            .lock()
            .expect("rate limiter lock poisoned");

        buckets.retain(|_, bucket| {
            let elapsed = now
                .saturating_duration_since(bucket.last_refill)
                .as_secs_f64();

            (bucket.tokens + elapsed * refill_per_sec).min(capacity) < capacity
        })
    }

    /// Number of distinct IPs currently tracked (≥1 open connection).
    /// Handy as a gauge — lets an operator see the limiter is actually
    /// doing something under load, not just trust it's wired in right.
    #[allow(unused)]
    pub fn ips_count(&self) -> usize {
        self.inner
            .buckets
            .lock()
            .expect("rate limiter lock poisoned")
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::thread::sleep;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, n))
    }

    #[test]
    fn allows_burst_then_throttles() {
        let rl = RateLimiter::new(1.0, 2);
        assert!(rl.allow(ip(1)));
        assert!(rl.allow(ip(1)));
        assert!(
            !rl.allow(ip(1)),
            "burst of 2 exhausted, 3rd must be rejected"
        );
    }

    #[test]
    fn refills_over_time() {
        let rl = RateLimiter::new(1000.0, 1); // fast rate keeps the test quick
        assert!(rl.allow(ip(1)));
        assert!(!rl.allow(ip(1)), "bucket of 1 exhausted immediately");
        sleep(std::time::Duration::from_millis(10));
        assert!(rl.allow(ip(1)), "should have refilled after waiting");
    }

    #[test]
    fn different_ips_independent() {
        let rl = RateLimiter::new(1.0, 1);
        assert!(rl.allow(ip(1)));
        assert!(rl.allow(ip(2)));
    }

    #[test]
    fn zero_rate_disables_and_tracks_nothing() {
        let rl = RateLimiter::new(0.0, 1);
        for _ in 0..1000 {
            assert!(rl.allow(ip(1)));
        }
        assert_eq!(rl.ips_count(), 0);
    }

    #[test]
    fn sweep_removes_fully_recovered_buckets() {
        let rl = RateLimiter::new(1000.0, 1);
        assert!(rl.allow(ip(1)));
        sleep(std::time::Duration::from_millis(10));
        rl.sweep();
        assert_eq!(rl.ips_count(), 0);
    }

    #[test]
    fn sweep_keeps_buckets_still_recovering() {
        let rl = RateLimiter::new(1.0, 5);
        for _ in 0..5 {
            assert!(rl.allow(ip(1)));
        }
        assert!(!rl.allow(ip(1)));
        rl.sweep();
        assert_eq!(
            rl.ips_count(),
            1,
            "bucket hasn't recovered yet, must not be swept"
        );
    }
}

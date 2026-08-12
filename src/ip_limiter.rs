//! Bounds how many connections a single client IP may have open at
//! once, independent of (and in addition to) the global
//! `ConnectionLimiter` in `limiter.rs`.
//!
//! Without this, a single peer can occupy an unbounded share of the
//! *global* connection slots just by opening many sockets and trickling
//! bytes in slowly (or not at all) until `handshake_timeout_secs` — the
//! global cap alone doesn't stop one IP from starving everyone else
//! while its own connections sit in the SNI-probe phase.
//!
//! Unlike `ConnectionLimiter` (one `Semaphore` sized once at startup),
//! this needs a *counter per IP*, created lazily on first sight and
//! removed again once it drops back to zero — so memory doesn't grow
//! unboundedly from the stream of scanner/bot IPs a public :443 port
//! attracts. It's also intentionally non-blocking: a single misbehaving
//! IP should be rejected immediately, not queued behind its own prior
//! connections the way the global limiter queues everyone fairly.

use hashbrown::HashMap;
use rustc_hash::FxBuildHasher;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

struct Inner {
    slots: Mutex<HashMap<IpAddr, usize, FxBuildHasher>>,
    /// `0` means "disabled" — every `try_acquire_slot` succeeds and nothing
    /// is tracked.
    max_per_ip: AtomicUsize,
}

/// RAII handle for one reserved per-IP slot. Dropping it (for any
/// reason: normal completion, early return, or a panic in the
/// connection task) decrements that IP's counter and, if it reaches
/// zero, removes the entry from the map — so idle IPs don't linger
/// there forever.
#[derive(Clone)]
pub struct IpSlot {
    addr: IpAddr,
    inner: Arc<Inner>,
}

/// Caps concurrent connections per client IP.
#[derive(Clone)]
pub struct IpLimiter {
    inner: Arc<Inner>,
}

impl Drop for IpSlot {
    fn drop(&mut self) {
        let mut slots = self.inner.slots.lock().expect("ip limiter lock poisoned");
        if let Some(slot) = slots.get_mut(&self.addr) {
            *slot -= 1;
            if (*slot) == 0 {
                slots.remove(&self.addr);
            }
        }
    }
}

impl IpLimiter {
    pub fn new(max_per_ip: usize) -> Self {
        let inner = Arc::new(Inner {
            slots: Mutex::new(HashMap::with_hasher(FxBuildHasher)),
            max_per_ip: AtomicUsize::new(max_per_ip),
        });
        Self { inner }
    }

    /// Tries to reserve a slot for `addr`. Returns `None` (reserving
    /// nothing) if `addr` already has `max_per_ip` connections open, or
    /// if `addr` itself is a loopback address (so metrics scraping and
    /// local health checks are never affected by this limit).
    pub fn try_acquire_slot(&self, addr: IpAddr) -> Option<IpSlot> {
        let max_per_ip = self.inner.max_per_ip.load(Ordering::Relaxed);
        if max_per_ip == 0 || addr.is_loopback() {
            // No limitation
            return Some(IpSlot {
                addr,
                inner: self.inner.clone(),
            });
        }

        {
            let mut slots = self.inner.slots.lock().expect("ip limiter lock poisoned");
            let slot_count = slots.entry(addr).or_insert(0);
            if *slot_count >= max_per_ip {
                return None;
            }

            *slot_count += 1;
        }

        Some(IpSlot {
            addr,
            inner: self.inner.clone(),
        })
    }

    pub fn set_limit(&self, max_per_ip: usize) {
        self.inner.max_per_ip.store(max_per_ip, Ordering::Relaxed);
    }

    /// Number of distinct IPs currently tracked (≥1 open connection).
    /// Handy as a gauge — lets an operator see the limiter is actually
    /// doing something under load, not just trust it's wired in right.
    #[allow(unused)]
    pub fn ips_count(&self) -> usize {
        self.inner
            .slots
            .lock()
            .expect("ip limiter lock poisoned")
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, n))
    }

    #[test]
    fn allows_up_to_the_limit_then_rejects() {
        let limiter = IpLimiter::new(2);
        let a = limiter.try_acquire_slot(ip(1));
        let b = limiter.try_acquire_slot(ip(1));
        let c = limiter.try_acquire_slot(ip(1));
        assert!(a.is_some());
        assert!(b.is_some());
        assert!(c.is_none());
    }

    #[test]
    fn different_ips_have_independent_counters() {
        let limiter = IpLimiter::new(1);
        assert!(limiter.try_acquire_slot(ip(1)).is_some());
        assert!(limiter.try_acquire_slot(ip(2)).is_some());
    }

    #[test]
    fn dropping_a_slot_frees_it_up_again() {
        let limiter = IpLimiter::new(1);
        let a = limiter.try_acquire_slot(ip(1));
        assert!(limiter.try_acquire_slot(ip(1)).is_none());
        drop(a);
        assert!(limiter.try_acquire_slot(ip(1)).is_some());
    }

    #[test]
    fn idle_ips_are_swept_from_the_map() {
        let limiter = IpLimiter::new(5);
        let a = limiter.try_acquire_slot(ip(1));
        assert_eq!(limiter.ips_count(), 1);
        drop(a);
        assert_eq!(limiter.ips_count(), 0);
    }

    #[test]
    fn zero_means_disabled() {
        let limiter = IpLimiter::new(0);
        for _ in 0..1000 {
            assert!(limiter.try_acquire_slot(ip(1)).is_some());
        }
        assert_eq!(limiter.ips_count(), 0);
    }

    #[test]
    fn set_max_per_ip_applies_to_subsequent_acquires() {
        let limiter = IpLimiter::new(1);
        let _a = limiter.try_acquire_slot(ip(1)).unwrap();
        assert!(limiter.try_acquire_slot(ip(1)).is_none());
        limiter.set_limit(2);
        assert!(limiter.try_acquire_slot(ip(1)).is_some());
    }
}

//! Step 6: Rate limit events to prevent DB/CPU overload.

use antidote_core::DropMetrics;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Simple sliding-window rate limiter: max N events per second.
pub struct RateLimiter {
    max_per_second: u32,
    count: AtomicU64,
    window_start: std::sync::Mutex<Instant>,
}

impl RateLimiter {
    pub fn new(max_per_second: u32) -> Self {
        Self {
            max_per_second,
            count: AtomicU64::new(0),
            window_start: std::sync::Mutex::new(Instant::now()),
        }
    }

    /// Returns true if the event should be allowed, false if it should be dropped.
    pub fn allow(&self) -> bool {
        let mut start = self.window_start.lock().unwrap();
        let now = Instant::now();
        if now.duration_since(*start) >= Duration::from_secs(1) {
            *start = now;
            self.count.store(0, Ordering::Relaxed);
        }
        let c = self.count.fetch_add(1, Ordering::Relaxed);
        c < self.max_per_second as u64
    }
}

/// Shared metrics for rate limiting (dropped count).
#[derive(Default)]
pub struct EventDropMetrics {
    pub dropped: AtomicU64,
}

impl EventDropMetrics {
    pub fn record_drop(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl DropMetrics for EventDropMetrics {
    fn get_dropped(&self) -> u64 {
        self.get()
    }
}

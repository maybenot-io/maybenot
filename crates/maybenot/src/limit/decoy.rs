use super::LimitDecoy;
use crate::MachineId;

/// A no-op limit that always allows decoys.
///
/// Use this when you don't want any framework-level decoy limiting. Per-machine
/// limits
/// ([`Machine::allowed_decoy_packets`](crate::Machine::allowed_decoy_packets))
/// still apply.
#[derive(Debug, Clone, Copy, Default)]
pub struct LimitDecoyNone;

impl<T: crate::time::Instant> LimitDecoy<T> for LimitDecoyNone {
    fn allow_decoy(&self, _current_time: T, _machine: MachineId) -> bool {
        true
    }

    fn max_decoys(&self, _current_time: T, _machine: MachineId) -> usize {
        usize::MAX
    }

    fn packet_sent(&mut self, _current_time: T) {}

    fn normal_queued(&mut self, _current_time: T) {}

    fn decoy_queued(&mut self, _current_time: T, _machine: MachineId) {}

    fn congestion(&mut self, _current_time: T) {}
}

/// A limit that restricts decoy traffic to a fraction of total queued traffic.
///
/// The ratio is computed as `decoy_queued / (decoy_queued + normal_queued)`.
/// Decoys are allowed when this ratio is below the configured limit.
#[derive(Debug, Clone, Copy)]
pub struct LimitDecoyFrac {
    limit: f64,
    decoy_queued: u64,
    normal_queued: u64,
}

impl LimitDecoyFrac {
    /// Creates a new `LimitDecoyFrac` with the given limit.
    ///
    /// # Panics
    ///
    /// Panics if `limit` is not in the range `[0.0, 1.0]`.
    pub fn new(limit: f64) -> Self {
        assert!((0.0..=1.0).contains(&limit), "limit must be in [0.0, 1.0]");
        Self {
            limit,
            decoy_queued: 0,
            normal_queued: 0,
        }
    }
}

impl<T: crate::time::Instant> LimitDecoy<T> for LimitDecoyFrac {
    fn allow_decoy(&self, _current_time: T, _machine: MachineId) -> bool {
        if self.limit == 0.0 {
            return false;
        }
        if self.limit == 1.0 {
            return true;
        }
        let total = self.decoy_queued + self.normal_queued;
        if total == 0 {
            return true;
        }
        (self.decoy_queued as f64 / total as f64) < self.limit
    }

    fn max_decoys(&self, _current_time: T, _machine: MachineId) -> usize {
        if self.limit == 0.0 {
            return 0;
        }
        if self.limit == 1.0 {
            return usize::MAX;
        }

        let total = self.decoy_queued + self.normal_queued;
        if total == 0 {
            // No traffic yet, allow unlimited
            return usize::MAX;
        }

        // We want max x such that (decoy + x) / (decoy + normal + x) < limit
        // Solving: x < limit * normal / (1 - limit) - decoy
        let max_allowed =
            self.limit * self.normal_queued as f64 / (1.0 - self.limit) - self.decoy_queued as f64;

        if max_allowed <= 0.0 {
            return 0;
        }

        // Since we need strict <, use a small epsilon to handle floating point
        // edge cases where max_allowed computes to exactly an integer
        let max_x = (max_allowed - 1e-9).max(0.0).floor();

        if max_x >= usize::MAX as f64 {
            usize::MAX
        } else {
            max_x as usize
        }
    }

    fn packet_sent(&mut self, _current_time: T) {}

    fn normal_queued(&mut self, _current_time: T) {
        self.normal_queued = self.normal_queued.saturating_add(1);
    }

    fn decoy_queued(&mut self, _current_time: T, _machine: MachineId) {
        self.decoy_queued = self.decoy_queued.saturating_add(1);
    }

    fn congestion(&mut self, _current_time: T) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn decoy_none_always_allows() {
        let t = LimitDecoyNone;
        let now = Instant::now();
        let mid = MachineId::from_raw(0);
        assert!(t.allow_decoy(now, mid));
        assert_eq!(t.max_decoys(now, mid), usize::MAX);
    }

    #[test]
    fn decoy_frac_zero() {
        let t = LimitDecoyFrac::new(0.0);
        assert!(!t.allow_decoy(Instant::now(), MachineId::from_raw(0)));
    }

    #[test]
    fn decoy_frac_one() {
        let t = LimitDecoyFrac::new(1.0);
        assert!(t.allow_decoy(Instant::now(), MachineId::from_raw(0)));
    }

    #[test]
    fn decoy_frac_half() {
        let mut t = LimitDecoyFrac::new(0.5);
        let now = Instant::now();
        // No traffic yet - allow
        assert!(t.allow_decoy(now, MachineId::from_raw(0)));
        // 1 normal, 0 decoy = 0% < 50% - allow
        t.normal_queued(now);
        assert!(t.allow_decoy(now, MachineId::from_raw(0)));
        // 1 normal, 1 decoy = 50% >= 50% - deny
        t.decoy_queued(now, MachineId::from_raw(0));
        assert!(!t.allow_decoy(now, MachineId::from_raw(0)));
    }

    #[test]
    fn decoy_frac_max_decoys() {
        let mut t = LimitDecoyFrac::new(0.5);
        let now = Instant::now();
        let mid = MachineId::from_raw(0);

        // No traffic yet - unlimited
        assert_eq!(t.max_decoys(now, mid), usize::MAX);

        // 1 normal, 0 decoy: can add 0 decoys (1/2 = 0.5 would hit limit)
        t.normal_queued(now);
        assert_eq!(t.max_decoys(now, mid), 0);

        // 2 normal, 0 decoy: can add 1 decoy (1/3 < 0.5, but 2/4 = 0.5 hits limit)
        t.normal_queued(now);
        assert_eq!(t.max_decoys(now, mid), 1);

        // 3 normal, 0 decoy: can add 2 decoys (2/5 = 0.4 < 0.5, but 3/6 = 0.5 hits)
        t.normal_queued(now);
        assert_eq!(t.max_decoys(now, mid), 2);

        // 3 normal, 1 decoy: can add 1 more (2/5 = 0.4 < 0.5, but 3/6 = 0.5 hits)
        t.decoy_queued(now, mid);
        assert_eq!(t.max_decoys(now, mid), 1);

        // 3 normal, 2 decoy: can add 0 more (already at 2/5 = 0.4, adding 1 -> 3/6 = 0.5)
        t.decoy_queued(now, mid);
        assert_eq!(t.max_decoys(now, mid), 0);

        // 3 normal, 3 decoy: over limit, 0 allowed
        t.decoy_queued(now, mid);
        assert_eq!(t.max_decoys(now, mid), 0);
    }

    #[test]
    fn decoy_frac_max_decoys_limit_zero() {
        let t = LimitDecoyFrac::new(0.0);
        assert_eq!(t.max_decoys(Instant::now(), MachineId::from_raw(0)), 0);
    }

    #[test]
    fn decoy_frac_max_decoys_limit_one() {
        let t = LimitDecoyFrac::new(1.0);
        assert_eq!(
            t.max_decoys(Instant::now(), MachineId::from_raw(0)),
            usize::MAX
        );
    }

    #[test]
    #[should_panic(expected = "limit must be in [0.0, 1.0]")]
    fn decoy_frac_invalid_limit_negative() {
        LimitDecoyFrac::new(-0.1);
    }

    #[test]
    #[should_panic(expected = "limit must be in [0.0, 1.0]")]
    fn decoy_frac_invalid_limit_over_one() {
        LimitDecoyFrac::new(1.1);
    }
}

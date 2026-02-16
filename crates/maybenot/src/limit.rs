//! Limit traits for controlling decoy and delay behavior in the framework.
//!
//! [`LimitDecoy`]: Controls decoy traffic generation through rate limiting and
//!   event notifications.
//!
//! [`LimitDecoyNone`]: A no-op implementation that always allows decoys.
//!
//! [`LimitDecoyFrac`]: An implementation that limits decoy traffic to a
//!   fraction of total queued traffic.

use crate::MachineId;

/// A trait for controlling decoy actions from an instance of the framework.
pub trait LimitDecoy<T: crate::time::Instant> {
    /// Returns true if a decoy action is allowed to be *scheduled* at the
    /// current time.
    ///
    /// If this function returns true, [`max_decoys`] SHOULD return > 0.
    fn allow_decoy(&self, current_time: T, machine: MachineId) -> bool;

    /// Returns the maximum number of decoy packets allowed to be scheduled.
    /// Return usize::MAX to let machines decide.
    ///
    /// If this function returns > 0, [`allow_decoy`] SHOULD return true.
    fn max_decoys(&self, current_time: T, machine: MachineId) -> usize;

    /// Called for every PacketSent event triggered in the framework.
    fn packet_sent(&mut self, current_time: T);

    /// Called for every NormalQueued event triggered in the framework.
    fn normal_queued(&mut self, current_time: T);

    /// Called for every DecoyQueued event triggered in the framework.
    fn decoy_queued(&mut self, current_time: T, machine: MachineId);

    /// Called for every Congestion event triggered in the framework.
    fn congestion(&mut self, _current_time: T);
}

/// Blanket impl allowing `Rc<RefCell<T>>` to be used as a decoy limit. This
/// enables a single type implementing both [`LimitDecoy`] and [`LimitDelay`] to
/// be shared between the two framework limit fields.
///
/// **Warning:** When a single `Rc<RefCell<T>>` is used for both limits,
/// [`congestion()`](LimitDecoy::congestion) will be called twice per
/// `Congestion` event (once via `LimitDecoy`, once via `LimitDelay`).
/// Implementations must guard against this (e.g., with a timestamp check).
impl<T, I> LimitDecoy<I> for std::rc::Rc<std::cell::RefCell<T>>
where
    T: LimitDecoy<I>,
    I: crate::time::Instant,
{
    fn allow_decoy(&self, current_time: I, machine: MachineId) -> bool {
        self.borrow().allow_decoy(current_time, machine)
    }

    fn max_decoys(&self, current_time: I, machine: MachineId) -> usize {
        self.borrow().max_decoys(current_time, machine)
    }

    fn packet_sent(&mut self, current_time: I) {
        self.borrow_mut().packet_sent(current_time)
    }

    fn normal_queued(&mut self, current_time: I) {
        self.borrow_mut().normal_queued(current_time)
    }

    fn decoy_queued(&mut self, current_time: I, machine: MachineId) {
        self.borrow_mut().decoy_queued(current_time, machine)
    }

    fn congestion(&mut self, current_time: I) {
        self.borrow_mut().congestion(current_time)
    }
}

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

/// A trait for controlling delay actions from an instance of the framework.
pub trait LimitDelay<T: crate::time::Instant> {
    /// Returns true if a delay action is allowed to be *scheduled* at the
    /// current time.
    ///
    /// If this function returns true, [`max_delayed_packets`] SHOULD return > 0
    /// and [`max_delayed_duration`] SHOULD NOT return T::Duration::is_zero()
    /// (i.e., a duration longer than 0).
    fn allow_delay(&self, current_time: T, machine: MachineId) -> bool;

    /// Returns the maximum number of delayed packets allowed to be scheduled.
    /// Return usize::MAX to let machines decide.
    ///
    /// If this function returns > 0, [`allow_delay`] SHOULD return true.
    fn max_delayed_packets(&self, current_time: T, machine: MachineId) -> usize;

    /// Returns the maximum delay duration allowed to be scheduled. Set to
    /// usize::MAX to let machines decide.
    ///
    /// If this function returns !T::Duration::is_zero(), [`allow_delay`] SHOULD
    /// return true.
    fn max_delayed_duration(&self, current_time: T, machine: MachineId) -> T::Duration;

    /// Called for every DelayBegin event triggered in the framework.
    fn delay_begin(&mut self, current_time: T);

    /// Called for every DelayEnd event triggered in the framework.
    fn delay_end(&mut self, current_time: T);

    /// Called for every Congestion event triggered in the framework.
    fn congestion(&mut self, _current_time: T) {}
}

/// Blanket impl allowing `Rc<RefCell<T>>` to be used as a delay limit. This
/// enables a single type implementing both [`LimitDecoy`] and [`LimitDelay`] to
/// be shared between the two framework limit fields.
///
/// **Warning:** When a single `Rc<RefCell<T>>` is used for both limits,
/// [`congestion()`](LimitDelay::congestion) will be called twice per
/// `Congestion` event (once via `LimitDecoy`, once via `LimitDelay`).
/// Implementations must guard against this (e.g., with a timestamp check).
impl<T, I> LimitDelay<I> for std::rc::Rc<std::cell::RefCell<T>>
where
    T: LimitDelay<I>,
    I: crate::time::Instant,
{
    fn allow_delay(&self, current_time: I, machine: MachineId) -> bool {
        self.borrow().allow_delay(current_time, machine)
    }

    fn max_delayed_packets(&self, current_time: I, machine: MachineId) -> usize {
        self.borrow().max_delayed_packets(current_time, machine)
    }

    fn max_delayed_duration(&self, current_time: I, machine: MachineId) -> I::Duration {
        self.borrow().max_delayed_duration(current_time, machine)
    }

    fn delay_begin(&mut self, current_time: I) {
        self.borrow_mut().delay_begin(current_time)
    }

    fn delay_end(&mut self, current_time: I) {
        self.borrow_mut().delay_end(current_time)
    }

    fn congestion(&mut self, current_time: I) {
        self.borrow_mut().congestion(current_time)
    }
}

/// A no-op limit that always allows delays.
///
/// Use this when you don't want any framework-level delay limiting. Per-machine
/// limits still apply.
#[derive(Debug, Clone, Copy, Default)]
pub struct LimitDelayNone;

impl<T: crate::time::Instant> LimitDelay<T> for LimitDelayNone {
    fn allow_delay(&self, _current_time: T, _machine: MachineId) -> bool {
        true
    }

    fn max_delayed_packets(&self, _current_time: T, _machine: MachineId) -> usize {
        usize::MAX
    }

    fn max_delayed_duration(&self, _current_time: T, _machine: MachineId) -> T::Duration {
        use crate::time::Duration;
        T::Duration::from_micros(u64::MAX)
    }

    fn delay_begin(&mut self, _current_time: T) {}

    fn delay_end(&mut self, _current_time: T) {}
}

/// A limit that restricts delay time to a fraction of a rolling time window.
///
/// Tracks how much time has been spent in delay within a configurable window,
/// and allows new delays only when the fraction is below the configured limit.
///
/// Note: Only one delay can be active at a time (shared connection). Multiple
/// `delay_begin` calls don't stack; `delay_end` always ends the current delay.
#[derive(Debug, Clone)]
pub struct LimitDelayFrac<T: crate::time::Instant> {
    limit: f64,
    window: T::Duration,
    max_packets: usize,
    completed_delays: std::collections::VecDeque<(T, T)>,
    ongoing_delay: Option<T>,
}

impl<T: crate::time::Instant> LimitDelayFrac<T> {
    /// Creates a new `LimitDelayFrac` with the given limit, window, and max
    /// packets.
    ///
    /// # Panics
    ///
    /// Panics if `limit` is not in the range `[0.0, 1.0]` or if `window` is
    /// zero.
    pub fn new(limit: f64, window: T::Duration, max_packets: usize) -> Self {
        use crate::time::Duration;
        assert!((0.0..=1.0).contains(&limit), "limit must be in [0.0, 1.0]");
        assert!(!window.is_zero(), "window must be non-zero");
        Self {
            limit,
            window,
            max_packets,
            completed_delays: std::collections::VecDeque::new(),
            ongoing_delay: None,
        }
    }

    /// Computes the fraction of the window that has been spent in delay.
    fn compute_delay_fraction(&self, current_time: T) -> f64 {
        use crate::time::Duration;

        let mut total_frac = 0.0;

        // Sum completed delay overlaps with [now - window, now]
        for &(begin, end) in &self.completed_delays {
            let ago_begin = current_time.saturating_duration_since(begin);
            let ago_end = current_time.saturating_duration_since(end);

            // begin_frac: how far back (as fraction of window) the delay
            // started clamped to 1.0 since delays starting before the window
            // only count from the window edge
            let begin_frac = ago_begin.div_duration_f64(self.window).min(1.0);
            // end_frac: how far back (as fraction of window) the delay ended
            let end_frac = ago_end.div_duration_f64(self.window);

            // The overlap is the difference
            let overlap_frac = begin_frac - end_frac;
            total_frac += overlap_frac;
        }

        // Add ongoing delay (from start to now)
        if let Some(start) = self.ongoing_delay {
            let ago_start = current_time.saturating_duration_since(start);
            // Clamp to window size
            let start_frac = ago_start.div_duration_f64(self.window).min(1.0);
            // End is now, so end_frac is 0
            total_frac += start_frac;
        }

        total_frac
    }

    /// Remove completed delays that are entirely outside the window.
    fn cleanup_old_delays(&mut self, current_time: T) {
        while let Some(&(_, end)) = self.completed_delays.front() {
            let ago_end = current_time.saturating_duration_since(end);
            if ago_end >= self.window {
                self.completed_delays.pop_front();
            } else {
                break;
            }
        }
    }
}

impl<T: crate::time::Instant> LimitDelay<T> for LimitDelayFrac<T> {
    fn allow_delay(&self, current_time: T, _machine: MachineId) -> bool {
        self.compute_delay_fraction(current_time) < self.limit
    }

    fn max_delayed_packets(&self, current_time: T, machine: MachineId) -> usize {
        if self.allow_delay(current_time, machine) {
            self.max_packets
        } else {
            0
        }
    }

    fn max_delayed_duration(&self, current_time: T, machine: MachineId) -> T::Duration {
        use crate::time::Duration;
        if self.allow_delay(current_time, machine) {
            T::Duration::from_micros(u64::MAX)
        } else {
            T::Duration::zero()
        }
    }

    fn delay_begin(&mut self, current_time: T) {
        if self.ongoing_delay.is_none() {
            self.ongoing_delay = Some(current_time);
        }
    }

    fn delay_end(&mut self, current_time: T) {
        if let Some(start) = self.ongoing_delay.take() {
            self.completed_delays.push_back((start, current_time));
            self.cleanup_old_delays(current_time);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

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

    #[test]
    fn delay_none_always_allows() {
        let t = LimitDelayNone;
        let now = Instant::now();
        let mid = MachineId::from_raw(0);
        assert!(t.allow_delay(now, mid));
        assert_eq!(t.max_delayed_packets(now, mid), usize::MAX);
        assert_eq!(
            t.max_delayed_duration(now, mid),
            Duration::from_micros(u64::MAX)
        );
    }

    #[test]
    fn delay_frac_limit_zero_never_allows() {
        let t: LimitDelayFrac<Instant> = LimitDelayFrac::new(0.0, Duration::from_secs(10), 100);
        let now = Instant::now();
        let mid = MachineId::from_raw(0);
        // Limit 0.0 means 0% < 0.0 is never true
        assert!(!t.allow_delay(now, mid));
        assert_eq!(t.max_delayed_packets(now, mid), 0);
        assert_eq!(t.max_delayed_duration(now, mid), Duration::ZERO);
    }

    #[test]
    fn delay_frac_limit_one_always_allows() {
        let t: LimitDelayFrac<Instant> = LimitDelayFrac::new(1.0, Duration::from_secs(10), 100);
        let now = Instant::now();
        let mid = MachineId::from_raw(0);
        // Initially no delay, 0% < 100% -> allow
        assert!(t.allow_delay(now, mid));
        assert_eq!(t.max_delayed_packets(now, mid), 100);
    }

    #[test]
    fn delay_frac_tracks_fraction() {
        let window = Duration::from_secs(10);
        let mut t: LimitDelayFrac<Instant> = LimitDelayFrac::new(0.5, window, 100);
        let mid = MachineId::from_raw(0);

        let start = Instant::now();

        // Initially 0% delay -> allow
        assert!(t.allow_delay(start, mid));

        // Start a delay
        t.delay_begin(start);

        // After 4 seconds (40% of window), still under 50%
        let after_4s = start + Duration::from_secs(4);
        assert!(t.allow_delay(after_4s, mid));

        // After 5 seconds (50% of window), not under 50% anymore
        let after_5s = start + Duration::from_secs(5);
        assert!(!t.allow_delay(after_5s, mid));

        // End the delay at 5s
        t.delay_end(after_5s);

        // Now we have 5s of completed delay in a 10s window = 50%, not allowed
        assert!(!t.allow_delay(after_5s, mid));

        // After 10s total (5s since delay ended), the delay is 5s out of
        // last 10s, so 50%, still not allowed
        let after_10s = start + Duration::from_secs(10);
        assert!(!t.allow_delay(after_10s, mid));

        // After 15s (the 5s delay is now 10-15s ago), part of it slides out
        // The delay was from t=0 to t=5, now at t=15
        // Window is [5, 15], delay overlap is [5, 5] = 0s
        let after_15s = start + Duration::from_secs(15);
        assert!(t.allow_delay(after_15s, mid));
    }

    #[test]
    fn delay_frac_window_expiration_cleanup() {
        let window = Duration::from_secs(10);
        let mut t: LimitDelayFrac<Instant> = LimitDelayFrac::new(0.5, window, 100);

        let start = Instant::now();

        // Create a short delay
        t.delay_begin(start);
        let after_1s = start + Duration::from_secs(1);
        t.delay_end(after_1s);

        // Verify it's tracked
        assert_eq!(t.completed_delays.len(), 1);

        // Create another delay much later (after window expires)
        let after_20s = start + Duration::from_secs(20);
        t.delay_begin(after_20s);
        let after_21s = start + Duration::from_secs(21);
        t.delay_end(after_21s);

        // Old delay should be cleaned up
        assert_eq!(t.completed_delays.len(), 1);
    }

    #[test]
    fn delay_frac_multiple_delay_begin_ignored() {
        let window = Duration::from_secs(10);
        let mut t: LimitDelayFrac<Instant> = LimitDelayFrac::new(0.5, window, 100);

        let start = Instant::now();
        t.delay_begin(start);

        // Second delay_begin should be ignored
        let after_2s = start + Duration::from_secs(2);
        t.delay_begin(after_2s);

        // End the delay
        let after_5s = start + Duration::from_secs(5);
        t.delay_end(after_5s);

        // Should have one completed delay from start (not after_2s) to after_5s
        assert_eq!(t.completed_delays.len(), 1);
        let (begin, end) = t.completed_delays[0];
        assert_eq!(begin, start);
        assert_eq!(end, after_5s);
    }

    #[test]
    fn delay_frac_delay_end_without_begin_ignored() {
        let window = Duration::from_secs(10);
        let mut t: LimitDelayFrac<Instant> = LimitDelayFrac::new(0.5, window, 100);

        let now = Instant::now();
        t.delay_end(now);

        // No delay should be recorded
        assert!(t.completed_delays.is_empty());
    }

    #[test]
    #[should_panic(expected = "limit must be in [0.0, 1.0]")]
    fn delay_frac_invalid_limit_negative() {
        let _: LimitDelayFrac<Instant> = LimitDelayFrac::new(-0.1, Duration::from_secs(10), 100);
    }

    #[test]
    #[should_panic(expected = "limit must be in [0.0, 1.0]")]
    fn delay_frac_invalid_limit_over_one() {
        let _: LimitDelayFrac<Instant> = LimitDelayFrac::new(1.1, Duration::from_secs(10), 100);
    }

    #[test]
    #[should_panic(expected = "window must be non-zero")]
    fn delay_frac_invalid_window_zero() {
        let _: LimitDelayFrac<Instant> = LimitDelayFrac::new(0.5, Duration::ZERO, 100);
    }

    #[test]
    fn joint_limit_shared_state() {
        use crate::Framework;
        use std::cell::RefCell;
        use std::rc::Rc;

        /// A joint limit that implements both LimitDecoy and LimitDelay,
        /// tracking total operations across both.
        struct JointLimit {
            operations: u64,
        }

        impl LimitDecoy<Instant> for JointLimit {
            fn allow_decoy(&self, _current_time: Instant, _machine: MachineId) -> bool {
                true
            }
            fn max_decoys(&self, _current_time: Instant, _machine: MachineId) -> usize {
                usize::MAX
            }
            fn packet_sent(&mut self, _current_time: Instant) {
                self.operations += 1;
            }
            fn normal_queued(&mut self, _current_time: Instant) {
                self.operations += 1;
            }
            fn decoy_queued(&mut self, _current_time: Instant, _machine: MachineId) {
                self.operations += 1;
            }
            fn congestion(&mut self, _current_time: Instant) {
                self.operations += 1;
            }
        }

        impl LimitDelay<Instant> for JointLimit {
            fn allow_delay(&self, _current_time: Instant, _machine: MachineId) -> bool {
                true
            }
            fn max_delayed_packets(&self, _current_time: Instant, _machine: MachineId) -> usize {
                usize::MAX
            }
            fn max_delayed_duration(
                &self,
                _current_time: Instant,
                _machine: MachineId,
            ) -> Duration {
                Duration::from_micros(u64::MAX)
            }
            fn delay_begin(&mut self, _current_time: Instant) {
                self.operations += 1;
            }
            fn delay_end(&mut self, _current_time: Instant) {
                self.operations += 1;
            }
            fn congestion(&mut self, _current_time: Instant) {
                self.operations += 1;
            }
        }

        let joint = Rc::new(RefCell::new(JointLimit { operations: 0 }));
        let machines: Vec<crate::Machine> = vec![];
        let now = Instant::now();
        let mut f =
            Framework::new(&machines, joint.clone(), joint.clone(), now, rand::rng()).unwrap();

        assert_eq!(joint.borrow().operations, 0);

        // NormalQueued triggers decoy_limit.normal_queued
        let _ = f.trigger_events(&[crate::TriggerEvent::NormalQueued], now);
        assert_eq!(joint.borrow().operations, 1);

        // PacketSent triggers decoy_limit.packet_sent
        let _ = f.trigger_events(&[crate::TriggerEvent::PacketSent], now);
        assert_eq!(joint.borrow().operations, 2);

        // DelayBegin triggers delay_limit.delay_begin (shared state!)
        let _ = f.trigger_events(
            &[crate::TriggerEvent::DelayBegin {
                machine: MachineId::from_raw(0),
            }],
            now,
        );
        assert_eq!(joint.borrow().operations, 3);

        // DelayEnd triggers delay_limit.delay_end (shared state!)
        let _ = f.trigger_events(&[crate::TriggerEvent::DelayEnd], now);
        assert_eq!(joint.borrow().operations, 4);

        // Congestion triggers both congestion() methods (shared state, called twice!)
        let _ = f.trigger_events(&[crate::TriggerEvent::Congestion], now);
        assert_eq!(joint.borrow().operations, 6);
    }
}

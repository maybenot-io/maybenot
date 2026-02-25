use super::LimitDelay;
use crate::{LimitError, MachineId};

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
    /// # Errors
    ///
    /// Returns [`LimitError::InvalidLimit`] if `limit` is not in `[0.0, 1.0]`,
    /// or [`LimitError::InvalidWindow`] if `window` is zero.
    pub fn new(limit: f64, window: T::Duration, max_packets: usize) -> Result<Self, LimitError> {
        use crate::time::Duration;
        if !(0.0..=1.0).contains(&limit) {
            return Err(LimitError::InvalidLimit);
        }
        if window.is_zero() {
            return Err(LimitError::InvalidWindow);
        }
        Ok(Self {
            limit,
            window,
            max_packets,
            completed_delays: std::collections::VecDeque::new(),
            ongoing_delay: None,
        })
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
        let t: LimitDelayFrac<Instant> =
            LimitDelayFrac::new(0.0, Duration::from_secs(10), 100).unwrap();
        let now = Instant::now();
        let mid = MachineId::from_raw(0);
        // Limit 0.0 means 0% < 0.0 is never true
        assert!(!t.allow_delay(now, mid));
        assert_eq!(t.max_delayed_packets(now, mid), 0);
        assert_eq!(t.max_delayed_duration(now, mid), Duration::ZERO);
    }

    #[test]
    fn delay_frac_limit_one_always_allows() {
        let t: LimitDelayFrac<Instant> =
            LimitDelayFrac::new(1.0, Duration::from_secs(10), 100).unwrap();
        let now = Instant::now();
        let mid = MachineId::from_raw(0);
        // Initially no delay, 0% < 100% -> allow
        assert!(t.allow_delay(now, mid));
        assert_eq!(t.max_delayed_packets(now, mid), 100);
    }

    #[test]
    fn delay_frac_tracks_fraction() {
        let window = Duration::from_secs(10);
        let mut t: LimitDelayFrac<Instant> = LimitDelayFrac::new(0.5, window, 100).unwrap();
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
        let mut t: LimitDelayFrac<Instant> = LimitDelayFrac::new(0.5, window, 100).unwrap();

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
        let mut t: LimitDelayFrac<Instant> = LimitDelayFrac::new(0.5, window, 100).unwrap();

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
        let mut t: LimitDelayFrac<Instant> = LimitDelayFrac::new(0.5, window, 100).unwrap();

        let now = Instant::now();
        t.delay_end(now);

        // No delay should be recorded
        assert!(t.completed_delays.is_empty());
    }

    #[test]
    fn delay_frac_invalid_limit_negative() {
        assert_eq!(
            LimitDelayFrac::<Instant>::new(-0.1, Duration::from_secs(10), 100).unwrap_err(),
            crate::limit::LimitError::InvalidLimit
        );
    }

    #[test]
    fn delay_frac_invalid_limit_over_one() {
        assert_eq!(
            LimitDelayFrac::<Instant>::new(1.1, Duration::from_secs(10), 100).unwrap_err(),
            crate::limit::LimitError::InvalidLimit
        );
    }

    #[test]
    fn delay_frac_invalid_window_zero() {
        assert_eq!(
            LimitDelayFrac::<Instant>::new(0.5, Duration::ZERO, 100).unwrap_err(),
            crate::limit::LimitError::InvalidWindow
        );
    }
}

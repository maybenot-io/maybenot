//! Rate-limited wrapper for the Maybenot framework.
//!
//! This module provides a [`RateLimitedFramework`] that wraps the core [`Framework`]
//! to add rate limiting capabilities. The rate limiter uses a sliding window algorithm
//! to limit the number of actions returned per second, helping prevent abuse and
//! excessive resource consumption.
//!
//! The sliding window algorithm is based on the approach described in Cloudflare's
//! blog post: <https://blog.cloudflare.com/counting-things-a-lot-of-different-things/>

use crate::time::{Duration, Instant};
use crate::{Framework, Machine, TriggerAction, TriggerEvent};
use rand_core::RngCore;
use std::ops::Sub;
use std::time::Instant as StdInstant;

/// A rate-limited wrapper around the Maybenot framework.
///
/// This struct wraps a [`Framework`] and applies rate limiting to the actions
/// returned by [`trigger_events`](Self::trigger_events). It uses a sliding window
/// algorithm to track the rate of events and blocks actions when the rate exceeds
/// the specified limit.
///
/// The rate limiter tracks events across a 1-second sliding window, using the
/// previous window's count and the current window's count to calculate the
/// effective rate. This approach prevents burst traffic from overwhelming the
/// system while allowing sustained traffic up to the limit.
///
/// # Example
/// ```
/// use maybenot::{Framework, RateLimitedFramework, Machine, TriggerEvent};
/// use std::time::Instant;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let machines = vec![];
/// let framework = Framework::new(machines, 0.0, 0.0, Instant::now(), rand::rng())?;
/// let mut rate_limited = RateLimitedFramework::new(framework);
///
/// let events = [TriggerEvent::NormalSent];
/// let actions: Vec<_> = rate_limited
///     .trigger_events(&events, 10.0, Instant::now())
///     .collect();
/// # Ok(())
/// # }
/// ```
pub struct RateLimitedFramework<M, R, T = StdInstant>
where
    M: AsRef<[Machine]>,
    R: RngCore,
    T: Instant,
    T::Duration: Sub<Output = T::Duration>,
{
    framework: Framework<M, R, T>,
    /// Count of events in the previous 1-second window
    prev: f64,
    /// Count of events in the current 1-second window
    current: f64,
    /// Start time of the current 1-second window
    tick: T,
}

impl<M, R, T> RateLimitedFramework<M, R, T>
where
    M: AsRef<[Machine]>,
    R: RngCore,
    T: Instant,
    T::Duration: Sub<Output = T::Duration>,
{
    /// Creates a new rate-limited framework wrapper.
    ///
    /// Initializes the rate limiter with zero counts for both the previous and
    /// current windows, and sets the current window start time to the framework's
    /// current time.
    ///
    /// # Arguments
    /// * `framework` - The underlying framework to wrap with rate limiting
    ///
    /// # Returns
    /// A new `RateLimitedFramework` instance
    pub fn new(framework: Framework<M, R, T>) -> Self {
        let tick = framework.current_time;

        Self {
            framework,
            prev: 0.0,
            current: 0.0,
            tick,
        }
    }

    /// Triggers events in the framework with rate limiting applied.
    ///
    /// This method forwards events to the underlying framework and applies rate
    /// limiting to the returned actions. It uses a sliding window algorithm to
    /// track the rate of events over time and blocks actions when the rate exceeds
    /// the specified limit.
    ///
    /// The sliding window calculation uses the formula from Cloudflare's approach:
    /// `rate = (prev * (1s - elapsed) / 1s) + current`
    ///
    /// Events are always processed (allowing machines to transition states), but
    /// actions may be dropped if the rate limit is exceeded.
    ///
    /// # Arguments
    /// * `events` - The events to trigger in the framework
    /// * `max_actions_per_second` - Maximum allowed actions per second
    /// * `current_time` - The current time for rate window calculations
    ///
    /// # Returns
    /// An iterator over the allowed actions (may be empty if rate limited)
    pub fn trigger_events(
        &mut self,
        events: &[TriggerEvent],
        max_actions_per_second: f64,
        current_time: T,
    ) -> impl Iterator<Item = &TriggerAction<T>> {
        let window_1s = Duration::from_micros(1_000_000);

        // We always trigger events since that can cause machines to transition,
        // we just rate limit the returned actions. If the user of the framework
        // cannot keep up, they're supposed to first start batching their
        // events, then tail drop old events worst-case.
        #[allow(unused_must_use)]
        self.framework.trigger_events(events, current_time);

        let delta = current_time.saturating_duration_since(self.tick);
        // are we in the current potentially busy window?
        if delta < window_1s {
            // simple sliding window like cloudflare uses/used,
            // https://blog.cloudflare.com/counting-things-a-lot-of-different-things/
            // , assuming previous hits were uniformly distributed
            let rate = (self.prev * (window_1s - delta).div_duration_f64(window_1s)) + self.current;
            if rate >= max_actions_per_second {
                // over rate, fill actions with None (dropping all actions)
                self.framework.actions.fill(None);
            }
        } else {
            if delta.div_duration_f64(window_1s) < 2.0 {
                // we are still in the next window, save previous count
                self.prev = self.current;
            } else {
                // long duration since last trigger, reset previous count
                self.prev = 0.0;
            }
            // start new window
            self.tick = current_time;
            self.current = 0.0;
        }

        self.current += self
            .framework
            .actions
            .iter()
            .filter(|a| a.is_some())
            .count() as f64;
        self.framework
            .actions
            .iter()
            .filter_map(|action| action.as_ref())
    }

    /// Returns a reference to the underlying framework.
    ///
    /// This provides read-only access to the wrapped framework instance.
    pub fn framework(&self) -> &Framework<M, R, T> {
        &self.framework
    }

    /// Returns a mutable reference to the underlying framework.
    ///
    /// This provides mutable access to the wrapped framework instance for
    /// advanced use cases that need to modify the framework state directly.
    pub fn framework_mut(&mut self) -> &mut Framework<M, R, T> {
        &mut self.framework
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::Action;
    use crate::dist::{Dist, DistType};
    use crate::event::Event;
    use crate::state::{State, Trans};
    use crate::{Framework, Machine, MachineId, TriggerEvent};
    use enum_map::enum_map;
    use std::time::Instant as StdInstant;

    fn create_test_framework() -> Framework<Vec<Machine>, rand::rngs::ThreadRng, StdInstant> {
        let mut state = State::new(enum_map! {
            Event::PaddingSent => vec![Trans(0, 1.0)],
        _ => vec![],
        });
        state.action = Some(Action::SendPadding {
            bypass: false,
            replace: false,
            timeout: Dist {
                dist: DistType::Uniform {
                    low: 0.0,
                    high: 0.0,
                },
                start: 0.0,
                max: 0.0,
            },
            limit: None,
        });

        let m = Machine::new(1_000_000, 0.0, 0, 0.0, vec![state]).unwrap();
        Framework::new(vec![m], 0.0, 0.0, StdInstant::now(), rand::rng()).unwrap()
    }

    #[test]
    fn test_new() {
        let framework = create_test_framework();
        let rate_limited = RateLimitedFramework::new(framework);

        assert_eq!(rate_limited.prev, 0.0);
        assert_eq!(rate_limited.current, 0.0);
    }

    #[test]
    fn test_framework_accessors() {
        let framework = create_test_framework();
        let mut rate_limited = RateLimitedFramework::new(framework);

        let _framework_ref = rate_limited.framework();
        let _framework_mut_ref = rate_limited.framework_mut();
    }

    #[test]
    fn test_rate_limiting_under_limit() {
        let framework = create_test_framework();
        let mut rate_limited = RateLimitedFramework::new(framework);

        let events = [TriggerEvent::PaddingSent {
            machine: MachineId::from_raw(0),
        }];
        let max_rate = 10.0;
        let current_time = StdInstant::now();

        let _actions: Vec<_> = rate_limited
            .trigger_events(&events, max_rate, current_time)
            .collect();

        assert_eq!(rate_limited.current, 1.0);
    }

    #[test]
    fn test_rate_limiting_over_limit() {
        let framework = create_test_framework();
        let mut rate_limited = RateLimitedFramework::new(framework);

        let events = [TriggerEvent::PaddingSent {
            machine: MachineId::from_raw(0),
        }];
        let max_rate = 0.5;
        let current_time = StdInstant::now();

        rate_limited.current = 1.0;

        let _actions: Vec<_> = rate_limited
            .trigger_events(&events, max_rate, current_time)
            .collect();

        assert_eq!(rate_limited.current, 1.0);
    }

    #[test]
    fn test_sliding_window_within_current_window() {
        let framework = create_test_framework();
        let mut rate_limited = RateLimitedFramework::new(framework);

        rate_limited.prev = 2.0;
        rate_limited.current = 1.0;

        let events = [TriggerEvent::PaddingSent {
            machine: MachineId::from_raw(0),
        }];
        let max_rate = 2.0;
        let current_time = rate_limited.tick + std::time::Duration::from_millis(500);

        let _actions: Vec<_> = rate_limited
            .trigger_events(&events, max_rate, current_time)
            .collect();
    }

    #[test]
    fn test_sliding_window_next_window() {
        let framework = create_test_framework();
        let mut rate_limited = RateLimitedFramework::new(framework);

        rate_limited.current = 5.0;
        let original_tick = rate_limited.tick;

        let events = [TriggerEvent::PaddingSent {
            machine: MachineId::from_raw(0),
        }];
        let max_rate = 10.0;
        let current_time = rate_limited.tick + std::time::Duration::from_millis(1500);

        let _actions: Vec<_> = rate_limited
            .trigger_events(&events, max_rate, current_time)
            .collect();

        assert_eq!(rate_limited.prev, 5.0);
        assert_eq!(rate_limited.current, 1.0);
        assert!(rate_limited.tick > original_tick);
    }

    #[test]
    fn test_sliding_window_long_duration_reset() {
        let framework = create_test_framework();
        let mut rate_limited = RateLimitedFramework::new(framework);

        rate_limited.current = 5.0;

        let events = [TriggerEvent::PaddingSent {
            machine: MachineId::from_raw(0),
        }];
        let max_rate = 10.0;
        let current_time = rate_limited.tick + std::time::Duration::from_secs(3);

        let _actions: Vec<_> = rate_limited
            .trigger_events(&events, max_rate, current_time)
            .collect();

        assert_eq!(rate_limited.prev, 0.0);
        assert_eq!(rate_limited.current, 1.0);
    }

    #[test]
    fn test_multiple_events_increment_current() {
        let framework = create_test_framework();
        let mut rate_limited = RateLimitedFramework::new(framework);

        let events = [TriggerEvent::PaddingSent {
            machine: MachineId::from_raw(0),
        }];
        let max_rate = 10.0;
        let current_time = StdInstant::now();

        rate_limited
            .trigger_events(&events, max_rate, current_time)
            .count();
        rate_limited
            .trigger_events(&events, max_rate, current_time)
            .count();
        rate_limited
            .trigger_events(&events, max_rate, current_time)
            .count();

        assert_eq!(rate_limited.current, 3.0);
    }

    #[test]
    fn test_actions_returned_when_under_rate_limit() {
        let framework = create_test_framework();
        let mut rate_limited = RateLimitedFramework::new(framework);

        let events = [TriggerEvent::PaddingSent {
            machine: crate::MachineId::from_raw(0),
        }];
        let max_rate = 10.0;
        let current_time = StdInstant::now();

        let actions: Vec<_> = rate_limited
            .trigger_events(&events, max_rate, current_time)
            .collect();

        assert!(!actions.is_empty());
        assert_eq!(rate_limited.current, 1.0);
    }

    #[test]
    fn test_actions_blocked_when_over_rate_limit() {
        let framework = create_test_framework();
        let mut rate_limited = RateLimitedFramework::new(framework);

        rate_limited.current = 2.0;

        let events = [TriggerEvent::PaddingSent {
            machine: crate::MachineId::from_raw(0),
        }];
        let max_rate = 1.0;
        let current_time = StdInstant::now();

        let actions: Vec<_> = rate_limited
            .trigger_events(&events, max_rate, current_time)
            .collect();

        assert!(actions.is_empty());
        assert_eq!(rate_limited.current, 2.0);
    }

    #[test]
    fn test_rate_limiting_with_sliding_window_calculation() {
        let framework = create_test_framework();
        let mut rate_limited = RateLimitedFramework::new(framework);

        rate_limited.prev = 3.0;
        rate_limited.current = 1.0;

        let events = [TriggerEvent::PaddingSent {
            machine: MachineId::from_raw(0),
        }];
        let max_rate = 2.5;
        let current_time = rate_limited.tick + std::time::Duration::from_millis(250);

        let actions: Vec<_> = rate_limited
            .trigger_events(&events, max_rate, current_time)
            .collect();

        assert!(actions.is_empty());
        assert_eq!(rate_limited.current, 1.0);
    }

    #[test]
    fn test_repeated_triggers_with_rate_limit_5() {
        let framework = create_test_framework();
        let mut rate_limited = RateLimitedFramework::new(framework);

        let events = [TriggerEvent::PaddingSent {
            machine: MachineId::from_raw(0),
        }];
        let max_rate = 5.0;
        let current_time = StdInstant::now();

        for i in 1..=5 {
            let actions: Vec<_> = rate_limited
                .trigger_events(&events, max_rate, current_time)
                .collect();
            assert!(!actions.is_empty(), "Expected actions on iteration {}", i);
            assert_eq!(rate_limited.current, i as f64);
        }

        let actions: Vec<_> = rate_limited
            .trigger_events(&events, max_rate, current_time)
            .collect();
        assert!(actions.is_empty(), "Expected no actions when over limit");
        assert_eq!(rate_limited.current, 5.0);
    }
}

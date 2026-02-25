//! Limit traits for controlling decoy and delay behavior in the framework.
//!
//! [`LimitDecoy`]: Controls decoy traffic generation through rate limiting and
//!   event notifications.
//!
//! [`LimitDecoyNone`]: A no-op implementation that always allows decoys.
//!
//! [`LimitDecoyFrac`]: An implementation that limits decoy traffic to a
//!   fraction of total queued traffic.

pub mod decoy;
pub mod delay;

pub use decoy::{LimitDecoyFrac, LimitDecoyFracWindowed, LimitDecoyNone};
pub use delay::{LimitDelayFrac, LimitDelayNone};

/// Error returned by limit constructors when given invalid configuration.
#[derive(Debug, Clone, PartialEq)]
pub enum LimitError {
    /// The `limit` parameter must be in the range `[0.0, 1.0]`.
    InvalidLimit,
    /// The `window` parameter must not be zero.
    InvalidWindow,
}

impl std::fmt::Display for LimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LimitError::InvalidLimit => write!(f, "limit must be in [0.0, 1.0]"),
            LimitError::InvalidWindow => write!(f, "window must not be zero"),
        }
    }
}

impl std::error::Error for LimitError {}

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

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

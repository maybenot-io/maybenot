//! Actions for [`State`](crate::state) transitions.

use rand_core::RngCore;
use serde::{Deserialize, Serialize};

use crate::constants::{
    MAX_SAMPLED_BLOCK_DURATION, MAX_SAMPLED_DECOY_N, MAX_SAMPLED_TIMEOUT,
    MAX_SAMPLED_TIMER_DURATION, STATE_LIMIT_MAX,
};
use crate::{Error, MachineId, dist};
use std::fmt;
use std::hash::Hash;

use self::dist::Dist;

/// The different types of timers used by a [`Machine`](crate::Machine).
#[derive(Debug, Eq, Hash, PartialEq, Clone, Copy, Serialize, Deserialize)]
pub enum Timer {
    /// The scheduled timer for actions with a timeout.
    Action,
    /// The machine's internal timer, updated by the machine using the
    /// UpdateTimer action.
    Internal,
    /// Apply to all timers.
    All,
}

/// An Action happens upon transition to a [`State`](crate::state). All actions
/// (except Cancel) can be limited. The limit is the maximum number of times the
/// action can be taken upon repeated transitions to the same state.
#[derive(PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Action {
    /// Cancel a timer.
    Cancel { timer: Timer },
    /// Schedule N decoy packets to be sent after a timeout.
    ///
    /// Replaces any previously pending scheduled action timer (set via
    /// DecoyTraffic or BlockOutgoing) for this machine.
    ///
    /// The bypass flag determines if the decoy packet(s) MUST bypass any
    /// existing blocking that was triggered with the bypass flag set.
    ///
    /// The replace flag determines if the decoy packet(s) MAY be replaced by
    /// packets already queued to be sent at the time the decoy packet would be
    /// sent. This applies for data queued to be turned into normal (non-decoy)
    /// packets AND _any_ packet (decoy or normal) in the egress queue yet to be
    /// sent (i.e., before the PacketSent event is triggered). Such a packet
    /// could be in the queue due to ongoing blocking or just not being sent yet
    /// (e.g., due to CC). We assume that packets will be encrypted ASAP for the
    /// egress queue and we do not want to keep state around to distinguish
    /// decoy and non-decoy, hence, any packet. For an egress queue of Q queued
    /// packets and N decoy packets to send with replace set, if N > Q, add N-Q
    /// decoy packets. Do not keep any state to track if any packet in the
    /// egress queue has been counted for replace decoy traffic or not across
    /// multiple DecoyTraffic actions.
    DecoyTraffic {
        bypass: bool,
        replace: bool,
        timeout: Dist,
        n: Dist,
        limit: Option<Dist>,
    },
    /// Schedule blocking of outgoing traffic after a timeout.
    ///
    /// Replaces any previously pending scheduled action timer (set via
    /// DecoyTraffic or BlockOutgoing) for this machine.
    ///
    /// The bypass flag determines if decoy actions are allowed to bypass this
    /// blocking action. This allows for machines that can fail closed (never
    /// bypass blocking) while simultaneously providing support for
    /// constant-rate defenses, when set along with the replace flag.
    ///
    /// The replace flag determines if the action duration MUST replace any
    /// existing blocking. Note that the blocking with the replace flag is
    /// always allowed if blocking is currently active, regardless of any limits
    /// set. This is to make it possible to create a machine that is guaranteed
    /// to prevent indefinite blocking (but comes at the cost of making it
    /// possible for a machine that indefinitely refresh blocking by using the
    /// replace flag).
    BlockOutgoing {
        bypass: bool,
        replace: bool,
        timeout: Dist,
        duration: Dist,
        limit: Option<Dist>,
    },
    /// Update the timer duration for a machine.
    ///
    /// The replace flag determines if the action duration MUST replace the
    /// current timer duration, if the timer has already been set.
    UpdateTimer {
        replace: bool,
        duration: Dist,
        limit: Option<Dist>,
    },
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:#?}")
    }
}

impl Action {
    /// Sample a timeout for a decoy or blocking action.
    pub(crate) fn sample_timeout<R: RngCore>(&self, rng: &mut R) -> u64 {
        match self {
            Action::DecoyTraffic { timeout, .. } | Action::BlockOutgoing { timeout, .. } => {
                timeout.sample(rng).min(MAX_SAMPLED_TIMEOUT).round() as u64
            }
            _ => 0,
        }
    }

    /// Sample a duration for a blocking or timer update action.
    pub(crate) fn sample_duration<R: RngCore>(&self, rng: &mut R) -> u64 {
        match self {
            Action::BlockOutgoing { duration, .. } => {
                duration.sample(rng).min(MAX_SAMPLED_BLOCK_DURATION).round() as u64
            }
            Action::UpdateTimer { duration, .. } => {
                duration.sample(rng).min(MAX_SAMPLED_TIMER_DURATION).round() as u64
            }
            _ => 0,
        }
    }

    /// Sample the number of decoy packets for a decoy action.
    pub(crate) fn sample_decoy_n<R: RngCore>(&self, rng: &mut R) -> usize {
        match self {
            Action::DecoyTraffic { n: amount, .. } => {
                amount.sample(rng).min(MAX_SAMPLED_DECOY_N as f64).round() as usize
            }
            _ => 0,
        }
    }

    /// Sample a limit.
    pub(crate) fn sample_limit<R: RngCore>(&self, rng: &mut R) -> u64 {
        match self {
            Action::DecoyTraffic { limit, .. }
            | Action::BlockOutgoing { limit, .. }
            | Action::UpdateTimer { limit, .. } => {
                if limit.is_none() {
                    return STATE_LIMIT_MAX;
                }
                limit.unwrap().sample(rng).round() as u64
            }
            _ => STATE_LIMIT_MAX,
        }
    }

    /// Check if the action has a limit distribution.
    pub(crate) fn has_limit(&self) -> bool {
        match self {
            Action::DecoyTraffic { limit, .. }
            | Action::BlockOutgoing { limit, .. }
            | Action::UpdateTimer { limit, .. } => limit.is_some(),
            _ => false,
        }
    }

    /// Validate all distributions contained in this action, if any.
    pub fn validate(&self) -> Result<(), Error> {
        match self {
            Action::DecoyTraffic {
                timeout, n, limit, ..
            } => {
                timeout.validate()?;
                n.validate()?;
                if let Some(limit) = limit {
                    limit.validate()?;
                }
            }
            Action::BlockOutgoing {
                timeout,
                duration,
                limit,
                ..
            } => {
                timeout.validate()?;
                duration.validate()?;
                if let Some(limit) = limit {
                    limit.validate()?;
                }
            }
            Action::UpdateTimer {
                duration, limit, ..
            } => {
                duration.validate()?;
                if let Some(limit) = limit {
                    limit.validate()?;
                }
            }
            _ => {}
        }

        Ok(())
    }
}

/// The action to be taken by the framework user.
#[derive(PartialEq, Eq, Debug, Clone)]
pub enum TriggerAction<T: crate::time::Instant = std::time::Instant> {
    /// Cancel one or more timers for a machine.
    ///
    /// Depending on the value of `timer`, either the internal timer should be
    /// cancelled, the external timer should be cancelled, or both.
    ///
    /// Cancelling a timer does not cause a
    /// [`TriggerEvent::TimerEnd`](crate::TriggerEvent::TimerEnd) event.
    Cancel { machine: MachineId, timer: Timer },
    /// Schedule N decoy packets to be sent after the given timeout.
    ///
    /// The bypass flag indicates if the decoy packet(s) MUST be sent despite
    /// active blocking of outgoing traffic. Note that this is only allowed if
    /// the active blocking was set with the bypass flag set to true.
    ///
    /// The replace flag determines if the decoy packet(s) MAY be replaced by
    /// packets already queued to be sent at the time the decoy packet would be
    /// sent. This applies for data queued to be turned into normal (non-decoy)
    /// packets AND _any_ packet (decoy or normal) in the egress queue yet to be
    /// sent (i.e., before the PacketSent event is triggered). Such a packet
    /// could be in the queue due to ongoing blocking or just not being sent yet
    /// (e.g., due to CC). We assume that packets will be encrypted ASAP for the
    /// egress queue and we do not want to keep state around to distinguish
    /// decoy and non-decoy, hence, any packet. For an egress queue of Q queued
    /// packets and N decoy packets to send with replace set, if N > Q, add N-Q
    /// decoy packets. Do not keep any state to track if any packet in the
    /// egress queue has been counted for replace decoy traffic or not across
    /// multiple DecoyTraffic actions.
    ///
    /// If the bypass and replace flags are both set to true AND the active
    /// blocking may be bypassed, then non-decoy packets MAY replace the decoy
    /// packet AND bypass the active blocking.
    ///
    /// For each decoy packet queued, a corresponding
    /// [`TriggerEvent::DecoyQueued`](crate::TriggerEvent::DecoyQueued) event
    /// SHOULD always be triggered, with a matching MachineId, even if the decoy
    /// packet is replaced by another packet. (If the decoy packet is replaced
    /// by queueing a _new_ normal packet, then a `NormalQueued` should _also_
    /// be triggered, along with `DecoyQueued`.  If the decoy packet is
    /// "replaced" by noting the presence of an already queued packet, then no
    /// additional event besides `DecoyQueued` needs to be triggered.)
    ///
    /// Note that, since only one action timer per machine can be pending at a
    /// time, this `DecoyTraffic` action should replace any currently pending
    /// `DecoyTraffic` or `BlockOutgoing` action timer for this machine that has
    /// not yet expired.
    DecoyTraffic {
        timeout: T::Duration,
        n: usize,
        bypass: bool,
        replace: bool,
        machine: MachineId,
    },
    /// Schedule blocking of outgoing traffic after the given timeout for a
    /// machine. The duration of the blocking is specified. Note that the
    /// blocking is framework scoped, i.e., if there are multiple machines
    /// running, then the blocking will affect all of them.
    ///
    /// Whenever the given action timeout expires, a corresponding
    /// [`TriggerEvent::BlockingBegin`](crate::TriggerEvent::BlockingBegin)
    /// event should be triggered with the same MachineId, regardless of whether
    /// the current blocking was adjusted.
    ///
    /// The bypass flag indicates if the blocking of outgoing traffic can be
    /// bypassed by decoy packets with the bypass flag set to true.
    ///
    /// The replace flag indicates if the duration MUST replace any other
    /// currently ongoing blocking of outgoing traffic. If the flag is false,
    /// the longest of the two durations MUST be used.
    ///
    /// Whenever the blocking timer of outgoing traffic is replaced or adjusted,
    /// the "bypassable" status of the blocking is also replaced.
    ///
    /// Note that, since only one action timer per machine can be pending at a
    /// time, this `BlockOutgoing` action should replace any currently pending
    /// `BlockOutgoing` or `DecoyTraffic` action timer for this machine that has
    /// not yet expired.
    BlockOutgoing {
        timeout: T::Duration,
        duration: T::Duration,
        bypass: bool,
        replace: bool,
        machine: MachineId,
    },
    /// Update the duration of the internal timer for a machine.
    ///
    /// The replace flag specifies if the duration should replace the current
    /// timer duration. If the flag is false, the longest of the two durations
    /// MUST be used.
    ///
    /// Whenever an internal timer is created, and whenever the timer's duration
    /// is changed, a corresponding
    /// [`TriggerEvent::TimerBegin`](crate::TriggerEvent::TimerBegin) event
    /// should be triggered, with a matching [`MachineId`].
    ///
    /// Whenever an internal expires, a corresponding
    /// [`TriggerEvent::TimerEnd`](crate::TriggerEvent::TimerEnd) event should
    /// be triggered. with a matching [`MachineId`].
    UpdateTimer {
        duration: T::Duration,
        replace: bool,
        machine: MachineId,
    },
}

impl fmt::Display for TriggerAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:#?}")
    }
}

#[cfg(test)]
mod tests {
    use crate::{action::*, dist::DistType};

    #[test]
    fn validate_cancel_action() {
        // always valid

        // action timer
        let a = Action::Cancel {
            timer: Timer::Action,
        };

        let r = a.validate();
        assert!(r.is_ok());

        // machine's internal timer
        let a = Action::Cancel {
            timer: Timer::Internal,
        };

        let r = a.validate();
        assert!(r.is_ok());

        // all timers
        let a = Action::Cancel { timer: Timer::All };

        let r = a.validate();
        assert!(r.is_ok());
    }

    #[test]
    fn validate_decoy_action() {
        // valid DecoyTraffic action
        let mut a = Action::DecoyTraffic {
            bypass: false,
            replace: false,
            timeout: Dist {
                dist: DistType::Uniform {
                    low: 10.0,
                    high: 10.0,
                },
                start: 0.0,
                max: 0.0,
            },
            n: Dist {
                dist: DistType::Uniform {
                    low: 1.0,
                    high: 1.0,
                },
                start: 0.0,
                max: 0.0,
            },
            limit: Some(Dist {
                dist: DistType::Normal {
                    mean: 50.0,
                    stdev: 10.0,
                },
                start: 0.0,
                max: 0.0,
            }),
        };

        let r = a.validate();
        assert!(r.is_ok());

        // invalid timeout dist, not allowed
        if let Action::DecoyTraffic { timeout, .. } = &mut a {
            *timeout = Dist {
                dist: DistType::Uniform {
                    low: 15.0, // NOTE low > high
                    high: 5.0,
                },
                start: 0.0,
                max: 0.0,
            };
        }

        let r = a.validate();
        assert!(r.is_err());

        // repair timeout dist
        if let Action::DecoyTraffic { timeout, .. } = &mut a {
            *timeout = Dist {
                dist: DistType::Uniform {
                    low: 10.0,
                    high: 10.0,
                },
                start: 0.0,
                max: 0.0,
            };
        }

        // invalid limit dist, not allowed
        if let Action::DecoyTraffic { limit, .. } = &mut a {
            *limit = Some(Dist {
                dist: DistType::Uniform {
                    low: 15.0, // NOTE low > high
                    high: 5.0,
                },
                start: 0.0,
                max: 0.0,
            });
        }

        let r = a.validate();
        assert!(r.is_err());

        // repair limit dist
        if let Action::DecoyTraffic { limit, .. } = &mut a {
            *limit = Some(Dist {
                dist: DistType::Normal {
                    mean: 50.0,
                    stdev: 10.0,
                },
                start: 0.0,
                max: 0.0,
            });
        }

        // invalid amount dist, not allowed
        if let Action::DecoyTraffic { n: amount, .. } = &mut a {
            *amount = Dist {
                dist: DistType::Uniform {
                    low: 15.0, // NOTE low > high
                    high: 5.0,
                },
                start: 0.0,
                max: 0.0,
            };
        }

        let r = a.validate();
        assert!(r.is_err());
    }

    #[test]
    fn validate_blocking_action() {
        // valid BlockOutgoing action
        let mut a = Action::BlockOutgoing {
            bypass: false,
            replace: false,
            timeout: Dist {
                dist: DistType::Uniform {
                    low: 10.0,
                    high: 10.0,
                },
                start: 0.0,
                max: 0.0,
            },
            duration: Dist {
                dist: DistType::Uniform {
                    low: 10.0,
                    high: 10.0,
                },
                start: 0.0,
                max: 0.0,
            },
            limit: Some(Dist {
                dist: DistType::Normal {
                    mean: 50.0,
                    stdev: 10.0,
                },
                start: 0.0,
                max: 0.0,
            }),
        };

        let r = a.validate();
        assert!(r.is_ok());

        // invalid timeout dist, not allowed
        if let Action::BlockOutgoing { timeout, .. } = &mut a {
            *timeout = Dist {
                dist: DistType::Uniform {
                    low: 15.0, // NOTE low > high
                    high: 5.0,
                },

                start: 0.0,
                max: 0.0,
            };
        }

        let r = a.validate();
        assert!(r.is_err());

        // repair timeout dist
        if let Action::BlockOutgoing { timeout, .. } = &mut a {
            *timeout = Dist {
                dist: DistType::Uniform {
                    low: 10.0,
                    high: 10.0,
                },
                start: 0.0,
                max: 0.0,
            };
        }

        // invalid duration dist, not allowed
        if let Action::BlockOutgoing { duration, .. } = &mut a {
            *duration = Dist {
                dist: DistType::Uniform {
                    low: 15.0, // NOTE low > high
                    high: 5.0,
                },
                start: 0.0,
                max: 0.0,
            };
        }

        let r = a.validate();
        assert!(r.is_err());

        // repair duration dist
        if let Action::BlockOutgoing { duration, .. } = &mut a {
            *duration = Dist {
                dist: DistType::Uniform {
                    low: 10.0,
                    high: 10.0,
                },
                start: 0.0,
                max: 0.0,
            };
        }

        // invalid limit dist, not allowed
        if let Action::BlockOutgoing { limit, .. } = &mut a {
            *limit = Some(Dist {
                dist: DistType::Uniform {
                    low: 15.0, // NOTE low > high
                    high: 5.0,
                },
                start: 0.0,
                max: 0.0,
            });
        }

        let r = a.validate();
        assert!(r.is_err());
    }

    #[test]
    fn validate_update_timer_action() {
        // valid UpdateTimer action
        let mut a = Action::UpdateTimer {
            replace: true,
            duration: Dist {
                dist: DistType::Uniform {
                    low: 10.0,
                    high: 10.0,
                },
                start: 0.0,
                max: 0.0,
            },
            limit: Some(Dist {
                dist: DistType::Normal {
                    mean: 50.0,
                    stdev: 10.0,
                },
                start: 0.0,
                max: 0.0,
            }),
        };

        let r = a.validate();
        assert!(r.is_ok());

        // invalid action dist, not allowed
        if let Action::UpdateTimer { duration, .. } = &mut a {
            *duration = Dist {
                dist: DistType::Uniform {
                    low: 15.0, // NOTE low > high
                    high: 5.0,
                },
                start: 0.0,
                max: 0.0,
            };
        }

        let r = a.validate();
        assert!(r.is_err());

        // repair action dist
        if let Action::UpdateTimer { duration, .. } = &mut a {
            *duration = Dist {
                dist: DistType::Uniform {
                    low: 10.0,
                    high: 10.0,
                },
                start: 0.0,
                max: 0.0,
            };
        }

        // invalid limit dist, not allowed
        if let Action::UpdateTimer { limit, .. } = &mut a {
            *limit = Some(Dist {
                dist: DistType::Uniform {
                    low: 15.0, // NOTE low > high
                    high: 5.0,
                },
                start: 0.0,
                max: 0.0,
            });
        }

        let r = a.validate();
        assert!(r.is_err());
    }
}

//! Actions for [`State`](crate::state) transitions.

use rand_core::RngCore;
use serde::{Deserialize, Serialize};

use crate::constants::*;
use crate::*;
use std::fmt;
use std::hash::Hash;

use self::dist::Dist;

/// The different types of timers used by a [`Machine`].
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
    /// Schedule padding to be sent after a timeout.
    ///
    /// The bypass flag determines if the padding packet MUST bypass any
    /// existing blocking that was triggered with the bypass flag set.
    ///
    /// The replace flag determines if the padding packet MAY be replaced by a
    /// non-padding packet queued at the time the padding packet would be sent.
    SendPadding {
        bypass: bool,
        replace: bool,
        timeout: Dist,
        limit: Option<Dist>,
    },
    /// Schedule blocking of outgoing traffic after a timeout.
    ///
    /// The bypass flag determines if padding actions are allowed to bypass this
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
        write!(f, "{:#?}", self)
    }
}

impl Action {
    /// Sample a timeout for a padding or blocking action.
    pub(crate) fn sample_timeout<R: RngCore>(&self, rng: &mut R) -> u64 {
        match self {
            Action::SendPadding { timeout, .. } | Action::BlockOutgoing { timeout, .. } => {
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

    /// Sample a limit.
    pub(crate) fn sample_limit<R: RngCore>(&self, rng: &mut R) -> u64 {
        match self {
            Action::SendPadding { limit, .. }
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
            Action::SendPadding { limit, .. }
            | Action::BlockOutgoing { limit, .. }
            | Action::UpdateTimer { limit, .. } => limit.is_some(),
            _ => false,
        }
    }

    /// Validate all distributions contained in this action, if any.
    pub fn validate(&self) -> Result<(), Error> {
        match self {
            Action::SendPadding { timeout, limit, .. } => {
                timeout.validate()?;
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
    /// Cancel the timer for a machine.
    Cancel { machine: MachineId, timer: Timer },
    /// Schedule padding to be injected after the given timeout for a machine.
    ///
    /// The bypass flag indicates if the padding packet MUST be sent despite
    /// active blocking of outgoing traffic. Note that this is only allowed if
    /// the active blocking was set with the bypass flag set to true.
    ///
    /// The replace flag indicates if the padding packet MAY be replaced by an
    /// existing non-padding packet already queued for sending at the time the
    /// padding packet would be sent (egress queued) or about to be sent.
    ///
    /// If the bypass and replace flags are both set to true AND the active
    /// blocking may be bypassed, then non-padding packets MAY replace the
    /// padding packet AND bypass the active blocking.
    SendPadding {
        timeout: T::Duration,
        bypass: bool,
        replace: bool,
        machine: MachineId,
    },
    /// Schedule blocking of outgoing traffic after the given timeout for a
    /// machine. The duration of the blocking is specified.
    ///
    /// The bypass flag indicates if the blocking of outgoing traffic can be
    /// bypassed by padding packets with the bypass flag set to true.
    ///
    /// The replace flag indicates if the duration MUST replace any other
    /// currently ongoing blocking of outgoing traffic. If the flag is false,
    /// the longest of the two durations MUST be used.
    BlockOutgoing {
        timeout: T::Duration,
        duration: T::Duration,
        bypass: bool,
        replace: bool,
        machine: MachineId,
    },
    /// Update the timer duration for a machine.
    ///
    /// The replace flag specifies if the duration should replace the current
    /// timer duration. If the flag is false, the longest of the two durations
    /// MUST be used.
    UpdateTimer {
        duration: T::Duration,
        replace: bool,
        machine: MachineId,
    },
}

impl fmt::Display for TriggerAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#?}", self)
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
    fn validate_padding_action() {
        // valid SendPadding action
        let mut a = Action::SendPadding {
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
        if let Action::SendPadding { timeout, .. } = &mut a {
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
        if let Action::SendPadding { timeout, .. } = &mut a {
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
        if let Action::SendPadding { limit, .. } = &mut a {
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

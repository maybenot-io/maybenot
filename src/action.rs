//! Actions for [`State`](crate::state) transitions.

use serde::{Deserialize, Serialize};
use simple_error::bail;

use crate::constants::*;
use crate::dist::*;
use crate::framework::MachineId;
use std::error::Error;
use std::hash::Hash;
use std::time::Duration;

/// The different types of timers used by a [`Machine`](crate::machine).
#[derive(Debug, Eq, Hash, PartialEq, Clone, Copy, Serialize, Deserialize)]
pub enum Timer {
    /// The scheduled timer for actions with a timeout.
    Action,
    /// The machine timer updated by the machine using the UpdateTimer action.
    Machine,
    /// Apply to all timers.
    All,
}

/// An Action happens upon transition to a [`State`](crate::state).
#[derive(PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Action {
    /// Cancel a timer.
    Cancel { timer: Timer },
    /// Schedule padding to be injected.
    ///
    /// The bypass flag determines if the padding packet MUST bypass any
    /// existing blocking that was triggered with the bypass flag set.
    ///
    /// The replace flag determines if the padding packet MAY be replaced by a
    /// non-padding packet queued at the time the padding packet would be sent.
    InjectPadding {
        bypass: bool,
        replace: bool,
        timeout_dist: Dist,
        limit_dist: Dist,
    },
    /// Schedule blocking of outgoing traffic.
    ///
    /// The bypass flag determines if padding actions are allowed to bypass
    /// this blocking action. This allows for machines that can fail closed
    /// (never bypass blocking) while simultaneously providing support for
    /// constant-rate defenses, when set along with the replace flag.
    ///
    /// The replace flag determines if the action duration should replace any
    /// existing blocking.
    BlockOutgoing {
        bypass: bool,
        replace: bool,
        timeout_dist: Dist,
        action_dist: Dist,
        limit_dist: Dist,
    },
    /// Update the timer duration for a machine.
    ///
    /// The replace flag determines if the action duration should replace the
    /// current timer duration, if the timer has already been set.
    UpdateTimer {
        replace: bool,
        action_dist: Dist,
        limit_dist: Dist,
    },
}

impl Action {
    /// Sample a timeout for a padding or blocking action.
    pub fn sample_timeout(&self) -> Result<f64, Box<dyn Error + Send + Sync>> {
        match self {
            Action::InjectPadding { timeout_dist, .. }
            | Action::BlockOutgoing { timeout_dist, .. } => {
                Ok(timeout_dist.sample().min(MAX_SAMPLED_TIMEOUT))
            }
            _ => {
                bail!("can only sample a timeout for InjectPadding and BlockOutgoing actions");
            }
        }
    }

    /// Sample a duration for a blocking or timer update action.
    pub fn sample_duration(&self) -> Result<f64, Box<dyn Error + Send + Sync>> {
        match self {
            Action::BlockOutgoing { action_dist, .. } => {
                Ok(action_dist.sample().min(MAX_SAMPLED_BLOCK_DURATION))
            }
            Action::UpdateTimer { action_dist, .. } => {
                Ok(action_dist.sample().min(MAX_SAMPLED_TIMER_DURATION))
            }
            _ => {
                bail!("can only sample a duration for BlockOutgoing and UpdateTimer actions");
            }
        }
    }

    /// Sample a limit.
    pub fn sample_limit(&self) -> u64 {
        match self {
            Action::InjectPadding { limit_dist, .. }
            | Action::BlockOutgoing { limit_dist, .. }
            | Action::UpdateTimer { limit_dist, .. } => {
                if limit_dist.dist == DistType::None {
                    return STATE_LIMIT_MAX;
                }
                let s = limit_dist.sample().round() as u64;
                s.min(STATE_LIMIT_MAX)
            }
            _ => STATE_LIMIT_MAX,
        }
    }

    /// Returns true if this action does not have a limit dist or if
    /// its limit dist is DistType::None. In both cases, sample_limit()
    /// will return STATE_LIMIT_MAX.
    pub fn is_limit_none(&self) -> bool {
        match self {
            Action::InjectPadding { limit_dist, .. }
            | Action::BlockOutgoing { limit_dist, .. }
            | Action::UpdateTimer { limit_dist, .. } => limit_dist.dist == DistType::None,
            _ => true,
        }
    }

    /// Validate all distributions contained in this action, if any.
    /// Also ensure that required distributions are not DistType::None.
    pub fn validate(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        match self {
            Action::InjectPadding {
                timeout_dist,
                limit_dist,
                ..
            } => {
                timeout_dist.validate()?;
                if timeout_dist.dist == DistType::None {
                    bail!("must specify a timeout dist for InjectPadding actions");
                }
                limit_dist.validate()?;
            }
            Action::BlockOutgoing {
                timeout_dist,
                action_dist,
                limit_dist,
                ..
            } => {
                timeout_dist.validate()?;
                if timeout_dist.dist == DistType::None {
                    bail!("must specify a timeout dist for BlockOutgoing actions");
                }
                action_dist.validate()?;
                if action_dist.dist == DistType::None {
                    bail!("must specify an action dist for BlockOutgoing actions");
                }
                limit_dist.validate()?;
            }
            Action::UpdateTimer {
                action_dist,
                limit_dist,
                ..
            } => {
                action_dist.validate()?;
                if action_dist.dist == DistType::None {
                    bail!("must specify an action dist for UpdateTimer actions");
                }
                limit_dist.validate()?;
            }
            _ => {}
        }

        Ok(())
    }
}

/// The action to be taken by the framework user.
#[derive(PartialEq, Eq, Debug, Clone)]
pub enum TriggerAction {
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
    InjectPadding {
        timeout: Duration,
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
    /// The replace flag indicates if the duration should replace any other
    /// currently ongoing blocking of outgoing traffic. If the flag is false,
    /// the longest of the two durations MUST be used.
    BlockOutgoing {
        timeout: Duration,
        duration: Duration,
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
        duration: Duration,
        replace: bool,
        machine: MachineId,
    },
}

#[cfg(test)]
mod tests {
    use crate::action::*;

    #[test]
    fn validate_cancel_action() {
        // always valid

        // action timer
        let a = Action::Cancel {
            timer: Timer::Action,
        };

        let r = a.validate();
        assert!(r.is_ok());
        assert!(a.is_limit_none());

        // machine timer
        let a = Action::Cancel {
            timer: Timer::Machine,
        };

        let r = a.validate();
        assert!(r.is_ok());
        assert!(a.is_limit_none());

        // all timers
        let a = Action::Cancel { timer: Timer::All };

        let r = a.validate();
        assert!(r.is_ok());
        assert!(a.is_limit_none());
    }

    #[test]
    fn validate_padding_action() {
        // valid InjectPadding action
        let mut a = Action::InjectPadding {
            bypass: false,
            replace: false,
            timeout_dist: Dist {
                dist: DistType::Uniform,
                param1: 10.0,
                param2: 10.0,
                start: 0.0,
                max: 0.0,
            },
            limit_dist: Dist {
                dist: DistType::Normal,
                param1: 50.0,
                param2: 10.0,
                start: 0.0,
                max: 0.0,
            },
        };

        let r = a.validate();
        assert!(r.is_ok());
        assert!(!a.is_limit_none());

        // timeout dist DistType::None, not allowed
        if let Action::InjectPadding { timeout_dist, .. } = &mut a {
            *timeout_dist = Dist::new();
        }

        let r = a.validate();
        assert!(r.is_err());

        // invalid timeout dist, not allowed
        if let Action::InjectPadding { timeout_dist, .. } = &mut a {
            *timeout_dist = Dist {
                dist: DistType::Uniform,
                param1: 15.0, // NOTE param1 > param2
                param2: 5.0,
                start: 0.0,
                max: 0.0,
            };
        }

        let r = a.validate();
        assert!(r.is_err());

        // repair timeout dist
        if let Action::InjectPadding { timeout_dist, .. } = &mut a {
            *timeout_dist = Dist {
                dist: DistType::Uniform,
                param1: 10.0,
                param2: 10.0,
                start: 0.0,
                max: 0.0,
            };
        }

        // limit dist DistType::None, this is OK
        if let Action::InjectPadding { limit_dist, .. } = &mut a {
            *limit_dist = Dist::new();
        }

        let r = a.validate();
        assert!(r.is_ok());
        assert!(a.is_limit_none());

        // invalid limit dist, not allowed
        if let Action::InjectPadding { limit_dist, .. } = &mut a {
            *limit_dist = Dist {
                dist: DistType::Uniform,
                param1: 15.0, // NOTE param1 > param2
                param2: 5.0,
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
            timeout_dist: Dist {
                dist: DistType::Uniform,
                param1: 10.0,
                param2: 10.0,
                start: 0.0,
                max: 0.0,
            },
            action_dist: Dist {
                dist: DistType::Uniform,
                param1: 10.0,
                param2: 10.0,
                start: 0.0,
                max: 0.0,
            },
            limit_dist: Dist {
                dist: DistType::Normal,
                param1: 50.0,
                param2: 10.0,
                start: 0.0,
                max: 0.0,
            },
        };

        let r = a.validate();
        assert!(r.is_ok());
        assert!(!a.is_limit_none());

        // timeout dist DistType::None, not allowed
        if let Action::BlockOutgoing { timeout_dist, .. } = &mut a {
            *timeout_dist = Dist::new();
        }

        let r = a.validate();
        assert!(r.is_err());

        // invalid timeout dist, not allowed
        if let Action::BlockOutgoing { timeout_dist, .. } = &mut a {
            *timeout_dist = Dist {
                dist: DistType::Uniform,
                param1: 15.0, // NOTE param1 > param2
                param2: 5.0,
                start: 0.0,
                max: 0.0,
            };
        }

        let r = a.validate();
        assert!(r.is_err());

        // repair timeout dist
        if let Action::BlockOutgoing { timeout_dist, .. } = &mut a {
            *timeout_dist = Dist {
                dist: DistType::Uniform,
                param1: 10.0,
                param2: 10.0,
                start: 0.0,
                max: 0.0,
            };
        }

        // action dist DistType::None, not allowed
        if let Action::BlockOutgoing { action_dist, .. } = &mut a {
            *action_dist = Dist::new();
        }

        let r = a.validate();
        assert!(r.is_err());

        // invalid action dist, not allowed
        if let Action::BlockOutgoing { action_dist, .. } = &mut a {
            *action_dist = Dist {
                dist: DistType::Uniform,
                param1: 15.0, // NOTE param1 > param2
                param2: 5.0,
                start: 0.0,
                max: 0.0,
            };
        }

        let r = a.validate();
        assert!(r.is_err());

        // repair action dist
        if let Action::BlockOutgoing { action_dist, .. } = &mut a {
            *action_dist = Dist {
                dist: DistType::Uniform,
                param1: 10.0,
                param2: 10.0,
                start: 0.0,
                max: 0.0,
            };
        }

        // limit dist DistType::None, this is OK
        if let Action::BlockOutgoing { limit_dist, .. } = &mut a {
            *limit_dist = Dist::new();
        }

        let r = a.validate();
        assert!(r.is_ok());
        assert!(a.is_limit_none());

        // invalid limit dist, not allowed
        if let Action::BlockOutgoing { limit_dist, .. } = &mut a {
            *limit_dist = Dist {
                dist: DistType::Uniform,
                param1: 15.0, // NOTE param1 > param2
                param2: 5.0,
                start: 0.0,
                max: 0.0,
            };
        }

        let r = a.validate();
        assert!(r.is_err());
    }

    #[test]
    fn validate_update_timer_action() {
        // valid UpdateTimer action
        let mut a = Action::UpdateTimer {
            replace: true,
            action_dist: Dist {
                dist: DistType::Uniform,
                param1: 10.0,
                param2: 10.0,
                start: 0.0,
                max: 0.0,
            },
            limit_dist: Dist {
                dist: DistType::Normal,
                param1: 50.0,
                param2: 10.0,
                start: 0.0,
                max: 0.0,
            },
        };

        let r = a.validate();
        assert!(r.is_ok());
        assert!(!a.is_limit_none());

        // action dist DistType::None, not allowed
        if let Action::UpdateTimer { action_dist, .. } = &mut a {
            *action_dist = Dist::new();
        }

        let r = a.validate();
        assert!(r.is_err());

        // invalid action dist, not allowed
        if let Action::UpdateTimer { action_dist, .. } = &mut a {
            *action_dist = Dist {
                dist: DistType::Uniform,
                param1: 15.0, // NOTE param1 > param2
                param2: 5.0,
                start: 0.0,
                max: 0.0,
            };
        }

        let r = a.validate();
        assert!(r.is_err());

        // repair action dist
        if let Action::UpdateTimer { action_dist, .. } = &mut a {
            *action_dist = Dist {
                dist: DistType::Uniform,
                param1: 10.0,
                param2: 10.0,
                start: 0.0,
                max: 0.0,
            };
        }

        // limit dist DistType::None, this is OK
        if let Action::UpdateTimer { limit_dist, .. } = &mut a {
            *limit_dist = Dist::new();
        }

        let r = a.validate();
        assert!(r.is_ok());
        assert!(a.is_limit_none());

        // invalid limit dist, not allowed
        if let Action::UpdateTimer { limit_dist, .. } = &mut a {
            *limit_dist = Dist {
                dist: DistType::Uniform,
                param1: 15.0, // NOTE param1 > param2
                param2: 5.0,
                start: 0.0,
                max: 0.0,
            };
        }

        let r = a.validate();
        assert!(r.is_err());
    }
}

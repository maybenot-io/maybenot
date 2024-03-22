//! Actions for [`State`](crate::state) transitions.

use serde::{Deserialize, Serialize};

use crate::framework::MachineId;
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
#[derive(Debug, Eq, Hash, PartialEq, Clone, Copy, Serialize, Deserialize)]
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
    InjectPadding { bypass: bool, replace: bool },
    /// Schedule blocking of outgoing traffic.
    ///
    /// The bypass flag determines if padding actions are allowed to bypass
    /// this blocking action. This allows for machines that can fail closed
    /// (never bypass blocking) while simultaneously providing support for
    /// constant-rate defenses, when set along with the replace flag.
    ///
    /// The replace flag determines if the action duration should replace any
    /// existing blocking.
    BlockOutgoing { bypass: bool, replace: bool },
    /// Update the timer duration for a machine.
    ///
    /// The replace flag determines if the action duration should replace the
    /// current timer duration, if the timer has already been set.
    UpdateTimer { replace: bool },
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

//! Actions for [`State`](crate::state) transitions.

use serde::{Deserialize, Serialize};

use crate::framework::MachineId;
use std::hash::Hash;
use std::time::Duration;

/// An Action happens upon transition to a [`State`](crate::state).
#[derive(Debug, Eq, Hash, PartialEq, Clone, Copy, Serialize, Deserialize)]
pub enum Action {
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
    /// Increment or decrement one of the counters associated with a machine.
    ///
    /// The counter field indicates which of the machine's counters should be
    /// updated. It can be used for indexing and may not exceed
    /// [`COUNTERSPERMACHINE`](crate::constants) minus one.
    ///
    /// The decrement flag, when set, specifies that counter updates subtract
    /// from the counter's current value instead of adding to it.
    UpdateCounter { counter: usize, decrement: bool },
    /// Update the timer duration for a machine.
    ///
    /// The replace flag determines if the action duration should replace the
    /// current timer duration, if the timer has already been set.
    UpdateTimer { replace: bool },
}

/// The action to be taken by the framework user.
#[derive(PartialEq, Eq, Debug, Clone)]
pub enum TriggerAction {
    /// Stop any currently scheduled action for the machine.
    Cancel { machine: MachineId },
    /// Schedule padding to be injected after the given timeout for a machine.
    /// The size of the padding (in bytes) is specified - this will never be
    /// larger than the MTU.
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
        size: u16,
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
    /// Update the value of one of the counters for a machine.
    ///
    /// The counter field indicates which of the machine's counters should be
    /// updated. It ranges from zero to [`COUNTERSPERMACHINE`](crate::constants)
    /// minus one and can be used for indexing.
    ///
    /// The decrement flag determines whether to add to or subtract from the
    /// current counter value.
    UpdateCounter {
        value: u64,
        counter: usize,
        decrement: bool,
        machine: MachineId,
    },
    /// Update the timer duration for a machine.
    ///
    /// The replace flag specifies if the duration should replace the current
    /// timer duration. If the flag is false, the longest of the two durations
    /// MUST be used.
    ///
    /// If the new duration of the timer is zero, which can occur if it was
    /// previously zero or the replace flag is true, the TimerEnd event MUST
    /// NOT be triggered. This allows for silently canceling the timer.
    UpdateTimer {
        duration: Duration,
        replace: bool,
        machine: MachineId,
    },
}

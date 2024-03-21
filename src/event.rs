//! Events for [`State`](crate::state) transitions.

use serde::{Deserialize, Serialize};

use self::Event::*;
use crate::framework::MachineId;
use std::fmt;
use std::hash::Hash;
use std::slice::Iter;

/// An Event may trigger a [`State`](crate::state) transition.
#[derive(Debug, Eq, Hash, PartialEq, Clone, Copy, Serialize, Deserialize)]
pub enum Event {
    /// NonPaddingRecv is when we received non-padding.
    NonPaddingRecv,
    /// PaddingRecv is when we received padding.
    PaddingRecv,
    /// NonPaddingSent is when we sent non-padding.
    NonPaddingSent,
    /// PaddingSent is when we sent padding.
    PaddingSent,
    /// BlockingBegin is when blocking started.
    BlockingBegin,
    /// BlockingEnd is when blocking ended.
    BlockingEnd,
    /// LimitReached is when a limit in a state is reached (internal).
    LimitReached,
    /// CounterZero is when a machine's counter was decremented to zero.
    CounterZero,
    /// TimerBegin is when a machine's timer started.
    TimerBegin,
    /// TimerEnd is when a machine's timer expired.
    TimerEnd,
    /// NonPaddingQueued is when we queued non-padding.
    NonPaddingQueued,
    /// PaddingQueued is when we queued padding.
    PaddingQueued,
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Event {
    pub fn iter() -> Iter<'static, Event> {
        static EVENTS: [Event; 12] = [
            NonPaddingRecv,
            PaddingRecv,
            NonPaddingSent,
            PaddingSent,
            BlockingBegin,
            BlockingEnd,
            LimitReached,
            CounterZero,
            TimerBegin,
            TimerEnd,
            NonPaddingQueued,
            PaddingQueued,
        ];
        EVENTS.iter()
    }
}

/// Represents an event to be triggered in the framework.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum TriggerEvent {
    /// Received non-padding packet.
    NonPaddingRecv,
    /// Received padding packet.
    PaddingRecv,
    /// Sent non-padding packet.
    NonPaddingSent,
    /// Sent padding packet.
    PaddingSent { machine: MachineId },
    /// Blocking of outgoing traffic started by the action from a machine.
    BlockingBegin { machine: MachineId },
    /// Blocking of outgoing traffic stopped.
    BlockingEnd,
    /// A machine's counter was decremented to zero.
    CounterZero { machine: MachineId },
    /// A machine's timer started.
    TimerBegin { machine: MachineId },
    /// A machine's timer expired.
    TimerEnd { machine: MachineId },
    /// Queued non-padding packet.
    NonPaddingQueued,
    /// Queued padding packet.
    PaddingQueued { machine: MachineId },
}

impl TriggerEvent {
    /// Checks if the [`TriggerEvent`] is a particular [`Event`].
    pub fn is_event(&self, e: Event) -> bool {
        match self {
            TriggerEvent::NonPaddingRecv => e == Event::NonPaddingRecv,
            TriggerEvent::PaddingRecv => e == Event::PaddingRecv,
            TriggerEvent::NonPaddingSent => e == Event::NonPaddingSent,
            TriggerEvent::PaddingSent { .. } => e == Event::PaddingSent,
            TriggerEvent::BlockingBegin { .. } => e == Event::BlockingBegin,
            TriggerEvent::BlockingEnd => e == Event::BlockingEnd,
            TriggerEvent::CounterZero { .. } => e == Event::CounterZero,
            TriggerEvent::TimerBegin { .. } => e == Event::TimerBegin,
            TriggerEvent::TimerEnd { .. } => e == Event::TimerEnd,
            TriggerEvent::NonPaddingQueued => e == Event::NonPaddingQueued,
            TriggerEvent::PaddingQueued { .. } => e == Event::PaddingQueued,
        }
    }
}

impl fmt::Display for TriggerEvent {
    // note that we don't share the private MachineId
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TriggerEvent::NonPaddingRecv => write!(f, "rn"),
            TriggerEvent::PaddingRecv => write!(f, "rp"),
            TriggerEvent::NonPaddingSent => write!(f, "sn"),
            TriggerEvent::PaddingSent { .. } => write!(f, "sp"),
            TriggerEvent::BlockingBegin { .. } => write!(f, "bb"),
            TriggerEvent::BlockingEnd => write!(f, "be"),
            TriggerEvent::CounterZero { .. } => write!(f, "cz"),
            TriggerEvent::TimerBegin { .. } => write!(f, "tb"),
            TriggerEvent::TimerEnd { .. } => write!(f, "te"),
            TriggerEvent::NonPaddingQueued => write!(f, "qn"),
            TriggerEvent::PaddingQueued { .. } => write!(f, "qp"),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::event::*;
    #[test]
    fn v1_events() {
        assert_eq!(Event::NonPaddingRecv.to_string(), "NonPaddingRecv");
        assert_eq!(Event::PaddingRecv.to_string(), "PaddingRecv");
        assert_eq!(Event::NonPaddingSent.to_string(), "NonPaddingSent");
        assert_eq!(Event::PaddingSent.to_string(), "PaddingSent");
        assert_eq!(Event::BlockingBegin.to_string(), "BlockingBegin");
        assert_eq!(Event::BlockingEnd.to_string(), "BlockingEnd");
        assert_eq!(Event::LimitReached.to_string(), "LimitReached");
    }

    #[test]
    fn v2_events() {
        assert_eq!(Event::CounterZero.to_string(), "CounterZero");
        assert_eq!(Event::TimerBegin.to_string(), "TimerBegin");
        assert_eq!(Event::TimerEnd.to_string(), "TimerEnd");
        assert_eq!(Event::NonPaddingQueued.to_string(), "NonPaddingQueued");
        assert_eq!(Event::PaddingQueued.to_string(), "PaddingQueued");
    }
}

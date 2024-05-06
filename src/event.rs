//! Events for [`State`](crate::state) transitions.

use serde::{Deserialize, Serialize};

use self::Event::*;
use crate::{constants::*, MachineId};
use enum_map::Enum;
use std::fmt;
use std::hash::Hash;
use std::slice::Iter;

/// An Event may trigger a [`State`](crate::state) transition.
#[derive(Debug, Enum, Eq, Hash, PartialEq, Clone, Copy, Serialize, Deserialize)]
pub enum Event {
    /// NormalRecv is when we received a normal, non-padding packet.
    NormalRecv,
    /// PaddingRecv is when we received a padding packet.
    PaddingRecv,
    /// TunnelRecv is when we received a packet in the tunnel: because it is
    /// encrypted, we do not know if it is a normal or padding packet yet.
    TunnelRecv,
    /// NormalSent is when we sent a normal, non-padding packet.
    NormalSent,
    /// PaddingSent is when we sent a padding packet.
    PaddingSent,
    /// TunnelSent is when we sent a packet in the tunnel: because it is now
    /// encrypted, we do not know if it is a normal or padding packet anymore.
    TunnelSent,
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
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Event {
    pub fn iter() -> Iter<'static, Event> {
        static EVENTS: [Event; EVENT_NUM] = [
            NormalRecv,
            PaddingRecv,
            TunnelRecv,
            NormalSent,
            PaddingSent,
            TunnelSent,
            BlockingBegin,
            BlockingEnd,
            LimitReached,
            CounterZero,
            TimerBegin,
            TimerEnd,
        ];
        EVENTS.iter()
    }

    // to usize
    pub const fn to_usize(&self) -> usize {
        *self as usize
    }
}

/// Represents an event to be triggered in the framework.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum TriggerEvent {
    /// Received non-padding packet.
    NormalRecv,
    /// Received padding packet.
    PaddingRecv,
    /// Received packet in the tunnel.
    TunnelRecv,
    /// Sent non-padding packet.
    NormalSent,
    /// Sent padding packet.
    PaddingSent { machine: MachineId },
    /// Sent packet in the tunnel.
    TunnelSent,
    /// Blocking of outgoing traffic started by the action from a machine.
    BlockingBegin { machine: MachineId },
    /// Blocking of outgoing traffic stopped.
    BlockingEnd,
    /// A machine's timer started.
    TimerBegin { machine: MachineId },
    /// A machine's timer expired.
    TimerEnd { machine: MachineId },
}

impl TriggerEvent {
    /// Checks if the [`TriggerEvent`] is a particular [`Event`].
    pub fn is_event(&self, e: Event) -> bool {
        match self {
            TriggerEvent::NormalRecv => e == Event::NormalRecv,
            TriggerEvent::PaddingRecv => e == Event::PaddingRecv,
            TriggerEvent::NormalSent => e == Event::NormalSent,
            TriggerEvent::PaddingSent { .. } => e == Event::PaddingSent,
            TriggerEvent::BlockingBegin { .. } => e == Event::BlockingBegin,
            TriggerEvent::BlockingEnd => e == Event::BlockingEnd,
            TriggerEvent::TimerBegin { .. } => e == Event::TimerBegin,
            TriggerEvent::TimerEnd { .. } => e == Event::TimerEnd,
            TriggerEvent::TunnelSent => e == Event::TunnelSent,
            TriggerEvent::TunnelRecv => e == Event::TunnelRecv,
        }
    }
}

impl fmt::Display for TriggerEvent {
    // note that we don't share the private MachineId
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TriggerEvent::NormalRecv => write!(f, "rn"),
            TriggerEvent::PaddingRecv => write!(f, "rp"),
            TriggerEvent::TunnelRecv => write!(f, "rt"),
            TriggerEvent::NormalSent => write!(f, "sn"),
            TriggerEvent::PaddingSent { .. } => write!(f, "sp"),
            TriggerEvent::TunnelSent => write!(f, "st"),
            TriggerEvent::BlockingBegin { .. } => write!(f, "bb"),
            TriggerEvent::BlockingEnd => write!(f, "be"),
            TriggerEvent::TimerBegin { .. } => write!(f, "tb"),
            TriggerEvent::TimerEnd { .. } => write!(f, "te"),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::event::*;
    #[test]
    fn v1_events() {
        assert_eq!(Event::NormalRecv.to_string(), "NormalRecv");
        assert_eq!(Event::PaddingRecv.to_string(), "PaddingRecv");
        assert_eq!(Event::NormalSent.to_string(), "NormalSent");
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
        assert_eq!(Event::TunnelRecv.to_string(), "TunnelRecv");
        assert_eq!(Event::TunnelSent.to_string(), "TunnelSent");
    }
}

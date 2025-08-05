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
    /// Signal is when a machine transitioned to [`STATE_SIGNAL`](crate::constants).
    Signal,
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
            Signal,
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
    ///
    /// This event should be triggered once for each incoming non-padding packet,
    /// after `TunnelRecv`, as soon as we have identified the packet as non-padding.
    NormalRecv,
    /// Received padding packet.
    ///
    /// This event should be triggered once for each incoming padding packet,
    /// after `TunnelRecv`, as soon as we have identified the packet as padding.
    PaddingRecv,
    /// Received a complete packet in the tunnel.
    ///
    /// This event should be triggered once for each incoming packet of any type,
    /// as soon as possible after the packet is received from the network,
    /// before the packet is queued, processed, or decrypted.
    ///
    /// (No event should be generated for a partially read packet.)
    TunnelRecv,
    /// Sent non-padding packet.
    ///
    /// Thie event should be triggered once for each outgoing non-padding packet,
    /// as soon as we have decided put it on any internal queue.
    NormalSent,
    /// Sent padding packet.
    ///
    /// Thie event should be triggered once for each outgoing padding packet,
    /// as soon as we have decided put it on any internal queue.
    PaddingSent { machine: MachineId },
    /// Sent packet in the tunnel.
    ///
    /// This event should be triggered once for each outgoing packet of any type,
    /// after that packet's `NormalSent` or `PaddingSent` event,
    /// as close as possible to the time when it is actually written to the network.
    TunnelSent,
    /// Blocking of outgoing traffic started by the action from a machine.
    ///
    /// This event should be triggered whenever the action timer
    /// for a [`TriggerAction::BlockOutgoing`] action expires,
    /// whether the blocking timer is adjusted or not.
    ///
    /// [`TriggerAction::BlockOutgoing`]: crate::TriggerAction::BlockOutgoing
    BlockingBegin { machine: MachineId },
    /// Blocking of outgoing traffic has stopped.
    ///
    /// This event should be triggered when the framework-scoped
    /// blocking timer expires.
    BlockingEnd,
    /// A machine's internal timer started, or was changed.
    ///
    /// This event should be triggered any time a new internal timer is started,
    /// or whenever the expiration time of an machine's internal timer changes.
    TimerBegin { machine: MachineId },
    /// A machine's internal timer expired.
    ///
    /// (This event _should not_ be sent in response to a timer being cancelled.)
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
        assert_eq!(Event::Signal.to_string(), "Signal");
    }
}

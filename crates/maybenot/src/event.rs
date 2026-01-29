//! Events for [`State`](crate::state) transitions.

use serde::{Deserialize, Serialize};

use self::Event::*;
use crate::{MachineId, constants::EVENT_NUM};
use enum_map::Enum;
use std::fmt;
use std::hash::Hash;
use std::slice::Iter;

/// An Event may trigger a [`State`](crate::state) transition.
#[derive(Debug, Enum, Eq, Hash, PartialEq, Clone, Copy, Serialize, Deserialize)]
pub enum Event {
    /// NormalRecv is when we received a normal, non-decoy packet.
    NormalRecv,
    /// DecoyRecv is when we received a decoy packet.
    DecoyRecv,
    /// PacketRecv is when we received a packet: because it is encrypted, we do
    /// not know if it is a normal or decoy packet yet.
    PacketRecv,
    /// NormalQueued is when we queued a normal, non-decoy packet.
    NormalQueued,
    /// DecoyQueued is when we queued a decoy packet.
    DecoyQueued,
    /// PacketSent is when we sent a packet: because it is encrypted, we do not
    /// know if it is a normal or decoy packet.
    PacketSent,
    /// DelayBegin is when delaying traffic starts.
    DelayBegin,
    /// DelayEnd is when delaying traffic stops.
    DelayEnd,
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
    /// Congestion is when an integration-specific congestion event occurred.
    Congestion,
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Event {
    pub fn iter() -> Iter<'static, Event> {
        static EVENTS: [Event; EVENT_NUM] = [
            NormalRecv,
            DecoyRecv,
            PacketRecv,
            NormalQueued,
            DecoyQueued,
            PacketSent,
            DelayBegin,
            DelayEnd,
            LimitReached,
            CounterZero,
            TimerBegin,
            TimerEnd,
            Signal,
            Congestion,
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
    /// Received non-decoy packet.
    ///
    /// This event should be triggered once for each incoming non-decoy
    /// packet, after `PacketRecv`, as soon as we have identified the packet as
    /// non-decoy.
    NormalRecv,
    /// Received decoy packet.
    ///
    /// This event should be triggered once for each incoming decoy packet,
    /// after `PacketRecv`, as soon as we have identified the packet as a decoy.
    DecoyRecv,
    /// Received a complete packet.
    ///
    /// This event should be triggered once for each incoming packet of any
    /// type, as soon as possible after the packet is received from the network,
    /// before the packet is queued, processed, or decrypted.
    ///
    /// (No event should be generated for a partially read packet.)
    PacketRecv,
    /// Sent non-decoy packet.
    ///
    /// This event should be triggered once for each outgoing non-decoy packet,
    /// as soon as we have decided put it on any egress queue.
    NormalQueued,
    /// Queued a decoy packet. This event should be triggered once for each
    /// outgoing decoy packet, as soon as we have decided put it on any egress
    /// queue.
    DecoyQueued { machine: MachineId },
    /// Sent a packet.
    ///
    /// This event should be triggered once for each outgoing packet of any
    /// type, after that packet's `NormalQueued` or `DecoyQueued` event, as
    /// close as possible to the time when the packet is actually written to the
    /// network.
    PacketSent,
    /// Delaying of outgoing traffic started by the action from a machine.
    ///
    /// This event should be triggered whenever the action timer for a
    /// [`crate::action::TriggerAction::DelayTraffic`] action expires, whether
    /// the delay timer is adjusted or not.
    DelayBegin { machine: MachineId },
    /// Delaying of outgoing traffic has stopped.
    ///
    /// This event should be triggered when the framework-scoped delaying timer
    /// expires.
    DelayEnd,
    /// A machine's internal timer started, or was changed.
    ///
    /// This event should be triggered any time a new internal timer is started,
    /// or whenever the expiration time of an machine's internal timer changes.
    TimerBegin { machine: MachineId },
    /// A machine's internal timer expired.
    ///
    /// (This event _should not_ be sent in response to a timer being
    /// cancelled.)
    TimerEnd { machine: MachineId },
    /// Congestion has occurred, by some measure.
    ///
    /// This is an integration-specific event that could be used to indicate,
    /// for example, queued packets or ECN messages. Machines should likely be
    /// designed for one semantic interpretation of this event.
    Congestion,
}

impl TriggerEvent {
    /// Checks if the [`TriggerEvent`] is a particular [`Event`].
    pub fn is_event(&self, e: Event) -> bool {
        match self {
            TriggerEvent::NormalRecv => e == Event::NormalRecv,
            TriggerEvent::DecoyRecv => e == Event::DecoyRecv,
            TriggerEvent::NormalQueued => e == Event::NormalQueued,
            TriggerEvent::DecoyQueued { .. } => e == Event::DecoyQueued,
            TriggerEvent::DelayBegin { .. } => e == Event::DelayBegin,
            TriggerEvent::DelayEnd => e == Event::DelayEnd,
            TriggerEvent::TimerBegin { .. } => e == Event::TimerBegin,
            TriggerEvent::TimerEnd { .. } => e == Event::TimerEnd,
            TriggerEvent::PacketSent => e == Event::PacketSent,
            TriggerEvent::PacketRecv => e == Event::PacketRecv,
            TriggerEvent::Congestion => e == Event::Congestion,
        }
    }
}

impl fmt::Display for TriggerEvent {
    // note that we don't share the private MachineId
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TriggerEvent::NormalRecv => write!(f, "nr"),
            TriggerEvent::NormalQueued => write!(f, "nq"),
            TriggerEvent::DecoyRecv => write!(f, "dr"),
            TriggerEvent::DecoyQueued { .. } => write!(f, "dq"),
            TriggerEvent::PacketRecv => write!(f, "pr"),
            TriggerEvent::PacketSent => write!(f, "ps"),
            TriggerEvent::DelayBegin { .. } => write!(f, "bb"),
            TriggerEvent::DelayEnd => write!(f, "be"),
            TriggerEvent::TimerBegin { .. } => write!(f, "tb"),
            TriggerEvent::TimerEnd { .. } => write!(f, "te"),
            TriggerEvent::Congestion => write!(f, "c"),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::event::*;
    #[test]
    fn v1_events() {
        assert_eq!(Event::NormalRecv.to_string(), "NormalRecv");
        // PaddingRecv
        assert_eq!(Event::DecoyRecv.to_string(), "DecoyRecv");
        // NormalSent
        assert_eq!(Event::NormalQueued.to_string(), "NormalQueued");
        // PaddingSent
        assert_eq!(Event::DecoyQueued.to_string(), "DecoyQueued");
        // BlockingBegin
        assert_eq!(Event::DelayBegin.to_string(), "DelayBegin");
        // BlockingEnd
        assert_eq!(Event::DelayEnd.to_string(), "DelayEnd");
        assert_eq!(Event::LimitReached.to_string(), "LimitReached");
    }

    #[test]
    fn v2_events() {
        // TODO: expand events as we lock in v3 and write v2 parsing logic
        // hidden behind a feature flag
        assert_eq!(Event::CounterZero.to_string(), "CounterZero");
        assert_eq!(Event::TimerBegin.to_string(), "TimerBegin");
        assert_eq!(Event::TimerEnd.to_string(), "TimerEnd");
        // PacketRecv
        assert_eq!(Event::PacketRecv.to_string(), "PacketRecv");
        // PacketSent
        assert_eq!(Event::PacketSent.to_string(), "PacketSent");
        assert_eq!(Event::Signal.to_string(), "Signal");
    }
}

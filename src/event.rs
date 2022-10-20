//! Events for [`State`](crate::state) transitions.

use self::Event::*;
use std::fmt;
use std::hash::Hash;
use std::slice::Iter;

/// An Event may trigger a [`State`](crate::state) transition.
#[derive(Debug, Eq, Hash, PartialEq, Clone, Copy)]
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
    /// UpdateMTU is when the MTU of the protected connection was updated.
    UpdateMTU,
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Event {
    pub fn iterator() -> Iter<'static, Event> {
        static EVENTS: [Event; 8] = [
            NonPaddingRecv,
            PaddingRecv,
            NonPaddingSent,
            PaddingSent,
            BlockingBegin,
            BlockingEnd,
            LimitReached,
            UpdateMTU,
        ];
        EVENTS.iter()
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
        assert_eq!(Event::UpdateMTU.to_string(), "UpdateMTU");
    }
}

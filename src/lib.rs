//! Maybenot is a framework for traffic analysis defenses that hide patterns in
//! encrypted communication.
//!
//! Consider encrypted communication protocols such as QUIC, TLS, Tor, and
//! WireGuard. While the connections are encrypted, *patterns* in the encrypted
//! communication may still leak information about the underlying plaintext
//! despite being encrypted. Maybenot is a framework for creating and executing
//! defenses that hide such patterns. Defenses are implemented as probabilistic
//! state machines.
//!
//! If you want to use Maybenot, see the below example and [`Framework`] for details.
//! As a user, that is typically all that you need and the other modules can be ignored.
//! Note that you create an existing [`Machine`] (for use with the [`Framework`]) using
//! the [`core::str::FromStr`] trait.
//!
//! If you want to build machines for the [`framework`], take a look at all the
//! modules. For top-down, start with [`machine`]. For bottom-up, start with
//! [`dist`], [`event`], [`action`], and [`counter`] before [`state`] and
//! finally [`machine`].
//!
//! ## Example usage
//! ```
//! use maybenot::{Framework, Machine, TriggerAction, TriggerEvent};
//! use std::{str::FromStr, time::Instant};
//! // This is a large example usage of the Maybenot framework. Some parts are a
//! // bit odd due to avoiding everything async but should convey the general
//! // idea.
//!
//! // Parse machine, this is a "no-op" machine that does nothing. Typically,
//! // you should expect to get one or more serialized machines, not build them
//! // from scratch. The framework takes a vector with zero or more machines as
//! // input when created. To add or remove a machine, just recreate the
//! // framework. If you expect to create many instances of the framework for
//! // the same machines, then share the same vector across framework instances.
//! // All runtime information is allocated internally in the framework without
//! // modifying the machines.
//! let s = "02eNpjYEAHjKhcAAAwAAI=";
//! // machines will error if invalid
//! let m = vec![Machine::from_str(s).unwrap()];
//!
//! // You create the framework, a lightweight operation, with the following
//! // parameters:
//! // - A vector of zero or more machines.
//! // - Max fractions prevent machines from causing too much overhead: note
//! // that machines can be defined to be allowed a fixed amount of
//! // padding/blocking, bypassing these limits until having used up their
//! // allowed budgets. This means that it is possible to create machines that
//! // trigger actions to block outgoing traffic indefinitely and/or send a lot
//! // of outgoing traffic.
//! // - The current time. For normal use, just provide the current time as
//! // below. This is exposed mainly for testing purposes (can also be used to
//! // make the creation of some odd types of machines easier).
//! //
//! // The framework validates all machines (like ::From_str() above) and verifies
//! // that the fractions are fractions, so it can return an error.
//! let mut f = Framework::new(&m, 0.0, 0.0, Instant::now()).unwrap();
//!
//! // Below is the main loop for operating the framework. This should run for
//! // as long as the underlying connection the framework is attached to can
//! // communicate (user or protocol-specific data, depending on what is being
//! // defended).
//! loop {
//!     // Wait for one or more new events (e.g., on a channel) that should be
//!     // triggered in the framework. Below we just set one example event. How
//!     // you wait and collect events is likely going to be a bottleneck. If
//!     // you have to consider dropping events, it is better to drop older
//!     // events than newer. Ideally, it should be possible to process all
//!     // events one-by-one.
//!     let events = [TriggerEvent::NormalSent];
//!
//!     // Trigger the event(s) in the framework. This takes linear time with the
//!     // number of events but is very fast (time should be dominated by a few
//!     // calls to sample randomness per event per machine).
//!     for action in f.trigger_events(&events, Instant::now()) {
//!         // After triggering all the events, the framework will provide zero
//!         // or more actions to take, up to a maximum of one action per
//!         // machine (regardless of the number of events). It is your
//!         // responsibility to perform those actions according to the
//!         // specification. To do so, you will need two timers per machine: an
//!         // action timer (for action timeouts) and an internal timer (part of the
//!         // machine's internal logic). The machine identifier (machine in each
//!         // TriggerAction) uniquely and deterministically maps to a single machine
//!         // running in the framework, so it is suitable as a key for a data structure
//!         // storing your timers per framework instance, e.g.,
//!         // HashMap<MachineId, (SomeTimerDataStructure, SomeTimerDataStructure)>).
//!         match action {
//!             TriggerAction::Cancel { machine: _, timer: _ } => {
//!                 // Cancel the specified timer (action, internal, or both) for the
//!                 // machine in question.
//!             }
//!             TriggerAction::SendPadding {
//!                 timeout: _,
//!                 bypass: _,
//!                 replace: _,
//!                 machine: _,
//!             } => {
//!                 // Set the action timer with the specified timeout. On expiry,
//!                 // do the following:
//!                 //
//!                 // 1. Send a padding packet.
//!                 // 2. Trigger TriggerEvent::PaddingSent { machine: machine }.
//!                 //
//!                 // If bypass is true, then the padding MUST be sent even if there
//!                 // is active blocking of outgoing traffic AND the active blocking
//!                 // had the bypass flag set. If the active blocking had bypass set
//!                 // to false, then the padding MUST NOT be sent. This is to support
//!                 // completely fail-closed defenses.
//!                 //
//!                 // If replace is true, then the padding MAY be replaced by
//!                 // another packet. The other packet could be an encrypted packet
//!                 // already queued but not already sent in the tunnel, containing either
//!                 // padding or normal data (ideally, the user of the framework cannot
//!                 // tell, because encrypted). The other data could also be
//!                 // normal data about to be turned into a normal packet and sent.
//!                 // Regardless of if the padding is replaced or not, the event
//!                 // should still be triggered (steps 2). If enqueued normal data sent
//!                 // instead of padding, then the NormalSent event should be triggered
//!                 // as well.
//!                 //
//!                 // Above, note the use case of having bypass and replace set to
//!                 // true. This is to support constant-rate defenses.
//!                 //
//!                 // Also, note that if there already is an action timer for an
//!                 // earlier action for the machine in question, overwrite it with
//!                 // the new timer. This will happen very frequently so make effort
//!                 // to make it efficient (typically, efficient machines will always
//!                 // have something scheduled but try to minimize actual padding
//!                 // sent).
//!             }
//!             TriggerAction::BlockOutgoing {
//!                 timeout: _,
//!                 duration: _,
//!                 bypass: _,
//!                 replace: _,
//!                 machine: _,
//!             } => {
//!                 // Set an action timer with the specified timeout, overwriting
//!                 // any existing action timer for the machine (be it to block or
//!                 // to send padding). On expiry, do the following (all or nothing):
//!                 //
//!                 // 1. If no blocking is currently taking place (globally
//!                 //    across all machines, so for this instance of the
//!                 //    framework), start blocking all outgoing traffic for
//!                 //    the specified duration. If blocking is already taking
//!                 //    place (due to any machine), there are two cases. If
//!                 //    replace is true, replace the existing blocking
//!                 //    duration with the specified duration in this action.
//!                 //    If replace is false, pick the longest duration of
//!                 //    the specified duration and the *remaining* duration to
//!                 //    block already in place.
//!                 // 2. Trigger TriggerEvent::BlockingBegin { machine: machine }
//!                 //    regardless of logic outcome in 1. (From the point of view
//!                 //    of the machine, blocking is now taking place).
//!                 //
//!                 // Note that blocking is global across all machines, since
//!                 // the intent is to block all outgoing traffic. Further, you
//!                 // MUST ensure that when blocking ends, you trigger
//!                 // TriggerEvent::BlockingEnd.
//!                 //
//!                 // If bypass is true and blocking was activated, extended, or
//!                 // replaced in step 1, then a bypass flag MUST be set and be
//!                 // available to check as part of dealing with
//!                 // TriggerAction::SendPadding actions (see above).
//!             }
//!             TriggerAction::UpdateTimer {
//!                 duration: _,
//!                 replace: _,
//!                 machine: _,
//!             } => {
//!                 // If the replace flag is true, overwrite the machine's
//!                 // internal timer with the specified duration. If replace
//!                 // is false, use the longest of the remaining and specified
//!                 // durations.
//!                 //
//!                 // Regardless of the outcome of the preceding logic, trigger
//!                 // TriggerEvent::TimerBegin { machine: machine }.
//!                 //
//!                 // Trigger TriggerEvent::TimerEnd { machine: machine } when
//!                 // the timer expires.
//!             }
//!         }
//!     }
//!
//!     // All done, continue the loop. We break below for the example test to
//!     // not get stuck.
//!     break;
//! }
//! ```
pub mod action;
pub mod constants;
pub mod counter;
pub mod dist;
pub mod error;
pub mod event;
pub mod framework;
pub mod machine;
pub mod state;

pub use crate::action::{Action, Timer, TriggerAction};
pub use crate::constants::{STATE_END, STATE_LIMIT_MAX, VERSION};
pub use crate::counter::{Counter, CounterUpdate, Operation};
pub use crate::dist::{Dist, DistType};
pub use crate::error::Error;
pub use crate::event::{Event, TriggerEvent};
pub use crate::framework::Framework;
pub use crate::framework::MachineId;
pub use crate::machine::Machine;
pub use crate::state::{State, Trans};

#[cfg(feature = "parsing")]
pub mod parsing;

#[cfg(test)]
mod tests {
    #[test]
    fn constants_set() {
        assert_eq!(crate::constants::VERSION, 2);
    }
}

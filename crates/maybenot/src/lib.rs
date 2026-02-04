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
//! If you want to use Maybenot, see the below example and [`Framework`] for
//! details. As a user, that is typically all that you need and the other
//! modules can be ignored. Note that you create an existing [`Machine`] (for
//! use with the [`Framework`]) using the [`core::str::FromStr`] trait.
//!
//! If you want to build machines for the [`Framework`], take a look at all the
//! modules. For top-down, start with the [`Machine`] type. For bottom-up, start
//! with [`dist`], [`event`], [`action`], and [`counter`] before [`state`] and
//! finally [`Machine`].
//!
//! ## Example usage
//! ```
//! use maybenot::{Framework, Machine, ThresholdDecoyNone, TriggerAction, TriggerEvent};
//! use std::{str::FromStr, time::Instant};
//! // This is a large example usage of the Maybenot framework. Some parts
//! // are a bit odd due to avoiding everything async but should convey the
//! // general idea.
//!
//! // Parse machine, this is a "no-op" machine that does nothing.
//! // Typically, you should expect to get one or more serialized machines,
//! // not build them from scratch. The framework takes a vector with zero
//! // or more machines as input when created. To add or remove a machine,
//! // just recreate the framework. If you expect to create many instances
//! // of the framework for the same machines, then share the same vector
//! // across framework instances. All runtime information is allocated
//! // internally in the framework without modifying the machines.
//! let s = "02eNpjYGBkQAcAACYAAg==";
//! // machines will error if invalid
//! let m = vec![Machine::from_str(s).unwrap()];
//!
//! // You create the framework, a lightweight operation, with the following
//! // parameters:
//! // - A vector of zero or more machines.
//! // - Max fractions prevent machines from causing too much overhead: note
//! // that machines can be defined to be allowed a fixed amount of
//! // decoy/delay, bypassing these limits until having used up their
//! // allowed budgets. This means that it is possible to create machines
//! // that trigger actions to delay outgoing traffic indefinitely and/or
//! // send a lot of outgoing traffic.
//! // - The current time. For normal use, just provide the current time as
//! // below. This is exposed mainly for testing purposes (can also be used
//! // to make the creation of some odd types of machines easier).
//! // - A random number generator. Typically, this should be a secure
//! // random number generator, like the one provided by the `rand` crate.
//! //
//! // The framework validates all machines (like ::From_str() above) and
//! // verifies that the fractions are fractions, so it can return an error.
//! let mut f = Framework::new(&m, ThresholdDecoyNone, 0.0, Instant::now(), rand::rng()).unwrap();
//!
//! // Below is the main loop for operating the framework. This should run
//! // for as long as the underlying connection the framework is attached to
//! // can communicate (user or protocol-specific data, depending on what is
//! // being defended).
//! loop {
//!     // Wait for one or more new events (e.g., on a channel) that should
//!     // be triggered in the framework. Below we just set one example
//!     // event. How you wait and collect events is likely going to be a
//!     // bottleneck. If you have to consider dropping events, it is better
//!     // to drop older events than newer. Ideally, it should be possible
//!     // to process all events one-by-one.
//!     let events = [TriggerEvent::NormalQueued];
//!
//!     // Trigger the event(s) in the framework. This takes linear time
//!     // with the number of events but is very fast (time should be
//!     // dominated by a few calls to sample randomness per event per
//!     // machine).
//!     for action in f.trigger_events(&events, Instant::now()) {
//!         // After triggering all the events, the framework will provide
//!         // zero or more actions to take, up to a maximum of one action
//!         // per machine (regardless of the number of events). It is your
//!         // responsibility to perform those actions according to the
//!         // specification. To do so, you will need two timers per
//!         // machine: an action timer (for action timeouts) and an
//!         // internal timer (part of the machine's internal logic). The
//!         // machine identifier (machine in each TriggerAction) uniquely
//!         // and deterministically maps to a single machine running in the
//!         // framework, so it is suitable as a key for a data structure
//!         // storing your timers per framework instance, e.g.,
//!         // HashMap<MachineId, (SomeTimerDataStructure,
//!         // SomeTimerDataStructure)>).
//!         match action {
//!             TriggerAction::Cancel {
//!                 machine: _,
//!                 timer: _,
//!             } => {
//!                 // Cancel the specified timer (action, internal, or
//!                 // both) for the machine in question.
//!             }
//!             TriggerAction::DecoyTraffic {
//!                 timeout: _,
//!                 n: _,
//!                 bypass: _,
//!                 replace: _,
//!                 machine: _,
//!             } => {
//!                 // Set the action timer with the specified timeout. On
//!                 // expiry, do the following:
//!                 //
//!                 // 1. Send N decoy packets.
//!                 // 2. Trigger TriggerEvent::DecoyQueued { machine:
//!                 //    machine } after each packet has been sent.
//!                 //
//!                 // If bypass is true, then the decoy MUST be sent even
//!                 // if there is active delay of outgoing traffic AND the
//!                 // active delay has the bypass flag set. If the active
//!                 // delay has bypass set to false, then the decoy MUST
//!                 // NOT be sent. This is to support completely
//!                 // fail-closed defenses.
//!                 //
//!                 // If replace is true, then decoy packets MAY be
//!                 // replaced by other packet(s). The other packets could
//!                 // be encrypted packets already queued but not already
//!                 // sent to the network, containing either decoy or
//!                 // normal data (ideally, the user of the framework
//!                 // cannot tell, because encrypted). The other data could
//!                 // also be normal data about to be turned into normal
//!                 // packet(s) and sent. Regardless of if decoy packets
//!                 // are replaced or not, an event per packet should still
//!                 // be triggered (step 2). If normal data is turned into
//!                 // a packet and sent instead of a decoy packet, then the
//!                 // NormalQueued event should be triggered as well.
//!                 //
//!                 // Above, note the use case of having bypass and replace
//!                 // set to true. This is to support constant-rate
//!                 // defenses.
//!                 //
//!                 // Also, note that if there already is an action timer
//!                 // for an earlier action for the machine in question,
//!                 // overwrite it with the new timer. This will happen
//!                 // very frequently so make effort to make it efficient
//!                 // (typically, efficient machines will always have
//!                 // something scheduled but try to minimize actual decoy
//!                 // sent).
//!             }
//!             TriggerAction::DelayTraffic {
//!                 timeout: _,
//!                 n: _,
//!                 duration: _,
//!                 bypass: _,
//!                 replace: _,
//!                 machine: _,
//!             } => {
//!                 // Set an action timer with the specified timeout,
//!                 // overwriting any existing action timer for the machine
//!                 // (be it to delay or to send decoy). On expiry, do the
//!                 // following (all or nothing):
//!                 //
//!                 // 1. If no delay is currently taking place (globally
//!                 //    across all machines, so for this instance of the
//!                 //    framework), start delaying all outgoing traffic
//!                 //    for the specified duration or until N packets have
//!                 //    been delayed, whichever happens first. If delay is
//!                 //    already taking place (due to any machine), there
//!                 //    are two cases. If replace is true, replace the
//!                 //    existing delay duration and maximum packet count N
//!                 //    with the specified duration and count in this
//!                 //    action. If replace is false, pick the longest
//!                 //    duration of the specified duration and the
//!                 //    *remaining* duration to delay already in place AND
//!                 //    the largest N. Select the two parameters
//!                 //    independently.
//!                 // 2. Trigger TriggerEvent::DelayBegin { machine:
//!                 //    machine } regardless of logic outcome in 1. (From
//!                 //    the point of view of the machine, delay is now
//!                 //    taking place).
//!                 //
//!                 // Note that delay is global across all machines, since
//!                 // the intent is to delay all outgoing traffic. Further,
//!                 // you MUST ensure that when the delay ends, you trigger
//!                 // TriggerEvent::DelayEnd.
//!                 //
//!                 // If bypass is true and delay was activated, extended,
//!                 // or replaced in step 1, then a bypass flag MUST be set
//!                 // and be available to check as part of dealing with
//!                 // TriggerAction::DecoyTraffic actions (see above).
//!             }
//!             TriggerAction::UpdateTimer {
//!                 duration: _,
//!                 replace: _,
//!                 machine: _,
//!             } => {
//!                 // If the replace flag is true, overwrite the machine's
//!                 // internal timer with the specified duration. If
//!                 // replace is false, use the longest of the remaining
//!                 // and specified durations.
//!                 //
//!                 // Regardless of the outcome of the preceding logic,
//!                 // trigger TriggerEvent::TimerBegin { machine: machine
//!                 // }.
//!                 //
//!                 // Trigger TriggerEvent::TimerEnd { machine: machine }
//!                 // when the timer expires.
//!             }
//!         }
//!     }
//!
//!     // All done, continue the loop. We break below for the example test
//!     // to not get stuck.
//!     break;
//! }
//! ```
//! ## Key concepts
//!
//! ### Packets
//!
//! We assume that all traffic is sent in "packets" of uniform size, which may
//! either be decoy or non-decoy ("normal").
//!
//! ### Egress queue
//!
//! We assume that outgoing packets are "queued" before they are sent over the
//! network.
//!
//! In the incoming direction, we first receive a packet, which is then
//! eventually processed/decrypted to find out whether it is decoy or not.
//!
//! In the outgoing direction, when we generate a packet, it is encrypted ASAP,
//! egress queued, and eventually transmitted on the network.
//!
//! ### Framework state, and per-machine state.
//!
//! For each [`Machine`] in a [`Framework`], you will need to maintain a certain
//! amount of state. Specifically, you will need to track:
//!
//! - A single "internal" timer, which the machine will manage via
//!   [`TriggerAction::UpdateTimer`] and [`TriggerAction::Cancel`]. If it
//!   expires, you will need to trigger [`TriggerEvent::TimerEnd`].
//! - A single "action" timer, which the machine will manage via
//!   [`TriggerAction::DecoyTraffic`], [`TriggerAction::DelayTraffic`], and
//!   [`TriggerAction::Cancel`].
//!   - An action to be taken if and when the "action" timer expires. This
//!     action may be "begin delaying packets for a certain Duration" or "send
//!     decoy packets". (There are additional flags associated with these
//!     actions.)
//!
//! Additionally, for the [`Framework`] itself, you will need to track:
//! - Whether traffic delay has been enabled, and when it will expire.
//! - Whether the enabled traffic delay is "bypassable" (q.v.).
//!
//! ### Delay
//!
//! In addition to sending decoy packets, a Maybenot [`Machine`] can tell the
//! application to temporarily _delay_ traffic.
//!
//! While traffic is delayed on a connection, no packets should ordinarily be
//! sent to the network until the delay expires. Instead, traffic should be
//! queued.
//!
//! The delay may be "bypassable" or "non-bypassable". This difference affects
//! whether decoy packets marked with the "bypass" flag can still be sent while
//! the delay is in effect.
//!
//! By cases:
//!
//! | Delay          | Decoy (N packets)| Action (for Q = |queue|)                                      |
//! | -------------- | ---------------  | ------------------------------------------------------------- |
//! | non-bypassable | none             | queue N decoy packets                                         |
//! |                | bypass           | queue N decoy packets                                         |
//! |                | replace          | queue N-Q decoy packets                                       |
//! |                | bypass, replace  | queue N-Q decoy packets                                       |
//! | bypassable     | none             | queue N decoy packets                                         |
//! |                | bypass           | send N decoy packets immediately                              |
//! |                | replace          | queue N-Q decoy packets                                       |
//! |                | bypass, replace  | send N packets immediately, first draining Q, then N-Q decoys |

pub mod action;
pub mod constants;
pub mod counter;
pub mod dist;
mod error;
pub mod event;
mod framework;
mod machine;
pub mod state;
pub mod threshold;
pub mod time;

pub use crate::action::{Timer, TriggerAction};
pub use crate::error::Error;
pub use crate::event::TriggerEvent;
pub use crate::threshold::{ThresholdDecoy, ThresholdDecoyFrac, ThresholdDecoyNone};
pub use framework::{Framework, MachineId};
pub use machine::Machine;

#[cfg(test)]
mod tests {

    #[test]
    fn constants_set() {
        assert_eq!(crate::constants::VERSION, 2);
    }

    #[test]
    fn example_usage() {
        use crate::{Framework, Machine, ThresholdDecoyNone, TriggerAction, TriggerEvent};
        use std::{str::FromStr, time::Instant};
        // This is a large example usage of the Maybenot framework. Some parts
        // are a bit odd due to avoiding everything async but should convey the
        // general idea.

        // Parse machine, this is a "no-op" machine that does nothing.
        // Typically, you should expect to get one or more serialized machines,
        // not build them from scratch. The framework takes a vector with zero
        // or more machines as input when created. To add or remove a machine,
        // just recreate the framework. If you expect to create many instances
        // of the framework for the same machines, then share the same vector
        // across framework instances. All runtime information is allocated
        // internally in the framework without modifying the machines.
        let s = "02eNpjYGBkQAcAACYAAg==";
        // machines will error if invalid
        let m = vec![Machine::from_str(s).unwrap()];

        // You create the framework, a lightweight operation, with the following
        // parameters:
        // - A vector of zero or more machines.
        // - Max fractions prevent machines from causing too much overhead: note
        // that machines can be defined to be allowed a fixed amount of
        // decoy/delay, bypassing these limits until having used up their
        // allowed budgets. This means that it is possible to create machines
        // that trigger actions to delay outgoing traffic indefinitely and/or
        // send a lot of outgoing traffic.
        // - The current time. For normal use, just provide the current time as
        // below. This is exposed mainly for testing purposes (can also be used
        // to make the creation of some odd types of machines easier).
        // - A random number generator. Typically, this should be a secure
        // random number generator, like the one provided by the `rand` crate.
        //
        // The framework validates all machines (like ::From_str() above) and
        // verifies that the fractions are fractions, so it can return an error.
        let mut f =
            Framework::new(&m, ThresholdDecoyNone, 0.0, Instant::now(), rand::rng()).unwrap();

        // Below is the main loop for operating the framework. This should run
        // for as long as the underlying connection the framework is attached to
        // can communicate (user or protocol-specific data, depending on what is
        // being defended).
        loop {
            // Wait for one or more new events (e.g., on a channel) that should
            // be triggered in the framework. Below we just set one example
            // event. How you wait and collect events is likely going to be a
            // bottleneck. If you have to consider dropping events, it is better
            // to drop older events than newer. Ideally, it should be possible
            // to process all events one-by-one.
            let events = [TriggerEvent::NormalQueued];

            // Trigger the event(s) in the framework. This takes linear time
            // with the number of events but is very fast (time should be
            // dominated by a few calls to sample randomness per event per
            // machine).
            for action in f.trigger_events(&events, Instant::now()) {
                // After triggering all the events, the framework will provide
                // zero or more actions to take, up to a maximum of one action
                // per machine (regardless of the number of events). It is your
                // responsibility to perform those actions according to the
                // specification. To do so, you will need two timers per
                // machine: an action timer (for action timeouts) and an
                // internal timer (part of the machine's internal logic). The
                // machine identifier (machine in each TriggerAction) uniquely
                // and deterministically maps to a single machine running in the
                // framework, so it is suitable as a key for a data structure
                // storing your timers per framework instance, e.g.,
                // HashMap<MachineId, (SomeTimerDataStructure,
                // SomeTimerDataStructure)>).
                match action {
                    TriggerAction::Cancel {
                        machine: _,
                        timer: _,
                    } => {
                        // Cancel the specified timer (action, internal, or
                        // both) for the machine in question.
                    }
                    TriggerAction::DecoyTraffic {
                        timeout: _,
                        n: _,
                        bypass: _,
                        replace: _,
                        machine: _,
                    } => {
                        // Set the action timer with the specified timeout. On
                        // expiry, do the following:
                        //
                        // 1. Send N decoy packets.
                        // 2. Trigger TriggerEvent::DecoyQueued { machine:
                        //    machine } after each packet has been sent.
                        //
                        // If bypass is true, then the decoy MUST be sent even
                        // if there is active delay of outgoing traffic AND the
                        // active delay has the bypass flag set. If the active
                        // delay has bypass set to false, then the decoy MUST
                        // NOT be sent. This is to support completely
                        // fail-closed defenses.
                        //
                        // If replace is true, then decoy packets MAY be
                        // replaced by other packet(s). The other packets could
                        // be encrypted packets already queued but not already
                        // sent to the network, containing either decoy or
                        // normal data (ideally, the user of the framework
                        // cannot tell, because encrypted). The other data could
                        // also be normal data about to be turned into normal
                        // packet(s) and sent. Regardless of if decoy packets
                        // are replaced or not, an event per packet should still
                        // be triggered (step 2). If normal data is turned into
                        // a packet and sent instead of a decoy packet, then the
                        // NormalQueued event should be triggered as well.
                        //
                        // Above, note the use case of having bypass and replace
                        // set to true. This is to support constant-rate
                        // defenses.
                        //
                        // Also, note that if there already is an action timer
                        // for an earlier action for the machine in question,
                        // overwrite it with the new timer. This will happen
                        // very frequently so make effort to make it efficient
                        // (typically, efficient machines will always have
                        // something scheduled but try to minimize actual decoy
                        // sent).
                    }
                    TriggerAction::DelayTraffic {
                        timeout: _,
                        n: _,
                        duration: _,
                        bypass: _,
                        replace: _,
                        machine: _,
                    } => {
                        // Set an action timer with the specified timeout,
                        // overwriting any existing action timer for the machine
                        // (be it to delay or to send decoy). On expiry, do the
                        // following (all or nothing):
                        //
                        // 1. If no delay is currently taking place (globally
                        //    across all machines, so for this instance of the
                        //    framework), start delaying all outgoing traffic
                        //    for the specified duration or until N packets have
                        //    been delayed, whichever happens first. If delay is
                        //    already taking place (due to any machine), there
                        //    are two cases. If replace is true, replace the
                        //    existing delay duration and maximum packet count N
                        //    with the specified duration and count in this
                        //    action. If replace is false, pick the longest
                        //    duration of the specified duration and the
                        //    *remaining* duration to delay already in place AND
                        //    the largest N. Select the two parameters
                        //    independently.
                        // 2. Trigger TriggerEvent::DelayBegin { machine:
                        //    machine } regardless of logic outcome in 1. (From
                        //    the point of view of the machine, delay is now
                        //    taking place).
                        //
                        // Note that delay is global across all machines, since
                        // the intent is to delay all outgoing traffic. Further,
                        // you MUST ensure that when the delay ends, you trigger
                        // TriggerEvent::DelayEnd.
                        //
                        // If bypass is true and delay was activated, extended,
                        // or replaced in step 1, then a bypass flag MUST be set
                        // and be available to check as part of dealing with
                        // TriggerAction::DecoyTraffic actions (see above).
                    }
                    TriggerAction::UpdateTimer {
                        duration: _,
                        replace: _,
                        machine: _,
                    } => {
                        // If the replace flag is true, overwrite the machine's
                        // internal timer with the specified duration. If
                        // replace is false, use the longest of the remaining
                        // and specified durations.
                        //
                        // Regardless of the outcome of the preceding logic,
                        // trigger TriggerEvent::TimerBegin { machine: machine
                        // }.
                        //
                        // Trigger TriggerEvent::TimerEnd { machine: machine }
                        // when the timer expires.
                    }
                }
            }

            // In real usage the loop would continue here. But since this is just an example test
            // that should terminate, we add a break here to make the test finish.
            if true {
                break;
            }
        }
    }
}

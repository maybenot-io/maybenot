use maybenot::{
    framework::{Action, Framework, TriggerEvent},
    machine::Machine,
};
use std::{str::FromStr, time::Instant};

#[test]
fn create_empty() {
    Framework::new(vec![], 0.0, 0.0, 100, Instant::now()).unwrap();
}

#[test]
fn example_usage() {
    // This is a large example usage of the maybenot framework. Some parts are a
    // bit odd due to avoiding everything async but should convey the general
    // idea.

    // Parse machine, this is a "no-op" machine that does nothing. Typically,
    // you should expect to get one or more serialized machines, not build them
    // from scratch. The framework takes a vector with zero or more machines as
    // input when created. To add or remove a machine, just recreate the
    // framework. If you expect to create many instances of the framework for
    // the same machines, then share the same vector across framework instances.
    // All runtime information is allocated internally in the framework without
    // modifying the machines.
    let s = "789cedca31010000000141fa9736084080bff9ace928a80003c70003".to_string();
    // machines will error if invalid
    let m = Machine::from_str(&s).unwrap();

    // Create the framework, a lightweight operation, with the following
    // parameters:
    // - A vector of zero or more machines.
    // - Max fractions prevent machines from causing too much overhead: note
    // that machines can be defined to be allowed a fixed amount of
    // padding/blocking, bypassing these limits until having used up their
    // allowed budgets. This means that it is possible to create machines that
    // trigger actions to block outgoing traffic indefinitely and/or send a lot
    // of outgoing traffic.
    // - The current MTU of the link being protected. It can be updated later by
    // triggering TriggerEvent::UpdateMTU { new_mtu: u16 }.
    // - The current time. For normal use, just provide the current time as
    // below. This is exposed mainly for testing purposes (can also be used to
    // make the creation of some odd types of machines easier).
    //
    // The framework validates all machines (like fn parse_machine() above) so
    // it can error out.
    let mut f = Framework::new(vec![m], 0.0, 0.0, 1420, Instant::now()).unwrap();

    // Below is the main loop for operating the framework. This should run for
    // as long as the underlying connection the framework is attached to can
    // communicate (user or protocol-specific data, depending on what is being
    // defended).
    loop {
        // Wait for one or more new events (e.g., on a channel) that should be
        // triggered in the framework. Below we just set one example event. How
        // you wait and collect events is likely going to be a bottleneck. If
        // you have to consider dropping events, it is better to drop older
        // events than newer.
        let events = [TriggerEvent::NonPaddingSent { bytes_sent: 1420 }];

        // Trigger the events in the framework. This takes linear time with the
        // number of events but is very fast (time should be dominated by at
        // most four calls to sample randomness per event per machine).
        for action in f.trigger_events(&events, Instant::now()) {
            // After triggering all the events, the framework will provide zero
            // or more actions to take, up to a maximum of one action per
            // machine (regardless of the number of events). It is your
            // responsibility to perform those actions according to the
            // specification. To do so, you will need up to one timer per
            // machine. The machine identifier (machine in each Action) uniquely
            // and deterministically maps to a single machine running in the
            // framework (so suitable as a key for a data structure storing your
            // timers, e.g., a HashMap<MachineId, SomeTimerDataStructure>).
            match action {
                Action::Cancel { machine: _ } => {
                    // If any active pending timer for this machine, cancel it.
                }
                Action::InjectPadding {
                    timeout: _,
                    size: _,
                    machine: _,
                } => {
                    // Set the timer with the specified timeout. On expiry, do
                    // the following (all of nothing):
                    // 1. Send size padding.
                    // 2. Add TriggerEvent::PaddingSent{ bytes_sent: size,
                    //    machine: machine } to be triggered next loop
                    //    iteration.
                    //
                    // Above, "send" should mimic as close as possible real
                    // application data being added for transport. Also, note
                    // that if there already is a timer for an earlier action
                    // for the machine index in question, replace it. This will
                    // happen very frequently so make effort to make it
                    // efficient (typically, efficient machines will always have
                    // something scheduled but try to minimize actual padding
                    // sent, i.e., expired timers).
                }
                Action::BlockOutgoing {
                    timeout: _,
                    duration: _,
                    overwrite: _,
                    machine: _,
                } => {
                    // Set the timer with the specified timeout, overwriting any
                    // existing action timer for the machine (be it to block or
                    // inject). On expiry, do the following (all or nothing):
                    // 1. If no blocking is currently taking place (globally
                    //    across all machines, so for this instance of the
                    //    framework), start blocking all outgoing traffic for
                    //    the specified duration. If blocking is already taking
                    //    place (due to any machine), there are two cases. If
                    //    overwrite is true, replace the existing blocking
                    //    duration with the specified duration in this action.
                    //    If overwrite is false, pick the longest duration of
                    //    the specified duration and the *remaining* duration to
                    //    block already in place.
                    // 2. Add TriggerEvent::BlockingBegin { machine: machine }
                    //    to be triggered next loop iteration (regardless of
                    //    logic outcome in 1, from the point of view of the
                    //    machine, blocking is now taking place).
                    //
                    // Note that blocking is global across all machines, since
                    // the intent is to block all outgoing traffic. Further, you
                    // MUST ensure that when blocking ends, you add
                    // TriggerEvent::BlockingEnd to be triggered next loop
                    // iteration.
                }
            }
        }

        // All done, continue the loop. We break below for the example test to
        // not get stuck.
        break;
    }
}

//! Maybenot is a framework for traffic analysis defenses that can be used to
//! hide patterns in encrypted communication.
//!
//! Consider encrypted communication protocols such as TLS, QUIC, WireGuard, or
//! Tor. While the connections are encrypted, *patterns* in the encrypted
//! communication may still leak information about the underlying plaintext
//! being communicated with encryption. Maybenot is a framework for creating
//! defenses that hide such patterns.
//!
//!
//! ## Example usage
//! ```
//! use maybenot::{
//! action::TriggerAction,
//! event::TriggerEvent,
//! framework::Framework,
//! machine::Machine,
//! };
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
//! let s = "02eNrFwDEBAAAAAbDpX1oDr7HFXQEBJgAC";
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
//! // The framework validates all machines (like ::From_str() above) so it can
//! // return an error.
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
//!     // events than newer.
//!     let events = [TriggerEvent::NonPaddingSent];
//!
//!     // Trigger the events in the framework. This takes linear time with the
//!     // number of events but is very fast (time should be dominated by at
//!     // most four calls to sample randomness per event per machine).
//!     for action in f.trigger_events(&events, Instant::now()) {
//!         // After triggering all the events, the framework will provide zero
//!         // or more actions to take, up to a maximum of one action per
//!         // machine (regardless of the number of events). It is your
//!         // responsibility to perform those actions according to the
//!         // specification. To do so, you will need an action timer, machine
//!         // timer, and two counters per machine. The machine identifier
//!         // (machine in each TriggerAction) uniquely and deterministically
//!         // maps to a single machine running in the framework (so suitable
//!         // as a key for a data structure storing your timers, e.g. a
//!         // HashMap<MachineId, SomeTimerDataStructure>), and counters.
//!         match action {
//!             TriggerAction::Cancel { machine: _ } => {
//!                 // If any pending action timer for this machine, cancel it.
//!             }
//!             TriggerAction::InjectPadding {
//!                 timeout: _,
//!                 size: _,
//!                 bypass: _,
//!                 replace: _,
//!                 machine: _,
//!             } => {
//!                 // Set the action timer with the specified timeout. On expiry,
//!                 // do the following (all or nothing):
//!                 //
//!                 // 1. Trigger TriggerEvent::PaddingQueued{ machine: machine }.
//!                 // 2. Send size padding.
//!                 // 3. Trigger TriggerEvent::PaddingSent{ machine: machine }.
//!                 //
//!                 // Above, "send" should mimic as close as possible real
//!                 // application data being added for transport.
//!                 //
//!                 // If bypass is true, then the padding MUST be sent even if there
//!                 // is active blocking of outgoing traffic AND the active blocking
//!                 // had the bypass flag set. If the active blocking had bypass set
//!                 // to false, then the padding MUST NOT be sent. This is to support
//!                 // completely fail closed defenses.
//!                 //
//!                 // If replace is true, then the padding MAY be replaced by
//!                 // other data. The other data could be in the form of an
//!                 // encrypted packet queued to be sent, which is either padding
//!                 // or non-padding (ideally, the user of the framework cannot
//!                 // tell, because encrypted). The other data could also be
//!                 // application data (non-padding) enqueued to be sent. In both
//!                 // cases, the replaced data MAY be of the same size as the
//!                 // padding. Regardless of if the padding is replaced or not,
//!                 // the events should still be triggered (steps 1/3). If enqueued
//!                 // non-padding is sent instead of padding, then NonPaddingSent
//!                 // should be triggered as well.
//!                 //
//!                 // Above, note the use-case of having bypass and replace set to
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
//!                 // inject). On expiry, do the following (all or nothing):
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
//!                 // 2. Add TriggerEvent::BlockingBegin { machine: machine }
//!                 //    to be triggered next loop iteration (regardless of
//!                 //    logic outcome in 1, from the point of view of the
//!                 //    machine, blocking is now taking place).
//!                 //
//!                 // Note that blocking is global across all machines, since
//!                 // the intent is to block all outgoing traffic. Further, you
//!                 // MUST ensure that when blocking ends, you add
//!                 // TriggerEvent::BlockingEnd to be triggered next loop
//!                 // iteration.
//!                 //
//!                 // If bypass is true and blocking was activated, extended, or
//!                 // replaced in step 1, then a bypass flag MUST be set and be
//!                 // available to check as part of dealing with
//!                 // TriggerAction::InjectPadding actions (see above).
//!             }
//!             TriggerAction::UpdateCounter {
//!                 value: _,
//!                 counter: _,
//!                 decrement: _,
//!                 machine: _,
//!             } => {
//!                 // Each machine has two counters - update the one specified
//!                 // by counter (will be 0 or 1). If decrement is true, subtract
//!                 // the given value from the current counter value; otherwise,
//!                 // add it. If the counter value is zero:
//!                 //
//!                 // 1. If the counter value was already zero, do nothing.
//!                 // 2. If the counter value has decreased to zero, add
//!                 //    TriggerEvent::CounterZero { machine: machine } to be
//!                 //    triggered next loop iteration.
//!             }
//!             TriggerAction::UpdateTimer {
//!                 duration: _,
//!                 replace: _,
//!                 machine: _,
//!             } => {
//!                 // If the replace flag is true, overwrite the machine's
//!                 // non-action timer with the specified duration. If replace
//!                 // is false, use the longest of the remaining and specified
//!                 // durations.
//!                 //
//!                 // Do not schedule any events to be triggered, even if the
//!                 // timer was set to zero - this allows for the timer to be
//!                 // explicitly reset. If the timer was not set to zero,
//!                 // trigger TriggerEvent::TimerEnd { machine: machine }
//!                 // when it subsequently expires.
//!             }
//!         }
//!     }
//!
//!     // All done, continue the loop. We break below for the example test to
//!     // not get stuck.
//!     break;
//! }
//! ```
use simple_error::bail;

use crate::action::*;
use crate::constants::*;
use crate::dist::DistType;
use crate::event::*;
use crate::machine::*;
use std::cmp::Ordering;
use std::error::Error;
use std::time::Duration;
use std::time::Instant;

/// An opaque token representing one machine running inside the framework.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct MachineId(usize);

impl MachineId {
    /// Create a new machine identifier from a raw integer. Intended for use
    /// with the `machine` field of [`TriggerAction`] and [`TriggerEvent`]. For
    /// testing purposes only. For regular use, use [`MachineId`] returned by
    /// [Framework::trigger_events]. Triggering an event in the framework for a
    /// machine that does not exist does not raise a panic or any error.
    pub fn from_raw(raw: usize) -> Self {
        MachineId(raw)
    }
}

#[derive(Debug, Clone)]
struct MachineRuntime {
    current_state: usize,
    state_limit: u64,
    padding_sent: u64,
    nonpadding_sent: u64,
    blocking_duration: Duration,
    machine_start: Instant,
}

#[derive(PartialEq)]
enum StateChange {
    Changed,
    Unchanged,
}

/// An instance of the Maybenot framework.
///
/// An instance of the [`Framework`] repeatedly takes as *input* one or more
/// [`TriggerEvent`] describing the encrypted traffic going over an encrypted
/// channel, and produces as *output* zero or more [`TriggerAction`], such as
/// to inject *padding* traffic or *block* outgoing traffic. One or more
/// [`Machine`] determine what [`TriggerAction`] to take based on
/// [`TriggerEvent`].
pub struct Framework<M> {
    actions: Vec<Option<TriggerAction>>,
    current_time: Instant,
    machines: M,
    runtime: Vec<MachineRuntime>,
    max_padding_frac: f64,
    nonpadding_sent_packets: u64,
    padding_sent_packets: u64,
    max_blocking_frac: f64,
    blocking_duration: Duration,
    blocking_started: Instant,
    blocking_active: bool,
    framework_start: Instant,
}

impl<M> Framework<M>
where
    M: AsRef<[Machine]>,
{
    /// Create a new framework instance with zero or more [`Machine`]. The max
    /// padding/blocking fractions are enforced as a total across all machines.
    /// The only way those limits can be violated are through
    /// [`Machine::allowed_padding_packets`] and
    /// [`Machine::allowed_blocked_microsec`], respectively. The current time is
    /// handed to the framework here (and later in [`Self::trigger_events()`]) to
    /// make some types of use-cases of the framework easier (weird machines and
    /// for simulation). Returns an error on any invalid [`Machine`] or limits
    /// not being fractions [0, 1.0].
    pub fn new(
        machines: M,
        max_padding_frac: f64,
        max_blocking_frac: f64,
        current_time: Instant,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        for m in machines.as_ref() {
            m.validate()?;
        }

        if !(0.0..=1.0).contains(&max_padding_frac) {
            bail!("max_padding_frac has to be between [0.0, 1.0]");
        }
        if !(0.0..=1.0).contains(&max_blocking_frac) {
            bail!("max_blocking_frac has to be between [0.0, 1.0]");
        }

        let mut runtime = vec![
            MachineRuntime {
                current_state: 0,
                state_limit: 0,
                padding_sent: 0,
                nonpadding_sent: 0,
                blocking_duration: Duration::from_secs(0),
                machine_start: current_time,
            };
            machines.as_ref().len()
        ];

        for (mi, r) in runtime.iter_mut().enumerate() {
            r.state_limit = machines.as_ref()[mi].states[0].sample_limit();
        }

        let actions = vec![None; machines.as_ref().len()];

        Ok(Self {
            actions,
            machines,
            runtime,
            current_time,
            max_blocking_frac,
            max_padding_frac,
            framework_start: current_time,
            blocking_active: false,
            blocking_started: current_time,
            blocking_duration: Duration::from_secs(0),
            padding_sent_packets: 0,
            nonpadding_sent_packets: 0,
        })
    }

    /// Returns the number of machines in the framework.
    pub fn num_machines(&self) -> usize {
        self.machines.as_ref().len()
    }

    /// Trigger zero or more [`TriggerEvent`] for all machines running in the
    /// framework. The current time SHOULD be the current time at time of
    /// calling the method (e.g., [`Instant::now()`]). Returns an iterator of
    /// zero or more [`TriggerAction`] that MUST be taken by the caller.
    pub fn trigger_events(
        &mut self,
        events: &[TriggerEvent],
        current_time: Instant,
    ) -> impl Iterator<Item = &TriggerAction> {
        // reset all actions
        self.actions.fill(None);

        // Process all events: note that each event may lead to up to one action
        // per machine, but that future events may replace those actions.
        // Under load, this is preferable (because something already happened
        // before we could cause an action, so better to catch up).
        self.current_time = current_time;
        for e in events {
            self.process_event(e);
        }

        // only return actions, no None
        self.actions.iter().filter_map(|action| action.as_ref())
    }

    fn process_event(&mut self, e: &TriggerEvent) {
        match e {
            TriggerEvent::NonPaddingRecv => {
                // no special accounting needed
                for mi in 0..self.runtime.len() {
                    self.transition(mi, Event::NonPaddingRecv);
                }
            }
            TriggerEvent::PaddingRecv => {
                // no special accounting needed
                for mi in 0..self.runtime.len() {
                    self.transition(mi, Event::PaddingRecv);
                }
            }
            TriggerEvent::NonPaddingSent => {
                self.nonpadding_sent_packets += 1;

                for mi in 0..self.runtime.len() {
                    self.runtime[mi].nonpadding_sent += 1;

                    // If the transition leaves the state unchanged and the limit of
                    // the machine includes nonpadding sent packets, decrement the
                    // limit. If the state changed, a new limit was sampled and this
                    // packet shouldn't count.
                    if self.transition(mi, Event::NonPaddingSent) == StateChange::Unchanged {
                        let cs = self.runtime[mi].current_state;
                        if cs != STATE_END
                            && self.machines.as_ref()[mi].states[cs].limit_includes_nonpadding
                        {
                            self.decrement_limit(mi);
                        }
                    }
                }
            }
            TriggerEvent::PaddingSent { machine } => {
                // accounting is global ...
                self.padding_sent_packets += 1;

                // ... but the event is per-machine
                let mi = machine.0;
                if mi >= self.runtime.len() {
                    // it's possible to create many instances of the framework
                    // with different numbers of machines, so we need to check
                    // this despite the machine being a MachineId
                    return;
                }

                self.runtime[mi].padding_sent += 1;

                if self.transition(mi, Event::PaddingSent) == StateChange::Unchanged {
                    // decrement only makes sense if we didn't change state
                    self.decrement_limit(mi)
                }
            }
            TriggerEvent::BlockingBegin { machine } => {
                // keep track of when we start blocking (for accounting in BlockingEnd)
                if !self.blocking_active {
                    self.blocking_active = true;
                    self.blocking_started = self.current_time;
                }

                // blocking is a global event
                for mi in 0..self.runtime.len() {
                    if self.transition(mi, Event::BlockingBegin) == StateChange::Unchanged
                        && mi == machine.0
                    {
                        // decrement only makes sense if we didn't
                        // change state and for the machine in question
                        self.decrement_limit(mi)
                    }
                }
            }
            TriggerEvent::BlockingEnd => {
                let mut blocked: Duration = Duration::from_secs(0);
                if self.blocking_active {
                    blocked = self.current_time.duration_since(self.blocking_started);
                    self.blocking_duration += blocked;
                    self.blocking_active = false;
                }

                for mi in 0..self.runtime.len() {
                    // since block is global, every machine was blocked the
                    // same duration
                    if !blocked.is_zero() {
                        self.runtime[mi].blocking_duration += blocked;
                    }
                    self.transition(mi, Event::BlockingEnd);
                }
            }
            TriggerEvent::CounterZero { machine } => {
                self.transition(machine.0, Event::CounterZero);
            }
            TriggerEvent::TimerEnd { machine } => {
                self.transition(machine.0, Event::TimerEnd);
            }
            TriggerEvent::NonPaddingQueued => {
                for mi in 0..self.runtime.len() {
                    self.transition(mi, Event::NonPaddingQueued);
                }
            }
            TriggerEvent::PaddingQueued { machine } => {
                let mi = machine.0;
                if mi >= self.runtime.len() {
                    return;
                }
                self.transition(mi, Event::NonPaddingQueued);
            }
        };
    }

    fn transition(&mut self, mi: usize, event: Event) -> StateChange {
        let machine = &self.machines.as_ref()[mi];

        // a machine in end state cannot transition
        if self.runtime[mi].current_state == STATE_END {
            return StateChange::Unchanged;
        }

        // sample next state
        let (next_state, set) = self.next_state(&self.runtime[mi], machine, event);

        // if no next state on event, done
        if !set {
            return StateChange::Unchanged;
        }

        // we got a next state, act on it
        match next_state {
            STATE_CANCEL => {
                // cancel any pending action, but doesn't count as a state change
                self.actions[mi] = Some(TriggerAction::Cancel {
                    machine: MachineId(mi),
                });
                StateChange::Unchanged
            }
            STATE_END => {
                // this is a state change (because we can never reach here if already in
                // STATEEND, see first check above), but we don't cancel any pending
                // action, nor schedule any new action
                self.runtime[mi].current_state = STATE_END;
                StateChange::Changed
            }
            _ => {
                // transition to same or different state?
                if self.runtime[mi].current_state == next_state {
                    if self.below_action_limits(&self.runtime[mi], machine) {
                        self.actions[mi] =
                            self.schedule_action(&self.runtime[mi], machine, MachineId(mi));
                    }
                    return StateChange::Unchanged;
                }
                self.runtime[mi].current_state = next_state;
                self.runtime[mi].state_limit = machine.states[next_state].sample_limit();
                if self.below_action_limits(&self.runtime[mi], machine) {
                    self.actions[mi] =
                        self.schedule_action(&self.runtime[mi], machine, MachineId(mi));
                }
                StateChange::Changed
            }
        }
    }

    fn schedule_action(
        &self,
        runtime: &MachineRuntime,
        machine: &Machine,
        mi: MachineId,
    ) -> Option<TriggerAction> {
        let current = &machine.states[runtime.current_state];

        match current.action {
            Action::InjectPadding { bypass, replace } => Some(TriggerAction::InjectPadding {
                timeout: Duration::from_micros(current.sample_timeout() as u64),
                size: current.sample_size() as u16,
                bypass,
                replace,
                machine: mi,
            }),
            Action::BlockOutgoing { bypass, replace } => Some(TriggerAction::BlockOutgoing {
                timeout: Duration::from_micros(current.sample_timeout() as u64),
                duration: Duration::from_micros(current.sample_block() as u64),
                bypass,
                replace,
                machine: mi,
            }),
            Action::UpdateCounter { counter, decrement } => Some(TriggerAction::UpdateCounter {
                value: current.sample_counter_value(),
                counter,
                decrement,
                machine: mi,
            }),
            Action::UpdateTimer { replace } => Some(TriggerAction::UpdateTimer {
                duration: Duration::from_micros(current.sample_timer_duration() as u64),
                replace,
                machine: mi,
            }),
        }
    }

    fn decrement_limit(&mut self, mi: usize) {
        if self.runtime[mi].state_limit > 0 {
            self.runtime[mi].state_limit -= 1;
        }
        let cs = self.runtime[mi].current_state;

        if self.runtime[mi].state_limit == 0
            && self.machines.as_ref()[mi].states[cs].limit_dist.dist != DistType::None
        {
            // take no action and trigger limit reached
            self.actions[mi] = None;
            // next, we trigger internally event LimitReached
            self.transition(mi, Event::LimitReached);
        }
    }

    fn next_state(
        &self,
        runtime: &MachineRuntime,
        machine: &Machine,
        event: Event,
    ) -> (usize, bool) {
        if !machine.states[runtime.current_state]
            .next_state
            .contains_key(&event)
        {
            return (0, false);
        }
        let next_prob = &machine.states[runtime.current_state].next_state[&event];

        let p = rand::random::<f64>();
        let mut total = 0.0;
        for i in 0..next_prob.len() {
            total += next_prob[i];
            if p <= total {
                // some events are machine-defined, others framework pseudo-states
                match next_prob.len().cmp(&(i + 2)) {
                    Ordering::Greater => return (i, true),
                    Ordering::Less => return (STATE_END, true),
                    Ordering::Equal => return (STATE_CANCEL, true),
                }
            }
        }

        (STATE_NOP, false)
    }

    fn below_action_limits(&self, runtime: &MachineRuntime, machine: &Machine) -> bool {
        let current = &machine.states[runtime.current_state];
        // either blocking or padding limits apply
        match current.action {
            Action::BlockOutgoing { .. } => self.below_limit_blocking(runtime, machine),
            Action::InjectPadding { .. } => self.below_limit_padding(runtime, machine),
            _ => true,
        }
    }

    fn below_limit_blocking(&self, runtime: &MachineRuntime, machine: &Machine) -> bool {
        let current = &machine.states[runtime.current_state];
        // blocking action

        // special case: we always allow overwriting existing blocking
        let replace = if let Action::BlockOutgoing { replace, .. } = current.action {
            replace
        } else {
            false
        };

        if replace && self.blocking_active {
            // we still check against state limit, because it's machine internal
            return runtime.state_limit > 0;
        }

        // compute durations we've been blocking
        let mut m_block_dur = runtime.blocking_duration;
        let mut g_block_dur = self.blocking_duration;
        if self.blocking_active {
            // account for ongoing blocking as well, add duration
            m_block_dur += self.current_time.duration_since(self.blocking_started);
            g_block_dur += self.current_time.duration_since(self.blocking_started);
        }

        // machine allowed blocking duration first, since it bypasses the
        // other two types of limits
        if m_block_dur < Duration::from_micros(machine.allowed_blocked_microsec) {
            // we still check against state limit, because it's machine internal
            return runtime.state_limit > 0;
        }

        // does the machine limit say no, if set?
        if machine.max_blocking_frac > 0.0 {
            // TODO: swap to m_block_dur.div_duration_f64()
            let f: f64 = m_block_dur.as_micros() as f64
                / self
                    .current_time
                    .duration_since(runtime.machine_start)
                    .as_micros() as f64;
            if f >= machine.max_blocking_frac {
                return false;
            }
        }

        // does the framework say no?
        if self.max_blocking_frac > 0.0 {
            // TODO: swap to g_block_dur.div_duration_f64()
            let f: f64 = g_block_dur.as_micros() as f64
                / self
                    .current_time
                    .duration_since(self.framework_start)
                    .as_micros() as f64;
            if f >= self.max_blocking_frac {
                return false;
            }
        }

        // only state-limit left to consider
        runtime.state_limit > 0
    }

    fn below_limit_padding(&self, runtime: &MachineRuntime, machine: &Machine) -> bool {
        // no limits apply if not made up padding count
        if runtime.padding_sent < machine.allowed_padding_packets {
            return runtime.state_limit > 0;
        }

        // hit machine limits?
        if machine.max_padding_frac > 0.0 {
            let total = runtime.nonpadding_sent + runtime.padding_sent;
            if total == 0 {
                return true;
            }
            if runtime.padding_sent as f64 / total as f64 >= machine.max_padding_frac {
                return false;
            }
        }

        // hit global limits?
        if self.max_padding_frac > 0.0 {
            let total = self.padding_sent_packets + self.nonpadding_sent_packets;
            if total == 0 {
                return true;
            }
            if self.padding_sent_packets as f64 / total as f64 >= self.max_padding_frac {
                return false;
            }
        }

        // only state-limit left to consider
        runtime.state_limit > 0
    }
}

#[cfg(test)]
mod tests {
    use crate::dist::*;
    use crate::framework::*;
    use crate::state::*;
    use std::collections::HashMap;
    use std::ops::Add;
    use std::time::Duration;
    use std::time::Instant;

    #[test]
    fn no_machines() {
        let machines = vec![];
        let f = Framework::new(&machines, 0.0, 0.0, Instant::now());
        assert!(!f.is_err());
    }

    #[test]
    fn reuse_machines() {
        let machines = vec![];
        let f1 = Framework::new(&machines, 0.0, 0.0, Instant::now());
        assert!(!f1.is_err());
        let f2 = Framework::new(&machines, 0.0, 0.0, Instant::now());
        assert!(!f2.is_err());
    }

    #[test]
    fn trigger_events_actions() {
        // plan: create a machine that swaps between two states, trigger one
        // then multiple events and check the resulting actions
        let num_states = 2;
        let packet_size: u16 = 150;

        // state 0: go to state 1 on PaddingSent, pad after 10 usec
        let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
        let mut e: HashMap<usize, f64> = HashMap::new();
        e.insert(1, 1.0);
        t.insert(Event::PaddingSent, e);

        let mut s0 = State::new(t, num_states);
        s0.timeout_dist = Dist {
            dist: DistType::Uniform,
            param1: 10.0,
            param2: 10.0,
            start: 0.0,
            max: 0.0,
        };
        s0.action_dist = Dist {
            dist: DistType::Uniform,
            param1: packet_size as f64,
            param2: packet_size as f64,
            start: 0.0,
            max: 0.0,
        };

        // state 1: go to state 0 on PaddingRecv, pad after 1 usec
        let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
        let mut e: HashMap<usize, f64> = HashMap::new();
        e.insert(0, 1.0);
        t.insert(Event::PaddingRecv, e);

        let mut s1 = State::new(t, num_states);
        s1.timeout_dist = Dist {
            dist: DistType::Uniform,
            param1: 1.0,
            param2: 1.0,
            start: 0.0,
            max: 0.0,
        };
        s1.action_dist = Dist {
            dist: DistType::Uniform,
            param1: packet_size as f64,
            param2: packet_size as f64,
            start: 0.0,
            max: 0.0,
        };

        // create a simple machine
        let m = Machine {
            allowed_padding_packets: 1000,
            max_padding_frac: 1.0,
            allowed_blocked_microsec: 0,
            max_blocking_frac: 0.0,
            states: vec![s0, s1],
        };

        let mut current_time = Instant::now();
        let machines = vec![m];
        let mut f = Framework::new(&machines, 0.0, 0.0, current_time).unwrap();

        assert_eq!(f.actions.len(), 1);

        // start triggering
        _ = f.trigger_events(
            &[TriggerEvent::BlockingBegin {
                machine: MachineId(0),
            }],
            current_time,
        );
        assert_eq!(f.actions[0], None);

        // move time forward, trigger again to make sure no scheduled timer
        current_time = current_time.add(Duration::from_micros(20));
        _ = f.trigger_events(
            &[TriggerEvent::BlockingBegin {
                machine: MachineId(0),
            }],
            current_time,
        );
        assert_eq!(f.actions[0], None);

        // trigger transition to next state
        _ = f.trigger_events(
            &[TriggerEvent::PaddingSent {
                machine: MachineId(0),
            }],
            current_time,
        );
        assert_eq!(
            f.actions[0],
            Some(TriggerAction::InjectPadding {
                timeout: Duration::from_micros(1),
                size: packet_size,
                bypass: false,
                replace: false,
                machine: MachineId(0),
            })
        );

        // increase time, trigger event, make sure no further action
        current_time = current_time.add(Duration::from_micros(20));
        _ = f.trigger_events(
            &[TriggerEvent::PaddingSent {
                machine: MachineId(0),
            }],
            current_time,
        );
        assert_eq!(f.actions[0], None);

        // go back to state 0
        _ = f.trigger_events(&[TriggerEvent::PaddingRecv], current_time);
        assert_eq!(
            f.actions[0],
            Some(TriggerAction::InjectPadding {
                timeout: Duration::from_micros(10),
                size: packet_size,
                bypass: false,
                replace: false,
                machine: MachineId(0),
            })
        );

        // test multiple triggers overwriting actions
        for _ in 0..10 {
            _ = f.trigger_events(
                &[
                    TriggerEvent::PaddingSent {
                        machine: MachineId(0),
                    },
                    TriggerEvent::PaddingRecv,
                ],
                current_time,
            );
            assert_eq!(
                f.actions[0],
                Some(TriggerAction::InjectPadding {
                    timeout: Duration::from_micros(10),
                    size: packet_size,
                    bypass: false,
                    replace: false,
                    machine: MachineId(0),
                })
            );
        }

        // triple trigger, swapping between states
        for i in 0..10 {
            if i % 2 == 0 {
                _ = f.trigger_events(
                    &[
                        TriggerEvent::PaddingRecv,
                        TriggerEvent::PaddingSent {
                            machine: MachineId(0),
                        },
                        TriggerEvent::PaddingRecv,
                    ],
                    current_time,
                );
                assert_eq!(
                    f.actions[0],
                    Some(TriggerAction::InjectPadding {
                        timeout: Duration::from_micros(10),
                        size: packet_size,
                        bypass: false,
                        replace: false,
                        machine: MachineId(0),
                    })
                );
            } else {
                _ = f.trigger_events(
                    &[
                        TriggerEvent::PaddingSent {
                            machine: MachineId(0),
                        },
                        TriggerEvent::PaddingRecv,
                        TriggerEvent::PaddingSent {
                            machine: MachineId(0),
                        },
                    ],
                    current_time,
                );
                assert_eq!(
                    f.actions[0],
                    Some(TriggerAction::InjectPadding {
                        timeout: Duration::from_micros(1),
                        size: packet_size,
                        bypass: false,
                        replace: false,
                        machine: MachineId(0),
                    })
                );
            }
        }
    }

    #[test]
    fn blocking_machine() {
        // a machine that blocks for 10us, 1us after NonPaddingSent

        // state 0
        let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
        let mut e: HashMap<usize, f64> = HashMap::new();
        e.insert(0, 1.0);
        t.insert(Event::NonPaddingSent, e);

        let mut s0 = State::new(t, 1);
        s0.timeout_dist = Dist {
            dist: DistType::Uniform,
            param1: 1.0,
            param2: 1.0,
            start: 0.0,
            max: 0.0,
        };
        s0.action_dist = Dist {
            dist: DistType::Uniform,
            param1: 10.0,
            param2: 10.0,
            start: 0.0,
            max: 0.0,
        };
        s0.action = Action::BlockOutgoing {
            bypass: false,
            replace: false,
        };

        // machine
        let m = Machine {
            allowed_padding_packets: 1000,
            max_padding_frac: 1.0,
            allowed_blocked_microsec: 0,
            max_blocking_frac: 0.0,
            states: vec![s0],
        };

        let mut current_time = Instant::now();
        let machines = vec![m];
        let mut f = Framework::new(&machines, 0.0, 0.0, current_time).unwrap();

        _ = f.trigger_events(&[TriggerEvent::NonPaddingSent], current_time);
        assert_eq!(
            f.actions[0],
            Some(TriggerAction::BlockOutgoing {
                timeout: Duration::from_micros(1),
                duration: Duration::from_micros(10),
                bypass: false,
                replace: false,
                machine: MachineId(0),
            })
        );

        current_time = current_time.add(Duration::from_micros(20));
        _ = f.trigger_events(
            &[TriggerEvent::BlockingBegin {
                machine: MachineId(0),
            }],
            current_time,
        );
        assert_eq!(f.actions[0], None);

        for _ in 0..10 {
            current_time = current_time.add(Duration::from_micros(1));
            _ = f.trigger_events(&[TriggerEvent::NonPaddingSent], current_time);
            assert_eq!(
                f.actions[0],
                Some(TriggerAction::BlockOutgoing {
                    timeout: Duration::from_micros(1),
                    duration: Duration::from_micros(10),
                    bypass: false,
                    replace: false,
                    machine: MachineId(0),
                })
            );
        }
    }

    #[test]
    fn counter_machine() {
        // a machine that counts PaddingSent - NonPaddingSent
        // use counter 1 for that, increment counter 0 on CounterZero
        let num_states = 3;

        // state 0
        let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
        let mut e0: HashMap<usize, f64> = HashMap::new();
        e0.insert(1, 1.0);
        let mut e1: HashMap<usize, f64> = HashMap::new();
        e1.insert(2, 1.0);
        t.insert(Event::PaddingSent, e0);
        t.insert(Event::CounterZero, e1);

        let mut s0 = State::new(t, num_states);
        s0.action_dist = Dist {
            dist: DistType::Uniform,
            param1: 1.0,
            param2: 1.0,
            start: 0.0,
            max: 0.0,
        };
        s0.action = Action::UpdateCounter {
            counter: 1,
            decrement: true,
        };

        // state 1
        let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
        let mut e: HashMap<usize, f64> = HashMap::new();
        e.insert(0, 1.0);
        t.insert(Event::NonPaddingSent, e);

        let mut s1 = State::new(t, num_states);
        s1.action_dist = Dist {
            dist: DistType::Uniform,
            param1: 1.0,
            param2: 1.0,
            start: 0.0,
            max: 0.0,
        };
        s1.action = Action::UpdateCounter {
            counter: 1,
            decrement: false,
        };

        // state 2
        let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
        let mut e0: HashMap<usize, f64> = HashMap::new();
        e0.insert(0, 1.0);
        let mut e1: HashMap<usize, f64> = HashMap::new();
        e1.insert(1, 1.0);
        t.insert(Event::NonPaddingSent, e0);
        t.insert(Event::PaddingSent, e1);

        let mut s2 = State::new(t, num_states);
        s2.action_dist = Dist {
            dist: DistType::Uniform,
            param1: 1.0,
            param2: 1.0,
            start: 0.0,
            max: 0.0,
        };
        s2.action = Action::UpdateCounter {
            counter: 0,
            decrement: false,
        };

        // machine
        let m = Machine {
            allowed_padding_packets: 1000,
            max_padding_frac: 1.0,
            allowed_blocked_microsec: 0,
            max_blocking_frac: 0.0,
            states: vec![s0, s1, s2],
        };

        let mut current_time = Instant::now();
        let machines = vec![m];
        let mut f = Framework::new(&machines, 0.0, 0.0, current_time).unwrap();

        _ = f.trigger_events(
            &[TriggerEvent::PaddingSent {
                machine: MachineId(0),
            }],
            current_time,
        );
        assert_eq!(
            f.actions[0],
            Some(TriggerAction::UpdateCounter {
                value: 1,
                counter: 1,
                decrement: false,
                machine: MachineId(0),
            })
        );

        current_time = current_time.add(Duration::from_micros(20));
        _ = f.trigger_events(&[TriggerEvent::NonPaddingSent], current_time);
        assert_eq!(
            f.actions[0],
            Some(TriggerAction::UpdateCounter {
                value: 1,
                counter: 1,
                decrement: true,
                machine: MachineId(0),
            })
        );

        current_time = current_time.add(Duration::from_micros(20));
        _ = f.trigger_events(
            &[TriggerEvent::CounterZero {
                machine: MachineId(0),
            }],
            current_time,
        );
        assert_eq!(
            f.actions[0],
            Some(TriggerAction::UpdateCounter {
                value: 1,
                counter: 0,
                decrement: false,
                machine: MachineId(0),
            })
        );
    }

    #[test]
    fn timer_machine() {
        // a machine that sets the timer to 1 ms after PaddingSent
        let num_states = 2;
        let packet_size: u16 = 150;

        // state 0
        let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
        let mut e: HashMap<usize, f64> = HashMap::new();
        e.insert(1, 1.0);
        t.insert(Event::PaddingSent, e);

        let mut s0 = State::new(t, num_states);
        s0.timeout_dist = Dist {
            dist: DistType::Uniform,
            param1: 1.0,
            param2: 1.0,
            start: 0.0,
            max: 0.0,
        };
        s0.action_dist = Dist {
            dist: DistType::Uniform,
            param1: packet_size as f64,
            param2: packet_size as f64,
            start: 0.0,
            max: 0.0,
        };

        // state 1
        let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
        let mut e: HashMap<usize, f64> = HashMap::new();
        e.insert(0, 1.0);
        t.insert(Event::TimerEnd, e);

        let mut s1 = State::new(t, num_states);
        s1.action_dist = Dist {
            dist: DistType::Uniform,
            param1: 1000.0, // 1 ms
            param2: 1000.0,
            start: 0.0,
            max: 0.0,
        };
        s1.action = Action::UpdateTimer { replace: false };

        // machine
        let m = Machine {
            allowed_padding_packets: 1000,
            max_padding_frac: 1.0,
            allowed_blocked_microsec: 0,
            max_blocking_frac: 0.0,
            states: vec![s0, s1],
        };

        let mut current_time = Instant::now();
        let machines = vec![m];
        let mut f = Framework::new(&machines, 0.0, 0.0, current_time).unwrap();

        _ = f.trigger_events(
            &[TriggerEvent::PaddingSent {
                machine: MachineId(0),
            }],
            current_time,
        );
        assert_eq!(
            f.actions[0],
            Some(TriggerAction::UpdateTimer {
                duration: Duration::from_micros(1000),
                replace: false,
                machine: MachineId(0),
            })
        );

        current_time = current_time.add(Duration::from_micros(20));
        _ = f.trigger_events(
            &[TriggerEvent::TimerEnd {
                machine: MachineId(0),
            }],
            current_time,
        );
        assert_eq!(
            f.actions[0],
            Some(TriggerAction::InjectPadding {
                timeout: Duration::from_micros(1),
                size: packet_size,
                bypass: false,
                replace: false,
                machine: MachineId(0),
            })
        );
    }

    #[test]
    fn machine_max_padding_frac() {
        // We create a machine that should be allowed to send 100*MTU padding
        // bytes before machine padding limits are applied, then the machine
        // should be limited from sending any padding until at least 100*MTU
        // nonpadding bytes have been sent, given the set max padding fraction
        // of 0.5.
        let packet_size: u16 = 1000;

        // state 0
        let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
        let mut e: HashMap<usize, f64> = HashMap::new();
        e.insert(0, 1.0);
        // we use sent for checking limits
        t.insert(Event::PaddingSent, e.clone());
        t.insert(Event::NonPaddingSent, e.clone());
        // recv as an event to check without adding bytes sent
        t.insert(Event::NonPaddingRecv, e.clone());

        let mut s0 = State::new(t, 1);
        s0.timeout_dist = Dist {
            dist: DistType::Uniform,
            param1: 2.0,
            param2: 2.0,
            start: 0.0,
            max: 0.0,
        };
        s0.action_dist = Dist {
            dist: DistType::Uniform,
            param1: packet_size as f64,
            param2: packet_size as f64,
            start: 0.0,
            max: 0.0,
        };

        // machine
        let m = Machine {
            allowed_padding_packets: 100,
            max_padding_frac: 0.5,
            allowed_blocked_microsec: 0,
            max_blocking_frac: 0.0,
            states: vec![s0],
        };

        let current_time = Instant::now();
        let machines = vec![m];
        let mut f = Framework::new(&machines, 0.0, 0.0, current_time).unwrap();

        // transition to get the loop going
        _ = f.trigger_events(&[TriggerEvent::NonPaddingRecv], current_time);

        // we expect 100 padding actions
        for _ in 0..100 {
            assert_eq!(
                f.actions[0],
                Some(TriggerAction::InjectPadding {
                    timeout: Duration::from_micros(2),
                    size: packet_size,
                    bypass: false,
                    replace: false,
                    machine: MachineId(0),
                })
            );

            _ = f.trigger_events(
                &[TriggerEvent::PaddingSent {
                    machine: MachineId(0),
                }],
                current_time,
            );
        }

        // limit hit, last event should prevent the action
        assert_eq!(f.actions[0], None);

        // trigger and check limit again
        _ = f.trigger_events(&[TriggerEvent::NonPaddingRecv], current_time);
        assert_eq!(f.actions[0], None);

        // verify that no padding is scheduled until we've sent the same amount
        // of bytes
        for _ in 0..100 {
            _ = f.trigger_events(&[TriggerEvent::NonPaddingSent], current_time);
            assert_eq!(f.actions[0], None);
        }

        // send one byte of nonpadding, putting us just over the limit
        _ = f.trigger_events(&[TriggerEvent::NonPaddingSent], current_time);

        assert_eq!(
            f.actions[0],
            Some(TriggerAction::InjectPadding {
                timeout: Duration::from_micros(2),
                size: packet_size,
                bypass: false,
                replace: false,
                machine: MachineId(0),
            })
        );
    }

    #[test]
    fn framework_max_padding_frac() {
        // to test the global limits of the framework we create two machines with
        // the same allowed padding, where both machines pad in parallel
        let packet_size: u16 = 1000;

        // state 0
        let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
        let mut e: HashMap<usize, f64> = HashMap::new();
        e.insert(0, 1.0);
        // we use sent for checking limits
        t.insert(Event::PaddingSent, e.clone());
        t.insert(Event::NonPaddingSent, e.clone());
        // recv as an event to check without adding bytes sent
        t.insert(Event::NonPaddingRecv, e.clone());

        let mut s0 = State::new(t, 1);
        s0.timeout_dist = Dist {
            dist: DistType::Uniform,
            param1: 2.0,
            param2: 2.0,
            start: 0.0,
            max: 0.0,
        };
        s0.action_dist = Dist {
            dist: DistType::Uniform,
            param1: packet_size as f64,
            param2: packet_size as f64,
            start: 0.0,
            max: 0.0,
        };

        // machines
        let m1 = Machine {
            allowed_padding_packets: 100,
            max_padding_frac: 0.0, // NOTE
            allowed_blocked_microsec: 0,
            max_blocking_frac: 0.0,
            states: vec![s0],
        };
        let m2 = m1.clone();

        // NOTE 0.5 max_padding_frac below
        let current_time = Instant::now();
        let machines = vec![m1, m2];
        let mut f = Framework::new(&machines, 0.5, 0.0, current_time).unwrap();

        // we have two machines that each can send 100 * mtu before their own or
        // any framework limits are applied (by design, see AllowedPaddingBytes)
        // trigger transition to get the loop going
        _ = f.trigger_events(&[TriggerEvent::NonPaddingRecv], current_time);

        // we expect 100 padding actions per machine
        for _ in 0..100 {
            assert_eq!(
                f.actions[0],
                Some(TriggerAction::InjectPadding {
                    timeout: Duration::from_micros(2),
                    size: packet_size,
                    bypass: false,
                    replace: false,
                    machine: MachineId(0),
                })
            );
            assert_eq!(
                f.actions[1],
                Some(TriggerAction::InjectPadding {
                    timeout: Duration::from_micros(2),
                    size: packet_size,
                    bypass: false,
                    replace: false,
                    machine: MachineId(1),
                })
            );
            _ = f.trigger_events(
                &[
                    TriggerEvent::PaddingSent {
                        machine: MachineId(0),
                    },
                    TriggerEvent::PaddingSent {
                        machine: MachineId(1),
                    },
                ],
                current_time,
            );
        }

        // limit hit, last event should prevent the action and future actions
        assert_eq!(f.actions[0], None);
        assert_eq!(f.actions[1], None);
        _ = f.trigger_events(
            &[TriggerEvent::NonPaddingRecv, TriggerEvent::NonPaddingRecv],
            current_time,
        );
        assert_eq!(f.actions[0], None);
        assert_eq!(f.actions[1], None);

        // in sync?
        assert_eq!(f.runtime[0].padding_sent, f.runtime[1].padding_sent);
        assert_eq!(f.runtime[0].padding_sent, 100);

        // OK, so we've sent in total 2*100*mtu of padding using two machines. This
        // means that we should need to send at least 2*100*mtu + 1 bytes before
        // padding is scheduled again
        for _ in 0..200 {
            _ = f.trigger_events(&[TriggerEvent::NonPaddingSent], current_time);
            assert_eq!(f.actions[0], None);
            assert_eq!(f.actions[1], None);
        }

        // the last byte should tip it over
        _ = f.trigger_events(&[TriggerEvent::NonPaddingSent], current_time);

        assert_eq!(
            f.actions[0],
            Some(TriggerAction::InjectPadding {
                timeout: Duration::from_micros(2),
                size: packet_size,
                bypass: false,
                replace: false,
                machine: MachineId(0),
            })
        );
        assert_eq!(
            f.actions[1],
            Some(TriggerAction::InjectPadding {
                timeout: Duration::from_micros(2),
                size: packet_size,
                bypass: false,
                replace: false,
                machine: MachineId(1),
            })
        );
    }

    #[test]
    fn machine_max_blocking_frac() {
        // We create a machine that should be allowed to block for 10us before
        // machine limits are applied, then the machine should be limited from
        // blocking until after 10us, given the set max blocking fraction of
        // 0.5.

        // state 0
        let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
        let mut e: HashMap<usize, f64> = HashMap::new();
        e.insert(0, 1.0);
        t.insert(Event::BlockingBegin, e.clone());
        t.insert(Event::BlockingEnd, e.clone());
        t.insert(Event::NonPaddingRecv, e.clone());

        let mut s0 = State::new(t, 1);
        // block every 2us for 2us
        s0.timeout_dist = Dist {
            dist: DistType::Uniform,
            param1: 2.0,
            param2: 2.0,
            start: 0.0,
            max: 0.0,
        };
        s0.action_dist = Dist {
            dist: DistType::Uniform,
            param1: 2.0,
            param2: 2.0,
            start: 0.0,
            max: 0.0,
        };
        s0.action = Action::BlockOutgoing {
            bypass: false,
            replace: false,
        };

        // machine
        let m = Machine {
            allowed_padding_packets: 0,
            max_padding_frac: 0.0,
            allowed_blocked_microsec: 10, // NOTE
            max_blocking_frac: 0.5,       // NOTE
            states: vec![s0],
        };

        let mut current_time = Instant::now();
        let machines = vec![m];
        let mut f = Framework::new(&machines, 0.0, 0.0, current_time).unwrap();

        // trigger self to start the blocking (triggers action)
        _ = f.trigger_events(&[TriggerEvent::NonPaddingRecv], current_time);

        // verify that we can block for 5*2=10us
        for _ in 0..5 {
            assert_eq!(
                f.actions[0],
                Some(TriggerAction::BlockOutgoing {
                    timeout: Duration::from_micros(2),
                    duration: Duration::from_micros(2),
                    bypass: false,
                    replace: false,
                    machine: MachineId(0),
                })
            );

            _ = f.trigger_events(
                &[TriggerEvent::BlockingBegin {
                    machine: MachineId(0),
                }],
                current_time,
            );
            assert_eq!(
                f.actions[0],
                Some(TriggerAction::BlockOutgoing {
                    timeout: Duration::from_micros(2),
                    duration: Duration::from_micros(2),
                    bypass: false,
                    replace: false,
                    machine: MachineId(0),
                })
            );
            current_time = current_time.add(Duration::from_micros(2));
            _ = f.trigger_events(&[TriggerEvent::BlockingEnd], current_time);
        }
        assert_eq!(f.actions[0], None);
        assert_eq!(f.runtime[0].blocking_duration, Duration::from_micros(10));

        // now we've burned our blocking budget, should be blocked for 10us
        for _ in 0..5 {
            current_time = current_time.add(Duration::from_micros(2));
            _ = f.trigger_events(&[TriggerEvent::NonPaddingRecv], current_time);
            assert_eq!(f.actions[0], None);
        }
        assert_eq!(f.runtime[0].blocking_duration, Duration::from_micros(10));
        assert_eq!(
            current_time.duration_since(f.runtime[0].machine_start),
            Duration::from_micros(20)
        );

        // push over the limit, should be allowed
        current_time = current_time.add(Duration::from_micros(2));
        _ = f.trigger_events(&[TriggerEvent::NonPaddingRecv], current_time);
        assert_eq!(
            f.actions[0],
            Some(TriggerAction::BlockOutgoing {
                timeout: Duration::from_micros(2),
                duration: Duration::from_micros(2),
                bypass: false,
                replace: false,
                machine: MachineId(0),
            })
        );
    }

    #[test]
    fn framework_max_blocking_frac() {
        // We create a machine that should be allowed to block for 10us before
        // machine limits are applied, then the machine should be limited from
        // blocking until after 10us, given the set max blocking fraction of
        // 0.5 in the framework.

        // state 0
        let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
        let mut e: HashMap<usize, f64> = HashMap::new();
        e.insert(0, 1.0);
        t.insert(Event::BlockingBegin, e.clone());
        t.insert(Event::BlockingEnd, e.clone());
        t.insert(Event::NonPaddingRecv, e.clone());

        let mut s0 = State::new(t, 1);
        // block every 2us for 2us
        s0.timeout_dist = Dist {
            dist: DistType::Uniform,
            param1: 2.0,
            param2: 2.0,
            start: 0.0,
            max: 0.0,
        };
        s0.action_dist = Dist {
            dist: DistType::Uniform,
            param1: 2.0,
            param2: 2.0,
            start: 0.0,
            max: 0.0,
        };
        s0.action = Action::BlockOutgoing {
            bypass: false,
            replace: false,
        };

        // machine
        let m = Machine {
            allowed_padding_packets: 0,
            max_padding_frac: 0.0,
            allowed_blocked_microsec: 10, // NOTE
            max_blocking_frac: 0.0,       // NOTE, 0.0 here, 0.5 in framework below
            states: vec![s0],
        };

        let mut current_time = Instant::now();
        let machines = vec![m];
        let mut f = Framework::new(&machines, 0.0, 0.5, current_time).unwrap();

        // trigger self to start the blocking (triggers action)
        _ = f.trigger_events(&[TriggerEvent::NonPaddingRecv], current_time);

        // verify that we can block for 5*2=10us
        for _ in 0..5 {
            assert_eq!(
                f.actions[0],
                Some(TriggerAction::BlockOutgoing {
                    timeout: Duration::from_micros(2),
                    duration: Duration::from_micros(2),
                    bypass: false,
                    replace: false,
                    machine: MachineId(0),
                })
            );

            _ = f.trigger_events(
                &[TriggerEvent::BlockingBegin {
                    machine: MachineId(0),
                }],
                current_time,
            );
            assert_eq!(
                f.actions[0],
                Some(TriggerAction::BlockOutgoing {
                    timeout: Duration::from_micros(2),
                    duration: Duration::from_micros(2),
                    bypass: false,
                    replace: false,
                    machine: MachineId(0),
                })
            );
            current_time = current_time.add(Duration::from_micros(2));
            _ = f.trigger_events(&[TriggerEvent::BlockingEnd], current_time);
        }
        assert_eq!(f.actions[0], None);
        assert_eq!(f.runtime[0].blocking_duration, Duration::from_micros(10));

        // now we've burned our blocking budget, should be blocked for 10us
        for _ in 0..5 {
            current_time = current_time.add(Duration::from_micros(2));
            _ = f.trigger_events(&[TriggerEvent::NonPaddingRecv], current_time);
            assert_eq!(f.actions[0], None);
        }
        assert_eq!(f.runtime[0].blocking_duration, Duration::from_micros(10));
        assert_eq!(
            current_time.duration_since(f.runtime[0].machine_start),
            Duration::from_micros(20)
        );

        // push over the limit, should be allowed
        current_time = current_time.add(Duration::from_micros(2));
        _ = f.trigger_events(&[TriggerEvent::NonPaddingRecv], current_time);
        assert_eq!(
            f.actions[0],
            Some(TriggerAction::BlockOutgoing {
                timeout: Duration::from_micros(2),
                duration: Duration::from_micros(2),
                bypass: false,
                replace: false,
                machine: MachineId(0),
            })
        );
    }

    #[test]
    fn framework_replace_blocking() {
        // Plan: create two machines. #0 will exceed its blocking limit
        // and no longer be allowed to block. #1 will then enable blocking,
        // so #0 should now be able to overwrite that blocking regardless
        // of its limit (special case in below_limit_blocking).

        // state 0, first machine
        let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
        let mut e: HashMap<usize, f64> = HashMap::new();
        e.insert(0, 1.0);
        t.insert(Event::NonPaddingRecv, e);

        let mut s0 = State::new(t, 1);
        // block every 2us for 2us
        s0.timeout_dist = Dist {
            dist: DistType::Uniform,
            param1: 2.0,
            param2: 2.0,
            start: 0.0,
            max: 0.0,
        };
        s0.action_dist = Dist {
            dist: DistType::Uniform,
            param1: 2.0,
            param2: 2.0,
            start: 0.0,
            max: 0.0,
        };
        s0.action = Action::BlockOutgoing {
            bypass: false,
            replace: true, // NOTE
        };

        // machine 0
        let m0 = Machine {
            allowed_padding_packets: 0,
            max_padding_frac: 0.0,
            allowed_blocked_microsec: 2, // NOTE
            max_blocking_frac: 0.5,      // NOTE
            states: vec![s0],
        };

        // state 0, second machine
        let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
        let mut e: HashMap<usize, f64> = HashMap::new();
        e.insert(0, 1.0);
        t.insert(Event::NonPaddingSent, e);

        let mut s0 = State::new(t, 1);
        // block instantly for 1000us
        s0.timeout_dist = Dist {
            dist: DistType::Uniform,
            param1: 0.0,
            param2: 0.0,
            start: 0.0,
            max: 0.0,
        };
        s0.action_dist = Dist {
            dist: DistType::Uniform,
            param1: 1000.0,
            param2: 1000.0,
            start: 0.0,
            max: 0.0,
        };
        s0.action = Action::BlockOutgoing {
            bypass: false,
            replace: false,
        };

        // machine 1
        let m1 = Machine {
            allowed_padding_packets: 0,
            max_padding_frac: 0.0,
            allowed_blocked_microsec: 0, // NOTE
            max_blocking_frac: 0.0,      // NOTE
            states: vec![s0],
        };

        let mut current_time = Instant::now();
        let machines = vec![m0, m1];
        let mut f = Framework::new(&machines, 0.0, 0.0, current_time).unwrap();

        // trigger to make machine 0 block
        _ = f.trigger_events(&[TriggerEvent::NonPaddingRecv], current_time);

        // verify machine 0 can block for 2us
        assert_eq!(
            f.actions[0],
            Some(TriggerAction::BlockOutgoing {
                timeout: Duration::from_micros(2),
                duration: Duration::from_micros(2),
                bypass: false,
                replace: true,
                machine: MachineId(0),
            })
        );

        _ = f.trigger_events(
            &[TriggerEvent::BlockingBegin {
                machine: MachineId(0),
            }],
            current_time,
        );

        current_time = current_time.add(Duration::from_micros(2));
        _ = f.trigger_events(&[TriggerEvent::BlockingEnd], current_time);

        // ensure machine 0 can no longer block
        _ = f.trigger_events(&[TriggerEvent::NonPaddingRecv], current_time);

        assert_eq!(f.actions[0], None);
        assert_eq!(f.runtime[0].blocking_duration, Duration::from_micros(2));

        // now cause machine 1 to start blocking
        _ = f.trigger_events(&[TriggerEvent::NonPaddingSent], current_time);

        // verify machine 1 blocks as expected
        assert_eq!(
            f.actions[1],
            Some(TriggerAction::BlockOutgoing {
                timeout: Duration::from_micros(0),
                duration: Duration::from_micros(1000),
                bypass: false,
                replace: false,
                machine: MachineId(1),
            })
        );

        _ = f.trigger_events(
            &[TriggerEvent::BlockingBegin {
                machine: MachineId(1),
            }],
            current_time,
        );

        // machine 0 should now be able to replace the blocking
        _ = f.trigger_events(&[TriggerEvent::NonPaddingRecv], current_time);

        assert_eq!(
            f.actions[0],
            Some(TriggerAction::BlockOutgoing {
                timeout: Duration::from_micros(2),
                duration: Duration::from_micros(2),
                bypass: false,
                replace: true,
                machine: MachineId(0),
            })
        );
    }

    #[test]
    fn framework_machine_sampled_limit() {
        // we create a machine that samples a padding limit of 4 padding sent,
        // then should be prevented from padding further by transitioning to
        // self
        let num_states = 2;
        let packet_size: u16 = 1500;

        // state 0
        let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
        let mut e: HashMap<usize, f64> = HashMap::new();
        e.insert(1, 1.0);
        t.insert(Event::NonPaddingSent, e);

        let s0 = State::new(t, num_states);

        // state 1
        let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
        let mut e: HashMap<usize, f64> = HashMap::new();
        e.insert(1, 1.0);
        t.insert(Event::PaddingSent, e);

        let mut s1 = State::new(t, num_states);
        s1.timeout_dist = Dist {
            dist: DistType::Uniform,
            param1: 1.0,
            param2: 1.0,
            start: 0.0,
            max: 0.0,
        };
        s1.action_dist = Dist {
            dist: DistType::Uniform,
            param1: packet_size as f64,
            param2: packet_size as f64,
            start: 0.0,
            max: 0.0,
        };
        s1.limit_dist = Dist {
            dist: DistType::Uniform,
            param1: 4.0,
            param2: 4.0,
            start: 0.0,
            max: 0.0,
        };

        // machine
        let m = Machine {
            allowed_padding_packets: 100000, // NOTE, will not apply
            max_padding_frac: 1.0,           // NOTE, will not apply
            allowed_blocked_microsec: 0,
            max_blocking_frac: 0.0,
            states: vec![s0, s1],
        };

        let mut current_time = Instant::now();
        let machines = vec![m];
        let mut f = Framework::new(&machines, 1.0, 0.0, current_time).unwrap();

        // trigger self to start the padding
        _ = f.trigger_events(&[TriggerEvent::NonPaddingSent], current_time);

        assert_eq!(f.runtime[0].state_limit, 4);

        // verify that we can send 4 padding
        for _ in 0..4 {
            assert_eq!(
                f.actions[0],
                Some(TriggerAction::InjectPadding {
                    timeout: Duration::from_micros(1),
                    size: packet_size,
                    bypass: false,
                    replace: false,
                    machine: MachineId(0),
                })
            );
            current_time = current_time.add(Duration::from_micros(1));
            _ = f.trigger_events(
                &[TriggerEvent::PaddingSent {
                    machine: MachineId(0),
                }],
                current_time,
            );
        }

        // padding accounting correct
        assert_eq!(f.runtime[0].padding_sent, 4);
        assert_eq!(f.runtime[0].nonpadding_sent, 1);

        // limit should be reached after 4 padding, blocking next action
        assert_eq!(f.actions[0], None);
        assert_eq!(f.runtime[0].state_limit, 0);
    }
}

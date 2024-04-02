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
//! let s = "02eNq9zSEBAAAAwrDTvzQegfwKDL7gm7MBNQAD";
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
//!     // number of events but is very fast (time should be dominated by a few
//!     // calls to sample randomness per event per machine).
//!     for action in f.trigger_events(&events, Instant::now()) {
//!         // After triggering all the events, the framework will provide zero
//!         // or more actions to take, up to a maximum of one action per
//!         // machine (regardless of the number of events). It is your
//!         // responsibility to perform those actions according to the
//!         // specification. To do so, you will need two timers per machine. The
//!         // machine identifier (machine in each TriggerAction) uniquely and
//!         // deterministically maps to a single machine running in the framework
//!         // (so suitable as a key for a data structure storing your timers, e.g.
//!         // a HashMap<MachineId, SomeTimerDataStructure>).
//!         match action {
//!             TriggerAction::Cancel { machine: _, timer: _ } => {
//!                 // Cancel the specified timer (action, machine, or both) for the
//!                 // machine in question.
//!             }
//!             TriggerAction::InjectPadding {
//!                 timeout: _,
//!                 bypass: _,
//!                 replace: _,
//!                 machine: _,
//!             } => {
//!                 // Set the action timer with the specified timeout. On expiry,
//!                 // do the following:
//!                 //
//!                 // 1. Queue a padding packet to be sent.
//!                 // 2. Trigger TriggerEvent::PaddingQueued{ machine: machine }.
//!                 // 3. When any padding packet actually is sent over the network,
//!                 //    trigger TriggerEvent::PaddingSent.
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
//!                 // the events should still be triggered (steps 2/3). If enqueued
//!                 // non-padding is sent instead of padding, then NonPaddingSent
//!                 // should be triggered as well.
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
//!                 // If a new timer is started or an existing timer replaced,
//!                 // add TriggerEvent::TimerBegin { machine: machine } to be
//!                 // triggered next loop iteration.
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
use simple_error::bail;

use crate::action::*;
use crate::constants::*;
use crate::counter::*;
use crate::event::*;
use crate::machine::*;
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
    padding_queued: u64,
    nonpadding_queued: u64,
    blocking_duration: Duration,
    machine_start: Instant,
    counter_value_a: u64,
    counter_value_b: u64,
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
    nonpadding_queued_packets: u64,
    padding_queued_packets: u64,
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
    /// make some types of use cases of the framework easier (weird machines and
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
                padding_queued: 0,
                nonpadding_queued: 0,
                blocking_duration: Duration::from_secs(0),
                machine_start: current_time,
                counter_value_a: 0,
                counter_value_b: 0,
            };
            machines.as_ref().len()
        ];

        for (mi, r) in runtime.iter_mut().enumerate() {
            let opt_action = machines.as_ref()[mi].states[0].state.action;

            if let Some(action) = opt_action {
                r.state_limit = action.sample_limit();
            }
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
            padding_queued_packets: 0,
            nonpadding_queued_packets: 0,
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
                // accounting is based on queued, not sent
                for mi in 0..self.runtime.len() {
                    self.transition(mi, Event::NonPaddingSent);
                }
            }
            TriggerEvent::PaddingSent => {
                // the event is global: tell all machines
                for mi in 0..self.runtime.len() {
                    self.transition(mi, Event::PaddingSent);
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
                        && self.runtime[mi].current_state != STATE_END
                        && mi == machine.0
                    {
                        // decrement only makes sense if we didn't
                        // change state and for the machine in question
                        self.decrement_limit(mi);
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
            TriggerEvent::TimerBegin { machine } => {
                let mi = machine.0;
                if mi >= self.runtime.len() {
                    return;
                }
                if self.transition(mi, Event::TimerBegin) == StateChange::Unchanged
                    && self.runtime[mi].current_state != STATE_END
                {
                    // decrement only makes sense if we didn't change state
                    self.decrement_limit(machine.0);
                }
            }
            TriggerEvent::TimerEnd { machine } => {
                let mi = machine.0;
                if mi >= self.runtime.len() {
                    return;
                }
                self.transition(mi, Event::TimerEnd);
            }
            TriggerEvent::NonPaddingQueued => {
                self.nonpadding_queued_packets += 1;

                for mi in 0..self.runtime.len() {
                    self.runtime[mi].nonpadding_queued += 1;

                    // If the transition leaves the state unchanged, decrement the
                    // limit. If the state changed, a new limit was sampled and this
                    // packet shouldn't count.
                    if self.transition(mi, Event::NonPaddingQueued) == StateChange::Unchanged
                        && self.runtime[mi].current_state != STATE_END
                    {
                        self.decrement_limit(mi);
                    }
                }
            }
            TriggerEvent::PaddingQueued { machine } => {
                self.padding_queued_packets += 1;

                let mi = machine.0;
                if mi >= self.runtime.len() {
                    return;
                }
                self.runtime[mi].padding_queued += 1;
                if self.transition(mi, Event::PaddingQueued) == StateChange::Unchanged
                    && self.runtime[mi].current_state != STATE_END
                {
                    // decrement only makes sense if we didn't change state
                    self.decrement_limit(mi);
                }
            }
        };
    }

    fn transition(&mut self, mi: usize, event: Event) -> StateChange {
        // a machine in end state cannot transition
        if self.runtime[mi].current_state == STATE_END {
            return StateChange::Unchanged;
        }

        // sample next state
        let next_state;
        // new block for immutable ref, makes things less ugly
        {
            let machine = &self.machines.as_ref()[mi];
            let state = &machine.states[self.runtime[mi].current_state];
            next_state = state.sample_state(event);
        }

        // if no next state on event, done
        if next_state.is_none() || next_state.unwrap() == STATE_NOP {
            return StateChange::Unchanged;
        }
        let next_state = next_state.unwrap();

        // we got a next state, act on it
        match next_state {
            STATE_CANCEL => {
                // cancel any pending action, but doesn't count as a state change
                self.actions[mi] = Some(TriggerAction::Cancel {
                    machine: MachineId(mi),
                    timer: Timer::All,
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
                let state_changed = if self.runtime[mi].current_state == next_state {
                    StateChange::Unchanged
                } else {
                    self.runtime[mi].current_state = next_state;
                    self.runtime[mi].state_limit = if let Some(action) =
                        self.machines.as_ref()[mi].states[next_state].state.action
                    {
                        action.sample_limit()
                    } else {
                        STATE_LIMIT_MAX
                    };
                    StateChange::Changed
                };

                // update the counter and check if transitioned
                let (trans, zeroed) = self.update_counter(mi);
                if zeroed {
                    if trans == StateChange::Changed {
                        return trans;
                    } else {
                        return state_changed;
                    }
                }

                if self.below_action_limits(&self.runtime[mi], &self.machines.as_ref()[mi]) {
                    self.actions[mi] = self.schedule_action(
                        &self.runtime[mi],
                        &self.machines.as_ref()[mi],
                        MachineId(mi),
                    );
                }

                state_changed
            }
        }
    }

    fn update_counter(&mut self, mi: usize) -> (StateChange, bool) {
        let current = &self.machines.as_ref()[mi].states[self.runtime[mi].current_state];

        if let Some(update) = &current.state.counter_update {
            let value = update.sample_value();
            let counter = if update.counter == Counter::CounterA {
                &mut self.runtime[mi].counter_value_a
            } else {
                &mut self.runtime[mi].counter_value_b
            };
            let already_zero = *counter == 0;

            match update.operation {
                CounterOperation::Increment => {
                    *counter = counter.saturating_add(value);
                }
                CounterOperation::Decrement => {
                    *counter = counter.saturating_sub(value);
                }
                CounterOperation::Set => {
                    *counter = value;
                }
            }

            if *counter == 0 && !already_zero {
                self.actions[mi] = None;
                let result = self.transition(mi, Event::CounterZero);
                return (result, true);
            }
        }
        // Do nothing if counter value is unchanged or not zero
        (StateChange::Unchanged, false)
    }

    fn schedule_action(
        &self,
        runtime: &MachineRuntime,
        machine: &Machine,
        mi: MachineId,
    ) -> Option<TriggerAction> {
        let current = &machine.states[runtime.current_state];
        let action = current.state.action?;

        match action {
            Action::Cancel { timer } => Some(TriggerAction::Cancel { machine: mi, timer }),
            Action::InjectPadding {
                bypass, replace, ..
            } => Some(TriggerAction::InjectPadding {
                timeout: Duration::from_micros(action.sample_timeout().unwrap() as u64),
                bypass,
                replace,
                machine: mi,
            }),
            Action::BlockOutgoing {
                bypass, replace, ..
            } => Some(TriggerAction::BlockOutgoing {
                timeout: Duration::from_micros(action.sample_timeout().unwrap() as u64),
                duration: Duration::from_micros(action.sample_duration().unwrap() as u64),
                bypass,
                replace,
                machine: mi,
            }),
            Action::UpdateTimer { replace, .. } => Some(TriggerAction::UpdateTimer {
                duration: Duration::from_micros(action.sample_duration().unwrap() as u64),
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

        if let Some(action) = self.machines.as_ref()[mi].states[cs].state.action {
            if self.runtime[mi].state_limit == 0 && action.has_limit() {
                // take no action and trigger limit reached
                self.actions[mi] = None;
                // next, we trigger internally event LimitReached
                self.transition(mi, Event::LimitReached);
            }
        }
    }

    fn below_action_limits(&self, runtime: &MachineRuntime, machine: &Machine) -> bool {
        let current = &machine.states[runtime.current_state];

        if current.state.action.is_none() {
            // This could be true, but no need for an extra call to schedule_action()
            return false;
        }

        match current.state.action.unwrap() {
            Action::BlockOutgoing { .. } => self.below_limit_blocking(runtime, machine),
            Action::InjectPadding { .. } => self.below_limit_padding(runtime, machine),
            Action::UpdateTimer { .. } => runtime.state_limit > 0,
            _ => true,
        }
    }

    fn below_limit_blocking(&self, runtime: &MachineRuntime, machine: &Machine) -> bool {
        let current = &machine.states[runtime.current_state];
        // blocking action

        // special case: we always allow overwriting existing blocking
        let replace = if let Some(Action::BlockOutgoing { replace, .. }) = current.state.action {
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
        if runtime.padding_queued < machine.allowed_padding_packets {
            return runtime.state_limit > 0;
        }

        // hit machine limits?
        if machine.max_padding_frac > 0.0 {
            let total = runtime.nonpadding_queued + runtime.padding_queued;
            if total == 0 {
                return true;
            }
            if runtime.padding_queued as f64 / total as f64 >= machine.max_padding_frac {
                return false;
            }
        }

        // hit global limits?
        if self.max_padding_frac > 0.0 {
            let total = self.padding_queued_packets + self.nonpadding_queued_packets;
            if total == 0 {
                return true;
            }
            if self.padding_queued_packets as f64 / total as f64 >= self.max_padding_frac {
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
    use enum_map::{enum_map, EnumMap};
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

        // state 0: go to state 1 on PaddingSent, pad after 10 usec
        let mut t: EnumMap<Event, Vec<StateTransition>> = enum_map! { _ => vec![] };
        t[Event::PaddingSent].push(StateTransition {
            state: 1,
            probability: 1.0,
        });

        let mut s0 = State::new(t);
        s0.action = Some(Action::InjectPadding {
            bypass: false,
            replace: false,
            timeout_dist: Dist {
                dist: DistType::Uniform {
                    low: 10.0,
                    high: 10.0,
                },
                start: 0.0,
                max: 0.0,
            },
            limit_dist: None,
        });

        // state 1: go to state 0 on PaddingRecv, pad after 1 usec
        let mut t: EnumMap<Event, Vec<StateTransition>> = enum_map! { _ => vec![] };
        t[Event::PaddingRecv].push(StateTransition {
            state: 0,
            probability: 1.0,
        });

        let mut s1 = State::new(t);
        s1.action = Some(Action::InjectPadding {
            bypass: false,
            replace: false,
            timeout_dist: Dist {
                dist: DistType::Uniform {
                    low: 1.0,
                    high: 1.0,
                },

                start: 0.0,
                max: 0.0,
            },
            limit_dist: None,
        });

        // create a simple machine
        let m = Machine::new(1000, 1.0, 0, 0.0, vec![s0, s1]).unwrap();

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
        _ = f.trigger_events(&[TriggerEvent::PaddingSent], current_time);
        assert_eq!(
            f.actions[0],
            Some(TriggerAction::InjectPadding {
                timeout: Duration::from_micros(1),
                bypass: false,
                replace: false,
                machine: MachineId(0),
            })
        );

        // increase time, trigger event, make sure no further action
        current_time = current_time.add(Duration::from_micros(20));
        _ = f.trigger_events(&[TriggerEvent::PaddingSent], current_time);
        assert_eq!(f.actions[0], None);

        // go back to state 0
        _ = f.trigger_events(&[TriggerEvent::PaddingRecv], current_time);
        assert_eq!(
            f.actions[0],
            Some(TriggerAction::InjectPadding {
                timeout: Duration::from_micros(10),
                bypass: false,
                replace: false,
                machine: MachineId(0),
            })
        );

        // test multiple triggers overwriting actions
        for _ in 0..10 {
            _ = f.trigger_events(
                &[TriggerEvent::PaddingSent, TriggerEvent::PaddingRecv],
                current_time,
            );
            assert_eq!(
                f.actions[0],
                Some(TriggerAction::InjectPadding {
                    timeout: Duration::from_micros(10),
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
                        TriggerEvent::PaddingSent,
                        TriggerEvent::PaddingRecv,
                    ],
                    current_time,
                );
                assert_eq!(
                    f.actions[0],
                    Some(TriggerAction::InjectPadding {
                        timeout: Duration::from_micros(10),
                        bypass: false,
                        replace: false,
                        machine: MachineId(0),
                    })
                );
            } else {
                _ = f.trigger_events(
                    &[
                        TriggerEvent::PaddingSent,
                        TriggerEvent::PaddingRecv,
                        TriggerEvent::PaddingSent,
                    ],
                    current_time,
                );
                assert_eq!(
                    f.actions[0],
                    Some(TriggerAction::InjectPadding {
                        timeout: Duration::from_micros(1),
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
        let mut t: EnumMap<Event, Vec<StateTransition>> = enum_map! { _ => vec![] };
        t[Event::NonPaddingSent].push(StateTransition {
            state: 0,
            probability: 1.0,
        });

        let mut s0 = State::new(t);
        s0.action = Some(Action::BlockOutgoing {
            bypass: false,
            replace: false,
            timeout_dist: Dist {
                dist: DistType::Uniform {
                    low: 1.0,
                    high: 1.0,
                },
                start: 0.0,
                max: 0.0,
            },
            action_dist: Dist {
                dist: DistType::Uniform {
                    low: 10.0,
                    high: 10.0,
                },
                start: 0.0,
                max: 0.0,
            },
            limit_dist: None,
        });

        // machine
        let m = Machine::new(1000, 1.0, 0, 0.0, vec![s0]).unwrap();

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
    fn timer_machine() {
        // a machine that sets the timer to 1 ms after PaddingSent

        // state 0
        let mut t: EnumMap<Event, Vec<StateTransition>> = enum_map! { _ => vec![] };
        t[Event::PaddingSent].push(StateTransition {
            state: 1,
            probability: 1.0,
        });

        let mut s0 = State::new(t);
        s0.action = Some(Action::InjectPadding {
            bypass: false,
            replace: false,
            timeout_dist: Dist {
                dist: DistType::Uniform {
                    low: 1.0,
                    high: 1.0,
                },

                start: 0.0,
                max: 0.0,
            },
            limit_dist: None,
        });

        // state 1
        let mut t: EnumMap<Event, Vec<StateTransition>> = enum_map! { _ => vec![] };
        t[Event::TimerEnd].push(StateTransition {
            state: 0,
            probability: 1.0,
        });

        let mut s1 = State::new(t);
        s1.action = Some(Action::UpdateTimer {
            replace: false,
            action_dist: Dist {
                dist: DistType::Uniform {
                    low: 1000.0,
                    high: 1000.0,
                },
                start: 0.0,
                max: 0.0,
            },
            limit_dist: None,
        });

        // machine
        let m = Machine::new(1000, 1.0, 0, 0.0, vec![s0, s1]).unwrap();

        let mut current_time = Instant::now();
        let machines = vec![m];
        let mut f = Framework::new(&machines, 0.0, 0.0, current_time).unwrap();

        _ = f.trigger_events(&[TriggerEvent::PaddingSent], current_time);
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
                bypass: false,
                replace: false,
                machine: MachineId(0),
            })
        );
    }

    #[test]
    fn counter_machine() {
        // a machine that counts PaddingSent - NonPaddingSent
        // use counter A for that, pad and increment counter B on CounterZero

        // state 0
        let mut t: EnumMap<Event, Vec<StateTransition>> = enum_map! { _ => vec![] };
        t[Event::PaddingSent].push(StateTransition {
            state: 1,
            probability: 1.0,
        });
        t[Event::CounterZero].push(StateTransition {
            state: 2,
            probability: 1.0,
        });

        let mut s0 = State::new(t);
        s0.counter_update = Some(CounterUpdate {
            counter: Counter::CounterA,
            operation: CounterOperation::Decrement,
            value_dist: Dist {
                dist: DistType::Uniform {
                    low: 1.0,
                    high: 1.0,
                },
                start: 0.0,
                max: 0.0,
            },
        });

        // state 1
        let mut t: EnumMap<Event, Vec<StateTransition>> = enum_map! { _ => vec![] };
        t[Event::NonPaddingSent].push(StateTransition {
            state: 0,
            probability: 1.0,
        });

        let mut s1 = State::new(t);
        s1.counter_update = Some(CounterUpdate {
            counter: Counter::CounterA,
            operation: CounterOperation::Increment,
            value_dist: Dist {
                dist: DistType::Uniform {
                    low: 1.0,
                    high: 1.0,
                },
                start: 0.0,
                max: 0.0,
            },
        });

        // state 2
        let mut t: EnumMap<Event, Vec<StateTransition>> = enum_map! { _ => vec![] };
        t[Event::NonPaddingSent].push(StateTransition {
            state: 0,
            probability: 1.0,
        });
        t[Event::PaddingSent].push(StateTransition {
            state: 1,
            probability: 1.0,
        });

        let mut s2 = State::new(t);
        s2.action = Some(Action::InjectPadding {
            bypass: false,
            replace: false,
            timeout_dist: Dist {
                dist: DistType::Uniform {
                    low: 2.0,
                    high: 2.0,
                },
                start: 0.0,
                max: 0.0,
            },
            limit_dist: None,
        });
        s2.counter_update = Some(CounterUpdate {
            counter: Counter::CounterB,
            operation: CounterOperation::Increment,
            value_dist: Dist {
                dist: DistType::Uniform {
                    low: 4.0,
                    high: 4.0,
                },
                start: 0.0,
                max: 0.0,
            },
        });

        // machine
        let m = Machine::new(1000, 1.0, 0, 0.0, vec![s0, s1, s2]).unwrap();

        let mut current_time = Instant::now();
        let machines = vec![m];
        let mut f = Framework::new(&machines, 0.0, 0.0, current_time).unwrap();

        _ = f.trigger_events(&[TriggerEvent::PaddingSent], current_time);
        assert_eq!(f.actions[0], None);
        assert_eq!(f.runtime[0].counter_value_a, 1);

        current_time = current_time.add(Duration::from_micros(20));
        _ = f.trigger_events(&[TriggerEvent::NonPaddingSent], current_time);
        assert_eq!(
            f.actions[0],
            Some(TriggerAction::InjectPadding {
                timeout: Duration::from_micros(2),
                bypass: false,
                replace: false,
                machine: MachineId(0),
            })
        );
        assert_eq!(f.runtime[0].counter_value_a, 0);
        assert_eq!(f.runtime[0].counter_value_b, 4);
    }

    #[test]
    fn counter_underflow_machine() {
        // check that underflow of counter value cannot occur
        // ensure CounterZero is not triggered when counter is already 0

        // state 0, decrement counter
        let mut t: EnumMap<Event, Vec<StateTransition>> = enum_map! { _ => vec![] };
        t[Event::NonPaddingSent].push(StateTransition {
            state: 0,
            probability: 1.0,
        });
        t[Event::NonPaddingRecv].push(StateTransition {
            state: 1,
            probability: 1.0,
        });
        t[Event::CounterZero].push(StateTransition {
            state: 2,
            probability: 1.0,
        });

        let mut s0 = State::new(t);
        s0.counter_update = Some(CounterUpdate {
            counter: Counter::CounterB,
            operation: CounterOperation::Decrement, // NOTE
            value_dist: Dist {
                dist: DistType::Uniform {
                    low: 10.0,
                    high: 10.0,
                },

                start: 0.0,
                max: 0.0,
            },
        });

        // state 1, set counter
        let mut t: EnumMap<Event, Vec<StateTransition>> = enum_map! { _ => vec![] };
        t[Event::NonPaddingSent].push(StateTransition {
            state: 0,
            probability: 1.0,
        });
        t[Event::NonPaddingRecv].push(StateTransition {
            state: 1,
            probability: 1.0,
        });
        t[Event::CounterZero].push(StateTransition {
            state: 2,
            probability: 1.0,
        });

        let mut s1 = State::new(t);
        s1.counter_update = Some(CounterUpdate {
            counter: Counter::CounterB,
            operation: CounterOperation::Set,
            value_dist: Dist {
                dist: DistType::Uniform {
                    low: 0.0, // NOTE
                    high: 0.0,
                },
                start: 0.0,
                max: 0.0,
            },
        });

        // state 2, pad
        let mut t: EnumMap<Event, Vec<StateTransition>> = enum_map! { _ => vec![] };
        t[Event::NonPaddingSent].push(StateTransition {
            state: 0,
            probability: 1.0,
        });
        t[Event::NonPaddingRecv].push(StateTransition {
            state: 1,
            probability: 1.0,
        });

        let mut s2 = State::new(t);
        s2.action = Some(Action::InjectPadding {
            bypass: false,
            replace: false,
            timeout_dist: Dist {
                dist: DistType::Uniform {
                    low: 2.0,
                    high: 2.0,
                },
                start: 0.0,
                max: 0.0,
            },
            limit_dist: None,
        });

        // machine
        let m = Machine::new(1000, 1.0, 0, 0.0, vec![s0, s1, s2]).unwrap();

        let current_time = Instant::now();
        let machines = vec![m];
        let mut f = Framework::new(&machines, 0.0, 0.0, current_time).unwrap();

        // decrement counter to 0
        _ = f.trigger_events(&[TriggerEvent::NonPaddingSent], current_time);
        assert_eq!(f.actions[0], None);
        assert_eq!(f.runtime[0].counter_value_b, 0);

        // set counter to 0
        _ = f.trigger_events(&[TriggerEvent::NonPaddingRecv], current_time);
        assert_eq!(f.actions[0], None);
        assert_eq!(f.runtime[0].counter_value_b, 0);
    }

    #[test]
    fn counter_overflow_machine() {
        // check that overflow of counter value cannot occur
        // set to max value, then try to add and make sure no change

        // state 0, increment counter
        let mut t: EnumMap<Event, Vec<StateTransition>> = enum_map! { _ => vec![] };
        t[Event::NonPaddingSent].push(StateTransition {
            state: 0,
            probability: 1.0,
        });
        t[Event::NonPaddingRecv].push(StateTransition {
            state: 1,
            probability: 1.0,
        });

        let mut s0 = State::new(t);
        s0.counter_update = Some(CounterUpdate {
            counter: Counter::CounterA,
            operation: CounterOperation::Increment, // NOTE
            value_dist: Dist {
                dist: DistType::Uniform {
                    low: 1000.0,
                    high: 1000.0,
                },
                start: 0.0,
                max: 0.0,
            },
        });

        // state 1, set counter
        let mut t: EnumMap<Event, Vec<StateTransition>> = enum_map! { _ => vec![] };
        t[Event::NonPaddingSent].push(StateTransition {
            state: 0,
            probability: 1.0,
        });
        t[Event::NonPaddingRecv].push(StateTransition {
            state: 1,
            probability: 1.0,
        });

        let mut s1 = State::new(t);
        s1.counter_update = Some(CounterUpdate {
            counter: Counter::CounterA,
            operation: CounterOperation::Set,
            value_dist: Dist {
                dist: DistType::Uniform {
                    low: u64::MAX as f64, // NOTE
                    high: u64::MAX as f64,
                },
                start: 0.0,
                max: 0.0,
            },
        });

        // machine
        let m = Machine::new(1000, 1.0, 0, 0.0, vec![s0, s1]).unwrap();

        let current_time = Instant::now();
        let machines = vec![m];
        let mut f = Framework::new(&machines, 0.0, 0.0, current_time).unwrap();

        // set counter to u64::MAX
        _ = f.trigger_events(&[TriggerEvent::NonPaddingRecv], current_time);
        assert_eq!(f.runtime[0].counter_value_a, u64::MAX);

        // try to increment counter by 1000
        _ = f.trigger_events(&[TriggerEvent::NonPaddingSent], current_time);
        assert_eq!(f.runtime[0].counter_value_a, u64::MAX);
    }

    #[test]
    fn machine_max_padding_frac() {
        // We create a machine that should be allowed to send 100 padding
        // packets before machine padding limits are applied, then the machine
        // should be limited from sending any padding until at least 100
        // nonpadding packets have been sent, given the set max padding fraction
        // of 0.5.

        // state 0
        let mut t: EnumMap<Event, Vec<StateTransition>> = enum_map! { _ => vec![] };
        // we use queued for checking limits
        t[Event::PaddingQueued].push(StateTransition {
            state: 0,
            probability: 1.0,
        });
        t[Event::NonPaddingQueued].push(StateTransition {
            state: 0,
            probability: 1.0,
        });
        // recv as an event to check without adding bytes sent
        t[Event::NonPaddingRecv].push(StateTransition {
            state: 0,
            probability: 1.0,
        });

        let mut s0 = State::new(t);
        s0.action = Some(Action::InjectPadding {
            bypass: false,
            replace: false,
            timeout_dist: Dist {
                dist: DistType::Uniform {
                    low: 2.0,
                    high: 2.0,
                },
                start: 0.0,
                max: 0.0,
            },
            limit_dist: None,
        });

        // machine
        let m = Machine::new(100, 0.5, 0, 0.0, vec![s0]).unwrap();

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
                    bypass: false,
                    replace: false,
                    machine: MachineId(0),
                })
            );

            _ = f.trigger_events(
                &[TriggerEvent::PaddingQueued {
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
            _ = f.trigger_events(&[TriggerEvent::NonPaddingQueued], current_time);
            assert_eq!(f.actions[0], None);
        }

        // send one byte of nonpadding, putting us just over the limit
        _ = f.trigger_events(&[TriggerEvent::NonPaddingQueued], current_time);

        assert_eq!(
            f.actions[0],
            Some(TriggerAction::InjectPadding {
                timeout: Duration::from_micros(2),
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

        // state 0
        let mut t: EnumMap<Event, Vec<StateTransition>> = enum_map! { _ => vec![] };
        // we use queued for checking limits
        t[Event::PaddingQueued].push(StateTransition {
            state: 0,
            probability: 1.0,
        });
        t[Event::NonPaddingQueued].push(StateTransition {
            state: 0,
            probability: 1.0,
        });
        // recv as an event to check without adding bytes sent
        t[Event::NonPaddingRecv].push(StateTransition {
            state: 0,
            probability: 1.0,
        });

        let mut s0 = State::new(t);
        s0.action = Some(Action::InjectPadding {
            bypass: false,
            replace: false,
            timeout_dist: Dist {
                dist: DistType::Uniform {
                    low: 2.0,
                    high: 2.0,
                },
                start: 0.0,
                max: 0.0,
            },
            limit_dist: None,
        });

        // machines
        let m1 = Machine::new(100, 0.0, 0, 0.0, vec![s0]).unwrap();
        let m2 = m1.clone();

        // NOTE 0.5 max_padding_frac below
        let current_time = Instant::now();
        let machines = vec![m1, m2];
        let mut f = Framework::new(&machines, 0.5, 0.0, current_time).unwrap();

        // we have two machines that each can send 100 packets before their own
        // or any framework limits are applied (by design, see
        // allowed_padding_packets) trigger transition to get the loop going
        _ = f.trigger_events(&[TriggerEvent::NonPaddingRecv], current_time);

        // we expect 100 padding actions per machine
        for _ in 0..100 {
            assert_eq!(
                f.actions[0],
                Some(TriggerAction::InjectPadding {
                    timeout: Duration::from_micros(2),
                    bypass: false,
                    replace: false,
                    machine: MachineId(0),
                })
            );
            assert_eq!(
                f.actions[1],
                Some(TriggerAction::InjectPadding {
                    timeout: Duration::from_micros(2),
                    bypass: false,
                    replace: false,
                    machine: MachineId(1),
                })
            );
            _ = f.trigger_events(
                &[
                    TriggerEvent::PaddingQueued {
                        machine: MachineId(0),
                    },
                    TriggerEvent::PaddingQueued {
                        machine: MachineId(1),
                    },
                    TriggerEvent::PaddingSent,
                    TriggerEvent::PaddingSent,
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
        assert_eq!(f.runtime[0].padding_queued, f.runtime[1].padding_queued);
        assert_eq!(f.runtime[0].padding_queued, 100);

        // OK, so we've sent in total 2*100*mtu of padding using two machines. This
        // means that we should need to send at least 2*100*mtu + 1 bytes before
        // padding is scheduled again
        for _ in 0..200 {
            _ = f.trigger_events(&[TriggerEvent::NonPaddingQueued], current_time);
            assert_eq!(f.actions[0], None);
            assert_eq!(f.actions[1], None);
        }

        // the last byte should tip it over
        _ = f.trigger_events(&[TriggerEvent::NonPaddingQueued], current_time);

        assert_eq!(
            f.actions[0],
            Some(TriggerAction::InjectPadding {
                timeout: Duration::from_micros(2),
                bypass: false,
                replace: false,
                machine: MachineId(0),
            })
        );
        assert_eq!(
            f.actions[1],
            Some(TriggerAction::InjectPadding {
                timeout: Duration::from_micros(2),
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
        let mut t: EnumMap<Event, Vec<StateTransition>> = enum_map! { _ => vec![] };
        t[Event::BlockingBegin].push(StateTransition {
            state: 0,
            probability: 1.0,
        });
        t[Event::BlockingEnd].push(StateTransition {
            state: 0,
            probability: 1.0,
        });
        t[Event::NonPaddingRecv].push(StateTransition {
            state: 0,
            probability: 1.0,
        });

        let mut s0 = State::new(t);
        // block every 2us for 2us
        s0.action = Some(Action::BlockOutgoing {
            bypass: false,
            replace: false,
            timeout_dist: Dist {
                dist: DistType::Uniform {
                    low: 2.0,
                    high: 2.0,
                },
                start: 0.0,
                max: 0.0,
            },
            action_dist: Dist {
                dist: DistType::Uniform {
                    low: 2.0,
                    high: 2.0,
                },
                start: 0.0,
                max: 0.0,
            },
            limit_dist: None,
        });

        // machine
        let m = Machine::new(0, 0.0, 10, 0.5, vec![s0]).unwrap();

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
        let mut t: EnumMap<Event, Vec<StateTransition>> = enum_map! { _ => vec![] };
        t[Event::BlockingBegin].push(StateTransition {
            state: 0,
            probability: 1.0,
        });
        t[Event::BlockingEnd].push(StateTransition {
            state: 0,
            probability: 1.0,
        });
        t[Event::NonPaddingRecv].push(StateTransition {
            state: 0,
            probability: 1.0,
        });

        let mut s0 = State::new(t);
        // block every 2us for 2us
        s0.action = Some(Action::BlockOutgoing {
            bypass: false,
            replace: false,
            timeout_dist: Dist {
                dist: DistType::Uniform {
                    low: 2.0,
                    high: 2.0,
                },

                start: 0.0,
                max: 0.0,
            },
            action_dist: Dist {
                dist: DistType::Uniform {
                    low: 2.0,
                    high: 2.0,
                },

                start: 0.0,
                max: 0.0,
            },
            limit_dist: None,
        });

        // machine
        let m = Machine::new(0, 0.0, 10, 0.0, vec![s0]).unwrap();

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
        let mut t: EnumMap<Event, Vec<StateTransition>> = enum_map! { _ => vec![] };
        t[Event::NonPaddingRecv].push(StateTransition {
            state: 0,
            probability: 1.0,
        });

        let mut s0 = State::new(t);
        // block every 2us for 2us
        s0.action = Some(Action::BlockOutgoing {
            bypass: false,
            replace: true, // NOTE
            timeout_dist: Dist {
                dist: DistType::Uniform {
                    low: 2.0,
                    high: 2.0,
                },
                start: 0.0,
                max: 0.0,
            },
            action_dist: Dist {
                dist: DistType::Uniform {
                    low: 2.0,
                    high: 2.0,
                },
                start: 0.0,
                max: 0.0,
            },
            limit_dist: None,
        });

        // machine 0
        let m0 = Machine::new(0, 0.0, 2, 0.5, vec![s0]).unwrap();

        // state 0, second machine
        let mut t: EnumMap<Event, Vec<StateTransition>> = enum_map! { _ => vec![] };
        t[Event::NonPaddingSent].push(StateTransition {
            state: 0,
            probability: 1.0,
        });

        let mut s0 = State::new(t);
        // block instantly for 1000us
        s0.action = Some(Action::BlockOutgoing {
            bypass: false,
            replace: false,
            timeout_dist: Dist {
                dist: DistType::Uniform {
                    low: 0.0,
                    high: 0.0,
                },

                start: 0.0,
                max: 0.0,
            },
            action_dist: Dist {
                dist: DistType::Uniform {
                    low: 1000.0,
                    high: 1000.0,
                },
                start: 0.0,
                max: 0.0,
            },
            limit_dist: None,
        });

        // machine 1
        let m1 = Machine::new(0, 0.0, 0, 0.0, vec![s0]).unwrap();

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

        // state 0
        let mut t: EnumMap<Event, Vec<StateTransition>> = enum_map! { _ => vec![] };
        t[Event::NonPaddingQueued].push(StateTransition {
            state: 1,
            probability: 1.0,
        });

        let s0 = State::new(t);

        // state 1
        let mut t: EnumMap<Event, Vec<StateTransition>> = enum_map! { _ => vec![] };
        t[Event::PaddingQueued].push(StateTransition {
            state: 1,
            probability: 1.0,
        });

        let mut s1 = State::new(t);
        s1.action = Some(Action::InjectPadding {
            bypass: false,
            replace: false,
            timeout_dist: Dist {
                dist: DistType::Uniform {
                    low: 1.0,
                    high: 1.0,
                },
                start: 0.0,
                max: 0.0,
            },
            limit_dist: Some(Dist {
                dist: DistType::Uniform {
                    low: 4.0,
                    high: 4.0,
                },
                start: 0.0,
                max: 0.0,
            }),
        });

        // machine
        let m = Machine::new(100000, 0.0, 0, 0.0, vec![s0, s1]).unwrap();

        let mut current_time = Instant::now();
        let machines = vec![m];
        let mut f = Framework::new(&machines, 0.0, 0.0, current_time).unwrap();

        // trigger self to start the padding
        _ = f.trigger_events(&[TriggerEvent::NonPaddingQueued], current_time);

        assert_eq!(f.runtime[0].state_limit, 4);

        // verify that we can send 4 padding
        for _ in 0..4 {
            assert_eq!(
                f.actions[0],
                Some(TriggerAction::InjectPadding {
                    timeout: Duration::from_micros(1),
                    bypass: false,
                    replace: false,
                    machine: MachineId(0),
                })
            );
            current_time = current_time.add(Duration::from_micros(1));
            _ = f.trigger_events(
                &[TriggerEvent::PaddingQueued {
                    machine: MachineId(0),
                }],
                current_time,
            );
        }

        // padding accounting correct
        assert_eq!(f.runtime[0].padding_queued, 4);
        assert_eq!(f.runtime[0].nonpadding_queued, 1);

        // limit should be reached after 4 padding, blocking next action
        assert_eq!(f.actions[0], None);
        assert_eq!(f.runtime[0].state_limit, 0);
    }
}

//! Maybenot is a framework for traffic analysis defenses that hide patterns in
//! encrypted communication.

use rand_core::Rng;

use crate::limit::{LimitDecoy, LimitDelay};
use crate::{
    Error, LimitDecoyNone, LimitDelayNone, Machine, TriggerAction, TriggerEvent, action, constants,
    counter, event,
};

use self::action::Action;
use self::constants::{STATE_END, STATE_LIMIT_MAX, STATE_SIGNAL};
use self::counter::Operation;
use self::event::Event;
use crate::time::Duration as _;

/// An opaque token representing one machine running inside the framework.
/// Values are guaranteed to be in the range 0..[Framework::num_machines], so
/// raw values using [`MachineId::into_raw`] are suitable for indexing a slice
/// of of at least [`Framework::num_machines`] elements. This is handy for
/// framework integration and keeping associated state with a performance focus,
/// but care must be taken to avoid out-of-bounds accesses (i.e., not very Rust
/// idiomatic).
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct MachineId(usize);

impl MachineId {
    /// Create a new machine identifier from a raw integer. Intended for use
    /// with the `machine` field of [`TriggerAction`] and [`TriggerEvent`]. For
    /// testing and FFI-wrapper purposes only. For regular use, use
    /// [`MachineId`] returned by [Framework::trigger_events]. Triggering an
    /// event in the framework for a machine that does not exist does not raise
    /// a panic or any error.
    pub fn from_raw(raw: usize) -> Self {
        MachineId(raw)
    }

    /// Return the raw integer representation of the machine identifier. For
    /// testing and FFI-wrapper purposes only. For regular use, use the
    /// [`MachineId`] returned by [Framework::trigger_events].
    pub fn into_raw(self) -> usize {
        self.0
    }
}

#[derive(Debug, Clone)]
struct MachineRuntime {
    current_state: usize,
    state_limit: u64,
    decoys_sent: u64,
    counter_a: u64,
    counter_b: u64,
}

#[derive(PartialEq)]
enum StateChange {
    Changed,
    Unchanged,
}

/// An internal signal target for signaling other machines. A machine will not
/// signal itself, but, if multiple machines send signals at the same time, then
/// a signal will be sent to all machines.
#[derive(Clone, Debug)]
enum SignalTarget {
    All,
    AllExcept(usize),
}

/// An instance of the Maybenot framework.
///
/// An instance of the [`Framework`] repeatedly takes as *input* one or more
/// [`TriggerEvent`] describing the encrypted traffic going over an encrypted
/// channel, and produces as *output* zero or more [`TriggerAction`], such as to
/// *send decoy traffic* or *delay outgoing traffic*. One or more [`Machine`]
/// determine what [`TriggerAction`] to take based on [`TriggerEvent`].
#[derive(Clone, Debug)]
pub struct Framework<M, R, T = std::time::Instant, C = LimitDecoyNone, L = LimitDelayNone>
where
    T: crate::time::Instant,
    C: LimitDecoy<T>,
    L: LimitDelay<T>,
{
    // updated each time the framework is triggered
    pub(crate) current_time: T,
    // random number generator, used for sampling distributions and transitions
    rng: R,
    // we allocate the actions vector once and reuse it, handing out references
    // as part of the iterator in [`Framework::trigger_events`].
    pub(crate) actions: Vec<Option<TriggerAction<T>>>,
    // the machines are immutable, but we need to keep track of their runtime
    // state (size independent of number of states in the machine).
    machines: M,
    runtime: Vec<MachineRuntime>,
    // decoy limit
    decoy_limit: C,
    // delay limit
    delay_limit: L,
    // delay accounting
    delay_duration: T::Duration,
    delay_started: T,
    delay_active: bool,
    // for internal signaling: if set, specifies the target machines to signal
    signal_pending: Option<SignalTarget>,
    // only allow each counter to be zeroed once per trigger_events call
    counter_zeroed_once: (bool, bool),
}

impl<M, R, T, C, L> Framework<M, R, T, C, L>
where
    M: AsRef<[Machine]>,
    R: Rng,
    T: crate::time::Instant,
    C: LimitDecoy<T>,
    L: LimitDelay<T>,
{
    /// Create a new framework instance with zero or more [`Machine`].
    ///
    /// The `decoy_limit` parameter controls decoy traffic generation. Use
    /// [`LimitDecoyNone`](crate::LimitDecoyNone) to allow all decoys (subject
    /// to per-machine limits), or [`LimitDecoyFrac`](crate::LimitDecoyFrac) to
    /// limit decoys to a fraction of total traffic.
    ///
    /// The `delay_limit` parameter controls delay traffic generation. Use
    /// [`LimitDelayNone`](crate::LimitDelayNone) to allow all delays (subject
    /// to per-machine limits), or [`LimitDelayFrac`](crate::LimitDelayFrac) to
    /// limit delays to a fraction of a rolling time window.
    ///
    /// The current time is handed to the framework here (and later in
    /// [`Self::trigger_events()`]) to make some types of use cases of the
    /// framework easier (weird machines and for simulation). The generic time
    /// type also allows for using custom time sources. This can for example
    /// improve performance.
    ///
    /// Returns an error on any invalid [`Machine`].
    pub fn new(
        machines: M,
        decoy_limit: C,
        delay_limit: L,
        current_time: T,
        rng: R,
    ) -> Result<Self, Error> {
        let mut runtime = Vec::with_capacity(machines.as_ref().len());
        for m in machines.as_ref() {
            m.validate()?;
            runtime.push(MachineRuntime {
                current_state: 0,
                state_limit: 0,
                decoys_sent: 0,
                counter_a: 0,
                counter_b: 0,
            });
        }

        let actions = vec![None; machines.as_ref().len()];

        // take ownership of rng before using it below to sample limits
        let mut s = Self {
            actions,
            machines,
            runtime,
            current_time,
            rng,
            decoy_limit,
            delay_limit,
            delay_active: false,
            delay_started: current_time,
            delay_duration: T::Duration::zero(),
            signal_pending: None,
            counter_zeroed_once: (false, false),
        };

        for (runtime, machine) in s.runtime.iter_mut().zip(s.machines.as_ref().iter()) {
            if let Some(action) = machine.states[0].action {
                runtime.state_limit = action.sample_limit(&mut s.rng);
            }
        }

        Ok(s)
    }

    /// Returns the number of machines in the framework.
    pub fn num_machines(&self) -> usize {
        self.machines.as_ref().len()
    }

    /// Returns true if all machines have reached the end state. This typically
    /// means that the framework should be dropped (remember to let all
    /// triggered actions expire and their effects be fully realized though).
    pub fn all_machines_ended(&self) -> bool {
        // TODO: consider if this functionality should be a TriggerAction
        // instead, but could be problematic with the action rate limiting
        self.runtime.iter().all(|r| r.current_state == STATE_END)
    }

    /// Trigger zero or more [`TriggerEvent`] for all machines running in the
    /// framework.
    ///
    /// The `current_time` SHOULD be the current time at the time of calling the
    /// method (e.g., [`Instant::now()`](std::time::Instant::now())).
    ///
    /// In more detail, the `current_time` SHOULD be a monotonically
    /// nondecreasing clock. This means that the time passed SHOULD never be
    /// earlier than what was given to [`Framework::new()`] or a previous call
    /// to `trigger_events` for the same framework instance. If this requirement
    /// is not followed, delay durations MAY be inaccurately accounted for,
    /// leading to less or more [`TriggerAction::DelayTraffic`] than intended by
    /// set framework and machine limits. The consequences of this depend on the
    /// running machines (e.g., a machine may also decoy as a consequence of
    /// delaying) and the use-case for the user of the framework.
    ///
    /// Returns an iterator of zero or more [`TriggerAction`] that MUST be taken
    /// by the caller.
    pub fn trigger_events<'a>(
        &'a mut self,
        events: &[TriggerEvent],
        current_time: T,
    ) -> impl Iterator<Item = &'a TriggerAction<T>> + use<'a, M, R, T, C, L> {
        // reset all actions
        self.actions.fill(None);

        // reset flags for zeroed counters (allowed to zero once per call)
        self.counter_zeroed_once = (false, false);

        // Process all events: note that each event may lead to up to one action
        // per machine, but that future events may replace those actions. Under
        // load, this is preferable (because something already happened before
        // we could cause an action, so better to catch up).
        self.current_time = current_time;
        for e in events {
            self.process_event(e);
        }

        // handle internal signaling: at most one signal per call to
        // trigger_events for sake of batching remaining a safety mechanism for
        // integrators (NOTE how self.signal_pending is consumed here with
        // take())
        if let Some(signal) = self.signal_pending.take() {
            // keep track of if we should exclude a machine
            let excluded = match signal {
                SignalTarget::All => None,
                SignalTarget::AllExcept(excluded) => Some(excluded),
            };

            // signal all machines, except the excluded one
            for mi in 0..self.runtime.len() {
                if let Some(excluded) = excluded {
                    if excluded == mi {
                        continue;
                    }
                }
                self.transition(mi, Event::Signal);
            }

            // edge case: if the signalling above resulted in another signal AND
            // we excluded a machine, then we need to signal the excluded
            // machine as well (per definition, the signal must have come from
            // another machine)
            if self.signal_pending.take().is_some() {
                if let Some(excluded) = excluded {
                    self.transition(excluded, Event::Signal);
                }
            }
        }

        // only return actions, no None
        self.actions.iter().filter_map(|action| action.as_ref())
    }

    fn process_event(&mut self, e: &TriggerEvent) {
        match e {
            TriggerEvent::NormalRecv => {
                // no special accounting needed
                for mi in 0..self.runtime.len() {
                    self.transition(mi, Event::NormalRecv);
                }
            }
            TriggerEvent::DecoyRecv => {
                // no special accounting needed
                for mi in 0..self.runtime.len() {
                    self.transition(mi, Event::DecoyRecv);
                }
            }
            TriggerEvent::PacketRecv => {
                // no special accounting needed
                for mi in 0..self.runtime.len() {
                    self.transition(mi, Event::PacketRecv);
                }
            }
            TriggerEvent::NormalQueued => {
                self.decoy_limit.normal_queued(self.current_time);

                for mi in 0..self.runtime.len() {
                    self.transition(mi, Event::NormalQueued);
                }
            }
            TriggerEvent::DecoyQueued { machine } => {
                self.decoy_limit.decoy_queued(self.current_time, *machine);

                let mi = machine.into_raw();
                if mi >= self.runtime.len() {
                    return;
                }
                self.runtime[mi].decoys_sent = self.runtime[mi].decoys_sent.saturating_add(1);
                if self.transition(mi, Event::DecoyQueued) == StateChange::Unchanged
                    && self.runtime[mi].current_state != STATE_END
                {
                    // decrement only makes sense if we didn't change state
                    self.decrement_state_limit(mi);
                }
            }
            TriggerEvent::PacketSent => {
                self.decoy_limit.packet_sent(self.current_time);

                for mi in 0..self.runtime.len() {
                    self.transition(mi, Event::PacketSent);
                }
            }
            TriggerEvent::DelayBegin { machine } => {
                self.delay_limit.delay_begin(self.current_time);

                // keep track of when we start delaying traffic (for accounting
                // in DelayEnd)
                if !self.delay_active {
                    self.delay_active = true;
                    self.delay_started = self.current_time;
                }

                // delaying traffic is a global event
                for mi in 0..self.runtime.len() {
                    if self.transition(mi, Event::DelayBegin) == StateChange::Unchanged
                        && self.runtime[mi].current_state != STATE_END
                        && mi == machine.into_raw()
                    {
                        // decrement only makes sense if we didn't
                        // change state and for the machine in question
                        self.decrement_state_limit(mi);
                    }
                }
            }
            TriggerEvent::DelayEnd => {
                self.delay_limit.delay_end(self.current_time);

                if self.delay_active {
                    let delayed = self
                        .current_time
                        .saturating_duration_since(self.delay_started);
                    self.delay_duration += delayed; // Duration has AddAssign trait with overflow protection
                    self.delay_active = false;
                }

                // delaying traffic is a global event
                for mi in 0..self.runtime.len() {
                    self.transition(mi, Event::DelayEnd);
                }
            }
            TriggerEvent::TimerBegin { machine } => {
                let mi = machine.into_raw();
                if mi >= self.runtime.len() {
                    return;
                }
                if self.transition(mi, Event::TimerBegin) == StateChange::Unchanged
                    && self.runtime[mi].current_state != STATE_END
                {
                    // decrement only makes sense if we didn't change state
                    self.decrement_state_limit(machine.into_raw());
                }
            }
            TriggerEvent::TimerEnd { machine } => {
                let mi = machine.into_raw();
                if mi >= self.runtime.len() {
                    return;
                }
                self.transition(mi, Event::TimerEnd);
            }
            TriggerEvent::Congestion => {
                self.decoy_limit.congestion(self.current_time);
                self.delay_limit.congestion(self.current_time);

                for mi in 0..self.runtime.len() {
                    self.transition(mi, Event::Congestion);
                }
            }
        }
    }

    fn transition(&mut self, mi: usize, event: Event) -> StateChange {
        // a machine in end state cannot transition
        if self.runtime[mi].current_state == STATE_END {
            return StateChange::Unchanged;
        }

        // sample next state
        // new block for immutable ref, makes things less ugly
        let next_state = {
            let machine = &self.machines.as_ref()[mi];
            let state = &machine.states[self.runtime[mi].current_state];
            state.sample_state(event, &mut self.rng)
        };

        // if no next state on event, done
        let Some(next_state) = next_state else {
            return StateChange::Unchanged;
        };

        // we got a next state, act on it
        match next_state {
            STATE_END => {
                // this is a state change (because we can never reach here if already in
                // STATE_END, see first check above), but we don't cancel any pending
                // action, nor schedule any new action
                self.runtime[mi].current_state = STATE_END;
                StateChange::Changed
            }
            STATE_SIGNAL => {
                // this is not a state change, just signal *other* machines
                self.signal_pending = match self.signal_pending {
                    // no signal pending, so signal all *other* machines
                    None => Some(SignalTarget::AllExcept(mi)),
                    // signal already pending from another machine, so signal
                    // all machines (including this one)
                    _ => Some(SignalTarget::All),
                };
                StateChange::Unchanged
            }
            _ => {
                let curr_state = self.runtime[mi].current_state;

                // transition to same or different state?
                if curr_state != next_state {
                    self.runtime[mi].current_state = next_state;
                    self.runtime[mi].state_limit = if let Some(action) =
                        self.machines.as_ref()[mi].states[next_state].action
                    {
                        action.sample_limit(&mut self.rng)
                    } else {
                        STATE_LIMIT_MAX
                    };
                }

                // update the counter, possible recursion: we need to update the
                // counter before scheduling an action; otherwise, counters will
                // be updated in reverse order. but we also don't want to
                // overwrite actions from later transitions, so check here.
                // finally, two chained transitions in and out of a state should
                // count as a changed state, so we need to keep track of it to
                // not prematurely decrement any limit.
                let (below_limits, apply_limits) =
                    self.below_action_limits(&self.runtime[mi], &self.machines.as_ref()[mi], mi);
                let (allow_schedule, state_changed) = self.update_counter(mi);

                // schedule an action if allowed by counter update and below all limits
                if allow_schedule && below_limits {
                    self.schedule_action(mi, next_state);

                    // if the limit allowed us to schedule the action, apply any
                    // max values
                    if apply_limits {
                        if let Some(TriggerAction::DecoyTraffic {
                            timeout: _,
                            n,
                            bypass: _,
                            replace: _,
                            machine,
                        }) = &mut self.actions[mi]
                        {
                            // respect the limit, but never schedule less than 1
                            // decoy (this can happen due to rounding in
                            // implementations)
                            *n = (*n)
                                .min(self.decoy_limit.max_decoys(self.current_time, *machine))
                                .max(1)
                        }

                        if let Some(TriggerAction::DelayTraffic {
                            n,
                            duration,
                            machine,
                            ..
                        }) = &mut self.actions[mi]
                        {
                            // respect the limit, but never schedule less than 1
                            // decoy (this can happen due to rounding in
                            // implementations)
                            *n = (*n)
                                .min(
                                    self.delay_limit
                                        .max_delayed_packets(self.current_time, *machine),
                                )
                                .max(1);
                            let max_dur = self
                                .delay_limit
                                .max_delayed_duration(self.current_time, *machine);
                            if *duration > max_dur && !max_dur.is_zero() {
                                *duration = max_dur;
                            }
                        }
                    }
                }

                if curr_state == self.runtime[mi].current_state && !state_changed {
                    StateChange::Unchanged
                } else {
                    StateChange::Changed
                }
            }
        }
    }

    fn update_counter(&mut self, mi: usize) -> (bool, bool) {
        let state = &self.machines.as_ref()[mi].states[self.runtime[mi].current_state];

        let old_value_a = self.runtime[mi].counter_a;
        let old_value_b = self.runtime[mi].counter_b;
        let mut any_counter_zeroed = false;

        // counter A and B are independent, so we update them separately
        if let Some(counter_a) = state.counter.0 {
            let change = if counter_a.copy {
                old_value_b
            } else {
                counter_a.sample_value(&mut self.rng)
            };

            let updated_value_a = &mut self.runtime[mi].counter_a;
            match counter_a.operation {
                Operation::Increment => {
                    *updated_value_a = updated_value_a.saturating_add(change);
                }
                Operation::Decrement => {
                    *updated_value_a = updated_value_a.saturating_sub(change);
                }
                Operation::Set => {
                    *updated_value_a = change;
                }
            }

            if old_value_a != 0 && *updated_value_a == 0 && !self.counter_zeroed_once.0 {
                any_counter_zeroed = true;
                self.counter_zeroed_once.0 = true;
            }
        }

        if let Some(counter_b) = state.counter.1 {
            let change = if counter_b.copy {
                old_value_a
            } else {
                counter_b.sample_value(&mut self.rng)
            };

            let updated_value_b = &mut self.runtime[mi].counter_b;
            match counter_b.operation {
                Operation::Increment => {
                    *updated_value_b = updated_value_b.saturating_add(change);
                }
                Operation::Decrement => {
                    *updated_value_b = updated_value_b.saturating_sub(change);
                }
                Operation::Set => {
                    *updated_value_b = change;
                }
            }

            if old_value_b != 0 && *updated_value_b == 0 && !self.counter_zeroed_once.1 {
                any_counter_zeroed = true;
                self.counter_zeroed_once.1 = true;
            }
        }

        if any_counter_zeroed {
            let state_changed = self.transition(mi, Event::CounterZero);
            return (
                self.actions[mi].is_none(),
                state_changed == StateChange::Changed,
            );
        }

        // no action scheduled, and state unchanged
        (true, false)
    }

    fn schedule_action(&mut self, mi: usize, state: usize) {
        let index = MachineId(mi);
        let action = self.machines.as_ref()[mi].states[state].action;

        self.actions[mi] = match action {
            Some(action) => match action {
                Action::Cancel { timer } => Some(TriggerAction::Cancel {
                    machine: index,
                    timer,
                }),
                Action::DecoyTraffic {
                    bypass, replace, ..
                } => Some(TriggerAction::DecoyTraffic {
                    timeout: T::Duration::from_micros(action.sample_timeout(&mut self.rng)),
                    n: action.sample_decoy_n(&mut self.rng),
                    bypass,
                    replace,
                    machine: index,
                }),
                Action::DelayTraffic {
                    bypass, replace, ..
                } => Some(TriggerAction::DelayTraffic {
                    timeout: T::Duration::from_micros(action.sample_timeout(&mut self.rng)),
                    n: action.sample_delay_n(&mut self.rng),
                    duration: T::Duration::from_micros(action.sample_duration(&mut self.rng)),
                    bypass,
                    replace,
                    machine: index,
                }),
                Action::UpdateTimer { replace, .. } => Some(TriggerAction::UpdateTimer {
                    duration: T::Duration::from_micros(action.sample_duration(&mut self.rng)),
                    replace,
                    machine: index,
                }),
            },
            None => None,
        };
    }

    fn decrement_state_limit(&mut self, mi: usize) {
        if self.runtime[mi].state_limit > 0 {
            self.runtime[mi].state_limit -= 1;
        }
        let cs = self.runtime[mi].current_state;

        if let Some(action) = self.machines.as_ref()[mi].states[cs].action {
            if self.runtime[mi].state_limit == 0 && action.has_limit() {
                // take no action and trigger limit reached
                self.actions[mi] = None;
                // next, we trigger internally event LimitReached
                self.transition(mi, Event::LimitReached);
            }
        }
    }

    fn below_action_limits(
        &self,
        runtime: &MachineRuntime,
        machine: &Machine,
        mi: usize,
    ) -> (bool, bool) {
        let current = &machine.states[runtime.current_state];

        let Some(action) = current.action else {
            return (false, false);
        };

        match action {
            Action::DelayTraffic { .. } => self.below_limit_delay(runtime, machine, mi),
            Action::DecoyTraffic { .. } => self.below_limit_decoy(runtime, machine, mi),
            Action::UpdateTimer { .. } => (runtime.state_limit > 0, false),
            _ => (true, false),
        }
    }

    fn below_limit_delay(
        &self,
        runtime: &MachineRuntime,
        machine: &Machine,
        mi: usize,
    ) -> (bool, bool) {
        // compute duration we've been delaying
        let mut total_delay_duration = self.delay_duration;
        if self.delay_active {
            // account for ongoing delay as well, add duration
            total_delay_duration += self
                .current_time
                .saturating_duration_since(self.delay_started);
        }

        // machine allowed delay duration first, since it bypasses the limit
        if total_delay_duration < T::Duration::from_micros(machine.allowed_delay_microsec) {
            // we still check against state limit, because it's machine internal
            return (runtime.state_limit > 0, false);
        }

        // check limit
        if !self
            .delay_limit
            .allow_delay(self.current_time, MachineId(mi))
        {
            return (false, false);
        }

        // only state-limit left to consider
        (runtime.state_limit > 0, true)
    }

    fn below_limit_decoy(
        &self,
        runtime: &MachineRuntime,
        machine: &Machine,
        mi: usize,
    ) -> (bool, bool) {
        // per-machine allowed decoys bypass limit
        if runtime.decoys_sent < machine.allowed_decoy_packets {
            return (runtime.state_limit > 0, false);
        }

        // check limit
        if !self
            .decoy_limit
            .allow_decoy(self.current_time, MachineId(mi))
        {
            return (false, false);
        }

        // only state-limit left to consider
        (runtime.state_limit > 0, true)
    }
}

#[cfg(test)]
mod tests;

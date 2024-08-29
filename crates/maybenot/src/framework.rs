//! Maybenot is a framework for traffic analysis defenses that hide patterns in
//! encrypted communication.

use rand_core::RngCore;

use crate::*;

use self::action::Action;
use self::constants::{STATE_END, STATE_LIMIT_MAX, STATE_SIGNAL};
use self::counter::Operation;
use self::event::Event;
use crate::time::Duration as _;

/// An opaque token representing one machine running inside the framework.
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
struct MachineRuntime<T: crate::time::Instant> {
    current_state: usize,
    state_limit: u64,
    padding_sent: u64,
    normal_sent: u64,
    blocking_duration: T::Duration,
    machine_start: T,
    allowed_blocked_microsec: T::Duration,
    counter_a: u64,
    counter_b: u64,
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
/// channel, and produces as *output* zero or more [`TriggerAction`], such as to
/// *send padding* traffic or *block outgoing* traffic. One or more [`Machine`]
/// determine what [`TriggerAction`] to take based on [`TriggerEvent`].
#[derive(Clone, Debug)]
pub struct Framework<M, R, T = std::time::Instant>
where
    T: crate::time::Instant,
{
    // updated each time the framework is triggered
    current_time: T,
    // random number generator, used for sampling distributions and transitions
    rng: R,
    // we allocate the actions vector once and reuse it, handing out references
    // as part of the iterator in [`Framework::trigger_events`].
    actions: Vec<Option<TriggerAction<T>>>,
    // the machines are immutable, but we need to keep track of their runtime
    // state (size independent of number of states in the machine).
    machines: M,
    runtime: Vec<MachineRuntime<T>>,
    // padding accounting
    max_padding_frac: f64,
    normal_sent_packets: u64,
    padding_sent_packets: u64,
    // blocking accounting
    max_blocking_frac: f64,
    blocking_duration: T::Duration,
    blocking_started: T,
    blocking_active: bool,
    // internal signaling: if None then we don't signal, Some(None) means all
    // machines receive the signal, Some(Some(...)) means one machine doesn't
    // (the one that sent the signal)
    signal_pending: Option<Option<usize>>,
    framework_start: T,
}

impl<M, R, T> Framework<M, R, T>
where
    M: AsRef<[Machine]>,
    R: RngCore,
    T: crate::time::Instant,
{
    /// Create a new framework instance with zero or more [`Machine`].
    ///
    /// The max padding/blocking fractions are enforced as a total across all machines.
    /// The only way those limits can be violated are through
    /// [`Machine::allowed_padding_packets`] and
    /// [`Machine::allowed_blocked_microsec`], respectively.
    ///
    /// The current time is handed to the framework here (and later in [`Self::trigger_events()`])
    /// to make some types of use cases of the framework easier (weird machines and
    /// for simulation). The generic time type also allows for using custom time sources.
    /// This can for example improve performance.
    ///
    /// Returns an error on any invalid [`Machine`] or limits not being fractions [0.0, 1.0].
    pub fn new(
        machines: M,
        max_padding_frac: f64,
        max_blocking_frac: f64,
        current_time: T,
        rng: R,
    ) -> Result<Self, Error> {
        if !(0.0..=1.0).contains(&max_padding_frac) {
            Err(Error::PaddingLimit)?;
        }
        if !(0.0..=1.0).contains(&max_blocking_frac) {
            Err(Error::BlockingLimit)?;
        }

        let mut runtime = Vec::with_capacity(machines.as_ref().len());
        for m in machines.as_ref() {
            m.validate()?;
            runtime.push(MachineRuntime {
                current_state: 0,
                state_limit: 0,
                padding_sent: 0,
                normal_sent: 0,
                blocking_duration: T::Duration::zero(),
                machine_start: current_time,
                allowed_blocked_microsec: T::Duration::from_micros(m.allowed_blocked_microsec),
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
            max_blocking_frac,
            max_padding_frac,
            framework_start: current_time,
            blocking_active: false,
            blocking_started: current_time,
            blocking_duration: T::Duration::zero(),
            padding_sent_packets: 0,
            normal_sent_packets: 0,
            signal_pending: None,
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
    /// is not followed, blocking durations MAY be inaccurately accounted for,
    /// leading to less or more [`TriggerAction::BlockOutgoing`] than intended
    /// by set framework and machine limits. The consequences of this depend on
    /// the running machines (e.g., a machine may also pad as a consequence of
    /// blocking) and the use-case for the user of the framework.
    ///
    /// Returns an iterator of zero or more [`TriggerAction`] that MUST be taken
    /// by the caller.
    pub fn trigger_events(
        &mut self,
        events: &[TriggerEvent],
        current_time: T,
    ) -> impl Iterator<Item = &TriggerAction<T>> {
        // reset all actions
        self.actions.fill(None);

        // Process all events: note that each event may lead to up to one action
        // per machine, but that future events may replace those actions.
        // Under load, this is preferable (because something already happened
        // before we could cause an action, so better to catch up).
        self.current_time = current_time;
        for e in events {
            self.process_event(e);

            // handle internal signaling
            // Special case: if a machine sends a signal which results in another
            // signal in response, that response may or may not be received; this
            // depends on the order in which machines are given to the framework.
            // Check for this explicitly (keep track of excluded machines).
            if let Some(signal) = self.signal_pending {
                let mut excluded = None;

                for mi in 0..self.runtime.len() {
                    if signal.is_some() && signal.unwrap() == mi {
                        excluded = Some(mi);
                        continue;
                    }
                    self.transition(mi, Event::Signal);
                }

                if let Some(excluded) = excluded {
                    if self.signal_pending.unwrap().is_none() {
                        self.transition(excluded, Event::Signal);
                    }
                }
                self.signal_pending = None;
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
            TriggerEvent::PaddingRecv => {
                // no special accounting needed
                for mi in 0..self.runtime.len() {
                    self.transition(mi, Event::PaddingRecv);
                }
            }
            TriggerEvent::TunnelRecv => {
                // no special accounting needed
                for mi in 0..self.runtime.len() {
                    self.transition(mi, Event::TunnelRecv);
                }
            }
            TriggerEvent::NormalSent => {
                self.normal_sent_packets += 1;

                for mi in 0..self.runtime.len() {
                    self.runtime[mi].normal_sent += 1;

                    self.transition(mi, Event::NormalSent);
                }
            }
            TriggerEvent::PaddingSent { machine } => {
                self.padding_sent_packets += 1;

                let mi = machine.into_raw();
                if mi >= self.runtime.len() {
                    return;
                }
                self.runtime[mi].padding_sent += 1;
                if self.transition(mi, Event::PaddingSent) == StateChange::Unchanged
                    && self.runtime[mi].current_state != STATE_END
                {
                    // decrement only makes sense if we didn't change state
                    self.decrement_limit(mi);
                }
            }
            TriggerEvent::TunnelSent => {
                // accounting is based on normal/padding sent, not tunnel
                for mi in 0..self.runtime.len() {
                    self.transition(mi, Event::TunnelSent);
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
                        && mi == machine.into_raw()
                    {
                        // decrement only makes sense if we didn't
                        // change state and for the machine in question
                        self.decrement_limit(mi);
                    }
                }
            }
            TriggerEvent::BlockingEnd => {
                let mut blocked = T::Duration::zero();
                if self.blocking_active {
                    blocked = self
                        .current_time
                        .saturating_duration_since(self.blocking_started);
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
                let mi = machine.into_raw();
                if mi >= self.runtime.len() {
                    return;
                }
                if self.transition(mi, Event::TimerBegin) == StateChange::Unchanged
                    && self.runtime[mi].current_state != STATE_END
                {
                    // decrement only makes sense if we didn't change state
                    self.decrement_limit(machine.into_raw());
                }
            }
            TriggerEvent::TimerEnd { machine } => {
                let mi = machine.into_raw();
                if mi >= self.runtime.len() {
                    return;
                }
                self.transition(mi, Event::TimerEnd);
            }
        };
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
                    None => Some(Some(mi)),
                    // signal pending from another machine, so signal all
                    // machines (including this one) by removing any machine
                    // index set
                    _ => Some(None),
                };
                StateChange::Unchanged
            }
            _ => {
                // transition to same or different state?
                let state_changed = if self.runtime[mi].current_state == next_state {
                    StateChange::Unchanged
                } else {
                    self.runtime[mi].current_state = next_state;
                    self.runtime[mi].state_limit = if let Some(action) =
                        self.machines.as_ref()[mi].states[next_state].action
                    {
                        action.sample_limit(&mut self.rng)
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
                    self.schedule_action(mi);
                }

                state_changed
            }
        }
    }

    fn update_counter(&mut self, mi: usize) -> (StateChange, bool) {
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

            if old_value_a != 0 && *updated_value_a == 0 {
                any_counter_zeroed = true;
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

            if old_value_b != 0 && *updated_value_b == 0 {
                any_counter_zeroed = true;
            }
        }

        if any_counter_zeroed {
            self.actions[mi] = None;
            return (self.transition(mi, Event::CounterZero), true);
        }

        // do nothing if counter value is unchanged or not zero
        (StateChange::Unchanged, false)
    }

    fn schedule_action(&mut self, mi: usize) {
        let index = MachineId(mi);
        let action = self.machines.as_ref()[mi].states[self.runtime[mi].current_state].action;

        self.actions[mi] = match action {
            Some(action) => match action {
                Action::Cancel { timer } => Some(TriggerAction::Cancel {
                    machine: index,
                    timer,
                }),
                Action::SendPadding {
                    bypass, replace, ..
                } => Some(TriggerAction::SendPadding {
                    timeout: T::Duration::from_micros(action.sample_timeout(&mut self.rng)),
                    bypass,
                    replace,
                    machine: index,
                }),
                Action::BlockOutgoing {
                    bypass, replace, ..
                } => Some(TriggerAction::BlockOutgoing {
                    timeout: T::Duration::from_micros(action.sample_timeout(&mut self.rng)),
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

    fn decrement_limit(&mut self, mi: usize) {
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

    fn below_action_limits(&self, runtime: &MachineRuntime<T>, machine: &Machine) -> bool {
        let current = &machine.states[runtime.current_state];

        let Some(action) = current.action else {
            return false;
        };

        match action {
            Action::BlockOutgoing { .. } => self.below_limit_blocking(runtime, machine),
            Action::SendPadding { .. } => self.below_limit_padding(runtime, machine),
            Action::UpdateTimer { .. } => runtime.state_limit > 0,
            _ => true,
        }
    }

    fn below_limit_blocking(&self, runtime: &MachineRuntime<T>, machine: &Machine) -> bool {
        let current = &machine.states[runtime.current_state];
        // blocking action

        // special case: we always allow overwriting existing blocking
        let replace = if let Some(Action::BlockOutgoing { replace, .. }) = current.action {
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
            m_block_dur += self
                .current_time
                .saturating_duration_since(self.blocking_started);
            g_block_dur += self
                .current_time
                .saturating_duration_since(self.blocking_started);
        }

        // machine allowed blocking duration first, since it bypasses the
        // other two types of limits
        if m_block_dur < runtime.allowed_blocked_microsec {
            // we still check against state limit, because it's machine internal
            return runtime.state_limit > 0;
        }

        // does the machine limit say no, if set?
        if machine.max_blocking_frac > 0.0 {
            let f: f64 = m_block_dur.div_duration_f64(
                self.current_time
                    .saturating_duration_since(runtime.machine_start),
            );
            if f >= machine.max_blocking_frac {
                return false;
            }
        }

        // does the framework say no?
        if self.max_blocking_frac > 0.0 {
            let f: f64 = g_block_dur.div_duration_f64(
                self.current_time
                    .saturating_duration_since(self.framework_start),
            );
            if f >= self.max_blocking_frac {
                return false;
            }
        }

        // only state-limit left to consider
        runtime.state_limit > 0
    }

    fn below_limit_padding(&self, runtime: &MachineRuntime<T>, machine: &Machine) -> bool {
        // no limits apply if not made up padding count
        if runtime.padding_sent < machine.allowed_padding_packets {
            return runtime.state_limit > 0;
        }

        // hit machine limits?
        if machine.max_padding_frac > 0.0 {
            let total = runtime.normal_sent + runtime.padding_sent;
            if total == 0 {
                return true;
            }
            if runtime.padding_sent as f64 / total as f64 >= machine.max_padding_frac {
                return false;
            }
        }

        // hit global limits?
        if self.max_padding_frac > 0.0 {
            let total = self.padding_sent_packets + self.normal_sent_packets;
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
    use crate::counter::Counter;
    use crate::dist::*;
    use crate::framework::*;
    use crate::state::*;
    use enum_map::enum_map;
    use std::ops::Add;
    use std::time::Duration;
    use std::time::Instant;

    #[test]
    fn no_machines() {
        let machines = vec![];
        let f = Framework::new(&machines, 0.0, 0.0, Instant::now(), rand::thread_rng());
        assert!(f.is_ok());
    }

    #[test]
    fn reuse_machines() {
        let machines = vec![];
        let f1 = Framework::new(&machines, 0.0, 0.0, Instant::now(), rand::thread_rng());
        assert!(f1.is_ok());
        let f2 = Framework::new(&machines, 0.0, 0.0, Instant::now(), rand::thread_rng());
        assert!(f2.is_ok());
    }

    #[test]
    fn noop_machine() {
        let s0 = State::new(enum_map! {
        _ => vec![],
        });
        let m = Machine::new(0, 0.0, 0, 0.0, vec![s0]).unwrap();
        assert_eq!(m.serialize(), "02eNpjYEAHjOgCAAA0AAI=");
    }

    #[test]
    fn trigger_events_actions() {
        // plan: create a machine that swaps between two states, trigger one
        // then multiple events and check the resulting actions

        // state 0: go to state 1 on PaddingSent, pad after 10 usec
        let mut s0 = State::new(enum_map! {
            Event::PaddingSent => vec![Trans(1, 1.0)],
        _ => vec![],
        });
        s0.action = Some(Action::SendPadding {
            bypass: false,
            replace: false,
            timeout: Dist {
                dist: DistType::Uniform {
                    low: 10.0,
                    high: 10.0,
                },
                start: 0.0,
                max: 0.0,
            },
            limit: None,
        });

        // state 1: go to state 0 on PaddingRecv, pad after 1 usec
        let mut s1 = State::new(enum_map! {
            Event::PaddingRecv => vec![Trans(0, 1.0)],
        _ => vec![],
        });
        s1.action = Some(Action::SendPadding {
            bypass: false,
            replace: false,
            timeout: Dist {
                dist: DistType::Uniform {
                    low: 1.0,
                    high: 1.0,
                },

                start: 0.0,
                max: 0.0,
            },
            limit: None,
        });

        // create a simple machine
        let m = Machine::new(1000, 1.0, 0, 0.0, vec![s0, s1]).unwrap();

        let mut current_time = Instant::now();
        let machines = vec![m];
        let mut f = Framework::new(&machines, 0.0, 0.0, current_time, rand::thread_rng()).unwrap();

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
            Some(TriggerAction::SendPadding {
                timeout: Duration::from_micros(1),
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
            Some(TriggerAction::SendPadding {
                timeout: Duration::from_micros(10),
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
                Some(TriggerAction::SendPadding {
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
                        TriggerEvent::PaddingSent {
                            machine: MachineId(0),
                        },
                        TriggerEvent::PaddingRecv,
                    ],
                    current_time,
                );
                assert_eq!(
                    f.actions[0],
                    Some(TriggerAction::SendPadding {
                        timeout: Duration::from_micros(10),
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
                    Some(TriggerAction::SendPadding {
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
        // a machine that blocks for 10us, 1us after NormalSent

        // state 0
        let mut s0 = State::new(enum_map! {
                 Event::NormalSent => vec![Trans(0, 1.0)],
             _ => vec![],
        });
        s0.action = Some(Action::BlockOutgoing {
            bypass: false,
            replace: false,
            timeout: Dist {
                dist: DistType::Uniform {
                    low: 1.0,
                    high: 1.0,
                },
                start: 0.0,
                max: 0.0,
            },
            duration: Dist {
                dist: DistType::Uniform {
                    low: 10.0,
                    high: 10.0,
                },
                start: 0.0,
                max: 0.0,
            },
            limit: None,
        });

        // machine
        let m = Machine::new(1000, 1.0, 0, 0.0, vec![s0]).unwrap();

        let mut current_time = Instant::now();
        let machines = vec![m];
        let mut f = Framework::new(&machines, 0.0, 0.0, current_time, rand::thread_rng()).unwrap();

        _ = f.trigger_events(&[TriggerEvent::NormalSent], current_time);
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
            _ = f.trigger_events(&[TriggerEvent::NormalSent], current_time);
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
        let mut s0 = State::new(enum_map! {
                 Event::PaddingSent => vec![Trans(1, 1.0)],
             _ => vec![],
        });
        s0.action = Some(Action::SendPadding {
            bypass: false,
            replace: false,
            timeout: Dist {
                dist: DistType::Uniform {
                    low: 1.0,
                    high: 1.0,
                },

                start: 0.0,
                max: 0.0,
            },
            limit: None,
        });

        // state 1
        let mut s1 = State::new(enum_map! {
                 Event::TimerEnd => vec![Trans(0, 1.0)],
             _ => vec![],
        });
        s1.action = Some(Action::UpdateTimer {
            replace: false,
            duration: Dist {
                dist: DistType::Uniform {
                    low: 1000.0,
                    high: 1000.0,
                },
                start: 0.0,
                max: 0.0,
            },
            limit: None,
        });

        // machine
        let m = Machine::new(1000, 1.0, 0, 0.0, vec![s0, s1]).unwrap();

        let mut current_time = Instant::now();
        let machines = vec![m];
        let mut f = Framework::new(&machines, 0.0, 0.0, current_time, rand::thread_rng()).unwrap();

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
            Some(TriggerAction::SendPadding {
                timeout: Duration::from_micros(1),
                bypass: false,
                replace: false,
                machine: MachineId(0),
            })
        );
    }

    #[test]
    fn counter_machine() {
        // count PaddingSent - NormalSent with counter A
        // pad and increment counter B by 4 on CounterZero

        // state 0
        let mut s0 = State::new(enum_map! {
            Event::PaddingSent => vec![Trans(1, 1.0)],
            Event::CounterZero => vec![Trans(2, 1.0)],
        _ => vec![],
        });
        s0.counter = (Some(Counter::new(Operation::Decrement)), None);

        // state 1
        let mut s1 = State::new(enum_map! {
            Event::NormalSent => vec![Trans(0, 1.0)],
        _ => vec![],
        });
        s1.counter = (Some(Counter::new(Operation::Increment)), None);

        // state 2
        let mut s2 = State::new(enum_map! {
            Event::NormalSent => vec![Trans(0, 1.0)],
            Event::PaddingSent => vec![Trans(1, 1.0)],
        _ => vec![],
        });
        s2.action = Some(Action::SendPadding {
            bypass: false,
            replace: false,
            timeout: Dist {
                dist: DistType::Uniform {
                    low: 2.0,
                    high: 2.0,
                },
                start: 0.0,
                max: 0.0,
            },
            limit: None,
        });
        s2.counter = (
            None,
            Some(Counter::new_dist(
                Operation::Increment,
                Dist {
                    dist: DistType::Uniform {
                        low: 4.0,
                        high: 4.0,
                    },
                    start: 0.0,
                    max: 0.0,
                },
            )),
        );

        // machine
        let m = Machine::new(1000, 1.0, 0, 0.0, vec![s0, s1, s2]).unwrap();

        let mut current_time = Instant::now();
        let machines = vec![m];
        let mut f = Framework::new(&machines, 0.0, 0.0, current_time, rand::thread_rng()).unwrap();

        _ = f.trigger_events(
            &[TriggerEvent::PaddingSent {
                machine: MachineId(0),
            }],
            current_time,
        );
        assert_eq!(f.actions[0], None);
        assert_eq!(f.runtime[0].counter_a, 1);

        current_time = current_time.add(Duration::from_micros(20));
        _ = f.trigger_events(&[TriggerEvent::NormalSent], current_time);
        assert_eq!(
            f.actions[0],
            Some(TriggerAction::SendPadding {
                timeout: Duration::from_micros(2),
                bypass: false,
                replace: false,
                machine: MachineId(0),
            })
        );
        assert_eq!(f.runtime[0].counter_a, 0);
        assert_eq!(f.runtime[0].counter_b, 4);
    }

    #[test]
    fn counter_underflow_machine() {
        // check that underflow of counter value cannot occur
        // ensure CounterZero is not triggered when counter is already 0

        // state 0, decrement counter
        let mut s0 = State::new(enum_map! {
            Event::NormalSent => vec![Trans(0, 1.0)],
            Event::NormalRecv => vec![Trans(1, 1.0)],
            Event::CounterZero => vec![Trans(2, 1.0)],
        _ => vec![],
        });
        s0.counter = (
            None,
            // NOTE decrement
            Some(Counter::new_dist(
                Operation::Decrement,
                Dist {
                    dist: DistType::Uniform {
                        low: 10.0,
                        high: 10.0,
                    },
                    start: 0.0,
                    max: 0.0,
                },
            )),
        );

        // state 1, set counter
        let mut s1 = State::new(enum_map! {
            Event::NormalSent => vec![Trans(0, 1.0)],
            Event::NormalRecv => vec![Trans(1, 1.0)],
            Event::CounterZero => vec![Trans(2, 1.0)],
        _ => vec![],
        });
        s1.counter = (
            None,
            Some(Counter::new_dist(
                Operation::Set,
                Dist {
                    dist: DistType::Uniform {
                        low: 0.0, // NOTE
                        high: 0.0,
                    },
                    start: 0.0,
                    max: 0.0,
                },
            )),
        );

        // state 2, pad
        let mut s2 = State::new(enum_map! {
            Event::NormalSent => vec![Trans(0, 1.0)],
            Event::NormalRecv => vec![Trans(1, 1.0)],
        _ => vec![],
        });
        s2.action = Some(Action::SendPadding {
            bypass: false,
            replace: false,
            timeout: Dist {
                dist: DistType::Uniform {
                    low: 2.0,
                    high: 2.0,
                },
                start: 0.0,
                max: 0.0,
            },
            limit: None,
        });

        // machine
        let m = Machine::new(1000, 1.0, 0, 0.0, vec![s0, s1, s2]).unwrap();

        let current_time = Instant::now();
        let machines = vec![m];
        let mut f = Framework::new(&machines, 0.0, 0.0, current_time, rand::thread_rng()).unwrap();

        // decrement counter to 0
        _ = f.trigger_events(&[TriggerEvent::NormalSent], current_time);
        assert_eq!(f.actions[0], None);
        assert_eq!(f.runtime[0].counter_b, 0);

        // set counter to 0
        _ = f.trigger_events(&[TriggerEvent::NormalRecv], current_time);
        assert_eq!(f.actions[0], None);
        assert_eq!(f.runtime[0].counter_b, 0);
    }

    #[test]
    fn counter_overflow_machine() {
        // check that overflow of counter value cannot occur
        // set to max value, then try to add and make sure no change

        // state 0, increment counter
        let mut s0 = State::new(enum_map! {
           Event::NormalSent => vec![Trans(0, 1.0)],
           Event::NormalRecv => vec![Trans(1, 1.0)],
           _ => vec![],
        });
        s0.counter = (
            // NOTE increment
            Some(Counter::new_dist(
                Operation::Increment,
                Dist {
                    dist: DistType::Uniform {
                        low: 1000.0,
                        high: 1000.0,
                    },
                    start: 0.0,
                    max: 0.0,
                },
            )),
            None,
        );

        // state 1, set counter
        let mut s1 = State::new(enum_map! {
            Event::NormalSent => vec![Trans(0, 1.0)],
            Event::NormalRecv => vec![Trans(1, 1.0)],
        _ => vec![],
        });
        s1.counter = (
            Some(Counter::new_dist(
                Operation::Set,
                Dist {
                    dist: DistType::Uniform {
                        low: u64::MAX as f64, // NOTE
                        high: u64::MAX as f64,
                    },
                    start: 0.0,
                    max: 0.0,
                },
            )),
            None,
        );

        // machine
        let m = Machine::new(1000, 1.0, 0, 0.0, vec![s0, s1]).unwrap();

        let current_time = Instant::now();
        let machines = vec![m];
        let mut f = Framework::new(&machines, 0.0, 0.0, current_time, rand::thread_rng()).unwrap();

        // set counter to u64::MAX
        _ = f.trigger_events(&[TriggerEvent::NormalRecv], current_time);
        assert_eq!(f.runtime[0].counter_a, u64::MAX);

        // try to increment counter by 1000
        _ = f.trigger_events(&[TriggerEvent::NormalSent], current_time);
        assert_eq!(f.runtime[0].counter_a, u64::MAX);
    }

    #[test]
    fn counter_convergence_machine() {
        // set and decrement both counters at once, check correctness
        // then decrement both to zero and ensure only one transition

        // state 0
        let mut s0 = State::new(enum_map! {
           Event::NormalSent => vec![Trans(0, 1.0)],
           Event::PaddingSent => vec![Trans(1, 1.0)],
           _ => vec![],
        });
        s0.counter = (
            Some(Counter::new_dist(
                Operation::Set,
                Dist {
                    dist: DistType::Uniform {
                        low: 44.0,
                        high: 44.0,
                    },
                    start: 0.0,
                    max: 0.0,
                },
            )),
            Some(Counter::new_dist(
                Operation::Set,
                Dist {
                    dist: DistType::Uniform {
                        low: 28.0,
                        high: 28.0,
                    },
                    start: 0.0,
                    max: 0.0,
                },
            )),
        );

        // state 1
        let mut s1 = State::new(enum_map! {
           Event::NormalSent => vec![Trans(1, 1.0)],
           Event::CounterZero => vec![Trans(2, 1.0)],
           _ => vec![],
        });
        s1.counter = (
            Some(Counter::new_dist(
                Operation::Decrement,
                Dist {
                    dist: DistType::Uniform {
                        low: 32.0,
                        high: 32.0,
                    },
                    start: 0.0,
                    max: 0.0,
                },
            )),
            Some(Counter::new_dist(
                Operation::Decrement,
                Dist {
                    dist: DistType::Uniform {
                        low: 15.0,
                        high: 15.0,
                    },
                    start: 0.0,
                    max: 0.0,
                },
            )),
        );

        // state 2
        let s2 = State::new(enum_map! {
           Event::CounterZero => vec![Trans(0, 1.0)],
           _ => vec![],
        });

        // machine
        let m = Machine::new(1000, 1.0, 0, 0.0, vec![s0, s1, s2]).unwrap();

        let mut current_time = Instant::now();
        let machines = vec![m];
        let mut f = Framework::new(&machines, 0.0, 0.0, current_time, rand::thread_rng()).unwrap();

        _ = f.trigger_events(&[TriggerEvent::NormalSent], current_time);
        assert_eq!(f.actions[0], None);
        assert_eq!(f.runtime[0].counter_a, 44);
        assert_eq!(f.runtime[0].counter_b, 28);

        current_time = current_time.add(Duration::from_micros(20));
        _ = f.trigger_events(
            &[TriggerEvent::PaddingSent {
                machine: MachineId(0),
            }],
            current_time,
        );
        assert_eq!(f.actions[0], None);
        assert_eq!(f.runtime[0].counter_a, 12);
        assert_eq!(f.runtime[0].counter_b, 13);

        current_time = current_time.add(Duration::from_micros(20));
        _ = f.trigger_events(&[TriggerEvent::NormalSent], current_time);
        assert_eq!(f.actions[0], None);
        assert_eq!(f.runtime[0].counter_a, 0);
        assert_eq!(f.runtime[0].counter_b, 0);
    }

    #[test]
    fn counter_divergence_machine() {
        // set both counters at once, check correctness
        // decrement only one to zero and ensure CounterZero

        // state 0
        let mut s0 = State::new(enum_map! {
           Event::NormalSent => vec![Trans(0, 1.0)],
           Event::PaddingSent => vec![Trans(1, 1.0)],
           _ => vec![],
        });
        s0.counter = (
            Some(Counter::new_dist(
                Operation::Set,
                Dist {
                    dist: DistType::Uniform {
                        low: 50.0,
                        high: 50.0,
                    },
                    start: 0.0,
                    max: 0.0,
                },
            )),
            Some(Counter::new_dist(
                Operation::Set,
                Dist {
                    dist: DistType::Uniform {
                        low: 50.0,
                        high: 50.0,
                    },
                    start: 0.0,
                    max: 0.0,
                },
            )),
        );

        // state 1
        let mut s1 = State::new(enum_map! {
           Event::CounterZero => vec![Trans(2, 1.0)],
           _ => vec![],
        });
        s1.counter = (
            None,
            Some(Counter::new_dist(
                Operation::Decrement,
                Dist {
                    dist: DistType::Uniform {
                        low: 50.0,
                        high: 50.0,
                    },
                    start: 0.0,
                    max: 0.0,
                },
            )),
        );

        // state 2
        let mut s2 = State::new(enum_map! {
           _ => vec![],
        });
        s2.counter = (
            Some(Counter::new_dist(
                Operation::Increment,
                Dist {
                    dist: DistType::Uniform {
                        low: 25.0,
                        high: 25.0,
                    },
                    start: 0.0,
                    max: 0.0,
                },
            )),
            None,
        );

        // machine
        let m = Machine::new(1000, 1.0, 0, 0.0, vec![s0, s1, s2]).unwrap();

        let mut current_time = Instant::now();
        let machines = vec![m];
        let mut f = Framework::new(&machines, 0.0, 0.0, current_time, rand::thread_rng()).unwrap();

        _ = f.trigger_events(&[TriggerEvent::NormalSent], current_time);
        assert_eq!(f.actions[0], None);
        assert_eq!(f.runtime[0].counter_a, 50);
        assert_eq!(f.runtime[0].counter_b, 50);

        current_time = current_time.add(Duration::from_micros(20));
        _ = f.trigger_events(
            &[TriggerEvent::PaddingSent {
                machine: MachineId(0),
            }],
            current_time,
        );
        assert_eq!(f.actions[0], None);
        assert_eq!(f.runtime[0].counter_a, 75);
        assert_eq!(f.runtime[0].counter_b, 0);
    }

    #[test]
    fn counter_copy_machine() {
        // set both counters at once, then copy their values

        // state 0
        let mut s0 = State::new(enum_map! {
           Event::NormalSent => vec![Trans(0, 1.0)],
           Event::PaddingSent => vec![Trans(1, 1.0)],
           _ => vec![],
        });
        s0.counter = (
            Some(Counter::new_dist(
                Operation::Set,
                Dist {
                    dist: DistType::Uniform {
                        low: 4.0,
                        high: 4.0,
                    },
                    start: 0.0,
                    max: 0.0,
                },
            )),
            Some(Counter::new_dist(
                Operation::Set,
                Dist {
                    dist: DistType::Uniform {
                        low: 13.0,
                        high: 13.0,
                    },
                    start: 0.0,
                    max: 0.0,
                },
            )),
        );

        // state 1
        let mut s1 = State::new(enum_map! {
           Event::PaddingSent => vec![Trans(2, 1.0)],
           _ => vec![],
        });
        s1.counter = (
            // should be 13.0
            Some(Counter::new_copy(Operation::Set)),
            // should be 9.0
            Some(Counter::new_copy(Operation::Decrement)),
        );

        // state 2
        let mut s2 = State::new(enum_map! {
           _ => vec![],
        });
        s2.counter = (
            // should be 22.0
            Some(Counter::new_copy(Operation::Increment)),
            // should still be 9.0
            None,
        );

        // machine
        let m = Machine::new(1000, 1.0, 0, 0.0, vec![s0, s1, s2]).unwrap();

        let mut current_time = Instant::now();
        let machines = vec![m];
        let mut f = Framework::new(&machines, 0.0, 0.0, current_time, rand::thread_rng()).unwrap();

        _ = f.trigger_events(&[TriggerEvent::NormalSent], current_time);
        assert_eq!(f.actions[0], None);
        assert_eq!(f.runtime[0].counter_a, 4);
        assert_eq!(f.runtime[0].counter_b, 13);

        current_time = current_time.add(Duration::from_micros(20));
        _ = f.trigger_events(
            &[TriggerEvent::PaddingSent {
                machine: MachineId(0),
            }],
            current_time,
        );
        assert_eq!(f.actions[0], None);
        assert_eq!(f.runtime[0].counter_a, 13);
        assert_eq!(f.runtime[0].counter_b, 9);

        current_time = current_time.add(Duration::from_micros(20));
        _ = f.trigger_events(
            &[TriggerEvent::PaddingSent {
                machine: MachineId(0),
            }],
            current_time,
        );
        assert_eq!(f.actions[0], None);
        assert_eq!(f.runtime[0].counter_a, 22);
        assert_eq!(f.runtime[0].counter_b, 9);
    }

    #[test]
    fn signal_one_machine() {
        // send a signal from one machine, ensure that the signal is received
        // by another machine but not the originating machine

        // state 0
        let s0_m0 = State::new(enum_map! {
           Event::NormalSent => vec![Trans(STATE_SIGNAL, 1.0)],
           Event::Signal => vec![Trans(1, 1.0)],
           _ => vec![],
        });
        let s0_m1 = State::new(enum_map! {
           Event::Signal => vec![Trans(1, 1.0)],
           _ => vec![],
        });

        // state 1
        let mut s1 = State::new(enum_map! {
           _ => vec![],
        });
        s1.action = Some(Action::SendPadding {
            bypass: false,
            replace: false,
            timeout: Dist {
                dist: DistType::Uniform {
                    low: 2.0,
                    high: 2.0,
                },
                start: 0.0,
                max: 0.0,
            },
            limit: None,
        });

        // machines
        let m0 = Machine::new(1000, 1.0, 0, 0.0, vec![s0_m0, s1.clone()]).unwrap();
        let m1 = Machine::new(1000, 1.0, 0, 0.0, vec![s0_m1, s1.clone()]).unwrap();

        let current_time = Instant::now();
        let machines = vec![m0, m1];
        let mut f = Framework::new(&machines, 0.0, 0.0, current_time, rand::thread_rng()).unwrap();

        _ = f.trigger_events(&[TriggerEvent::NormalSent], current_time);
        assert_eq!(f.actions[0], None);
        assert_eq!(
            f.actions[1],
            Some(TriggerAction::SendPadding {
                timeout: Duration::from_micros(2),
                bypass: false,
                replace: false,
                machine: MachineId(1),
            })
        );
    }

    #[test]
    fn signal_two_machine() {
        // send a signal from two machines, ensure that both get a signal

        // state 0
        let s0 = State::new(enum_map! {
           Event::NormalSent => vec![Trans(STATE_SIGNAL, 1.0)],
           Event::Signal => vec![Trans(1, 1.0)],
           _ => vec![],
        });

        // state 1
        let mut s1 = State::new(enum_map! {
           _ => vec![],
        });
        s1.action = Some(Action::SendPadding {
            bypass: false,
            replace: false,
            timeout: Dist {
                dist: DistType::Uniform {
                    low: 2.0,
                    high: 2.0,
                },
                start: 0.0,
                max: 0.0,
            },
            limit: None,
        });

        // machines
        let m0 = Machine::new(1000, 1.0, 0, 0.0, vec![s0.clone(), s1.clone()]).unwrap();
        let m1 = Machine::new(1000, 1.0, 0, 0.0, vec![s0.clone(), s1.clone()]).unwrap();

        let current_time = Instant::now();
        let machines = vec![m0, m1];
        let mut f = Framework::new(&machines, 0.0, 0.0, current_time, rand::thread_rng()).unwrap();

        _ = f.trigger_events(&[TriggerEvent::NormalSent], current_time);
        assert_eq!(
            f.actions[0],
            Some(TriggerAction::SendPadding {
                timeout: Duration::from_micros(2),
                bypass: false,
                replace: false,
                machine: MachineId(0),
            })
        );
        assert_eq!(
            f.actions[1],
            Some(TriggerAction::SendPadding {
                timeout: Duration::from_micros(2),
                bypass: false,
                replace: false,
                machine: MachineId(1),
            })
        );
    }

    #[test]
    fn signal_response() {
        // send a signal and respond to it, ensure that both machines get a signal

        // state 0
        let s0_m0 = State::new(enum_map! {
           Event::NormalSent => vec![Trans(STATE_SIGNAL, 1.0)],
           Event::Signal => vec![Trans(1, 1.0)],
           _ => vec![],
        });
        let s0_m1 = State::new(enum_map! {
           Event::Signal => vec![Trans(STATE_SIGNAL, 1.0)],
           _ => vec![],
        });

        // state 1
        let mut s1 = State::new(enum_map! {
           _ => vec![],
        });
        s1.action = Some(Action::SendPadding {
            bypass: false,
            replace: false,
            timeout: Dist {
                dist: DistType::Uniform {
                    low: 2.0,
                    high: 2.0,
                },
                start: 0.0,
                max: 0.0,
            },
            limit: None,
        });

        // machines
        let m0 = Machine::new(1000, 1.0, 0, 0.0, vec![s0_m0, s1.clone()]).unwrap();
        let m1 = Machine::new(1000, 1.0, 0, 0.0, vec![s0_m1, s1.clone()]).unwrap();

        let current_time = Instant::now();
        let machines = vec![m0, m1];
        let mut f = Framework::new(&machines, 0.0, 0.0, current_time, rand::thread_rng()).unwrap();

        _ = f.trigger_events(&[TriggerEvent::NormalSent], current_time);
        assert_eq!(
            f.actions[0],
            Some(TriggerAction::SendPadding {
                timeout: Duration::from_micros(2),
                bypass: false,
                replace: false,
                machine: MachineId(0),
            })
        );
        assert_eq!(f.actions[1], None);
    }

    #[test]
    fn machine_max_padding_frac() {
        // We create a machine that should be allowed to send 100 padding
        // packets before machine padding limits are applied, then the machine
        // should be limited from sending any padding until at least 100
        // normal packets have been sent, given the set max padding fraction
        // of 0.5.

        // state 0
        let mut s0 = State::new(enum_map! {
            // we use sent for checking limits and recv as an event to check
            // without adding bytes sent
            Event::PaddingSent | Event::NormalSent | Event::NormalRecv => vec![Trans(0, 1.0)],
            _ => vec![],
        });
        s0.action = Some(Action::SendPadding {
            bypass: false,
            replace: false,
            timeout: Dist {
                dist: DistType::Uniform {
                    low: 2.0,
                    high: 2.0,
                },
                start: 0.0,
                max: 0.0,
            },
            limit: None,
        });

        // machine
        let m = Machine::new(100, 0.5, 0, 0.0, vec![s0]).unwrap();

        let current_time = Instant::now();
        let machines = vec![m];
        let mut f = Framework::new(&machines, 0.0, 0.0, current_time, rand::thread_rng()).unwrap();

        // transition to get the loop going
        _ = f.trigger_events(&[TriggerEvent::NormalRecv], current_time);

        // we expect 100 padding actions
        for _ in 0..100 {
            assert_eq!(
                f.actions[0],
                Some(TriggerAction::SendPadding {
                    timeout: Duration::from_micros(2),
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
        _ = f.trigger_events(&[TriggerEvent::NormalRecv], current_time);
        assert_eq!(f.actions[0], None);

        // verify that no padding is scheduled until we've sent the same amount
        // of bytes
        for _ in 0..100 {
            _ = f.trigger_events(&[TriggerEvent::NormalSent], current_time);
            assert_eq!(f.actions[0], None);
        }

        // send one byte of normal, putting us just over the limit
        _ = f.trigger_events(&[TriggerEvent::NormalSent], current_time);

        assert_eq!(
            f.actions[0],
            Some(TriggerAction::SendPadding {
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
        let mut s0 = State::new(enum_map! {
            // we use sent for checking limits and recv as an event to check
            // without adding bytes sent
            Event::PaddingSent | Event::NormalSent | Event::NormalRecv => vec![Trans(0, 1.0)],
        _ => vec![],
        });
        s0.action = Some(Action::SendPadding {
            bypass: false,
            replace: false,
            timeout: Dist {
                dist: DistType::Uniform {
                    low: 2.0,
                    high: 2.0,
                },
                start: 0.0,
                max: 0.0,
            },
            limit: None,
        });

        // machines
        let m1 = Machine::new(100, 0.0, 0, 0.0, vec![s0]).unwrap();
        let m2 = m1.clone();

        // NOTE 0.5 max_padding_frac below
        let current_time = Instant::now();
        let machines = vec![m1, m2];
        let mut f = Framework::new(&machines, 0.5, 0.0, current_time, rand::thread_rng()).unwrap();

        // we have two machines that each can send 100 packets before their own
        // or any framework limits are applied (by design, see
        // allowed_padding_packets) trigger transition to get the loop going
        _ = f.trigger_events(&[TriggerEvent::NormalRecv], current_time);

        // we expect 100 padding actions per machine
        for _ in 0..100 {
            assert_eq!(
                f.actions[0],
                Some(TriggerAction::SendPadding {
                    timeout: Duration::from_micros(2),
                    bypass: false,
                    replace: false,
                    machine: MachineId(0),
                })
            );
            assert_eq!(
                f.actions[1],
                Some(TriggerAction::SendPadding {
                    timeout: Duration::from_micros(2),
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
                    TriggerEvent::TunnelSent,
                    TriggerEvent::TunnelSent,
                ],
                current_time,
            );
        }

        // limit hit, last event should prevent the action and future actions
        assert_eq!(f.actions[0], None);
        assert_eq!(f.actions[1], None);
        _ = f.trigger_events(
            &[TriggerEvent::NormalRecv, TriggerEvent::NormalRecv],
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
            _ = f.trigger_events(&[TriggerEvent::NormalSent], current_time);
            assert_eq!(f.actions[0], None);
            assert_eq!(f.actions[1], None);
        }

        // the last byte should tip it over
        _ = f.trigger_events(&[TriggerEvent::NormalSent], current_time);

        assert_eq!(
            f.actions[0],
            Some(TriggerAction::SendPadding {
                timeout: Duration::from_micros(2),
                bypass: false,
                replace: false,
                machine: MachineId(0),
            })
        );
        assert_eq!(
            f.actions[1],
            Some(TriggerAction::SendPadding {
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
        let mut s0 = State::new(enum_map! {
           Event::BlockingBegin | Event::BlockingEnd | Event::NormalRecv => vec![Trans(0, 1.0)],
           _ => vec![],
        });
        // block every 2us for 2us
        s0.action = Some(Action::BlockOutgoing {
            bypass: false,
            replace: false,
            timeout: Dist {
                dist: DistType::Uniform {
                    low: 2.0,
                    high: 2.0,
                },
                start: 0.0,
                max: 0.0,
            },
            duration: Dist {
                dist: DistType::Uniform {
                    low: 2.0,
                    high: 2.0,
                },
                start: 0.0,
                max: 0.0,
            },
            limit: None,
        });

        // machine
        let m = Machine::new(0, 0.0, 10, 0.5, vec![s0]).unwrap();

        let mut current_time = Instant::now();
        let machines = vec![m];
        let mut f = Framework::new(&machines, 0.0, 0.0, current_time, rand::thread_rng()).unwrap();

        // trigger self to start the blocking (triggers action)
        _ = f.trigger_events(&[TriggerEvent::NormalRecv], current_time);

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
            _ = f.trigger_events(&[TriggerEvent::NormalRecv], current_time);
            assert_eq!(f.actions[0], None);
        }
        assert_eq!(f.runtime[0].blocking_duration, Duration::from_micros(10));
        assert_eq!(
            current_time.duration_since(f.runtime[0].machine_start),
            Duration::from_micros(20)
        );

        // push over the limit, should be allowed
        current_time = current_time.add(Duration::from_micros(2));
        _ = f.trigger_events(&[TriggerEvent::NormalRecv], current_time);
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
        let mut s0 = State::new(enum_map! {
            Event::BlockingBegin | Event::BlockingEnd | Event::NormalRecv => vec![Trans(0, 1.0)],
        _ => vec![],
        });
        // block every 2us for 2us
        s0.action = Some(Action::BlockOutgoing {
            bypass: false,
            replace: false,
            timeout: Dist {
                dist: DistType::Uniform {
                    low: 2.0,
                    high: 2.0,
                },

                start: 0.0,
                max: 0.0,
            },
            duration: Dist {
                dist: DistType::Uniform {
                    low: 2.0,
                    high: 2.0,
                },

                start: 0.0,
                max: 0.0,
            },
            limit: None,
        });

        // machine
        let m = Machine::new(0, 0.0, 10, 0.0, vec![s0]).unwrap();

        let mut current_time = Instant::now();
        let machines = vec![m];
        let mut f = Framework::new(&machines, 0.0, 0.5, current_time, rand::thread_rng()).unwrap();

        // trigger self to start the blocking (triggers action)
        _ = f.trigger_events(&[TriggerEvent::NormalRecv], current_time);

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
            _ = f.trigger_events(&[TriggerEvent::NormalRecv], current_time);
            assert_eq!(f.actions[0], None);
        }
        assert_eq!(f.runtime[0].blocking_duration, Duration::from_micros(10));
        assert_eq!(
            current_time.duration_since(f.runtime[0].machine_start),
            Duration::from_micros(20)
        );

        // push over the limit, should be allowed
        current_time = current_time.add(Duration::from_micros(2));
        _ = f.trigger_events(&[TriggerEvent::NormalRecv], current_time);
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
        let mut s0 = State::new(enum_map! {
            Event::NormalRecv => vec![Trans(0, 1.0)],
        _ => vec![],
        });
        // block every 2us for 2us
        s0.action = Some(Action::BlockOutgoing {
            bypass: false,
            replace: true, // NOTE
            timeout: Dist {
                dist: DistType::Uniform {
                    low: 2.0,
                    high: 2.0,
                },
                start: 0.0,
                max: 0.0,
            },
            duration: Dist {
                dist: DistType::Uniform {
                    low: 2.0,
                    high: 2.0,
                },
                start: 0.0,
                max: 0.0,
            },
            limit: None,
        });

        // machine 0
        let m0 = Machine::new(0, 0.0, 2, 0.5, vec![s0]).unwrap();

        // state 0, second machine
        let mut s0 = State::new(enum_map! {
            Event::NormalSent => vec![Trans(0, 1.0)],
        _ => vec![],
        });
        // block instantly for 1000us
        s0.action = Some(Action::BlockOutgoing {
            bypass: false,
            replace: false,
            timeout: Dist {
                dist: DistType::Uniform {
                    low: 0.0,
                    high: 0.0,
                },

                start: 0.0,
                max: 0.0,
            },
            duration: Dist {
                dist: DistType::Uniform {
                    low: 1000.0,
                    high: 1000.0,
                },
                start: 0.0,
                max: 0.0,
            },
            limit: None,
        });

        // machine 1
        let m1 = Machine::new(0, 0.0, 0, 0.0, vec![s0]).unwrap();

        let mut current_time = Instant::now();
        let machines = vec![m0, m1];
        let mut f = Framework::new(&machines, 0.0, 0.0, current_time, rand::thread_rng()).unwrap();

        // trigger to make machine 0 block
        _ = f.trigger_events(&[TriggerEvent::NormalRecv], current_time);

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
        _ = f.trigger_events(&[TriggerEvent::NormalRecv], current_time);

        assert_eq!(f.actions[0], None);
        assert_eq!(f.runtime[0].blocking_duration, Duration::from_micros(2));

        // now cause machine 1 to start blocking
        _ = f.trigger_events(&[TriggerEvent::NormalSent], current_time);

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
        _ = f.trigger_events(&[TriggerEvent::NormalRecv], current_time);

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
        let s0 = State::new(enum_map! {
            Event::NormalSent => vec![Trans(1, 1.0)],
        _ => vec![],
        });

        // state 1
        let mut s1 = State::new(enum_map! {
            Event::PaddingSent => vec![Trans(1, 1.0)],
        _ => vec![],
        });
        s1.action = Some(Action::SendPadding {
            bypass: false,
            replace: false,
            timeout: Dist {
                dist: DistType::Uniform {
                    low: 1.0,
                    high: 1.0,
                },
                start: 0.0,
                max: 0.0,
            },
            limit: Some(Dist {
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
        let mut f = Framework::new(&machines, 0.0, 0.0, current_time, rand::thread_rng()).unwrap();

        // trigger self to start the padding
        _ = f.trigger_events(&[TriggerEvent::NormalSent], current_time);

        assert_eq!(f.runtime[0].state_limit, 4);

        // verify that we can send 4 padding
        for _ in 0..4 {
            assert_eq!(
                f.actions[0],
                Some(TriggerAction::SendPadding {
                    timeout: Duration::from_micros(1),
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
        assert_eq!(f.runtime[0].normal_sent, 1);

        // limit should be reached after 4 padding, blocking next action
        assert_eq!(f.actions[0], None);
        assert_eq!(f.runtime[0].state_limit, 0);
    }
}

use crate::constants::*;
use crate::dist::DistType;
use crate::event::*;
use crate::machine::*;
use std::error::Error;
use std::time::Duration;
use std::time::Instant;

#[derive(Clone)]
pub struct TriggerEvent {
    pub event: Event,
    pub n: u64,
    pub mi: usize,
}

#[derive(PartialEq, Debug)]
pub enum Action {
    None,
    Cancel,
    InjectPadding {
        timeout: Duration,
        size: u16,
    },
    BlockOutgoing {
        timeout: Duration,
        duration: Duration,
        overwrite: bool,
    },
}

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

pub struct Framework {
    pub actions: Vec<Action>,
    current_time: Instant,
    machines: Vec<Machine>,
    runtime: Vec<MachineRuntime>,
    global_max_padding_frac: f64,
    global_nonpadding_sent_bytes: u64,
    global_paddingsent_bytes: u64,
    global_max_blocking_frac: f64,
    global_blocking_duration: Duration,
    global_blocking_started: Instant,
    global_blocking_active: bool,
    global_framework_start: Instant,
    mtu: u64,
}

impl Framework {
    pub fn new(
        machines: Vec<Machine>,
        max_padding_frac: f64,
        max_blocking_frac: f64,
        mtu: u64,
        current_time: Instant,
    ) -> Result<Self, Box<dyn Error>> {
        for m in &machines {
            m.validate()?;
        }

        let mut runtime = vec![];
        for _ in 0..machines.len() {
            runtime.push(MachineRuntime {
                current_state: 0,
                state_limit: 0,
                padding_sent: 0,
                nonpadding_sent: 0,
                blocking_duration: Duration::from_secs(0),
                machine_start: current_time.clone(),
            });
        }

        let mut actions = vec![];
        for _ in 0..machines.len() {
            actions.push(Action::None);
        }

        Ok(Self {
            actions,
            machines,
            runtime,
            mtu,
            current_time,
            global_max_blocking_frac: max_blocking_frac,
            global_max_padding_frac: max_padding_frac,
            global_framework_start: current_time.clone(),
            global_blocking_active: false,
            global_blocking_started: current_time.clone(), // ugly, can't be unset
            global_blocking_duration: Duration::from_secs(0),
            global_paddingsent_bytes: 0,
            global_nonpadding_sent_bytes: 0,
        })
    }

    pub fn num_machines(&self) -> usize {
        self.machines.len()
    }

    pub fn trigger_events(&mut self, events: Vec<TriggerEvent>, current_time: Instant) {
        for mi in 0..self.actions.len() {
            self.actions[mi] = Action::None;
        }

        self.current_time = current_time;
        for e in events {
            self.process_event(&e);
        }
    }

    fn process_event(&mut self, e: &TriggerEvent) {
        match e.event {
            Event::NonPaddingRecv | Event::PaddingRecv => {
                // no special accounting needed on received (non)padding
                for mi in 0..self.runtime.len() {
                    self.transition(mi, e.event, e.n);
                }
            }
            Event::NonPaddingSent => {
                self.global_nonpadding_sent_bytes += e.n;

                for mi in 0..self.runtime.len() {
                    self.runtime[mi].nonpadding_sent += e.n;

                    // If the transition leaves the state unchanged and the limit of
                    // the machine includes nonpadding sent packets, decrement the
                    // limit. If the state changed, a new limit was sampled and this
                    // packet shouldn't count.
                    if self.transition(mi, e.event, e.n) == StateChange::Unchanged {
                        let cs = self.runtime[mi].current_state;
                        if cs != STATEEND {
                            if self.machines[mi].states[cs].limit_includes_nonpadding {
                                self.decrement_limit(mi);
                            }
                        }
                    }
                }
            }
            Event::PaddingSent => {
                // accounting is global ...
                self.global_paddingsent_bytes += e.n;

                for mi in 0..self.runtime.len() {
                    // ... but the event is per-machine
                    // TODO: we probably want a PaddingQueued (self) and PaddingSent (global)
                    if mi == e.mi {
                        self.runtime[mi].padding_sent += e.n;

                        if self.transition(mi, e.event, e.n) == StateChange::Unchanged {
                            // decrement only makes sense if we didn't change state
                            self.decrement_limit(mi)
                        }
                    }
                }
            }
            Event::BlockingBegin => {
                // keep track of when we start blocking (for accounting in BlockingEnd)
                if !self.global_blocking_active {
                    self.global_blocking_active = true;
                    self.global_blocking_started = self.current_time.clone();
                }

                // blocking is a global event
                for mi in 0..self.runtime.len() {
                    if self.transition(mi, e.event, e.n) == StateChange::Unchanged {
                        if mi == e.mi {
                            // decrement only makes sense if we didn't
                            // change state and for the machine in question
                            self.decrement_limit(mi)
                        }
                    }
                }
            }
            Event::BlockingEnd => {
                let mut blocked: Duration = Duration::from_secs(0);
                if self.global_blocking_active {
                    blocked = self
                        .current_time
                        .duration_since(self.global_blocking_started);
                    self.global_blocking_duration += blocked;
                    self.global_blocking_active = false;
                }

                for mi in 0..self.runtime.len() {
                    // since block is global, every machine was blocked the
                    // same duration
                    if !blocked.is_zero() {
                        self.runtime[mi].blocking_duration += blocked;
                    }
                    self.transition(mi, e.event, e.n);
                }
            }
            Event::LimitReached => {
                // limit is an internal event
                self.transition(e.mi, e.event, e.n);
            }
            Event::UpdateMTU => {
                self.mtu = e.n;
                for mi in 0..self.runtime.len() {
                    self.transition(mi, e.event, e.n);
                }
            }
        };
    }

    fn transition(&mut self, mi: usize, event: Event, n: u64) -> StateChange {
        // a machine in end state cannot transition
        if self.runtime[mi].current_state == STATEEND {
            return StateChange::Unchanged;
        }

        // ignore events generated by small packets if not included
        if !self.machines[mi].include_small_packets && n > 0 && n <= MAXSMALLPACKETSIZE {
            return StateChange::Unchanged;
        }

        // sample next state
        let (next_state, set) = self.next_state(mi, event);

        // if no next state on event, done
        if !set {
            return StateChange::Unchanged;
        }

        // we got a next state, act on it
        match next_state {
            STATECANCEL => {
                // cancel any pending action, but doesn't count as a state change
                self.actions[mi] = Action::Cancel;
                return StateChange::Unchanged;
            }
            STATEEND => {
                // this is a state change (because we can never reach here if already in
                // STATEEND, see first check above), but we don't cancel any pending
                // action, nor schedule any new action
                self.runtime[mi].current_state = STATEEND;
                return StateChange::Changed;
            }
            _ => {
                // transition to same or different state?
                if self.runtime[mi].current_state == next_state {
                    if self.below_action_limits(mi) {
                        self.schedule_action(mi);
                    }
                    return StateChange::Unchanged;
                }
                self.runtime[mi].current_state = next_state;
                self.runtime[mi].state_limit = self.machines[mi].states[next_state].sample_limit();
                if self.below_action_limits(mi) {
                    self.schedule_action(mi);
                }
                return StateChange::Changed;
            }
        }
    }

    fn schedule_action(&mut self, mi: usize) {
        let current = &self.machines[mi].states[self.runtime[mi].current_state];

        if current.block.dist != DistType::None {
            self.actions[mi] = Action::BlockOutgoing {
                timeout: Duration::from_micros(current.sample_timeout() as u64),
                duration: Duration::from_micros(current.sample_block() as u64),
                overwrite: current.block_overwrite,
            };
        } else {
            self.actions[mi] = Action::InjectPadding {
                timeout: Duration::from_micros(current.sample_timeout() as u64),
                size: current.sample_size(self.mtu) as u16,
            };
        }
    }

    fn decrement_limit(&mut self, mi: usize) {
        if self.runtime[mi].state_limit > 0 {
            self.runtime[mi].state_limit -= 1;
        }
        let cs = self.runtime[mi].current_state;

        if self.runtime[mi].state_limit == 0
            && self.machines[mi].states[cs].limit.dist != DistType::None
        {
            // cancel any pending timers, and trigger limit reached
            self.actions[mi] = Action::Cancel;
            // next, we trigger internally event LimitReached
            self.process_event(&TriggerEvent {
                event: Event::LimitReached,
                mi: mi,
                n: 0,
            })
        }
    }

    fn next_state(&self, mi: usize, event: Event) -> (usize, bool) {
        let cs = self.runtime[mi].current_state;
        if !self.machines[mi].states[cs].next_state.contains_key(&event) {
            return (0, false);
        }

        let next_prop = &self.machines[mi].states[cs].next_state[&event];

        let p = rand::random::<f64>();
        let mut total = 0.0;
        for i in 0..next_prop.len() {
            total += next_prop[i];
            if p <= total {
                // some events are machine-defined, others framework pseudo-states
                if i + 2 < next_prop.len() {
                    return (i, true);
                } else if i + 2 == next_prop.len() {
                    return (STATECANCEL, true);
                } else {
                    return (STATEEND, true);
                }
            }
        }

        (STATENOP, false)
    }

    fn below_action_limits(&self, mi: usize) -> bool {
        let current = &self.machines[mi].states[self.runtime[mi].current_state];
        // either blocking or padding limits apply
        if current.block.dist != DistType::None {
            return self.below_limit_blocking(mi);
        }
        self.below_limit_padding(mi)
    }

    fn below_limit_blocking(&self, mi: usize) -> bool {
        let current = &self.machines[mi].states[self.runtime[mi].current_state];
        // blocking action

        // special case: we always allow overwriting existing blocking
        if current.block_overwrite && !self.global_blocking_active {
            // we still check against sate limit, because its machine internal
            return self.runtime[mi].state_limit > 0;
        }

        // compute durations we've been blocking
        let mut m_block_dur = self.runtime[mi].blocking_duration;
        let mut g_block_dur = self.global_blocking_duration;
        if self.global_blocking_active {
            // account for ongoing blocking as well, add duration
            m_block_dur += self
                .current_time
                .duration_since(self.global_blocking_started);
            g_block_dur += self
                .current_time
                .duration_since(self.global_blocking_started);
        }

        // machine allowed blocking duration first, since it bypasses the
        // other two types of limits
        if m_block_dur < Duration::from_micros(self.machines[mi].allowed_blocked_microsec) {
            // we still check against sate limit, because its machine internal
            return self.runtime[mi].state_limit > 0;
        }

        // does the machine limit say no, if set?
        if self.machines[mi].max_blocking_frac > 0.0 {
            // TODO: swap to m_block_dur.div_duration_f64()
            let f: f64 = m_block_dur.as_micros() as f64
                / self
                    .current_time
                    .duration_since(self.runtime[mi].machine_start)
                    .as_micros() as f64;
            if f >= self.machines[mi].max_blocking_frac {
                return false;
            }
        }

        // does the framework say no?
        if self.global_max_blocking_frac > 0.0 {
            // TODO: swap to g_block_dur.div_duration_f64()
            let f: f64 = g_block_dur.as_micros() as f64
                / self
                    .current_time
                    .duration_since(self.global_framework_start)
                    .as_micros() as f64;
            if f >= self.global_max_blocking_frac {
                return false;
            }
        }

        // only state-limit left to consider
        return self.runtime[mi].state_limit > 0;
    }

    fn below_limit_padding(&self, mi: usize) -> bool {
        // no limits apply if not made up padding count
        if self.runtime[mi].padding_sent < self.machines[mi].allowed_padding_bytes {
            return self.runtime[mi].state_limit > 0;
        }

        // hit machine limits?
        if self.machines[mi].max_padding_frac > 0.0 {
            let total = self.runtime[mi].nonpadding_sent + self.runtime[mi].padding_sent;
            if total == 0 {
                // FIXME: edge-case, was defined as false in go-framework, but should be true?
                return false;
            }
            if self.runtime[mi].padding_sent as f64 / total as f64
                >= self.machines[mi].max_padding_frac
            {
                return false;
            }
        }

        // hit global limits?
        if self.global_max_padding_frac > 0.0 {
            let frac = self.global_paddingsent_bytes as f64
                / (self.global_paddingsent_bytes as f64 + self.global_nonpadding_sent_bytes as f64);
            if frac >= self.global_max_padding_frac {
                return false;
            }
        }

        // only state-limit left to consider
        return self.runtime[mi].state_limit > 0;
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
        let f = Framework::new(vec![], 0.0, 0.0, 150, Instant::now());
        assert!(!f.is_err());
    }

    #[test]
    fn trigger_events_actions() {
        // plan: create a machine that swaps between two states, trigger one
        // then multiple events and check the resulting actions

        let num_states = 2;

        // state 0: go to state 1 on PaddingSent, pad after 10 usec
        let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
        let mut e: HashMap<usize, f64> = HashMap::new();
        e.insert(1, 1.0);
        t.insert(Event::PaddingSent, e);
        let s0 = State {
            timeout: Dist {
                dist: DistType::Uniform,
                param1: 10.0,
                param2: 10.0,
                start: 0.0,
                max: 0.0,
            },
            size: Dist {
                dist: DistType::None,
                param1: 0.0,
                param2: 0.0,
                start: 0.0,
                max: 0.0,
            },
            limit: Dist {
                dist: DistType::None,
                param1: 0.0,
                param2: 0.0,
                start: 0.0,
                max: 0.0,
            },
            block: Dist {
                dist: DistType::None,
                param1: 0.0,
                param2: 0.0,
                start: 0.0,
                max: 0.0,
            },
            block_overwrite: false,
            limit_includes_nonpadding: false,
            next_state: make_next_state(t, num_states),
        };

        // state 1: go to state 0 on PaddingRecv, pad after 1 usec
        let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
        let mut e: HashMap<usize, f64> = HashMap::new();
        e.insert(0, 1.0);
        t.insert(Event::PaddingRecv, e);
        let s1 = State {
            timeout: Dist {
                dist: DistType::Uniform,
                param1: 1.0,
                param2: 1.0,
                start: 0.0,
                max: 0.0,
            },
            size: Dist {
                dist: DistType::None,
                param1: 0.0,
                param2: 0.0,
                start: 0.0,
                max: 0.0,
            },
            limit: Dist {
                dist: DistType::None,
                param1: 0.0,
                param2: 0.0,
                start: 0.0,
                max: 0.0,
            },
            block: Dist {
                dist: DistType::None,
                param1: 0.0,
                param2: 0.0,
                start: 0.0,
                max: 0.0,
            },
            block_overwrite: false,
            limit_includes_nonpadding: false,
            next_state: make_next_state(t, num_states),
        };

        // create a simple machine
        let m = Machine {
            allowed_padding_bytes: 1000 * 1024,
            max_padding_frac: 1.0,
            allowed_blocked_microsec: 0,
            max_blocking_frac: 0.0,
            states: vec![s0, s1],
            include_small_packets: true,
        };

        let mut current_time = Instant::now();
        let mtu = 150;
        let mut f = Framework::new(vec![m], 0.0, 0.0, mtu, current_time).unwrap();

        assert_eq!(f.num_machines(), 1);
        assert_eq!(f.actions.len(), 1);

        // start triggering
        f.trigger_events(
            [TriggerEvent {
                event: Event::BlockingBegin,
                n: 0,
                mi: 0,
            }]
            .to_vec(),
            current_time,
        );
        assert_eq!(f.actions[0], Action::None);

        // move time forward, trigger again to make sure no scheduled timer
        current_time = current_time.add(Duration::from_micros(20));
        f.trigger_events(
            [TriggerEvent {
                event: Event::BlockingBegin,
                n: 0,
                mi: 0,
            }]
            .to_vec(),
            current_time,
        );
        assert_eq!(f.actions[0], Action::None);

        // trigger transition to next state
        f.trigger_events(
            [TriggerEvent {
                event: Event::PaddingSent,
                n: 0,
                mi: 0,
            }]
            .to_vec(),
            current_time,
        );
        assert_eq!(
            f.actions[0],
            Action::InjectPadding {
                timeout: Duration::from_micros(1),
                size: mtu as u16
            }
        );

        // increase time, trigger event, make sure no further action
        current_time = current_time.add(Duration::from_micros(20));
        f.trigger_events(
            [TriggerEvent {
                event: Event::PaddingSent,
                n: 0,
                mi: 0,
            }]
            .to_vec(),
            current_time,
        );
        assert_eq!(f.actions[0], Action::None);

        // go back to state 0
        f.trigger_events(
            [TriggerEvent {
                event: Event::PaddingRecv,
                n: 0,
                mi: 0,
            }]
            .to_vec(),
            current_time,
        );
        assert_eq!(
            f.actions[0],
            Action::InjectPadding {
                timeout: Duration::from_micros(10),
                size: mtu as u16
            }
        );

        // test multiple triggers overwriting actions
        for _ in 0..10 {
            f.trigger_events(
                [
                    TriggerEvent {
                        event: Event::PaddingSent,
                        n: 0,
                        mi: 0,
                    },
                    TriggerEvent {
                        event: Event::PaddingRecv,
                        n: 0,
                        mi: 0,
                    },
                ]
                .to_vec(),
                current_time,
            );
            assert_eq!(
                f.actions[0],
                Action::InjectPadding {
                    timeout: Duration::from_micros(10),
                    size: mtu as u16
                }
            );
        }

        // triple trigger, swapping between states
        for i in 0..10 {
            if i % 2 == 0 {
                f.trigger_events(
                    [
                        TriggerEvent {
                            event: Event::PaddingRecv,
                            n: 0,
                            mi: 0,
                        },
                        TriggerEvent {
                            event: Event::PaddingSent,
                            n: 0,
                            mi: 0,
                        },
                        TriggerEvent {
                            event: Event::PaddingRecv,
                            n: 0,
                            mi: 0,
                        },
                    ]
                    .to_vec(),
                    current_time,
                );
                assert_eq!(
                    f.actions[0],
                    Action::InjectPadding {
                        timeout: Duration::from_micros(10),
                        size: mtu as u16
                    }
                );
            } else {
                f.trigger_events(
                    [
                        TriggerEvent {
                            event: Event::PaddingSent,
                            n: 0,
                            mi: 0,
                        },
                        TriggerEvent {
                            event: Event::PaddingRecv,
                            n: 0,
                            mi: 0,
                        },
                        TriggerEvent {
                            event: Event::PaddingSent,
                            n: 0,
                            mi: 0,
                        },
                    ]
                    .to_vec(),
                    current_time,
                );
                assert_eq!(
                    f.actions[0],
                    Action::InjectPadding {
                        timeout: Duration::from_micros(1),
                        size: mtu as u16
                    }
                );
            }
        }
    }
}

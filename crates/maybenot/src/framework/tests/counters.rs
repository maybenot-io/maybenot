use super::*;

#[test]
fn counter_machine() {
    // count DecoyQueued - NormalQueued with counter A
    // pad and increment counter B by 4 on CounterZero

    // state 0
    let mut s0 = State::new(enum_map! {
        Event::DecoyQueued => vec![Trans(1, 1.0)],
        Event::CounterZero => vec![Trans(2, 1.0)],
    _ => vec![],
    });
    s0.counter = (Some(Counter::new(Operation::Decrement)), None);

    // state 1
    let mut s1 = State::new(enum_map! {
        Event::NormalQueued => vec![Trans(0, 1.0)],
    _ => vec![],
    });
    s1.counter = (Some(Counter::new(Operation::Increment)), None);

    // state 2
    let mut s2 = State::new(enum_map! {
        Event::NormalQueued => vec![Trans(0, 1.0)],
        Event::DecoyQueued => vec![Trans(1, 1.0)],
    _ => vec![],
    });
    s2.action = Some(Action::DecoyTraffic {
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
        n: Dist {
            dist: DistType::Uniform {
                low: 1.0,
                high: 1.0,
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
    let m = Machine::new(1000, 0, vec![s0, s1, s2]).unwrap();

    let mut current_time = Instant::now();
    let machines = vec![m];
    let mut f = Framework::new(
        &machines,
        LimitDecoyNone,
        LimitDelayNone,
        current_time,
        rand::rng(),
    )
    .unwrap();

    _ = f.trigger_events(
        &[TriggerEvent::DecoyQueued {
            machine: MachineId(0),
        }],
        current_time,
    );
    assert_eq!(f.actions[0], None);
    assert_eq!(f.runtime[0].counter_a, 1);

    current_time = current_time.add(Duration::from_micros(20));
    _ = f.trigger_events(&[TriggerEvent::NormalQueued], current_time);
    assert_eq!(
        f.actions[0],
        Some(TriggerAction::DecoyTraffic {
            timeout: Duration::from_micros(2),
            n: 1,
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
        Event::NormalQueued => vec![Trans(0, 1.0)],
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
        Event::NormalQueued => vec![Trans(0, 1.0)],
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
        Event::NormalQueued => vec![Trans(0, 1.0)],
        Event::NormalRecv => vec![Trans(1, 1.0)],
    _ => vec![],
    });
    s2.action = Some(Action::DecoyTraffic {
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
        n: Dist {
            dist: DistType::Uniform {
                low: 1.0,
                high: 1.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });

    // machine
    let m = Machine::new(1000, 0, vec![s0, s1, s2]).unwrap();

    let current_time = Instant::now();
    let machines = vec![m];
    let mut f = Framework::new(
        &machines,
        LimitDecoyNone,
        LimitDelayNone,
        current_time,
        rand::rng(),
    )
    .unwrap();

    // decrement counter to 0
    _ = f.trigger_events(&[TriggerEvent::NormalQueued], current_time);
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
       Event::NormalQueued => vec![Trans(0, 1.0)],
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
        Event::NormalQueued => vec![Trans(0, 1.0)],
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
    let m = Machine::new(1000, 0, vec![s0, s1]).unwrap();

    let current_time = Instant::now();
    let machines = vec![m];
    let mut f = Framework::new(
        &machines,
        LimitDecoyNone,
        LimitDelayNone,
        current_time,
        rand::rng(),
    )
    .unwrap();

    // set counter to u64::MAX
    _ = f.trigger_events(&[TriggerEvent::NormalRecv], current_time);
    assert_eq!(f.runtime[0].counter_a, u64::MAX);

    // try to increment counter by 1000
    _ = f.trigger_events(&[TriggerEvent::NormalQueued], current_time);
    assert_eq!(f.runtime[0].counter_a, u64::MAX);
}

#[test]
fn counter_convergence_machine() {
    // set and decrement both counters at once, check correctness
    // then decrement both to zero and ensure only one transition

    // state 0
    let mut s0 = State::new(enum_map! {
       Event::NormalQueued => vec![Trans(0, 1.0)],
       Event::DecoyQueued => vec![Trans(1, 1.0)],
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
       Event::NormalQueued => vec![Trans(1, 1.0)],
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
    let m = Machine::new(1000, 0, vec![s0, s1, s2]).unwrap();

    let mut current_time = Instant::now();
    let machines = vec![m];
    let mut f = Framework::new(
        &machines,
        LimitDecoyNone,
        LimitDelayNone,
        current_time,
        rand::rng(),
    )
    .unwrap();

    _ = f.trigger_events(&[TriggerEvent::NormalQueued], current_time);
    assert_eq!(f.actions[0], None);
    assert_eq!(f.runtime[0].counter_a, 44);
    assert_eq!(f.runtime[0].counter_b, 28);

    current_time = current_time.add(Duration::from_micros(20));
    _ = f.trigger_events(
        &[TriggerEvent::DecoyQueued {
            machine: MachineId(0),
        }],
        current_time,
    );
    assert_eq!(f.actions[0], None);
    assert_eq!(f.runtime[0].counter_a, 12);
    assert_eq!(f.runtime[0].counter_b, 13);

    current_time = current_time.add(Duration::from_micros(20));
    _ = f.trigger_events(&[TriggerEvent::NormalQueued], current_time);
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
       Event::NormalQueued => vec![Trans(0, 1.0)],
       Event::DecoyQueued => vec![Trans(1, 1.0)],
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
    let m = Machine::new(1000, 0, vec![s0, s1, s2]).unwrap();

    let mut current_time = Instant::now();
    let machines = vec![m];
    let mut f = Framework::new(
        &machines,
        LimitDecoyNone,
        LimitDelayNone,
        current_time,
        rand::rng(),
    )
    .unwrap();

    _ = f.trigger_events(&[TriggerEvent::NormalQueued], current_time);
    assert_eq!(f.actions[0], None);
    assert_eq!(f.runtime[0].counter_a, 50);
    assert_eq!(f.runtime[0].counter_b, 50);

    current_time = current_time.add(Duration::from_micros(20));
    _ = f.trigger_events(
        &[TriggerEvent::DecoyQueued {
            machine: MachineId(0),
        }],
        current_time,
    );
    assert_eq!(f.actions[0], None);
    assert_eq!(f.runtime[0].counter_a, 75);
    assert_eq!(f.runtime[0].counter_b, 0);
}

#[test]
fn counter_chain_machine() {
    // set both counters at once, then decrement one after the other
    // ensure that the updates happen in the correct order (recursion)
    // also, ensure that the *latest* specified action gets scheduled

    // state 0
    let mut s0 = State::new(enum_map! {
       Event::NormalQueued => vec![Trans(0, 1.0)],
       Event::DecoyQueued => vec![Trans(1, 1.0)],
       _ => vec![],
    });
    s0.counter = (
        Some(Counter::new(Operation::Set)), // (1, 1)
        Some(Counter::new(Operation::Set)),
    );

    // state 1
    let mut s1 = State::new(enum_map! {
       Event::CounterZero => vec![Trans(2, 1.0)], // the "chain reaction"
       _ => vec![],
    });
    s1.action = Some(Action::DecoyTraffic {
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
        n: Dist {
            dist: DistType::Uniform {
                low: 1.0,
                high: 1.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    s1.counter = (
        Some(Counter::new(Operation::Decrement)),
        None, // (0, 1)
    );

    // state 2
    let mut s2 = State::new(enum_map! {
       Event::CounterZero => vec![Trans(3, 1.0)],
       _ => vec![],
    });
    s2.action = Some(Action::DecoyTraffic {
        bypass: true,
        replace: false,
        timeout: Dist {
            dist: DistType::Uniform {
                low: 67.0,
                high: 67.0,
            },
            start: 0.0,
            max: 0.0,
        },
        n: Dist {
            dist: DistType::Uniform {
                low: 1.0,
                high: 1.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    s2.counter = (
        None,
        Some(Counter::new(Operation::Decrement)), // (0, 0)
    );

    // state 3
    let mut s3 = State::new(enum_map! {
       _ => vec![],
    });
    s3.counter = (
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
        None,
    );

    // machine
    let m = Machine::new(0, 0, vec![s0, s1, s2, s3]).unwrap();

    let mut current_time = Instant::now();
    let machines = vec![m];
    let mut f = Framework::new(
        &machines,
        LimitDecoyNone,
        LimitDelayNone,
        current_time,
        rand::rng(),
    )
    .unwrap();

    _ = f.trigger_events(&[TriggerEvent::NormalQueued], current_time);
    assert_eq!(f.actions[0], None);
    assert_eq!(f.runtime[0].counter_a, 1);
    assert_eq!(f.runtime[0].counter_b, 1);

    current_time = current_time.add(Duration::from_micros(20));
    _ = f.trigger_events(
        &[TriggerEvent::DecoyQueued {
            machine: MachineId(0),
        }],
        current_time,
    );
    assert_eq!(
        f.actions[0],
        Some(TriggerAction::DecoyTraffic {
            timeout: Duration::from_micros(67),
            n: 1,
            bypass: true,
            replace: false,
            machine: MachineId(0),
        })
    );
    assert_eq!(f.runtime[0].counter_a, 13);
    assert_eq!(f.runtime[0].counter_b, 0);
}

#[test]
fn counter_copy_machine() {
    // set both counters at once, then copy their values

    // state 0
    let mut s0 = State::new(enum_map! {
       Event::NormalQueued => vec![Trans(0, 1.0)],
       Event::DecoyQueued => vec![Trans(1, 1.0)],
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
       Event::DecoyQueued => vec![Trans(2, 1.0)],
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
    let m = Machine::new(1000, 0, vec![s0, s1, s2]).unwrap();

    let mut current_time = Instant::now();
    let machines = vec![m];
    let mut f = Framework::new(
        &machines,
        LimitDecoyNone,
        LimitDelayNone,
        current_time,
        rand::rng(),
    )
    .unwrap();

    _ = f.trigger_events(&[TriggerEvent::NormalQueued], current_time);
    assert_eq!(f.actions[0], None);
    assert_eq!(f.runtime[0].counter_a, 4);
    assert_eq!(f.runtime[0].counter_b, 13);

    current_time = current_time.add(Duration::from_micros(20));
    _ = f.trigger_events(
        &[TriggerEvent::DecoyQueued {
            machine: MachineId(0),
        }],
        current_time,
    );
    assert_eq!(f.actions[0], None);
    assert_eq!(f.runtime[0].counter_a, 13);
    assert_eq!(f.runtime[0].counter_b, 9);

    current_time = current_time.add(Duration::from_micros(20));
    _ = f.trigger_events(
        &[TriggerEvent::DecoyQueued {
            machine: MachineId(0),
        }],
        current_time,
    );
    assert_eq!(f.actions[0], None);
    assert_eq!(f.runtime[0].counter_a, 22);
    assert_eq!(f.runtime[0].counter_b, 9);
}

#[test]
fn counter_triggered_no_early_limit_decrement() {
    // a machine that uses two CounterZero events to trigger a transition
    // away and back again to the same state, refreshing limits

    // state 0, counters (2, 1)
    let mut s0 = State::new(enum_map! {
       Event::NormalQueued => vec![Trans(0, 1.0)],
       Event::DecoyQueued => vec![Trans(1, 1.0)],
       _ => vec![],
    });
    s0.counter = (
        Some(Counter::new_dist(
            Operation::Set,
            Dist {
                dist: DistType::Uniform {
                    low: 2.0,
                    high: 2.0,
                },
                start: 0.0,
                max: 0.0,
            },
        )),
        Some(Counter::new(Operation::Set)),
    );

    // state 1, diff (-1, 0)
    let mut s1 = State::new(enum_map! {
       Event::CounterZero => vec![Trans(2, 1.0)],
       Event::DecoyQueued => vec![Trans(1, 1.0)],
       _ => vec![],
    });
    s1.counter = (Some(Counter::new(Operation::Decrement)), None);
    s1.action = Some(Action::DecoyTraffic {
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
        n: Dist {
            dist: DistType::Uniform {
                low: 1.0,
                high: 1.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: Some(Dist {
            dist: DistType::Uniform {
                low: 2.0,
                high: 2.0,
            },
            start: 0.0,
            max: 0.0,
        }),
    });

    // state 2, diff (0, -1)
    let mut s2 = State::new(enum_map! {
       Event::CounterZero => vec![Trans(1, 1.0)],
       _ => vec![],
    });
    s2.counter = (None, Some(Counter::new(Operation::Decrement)));

    let m = Machine::new(1000, 0, vec![s0, s1, s2]).unwrap();

    let current_time = Instant::now();
    let machines = vec![m];
    let mut f = Framework::new(
        &machines,
        LimitDecoyNone,
        LimitDelayNone,
        current_time,
        rand::rng(),
    )
    .unwrap();

    _ = f.trigger_events(&[TriggerEvent::NormalQueued], current_time);
    assert_eq!(f.actions[0], None);
    assert_eq!(f.runtime[0].counter_a, 2);
    assert_eq!(f.runtime[0].counter_b, 1);

    _ = f.trigger_events(
        &[TriggerEvent::DecoyQueued {
            machine: MachineId(0),
        }],
        current_time,
    );
    assert!(f.actions[0].is_some());
    assert_eq!(f.runtime[0].counter_a, 1);
    assert_eq!(f.runtime[0].counter_b, 1);
    assert_eq!(f.runtime[0].state_limit, 2);

    _ = f.trigger_events(
        &[TriggerEvent::DecoyQueued {
            machine: MachineId(0),
        }],
        current_time,
    );
    assert!(f.actions[0].is_some());
    assert_eq!(f.runtime[0].counter_a, 0);
    assert_eq!(f.runtime[0].counter_b, 0);
    // this should be 2, because both the counters hitting zero transition
    // out of state 1 and back again, refreshing the limit
    assert_eq!(f.runtime[0].state_limit, 2);
}

#[test]
fn test_infinite_loop_counter() {
    // just to get started
    let s0 = State::new(enum_map! {
       Event::NormalQueued => vec![Trans(1, 1.0)],
       _ => vec![],
    });

    // set counter A to 1, B is 0
    let mut init = State::new(enum_map! {
    Event::NormalQueued => vec![Trans(2, 1.0)],
    _ => vec![],
    });
    init.counter = (Some(Counter::new(Operation::Set)), None);

    // decrement counter A, triggering CounterZero, and set B to 1
    let mut state_a = State::new(enum_map! {
    // to state_b
    Event::CounterZero => vec![Trans(3, 1.0)],
    // to state_pad
    Event::NormalRecv => vec![Trans(4, 1.0)],
    _ => vec![],
    });
    state_a.counter = (
        Some(Counter::new(Operation::Decrement)),
        Some(Counter::new(Operation::Set)),
    );

    // decrement counter B, triggering CounterZero, and set A to 1
    let mut state_b = State::new(enum_map! {
    // back to state_a
    Event::CounterZero => vec![Trans(2, 1.0)],
    _ => vec![],
    });
    state_b.counter = (
        Some(Counter::new(Operation::Set)),
        Some(Counter::new(Operation::Decrement)),
    );

    let mut state_pad = State::new(enum_map! {
        _ => vec![],
    });
    state_pad.action = Some(Action::DecoyTraffic {
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
        n: Dist {
            dist: DistType::Uniform {
                low: 1.0,
                high: 1.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });

    let m = Machine::new(1000, 0, vec![s0, init, state_a, state_b, state_pad]).unwrap();
    let machines = vec![m];
    let current_time = Instant::now();
    let mut f = Framework::new(
        machines,
        LimitDecoyNone,
        LimitDelayNone,
        current_time,
        rand::rng(),
    )
    .unwrap();
    // get into init state
    _ = f.trigger_events(&[TriggerEvent::NormalQueued], current_time);
    // transition to state_a: this should not loop forever, but be limited
    // to one zeroing of each counter, get stuck in state_a (after having
    // zeroed counter b in state_b), then transition to state_pad, returning
    // one action
    assert_eq!(
        f.trigger_events(
            &[TriggerEvent::NormalQueued, TriggerEvent::NormalRecv],
            current_time
        )
        .count(),
        1
    );
}

use super::*;

#[test]
fn trigger_events_actions() {
    // plan: create a machine that swaps between two states, trigger one
    // then multiple events and check the resulting actions

    // state 0: go to state 1 on DecoyQueued, pad after 10 usec
    let mut s0 = State::new(enum_map! {
        Event::DecoyQueued => vec![Trans(1, 1.0)],
    _ => vec![],
    });
    s0.action = Some(Action::DecoyTraffic {
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

    // state 1: go to state 0 on DecoyRecv, pad after 1 usec
    let mut s1 = State::new(enum_map! {
        Event::DecoyRecv => vec![Trans(0, 1.0)],
    _ => vec![],
    });
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
        limit: None,
    });

    // create a simple machine
    let m = Machine::new(1000, 0, vec![s0, s1]).unwrap();

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

    assert_eq!(f.actions.len(), 1);

    // start triggering
    _ = f.trigger_events(
        &[TriggerEvent::DelayBegin {
            machine: MachineId(0),
        }],
        current_time,
    );
    assert_eq!(f.actions[0], None);

    // move time forward, trigger again to make sure no scheduled timer
    current_time = current_time.add(Duration::from_micros(20));
    _ = f.trigger_events(
        &[TriggerEvent::DelayBegin {
            machine: MachineId(0),
        }],
        current_time,
    );
    assert_eq!(f.actions[0], None);

    // trigger transition to next state
    _ = f.trigger_events(
        &[TriggerEvent::DecoyQueued {
            machine: MachineId(0),
        }],
        current_time,
    );
    assert_eq!(
        f.actions[0],
        Some(TriggerAction::DecoyTraffic {
            timeout: Duration::from_micros(1),
            n: 1,
            bypass: false,
            replace: false,
            machine: MachineId(0),
        })
    );

    // increase time, trigger event, make sure no further action
    current_time = current_time.add(Duration::from_micros(20));
    _ = f.trigger_events(
        &[TriggerEvent::DecoyQueued {
            machine: MachineId(0),
        }],
        current_time,
    );
    assert_eq!(f.actions[0], None);

    // go back to state 0
    _ = f.trigger_events(&[TriggerEvent::DecoyRecv], current_time);
    assert_eq!(
        f.actions[0],
        Some(TriggerAction::DecoyTraffic {
            timeout: Duration::from_micros(10),
            n: 1,
            bypass: false,
            replace: false,
            machine: MachineId(0),
        })
    );

    // test multiple triggers overwriting actions
    for _ in 0..10 {
        _ = f.trigger_events(
            &[
                TriggerEvent::DecoyQueued {
                    machine: MachineId(0),
                },
                TriggerEvent::DecoyRecv,
            ],
            current_time,
        );
        assert_eq!(
            f.actions[0],
            Some(TriggerAction::DecoyTraffic {
                timeout: Duration::from_micros(10),
                n: 1,
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
                    TriggerEvent::DecoyRecv,
                    TriggerEvent::DecoyQueued {
                        machine: MachineId(0),
                    },
                    TriggerEvent::DecoyRecv,
                ],
                current_time,
            );
            assert_eq!(
                f.actions[0],
                Some(TriggerAction::DecoyTraffic {
                    timeout: Duration::from_micros(10),
                    n: 1,
                    bypass: false,
                    replace: false,
                    machine: MachineId(0),
                })
            );
        } else {
            _ = f.trigger_events(
                &[
                    TriggerEvent::DecoyQueued {
                        machine: MachineId(0),
                    },
                    TriggerEvent::DecoyRecv,
                    TriggerEvent::DecoyQueued {
                        machine: MachineId(0),
                    },
                ],
                current_time,
            );
            assert_eq!(
                f.actions[0],
                Some(TriggerAction::DecoyTraffic {
                    timeout: Duration::from_micros(1),
                    n: 1,
                    bypass: false,
                    replace: false,
                    machine: MachineId(0),
                })
            );
        }
    }
}

#[test]
fn delaying_machine() {
    // a machine that delays traffic for 10us, 1us after NormalQueued

    // state 0
    let mut s0 = State::new(enum_map! {
             Event::NormalQueued => vec![Trans(0, 1.0)],
         _ => vec![],
    });
    s0.action = Some(Action::DelayTraffic {
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
                low: 0.0,
                high: 0.0,
            },
            start: 1_000.0,
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
    let m = Machine::new(1000, 0, vec![s0]).unwrap();

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
    assert_eq!(
        f.actions[0],
        Some(TriggerAction::DelayTraffic {
            timeout: Duration::from_micros(1),
            n: 1_000,
            duration: Duration::from_micros(10),
            bypass: false,
            replace: false,
            machine: MachineId(0),
        })
    );

    current_time = current_time.add(Duration::from_micros(20));
    _ = f.trigger_events(
        &[TriggerEvent::DelayBegin {
            machine: MachineId(0),
        }],
        current_time,
    );
    assert_eq!(f.actions[0], None);

    for _ in 0..10 {
        current_time = current_time.add(Duration::from_micros(1));
        _ = f.trigger_events(&[TriggerEvent::NormalQueued], current_time);
        assert_eq!(
            f.actions[0],
            Some(TriggerAction::DelayTraffic {
                timeout: Duration::from_micros(1),
                n: 1_000,
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
    // a machine that sets the timer to 1 ms after DecoyQueued

    // state 0
    let mut s0 = State::new(enum_map! {
             Event::DecoyQueued => vec![Trans(1, 1.0)],
         _ => vec![],
    });
    s0.action = Some(Action::DecoyTraffic {
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
    let m = Machine::new(1000, 0, vec![s0, s1]).unwrap();

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
        Some(TriggerAction::DecoyTraffic {
            timeout: Duration::from_micros(1),
            n: 1,
            bypass: false,
            replace: false,
            machine: MachineId(0),
        })
    );
}

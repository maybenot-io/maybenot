use super::*;

#[test]
fn signal_one_machine() {
    // send a signal from one machine, ensure that the signal is received
    // by another machine but not the originating machine

    // state 0
    let s0_m0 = State::new(enum_map! {
       Event::NormalQueued => vec![Trans(STATE_SIGNAL, 1.0)],
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

    // machines
    let m0 = Machine::new(1000, 0, vec![s0_m0, s1.clone()]).unwrap();
    let m1 = Machine::new(1000, 0, vec![s0_m1, s1.clone()]).unwrap();

    let current_time = Instant::now();
    let machines = vec![m0, m1];
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
    assert_eq!(
        f.actions[1],
        Some(TriggerAction::DecoyTraffic {
            timeout: Duration::from_micros(2),
            n: 1,
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
       Event::NormalQueued => vec![Trans(STATE_SIGNAL, 1.0)],
       Event::Signal => vec![Trans(1, 1.0)],
       _ => vec![],
    });

    // state 1
    let mut s1 = State::new(enum_map! {
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

    // machines
    let m0 = Machine::new(1000, 0, vec![s0.clone(), s1.clone()]).unwrap();
    let m1 = Machine::new(1000, 0, vec![s0.clone(), s1.clone()]).unwrap();

    let current_time = Instant::now();
    let machines = vec![m0, m1];
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
        Some(TriggerAction::DecoyTraffic {
            timeout: Duration::from_micros(2),
            n: 1,
            bypass: false,
            replace: false,
            machine: MachineId(0),
        })
    );
    assert_eq!(
        f.actions[1],
        Some(TriggerAction::DecoyTraffic {
            timeout: Duration::from_micros(2),
            n: 1,
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
       Event::NormalQueued => vec![Trans(STATE_SIGNAL, 1.0)],
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

    // machines
    let m0 = Machine::new(1000, 0, vec![s0_m0, s1.clone()]).unwrap();
    let m1 = Machine::new(1000, 0, vec![s0_m1, s1.clone()]).unwrap();

    let current_time = Instant::now();
    let machines = vec![m0, m1];
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
        Some(TriggerAction::DecoyTraffic {
            timeout: Duration::from_micros(2),
            n: 1,
            bypass: false,
            replace: false,
            machine: MachineId(0),
        })
    );
    assert_eq!(f.actions[1], None);
}

use super::*;
use crate::limit::LimitDelayFrac;

#[test]
fn framework_max_decoy_frac() {
    // to test the global limits of the framework we create two machines
    // with the same allowed decoy, where both machines send decoys in
    // parallel

    // state 0
    let mut s0 = State::new(enum_map! {
        // we use sent for checking limits and recv as an event to check
        // without adding bytes sent
        Event::DecoyQueued | Event::NormalQueued | Event::NormalRecv => vec![Trans(0, 1.0)],
    _ => vec![],
    });
    s0.action = Some(Action::DecoyTraffic {
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
    let m1 = Machine::new(100, 0, vec![s0]).unwrap();
    let m2 = m1.clone();

    // NOTE 0.5 max_decoy_frac below
    let current_time = Instant::now();
    let machines = vec![m1, m2];
    let mut f = Framework::new(
        &machines,
        LimitDecoyFrac::new(0.5),
        LimitDelayNone,
        current_time,
        rand::rng(),
    )
    .unwrap();

    // we have two machines that each can send 100 packets before their own
    // or any framework limits are applied (by design, see
    // allowed_decoy_packets) trigger transition to get the loop going
    _ = f.trigger_events(&[TriggerEvent::NormalRecv], current_time);

    // we expect 100 decoy actions per machine
    for _ in 0..100 {
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
        _ = f.trigger_events(
            &[
                TriggerEvent::DecoyQueued {
                    machine: MachineId(0),
                },
                TriggerEvent::DecoyQueued {
                    machine: MachineId(1),
                },
                TriggerEvent::PacketSent,
                TriggerEvent::PacketSent,
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
    assert_eq!(f.runtime[0].decoys_sent, f.runtime[1].decoys_sent);
    assert_eq!(f.runtime[0].decoys_sent, 100);

    // OK, so we've sent in total 2*100 decoys using two machines. This
    // means that we should need to send at least 2*100 + 1 packets before a
    // decoy is scheduled again
    for _ in 0..200 {
        _ = f.trigger_events(&[TriggerEvent::NormalQueued], current_time);
        assert_eq!(f.actions[0], None);
        assert_eq!(f.actions[1], None);
    }

    // one more event should tip it over
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
fn framework_max_delay_frac() {
    // We create a machine that should be allowed to delay for 10us before
    // machine limits are applied, then the machine should be limited by the
    // delay limit (0.4 fraction of a 100us window = at most 40us delay).
    // Using a single long delay avoids floating-point accumulation.

    // state 0
    let mut s0 = State::new(enum_map! {
        Event::DelayBegin | Event::DelayEnd | Event::NormalRecv => vec![Trans(0, 1.0)],
    _ => vec![],
    });
    // delay every 2us for 10us
    s0.action = Some(Action::DelayTraffic {
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

    // machine: allowed_delay_microsec = 10
    let m = Machine::new(0, 10, vec![s0]).unwrap();

    let mut current_time = Instant::now();
    let machines = vec![m];
    // 0.4 fraction of a 100us window = at most 40us of delay
    let mut f = Framework::new(
        &machines,
        LimitDecoyNone,
        LimitDelayFrac::new(0.4, Duration::from_micros(100), usize::MAX),
        current_time,
        rand::rng(),
    )
    .unwrap();

    // trigger self to start delaying traffic (triggers action)
    _ = f.trigger_events(&[TriggerEvent::NormalRecv], current_time);
    assert!(f.actions[0].is_some());

    // start the delay
    _ = f.trigger_events(
        &[TriggerEvent::DelayBegin {
            machine: MachineId(0),
        }],
        current_time,
    );

    // allowed_delay_microsec = 10, so the first 10us of delay bypasses
    // the limit; advance 10us and end the delay
    current_time = current_time.add(Duration::from_micros(10));
    _ = f.trigger_events(&[TriggerEvent::DelayEnd], current_time);
    assert_eq!(f.delay_duration, Duration::from_micros(10));

    // 10us of delay in a 100us window = 10%, below 40% limit.
    // New delay should be allowed by limit.
    _ = f.trigger_events(&[TriggerEvent::NormalRecv], current_time);
    assert!(f.actions[0].is_some());

    // Start and end another 30us delay (total = 40us)
    _ = f.trigger_events(
        &[TriggerEvent::DelayBegin {
            machine: MachineId(0),
        }],
        current_time,
    );
    current_time = current_time.add(Duration::from_micros(30));
    _ = f.trigger_events(&[TriggerEvent::DelayEnd], current_time);
    assert_eq!(f.delay_duration, Duration::from_micros(40));

    // 40us of delay in 100us window = 40%, not < 40% → blocked
    _ = f.trigger_events(&[TriggerEvent::NormalRecv], current_time);
    assert_eq!(f.actions[0], None);

    // advance time so that the delays slide out of the window
    // at t=110, window covers [10, 110], first delay [0, 10] is outside
    // second delay [10, 40] overlaps [10, 40] = 30us → 30% < 40% → allowed
    current_time = current_time.add(Duration::from_micros(70));
    _ = f.trigger_events(&[TriggerEvent::NormalRecv], current_time);
    assert!(f.actions[0].is_some());
}

#[test]
fn framework_replace_delay() {
    // Plan: create two machines. #0 will exceed its delay limit and no
    // longer be allowed to cause delay. #1 will then delay traffic, so #0
    // should now be able to overwrite that delay regardless of its limit
    // (special case in below_limit_delay fn). XXX: broken plan after
    // removing per-machine limits. Neutering test now, to be re-done
    // regardless as we remake limits.
}

#[test]
fn framework_machine_sampled_limit() {
    // we create a machine that samples a decoy limit of 4 decoys sent, then
    // should be prevented from sending further decoys by transitioning to
    // self

    // state 0
    let s0 = State::new(enum_map! {
        Event::NormalQueued => vec![Trans(1, 1.0)],
    _ => vec![],
    });

    // state 1
    let mut s1 = State::new(enum_map! {
        Event::DecoyQueued => vec![Trans(1, 1.0)],
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
    let m = Machine::new(100000, 0, vec![s0, s1]).unwrap();

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

    // trigger self to start the decoy sending
    _ = f.trigger_events(&[TriggerEvent::NormalQueued], current_time);

    assert_eq!(f.runtime[0].state_limit, 4);

    // verify that we can send 4 decoys
    for _ in 0..4 {
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
        current_time = current_time.add(Duration::from_micros(1));
        _ = f.trigger_events(
            &[TriggerEvent::DecoyQueued {
                machine: MachineId(0),
            }],
            current_time,
        );
    }

    // decoy accounting correct
    assert_eq!(f.runtime[0].decoys_sent, 4);

    // limit should be reached after 4 decoys, delay next action
    assert_eq!(f.actions[0], None);
    assert_eq!(f.runtime[0].state_limit, 0);
}

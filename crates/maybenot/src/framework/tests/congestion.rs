use super::*;

#[test]
fn congestion_machine() {
    // plan: create a machine that changes state on congestion

    // state 0: go to state 1 on Congestion
    let s0 = State::new(enum_map! {
        Event::Congestion => vec![Trans(1, 1.0)],
    _ => vec![],
    });

    // state 1: pad after 1 usec
    let mut s1 = State::new(enum_map! { _ => vec![] });
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

    assert_eq!(f.actions.len(), 1);

    // start triggering
    _ = f.trigger_events(&[TriggerEvent::Congestion], current_time);
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

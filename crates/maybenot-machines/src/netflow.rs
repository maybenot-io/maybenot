use enum_map::enum_map;

use maybenot::{
    Machine,
    action::Action,
    dist::{Dist, DistType},
    event::Event,
    state::{State, Trans},
};

/// A simple NetFlow machine with the goal of keeping NetFlow records from being
/// generated ("collapsed"). Shares values from Tor's NetFlow logic for
/// connection-level padding, sending padding uniformly random every 1.5-9.5
/// seconds.
pub fn simple_netflow() -> Machine {
    gen_simple_netflow_machine(1500, 9500)
}

fn gen_simple_netflow_machine(low_ms: usize, high_ms: usize) -> Machine {
    // start state: on any packet, move to first state
    let s0 = State::new(enum_map! {
       Event::TunnelSent | Event::TunnelRecv => vec![Trans(1, 1.0)],
       _ => vec![],
    });

    // padding state: pad after a random delay of no activity
    let mut s1 = State::new(enum_map! {
       Event::TunnelSent => vec![Trans(1, 1.0)],
       _ => vec![],
    });
    s1.action = Some(Action::SendPadding {
        bypass: false,
        replace: false,
        timeout: Dist {
            dist: DistType::Uniform {
                low: low_ms as f64 * 1000.0,
                high: high_ms as f64 * 1000.0,
            },
            // always make sure to spawn a timer for consistency
            start: 1.0,
            max: 0.0,
        },
        limit: None,
    });

    // no limits
    Machine::new(u64::MAX, 0.0, 0, 0.0, vec![s0, s1]).unwrap()
}

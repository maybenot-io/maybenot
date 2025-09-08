use maybenot::{
    Machine,
    action::Action,
    constants::MAX_SAMPLED_BLOCK_DURATION,
    counter::{Counter, Operation},
    dist::{Dist, DistType},
    event::Event,
    state::{State, Trans},
};

use enum_map::enum_map;

/// Tamaraw from "A Systematic Approach to Developing and Evaluating Website
/// Fingerprinting Defenses" by Cai et al., CCS 2014. Pads at rate p s/packet,
/// with a soft stop condition, as implemented by Gong et al., "WFDefProxy: Real
/// World Implementation and Evaluation of Website Fingerprinting Defenses",
/// TIFS 2023.
pub fn tamaraw(p: f64, stop_window: f64) -> Vec<Machine> {
    vec![make_padding_machine(p), make_soft_stop_machine(stop_window)]
}

// make a machine that starts blocking, pads at rate p s/packet, and stops on
// blocking ending
fn make_padding_machine(p: f64) -> Machine {
    let mut states = vec![];

    let start = State::new(enum_map! {
        Event::NormalSent => vec![Trans(1, 1.0)],
       _ => vec![],
    });
    states.push(start);

    let mut block = State::new(enum_map! {
        Event::BlockingBegin => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    block.action = Some(Action::BlockOutgoing {
        bypass: true,
        replace: true,
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
                low: MAX_SAMPLED_BLOCK_DURATION,
                high: MAX_SAMPLED_BLOCK_DURATION,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    states.push(block);

    let mut padding = State::new(enum_map! {
        Event::BlockingEnd => vec![Trans(0, 1.0)],
        Event::TunnelSent => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    padding.action = Some(Action::SendPadding {
        bypass: true,
        replace: true,
        timeout: Dist {
            dist: DistType::Uniform {
                low: 0.0,
                high: 0.0,
            },
            start: 1000.0 * 1000.0 * p,
            max: 0.0,
        },
        limit: None,
    });
    states.push(padding);

    Machine::new(u64::MAX, 0.0, u64::MAX, 0.0, states).unwrap()
}

// make a machine that tracks the stop state of Tamaraw with a soft stop
// condition (from Gong et al. in their WFDefProxy paper) that restarts on new
// BlockingBegin
fn make_soft_stop_machine(stop_window: f64) -> Machine {
    let mut states = vec![];

    // 0: start machine when the padding machine starts blocking
    let start = State::new(enum_map! {
        Event::BlockingBegin => vec![Trans(1, 1.0)],
       _ => vec![],
    });
    states.push(start);

    // 1: set the L counter
    let mut set_counter = State::new(enum_map! {
        Event::TunnelSent => vec![Trans(2, 1.0)],
        Event::NormalSent => vec![Trans(3, 1.0)],
        Event::TimerEnd => vec![Trans(4, 1.0)],
       _ => vec![],
    });
    set_counter.counter = (
        Some(Counter {
            operation: Operation::Set,
            dist: Some(Dist {
                dist: DistType::Uniform {
                    low: 0.0,
                    high: 0.0,
                },
                start: 100.0,
                max: 0.0,
            }),
            copy: false,
        }),
        None,
    );
    states.push(set_counter);

    // 2: dec counter on TunnelSent
    let mut dec_counter = State::new(enum_map! {
        // refresh counter to count % L packets left for later
        Event::CounterZero=> vec![Trans(1, 1.0)],
        Event::TunnelSent => vec![Trans(2, 1.0)],
        Event::NormalSent => vec![Trans(3, 1.0)],
        Event::TimerEnd => vec![Trans(4, 1.0)],
       _ => vec![],
    });
    dec_counter.counter = (
        Some(Counter {
            operation: Operation::Decrement,
            dist: None,
            copy: false,
        }),
        None,
    );
    states.push(dec_counter);

    // 3: set the timer for the stop window
    let mut timer = State::new(enum_map! {
        Event::NormalSent => vec![Trans(3, 1.0)],
        Event::TimerEnd => vec![Trans(4, 1.0)],
       _ => vec![],
    });
    timer.action = Some(Action::UpdateTimer {
        replace: true,
        duration: Dist {
            dist: DistType::Uniform {
                low: 0.0,
                high: 0.0,
            },
            start: stop_window,
            max: 0.0,
        },
        limit: None,
    });
    states.push(timer);

    // 4: tail state, decrement until zero to send % L total number of packets
    let mut tail = State::new(enum_map! {
        Event::PaddingSent=> vec![Trans(4, 1.0)],
        Event::CounterZero=> vec![Trans(5, 1.0)],
       _ => vec![],
    });
    tail.counter = (
        Some(Counter {
            operation: Operation::Decrement,
            dist: None,
            copy: false,
        }),
        None,
    );
    tail.action = Some(Action::SendPadding {
        bypass: true,
        replace: true,
        timeout: Dist {
            dist: DistType::Uniform {
                low: 0.0,
                high: 0.0,
            },
            start: 1.0,
            max: 0.0,
        },
        limit: None,
    });
    states.push(tail);

    // 5: end blocking
    let mut end = State::new(enum_map! {
        Event::BlockingEnd=> vec![Trans(0, 1.0)],
       _ => vec![],
    });
    end.action = Some(Action::BlockOutgoing {
        bypass: true,
        replace: true,
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
                low: 0.0,
                high: 0.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    states.push(end);

    Machine::new(u64::MAX, 0.0, u64::MAX, 0.0, states).unwrap()
}

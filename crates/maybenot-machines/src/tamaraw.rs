use maybenot::{
    Machine,
    action::Action,
    constants::MAX_SAMPLED_DELAY_DURATION,
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

// make a machine that starts delay, pads at rate p s/packet, and stops on
// delay ending
fn make_padding_machine(p: f64) -> Machine {
    let mut states = vec![];

    let start = State::new(enum_map! {
        Event::NormalQueued => vec![Trans(1, 1.0)],
       _ => vec![],
    });
    states.push(start);

    let mut block = State::new(enum_map! {
        Event::DelayBegin => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    block.action = Some(Action::DelayTraffic {
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
        n: Dist {
            dist: DistType::Uniform {
                low: 0.0,
                high: 0.0,
            },
            start: f64::MAX,
            max: 0.0,
        },
        duration: Dist {
            dist: DistType::Uniform {
                low: MAX_SAMPLED_DELAY_DURATION,
                high: MAX_SAMPLED_DELAY_DURATION,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    states.push(block);

    let mut padding = State::new(enum_map! {
        Event::DelayEnd => vec![Trans(0, 1.0)],
        Event::PacketSent => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    padding.action = Some(Action::DecoyTraffic {
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
        n: Dist {
            dist: DistType::Uniform {
                low: 0.0,
                high: 0.0,
            },
            start: 1.0,
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

    // 0: start machine when the padding machine starts delay
    let start = State::new(enum_map! {
        Event::DelayBegin => vec![Trans(1, 1.0)],
       _ => vec![],
    });
    states.push(start);

    // 1: set the L counter
    let mut set_counter = State::new(enum_map! {
        Event::PacketSent => vec![Trans(2, 1.0)],
        Event::NormalQueued => vec![Trans(3, 1.0)],
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

    // 2: dec counter on PacketSent
    let mut dec_counter = State::new(enum_map! {
        // refresh counter to count % L packets left for later
        Event::CounterZero=> vec![Trans(1, 1.0)],
        Event::PacketSent => vec![Trans(2, 1.0)],
        Event::NormalQueued => vec![Trans(3, 1.0)],
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
        Event::NormalQueued => vec![Trans(3, 1.0)],
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
        Event::DecoyQueued=> vec![Trans(4, 1.0)],
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
    tail.action = Some(Action::DecoyTraffic {
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
        n: Dist {
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

    // 5: end delay
    let mut end = State::new(enum_map! {
        Event::DelayEnd=> vec![Trans(0, 1.0)],
       _ => vec![],
    });
    end.action = Some(Action::DelayTraffic {
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
        n: Dist {
            dist: DistType::Uniform {
                low: 0.0,
                high: 0.0,
            },
            start: f64::MAX,
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

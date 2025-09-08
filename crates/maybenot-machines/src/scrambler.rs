// Scrambler -- regularizes packet timing within segments and randomizes their
// sizes. Code from the paper: David Hasselquist, Ethan Witwer, August Carlson,
// Niklas Johansson, and Niklas Carlsson. "Raising the Bar: Improved
// Fingerprinting Attacks and Defenses for Video Streaming Traffic". Proceedings
// on Privacy Enhancing Technologies (PoPETs), volume 4, 2024. Ported to
// Maybenot v2 by Tobias Pulls.

use maybenot::{
    Machine,
    action::Action,
    constants::MAX_SAMPLED_BLOCK_DURATION,
    dist::{Dist, DistType},
    event::Event,
    state::{State, Trans},
};

use enum_map::enum_map;

// Machine #1 states
const NUM_STATES_M1: usize = 7;

const START_STATE_INDEX: usize = 0;
const BLOCK_STATE_INDEX: usize = 1;
const MIN_STATE_INDEX: usize = 2;
const LEFT_STATE_INDEX: usize = 3; // index of L_1
const RIGHT_STATE_INDEX: usize = 4; // index of R_1

// Machine #2 states
const NUM_STATES_M2: usize = 3;

const COUNT_LEFT_INDEX: usize = 0;
const COUNT_RIGHT_INDEX: usize = 1;
const SIGNAL_INDEX: usize = 2;

// 3 Mbps (250 packets/sec), for client
const SEND_INTERVAL: f64 = 4000.0;

pub fn scrambler_server(
    interval: f64,
    min_count: f64,
    min_trail: f64,
    max_trail: f64,
) -> Vec<Machine> {
    vec![
        generate_machine_one(interval, min_count, min_trail, max_trail),
        generate_machine_two(min_count),
    ]
}

pub fn scrambler_client() -> Vec<Machine> {
    // "On the client side, we run a simple 3 Mbps constant-rate defense."
    let mut states: Vec<State> = Vec::with_capacity(3);

    let start = State::new(enum_map! {
        // NonPaddingSent/NonPaddingRecv --> BLOCK (100%)
        Event::NormalSent => vec![Trans(1, 1.0)],
        Event::NormalRecv => vec![Trans(1, 1.0)],
       _ => vec![],
    });
    states.push(start);

    let mut block = State::new(enum_map! {
        // BlockingBegin --> CONST (100%)
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
        // PaddingSent --> CONST (100%)
        Event::PaddingSent => vec![Trans(2, 1.0)],
       _ => vec![],
    });
    padding.action = Some(Action::SendPadding {
        bypass: true,
        replace: true,
        timeout: Dist {
            dist: DistType::Uniform {
                low: SEND_INTERVAL,
                high: SEND_INTERVAL,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    states.push(padding);

    vec![Machine::new(0, 0.0, 0, 0.0, states).unwrap()]
}

// Generate Machine #1 with the specified parameters.
fn generate_machine_one(interval: f64, min_count: f64, min_trail: f64, max_trail: f64) -> Machine {
    // States
    let mut states: Vec<State> = Vec::with_capacity(NUM_STATES_M1);
    states.push(generate_start_state());
    states.push(generate_block_state());

    states.push(generate_min_state(interval, min_count));

    states.push(generate_left_state(0, interval, min_trail, max_trail));
    states.push(generate_right_state(0, interval, min_trail, max_trail));

    states.push(generate_left_state(
        1,
        interval,
        min_trail / 4.0,
        max_trail / 4.0,
    ));
    states.push(generate_right_state(
        1,
        interval,
        min_trail / 4.0,
        max_trail / 4.0,
    ));

    Machine::new(0, 0.0, 0, 0.0, states).unwrap()
}

// Generate the START state for Machine #1.
fn generate_start_state() -> State {
    State::new(enum_map! {
        // NormalSent --> BLOCK (100%)
        Event::NormalSent => vec![Trans(BLOCK_STATE_INDEX, 1.0)],
       _ => vec![],
    })
}

// Generate the BLOCK state for Machine #1.
fn generate_block_state() -> State {
    let mut block = State::new(enum_map! {
        // BlockingBegin --> MIN (100%)
        Event::BlockingBegin => vec![Trans(MIN_STATE_INDEX, 1.0)],
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

    block
}

// Generate the MIN state for Machine #1.
fn generate_min_state(interval: f64, min_count: f64) -> State {
    let mut min = State::new(enum_map! {
        // PaddingSent --> MIN (100%)
        Event::PaddingSent => vec![Trans(MIN_STATE_INDEX, 1.0)],
        // LimitReached --> R_1 (100%)
        Event::LimitReached => vec![Trans(RIGHT_STATE_INDEX, 1.0)],
       _ => vec![],
    });
    min.action = Some(Action::SendPadding {
        bypass: true,
        replace: true,
        timeout: Dist {
            dist: DistType::Uniform {
                low: interval,
                high: interval,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: Some(Dist {
            dist: DistType::Uniform {
                low: min_count,
                high: min_count,
            },
            start: 0.0,
            max: 0.0,
        }),
    });

    min
}

// Generate an L state for Machine #1.
fn generate_left_state(index: usize, interval: f64, min_trail: f64, max_trail: f64) -> State {
    let mut left = if index == 0 {
        State::new(enum_map! {
            // PaddingSent --> L_{index} (100%)
            Event::PaddingSent => vec![Trans(LEFT_STATE_INDEX + 2 * index, 1.0)],
            // NormalSent --> R_{index} (100%)
            Event::NormalSent => vec![Trans(RIGHT_STATE_INDEX + 2 * index, 1.0)],
            // LimitReached --> START (100%)
            Event::LimitReached => vec![Trans(START_STATE_INDEX, 1.0)],
            // BlockingBegin --> L_2 (if L_1)
            Event::BlockingBegin => vec![Trans(LEFT_STATE_INDEX + 2, 1.0)],
           _ => vec![],
        })
    } else {
        State::new(enum_map! {
            // PaddingSent --> L_{index} (100%)
            Event::PaddingSent => vec![Trans(LEFT_STATE_INDEX + 2 * index, 1.0)],
            // NormalSent --> R_{index} (100%)
            Event::NormalSent => vec![Trans(RIGHT_STATE_INDEX + 2 * index, 1.0)],
            // LimitReached --> START (100%)
            Event::LimitReached => vec![Trans(START_STATE_INDEX, 1.0)],
           _ => vec![],
        })
    };

    left.action = Some(Action::SendPadding {
        bypass: true,
        replace: true,
        timeout: Dist {
            dist: DistType::Uniform {
                low: interval,
                high: interval,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: Some(Dist {
            dist: DistType::Uniform {
                low: min_trail,
                high: max_trail,
            },
            start: 0.0,
            max: 0.0,
        }),
    });

    left
}

// Generate an R state for Machine #1.
fn generate_right_state(index: usize, interval: f64, min_trail: f64, max_trail: f64) -> State {
    let mut right = if index == 0 {
        State::new(enum_map! {
            // PaddingSent --> R_{index} (100%)
            Event::PaddingSent => vec![Trans(RIGHT_STATE_INDEX + 2 * index, 1.0)],
            // NormalSent --> L_{index} (100%)
            Event::NormalSent => vec![Trans(LEFT_STATE_INDEX + 2 * index, 1.0)],
            // LimitReached --> START (100%)
            Event::LimitReached => vec![Trans(START_STATE_INDEX, 1.0)],
            // BlockingBegin --> R_2 (if R_1)
            Event::BlockingBegin => vec![Trans(RIGHT_STATE_INDEX + 2, 1.0)],
           _ => vec![],
        })
    } else {
        State::new(enum_map! {
            // PaddingSent --> R_{index} (100%)
            Event::PaddingSent => vec![Trans(RIGHT_STATE_INDEX + 2 * index, 1.0)],
            // NormalSent --> L_{index} (100%)
            Event::NormalSent => vec![Trans(LEFT_STATE_INDEX + 2 * index, 1.0)],
            // LimitReached --> START (100%)
            Event::LimitReached => vec![Trans(START_STATE_INDEX, 1.0)],
           _ => vec![],
        })
    };

    right.action = Some(Action::SendPadding {
        bypass: true,
        replace: true,
        timeout: Dist {
            dist: DistType::Uniform {
                low: interval,
                high: interval,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: Some(Dist {
            dist: DistType::Uniform {
                low: min_trail,
                high: max_trail,
            },
            start: 0.0,
            max: 0.0,
        }),
    });

    right
}

// Generate Machine #2 with the specified parameters.
fn generate_machine_two(min_count: f64) -> Machine {
    // States
    let mut states: Vec<State> = Vec::with_capacity(NUM_STATES_M2);
    states.push(generate_count_left_state(min_count));
    states.push(generate_count_right_state(min_count));
    states.push(generate_signal_state());

    Machine::new(0, 0.0, 0, 0.0, states).unwrap()
}

// Generate the L state for Machine #2.
fn generate_count_left_state(count: f64) -> State {
    let mut left = State::new(enum_map! {
        // NormalSent --> L (100%)
        Event::NormalSent => vec![Trans(COUNT_LEFT_INDEX, 1.0)],
        // BlockingBegin --> R (100%)
        Event::BlockingBegin => vec![Trans(COUNT_RIGHT_INDEX, 1.0)],
        // LimitReached --> SIGNAL (100%)
        Event::LimitReached => vec![Trans(SIGNAL_INDEX, 1.0)],
       _ => vec![],
    });

    left.action = Some(Action::SendPadding {
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
        limit: Some(Dist {
            dist: DistType::Uniform {
                low: count * 1.25,
                high: count * 1.25,
            },
            start: 0.0,
            max: 0.0,
        }),
    });

    left
}

// Generate the R state for Machine #2.
fn generate_count_right_state(count: f64) -> State {
    let mut right = State::new(enum_map! {
        // NormalSent --> R (100%)
        Event::NormalSent => vec![Trans(COUNT_RIGHT_INDEX, 1.0)],
        // BlockingBegin --> L (100%)
        Event::BlockingBegin => vec![Trans(COUNT_LEFT_INDEX, 1.0)],
        // LimitReached --> SIGNAL (100%)
        Event::LimitReached => vec![Trans(SIGNAL_INDEX, 1.0)],
       _ => vec![],
    });

    right.action = Some(Action::SendPadding {
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
        limit: Some(Dist {
            dist: DistType::Uniform {
                low: count * 1.25,
                high: count * 1.25,
            },
            start: 0.0,
            max: 0.0,
        }),
    });

    right
}

// Generate the SIGNAL for Machine #2.
fn generate_signal_state() -> State {
    let mut block = State::new(enum_map! {
        // BlockingBegin --> R (100%)
        Event::BlockingBegin => vec![Trans(COUNT_RIGHT_INDEX, 1.0)],
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

    block
}

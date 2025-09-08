use maybenot::{
    Machine,
    action::Action,
    counter::{Counter, Operation},
    dist::{Dist, DistType},
    event::Event,
    state::{State, Trans},
};

use enum_map::enum_map;

// an implementation of Break-Pad (October) by Huang and Du, "Break-Pad:
// effective padding machines for tor with break burst padding",
// https://cybersecurity.springeropen.com/articles/10.1186/s42400-024-00222-y

pub fn break_pad_client() -> Vec<Machine> {
    let mut states = vec![];

    // client starts on normal sent
    let start = State::new(enum_map! {
        Event::NormalSent => vec![Trans(1, 1.0)],
       _ => vec![],
    });
    states.push(start);

    // make wait states
    states.extend(make_wait_states(
        states.len(),
        Dist {
            dist: DistType::Weibull {
                scale: 1.3832926042292748,
                shape: 8.766888541863576,
            },
            start: 0.0,
            max: 0.0,
        },
    ));

    // make pad state
    states.extend(make_pad_state(
        states.len(),
        0,
        make_pareto(1.9667283364576538, 0.05282296143414936),
    ));

    vec![Machine::new(1500, 0.5, 0, 0.0, states).unwrap()]
}

pub fn break_pad_server() -> Vec<Machine> {
    let mut states = vec![];

    // server starts on normal received
    let start = State::new(enum_map! {
        Event::NormalRecv => vec![Trans(1, 1.0)],
       _ => vec![],
    });
    states.push(start);

    // make wait states
    states.extend(make_wait_states(
        states.len(),
        Dist {
            dist: DistType::Weibull {
                scale: 1.1939537311219628,
                shape: 2.2388583813756533,
            },
            start: 0.0,
            max: 0.0,
        },
    ));

    // make pad state
    states.extend(make_pad_state(
        states.len(),
        0,
        make_pareto(7.009539453953314, -1.7523848634883286),
    ));

    vec![Machine::new(1500, 0.5, 0, 0.0, states).unwrap()]
}

fn make_wait_states(start: usize, threshold: Dist) -> Vec<State> {
    let mut states = vec![];

    // set threshold and wait for normal receive
    let mut set_threshold = State::new(enum_map! {
        Event::NormalRecv => vec![Trans(start+1, 1.0)],
        _ => vec![],
    });
    set_threshold.counter = (Some(Counter::new_dist(Operation::Set, threshold)), None);
    states.push(set_threshold);

    // countdown to zero
    let mut countdown = State::new(enum_map! {
        // reset the counter
        Event::NormalSent => vec![Trans(start, 1.0)],
        // decrement the counter
        Event::TunnelRecv => vec![Trans(start+1, 1.0)],
        // counter reaches zero, send padding
        Event::CounterZero => vec![Trans(start+2, 1.0)],
        _ => vec![],
    });
    countdown.counter = (Some(Counter::new(Operation::Decrement)), None);
    states.push(countdown);

    states
}

fn make_pad_state(start: usize, done: usize, limit: Dist) -> Vec<State> {
    let mut states = vec![];

    let mut pad_state = State::new(enum_map! {
        Event::PaddingSent => vec![Trans(start, 1.0)],
        Event::LimitReached => vec![Trans(done, 1.0)],
        _ => vec![],
    });
    pad_state.action = Some(Action::SendPadding {
        bypass: false,
        replace: false,
        timeout: Dist {
            dist: DistType::Uniform {
                low: 0.0,
                high: 0.0,
            },
            // always spawn a timer
            start: 1.0,
            max: 0.0,
        },
        limit: Some(limit),
    });
    states.push(pad_state);

    states
}

// Creates a Maybenot v2 Pareto distribution based on parameter for the Pareto
// distribution in Tor's Circuit Padding Framework. See
// https://gitlab.torproject.org/tpo/core/tor/-/blob/main/src/core/or/circuitpadding.c?ref_type=heads#L756
// for the original code.
fn make_pareto(circpad_param1: f64, circpad_param2: f64) -> Dist {
    // We take the absolute value of the second parameter (xi) to ensure it is
    // positive: this is because the Pareto distribution requires positive shape
    // and scale parameters. This modifies the tail behavior (it seems), but,
    // hopefully this is not a problem. The results are pretty decent when
    // simulating the defense on BigEnough.
    let circpad_param2 = circpad_param2.abs();
    // Tor uses a generalized Pareto distribution, with mu 0, sigma = param1,
    // and xi = param2. Maybenot uses the "regular" Pareto distribution, with
    // scale and shape parameters.
    let scale = circpad_param1 / circpad_param2;
    let shape = 1.0 / circpad_param2;

    Dist {
        dist: DistType::Pareto { scale, shape },
        // start has to be 1 to ensure we reach a limit in the padding state
        start: 1.0,
        max: 0.0,
    }
}

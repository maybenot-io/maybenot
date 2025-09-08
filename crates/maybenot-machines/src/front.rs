// Maybenot FRONT -- uses normally distributed padding to approximate the FRONT
// defense Code from the paper "State Machine Frameworks for Website
// Fingerprinting Defenses: Maybe Not" and updates to Maybenot v2 from
// https://github.com/moschramm/maybenot-defenses

use enum_map::enum_map;
use rand::Rng;
use rand::RngCore;
use std::f64::consts::E;
use std::f64::consts::PI;

use maybenot::{
    Machine,
    action::Action,
    constants::STATE_END,
    dist::{Dist, DistType},
    event::Event,
    state::State,
    state::Trans,
};

pub fn front<R: RngCore>(
    padding_budget_max: u32,
    window_min: f64,
    window_max: f64,
    num_states: usize,
    rng: &mut R,
) -> Vec<Machine> {
    let padding_budget = rng.random_range(1..padding_budget_max);
    let padding_window = rng.random_range(window_min..window_max);
    gen_front(padding_window, padding_budget, num_states)
}

// Generate a FRONT machine with the specified number of PADDING states.
fn gen_front(padding_window: f64, padding_budget: u32, num_states: usize) -> Vec<Machine> {
    let area = 1.0 / (num_states as f64); // Area under Rayleigh CDF curve of each state
    let max_t = rayleigh_max_t(padding_window);

    // States
    let mut states: Vec<State> = Vec::with_capacity(num_states + 1);
    states.push(generate_start_state());

    let mut t1 = 0.0; // Starting time of next PADDING state
    let mut total_padding_frac = 0.0; // Area coverage of current PADDING states

    for i in 1..num_states {
        let width = calc_interval_width(t1, max_t, area, padding_window);
        let middle = t1 + (width / 2.0);
        let t2 = t1 + width;

        let padding_count = area * (padding_budget as f64);
        let timeout = width / padding_count;
        let stdev = (padding_window).powi(2) / (padding_count * middle * PI.sqrt());

        states.push(generate_padding_state(
            i,
            i + 1,
            padding_count,
            timeout,
            stdev,
        ));

        t1 = t2;
        total_padding_frac += area;
    }

    // Last state, to max_t
    let width = max_t - t1;
    let middle = t1 + (width / 2.0);

    let padding_count = (1.0 - total_padding_frac) * (padding_budget as f64);
    let timeout = width / padding_count;
    let stdev = (padding_window).powi(2) / (padding_count * middle * PI.sqrt());

    // add last padding state
    states.push(generate_last_padding_state(
        num_states,
        padding_count,
        timeout,
        stdev,
    ));

    vec![Machine::new(u64::MAX, 0.0, 0, 0.0, states).unwrap()]
}

// Generate a PADDING state for a machine.
fn generate_padding_state(
    curr_index: usize,
    next_index: usize,
    padding_count: f64,
    timeout: f64,
    stdev: f64,
) -> State {
    let mut state = State::new(enum_map! {
        Event::PaddingSent => vec![Trans(curr_index, 1.0)],
        Event::LimitReached => vec![Trans(next_index, 1.0)],
        _ => vec![],
    });

    let timeout = Dist::new(
        DistType::Normal {
            mean: timeout,
            stdev,
        },
        0.0,
        timeout * 2.0,
    );
    let limit = Dist::new(
        DistType::Uniform {
            low: 1.0,
            high: padding_count.max(1.0),
        },
        0.0,
        0.0,
    );

    state.action = Some(Action::SendPadding {
        bypass: false,
        replace: false,
        timeout,
        limit: Some(limit),
    });

    state
}

// Generate the last PADDING state for a machine.
fn generate_last_padding_state(
    curr_index: usize,
    padding_count: f64,
    timeout: f64,
    stdev: f64,
) -> State {
    let mut state = State::new(enum_map! {
        Event::PaddingSent => vec![Trans(curr_index, 1.0)],
        Event::LimitReached => vec![Trans(STATE_END, 1.0)],
        _ => vec![],
    });

    let timeout: Dist = Dist::new(
        DistType::Normal {
            mean: timeout,
            stdev,
        },
        0.0,
        timeout * 2.0,
    );
    let limit = Dist::new(
        DistType::Uniform {
            low: 1.0,
            high: padding_count.max(1.0),
        },
        0.0,
        0.0,
    );

    state.action = Some(Action::SendPadding {
        bypass: false,
        replace: false,
        timeout,
        limit: Some(limit),
    });

    state
}

// Generate the START state for a machine.
fn generate_start_state() -> State {
    State::new(enum_map! {
        Event::NormalSent => vec![Trans(1, 1.0)],
        Event::NormalRecv => vec![Trans(1, 1.0)],
        _ => vec![],
    })
}

// Find the width of an interval in the Rayleigh distribution,
// starting at a, with the specified area. Uses a search algorithm
// because numerical error affects direct calculation significantly.
fn calc_interval_width(a: f64, max_t: f64, area: f64, scale: f64) -> f64 {
    let mut b = max_t;
    let mut increment = (b - a) / 2.0;

    let mut curr_area = rayleigh_cdf(b, scale) - rayleigh_cdf(a, scale);
    let mut curr_diff = area - curr_area;

    while curr_diff.abs() > f64::EPSILON {
        if curr_diff < 0.0 {
            b -= increment;
        } else {
            b += increment;
        }
        increment /= 2.0;

        curr_area = rayleigh_cdf(b, scale) - rayleigh_cdf(a, scale);
        curr_diff = area - curr_area;
    }

    b - a
}

// Cumulative distribution function of Rayleigh distribution
fn rayleigh_cdf(t: f64, scale: f64) -> f64 {
    let exp_num = -t.powi(2);
    let exp_div = 2.0 * scale.powi(2);
    let exp = exp_num / exp_div;

    1.0 - E.powf(exp)
}

// Return the value of t (input to Rayleigh CDF) at which area = 0.9996645373720975, chosen
// empirically. This is a bit more than 6 standard deviations.
fn rayleigh_max_t(scale: f64) -> f64 {
    let a: f64 = -2.0 * scale.powi(2);
    let b: f64 = 1.0 - 0.9996645373720975;

    (a * b.log(E)).sqrt()
}

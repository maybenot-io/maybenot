use std::ops::RangeInclusive;

use enum_map::{EnumMap, enum_map};
use maybenot::{
    Machine, Timer,
    action::Action,
    counter::{Counter, Operation},
    dist::{Dist, DistType},
    event::Event,
    state::{State, Trans},
};

use rand::Rng;
use rand::prelude::SliceRandom;

use crate::{
    random_machine::{DEFAULT_REF_COUNT_POINT, check_machine_states, round_f32, round_f64},
    rng_range,
};

/// Create a random Maybenot machine.
#[allow(clippy::too_many_arguments)]
pub(crate) fn random_machine<R: Rng>(
    num_states: usize,
    action_block: bool,
    expressive: bool,
    fixed_budget: bool,
    frac_limit: bool,
    duration_point: RangeInclusive<f64>,
    count_point: RangeInclusive<u64>,
    min_action_timeout: RangeInclusive<f64>,
    rng: &mut R,
) -> Machine {
    let allowed_padding_packets = if fixed_budget {
        let p = rng_range!(rng, count_point);
        rng.random_range(0..=p)
    } else {
        0
    };
    let allowed_blocked_microsec = if fixed_budget && action_block {
        let p = rng_range!(rng, duration_point) as u64;
        rng.random_range(0..=p)
    } else {
        0
    };
    let max_padding_frac = if frac_limit {
        round_f64(rng.random_range(0.0..=1.0))
    } else {
        0.0
    };
    let max_blocking_frac = if action_block && frac_limit {
        round_f64(rng.random_range(0.0..=1.0))
    } else {
        0.0
    };
    loop {
        let states: Vec<State> = (0..num_states)
            .map(|_| {
                random_state(
                    num_states,
                    action_block,
                    expressive,
                    rng_range!(rng, count_point).max(1),
                    rng_range!(rng, duration_point).max(1.0),
                    min_action_timeout.clone(),
                    rng,
                )
            })
            .collect();
        if check_machine_states(&states) {
            let m = Machine::new(
                allowed_padding_packets,
                max_padding_frac,
                allowed_blocked_microsec,
                max_blocking_frac,
                states,
            );
            if let Ok(m) = m {
                return m;
            }
        }
    }
}

pub fn random_state<R: Rng>(
    num_states: usize,
    action_block: bool,
    expressive: bool,
    count_point: u64,
    duration_point: f64,
    min_action_timeout: RangeInclusive<f64>,
    rng: &mut R,
) -> State {
    let mut action = if expressive {
        // bias towards having an action
        if rng.random_bool(0.75) {
            Some(random_action(
                action_block,
                expressive,
                count_point,
                duration_point,
                rng,
            ))
        } else {
            None
        }
    } else {
        Some(random_action(
            action_block,
            expressive,
            count_point,
            duration_point,
            rng,
        ))
    };

    // enforce the minimum action timeout for blocking and padding actions
    match action {
        Some(Action::BlockOutgoing {
            ref mut timeout, ..
        })
        | Some(Action::SendPadding {
            ref mut timeout, ..
        }) => {
            let min = rng_range!(rng, min_action_timeout);
            if timeout.start < min {
                timeout.start = min;
            }
        }
        _ => {}
    }

    let counter = if expressive {
        match rng.random_range(0..6) {
            // 50% chance of no counter
            0..=2 => (None, None),
            3 => (Some(random_counter(rng)), None),
            4 => (None, Some(random_counter(rng))),
            5 => (Some(random_counter(rng)), Some(random_counter(rng))),
            _ => unreachable!(),
        }
    } else {
        (None, None)
    };

    let action_has_limit = action.is_some()
        && match action.as_ref().unwrap() {
            Action::SendPadding { limit, .. }
            | Action::BlockOutgoing { limit, .. }
            | Action::UpdateTimer { limit, .. } => limit.is_some(),
            _ => false,
        };
    let transitions =
        random_transitions(num_states, action_block, expressive, action_has_limit, rng);

    let mut s = State::new(transitions);
    s.action = action;
    s.counter = counter;
    s
}

pub fn random_transitions<R: Rng>(
    num_states: usize,
    blocking: bool,
    expressive: bool,
    has_limit: bool,
    rng: &mut R,
) -> EnumMap<Event, Vec<Trans>> {
    let mut map = enum_map! {_ => vec![]};

    for e in Event::iter() {
        // skip events that are not allowed/relevant
        if !blocking && (*e == Event::BlockingBegin || *e == Event::BlockingEnd) {
            // NOTE: this can be used to signal to this machine from another
            // machine triggering blocking, but we ignore that for now
            continue;
        }
        if !has_limit && *e == Event::LimitReached {
            continue;
        }
        if !expressive
            && (*e == Event::TimerBegin
                || *e == Event::TimerEnd
                || *e == Event::CounterZero
                || *e == Event::Signal)
        {
            continue;
        }

        // generate transitions, always considering the LimitReached event if
        // the action has a limit
        if rng.random_bool(0.5) || has_limit && *e == Event::LimitReached {
            // number of transitions
            let n = rng.random_range(1..=num_states);
            // pick n unique states to transition to TODO: if expressive, add
            // support for transitioning to STATE_SIGNAL
            let mut states = (0..num_states).collect::<Vec<_>>();
            states.shuffle(rng);
            states.truncate(n);

            // give each state a random probability, rounded using round(), in
            // total summing up to at most 1.0
            let mut prob: Vec<f32> = vec![0.0; n];
            loop {
                let mut sum = 0.0;
                for p in prob.iter_mut() {
                    *p = round_f32(rng.random_range(0.1..=1.0));
                    sum += *p;
                }
                // normalize probabilities
                for p in prob.iter_mut() {
                    *p = round_f32(*p / sum);
                }
                sum = prob.iter().sum();
                if sum <= 1.0 {
                    break;
                }
            }

            // create transitions
            let mut t = vec![];
            for (s, p) in states.iter().zip(prob.iter()) {
                t.push(Trans(*s, *p));
            }

            // done, insert into map
            map[*e] = t;
        }
    }

    map
}

pub fn random_counter<R: Rng>(rng: &mut R) -> Counter {
    let operation = match rng.random_range(0..3) {
        0 => Operation::Increment,
        1 => Operation::Decrement,
        2 => Operation::Set,
        _ => unreachable!(),
    };

    match rng.random_range(0..3) {
        0 => Counter {
            operation,
            dist: None,
            copy: false,
        },
        1 => Counter {
            operation,
            dist: Some(random_dist(DEFAULT_REF_COUNT_POINT as f64, false, rng)),
            copy: false,
        },
        2 => Counter {
            operation,
            dist: None,
            copy: true,
        },
        _ => unreachable!(),
    }
}

pub fn random_action<R: Rng>(
    blocking: bool,
    expressive: bool,
    count_point: u64,
    duration_point: f64,
    rng: &mut R,
) -> Action {
    if expressive && blocking {
        return match rng.random_range(0..4) {
            0 => random_action_cancel(rng),
            1 => random_action_padding(count_point, duration_point, rng),
            2 => random_action_blocking(count_point, duration_point, expressive, rng),
            3 => random_action_timer(count_point, duration_point, rng),
            _ => unreachable!(),
        };
    }
    if expressive && !blocking {
        return match rng.random_range(0..3) {
            0 => random_action_cancel(rng),
            1 => random_action_padding(count_point, duration_point, rng),
            2 => random_action_timer(count_point, duration_point, rng),
            _ => unreachable!(),
        };
    }
    if blocking {
        return match rng.random_range(0..2) {
            0 => random_action_padding(count_point, duration_point, rng),
            1 => random_action_blocking(count_point, duration_point, expressive, rng),
            _ => unreachable!(),
        };
    }
    random_action_padding(count_point, duration_point, rng)
}

fn random_action_cancel<R: Rng>(rng: &mut R) -> Action {
    match rng.random_range(0..3) {
        0 => Action::Cancel {
            timer: Timer::Action,
        },
        1 => Action::Cancel {
            timer: Timer::Internal,
        },
        2 => Action::Cancel { timer: Timer::All },
        _ => unreachable!(),
    }
}

fn random_action_padding<R: Rng>(count_point: u64, duration_point: f64, rng: &mut R) -> Action {
    Action::SendPadding {
        bypass: rng.random_bool(0.5),
        replace: rng.random_bool(0.5),
        timeout: random_timeout(duration_point, rng),
        limit: random_limit(count_point, rng),
    }
}

fn random_action_blocking<R: Rng>(
    count_point: u64,
    duration_point: f64,
    expressive: bool,
    rng: &mut R,
) -> Action {
    Action::BlockOutgoing {
        bypass: rng.random_bool(0.5),
        // replaceable blocking ignores limits, making it possible for machines
        // that repeatedly blocks to cause infinite blocking: this is too
        // powerful for random machines, so we disable it by default
        replace: match expressive {
            true => rng.random_bool(0.5),
            false => false,
        },
        timeout: random_timeout(duration_point, rng),
        duration: random_timeout(duration_point, rng),
        limit: random_limit(count_point, rng),
    }
}

fn random_action_timer<R: Rng>(count_point: u64, duration_point: f64, rng: &mut R) -> Action {
    Action::UpdateTimer {
        replace: rng.random_bool(0.5),
        duration: random_timeout(duration_point, rng),
        limit: random_limit(count_point, rng),
    }
}

pub fn random_limit<R: Rng>(count_point: u64, rng: &mut R) -> Option<Dist> {
    if rng.random_bool(0.5) {
        Some(random_dist(count_point as f64, false, rng))
    } else {
        None
    }
}

pub fn random_timeout<R: Rng>(duration_point: f64, rng: &mut R) -> Dist {
    random_dist(duration_point, true, rng)
}

pub fn random_dist<R: Rng>(point: f64, is_timeout: bool, rng: &mut R) -> Dist {
    loop {
        let start = if rng.random_bool(0.5) {
            round_f64(rng.random_range(0.0..=point))
        } else {
            0.0
        };
        let max = if rng.random_bool(0.5) {
            round_f64(rng.random_range(start.min(point)..=point))
        } else {
            point
        };
        let dist = Dist {
            start,
            max,
            dist: if is_timeout {
                random_timeout_dist_type(point, rng)
            } else {
                random_count_dist_type(point, rng)
            },
        };

        if dist.validate().is_ok() {
            return dist;
        }
    }
}

// create a random distribution type for counts based on the point of reference
fn random_count_dist_type<R: Rng>(point: f64, rng: &mut R) -> DistType {
    match rng.random_range(0..=5) {
        0 => {
            let x = round_f64(rng.random_range(0.0..point));
            let y = round_f64(rng.random_range(x.min(point)..=point));
            DistType::Uniform { low: x, high: y }
        }
        1 => DistType::Binomial {
            trials: rng.random_range(10..=((point as u64).max(11))),
            probability: round_f64(rng.random_range::<f64, _>(0.0..=1.0).max(0.001)),
        },
        2 => DistType::Geometric {
            probability: round_f64(rng.random_range::<f64, _>(0.0..=1.0).max(0.001)),
        },
        3 => DistType::Pareto {
            scale: round_f64(rng.random_range::<f64, _>(point / 100.0..=point).max(0.001)),
            shape: round_f64(rng.random_range(0.001..=10.0)),
        },
        4 => DistType::Poisson {
            lambda: round_f64(rng.random_range(0.0..=point)),
        },
        5 => DistType::Weibull {
            scale: round_f64(rng.random_range(0.0..=point)),
            shape: round_f64(rng.random_range(0.5..5.0)),
        },
        _ => unreachable!(),
    }
}

// create a random distribution type for timeouts based on the point of reference
fn random_timeout_dist_type<R: Rng>(point: f64, rng: &mut R) -> DistType {
    match rng.random_range(0..=7) {
        0 => {
            let x = round_f64(rng.random_range(0.0..point));
            let y = round_f64(rng.random_range(x.min(point)..=point));
            DistType::Uniform { low: x, high: y }
        }
        1 => DistType::Normal {
            mean: round_f64(rng.random_range(0.0..=point)),
            stdev: round_f64(rng.random_range(0.0..=point)),
        },
        2 => DistType::SkewNormal {
            location: round_f64(rng.random_range(point * 0.5..=point * 1.5)),
            scale: round_f64(rng.random_range(point / 100.0..=point / 10.0)),
            shape: round_f64(rng.random_range(-5.0..=5.0)),
        },
        3 => DistType::LogNormal {
            mu: round_f64(rng.random_range(0.0..=20.0)),
            sigma: round_f64(rng.random_range(0.0..=1.0)),
        },
        4 => DistType::Pareto {
            scale: round_f64(rng.random_range::<f64, _>(point / 100.0..=point).max(0.001)),
            shape: round_f64(rng.random_range(0.001..=10.0)),
        },
        5 => DistType::Poisson {
            lambda: round_f64(rng.random_range(0.0..=point)),
        },
        6 => DistType::Weibull {
            scale: round_f64(rng.random_range(0.0..=point)),
            shape: round_f64(rng.random_range(0.5..5.0)),
        },
        7 => DistType::Gamma {
            scale: round_f64(rng.random_range(0.0..=point).max(0.001)),
            shape: round_f64(rng.random_range(0.001..=10.0)),
        },
        _ => unreachable!(),
    }
}

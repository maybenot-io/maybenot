//! An implementation of "RegulaTor: A Straightforward Website Fingerprinting
//! Defense" by Holland and Hopper, PETS 2022.

use std::vec;

use enum_map::enum_map;

use maybenot::{
    Machine, Timer,
    action::Action,
    constants::{MAX_SAMPLED_BLOCK_DURATION, STATE_END, STATE_SIGNAL},
    counter::{Counter, Operation},
    dist::{Dist, DistType},
    event::Event,
    state::{State, Trans},
};

// Root of many bugs in complex machines like those for attempting to accurately
// port RegulaTor: Datasets like BigEnough with many events that happen at the
// same time, or blocking ending resulting in many events at the exact same
// time. The Maybenot simulator deals with different events with different
// priorities, in general, prioritizing events that relate to the protected
// tunnel higher than actions from machines. This, especially in conjunction
// with counters potentially missing things due to encoding different things in
// different states is a PAIN to debug. This is the root of some seemingly odd
// machines here.
pub fn regulator_client(u: f64, c: f64) -> Vec<Machine> {
    vec![
        // machine that blocks outgoing with bypass replace then stops itself
        make_regulator_seal_machine(),
        // send packets at a fraction of the rate they're received
        make_regulator_loop_machine(u),
        // ensure that packets are never queued for more than C seconds: works
        // by temporarily releasing the block. Unfortunately, this means we
        // might send some more packets than we should, but it's the only way
        // that we found that is robust in Maybenot (i.e., free from edge-cases
        // where some packets are queued for longer).
        make_regulator_client_queue_machine(c),
    ]
}

pub fn regulator_server(r: f64, d: f64, t: f64, n: f64, num_bins: usize) -> Vec<Machine> {
    vec![
        // machine that blocks outgoing with bypass replace then ends
        make_regulator_seal_machine(),
        // machine that sends 10 packets at a constant rate, sends signal, ends
        make_regulator_boot_machine(10.0, 10),
        // on signal, (re)start a machine that pads at rate RD^t, where the rate
        // can never go below 1 PPS .. ends on blocking ending
        make_regulator_rate_machine(r, d, num_bins),
        // if we ever queue more than rate * threshold packets in any bin, surge
        // (reset) by sending a signal
        make_regulator_surge_machine(r, d, t, num_bins),
        // the echo machine echoes signals (purpose is to restart the surge
        // machine when it signals)
        make_regulator_echo_machine(),
        // count until we have spent padding budget, then end blocking, ending
        // the rate machine, and starting the blocking rate machine
        make_regulator_budget_machine(n),
        // like the rate machine, but with blocking toggled at the same PPS rate
        // as the padding rate
        make_regulator_block_rate_machine(r, d, num_bins),
    ]
}

fn make_regulator_block_rate_machine(r: f64, d: f64, num_bins: usize) -> Machine {
    let mut states = vec![];

    let start = State::new(enum_map! {
        Event::BlockingEnd => vec![Trans(1, 1.0)],
       _ => vec![],
    });
    states.push(start);

    // on every state, we will restart on signal
    let restart = states.len();

    let (delta_sec, rates) = get_rate_bins(r, d, num_bins);

    for rate in rates {
        let start = states.len();

        // 0: start a timer for delta_sec, then go to blocking state
        let mut timer = State::new(enum_map! {
            Event::TimerBegin  => vec![Trans(start + 1, 1.0)],
            Event::Signal => vec![Trans(restart, 1.0)],
            _ => vec![],
        });
        timer.action = Some(Action::UpdateTimer {
            replace: true,
            duration: Dist {
                dist: DistType::Uniform {
                    low: 0.0,
                    high: 0.0,
                },
                start: delta_sec * 1_000_000.0,
                max: 0.0,
            },
            limit: None,
        });
        states.push(timer);

        // 1: blocking at rate until timer expires
        let mut block = State::new(enum_map! {
            Event::BlockingEnd => vec![Trans(start +1, 1.0)],
            Event::TimerEnd  => vec![Trans(start +2, 1.0)],
            Event::Signal => vec![Trans(restart, 1.0)],
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
                    low: 0.0,
                    high: 0.0,
                },
                start: (1_000_000.0 / rate),
                max: 0.0,
            },
            limit: None,
        });
        states.push(block);
    }

    // last state that blocks 1s at a time for up to 60s
    let mut block = State::new(enum_map! {
        Event::BlockingEnd => vec![Trans(states.len(), 1.00)],
        Event::Signal => vec![Trans(restart, 1.0)],
        Event::LimitReached => vec![Trans(STATE_END, 1.0)],
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
            start: 1_000_000_000.0,
            max: 0.0,
        },
        duration: Dist {
            dist: DistType::Uniform {
                low: 0.0,
                high: 0.0,
            },
            start: 1.0,
            max: 0.0,
        },
        limit: Some(Dist {
            dist: DistType::Uniform {
                low: 0.0,
                high: 0.0,
            },
            start: 60.0,
            max: 0.0,
        }),
    });
    states.push(block);

    Machine::new(u64::MAX, 0.0, u64::MAX, 0.0, states).unwrap()
}

fn make_regulator_budget_machine(budget: f64) -> Machine {
    let mut states = vec![];

    let start = State::new(enum_map! {
        Event::BlockingBegin => vec![Trans(1, 1.0)],
       _ => vec![],
    });
    states.push(start);

    // 1: sample budget
    let mut setup = State::new(enum_map! {
        // increment on normal sent
        Event::NormalSent => vec![Trans(2, 1.0)],
        // decrement on tunnel sent
        Event::TunnelSent => vec![Trans(3, 1.0)],
        _ => vec![],
    });
    setup.counter = (
        Some(Counter::new_dist(
            Operation::Set,
            Dist {
                dist: DistType::Uniform {
                    low: 1.0, // or we never CounterZero below
                    high: budget,
                },
                start: 0.0,
                max: 0.0,
            },
        )),
        None,
    );
    states.push(setup);

    // 2: increment on normal queued
    let mut dec = State::new(enum_map! {
        Event::NormalSent => vec![Trans(2, 1.0)],
        Event::TunnelSent => vec![Trans(3, 1.0)],
        Event::CounterZero => vec![Trans(4, 1.0)],
        _ => vec![],
    });
    dec.counter = (Some(Counter::new(Operation::Increment)), None);
    states.push(dec);

    // 3: decrement on tunnel sent
    let mut dec = State::new(enum_map! {
        Event::NormalSent => vec![Trans(2, 1.0)],
        Event::TunnelSent => vec![Trans(3, 1.0)],
        Event::CounterZero => vec![Trans(4, 1.0)],
        _ => vec![],
    });
    dec.counter = (Some(Counter::new(Operation::Decrement)), None);
    states.push(dec);

    // 4: block override and signal on BlockingBegin, so that we get
    // BlockingBegin -> Signal -> BlockingEnd
    let mut end = State::new(enum_map! {
        Event::BlockingBegin => vec![Trans(STATE_SIGNAL, 1.0)],
        Event::Signal => vec![Trans(STATE_END, 1.0)],
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

fn make_regulator_echo_machine() -> Machine {
    let mut states = vec![];

    let echo = State::new(enum_map! {
        Event::Signal => vec![Trans(STATE_SIGNAL, 1.0)],
       _ => vec![],
    });
    states.push(echo);

    Machine::new(u64::MAX, 0.0, u64::MAX, 0.0, states).unwrap()
}

// mirror make_regulator_rate_machine(), triggering a "surge" (reset) if we ever
// queue more than rate * threshold packets in any bin
fn make_regulator_surge_machine(r: f64, d: f64, threshold: f64, num_bins: usize) -> Machine {
    let mut states = vec![];

    let start = State::new(enum_map! {
        Event::Signal => vec![Trans(1, 1.0)],
       _ => vec![],
    });
    states.push(start);

    // on every state, we will restart on signal
    let restart = states.len();

    let (delta_sec, rates) = get_rate_bins(r, d, num_bins);

    // Our bins are memoryless to make implementation easier. Total packets sent
    // in each bin: rate * delta_sec. delta_sec is longer than one second. With
    // a decay, more likely to go over any threshold at the end of a bin. We
    // know that we are going to hyperparameter tune this, so we make a simpler
    // version.

    for rate in rates {
        let start = states.len();
        let next_bin = states.len() + 3;

        // 0: start a timer for delta_sec, then go to counting init state
        let mut timer = State::new(enum_map! {
            Event::TimerBegin  => vec![Trans(start + 1, 1.0)],
            Event::Signal => vec![Trans(restart, 1.0)],
            _ => vec![],
        });
        timer.action = Some(Action::UpdateTimer {
            replace: true,
            duration: Dist {
                dist: DistType::Uniform {
                    low: 0.0,
                    high: 0.0,
                },
                start: delta_sec * 1_000_000.0,
                max: 0.0,
            },
            limit: None,
        });
        states.push(timer);

        // 1: set counter A on this bin's threshold
        let mut setup = State::new(enum_map! {
            // get to the dec state
            Event::NormalSent => vec![Trans(start +2, 1.0)],
            // always there events
            Event::TimerEnd  => vec![Trans(next_bin, 1.0)],
            Event::CounterZero => vec![Trans(STATE_SIGNAL, 1.0)],
            Event::Signal => vec![Trans(restart, 1.0)],
            _ => vec![],
        });
        setup.counter = (
            Some(Counter::new_dist(
                Operation::Set,
                Dist {
                    dist: DistType::Uniform {
                        low: 0.0,
                        high: 0.0,
                    },
                    start: (rate * threshold).ceil() + 1.0,
                    max: 0.0,
                },
            )),
            None,
        );
        states.push(setup);

        // 2: decrement counter A on every normal packet
        let mut dec = State::new(enum_map! {
            Event::NormalSent => vec![Trans(start +2, 1.0)],
            // always there events
            Event::TimerEnd  => vec![Trans(next_bin, 1.0)],
            Event::CounterZero => vec![Trans(STATE_SIGNAL, 1.0)],
            Event::Signal => vec![Trans(restart, 1.0)],
            _ => vec![],
        });
        dec.counter = (Some(Counter::new(Operation::Decrement)), None);
        states.push(dec);
    }

    // last state that signals directly on a NormalSent (this will happen above
    // for the tail bins)
    let tail = State::new(enum_map! {
        Event::NormalSent => vec![Trans(STATE_SIGNAL, 1.0)],
        Event::Signal => vec![Trans(restart, 1.0)],
        _ => vec![],
    });
    states.push(tail);

    Machine::new(u64::MAX, 0.0, u64::MAX, 0.0, states).unwrap()
}

// After signal, send packets at rate RD^t. Another signal restarts the machine.
fn make_regulator_rate_machine(r: f64, d: f64, num_bins: usize) -> Machine {
    let mut states = vec![];

    let start = State::new(enum_map! {
        Event::Signal => vec![Trans(1, 1.0)],
        Event::BlockingEnd => vec![Trans(STATE_END, 1.0)],
       _ => vec![],
    });
    states.push(start);

    // on every state, we will restart on signal
    let restart = states.len();

    let (delta_sec, rates) = get_rate_bins(r, d, num_bins);

    for rate in rates {
        let start = states.len();

        // start a timer for delta_sec, then go to padding state
        let mut timer = State::new(enum_map! {
            Event::TimerBegin  => vec![Trans(start + 1, 1.0)],
            Event::Signal => vec![Trans(restart, 1.0)],
            Event::BlockingEnd => vec![Trans(STATE_END, 1.0)],
            _ => vec![],
        });
        timer.action = Some(Action::UpdateTimer {
            replace: true,
            duration: Dist {
                dist: DistType::Uniform {
                    low: 0.0,
                    high: 0.0,
                },
                start: delta_sec * 1_000_000.0,
                max: 0.0,
            },
            limit: None,
        });
        states.push(timer);

        // padding at rate until timer expires
        let mut pad = State::new(enum_map! {
            Event::TunnelSent => vec![Trans(start +1, 1.0)],
            Event::TimerEnd  => vec![Trans(start +2, 1.0)],
            Event::Signal => vec![Trans(restart, 1.0)],
            Event::BlockingEnd => vec![Trans(STATE_END, 1.0)],
            _ => vec![],
        });
        pad.action = Some(Action::SendPadding {
            bypass: true,
            replace: true,
            timeout: Dist {
                dist: DistType::Uniform {
                    low: 0.0,
                    high: 0.0,
                },
                start: 1_000_000.0 / rate,
                max: 0.0,
            },
            limit: None,
        });
        states.push(pad);
    }

    // last state that pads at 1 PPS forever
    let mut pad = State::new(enum_map! {
        Event::TunnelSent => vec![Trans(states.len(), 1.0)],
        Event::Signal => vec![Trans(restart, 1.0)],
        Event::BlockingEnd => vec![Trans(STATE_END, 1.0)],
        _ => vec![],
    });
    pad.action = Some(Action::SendPadding {
        bypass: true,
        replace: true,
        timeout: Dist {
            dist: DistType::Uniform {
                low: 0.0,
                high: 0.0,
            },
            start: 1_000_000.0,
            max: 0.0,
        },
        limit: None,
    });
    states.push(pad);

    Machine::new(u64::MAX, 0.0, u64::MAX, 0.0, states).unwrap()
}

// returns the number of seconds for each bin, and the rates for each bin
fn get_rate_bins(r: f64, d: f64, num_bins: usize) -> (f64, Vec<f64>) {
    let mut rates = vec![];

    // the time when the rate will be 1.0 (can never go below 1 in RegulaTor)
    let time_end = (1.0 / r).ln() / d.ln();
    let delta = time_end / num_bins as f64;

    for i in 0..num_bins {
        let start = i as f64 * delta;
        let end = (i + 1) as f64 * delta;
        // fˉ​i = r/(Δt * ln(D)) * ​[Dti+1​−Dti​]
        let avg = (r / (delta * d.ln())) * (d.powf(end) - d.powf(start));
        rates.push(avg);
    }

    (delta, rates)
}

// after blocking begin, sends n padding packets at pps, then sends a signal
fn make_regulator_boot_machine(pps: f64, n: usize) -> Machine {
    let mut states = vec![];

    let start = State::new(enum_map! {
        Event::BlockingBegin => vec![Trans(1, 1.0)],
       _ => vec![],
    });
    states.push(start);

    let mut pad = State::new(enum_map! {
        Event::PaddingSent => vec![Trans(1, 1.0)],
        Event::LimitReached => vec![Trans(STATE_SIGNAL, 1.0)],
        Event::BlockingEnd => vec![Trans(STATE_END, 1.0)],
        _ => vec![],
    });
    pad.action = Some(Action::SendPadding {
        bypass: true,
        replace: true,
        timeout: Dist {
            dist: DistType::Uniform {
                low: 0.0,
                high: 0.0,
            },
            start: 1_000_000.0 / pps,
            max: 0.0,
        },
        limit: Some(Dist {
            dist: DistType::Uniform {
                low: 0.0,
                high: 0.0,
            },
            start: n as f64,
            max: 0.0,
        }),
    });
    states.push(pad);

    Machine::new(u64::MAX, 0.0, u64::MAX, 0.0, states).unwrap()
}

// RegulaTor, both sides:
// A machine that enables infinite blocking on the first NormalSent, thereby
// "sealing" the network link.
fn make_regulator_seal_machine() -> Machine {
    let mut states = vec![];

    // start state (0)
    let start = State::new(enum_map! {
        Event::NormalSent => vec![Trans(1, 1.0)],
       _ => vec![],
    });
    states.push(start);

    // block state (1), infinite blocking
    let mut block = State::new(enum_map! {
        Event::BlockingBegin => vec![Trans(STATE_END, 1.0)],
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

    Machine::new(u64::MAX, 0.0, u64::MAX, 0.0, states).unwrap()
}

// RegulaTor, client side (1/2):
// A machine that sends packets at a fraction of the rate they're received.
fn make_regulator_loop_machine(upload_ratio: f64) -> Machine {
    let mut states = vec![];

    // start state (0)
    let start = State::new(enum_map! {
        Event::NormalSent => vec![Trans(1, 1.0)],
       _ => vec![],
    });
    states.push(start);

    // init state (1)
    let mut init = State::new(enum_map! {
        Event::TunnelRecv => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    init.counter = (
        // count packets remaining before sending one
        Some(Counter::new_dist(
            Operation::Set,
            Dist {
                dist: DistType::Uniform {
                    low: upload_ratio.floor(),
                    high: upload_ratio.floor(),
                },
                start: 0.0,
                max: 0.0,
            },
        )),
        None,
    );
    states.push(init);

    // loop cluster
    push_loop_cluster(&mut states, upload_ratio);

    Machine::new(u64::MAX, 0.0, u64::MAX, 0.0, states).unwrap()
}

// (Related to the "loop machine") count approximately upload_ratio packets
// received before sending to maintain the correct ratio.
fn push_loop_cluster(states: &mut Vec<State>, upload_ratio: f64) {
    let start_index = states.len();
    let prob_wait_extra = upload_ratio.fract() as f32;

    // base state (+0), wait for upload_ratio.floor() packets
    let mut transitions = enum_map! {
        Event::TunnelRecv => vec![Trans(start_index, 1.0)],
        Event::CounterZero => vec![Trans(start_index + 2, 1.0 - prob_wait_extra)],
        _ => vec![],
    };
    if prob_wait_extra > 0.0 {
        transitions[Event::CounterZero].push(Trans(start_index + 1, prob_wait_extra));
    }
    let mut base = State::new(transitions);
    base.counter = (
        // received one packet, count down
        Some(Counter::new(Operation::Decrement)),
        None,
    );
    states.push(base);

    // extra state (+1), wait for an additional packet
    let extra = State::new(enum_map! {
        Event::TunnelRecv => vec![Trans(start_index + 2, 1.0)],
        _ => vec![],
    });
    states.push(extra);

    // send state (+2)
    let mut send = State::new(enum_map! {
        Event::TunnelSent => vec![Trans(start_index, 1.0)],
        _ => vec![],
    });
    send.action = Some(Action::SendPadding {
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
        limit: None,
    });
    send.counter = (
        // reset the count
        Some(Counter::new_dist(
            Operation::Set,
            Dist {
                dist: DistType::Uniform {
                    low: upload_ratio.floor(),
                    high: upload_ratio.floor(),
                },
                start: 0.0,
                max: 0.0,
            },
        )),
        None,
    );
    states.push(send);
}

fn make_regulator_client_queue_machine(c: f64) -> Machine {
    let mut states = vec![];

    // wait for a normal packet to get queued, cancel any timer
    let mut start = State::new(enum_map! {
        Event::NormalSent => vec![Trans(1, 1.0)],
       _ => vec![],
    });
    start.action = Some(Action::Cancel { timer: Timer::All });
    states.push(start);

    // 1: start a timer for C seconds
    let mut timer = State::new(enum_map! {
        // if we send a packet, reset the timer
        Event::TunnelSent  => vec![Trans(1, 1.0)],
        Event::TimerEnd  => vec![Trans(2, 1.0)],

        _ => vec![],
    });
    timer.action = Some(Action::UpdateTimer {
        replace: true,
        duration: Dist {
            dist: DistType::Uniform {
                low: 0.0,
                high: 0.0,
            },
            start: c * 1_000_000.0,
            max: 0.0,
        },
        limit: None,
    });
    states.push(timer);

    // 2: release blocking, sending all queued packets
    let mut release = State::new(enum_map! {
        Event::BlockingEnd => vec![Trans(3, 1.0)],
        _ => vec![],
    });
    release.action = Some(Action::BlockOutgoing {
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
    states.push(release);

    // and block again after 1us, then to start
    let mut block = State::new(enum_map! {
        Event::BlockingBegin => vec![Trans(0, 1.0)],
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
            start: 1.0,
            max: 0.0,
        },
        duration: Dist {
            dist: DistType::Uniform {
                low: 0.0,
                high: 0.0,
            },
            start: MAX_SAMPLED_BLOCK_DURATION,
            max: 0.0,
        },
        limit: None,
    });
    states.push(block);

    Machine::new(u64::MAX, 0.0, u64::MAX, 0.0, states).unwrap()
}

use std::time::{Duration, Instant};

use log::debug;
use maybenot::{action::Action, state::State, Machine, TriggerEvent};
use maybenot_simulator::{
    network::Network, queue::SimQueue, sim_advanced, SimEvent, SimulatorArgs,
};

#[allow(clippy::too_many_arguments)]
pub fn run_test_sim(
    input: &str,
    output: &str,
    delay: Duration,
    machines_client: &[Machine],
    machines_server: &[Machine],
    client: bool,
    max_trace_length: usize,
    only_packets: bool,
    as_ms: bool,
) {
    let binding = Network::new(delay, None);
    let mut args = SimulatorArgs::new(&binding, max_trace_length, only_packets, None, None);
    args.continue_after_all_normal_packets_processed = true;
    let starting_time = Instant::now();
    let mut sq = make_sq(input.to_string(), delay, starting_time, as_ms);
    let trace = sim_advanced(machines_client, machines_server, &mut sq, &args);
    let mut fmt = fmt_trace(&trace, client, as_ms);
    if fmt.len() > output.len() {
        fmt = fmt.get(0..output.len()).unwrap().to_string();
    }
    debug!("input: {}", input);
    assert_eq!(output, fmt);
}

fn fmt_trace(trace: &[SimEvent], client: bool, ms: bool) -> String {
    fn fmt_event(e: &SimEvent, base: Instant, ms: bool) -> String {
        format!(
            "{:1},{}",
            match ms {
                true => e.time.duration_since(base).as_millis(),
                false => e.time.duration_since(base).as_micros(),
            },
            e.event
        )
    }

    let base = trace[0].time;
    let mut s: String = "".to_string();
    for trace in trace {
        if trace.client == client {
            s = format!("{} {}", s, fmt_event(trace, base, ms));
        }
    }
    s.trim().to_string()
}

pub fn make_sq(s: String, delay: Duration, starting_time: Instant, as_ms: bool) -> SimQueue {
    let mut sq = SimQueue::new();
    let integration_delay = Duration::from_micros(0);

    // format we expect to parse: 0,s 18,s 25,r 25,r 30,s 35,r
    for line in s.split(' ') {
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() == 2 {
            let timestamp = starting_time
                + match as_ms {
                    true => Duration::from_millis(parts[0].parse::<u64>().unwrap()),
                    false => Duration::from_micros(parts[0].parse::<u64>().unwrap()),
                };

            match parts[1] {
                "s" | "sn" => {
                    // client sent at the given time
                    sq.push(
                        TriggerEvent::NormalSent,
                        true,
                        false,
                        timestamp,
                        integration_delay,
                    );
                }
                "r" | "rn" => {
                    // sent by server delay time ago
                    let sent = timestamp - delay;
                    sq.push(
                        TriggerEvent::NormalSent,
                        false,
                        false,
                        sent,
                        integration_delay,
                    );
                }
                _ => {
                    panic!("invalid direction")
                }
            }
        }
    }

    sq
}

pub fn set_bypass(s: &mut State, value: bool) {
    if let Some(ref mut a) = s.action {
        match a {
            Action::BlockOutgoing { bypass, .. } => {
                *bypass = value;
            }
            Action::SendPadding { bypass, .. } => {
                *bypass = value;
            }
            _ => {}
        }
    }
}

pub fn set_replace(s: &mut State, value: bool) {
    if let Some(ref mut a) = s.action {
        match a {
            Action::BlockOutgoing { replace, .. } => {
                *replace = value;
            }
            Action::SendPadding { replace, .. } => {
                *replace = value;
            }
            _ => {}
        }
    }
}

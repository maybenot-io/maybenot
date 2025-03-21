use std::env;
use std::fs::File;
use std::io::Write;
use std::time::{Duration, Instant};

use log::debug;
use maybenot::{action::Action, state::State, Machine, TriggerEvent};
use maybenot_simulator::{
    linktrace::{load_linktrace_from_file, mk_start_instant},
    network::{ExtendedNetworkLabels, Network},
    queue::SimQueue,
    sim_advanced, SimEvent, SimulatorArgs,
};
use once_cell::sync::Lazy;

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
    //let binding = Network::new(delay, None);
    //let mut args = SimulatorArgs::new(&binding, max_trace_length, only_packets);
    let mut args = SimulatorArgs::new(Network::new(delay, None), max_trace_length, only_packets);
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

#[allow(non_camel_case_types)]
pub enum TraceSpec {
    ether100M,
    ether100M_10M_assym,
}

pub fn get_test_simargs(
    base_args: SimulatorArgs,
    use_network: String,
    tracespec: TraceSpec,
) -> SimulatorArgs {
    match (use_network.as_str(), tracespec) {
        ("hires", TraceSpec::ether100M) => {
            let linktrace = load_linktrace_from_file("tests/ether100M_synth5M.ltbin.gz")
                .expect("Failed to load LinkTrace ltbin from file");
            SimulatorArgs {
                simulated_network_type: Some(ExtendedNetworkLabels::Linktrace),
                linktrace: Some(linktrace),
                ..base_args
            }
        }
        ("hires", TraceSpec::ether100M_10M_assym) => {
            let linktrace = load_linktrace_from_file("tests/ether_100Mserv_10Mcli_5M.ltbin.gz")
                .expect("Failed to load LinkTrace ltbin from file");
            SimulatorArgs {
                simulated_network_type: Some(ExtendedNetworkLabels::Linktrace),
                linktrace: Some(linktrace),
                ..base_args
            }
        }
        ("stdres", TraceSpec::ether100M) => {
            let linktrace = load_linktrace_from_file("tests/ether100M_synth10K_std.ltbin.gz")
                .expect("Failed to load LinkTrace ltbin from file");
            SimulatorArgs {
                simulated_network_type: Some(ExtendedNetworkLabels::Linktrace),
                linktrace: Some(linktrace),
                ..base_args
            }
        }
        ("stdres", TraceSpec::ether100M_10M_assym) => {
            let linktrace =
                load_linktrace_from_file("tests/ether_100Mserv_10Mcli_10K_std.ltbin.gz")
                    .expect("Failed to load LinkTrace ltbin from file");
            SimulatorArgs {
                simulated_network_type: Some(ExtendedNetworkLabels::Linktrace),
                linktrace: Some(linktrace),
                ..base_args
            }
        }
        ("fixed", TraceSpec::ether100M) => SimulatorArgs {
            simulated_network_type: Some(ExtendedNetworkLabels::FixedTput),
            client_tput: Some(100_000_000),
            server_tput: Some(100_000_000),
            ..base_args
        },
        ("fixed", TraceSpec::ether100M_10M_assym) => SimulatorArgs {
            simulated_network_type: Some(ExtendedNetworkLabels::FixedTput),
            client_tput: Some(10_000_000),
            server_tput: Some(100_000_000),
            ..base_args
        },
        ("bneck", _) => base_args,
        (other, _) => panic!(
            "Invalid USE_NETWORK value: {}. Expected either 'hires', 'stdres', 'fixed', 'bneck'.",
            other
        ),
    }
}

pub fn run_test_sim_trace(
    input: &str,
    output: &str,
    delay: Duration,
    machines_client: &[Machine],
    machines_server: &[Machine],
    client: bool,
    max_trace_length: usize,
    only_packets: bool,
    as_ms: bool,
    description: &str,
    use_network: &str,
    skip_asserts: bool,
) {
    let network = Network::new(delay, None);
    let base_args = SimulatorArgs::new(network, max_trace_length, only_packets);

    let mut args = match use_network {
        "hires" => {
            let linktrace = load_linktrace_from_file("tests/ether100M_synth5M.ltbin.gz")
                .expect("Failed to load LinkTrace ltbin from file");
            SimulatorArgs {
                simulated_network_type: Some(ExtendedNetworkLabels::Linktrace),
                linktrace: Some(linktrace),
                ..base_args
            }
        }
        "stdres" => {
            let linktrace = load_linktrace_from_file("tests/ether100M_synth10K_std.ltbin.gz")
                .expect("Failed to load LinkTrace ltbin from file");
            SimulatorArgs {
                simulated_network_type: Some(ExtendedNetworkLabels::Linktrace),
                linktrace: Some(linktrace),
                ..base_args
            }
        }
        "fixed" => SimulatorArgs {
            simulated_network_type: Some(ExtendedNetworkLabels::FixedTput),
            client_tput: Some(100_000_000),
            server_tput: Some(100_000_000),
            ..base_args
        },
        "bneck" => base_args,
        other => panic!(
            "Invalid USE_NETWORK value: {}. Expected either 'fixed' or 'bneck'.",
            other
        ),
    };

    let tracefilename = format!("{}__{}.simtrace", description, use_network);

    args.continue_after_all_normal_packets_processed = true;
    let starting_time = mk_start_instant();
    let mut sq = make_sq(input.to_string(), delay, starting_time, as_ms);
    let trace = run_and_save_trace(&tracefilename, || {
        sim_advanced(machines_client, machines_server, &mut sq, &args)
    });
    let mut fmt = fmt_trace(&trace, client, as_ms);
    if fmt.len() > output.len() {
        fmt = fmt.get(0..output.len()).unwrap().to_string();
    }
    debug!("input: {}", input);
    if !skip_asserts {
        assert_eq!(output, fmt);
    }
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

/// Runs the closure `f` to produce a result (e.g. the trace), and if the
/// environment variable `SAVE_TRACE` is set to "1", writes the formatted result
/// to the specified filename.
/// eg.   $SAVE_TRACE=1 cargo test
static SAVE_TRACE: Lazy<bool> = Lazy::new(|| match env::var("SAVE_TRACE").as_deref() {
    Ok("0") => false,
    Ok("1") => true,
    Ok(v) => panic!("Invalid SAVE_TRACE value: {}. Expected 0 or 1.", v),
    Err(_) => false,
});

pub fn run_and_save_trace<T, F>(filename: &str, f: F) -> T
where
    F: FnOnce() -> T,
    T: std::fmt::Debug,
{
    let result = f();

    if *SAVE_TRACE {
        let mut file = File::create(filename).expect("Failed to create trace output file");
        write!(file, "{:#?}", result).expect("Failed to write trace to file");
        println!("Trace saved to {}", filename);
    }
    result
}

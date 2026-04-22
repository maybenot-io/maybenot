use maybenot::{Machine, TriggerEvent};
use maybenot_simulator::{parse_trace, settings::Setting, sim, topology::load_topology_from_file};
use std::{str::FromStr, time::Duration};

#[cfg(feature = "trace-tests")]
use maybenot_simulator::{SimulatorArgs, sim_advanced, topology::load_topology_from_str};
#[cfg(feature = "trace-tests")]
use std::fs;
#[cfg(feature = "trace-tests")]
use toml::Value;

/// Modifies TOML string by applying parameter changes to specific sections.
/// Format: "SectionType:ID::param1:value1::param2:value2\n..."
#[cfg(feature = "trace-tests")]
fn modify_toml(toml_in: &str, modifier_string: &str) -> Result<String, String> {
    let mut toml_value: toml::Value =
        toml::from_str(toml_in).map_err(|e| format!("Failed to parse input TOML: {}", e))?;

    let root_table = toml_value
        .as_table_mut()
        .ok_or("TOML root is not a table")?;

    for line in modifier_string.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split("::").collect();
        if parts.is_empty() {
            return Err("Empty modification line".to_string());
        }

        let section_parts: Vec<&str> = parts[0].split(':').collect();
        if section_parts.len() != 2 {
            return Err(format!("Invalid section format in line: {}", line));
        }

        let section_type = section_parts[0];
        let section_id: usize = section_parts[1]
            .parse()
            .map_err(|_| format!("Invalid section ID in line: {}", line))?;

        let section_array = match section_type {
            "Node" => root_table.get_mut("Node"),
            "Link" => root_table.get_mut("Link"),
            _ => return Err(format!("Unsupported section type: {}", section_type)),
        };

        let section_array = section_array
            .and_then(|v| v.as_array_mut())
            .ok_or(format!("Section {} is not an array", section_type))?;

        let target_section = section_array
            .iter_mut()
            .find(|entry| {
                entry
                    .as_table()
                    .and_then(|table| table.get("id"))
                    .and_then(Value::as_integer)
                    .map(|id| id == section_id as i64)
                    .unwrap_or(false)
            })
            .ok_or(format!(
                "Section {} with ID {} not found",
                section_type, section_id
            ))?;

        let target_table = target_section
            .as_table_mut()
            .ok_or("Section entry is not a table".to_string())?;

        for param_part in &parts[1..] {
            let param_kv: Vec<&str> = param_part.split(':').collect();
            if param_kv.len() != 2 {
                return Err(format!("Invalid parameter format in: {}", param_part));
            }

            let param_name = param_kv[0];
            let param_value_str = param_kv[1];

            let param_value = if let Ok(int_val) = param_value_str.parse::<i64>() {
                toml::Value::Integer(int_val)
            } else if let Ok(float_val) = param_value_str.parse::<f64>() {
                toml::Value::Float(float_val)
            } else if let Ok(bool_val) = param_value_str.parse::<bool>() {
                toml::Value::Boolean(bool_val)
            } else {
                toml::Value::String(param_value_str.to_string())
            };

            target_table.insert(param_name.to_string(), param_value);
        }
    }

    toml::to_string_pretty(&toml_value).map_err(|e| format!("Failed to serialize TOML: {}", e))
}

#[cfg(feature = "trace-tests")]
#[allow(dead_code)]
mod common;

#[test_log::test]
fn full_trace_compare() {
    // Load the EARLY_TEST_TRACE file
    const EARLY_TRACE: &str = include_str!("EARLY_TEST_TRACE.log");

    // Use the same network configuration as the bench
    let (topology, mut link_state) =
        load_topology_from_file("tests/cfg/maybenot_test.toml").unwrap();

    // Parse the trace with the same parameters as the bench
    let trafserv_to_client_delay = Duration::from_millis(20);
    let (si, mut sq) = parse_trace(EARLY_TRACE, &topology, trafserv_to_client_delay).unwrap();

    // 30097 gives 10000 client events, with basic toml to be used in benching to get comparable times
    //let output_trace = sim(&[], &[], &mut input_trace, &mut sim_network, 30097, true);
    // 56829 gives 10000 client events, with basic toml to be used in benching to get comparable times
    //let output_trace = sim(&[], &[], &mut input_trace, &mut sim_network, 56829, true);

    let output_trace = sim(
        &[],
        &[],
        &topology,
        &mut link_state,
        &si,
        &mut sq,
        50000,
        true,
    );
    // print length of output trace
    println!("Output trace length: {}", output_trace.len());

    // Print the first 15 events in output trace for debugging
    println!("First 15 events in output trace:");
    for event in output_trace.iter().take(15) {
        println!("{}", event.display_full(&si, &topology, &link_state));
    }

    // Convert output trace to EARLY_TEST_TRACE format (time,direction) - ignoring size
    let mut formatted_output = Vec::new();

    for event in output_trace.iter().filter(|e| e.node_id == 0) {
        // Client perspective only
        let relative_time = event.time.as_nanos() as i128 - si.time_zero().as_nanos() as i128;
        let direction = match event.event {
            //TriggerEvent::NormalQueued | TriggerEvent::DecoyQueued { .. } | TriggerEvent::PacketSent => "s",
            //TriggerEvent::NormalRecv | TriggerEvent::DecoyRecv | TriggerEvent::PacketRecv => "r",
            TriggerEvent::PacketSent => "s",
            TriggerEvent::PacketRecv => "r",
            _ => continue, // Skip other event types
        };
        // Only compare time and direction, ignore packet size
        formatted_output.push(format!("{},{}", relative_time, direction));
    }

    // Parse the expected trace and extract only time and direction
    let expected_lines: Vec<String> = EARLY_TRACE
        .trim()
        .lines()
        .map(|line| {
            let parts: Vec<&str> = line.trim().split(',').collect();
            if parts.len() >= 2 {
                format!("{},{}", parts[0], parts[1]) // Only time and direction
            } else {
                line.trim().to_string()
            }
        })
        .collect();

    // Compare line by line
    println!(
        "Comparing {} expected lines with {} output lines",
        expected_lines.len(),
        formatted_output.len()
    );

    let max_lines = std::cmp::min(expected_lines.len(), formatted_output.len());
    let mut differences = 0;

    for i in 0..max_lines {
        let expected = &expected_lines[i];
        let actual = &formatted_output[i];

        if expected != actual {
            differences += 1;
            if differences <= 10 {
                // Only show first 10 differences
                println!("Line {}: Expected '{}', Got '{}'", i + 1, expected, actual);
            }
        }
    }

    if expected_lines.len() != formatted_output.len() {
        println!(
            "Length mismatch: Expected {} lines, got {}",
            expected_lines.len(),
            formatted_output.len()
        );
    }

    if differences == 0 && expected_lines.len() == formatted_output.len() {
        println!("✓ All lines match perfectly!");
    } else {
        println!(
            "✗ Found {} differences out of {} lines",
            differences, max_lines
        );
    }

    // For debugging, print first few lines of each
    println!("\nFirst 5 expected lines (time,direction only):");
    for (i, line) in expected_lines.iter().take(5).enumerate() {
        println!("  {}: {}", i + 1, line);
    }

    println!("\nFirst 5 output lines (time,direction only):");
    for (i, line) in formatted_output.iter().take(5).enumerate() {
        println!("  {}: {}", i + 1, line);
    }
}

#[test_log::test]
fn simulator_example_use() {
    // Example trace: first ten packets from the client's perspective when
    // visiting google.com. Format is "time_ns,direction\n" where direction is
    // "s" (sent) or "r" (received).
    let raw_trace = "0,s
    19714282,r
    183976147,s
    243699564,r
    1696037773,s
    2047985926,s
    2055955094,r
    9401039609,s
    9401094589,s
    9420892765,r";

    // Network topology the simulator runs on: a VPN (client ↔ relay ↔
    // endpoint) with a custom 100 Mbps / 30 ms RTT client↔relay link.
    let (topology, mut link_state) = Setting::VpnCustom {
        mbps: 100,
        rtt: Duration::from_millis(30),
    }
    .create()
    .unwrap();

    // Parse the raw trace into a queue of simulator events. `one_way_delay` is
    // used to back out when endpoint-side sends must have happened so the
    // client observes packets at the same times as in the raw trace.
    let one_way_delay = Duration::from_millis(20);
    let (si, mut sq) = parse_trace(raw_trace, &topology, one_way_delay).unwrap();

    // A simple machine that sends one decoy packet 20 ms after the first
    // normal packet is sent.
    let m = "03eNp9ybERACAIxdB8F8PRLN3PRRzBk4IKeF0uMHCSYBnhd26fSe9auR7NIQOR";
    let m = Machine::from_str(m).unwrap();

    // Run the simulator with the machine at the client, stopping after 100
    // recorded packets (across both client and server).
    let trace = sim(
        &[m],
        &[],
        &topology,
        &mut link_state,
        &si,
        &mut sq,
        100,
        true,
    );

    // Print client-side packet events in trace-relative milliseconds.
    let t0 = si.time_zero();
    for event in trace.iter().filter(|e| e.node_id == 0) {
        let ms = (event.time - t0).as_millis();
        match event.event {
            TriggerEvent::PacketSent => {
                if event.contains_decoy {
                    println!("sent a decoy packet at {} ms", ms);
                } else {
                    println!("sent a normal packet at {} ms", ms);
                }
            }
            TriggerEvent::PacketRecv => {
                if event.contains_decoy {
                    println!("received a decoy packet at {} ms", ms);
                } else {
                    println!("received a normal packet at {} ms", ms);
                }
            }
            _ => {}
        }
    }

    // Output:
    // sent a normal packet at 0 ms
    // received a normal packet at 19 ms
    // sent a decoy packet at 20 ms
    // sent a normal packet at 184 ms
    // received a normal packet at 244 ms
    // sent a normal packet at 1696 ms
    // sent a normal packet at 2048 ms
    // received a normal packet at 2056 ms
    // sent a normal packet at 9401 ms
    // sent a normal packet at 9401 ms
    // received a normal packet at 9421 ms
}

#[cfg(feature = "trace-tests")]
use std::time::Instant;

#[cfg(feature = "trace-tests")]
//const SIM_EVENT_COUNTS: [usize; 3] = [5_000, 10_000, 20_000];
const SIM_EVENT_COUNTS: [usize; 1] = [10_000];
#[cfg(feature = "trace-tests")]
const CONFIG_FILES: [&str; 3] = [
    "/tests/cfg/maybenot_baseline_test.toml",
    "/tests/cfg/maybenot_fast_test.toml",
    "/tests/cfg/maybenot_complex_test.toml",
];
#[cfg(feature = "trace-tests")]
//HiTraceTput takes very long to load, so not included by default.
const LINK_TYPES: [(&str, &str, &str); 2] = [
    (
        "FixedTput",
        "Link:0::type:FixedTput::tput_bps:100000000",
        "",
    ),
    //("HiTraceTput", "Link:0::type:HiTraceTput::trace_file:tests/data/ether100M_synth40M.ltbin.gz", "/tests/data/ether100M_synth40M.ltbin.gz"),
    (
        "StdTraceTput",
        "Link:0::type:StdTraceTput::trace_file:tests/data/ether100M_synth10K_std.ltbin.gz",
        "/tests/data/ether100M_synth10K_std.ltbin.gz",
    ),
];

#[test_log::test]
#[cfg(feature = "trace-tests")]
fn v3_multi_run_like() {
    common::setup_traces();
    const EARLY_TRACE: &str = include_str!("EARLY_TEST_TRACE.log");

    let toml_path = env!("CARGO_MANIFEST_DIR").to_string();

    for sim_event_count in SIM_EVENT_COUNTS.iter() {
        for (link_name, toml_edit_string, _pattern_file_path) in LINK_TYPES.iter() {
            for config_file in CONFIG_FILES.iter() {
                let config_path = toml_path.clone() + config_file;
                let config_name = config_file.split('_').nth(1).unwrap();

                println!("Running simulation with config: {}", config_path);
                // Read TOML file content
                let toml_content = fs::read_to_string(&config_path).unwrap();

                // Modify TOML to change Link 0's type
                let modified_toml = modify_toml(&toml_content, toml_edit_string).unwrap();

                // Use load_topology_from_str instead of load_topology_from_file
                let (topology, link_state) = load_topology_from_str(&modified_toml).unwrap();
                let trafserv_to_client_delay = Duration::from_millis(20);
                let (si, sq) =
                    parse_trace(EARLY_TRACE, &topology, trafserv_to_client_delay).unwrap();
                let mut output_len = 0;
                let bench_name = format!(
                    "v3_{:?}K_{}_{},",
                    sim_event_count / 1000,
                    config_name,
                    link_name
                );
                //c.bench_function(bench_name.as_str(), |b| {
                //b.iter(|| {

                let start = Instant::now();
                // Can use 1000 when running test with --release
                //for _ in 0..1000 {
                for _ in 0..2 {
                    let mut args = SimulatorArgs::new(*sim_event_count, true);
                    args.only_client_events = true;
                    args.stop_after_all_normal_packets = true;
                    let trace = sim_advanced(
                        &[],
                        &[],
                        &topology,
                        &mut link_state.clone(),
                        &si,
                        &mut sq.clone(),
                        &args,
                    );
                    //let trace = simul_advanced(&[ratio3_machine()], &[], &topology, &mut link_state.clone(), &si, &mut sq.clone(), &args);

                    output_len = trace.len();
                    print!("x");
                }
                //});
                //});
                let duration = start.elapsed();
                println!(
                    "\n{}   Loop took {:.3} seconds",
                    bench_name,
                    duration.as_secs_f64()
                );
                println!("Length of output trace: {}", output_len);
            }
        }
    }
}

use enum_map::enum_map;
use maybenot::{
    action::Action,
    constants::MAX_SAMPLED_DELAY_DURATION,
    dist::{Dist, DistType},
    event::Event,
    state::{State, Trans},
};

fn _ratio3_machine() -> Machine {
    let n = 3;
    let mut states = vec![];

    // start state 0
    let start_state = State::new(enum_map! {
       Event::PacketSent | Event::PacketRecv => vec![Trans(1, 1.0)],
       _ => vec![],
    });
    states.push(start_state);

    // delay state 1
    let mut delay_state = State::new(enum_map! {
        Event::DelayBegin => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    delay_state.action = Some(Action::DelayTraffic {
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
            start: MAX_SAMPLED_DELAY_DURATION,
            max: 0.0,
        },
        n: Dist {
            dist: DistType::Uniform {
                low: 1.0,
                high: 1.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    states.push(delay_state);

    // recv states 2..n+2
    for i in 0..n {
        states.push(State::new(enum_map! {
           // to the next state
           Event::PacketRecv => vec![Trans(3+i, 1.0)],
           // something else let traffic through, back to counting
           //Event::PacketSent => vec![Trans(2, 1.0)],
           _ => vec![],
        }));
    }

    // decoy state n+2
    let mut decoy_state = State::new(enum_map! {
        Event::DecoyQueued => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    decoy_state.action = Some(Action::DecoyTraffic {
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
                low: 1.0,
                high: 1.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    states.push(decoy_state);

    Machine::new(u64::MAX, u64::MAX, states).unwrap()
}

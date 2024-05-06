use enum_map::enum_map;
use maybenot::{
    action::Action,
    dist::{Dist, DistType},
    event::Event,
    state::{State, Trans},
    Machine, TriggerEvent,
};
use maybenot_simulator::{network::Network, parse_trace, sim};
use std::{str::FromStr, time::Duration};

#[test_log::test]
fn simple_machine_for_example() {
    let s0 = State::new(enum_map! {
        Event::NormalSent => vec![Trans(1, 1.0)],
        _ => vec![],
    });
    let mut s1 = State::new(enum_map! {
        _ => vec![],
    });
    s1.action = Some(Action::SendPadding {
        bypass: false,
        replace: false,
        timeout: Dist {
            dist: DistType::Uniform {
                low: 0.0,
                high: 0.0,
            },
            start: 20.0 * 1000.0,
            max: 0.0,
        },
        limit: None,
    });
    let m = Machine::new(0, 0.0, 0, 0.0, vec![s0, s1]).unwrap();
    assert_eq!(
        m.serialize(),
        "02eNptibEJAAAIw1of09Mc/c+HRMFFzFBoAlxkliTgurLfT6T9oQBWJgJi"
    );
}

#[test_log::test]
fn simulator_example_use() {
    // The first ten packets of a network trace from the client's perspective
    // when visiting google.com. The format is: "time,direction\n". The
    // direction is either "s" (sent) or "r" (received). The time is in
    // nanoseconds since the start of the trace.
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

    // The network model for simulating the network between the client and the
    // server. Currently just a delay.
    let network = Network::new(Duration::from_millis(10));

    // Parse the raw trace into a queue of events for the simulator. This uses
    // the delay to generate a queue of events at the client and server in such
    // a way that the client is ensured to get the packets in the same order and
    // at the same time as in the raw trace.
    let mut input_trace = parse_trace(raw_trace, &network);

    // A simple machine that sends one padding packet 20 milliseconds after the
    // first normal packet is sent.
    let m = "02eNptibEJAAAIw1of09Mc/c+HRMFFzFBoAlxkliTgurLfT6T9oQBWJgJi";
    let m = Machine::from_str(m).unwrap();

    // Run the simulator with the machine at the client. Run the simulation up
    // until 100 packets have been recorded (total, client and server).
    let trace = sim(&[m], &[], &mut input_trace, network.delay, 100, true);

    // print packets from the client's perspective
    let starting_time = trace[0].time;
    trace
        .into_iter()
        .filter(|p| p.client)
        .for_each(|p| match p.event {
            TriggerEvent::TunnelSent => {
                if p.contains_padding {
                    println!(
                        "sent a padding packet at {} ms",
                        (p.time - starting_time).as_millis()
                    );
                } else {
                    println!(
                        "sent a normal packet at {} ms",
                        (p.time - starting_time).as_millis()
                    );
                }
            }
            TriggerEvent::TunnelRecv => {
                if p.contains_padding {
                    println!(
                        "received a padding packet at {} ms",
                        (p.time - starting_time).as_millis()
                    );
                } else {
                    println!(
                        "received a normal packet at {} ms",
                        (p.time - starting_time).as_millis()
                    );
                }
            }
            _ => {}
        });

    // Output:
    // sent a normal packet at 0 ms
    // received a normal packet at 19 ms
    // sent a padding packet at 20 ms
    // sent a normal packet at 183 ms
    // received a normal packet at 243 ms
    // sent a normal packet at 1696 ms
    // sent a normal packet at 2047 ms
    // received a normal packet at 2055 ms
    // sent a normal packet at 9401 ms
    // sent a normal packet at 9401 ms
    // received a normal packet at 9420 ms
}

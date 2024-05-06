use maybenot::{framework::TriggerEvent, machine::Machine};
use maybenot_simulator::{network::Network, parse_trace, sim};
use std::{str::FromStr, time::Duration};

#[test_log::test]
fn simulator_example_use() {
    // A trace of ten packets from the client's perspective when visiting
    // google.com over WireGuard. The format is: "time,direction,size\n". The
    // direction is either "s" (sent) or "r" (received). The time is in
    // nanoseconds since the start of the trace. The size is in bytes.
    let raw_trace = "0,s,52
    19714282,r,52
    183976147,s,52
    243699564,r,52
    1696037773,s,40
    2047985926,s,52
    2055955094,r,52
    9401039609,s,73
    9401094589,s,73
    9420892765,r,191";

    // The network model for simulating the network between the client and the
    // server. Currently just a delay.
    let network = Network::new(Duration::from_millis(10));

    // Parse the raw trace into a queue of events for the simulator. This uses
    // the delay to generate a queue of events at the client and server in such
    // a way that the client is ensured to get the packets in the same order and
    // at the same time as in the raw trace.
    let mut input_trace = parse_trace(raw_trace, &network);

    // A simple machine that sends one padding packet of 1000 bytes 20
    // milliseconds after the first NonPaddingSent is sent.
    let m = "789cedcfc10900200805506d82b6688c1caf5bc3b54823f4a1a2a453b7021ff8ff49\
    41261f685323426187f8d3f9cceb18039205b9facab8914adf9d6d9406142f07f0";
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
            TriggerEvent::NonPaddingSent { bytes_sent } => {
                println!(
                    "sent {} bytes at {} ms",
                    bytes_sent,
                    (p.time - starting_time).as_millis()
                );
            }
            TriggerEvent::PaddingSent { bytes_sent, .. } => {
                println!(
                    "sent {} bytes of padding at {} ms",
                    bytes_sent,
                    (p.time - starting_time).as_millis()
                );
            }
            TriggerEvent::NonPaddingRecv { bytes_recv } => {
                println!(
                    "received {} bytes at {} ms",
                    bytes_recv,
                    (p.time - starting_time).as_millis()
                );
            }
            TriggerEvent::PaddingRecv { bytes_recv, .. } => {
                println!(
                    "received {} bytes of padding at {} ms",
                    bytes_recv,
                    (p.time - starting_time).as_millis()
                );
            }
            _ => {}
        });

    // Output:
    // sent 52 bytes at 0 ms
    // received 52 bytes at 19 ms
    // sent 1000 bytes of padding at 20 ms
    // sent 52 bytes at 183 ms
    // received 52 bytes at 243 ms
    // sent 40 bytes at 1696 ms
    // sent 52 bytes at 2047 ms
    // received 52 bytes at 2055 ms
    // sent 73 bytes at 9401 ms
    // sent 73 bytes at 9401 ms
    // received 191 bytes at 9420 ms
}

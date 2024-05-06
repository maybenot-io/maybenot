# The Maybenot Simulator

A simulator for the [Maybenot
framework](https://github.com/maybenot-io/maybenot/).

[![Crates.io][crates-badge]][crates-url]
[![Documentation][docs-badge]][docs-url]
[![Build Status][tests-badge]][tests-url]
[![MIT OR Apache-2.0][license-badge]][license-url]

[crates-badge]: https://img.shields.io/crates/v/maybenot-simulator.svg
[crates-url]: https://crates.io/crates/maybenot-simulator
[docs-badge]: https://docs.rs/maybenot-simulator/badge.svg
[docs-url]: https://docs.rs/maybenot-simulator
[tests-badge]: https://github.com/maybenot-io/maybenot-simulator/actions/workflows/tests.yml/badge.svg
[tests-url]: https://github.com/maybenot-io/maybenot-simulator/actions
[license-badge]: https://img.shields.io/crates/l/maybenot-simulator
[license-url]: https://github.com/maybenot-io/maybenot-simulator/

## Example Usage
See [cargo docs][docs-url] for details on the API. The following is a simple
example of how to use the simulator:

```rust
use maybenot::{event::TriggerEvent, machine::Machine};
use maybenot_simulator::{network::Network, parse_trace, sim};
use std::{str::FromStr, time::Duration};

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
```

Produces the following output:

```
sent a normal packet at 0 ms
received a normal packet at 19 ms
sent a padding packet at 20 ms
sent a normal packet at 183 ms
received a normal packet at 243 ms
sent a normal packet at 1696 ms
sent a normal packet at 2047 ms
received a normal packet at 2055 ms
sent a normal packet at 9401 ms
sent a normal packet at 9401 ms
received a normal packet at 9420 ms
```

## Key Limitations
This is a prototype simulator, and as such, it has a number of limitations. For
one, it is a simulator! We are simulating the integration with the
application/destination using the framework and the network between the client
and server. We have a *sim2real* problem.

In terms of networking, the relevant code for the simulator is in
`src/network.rs`. It is very crude: we use a fixed static delay. This should be
improved and evaluated against real-world network experiments. The goal of the
simulator is not necessarily to be a perfect simulator, but a useful simulator
for making different kinds of traffic analysis defenses.

There are also fundamental issues with simulating blocking actions of machines.
Because the simulator takes as input a base network trace of encrypted network
traffic, we do not know any semantics or inter-dependencies between the packets
in the encrypted trace. As a result, we cannot properly simulate blocking
actions. For example, if a machine blocks a packet, we cannot know if the
blocked packet contains a request for a resource that leads to a response
contained in the following received packets. The simulator will happily still
receive the resource in the encrypted network trace. Here be dragons.

## Rich Debug Output
The simulator can be run with the `RUST_LOG=debug` environment variable set to
get rich debug output. For example, to run the integration test
`test_bypass_machine` with debug output, run the following command:

```
RUST_LOG=debug cargo test test_bypass_machine
```

## Contributing
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as MIT or Apache-2.0, without any additional terms or conditions.

## Sponsorship
Made possible with support from [Mullvad VPN](https://mullvad.net/), the
[Swedish Internet Foundation](https://internetstiftelsen.se/en/), and the
[Knowledge Foundation of Sweden](https://www.kks.se/en/start-en/).

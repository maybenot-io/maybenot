# The Maybenot Simulator v3

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
[tests-badge]: https://github.com/maybenot-io/maybenot/actions/workflows/build-and-test.yml/badge.svg
[tests-url]: https://github.com/maybenot-io/maybenot-simulator/actions
[license-badge]: https://img.shields.io/crates/l/maybenot-simulator
[license-url]: https://github.com/maybenot-io/maybenot-simulator/

## Example Usage

See [cargo docs][docs-url] for details on the API. The following is a simple
example of how to use the simulator:

```rust
use maybenot::{Machine, TriggerEvent};
use maybenot_simulator::{parse_trace, settings::Setting, sim};
use std::{str::FromStr, time::Duration};

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

// Parse the raw trace into a queue of simulator events. `one_way_delay`
// is used to back out when endpoint-side sends must have happened so the
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
```

Produces the following output:

```bash
sent a normal packet at 0 ms
received a normal packet at 19 ms
sent a decoy packet at 20 ms
sent a normal packet at 184 ms
received a normal packet at 244 ms
sent a normal packet at 1696 ms
sent a normal packet at 2048 ms
received a normal packet at 2056 ms
sent a normal packet at 9401 ms
sent a normal packet at 9401 ms
received a normal packet at 9421 ms
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

There are also fundamental issues with simulating delaying actions of machines.
Because the simulator takes as input a base network trace of encrypted network
traffic, we do not know any semantics or inter-dependencies between the packets
in the encrypted trace. As a result, we cannot properly simulate delaying
actions. For example, if a machine blocks a packet, we cannot know if the
blocked packet contains a request for a resource that leads to a response
contained in the following received packets. The simulator will happily still
receive the resource in the encrypted network trace. Here be dragons.

## Rich Debug Output

The simulator can be run with the `RUST_LOG=debug` environment variable set to
get rich debug output. For example, to run the integration test
`test_bypass_machine` with debug output, run the following command:

```bash
RUST_LOG=debug cargo test test_bypass_machine
```

## Testing

The test suite includes both fast unit tests and slower integration tests that require
large generated trace files (up to 106MB compressed).

### Running Tests

```bash
# Run fast tests only (default, excludes trace-dependent tests)
cargo test

# Run all tests including trace-dependent ones
cargo test-all
# or equivalently: cargo test --features trace-tests

# Run only trace-dependent tests
cargo test-traces
```

### Generating Test Traces

Tests requiring trace files are gated behind the `trace-tests` feature flag. When you
first run these tests, the required trace files will be automatically generated using
the `xtask-linktrace` tool.

## Contributing

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as MIT or Apache-2.0, without any additional terms or conditions.

## Sponsorship

Made possible with support from [Mullvad VPN](https://mullvad.net/), the
[Swedish Internet Foundation](https://internetstiftelsen.se/en/), and the
[Knowledge Foundation of Sweden](https://www.kks.se/en/start-en/).

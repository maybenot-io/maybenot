# Maybenot 🤔

Maybenot is a framework for traffic analysis defenses that hide patterns in
encrypted communication. Its goal is to increase the uncertainty of network
attackers, hence its logo 🤔 - the thinking face emoji (U+1F914).

[![Crates.io][crates-badge]][crates-url]
[![Documentation][docs-badge]][docs-url]
[![Build Status][tests-badge]][tests-url]
[![MIT OR Apache-2.0][license-badge]][license-url]

[crates-badge]: https://img.shields.io/crates/v/maybenot.svg
[crates-url]: https://crates.io/crates/maybenot
[docs-badge]: https://docs.rs/maybenot/badge.svg
[docs-url]: https://docs.rs/maybenot
[tests-badge]: https://github.com/maybenot-io/maybenot/actions/workflows/build-and-test.yml/badge.svg
[tests-url]: https://github.com/maybenot-io/maybenot/actions
[license-badge]: https://img.shields.io/crates/l/maybenot
[license-url]: https://github.com/maybenot-io/maybenot/

Consider encrypted communication protocols such as QUIC, TLS,  Tor, and
WireGuard. While the connections are encrypted, *patterns* in the encrypted
communication may still leak information about the communicated plaintext.
Maybenot is a framework for creating defenses that hide such patterns.

To simulate defenses based on Maybenot, see the [Maybenot
simulator](https://github.com/maybenot-io/maybenot/tree/main/crates/maybenot-simulator/).

## Design

An instance of Maybenot repeatedly takes as *input* one or more *events*
describing the encrypted traffic going over an encrypted channel. It produces as
*output* zero or more *scheduled actions*, such as to send *padding* traffic or
to *block* outgoing traffic. One or more *state machines* determine what actions
to take based on events. State machines have a lightweight runtime and are
subject to *limits* on the amount of padding and blocking they can schedule.

<p align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/maybenot-io/maybenot/main/crates/maybenot/overview-dark.svg">
  <img alt="design overview" src="https://raw.githubusercontent.com/maybenot-io/maybenot/main/crates/maybenot/overview-light.svg">
</picture>
</p>

Integration with an encrypted communication protocol is done by reporting events
and executing scheduled actions. Maybenot does not specify the specific async
runtime or how to keep time for ease of integration.

## Example usage

```rust,no_run
use crate::{Framework, Machine, TriggerAction, TriggerEvent};
use std::{str::FromStr, time::Instant};

// deserialize a machine, this is a "no-op" machine that does nothing
let s = "02eNpjYEAHjOgCAAA0AAI=";
let m = vec![Machine::from_str(s).unwrap()];

// create framework instance
let mut f = Framework::new(&m, 0.0, 0.0, Instant::now(), rand::thread_rng()).unwrap();

loop {
    // collect one or more events
    let events = [TriggerEvent::NormalSent];

    // trigger events, schedule actions, at most one per machine
    for action in f.trigger_events(&events, Instant::now()) {
        match action {
            TriggerAction::Cancel { 
                machine: MachineId,
                timer: Timer,
            } => {
                // cancel the specified timer (action, machine, or both) for the
                // machine in question, if any
            }
            TriggerAction::SendPadding {
                timeout: Duration,
                bypass: bool,
                replace: bool,
                machine: MachineId,
            } => {
                // schedule padding to be sent after timeout
            }
            TriggerAction::BlockOutgoing {
                timeout: Duration,
                duration: Duration,
                bypass: bool,
                replace: bool,
                machine: MachineId,
            } => {
                // block outgoing traffic for the specified duration after timeout
            }
            TriggerAction::UpdateTimer {
                duration: Duration,
                replace: bool,
                machine: MachineId,
            } => {
                // update the internal timer for the machine in question
            }
        }
    }
}
 ```

## More details

See the [WPES 2023 paper](https://doi.org/10.1145/3603216.3624953) and
[documentation](https://docs.rs/maybenot/latest/maybenot) for further details on
the framework.

The current version of the framework includes a number of improvements over v1,
some of which are discussed in the paper. Refer to the [arXiv design
document](https://arxiv.org/abs/2304.09510) for an in-depth explanation of the
new capabilities (soon updated to v2).

Development of defenses using Maybenot is under active development. For some
early results, see
[https://github.com/ewitwer/maybenot-defenses](https://github.com/ewitwer/maybenot-defenses).

## Contributing

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as MIT or Apache-2.0, without any additional terms or conditions.

## Origin

Maybenot is based on the [Circuit Padding Framework of
Tor](https://gitweb.torproject.org/tor.git/plain/doc/HACKING/CircuitPaddingDevelopment.md)
by Perry and Kadianakis from 2019, which is a generalization of the [WTF-PAD
Website Fingerprinting Defense](https://arxiv.org/pdf/1512.00524.pdf) design by
Juarez et al. from 2016, which in turn is based on the concept of [Adaptive
Padding](https://www.cs.utexas.edu/~shmat/shmat_esorics06.pdf) by Shmatikov and
Wang from 2006.

## Sponsorship

Made possible with support from [Mullvad VPN](https://mullvad.net/), the
[Swedish Internet Foundation](https://internetstiftelsen.se/en/), and the
[Knowledge Foundation of Sweden](https://www.kks.se/en/start-en/).

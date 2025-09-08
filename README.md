# Maybenot

Maybenot is a framework for traffic analysis defenses that hide patterns in
encrypted communication. Its goal is to increase the uncertainty of network
attackers, hence its logo 🤔 - the thinking face emoji (U+1F914).

Consider encrypted communication protocols such as TLS, QUIC, WireGuard, or Tor.
While the connections are encrypted, *patterns* in the encrypted communication
may still leak information about the communicated plaintext. Maybenot is a
framework for running defenses that hide such patterns.

## Workspace structure

The Maybenot workspace consists of the following crates:

- [maybenot](crates/maybenot): The core framework for running defenses.
- [maybenot-ffi](crates/maybenot-ffi): A wrapper library around maybenot with a
  C FFI.
- [maybenot-simulator](crates/maybenot-simulator): A simulator for testing
  defenses.
- [maybenot-machines](crates/maybenot-machines): A library of maybenot machines
  for defenses.
- [maybenot-gen](crates/maybenot-gen): A library for generating maybenot defenses.
- [maybenot-cli](crates/maybenot-cli): A binary CLI for creating maybenot
  defenses.

## The big picture

The `maybenot` framework is integrated with some encrypted protocol, either
directly or using something like `maybenot-ffi`. State machines are run within
the framework, triggering cover traffic and delays to hide patterns. Machines
can be rapidly evaluated using `maybenot-sim`. We have implemented a bunch of
machines by hand, available in `maybenot-machines`. Many are based on related
work in the [academic literature around website
fingerprinting](https://www-users.cse.umn.edu/~hoppernj/sok_wf_def_sp23.pdf). It
is also possible to generate (many) machines using `maybenot-gen`, either used
directly as a library, or using a binary CLI like `maybenot-cli`.

## Further details

See the README-files of each respective crate and their
[docs.rs](https://docs.rs/maybenot/latest/maybenot).

Papers related to Maybenot:

- Defense generation a [PETS 2026 (camera-ready available during fall)](FIXME).
- Version 2 of the framework on [arXiv](https://arxiv.org/abs/2304.09510).
- Version 1 of the framework at [WPES
  2023](https://doi.org/10.1145/3603216.3624953).

Maybenot is used by [Mullvad VPN](https://mullvad.net) in
[DAITA](https://mullvad.net/en/vpn/daita). [Their WireGuard Go
integration](https://github.com/mullvad/wireguard-go/).

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

# Maybenot
Maybenot is a framework for traffic analysis defenses that hide patterns in
encrypted communication. Its goal is to increase the uncertainty of network
attackers, hence its logo 🤔 - the thinking face emoji (U+1F914).

Consider encrypted communication protocols such as TLS, QUIC, WireGuard, or Tor.
While the connections are encrypted, *patterns* in the encrypted communication
may still leak information about the communicated plaintext. Maybenot is a
framework for creating defenses that hide such patterns.

## Workspace structure
The Maybenot workspace consists of the following crates:
- [maybenot](crates/maybenot): The core framework for creating defenses.
- [maybenot-ffi](crates/maybenot-ffi): A wrapper library around maybenot with a C FFI.
- [maybenot-simulator](crates/maybenot-simulator): A simulator for testing
  defenses.

More crates are in the process of being added to the workspace. This happens in
parallel with the development of v2 of the framework, so sorry if it's a bit
messy for now. We aim for a clean slate once v2 is done.

## More details
See the [paper](https://doi.org/10.1145/3603216.3624953) and
[documentation](https://docs.rs/maybenot/latest/maybenot) for further details on
the framework.

Development of defenses using Maybenot is under active development. For some
early results, see
[https://github.com/ewitwer/maybenot-defenses](https://github.com/ewitwer/maybenot-defenses).

While v1 of the framework and simulator are stable, v2 is slowly shaping up as
we expand the capabilities of the framework. The goal is to keep the framework
as simple as possible, while still being expressive enough to implement a wide
range of defenses.

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
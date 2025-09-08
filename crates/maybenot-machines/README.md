# Maybenot machines

A library of [Maybenot](https://github.com/maybenot-io/maybenot) machines for
traffic analysis defenses.

[![Crates.io][crates-badge]][crates-url]
[![Documentation][docs-badge]][docs-url]
[![Build Status][tests-badge]][tests-url]
[![MIT OR Apache-2.0][license-badge]][license-url]

[crates-badge]: https://img.shields.io/crates/v/maybenot-machines.svg
[crates-url]: https://crates.io/crates/maybenot-machines
[docs-badge]: https://docs.rs/maybenot-machines/badge.svg
[docs-url]: https://docs.rs/maybenot-machines
[tests-badge]: https://github.com/maybenot-io/maybenot/actions/workflows/build-and-test.yml/badge.svg
[tests-url]: https://github.com/maybenot-io/maybenot/actions
[license-badge]: https://img.shields.io/crates/l/maybenot-machines
[license-url]: https://github.com/maybenot-io/maybenot/

Implements:

- Break-Pad by Huang and Du, [Break-Pad: effective padding machines for tor with
break burst
padding](https://cybersecurity.springeropen.com/articles/10.1186/s42400-024-00222-y),
Cybersecurity 2024
- FRONT by Gong and Wang, [Zero-delay Lightweight Defenses against Website
  Fingerprinting](https://www.usenix.org/conference/usenixsecurity20/presentation/gong),
  USENIX Security 2020
- Interspace by Pulls, [Towards Effective and Efficient Padding Machines for
  Tor](https://arxiv.org/abs/2011.13471), arXiv 2020
- NetFlow padding, based on [Tor spec: Connection-level
  padding](https://spec.torproject.org/padding-spec/connection-level-padding.html)
  by the Tor Project
- RegulaTor by Holland and Hopper, [RegulaTor: A Straightforward Website
  Fingerprinting
  Defense](https://petsymposium.org/popets/2022/popets-2022-0049.php), PETS 2022
- Scrambler by Hasselquist et al., [Raising the Bar: Improved Fingerprinting
  Attacks and Defenses for Video Streaming
  Traffic](https://petsymposium.org/popets/2024/popets-2024-0112.php), PETS 2024
- Tamaraw by Cai et al., [A Systematic Approach to Developing and Evaluating
  Website Fingerprinting
  Defenses](https://cypherpunks.ca/~iang/pubs/webfingerprint-ccs14.pdf), CCS
  2014, with a soft stop condition by Gong et al., [WFDefProxy: Real World
  Implementation and Evaluation of Website Fingerprinting
  Defenses](https://ieeexplore.ieee.org/document/10295524), TIFS 2023

## Contributing

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as MIT or Apache-2.0, without any additional terms or conditions.

## Sponsorship

Made possible with support from [Mullvad VPN](https://mullvad.net/), the
[Swedish Internet Foundation](https://internetstiftelsen.se/en/), and the
[Knowledge Foundation of Sweden](https://www.kks.se/en/start-en/).

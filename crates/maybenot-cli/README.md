# Maybenot CLI

A CLI tool for defense generation using
[Maybenot](https://github.com/maybenot-io/maybenot). Provides command-line
utilities for creating, optimizing, and analyzing traffic analysis defenses
using the Maybenot framework.

[![Crates.io][crates-badge]][crates-url]
[![Documentation][docs-badge]][docs-url]
[![Build Status][tests-badge]][tests-url]
[![MIT OR Apache-2.0][license-badge]][license-url]

[crates-badge]: https://img.shields.io/crates/v/maybenot-cli.svg
[crates-url]: https://crates.io/crates/maybenot-cli
[docs-badge]: https://docs.rs/maybenot-cli/badge.svg
[docs-url]: https://docs.rs/maybenot-cli
[tests-badge]: https://github.com/maybenot-io/maybenot/actions/workflows/build-and-test.yml/badge.svg
[tests-url]: https://github.com/maybenot-io/maybenot/actions
[license-badge]: https://img.shields.io/crates/l/maybenot-cli
[license-url]: https://github.com/maybenot-io/maybenot/

```console
A CLI tool for defense generation using Maybenot

Usage: maybenot <COMMAND>

Commands:
  search      Search for defenses based on the provided configuration
  derive      Derive a defense from a seed using the provided configuration
  combo       Combine machines of existing defenses into new defenses
  sim         Simulate defenses on a dataset
  eval        Evaluate defenses on a dataset
  eval-print  Print the results of an evaluation in a human-readable format
  fixed       Create or update defenses by adding fixed static machines
  budget      Update budgets for existing defenses
  release     Create a release JSON with placeholder values
  tune-rng    Tune config by randomly replacing values to search for better defenses
  help        Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version

```

As part of the [Maybenot GitHub
repository](https://github.com/maybenot-io/maybenot), there is an example
configuration in `examples/popets26-eph-padding.toml` based on the ephemeral
padding-only defenses in the "Ephemeral Network-Layer Fingerprinting Defenses"
paper, PETS 2026 (to appear). You will need to edit the path to the extracted
[BigEnough
dataset](https://dart.cse.kau.se/popets-2026.1-ephemeral-defs-paper-artifacts/bigenough-95x10x20-standard-rngsubpages.tar.gz)
by [Mathews et
al.](https://www-users.cse.umn.edu/~hoppernj/sok_wf_def_sp23.pdf), and ensure
that your environment can run `scripts/rf.py` and `scripts/df.py` (also in the
Maybenot repo). The below three commands:

1. Searches for 100 random defenses.
2. Combines the 100 defenses into 19000 defenses to match the number of traces
in BigEnough.
3. Simulated the defenses on the BigEnough dataset and evaluates the results in
   terms of overheads and attack accuracy by the [Deep
   Fingerprinting](https://dl.acm.org/doi/pdf/10.1145/3243734.3243768) and
   [Robust
   Fingerprinting](https://www.usenix.org/conference/usenixsecurity23/presentation/shen-meng)
   attacks.

```console
$ maybenot search -c examples/popets26-eph-padding.toml -o def-100
$ maybenot combo -c examples/popets26-eph-padding.toml -i def-100 -o def-100-h2-19k
$ maybenot sim -c examples/popets26-eph-padding.toml -i def-100-h2-19k -o /mnt/ramdisk/def-100-h2-19k-be -e
```

## Contributing

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as MIT or Apache-2.0, without any additional terms or conditions.

## Sponsorship

Made possible with support from [Mullvad VPN](https://mullvad.net/), the
[Swedish Internet Foundation](https://internetstiftelsen.se/en/), and the
[Knowledge Foundation of Sweden](https://www.kks.se/en/start-en/).

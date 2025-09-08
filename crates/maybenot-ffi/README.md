# Maybenot FFI

This crate contains C FFI bindings for Maybenot, which let's you use Maybenot as
a static library for languages other than Rust. Headers are found at
`maybenot-ffi/maybenot.h` and are auto-generated when compiling using `make`.

[![Crates.io][crates-badge]][crates-url]
[![Documentation][docs-badge]][docs-url]
[![Build Status][tests-badge]][tests-url]
[![MIT OR Apache-2.0][license-badge]][license-url]

[crates-badge]: https://img.shields.io/crates/v/maybenot-ffi.svg
[crates-url]: https://crates.io/crates/maybenot-ffi
[docs-badge]: https://docs.rs/maybenot-ffi/badge.svg
[docs-url]: https://docs.rs/maybenot-ffi
[tests-badge]: https://github.com/maybenot-io/maybenot/actions/workflows/build-and-test.yml/badge.svg
[tests-url]: https://github.com/maybenot-io/maybenot/actions
[license-badge]: https://img.shields.io/crates/l/maybenot-ffi
[license-url]: https://github.com/maybenot-io/maybenot-ffi/

## Building

You need to have [rust](https://rustup.rs/) installed.
`cbindgen` is also required: `cargo install --force cbindgen`
Then just run `make` to build a static library at `maybenot-ffi/libmaybenot.a`.

Arguments to `make`, including default values:
- `DESTINATION=.` - the directory where the output artifacts will be placed.
- `TARGET=` override target architecture; cross-compile.
  Use `rustup target` to list and install targets.
- `PROFILE=release` - override the cargo profile, valid options are `release` and `debug`.
- `CARGO=cargo` - path to cargo.
- `CBINDGEN=cbindgen` - path to cbindgen.
- `CARGO_TARGET_DIR=../../target` - the build directory.

Example:

```
make TARGET=x86_64-unknown-linux-gnu PROFILE=debug
```

In order to link the resulting library to your program, you'll need to explicitly link some
additional dependencies in addition to `-lmaybenot`.
Run the following command to get an up-to-date list of the required flags for your platform:

```
RUSTFLAGS="--print native-static-libs" cargo build
```

## Contributing

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as MIT or Apache-2.0, without any additional terms or conditions.

## Sponsorship

Made possible with support from [Mullvad VPN](https://mullvad.net/), the
[Swedish Internet Foundation](https://internetstiftelsen.se/en/), and the
[Knowledge Foundation of Sweden](https://www.kks.se/en/start-en/).

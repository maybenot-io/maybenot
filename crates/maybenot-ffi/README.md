# Maybenot FFI

This crate contains C FFI bindings for Maybenot, which let's you use Maybenot as a static library
for languages other than Rust. Headers are found at `maybenot-ffi/maybenot.h` and are
auto-generated when compiling.

## Building
You need to have [rust](https://rustup.rs/) installed.
Then just run `make` to build a static library at `maybenot-ffi/libmaybenot.a`.

Arguments to `make`:
- `CARGO` override the `cargo` command
- `TARGET` override target architecture; cross-compile.
- `PROFILE` override the cargo profile, valid options are `release` and `debug`.
- `DESTINATION` change the directory where the output artifacts will be places.

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

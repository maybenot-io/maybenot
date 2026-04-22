# xtask - Maybenot Automation Tasks

This crate contains automation tools for the Maybenot workspace, following the
[xtask pattern](https://github.com/matklad/cargo-xtask) for project-specific
tooling. The `xtask` crate is **not** meant for end users. It contains
development and testing utilities for the Maybenot project.

## Structure

The `xtask` crate supports multiple automation task binaries:

- **`linktrace`** - Network trace generation and management utilities
- _(Future tools can be added here)_

Each binary is located in `src/bin/<name>.rs` and configured in `Cargo.toml`.

To add a new automation task binary:

1. **Create the binary file**: `xtask/src/bin/yourtool.rs`
2. **Add to Cargo.toml**:

   ```toml
   [[bin]]
   name = "yourtool"
   path = "src/bin/yourtool.rs"
   ```

3. **Add cargo alias** in `.cargo/config.toml`:

   ```toml
   xtask-yourtool = "run --package xtask --bin yourtool --"
   ```

4. **Document** in this README below
5. **Use**: `cargo xtask-yourtool <args>`

---

## `linktrace` - Network Trace Utilities

Generates and manages synthetic network link traces for simulator testing.

These traces simulate various network conditions (Ethernet, Starlink, etc.) and
are used by the `maybenot-simulator` test suite. The generated files are large
(up to 106MB compressed) and are not checked into git.

The `linktrace` binary is invoked via the cargo alias defined in
`.cargo/config.toml`:

```bash
cargo xtask-linktrace <command> [options]
```

```bash
cargo xtask-linktrace list-presets
```

Shows available network presets like `hires_ether100M`, `stdres_ether10M`,
`hires_starlink_dl`, etc.

```bash
cargo xtask-linktrace create-synthlinktrace \
    --save-file "trace.tr.gz" \
    --linecount 10000 \
    --preset "hires_ether100M"
```

Generates a synthetic bandwidth trace file (`.tr` or `.tr.gz` format).

```bash
cargo xtask-linktrace create-tracebin-hi \
    --bw-tracefile "trace.tr.gz" \
    --save-file "trace" \
    --sizebins "0,129,1501" \
    --binpktsizes "128,1500"
```

Converts trace to high-resolution binary format (1 microsecond slots) → `trace.ltbin.gz`

```bash
cargo xtask-linktrace create-tracebin-std \
    --bw-tracefile "trace.tr.gz" \
    --save-file "trace"
```

Converts trace to standard-resolution binary format (1 millisecond slots) → `trace.ltbin.gz`

```bash
cargo xtask-linktrace create-tracebundle \
    --tracedirectory "./traces" \
    --bundleinfo "Bundle description or path/to/info.txt" \
    --save-file "bundle.lbbundle.gz"
```

Bundles multiple `.ltbin.gz` files into a single compressed bundle.

```bash
cargo xtask-linktrace trace-info --filename "trace.ltbin.gz"
```

Displays trace metadata (resolution, duration, size bins, etc.)

```bash
cargo xtask-linktrace bundle-info --filename "bundle.lbbundle.gz"
cargo xtask-linktrace list-bundle-traces --filename "bundle.lbbundle.gz"
```

Shows bundle metadata and lists contained traces.

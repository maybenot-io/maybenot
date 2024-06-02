# Changelog

Manually generated changelog, for now. We follow semantic versioning.

## 1.1.2 - 2024-06-02
- Bump `ring` to 0.17 for Windows ARM64 support (thanks Daniel Paoliello).

## 1.1.1 - 2024-04-30
- Added `into_raw()` to MachineId to make Maybenot FFI wrapping easier.

## 1.1.0 - 2024-04-06
- Limits sampled on framework init to allow self-transition to first state.
- Padding is now allowed before any bytes have yet been sent (edge case).
- Fixed possibility for divide-by-zero when calculating padding limits.
- Fixed improper limit calculation when replacing existing blocking.
- Transition probabilities must now sum to 1.0 instead of 1.0005.
- Updates to documentation to fix typos and improve clarity.

## 1.0.1 - 2023-11-24
- README update to render better on crates.io and fixed a typo.

## 1.0.0 - 2023-11-24
- Initial public release of Maybenot.

# Changelog

Manually generated changelog, for now. We follow semantic versioning.

## 2.2.1 - 2025-09-09

- MSRV 1.85 to align with Arti.

## 2.2.0 - 2025-09-08

- Doc improvements focused on integration aspects, thanks Nick Mathewson.
- Set STATE_MAX to 100,000 to prevent resource exhaustion on Machine::from_str
  (was already limited by MAX_DECOMPRESSED_SIZE).
- Remove deprecated v1 Machine parsing feature and dependencies.
- Add overflow protection to counter sampling and packet counters.
- Improve numerical robustness in distribution sampling.
- Update to Rust edition 2024 with comprehensive clippy lint configuration.
- Update all dependencies to rand 0.9 ecosystem and latest versions.
- Add RateLimitedFramework with sliding window rate limiting for action control.
- Use std::time::Duration::div_duration_f64 (available since Rust 1.80).
- Add Framework::all_machines_ended() helper to check if all machines finished.

## 2.1.0 - 2025-02-02

- Bug fix: restricted parameter values for several distributions that caused
  crashes, hangs, or very slow sampling due to issues in the underlying crate.
  This is the reason for the minor version bump; while it is improbable that any
  machines seeing any use won't be valid anymore, it's possible.
- Bug fix: attempting to parse a malformed UTF8 string as a machine resulted in
  a crash. No machines serialized by previous versions of Maybenot are affected.
  Hardening fix.
- Bug fix: remove the use of `Uniform::new()` from `rand_dist` due to an
  underlying `rand` crate bug where specially crafted parameters can cause
  excessive execution time; see [mentions of uniform floats in ongoing rand 0.9
  tasks](https://github.com/rust-random/rand/issues/1165).

## 2.0.1 - 2024-10-24

- Bug fix: actions are now scheduled correctly when a counter is zeroed.
  Previously, a counter being decremented to zero on a state transition would
  result in no action in the absence of further transitions.
- Bug fix: account for two CounterZero transitions out and back into a state
  being state changes (that should not prematurely decrement any set limits).

## 2.0.0 - 2024-09-09

- Substantial refactoring and interface simplification. As an integrator, the
  main integration focus should be triggering one or more `TriggerEvent` with
  `trigger_events()` in an instance of the framework and properly handling the
  returned `TriggerAction` iterator.
- Changed terminology from "non-padding" to "normal" throughout the framework,
  including relevant event names (now `NormalSent` and `NormalRecv` instead of
  `NonPaddingSent` and `NonPaddingRecv`).
- Bytes/MTU are no longer supported in favor of simpler packet counts. As a
  result, the `include_small_packets` flag for machines has been removed.
- Removed the `limit_includes_nonpadding` flag for states.
- Added events for packets just as they enter (`TunnelRecv`) and exit
  (`TunnelSent`) the tunnel, distinguished from Normal/Padding Sent/Recv events
  that relate to the packets' contents. These are useful for more complex
  machines and effectively dealing with blocking actions.
- Added two counters per machine which are updated upon transition to a state if
  its `counter` field is set. A `CounterZero` event is triggered when either of
  a machine's counters is decremented to zero. Counters are internal to the
  framework and are not exposed to the integrator.
- Added a per-machine "internal" timer which can be set using an `UpdateTimer`
  action. These are handled by the integrator (to not impose any particular
  runtime for timers), who triggers the corresponding `TimerBegin` and
  `TimerEnd` events as the timer starts and fire.
- Extended the `Cancel` action that can be used to cancel a pending action timer
  (timeout), the machine's internal timer, or both. The internal pseudo-state
  `STATE_CANCEL` transition is removed.
- Added support for `Event::Signal`, allowing machines to signal between each
  other by transitioning to `STATE_SIGNAL`. Useful for multiple machines that
  need to coordinate their states. This is internal to the framework and is not
  exposed to the integrator.
- Added support for the `SkewNormal` distribution.
- Added an optional `parsing` feature to reconstruct v1 machines, though they
  may behave differently than expected. v1 machines are now deprecated.
- Machines are now serialized exclusively with Serde, and the custom format used
  in v1 has been removed.
- Make it possible to run framework with different time sources. Exposes
  `Instant` and `Duration` traits that can be implemented for any type. Still
  uses `std::time` types by default.
- Random number generation is now handled by the integrator, who must provide
  the framework with a random number generator that implements the `RngCore`
  trait. Allows for testing with a deterministic RNG and for using custom RNGs.

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

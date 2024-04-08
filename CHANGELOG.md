# Changelog

Manually generated changelog, for now. We follow semantic versioning.

## 2.0.0 - TBA
- Substantial refactoring and interface simplification.
- Changed terminology from "non-padding" to "normal" throughout the framework,
  including relevant event names (now NormalSent and NormalRecv instead of
  NonPaddingSent and NonPaddingRecv).
- Bytes/MTU are no longer supported in favor of simpler packet counts. As a
  result, the `include_small_packets` flag for machines has been removed.
- State limits are now always decremented for both normal and padding packets,
  and the `limit_includes_nonpadding` flag for states has been removed.
- Added events for queued packets (NormalQueued and PaddingQueued), which are
  now used for accounting rather than sent packets.
- Added two counters per machine which are updated upon transition to a state
  if its `counter` field is set. A CounterZero event is triggered when either
  of a machine's counters is decremented to zero.
- Added a per-machine "internal" timer which can be set using an UpdateTimer
  action. These are handled by the integrator, who triggers the corresponding
  TimerBegin and TimerEnd events as needed.
- Added a Cancel action which can be used to cancel a pending action
  timer (timeout), the machine's internal timer, or both. The STATE_CANCEL
  transition will now cancel both timers.
- Added support for the SkewNormal distribution.
- Added an optional `fast-sample` feature, which is enabled by default, to
  sample the next state to transition to in O(1) time at the cost of increased
  memory usage.
- Added an optional `parsing` feature to reconstruct v1 machines, though they
  may behave differently than expected. v1 machines are now deprecated.
- Machines are now serialized exclusively with Serde, and the custom format
  used in v1 has been removed.

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

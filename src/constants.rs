//! Global constants for the framework.

/// The highest possible version of a [`Machine`](crate::machine) supported by
/// this framework.
pub const VERSION: u8 = 2;

/// The maximum size of a decompressed encoded [`Machine`](crate::machine) in
/// bytes. Set to 1MB. This is a soft limit and can be increased if necessary.
pub const MAX_DECOMPRESSED_SIZE: usize = 1 << 20;

/// The maximum sampled timeout in a [`State`](crate::state), set to a day in
/// microseconds.
pub const MAX_SAMPLED_TIMEOUT: f64 = 24.0 * 60.0 * 60.0 * 1000.0 * 1000.0;

/// The maximum sampled timer duration in a [`State`](crate::state), set to a
/// day in microseconds.
pub const MAX_SAMPLED_TIMER_DURATION: f64 = 24.0 * 60.0 * 60.0 * 1000.0 * 1000.0;

/// The maximum sampled blocking duration in a [`State`](crate::state), set to a
/// day in microseconds.
pub const MAX_SAMPLED_BLOCK_DURATION: f64 = 24.0 * 60.0 * 60.0 * 1000.0 * 1000.0;

/// The maximum sampled counter value in a [`State`](crate::state), which is
/// currently effectively unlimited in practice.
pub const MAX_SAMPLED_COUNTER_VALUE: u64 = u64::MAX;

/// The maximum possible sampled limit of a [`State`](crate::state). This is the
/// default if no limit dist is specified (in practice, the same as no limit).
pub const STATE_LIMIT_MAX: u64 = u64::MAX;

/// An internal pseudo-state that means that no [`State`](crate::state) defined
/// in a transition: it is used for state transitions as a "no-op" transition
/// for any remaining probability up until 1.0.
pub const STATE_NOP: usize = usize::MAX;
/// A pseudo-state that means the [`Machine`](crate::machine) should completely
/// stop.
pub const STATE_END: usize = STATE_NOP - 1;
/// A pseudo-state that means that we should reset all current pending timers but
/// remain in the current [`State`](crate::state).
pub const STATE_CANCEL: usize = STATE_END - 1;
/// The maximum number of [`State`](crate::state) a [`Machine`](crate::machine)
/// can have.
pub const STATE_MAX: usize = STATE_CANCEL - 1;

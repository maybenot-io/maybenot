//! Global constants for the framework.

/// The highest possible version of a [`Machine`](crate::Machine) supported by
/// this framework.
pub const VERSION: u8 = 2;

/// The maximum size of a decompressed encoded [`Machine`](crate::Machine) in
/// bytes. Set to 1MB. This is a soft limit and can be increased if necessary.
pub const MAX_DECOMPRESSED_SIZE: usize = 1 << 20;

/// The number of [`Event`](crate::event)s in the framework.
pub const EVENT_NUM: usize = 13;

/// The maximum sampled timeout in a [`State`](crate::state), set to a day in
/// microseconds.
pub const MAX_SAMPLED_TIMEOUT: f64 = 24.0 * 60.0 * 60.0 * 1000.0 * 1000.0;

/// The maximum sampled timer duration in a [`State`](crate::state), set to a
/// day in microseconds.
pub const MAX_SAMPLED_TIMER_DURATION: f64 = 24.0 * 60.0 * 60.0 * 1000.0 * 1000.0;

/// The maximum sampled blocking duration in a [`State`](crate::state), set to a
/// day in microseconds.
pub const MAX_SAMPLED_BLOCK_DURATION: f64 = 24.0 * 60.0 * 60.0 * 1000.0 * 1000.0;

/// The maximum possible sampled limit of a [`State`](crate::state). This is the
/// default if no limit dist is specified (in practice, the same as no limit).
pub(crate) const STATE_LIMIT_MAX: u64 = u64::MAX;

/// A pseudo-state that means the [`Machine`](crate::Machine) should completely
/// stop.
pub const STATE_END: usize = u32::MAX as usize;
/// A pseudo-state that triggers a Signal [`Event`](crate::event) in all other
/// running machines.
pub const STATE_SIGNAL: usize = STATE_END - 1;
/// The maximum number of [`State`](crate::state)s a [`Machine`](crate::Machine)
/// can have. Set to 100,000 as a safety measure to prevent resource exhaustion.
/// Likely much higher than `MAX_DECOMPRESSED_SIZE` allows for as-is.
pub const STATE_MAX: usize = 100_000;

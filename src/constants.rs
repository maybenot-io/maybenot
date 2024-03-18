//! Global constants for the framework.

/// The highest possible version of a [`Machine`](crate::machine) supported by
/// this framework.
pub const VERSION: u8 = 2;

/// The maximum sampled timeout in a [`State`](crate::state), set to a day in
/// microseconds.
pub const MAXSAMPLEDTIMEOUT: f64 = 24.0 * 60.0 * 60.0 * 1000.0 * 1000.0;

/// The maximum sampled blocking duration in a [`State`](crate::state), set to
/// one minute in microseconds.
pub const MAXSAMPLEDBLOCK: f64 = 1000.0 * 1000.0 * 60.0;

/// The size (in bytes) of a serialized distribution for a [`State`](crate::state).
pub const SERIALIZEDDISTSIZE: usize = 2 + 8 * 4;

/// The maximum possible sampled limit of a [`State`](crate::state). This is the
/// default if no limit dist is specified (in practice, the same as no limit).
pub const STATELIMITMAX: u64 = u64::MAX;

/// An internal pseudo-state that means that no [`State`](crate::state) defined
/// in a transition: it is used for state transitions as a "no-op" transition
/// for any remaining probability up until 1.0.
pub const STATENOP: usize = usize::MAX;
/// A pseudo-state that means the [`Machine`](crate::machine) should completely
/// stop.
pub const STATEEND: usize = STATENOP - 1;
// A pseudo-state that means that we should cancel our current pending timer but
/// remain in the current [`State`](crate::state).
pub const STATECANCEL: usize = STATEEND - 1;
/// The maximum number of [`States`](crate::state) a [`Machine`](crate::machine)
/// can have.
pub const STATEMAX: usize = STATECANCEL - 1;

/// The number of counters available to each machine. This limits the IDs
/// that can be specified in an UpdateCounter [`Action`](crate::action).
pub const COUNTERSPERMACHINE: usize = 2;

/// The maximum sampled counter value in a [`State`](crate::state), which is
/// currently effectively unlimited in practice.
pub const MAXSAMPLEDCOUNTERVALUE: u64 = u64::MAX;

/// The maximum sampled timer duration in a [`State`](crate::state), set to a
/// day in microseconds.
pub const MAXSAMPLEDTIMERDURATION: f64 = 24.0 * 60.0 * 60.0 * 1000.0 * 1000.0;

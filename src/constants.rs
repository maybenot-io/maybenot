// VERSION specifies the highest possible version of padding machines supported
// by the framework.
pub const VERSION: u8 = 1;

// MAXSAMPLEDTIMEOUT is the maximum sampled timeout, set to a day in
// microseconds.
pub const MAXSAMPLEDTIMEOUT: f64 = 24.0 * 60.0 * 60.0 * 1000.0 * 1000.0;

// MAXSAMPLEDBLOCK is the maximum sampled blocking duration, set to one minute
// in microseconds.
pub const MAXSAMPLEDBLOCK: f64 = 1000.0 * 1000.0 * 60.0;

// SERIALIZEDDISTSIZE is the size (in bytes) of a serialized State.
pub const SERIALIZEDDISTSIZE: usize = 2 + 8 * 4;

// STATELIMITMAX is the maximum possible limit of a state. This is the default
// if no limit dist is specified.
pub const STATELIMITMAX: u64 = u64::MAX;

// STATENOP is an internal pseudo-state that means no state defined: is used for
// state transitions as a "no-op" transition for any remaining probability up
// until 1.0.
pub const STATENOP: usize = u64::MAX as usize;
// STATEEND is a pseudo-state that means the machine should completely stop.
pub const STATEEND: usize = STATENOP - 1;
// STATECANCEL is a pseudo-state that means that we should cancel our current
// pending timer but remain in the current state.
pub const STATECANCEL: usize = STATEEND - 1;
// STATEMAX is the maximum number of states a Machine can have.
pub const STATEMAX: usize = STATECANCEL - 1;

// MAXSMALLPACKETSIZE is the max size of packets considered as a small packet
// (e.g., TCP ACKs, WireGuard keepalive)
pub const MAXSMALLPACKETSIZE: u64 = 52;
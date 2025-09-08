use crate::{MaybenotAction, MaybenotEvent, MaybenotFramework, error::MaybenotResult};
use core::{
    ffi::{CStr, c_char},
    mem::MaybeUninit,
    slice::from_raw_parts_mut,
};
use std::slice::from_raw_parts;

// NOTE: must be null-terminated.
static VERSION: &str = concat!("maybenot-ffi/", env!("CARGO_PKG_VERSION"), "\0");

/// Get the version of maybenot-ffi as a null terminated UTF-8-string.
///
/// Example: `maybenot-ffi/1.0.1`
#[unsafe(no_mangle)]
pub extern "C" fn maybenot_version() -> *const c_char {
    debug_assert_eq!(
        VERSION.find('\0'),
        Some(VERSION.len() - 1),
        "VERSION must be null terminated"
    );

    VERSION.as_ptr().cast()
}

/// Start a new [`MaybenotFramework`] instance.
///
/// # Safety
/// - `machines_str` must be a null-terminated UTF-8 string, containing LF-separated machines.
/// - `out` must be a valid pointer to some valid and aligned pointer-sized memory.
/// - The pointer written to `out` is NOT safe to be used concurrently.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn maybenot_start(
    machines_str: *const c_char,
    max_padding_frac: f64,
    max_blocking_frac: f64,
    out: *mut MaybeUninit<*mut MaybenotFramework>,
) -> MaybenotResult {
    // SAFETY: see function docs
    let Some(out) = (unsafe { out.as_mut() }) else {
        return MaybenotResult::NullPointer;
    };

    // SAFETY: see function docs
    let machines_str = unsafe { CStr::from_ptr(machines_str) };
    let Ok(machines_str) = machines_str.to_str() else {
        return MaybenotResult::MachineStringNotUtf8;
    };

    let framework =
        match MaybenotFramework::start(machines_str, max_padding_frac, max_blocking_frac) {
            Ok(framework) => framework,
            Err(e) => return e,
        };

    // framework MUST be Sync if we are going to hand out references to it over FFI.
    // we can assert this at compile time:
    fn assert_sync(_: &impl Sync) {}
    assert_sync(&framework);

    let box_pointer = Box::into_raw(Box::new(framework));
    out.write(box_pointer);

    MaybenotResult::Ok
}

/// Get the number of machines running in the [`MaybenotFramework`] instance.
///
/// # Safety
/// - `this` must have been created by [`maybenot_start`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn maybenot_num_machines(this: *mut MaybenotFramework) -> usize {
    let Some(this) = (unsafe { this.as_mut() }) else {
        return 0;
    };

    this.framework.num_machines()
}

/// Stop a running [`MaybenotFramework`] instance. This will free the maybenot pointer.
///
/// # Safety
/// - `this` MUST have been created by [`maybenot_start`].
/// - `this` MUST NOT be used after it has been passed to [`maybenot_stop`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn maybenot_stop(this: *mut MaybenotFramework) {
    // Reconstruct the Box<Maybenot> and drop it.
    // SAFETY: caller pinky promises that this pointer was created by `maybenot_start`
    let _this = unsafe { Box::from_raw(this) };
}

/// Feed events to the [`MaybenotFramework`] instance.
///
/// This may generate [super::MaybenotAction]s that will be written to `actions_out`.
/// The number of actions will be written to `num_actions_out`.
///
/// # Safety
/// - `this` MUST have been created by [`maybenot_start`].
/// - `events` MUST be a valid pointer to an array of size `num_events`.
/// - `actions_out` MUST have capacity for [`maybenot_num_machines`] items of size
///   `sizeof(MaybenotAction)` bytes.
/// - `num_actions_out` MUST be a valid pointer where a 64bit int can be written.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn maybenot_on_events(
    this: *mut MaybenotFramework,
    events: *const MaybenotEvent,
    num_events: usize,
    actions_out: *mut MaybeUninit<MaybenotAction>,
    num_actions_out: *mut usize,
) -> MaybenotResult {
    let Some(this) = (unsafe { this.as_mut() }) else {
        return MaybenotResult::NullPointer;
    };

    if events.is_null() || actions_out.is_null() || num_actions_out.is_null() {
        return MaybenotResult::NullPointer;
    }

    // SAFETY: caller promises that `events` points to a valid array containing `num_events` events.
    // Rust arrays have the same layout as C arrays.
    let events: &[MaybenotEvent] = unsafe { from_raw_parts(events, num_events) };

    // SAFETY: called promises that `actions_out` points to valid memory with the capacity to
    // hold at least a `num_machines` amount of `MaybenotAction`. Rust arrays have the same
    // layout as C arrays. Since we use `MaybeUninit`, rust won't assume that the slice
    // elements have been initialized.
    let actions: &mut [MaybeUninit<MaybenotAction>] =
        unsafe { from_raw_parts_mut(actions_out, this.framework.num_machines()) };

    let num_actions = this.on_events(events, actions);
    unsafe { num_actions_out.write(num_actions) };
    MaybenotResult::Ok
}

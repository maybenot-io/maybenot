use crate::{error::MaybenotResult, MaybenotAction, MaybenotEvent, MaybenotFramework};
use core::{
    ffi::{c_char, CStr},
    mem::MaybeUninit,
    slice::from_raw_parts_mut,
};

// NOTE: must be null-terminated.
static VERSION: &str = concat!("maybenot-ffi/", env!("CARGO_PKG_VERSION"), "\0");

/// Get the version of maybenot-ffi as a null terminated UTF-8-string.
///
/// Example: `maybenot-ffi/1.0.1`
#[no_mangle]
pub extern "C" fn maybenot_version() -> *const c_char {
    debug_assert_eq!(
        VERSION.chars().last(),
        Some('\0'),
        "VERSION must be null terminated"
    );

    VERSION.as_ptr().cast()
}

/// Start a new [`MaybenotFramework`] instance.
///
/// # Safety
/// - `machines_str` must be a null-terminated UTF-8 string, containing LF-separated machines.
/// - `out` must be a valid pointer to some valid pointer-sized memory.
#[no_mangle]
pub unsafe extern "C" fn maybenot_start(
    machines_str: *const c_char,
    max_padding_bytes: f64,
    max_blocking_bytes: f64,
    mtu: u16,
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

    MaybenotFramework::start(machines_str, max_padding_bytes, max_blocking_bytes, mtu)
        .map(|maybenot| {
            let box_pointer = Box::into_raw(Box::new(maybenot));
            out.write(box_pointer);
        })
        .into()
}

/// Get the number of machines running in the [`MaybenotFramework`] instance.
///
/// # Safety
///
/// `this` must be a valid pointer to a [`MaybenotFramework`] instance
#[no_mangle]
pub unsafe extern "C" fn maybenot_num_machines(this: *mut MaybenotFramework) -> u64 {
    let Some(this) = (unsafe { this.as_mut() }) else {
        return 0;
    };

    this.framework.num_machines() as u64
}

/// Stop a running [`MaybenotFramework`] instance. This will free the maybenot pointer.
///
/// # Safety
/// The pointer MUST have been created by [maybenot_start].
#[no_mangle]
pub unsafe extern "C" fn maybenot_stop(this: *mut MaybenotFramework) {
    // Reconstruct the Box<Maybenot> and drop it.
    // SAFETY: caller pinky promises that this pointer was created by `maybenot_start`
    let _this = unsafe { Box::from_raw(this) };
}

/// Feed an event to the [`MaybenotFramework`] instance.
///
/// This may generate [super::MaybenotAction]s that will be written to `actions_out`.
///
/// # Safety
/// `actions_out` must have capacity for [maybenot_num_machines] items of size
/// `sizeof(MaybenotAction)` bytes.
///
/// The number of actions will be written to `num_actions_out`.
#[no_mangle]
pub unsafe extern "C" fn maybenot_on_event(
    this: *mut MaybenotFramework,
    event: MaybenotEvent,
    actions_out: *mut MaybeUninit<MaybenotAction>,
    num_actions_out: *mut u64,
) -> MaybenotResult {
    let Some(this) = (unsafe { this.as_mut() }) else {
        return MaybenotResult::NullPointer;
    };

    // SAFETY: called promises that `actions_out` points to valid memory with the capacity to
    // hold at least a `num_machines` amount of `MaybenotAction`. Rust arrays have the same
    // layout as C arrays. Since we use `MaybeUninit`, rust won't assume that the slice
    // elements have been initialized.
    let actions: &mut [MaybeUninit<MaybenotAction>] =
        unsafe { from_raw_parts_mut(actions_out, this.framework.num_machines()) };

    let num_actions = this.on_event(event, actions) as u64;
    unsafe { num_actions_out.write(num_actions) };
    MaybenotResult::Ok
}

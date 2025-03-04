/// An FFI friendly result error code type.
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum MaybenotResult {
    /// Operation completed successfully
    Ok = 0,

    /// The machine string wasn't valid UTF-8
    MachineStringNotUtf8 = 1,

    /// Failed to parse machine string
    InvalidMachineString = 2,

    /// Failed to start framework
    StartFramework = 3,

    /// A null pointer was encountered
    NullPointer = 4,
}

impl<T> From<Result<T, MaybenotResult>> for MaybenotResult {
    fn from(result: Result<T, MaybenotResult>) -> Self {
        result.map(|_| MaybenotResult::Ok).unwrap_or_else(|err| err)
    }
}

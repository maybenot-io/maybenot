use std::fmt;

/// Specific error types Maybenot.
#[derive(Debug, Clone)]
pub enum Error {
    /// Invalid padding limit.
    PaddingLimit,

    /// Invalid blocking limit.
    BlockingLimit,

    /// Invalid machine. The string describes why in detail.
    Machine(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Error::PaddingLimit => write!(f, "max_padding_frac has to be between [0.0, 1.0]"),
            Error::BlockingLimit => write!(f, "max_blocking_frac has to be between [0.0, 1.0]"),
            Error::Machine(ref msg) => write!(f, "invalid machine: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

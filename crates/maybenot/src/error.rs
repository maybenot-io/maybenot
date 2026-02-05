use std::fmt;

/// Specific error types Maybenot.
#[derive(Debug, Clone)]
pub enum Error {
    /// Invalid machine. The string describes why in detail.
    Machine(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Error::Machine(ref msg) => write!(f, "invalid machine: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

use std::fmt;

/// Specific error types Maybenot.
#[derive(Debug, Clone)]
pub enum Error {
    /// Invalid machine. The string describes why in detail.
    Machine(String),
    /// Invalid limit configuration.
    Limit(crate::limit::LimitError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Machine(msg) => write!(f, "invalid machine: {msg}"),
            Error::Limit(e) => write!(f, "invalid limit: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<crate::limit::LimitError> for Error {
    fn from(e: crate::limit::LimitError) -> Self {
        Error::Limit(e)
    }
}

//! Maybenot is a framework for traffic analysis defenses that can be used to
//! hide patterns in encrypted communication.
//!
//! Consider encrypted communication protocols such as TLS, QUIC, WireGuard, or
//! Tor. While the connections are encrypted, *patterns* in the encrypted
//! communication may still leak information about the underlying plaintext
//! being communicated over encrypted. Maybenot is a framework for creating
//! defenses that hide such patterns.
//!
//! If you want to use Maybenot, see [`framework`] for details. As a user, that
//! is typically all that you need and the other modules can be ignored. Note
//! that you create an existing [`machine::Machine`] (for use with the
//! [`framework`]) using the [`core::str::FromStr`] trait.
//!
//! If you want to build machines for the [`framework`], take a look at all the
//! modules. For top-down, start with [`machine`]. For bottom-down, start with
//! [`dist`] and [`event`] before [`state`] and finally [`machine`].
pub mod constants;
pub mod dist;
pub mod event;
pub mod framework;
pub mod machine;
pub mod state;

#[cfg(test)]
mod tests {
    #[test]
    fn constants_set() {
        assert_eq!(crate::constants::VERSION, 1);
    }
}

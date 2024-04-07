//! Maybenot is a framework for traffic analysis defenses that hide patterns in
//! encrypted communication.
//!
//! Consider encrypted communication protocols such as QUIC, TLS, Tor, and
//! WireGuard. While the connections are encrypted, *patterns* in the encrypted
//! communication may still leak information about the underlying plaintext
//! despite being encrypted. Maybenot is a framework for creating and executing
//! defenses that hide such patterns. Defenses are implemented as probabilistic
//! state machines.
//!
//! If you want to use Maybenot, see [`framework`] for details. As a user, that
//! is typically all that you need and the other modules can be ignored. Note
//! that you create an existing [`machine::Machine`] (for use with the
//! [`framework`]) using the [`core::str::FromStr`] trait.
//!
//! If you want to build machines for the [`framework`], take a look at all the
//! modules. For top-down, start with [`machine`]. For bottom-up, start with
//! [`dist`], [`event`], [`action`], and [`counter`] before [`state`] and
//! finally [`machine`].
pub mod action;
pub mod constants;
pub mod counter;
pub mod dist;
pub mod event;
pub mod framework;
pub mod machine;
pub mod state;

#[cfg(feature = "parsing")]
pub mod parsing;

#[cfg(test)]
mod tests {
    #[test]
    fn constants_set() {
        assert_eq!(crate::constants::VERSION, 2);
    }
}

//! Legacy machine string parser for Maybenot.
//!
//! Converts v1 and v2 machine strings into v3 [`Machine`] structs.
//!
//! - **v1**: custom hex-encoded binary format (no version prefix)
//! - **v2**: bincode-serialized structs with old field names, prefixed `"02"`
//! - **v3**: postcard-serialized (current format), prefixed `"03"` — handled by
//!   [`maybenot::Machine`] directly via [`std::str::FromStr`]
//!
//! Use [`parse_legacy`] to auto-detect v1 vs v2, or call [`parse_v1`] /
//! [`parse_v2`] directly.

mod v1;
mod v2;

pub use maybenot::{Error, Machine};
pub use v1::parse_v1;
pub use v2::parse_v2;

/// Parse a legacy machine string, auto-detecting v1 or v2 by prefix.
///
/// Strings starting with `"02"` are treated as v2 (bincode); all others are
/// treated as v1 (hex-encoded binary). Returns an error if parsing or
/// validation fails.
pub fn parse_legacy(s: &str) -> Result<Machine, Error> {
    if s.starts_with("02") {
        parse_v2(s)
    } else {
        parse_v1(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // V1 test strings from the original parsing.rs test suite.
    const V1_MACHINES: &[&str] = &[
        "789cedca2101000000c230e85f1a8387009f9e351d051503ca0003",
        "789cd5cfbb0900200c04d08b833886adb889389f5bb9801be811acb58ae2837ce02010c158b070555c9538b6377a64dbb0ceff242c20b79038507dd169fbede9f629bf6f021efa1b66",
        "789ccdd14b4802411807f0d122d630a80e75e920646a9db2d24bd48c9587b012bc04415d32e856eca107d4210f792809a38804e910f400835ca88387d8961e144920b551aed8b59032cc0e59d16c0f41962510dafa0d0cc3cc77f8bef9cbc0b7e0092f06f131832c076f3f21c0e88d464f4c1b51449d3731df6b432feb0fa1f6e20e841f3fc801e5bd5f3d28efa43d8bbc1a1a5f6692e12589b860c84f62f752fbcd3e14605fb549f6bb6de86e0c1a7a028d88f09575d9a7dad2491120ff6279b0a1ca84ecf551ab6b418502adca267a486bc28f5fb20d4a7cb2db0d32fe34c94067ccda6d64afe1dba926585a782e5a2fb5dcdd9496721e42dfd5e35aed5e04865a0a9a13c3ec9ff62707db89d7b391233d1ae7a35458d219ce3049dd40b40827966d52e24a1c4a0be362a05fcde9923b97d0ecf1fa2b9f39c14f181ceeb914c74273f52cb9143e862b7d1554dd565850f7dfbd03f1ca70ff",
    ];

    #[test]
    fn parse_v1_roundtrip() {
        use std::str::FromStr;
        for s in V1_MACHINES {
            let m = parse_v1(s).expect("parse_v1 failed");
            m.validate().expect("validate failed");
            // Re-serializes as v3
            let serialized = m.serialize();
            assert!(serialized.starts_with("03"), "expected v3 prefix");
            // Roundtrips through v3 deserialization
            let m2 = Machine::from_str(&serialized).expect("v3 from_str failed");
            assert_eq!(m2.serialize(), serialized);
        }
    }

    #[test]
    fn parse_legacy_routes_v1() {
        let m = parse_legacy(V1_MACHINES[0]).expect("parse_legacy v1 failed");
        m.validate().expect("validate failed");
    }
}

use anyhow::Result;
use maybenot_gen::derive::DeriveConfig;
use serde::{Deserialize, Serialize};
use std::fs;
use std::ops::RangeInclusive;
use std::path::Path;

use crate::find::combo::ComboConfig;
use crate::find::search::SearchConfig;
use crate::tweak::eval::EvalConfig;
use crate::tweak::sim::SimConfig;

/// Complete configuration for Maybenot CLI. Parsed to/from TOML. All sections
/// are optional and used by different commands.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub search: Option<SearchConfig>,
    pub derive: Option<DeriveConfig>,
    pub combo: Option<ComboConfig>,
    pub sim: Option<SimConfig>,
    pub eval: Option<EvalConfig>,
}

// a simple loader that reads the config from a file
impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let contents = fs::read_to_string(path)?;
        Ok(toml::from_str(&contents)?)
    }

    #[allow(dead_code)]
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let contents = toml::to_string_pretty(self)?;
        fs::write(path, contents)?;
        Ok(())
    }
}

// Helper to deserialize ranges that can be either [min, max] arrays or { start,
// end } objects. This results in a more readable configuration file (imo).
#[derive(Deserialize)]
#[serde(untagged)]
enum RangeFormat<T> {
    Array([T; 2]),
    Object { start: T, end: T },
}

impl<T> From<RangeFormat<T>> for RangeInclusive<T> {
    fn from(range: RangeFormat<T>) -> Self {
        match range {
            RangeFormat::Array([start, end]) => start..=end,
            RangeFormat::Object { start, end } => start..=end,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_maybenot_config_range_format_parsing() {
        // test basic RangeFormat parsing for both array and object notation
        let array_format = r#"range = [1, 5]"#;
        let object_format = r#"range = { start = 1, end = 5 }"#;

        #[derive(Deserialize)]
        struct TestStruct {
            range: RangeFormat<i32>,
        }

        let array_test: TestStruct = toml::from_str(array_format).unwrap();
        let object_test: TestStruct = toml::from_str(object_format).unwrap();

        let array_inclusive: RangeInclusive<i32> = array_test.range.into();
        let object_inclusive: RangeInclusive<i32> = object_test.range.into();

        assert_eq!(array_inclusive.start(), &1);
        assert_eq!(array_inclusive.end(), &5);
        assert_eq!(object_inclusive.start(), &1);
        assert_eq!(object_inclusive.end(), &5);
    }

    #[test]
    fn test_maybenot_config_derive_with_mixed_range_formats() {
        let toml_config = r#"
[derive]
# Maximum attempts to derive a defense
max_attempts = 1024

# Constraint configuration - test optional ranges and standard fields
[derive.constraints]
client_load = [0.0, 1.0]
server_load = { start = 0.0, end = 0.5 }
delay = [0.0, 0.2]
client_min_normal_packets = 10
server_min_normal_packets = 5
include_after_last_normal = false

# Environment configuration - mix of array and object notation
[derive.env]
traces = ["BigEnough", "TorCircuit"]
num_traces = [1, 3]
sim_steps = { start = 1000, end = 5000 }
implied_framework_limits = true

# Network configuration - test both formats
[derive.env.network]
rtt_in_ms = [10, 100]
packets_per_sec = { start = 100, end = 1000 }

# Machine configuration - test comprehensive settings with mixed formats
[derive.machine]
num_states = { start = 2, end = 10 }
allow_blocking_client = true
allow_blocking_server = false
allow_expressive = true
allow_fixed_budget = false
allow_frac_limits = true
duration_point = [1000.0, 100000.0]
count_point = { start = 10, end = 100 }
min_action_timeout = [0.0, 1000.0]
"#;

        let config: Result<Config, toml::de::Error> = toml::from_str(toml_config);

        match config {
            Ok(parsed_config) => {
                println!("Successfully parsed comprehensive MaybenotConfig: {parsed_config:?}");

                let derive_config = parsed_config.derive.unwrap();

                assert_eq!(derive_config.max_attempts, Some(1024));

                // test constraint ranges - mix of array and object formats
                assert_eq!(
                    derive_config
                        .constraints
                        .client_load
                        .as_ref()
                        .unwrap()
                        .start(),
                    &0.0
                );
                assert_eq!(
                    derive_config
                        .constraints
                        .client_load
                        .as_ref()
                        .unwrap()
                        .end(),
                    &1.0
                );
                assert_eq!(
                    derive_config
                        .constraints
                        .server_load
                        .as_ref()
                        .unwrap()
                        .start(),
                    &0.0
                );
                assert_eq!(
                    derive_config
                        .constraints
                        .server_load
                        .as_ref()
                        .unwrap()
                        .end(),
                    &0.5
                );
                assert_eq!(
                    derive_config.constraints.delay.as_ref().unwrap().start(),
                    &0.0
                );
                assert_eq!(
                    derive_config.constraints.delay.as_ref().unwrap().end(),
                    &0.2
                );
                assert_eq!(
                    derive_config.constraints.client_min_normal_packets,
                    Some(10)
                );
                assert_eq!(derive_config.constraints.server_min_normal_packets, Some(5));
                assert_eq!(
                    derive_config.constraints.include_after_last_normal,
                    Some(false)
                );

                // test environment ranges - mix of array and object formats
                assert_eq!(derive_config.env.num_traces.start(), &1);
                assert_eq!(derive_config.env.num_traces.end(), &3);
                assert_eq!(derive_config.env.sim_steps.start(), &1000);
                assert_eq!(derive_config.env.sim_steps.end(), &5000);
                assert_eq!(derive_config.env.implied_framework_limits, Some(true));

                // test network ranges - both formats
                assert_eq!(derive_config.env.network.rtt_in_ms.start(), &10);
                assert_eq!(derive_config.env.network.rtt_in_ms.end(), &100);
                assert_eq!(
                    derive_config
                        .env
                        .network
                        .packets_per_sec
                        .as_ref()
                        .unwrap()
                        .start(),
                    &100
                );
                assert_eq!(
                    derive_config
                        .env
                        .network
                        .packets_per_sec
                        .as_ref()
                        .unwrap()
                        .end(),
                    &1000
                );

                // test machine configuration with comprehensive range testing
                assert_eq!(derive_config.machine.num_states.start(), &2);
                assert_eq!(derive_config.machine.num_states.end(), &10);
                assert_eq!(derive_config.machine.allow_blocking_client, Some(true));
                assert_eq!(derive_config.machine.allow_blocking_server, Some(false));
                assert_eq!(derive_config.machine.allow_expressive, Some(true));
                assert_eq!(derive_config.machine.allow_fixed_budget, Some(false));
                assert_eq!(derive_config.machine.allow_frac_limits, Some(true));
                assert_eq!(
                    derive_config
                        .machine
                        .duration_point
                        .as_ref()
                        .unwrap()
                        .start(),
                    &1000.0
                );
                assert_eq!(
                    derive_config.machine.duration_point.as_ref().unwrap().end(),
                    &100000.0
                );
                assert_eq!(
                    derive_config.machine.count_point.as_ref().unwrap().start(),
                    &10
                );
                assert_eq!(
                    derive_config.machine.count_point.as_ref().unwrap().end(),
                    &100
                );
                assert_eq!(
                    derive_config
                        .machine
                        .min_action_timeout
                        .as_ref()
                        .unwrap()
                        .start(),
                    &0.0
                );
                assert_eq!(
                    derive_config
                        .machine
                        .min_action_timeout
                        .as_ref()
                        .unwrap()
                        .end(),
                    &1000.0
                );
            }
            Err(e) => {
                panic!("Failed to parse comprehensive TOML config: {e}");
            }
        }
    }
}

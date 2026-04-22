use std::process::Command;
use std::sync::Once;

static INIT: Once = Once::new();

/// Helper function to ensure traces exist before running trace-dependent tests.
/// Call this at the start of any test that needs generated trace files.
#[cfg(feature = "trace-tests")]
pub fn setup_traces() {
    let manifest_root = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let tests_dir = std::path::Path::new(&manifest_root).join("tests");
    ensure_traces_exist(&tests_dir);
}

/// Ensures all required trace files exist for testing. This is a fallback
/// mechanism in case the build script didn't run or failed to generate the
/// required files.
pub fn ensure_traces_exist(tests_dir: &std::path::Path) {
    INIT.call_once(|| {
        let required_trace_files = [
            "ether100M_synth10K_std.ltbin.gz",
            "ether100M_synth5K.tr",
            "ether10M_synth10K_std.ltbin.gz",
            "test100K_synth2M_std.ltbin.gz",
            "ether100M_synth5K.ltbin.gz",
            "ether100M_synth5M.ltbin.gz",
            "ether100M_synth5M_21bins.ltbin.gz",
            "ether100M_synth10M.ltbin.gz",
            "ether10M_synth5M.ltbin.gz",
            "ether100M_synth40M.ltbin.gz",
        ];

        // Check if any files are missing (look in crate/tests/data/ directory)
        let data_dir = tests_dir.join("data");
        let missing_files: Vec<_> = required_trace_files
            .iter()
            .filter(|&file| !data_dir.join(file).exists())
            .collect();

        if missing_files.is_empty() {
            println!("All required trace files exist");
            return;
        }

        println!(
            "Missing {} trace files, attempting to generate them...",
            missing_files.len()
        );
        for file in &missing_files {
            println!("Missing: {}", file);
        }

        // Run the trace generation script (should be in crate/tests directory)
        let script_path = tests_dir.join("create_testlinktraces.sh");
        println!("Looking for script at: {:?}", script_path);

        if !script_path.exists() {
            panic!("Trace generation script not found: {:?}", script_path);
        }

        println!("Running trace generation script...");

        let info_cmd = "echo '\n\nSTARTING TRACE GENERATION FOR TESTS AND BENCHMARKS, \
        WILL TAKE SOME TIME, RUNS ONCE.\n IF A LINKTRACE TEST FAILS, TRY AGAIN AFTER THIS \
        GENERATION HAS FINISHED.\n\n'";
        let _ = Command::new("bash")
            .arg("-c")
            .arg(info_cmd)
            .current_dir(tests_dir)
            .status();

        let script_result = Command::new("bash")
            .arg(&script_path)
            .current_dir(tests_dir)
            .status();

        match script_result {
            Ok(status) if status.success() => {
                println!("Successfully generated trace files");
            }
            Ok(status) => {
                panic!(
                    "Failed to run trace generation script: exit code {}",
                    status
                );
            }
            Err(e) => {
                panic!("Failed to execute trace generation script: {}", e);
            }
        }

        // Verify files were created (check in crate/tests/data directory)
        let still_missing: Vec<_> = required_trace_files
            .iter()
            .filter(|&file| !data_dir.join(file).exists())
            .collect();

        if !still_missing.is_empty() {
            panic!(
                "Failed to generate all required trace files. Still missing: {:?}",
                still_missing
            );
        }

        println!("All required trace files are now present");
    });
}

/// Attempts to find the workspace root directory by looking for Cargo.toml with
/// workspace configuration.
#[cfg(feature = "trace-tests")]
fn find_workspace_root() -> std::path::PathBuf {
    let mut current = std::env::current_dir().expect("Failed to get current directory");

    loop {
        let cargo_toml = current.join("Cargo.toml");
        if cargo_toml.exists() {
            // Try to read the Cargo.toml and check if it's a workspace
            if let Ok(content) = std::fs::read_to_string(&cargo_toml) {
                if content.contains("[workspace]") {
                    return current;
                }
            }
        }

        // Move up one directory
        if let Some(parent) = current.parent() {
            current = parent.to_path_buf();
        } else {
            panic!("Could not find workspace root directory");
        }
    }
}

#[cfg(test)]
#[cfg(feature = "trace-tests")]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "trace-tests")]
    fn test_find_workspace_root() {
        let root = find_workspace_root();
        assert!(root.join("Cargo.toml").exists());

        // Should contain workspace configuration
        let content = std::fs::read_to_string(root.join("Cargo.toml"))
            .expect("Failed to read workspace Cargo.toml");
        assert!(content.contains("[workspace]"));
    }

    #[test]
    #[cfg(feature = "trace-tests")]
    fn test_ensure_traces_exist() {
        // Get the tests directory path using manifest root
        let manifest_root = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
        let tests_dir = std::path::Path::new(&manifest_root).join("tests");

        // This test will actually run the trace generation if needed
        ensure_traces_exist(&tests_dir);

        // Verify that all required files now exist (in tests/data directory)
        let data_dir = tests_dir.join("data");
        let required_files = [
            "ether100M_synth10K_std.ltbin.gz",
            "ether10M_synth10K_std.ltbin.gz",
            "test100K_synth2M_std.ltbin.gz",
            "ether100M_synth5K.ltbin.gz",
            "ether100M_synth5M.ltbin.gz",
            "ether100M_synth5M_21bins.ltbin.gz",
            "ether100M_synth10M.ltbin.gz",
            "ether10M_synth5M.ltbin.gz",
            "ether100M_synth40M.ltbin.gz",
        ];

        for file in &required_files {
            let file_path = data_dir.join(file);
            assert!(
                file_path.exists(),
                "Required trace file missing: {}",
                file_path.display()
            );
        }
    }
}

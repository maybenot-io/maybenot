use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_derive_seed_42() {
    let mut cmd = Command::cargo_bin("maybenot").unwrap();

    let output = cmd
        .arg("derive")
        .arg("-c")
        .arg("examples/derive-seed-42.toml")
        .arg("-s")
        .arg("42")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "Command failed with exit code: {:?}\nStdout: {}\nStderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("successfully derived defense in 3 attempts"),
        "Expected 'successfully derived defense in 3 attempts' in output.\nStdout: {stdout}\nStderr: {stderr}"
    );
}

#[test]
fn test_search_seed_42() {
    let temp_dir = tempdir().unwrap();
    let output_file = temp_dir.path().join("test.def");

    let mut cmd = Command::cargo_bin("maybenot").unwrap();

    let output = cmd
        .arg("search")
        .arg("-c")
        .arg("examples/derive-seed-42.toml")
        .arg("-o")
        .arg(output_file.to_str().unwrap())
        .arg("-n")
        .arg("1")
        .arg("-s")
        .arg("42")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "Command failed with exit code: {:?}\nStdout: {}\nStderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        output_file.exists(),
        "Output file was not created: {}",
        output_file.display()
    );

    let file_contents = fs::read_to_string(&output_file).unwrap();
    assert!(
        file_contents.contains("attempts 2"),
        "Expected 'attempts 2' in output file.\nFile contents: {file_contents}"
    );
}

#[test]
fn test_sim_simulate_config() {
    let temp_dir = tempdir().unwrap();
    let output_dir = temp_dir.path().join("sim_output");

    let mut cmd = Command::cargo_bin("maybenot").unwrap();

    let output = cmd
        .arg("sim")
        .arg("-c")
        .arg("examples/simulate.toml")
        .arg("-i")
        .arg("examples/10-padding-defenses.def")
        .arg("-o")
        .arg(output_dir.to_str().unwrap())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "Command failed with exit code: {:?}\nStdout: {}\nStderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        output_dir.exists(),
        "Output directory was not created: {}",
        output_dir.display()
    );

    let mut total_files = 0;
    let mut subdirs = 0;
    for entry in fs::read_dir(&output_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            subdirs += 1;
            for file_entry in fs::read_dir(&path).unwrap() {
                let file_entry = file_entry.unwrap();
                if file_entry.path().is_file() {
                    total_files += 1;
                }
            }
        }
    }
    assert_eq!(subdirs, 2, "Expected 2 subdirectories, found {subdirs}");
    assert_eq!(
        total_files, 8,
        "Expected 8 files total in subdirectories, found {total_files}"
    );
}

use anyhow::{Result, bail};
use maybenot_simulator::{
    integration::Integration, network::Network, parse_trace_advanced, queue::SimQueue,
};
use rand::Rng;
use rand::seq::IndexedRandom;

use super::Traces;
use std::fs::{metadata, read_dir, read_to_string};
use std::path::{Path, PathBuf};

/// From the BigEnough dataset by Mathews et al., "SoK: A Critical Evaluation of
/// Efficient Website Fingerprinting Defenses", S&P 2023. Selected to have at
/// least 1000 packets, all from different classes.
const BIGENOUGH_TRACES: [&str; 14] = [
    include_str!("data-bigenough-standard/0000-0000-0000.log"),
    include_str!("data-bigenough-standard/0001-0000-0000.log"),
    include_str!("data-bigenough-standard/0002-0000-0000.log"),
    include_str!("data-bigenough-standard/0003-0001-0001.log"),
    include_str!("data-bigenough-standard/0010-0000-0000.log"),
    include_str!("data-bigenough-standard/0020-0000-0000.log"),
    include_str!("data-bigenough-standard/0030-0000-0005.log"),
    include_str!("data-bigenough-standard/0040-0000-0000.log"),
    include_str!("data-bigenough-standard/0050-0000-0000.log"),
    include_str!("data-bigenough-standard/0060-0000-0000.log"),
    include_str!("data-bigenough-standard/0071-0000-0000.log"),
    include_str!("data-bigenough-standard/0080-0000-0000.log"),
    include_str!("data-bigenough-standard/0090-0000-0000.log"),
    include_str!("data-bigenough-standard/0091-0000-0000.log"),
];

/// From Syverson et al. "Onion-Location Measurements and Fingerprinting", PETS
/// 2025. The traces are the first 30 cells of general and rend circuits. We
/// ignore hsdir and intro circuits, because they will always be trivially
/// distinguishable by their relative short lengths. While 30 cells is too much
/// for the handshake, it is a comfortable margin for circuit fingerprinting for
/// general, rend, hsdir, and intro circuits using DF.
const TOR_CIRCUIT_FP_TRACES: [&str; 14] = [
    include_str!("data-tor-circuit-fp/general/0.log"),
    include_str!("data-tor-circuit-fp/rend/0.log"),
    include_str!("data-tor-circuit-fp/general/1.log"),
    include_str!("data-tor-circuit-fp/rend/1.log"),
    include_str!("data-tor-circuit-fp/general/2.log"),
    include_str!("data-tor-circuit-fp/rend/2.log"),
    include_str!("data-tor-circuit-fp/general/3.log"),
    include_str!("data-tor-circuit-fp/rend/3.log"),
    include_str!("data-tor-circuit-fp/general/4.log"),
    include_str!("data-tor-circuit-fp/rend/4.log"),
    include_str!("data-tor-circuit-fp/general/5.log"),
    include_str!("data-tor-circuit-fp/rend/5.log"),
    include_str!("data-tor-circuit-fp/general/6.log"),
    include_str!("data-tor-circuit-fp/rend/6.log"),
];

/// From the Deep Fingerprinting paper dataset by Sirinam et al., "Deep
/// Fingerprinting: Undermining Website Fingerprinting Defenses with Deep
/// Learning", CCS 2018. The traces are from the wflib version of the dataset at
/// https://github.com/Xinhao-Deng/Website-Fingerprinting-Library/. Selected to
/// have at least 1000 packets, all from different classes.
const DEEP_FINGERPRINTING_TRACES: [&str; 14] = [
    include_str!("data-df-wflib/1.log"),
    include_str!("data-df-wflib/2.log"),
    include_str!("data-df-wflib/3.log"),
    include_str!("data-df-wflib/6.log"),
    include_str!("data-df-wflib/10.log"),
    include_str!("data-df-wflib/20.log"),
    include_str!("data-df-wflib/30.log"),
    include_str!("data-df-wflib/41.log"),
    include_str!("data-df-wflib/50.log"),
    include_str!("data-df-wflib/60.log"),
    include_str!("data-df-wflib/70.log"),
    include_str!("data-df-wflib/80.log"),
    include_str!("data-df-wflib/89.log"),
    include_str!("data-df-wflib/91.log"),
];

/// From the Gong-Surakav dataset by Gong et al., "Surakav: Generating Realistic
/// Traces for a Strong Website Fingerprinting Defense", IEEE S&P 2022. Selected
/// to have at least 1000 packets, all from different classes. Undefended
/// dataset from the tiktok npz file.
const GONG_SURAKAV_TRACES: [&str; 14] = [
    include_str!("data-gong-surakav/2-2.log"),
    include_str!("data-gong-surakav/3-3.log"),
    include_str!("data-gong-surakav/4-4.log"),
    include_str!("data-gong-surakav/10-10.log"),
    include_str!("data-gong-surakav/20-20.log"),
    include_str!("data-gong-surakav/21-21.log"),
    include_str!("data-gong-surakav/32-32.log"),
    include_str!("data-gong-surakav/33-33.log"),
    include_str!("data-gong-surakav/42-42.log"),
    include_str!("data-gong-surakav/43-43.log"),
    include_str!("data-gong-surakav/51-51.log"),
    include_str!("data-gong-surakav/66-66.log"),
    include_str!("data-gong-surakav/77-77.log"),
    include_str!("data-gong-surakav/99-99.log"),
];

pub fn load_traces<R: Rng>(
    traces: &[Traces],
    num_traces: usize,
    network: Network,
    client_integration: &Option<Integration>,
    server_integration: &Option<Integration>,
    rng: &mut R,
) -> Result<Vec<SimQueue>> {
    let mut candidate_traces: Vec<&str> = Vec::new();

    for t in traces {
        match t {
            Traces::BigEnough => {
                candidate_traces.extend(&BIGENOUGH_TRACES);
            }
            Traces::DeepFingerprinting => {
                candidate_traces.extend(&DEEP_FINGERPRINTING_TRACES);
            }
            Traces::GongSurakav => {
                candidate_traces.extend(&GONG_SURAKAV_TRACES);
            }
            Traces::TorCircuit => {
                candidate_traces.extend(&TOR_CIRCUIT_FP_TRACES);
            }
            Traces::Custom {
                root,
                min_bytes,
                max_bytes,
            } => {
                {
                    let root_path = Path::new(&root);
                    let mut file_paths = Vec::new();

                    // recursively traverse directory and collect all file paths
                    fn visit_dirs(
                        dir: &Path,
                        files: &mut Vec<PathBuf>,
                        min_size: u64,
                        max_size: u64,
                    ) -> Result<()> {
                        for entry in read_dir(dir)? {
                            let entry = entry?;
                            let path = entry.path();
                            if path.is_dir() {
                                visit_dirs(&path, files, min_size, max_size)?;
                            } else if path.is_file()
                                && metadata(&path)?.len() >= min_size
                                && metadata(&path)?.len() <= max_size
                            {
                                files.push(path);
                            }
                        }
                        Ok(())
                    }
                    visit_dirs(root_path, &mut file_paths, *min_bytes, *max_bytes)?;

                    if file_paths.len() < num_traces {
                        bail!(
                            "only {} files found in custom root, requested {}",
                            file_paths.len(),
                            num_traces
                        );
                    }

                    // choose n random distinct files
                    let chosen_files: Vec<_> = file_paths
                        .choose_multiple(rng, num_traces)
                        .cloned()
                        .collect();

                    // for each chosen file, read its contents, create SimQueues, and return
                    return Ok(chosen_files
                        .iter()
                        .map(|file| {
                            parse_trace_advanced(
                                &read_to_string(file).expect("file not found"),
                                network,
                                client_integration.as_ref(),
                                server_integration.as_ref(),
                            )
                        })
                        .collect::<Vec<_>>());
                }
            }
        }
    }

    if num_traces > candidate_traces.len() {
        bail!(
            "only {} traces available for {:#?}, requested {}",
            candidate_traces.len(),
            traces,
            num_traces
        );
    }

    if num_traces < candidate_traces.len() {
        // select a random subset of traces
        candidate_traces = candidate_traces
            .choose_multiple(rng, num_traces)
            .cloned()
            .collect();
    }

    Ok(candidate_traces
        .iter()
        .map(|trace| {
            parse_trace_advanced(
                trace,
                network,
                client_integration.as_ref(),
                server_integration.as_ref(),
            )
        })
        .collect::<Vec<_>>())
}

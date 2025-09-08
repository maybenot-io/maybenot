use std::{
    collections::HashMap,
    fs::{self, read_to_string},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use indicatif::ParallelProgressIterator;
use log::info;
use maybenot_gen::overhead::DefendedTraceStats;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use serde_json::{from_str, to_string_pretty};
use statrs::statistics::{Data, Distribution, Median};

use crate::{config::Config, get_progress_style};
use std::collections::BTreeMap;

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct EvalConfig {
    /// undefended dataset used for simulation
    pub base_dataset: String,
    /// path to output json file, if set, will create or append to it
    pub output: Option<PathBuf>,
    /// classifiers to use for evaluation, should be complete commands with
    /// arguments that returns the results as a string on the last line of
    /// stdout to be printed. The directory of the defended traces will be
    /// passed as the last argument.
    pub classifiers: Option<Vec<String>>,
}

pub fn eval(config: Config, input: &Path, output: Option<&PathBuf>) -> Result<()> {
    let Some(cfg) = config.eval else {
        bail!("no eval configuration found in config file")
    };

    // if output is set, check that we can create or append to it
    if let Some(output) = output.or(cfg.output.as_ref()) {
        let fp = Path::new(&output);
        if fp.exists() && !fp.is_file() {
            bail!(format!(
                "output exists but {} is not a file",
                output.display()
            ));
        }
        if fp.exists() && fp.metadata().is_ok_and(|m| m.permissions().readonly()) {
            bail!(format!(
                "output {} already exists and is not writable",
                output.display()
            ));
        }
    }

    if !input.is_dir() {
        bail!(format!("input {} is not a directory", input.display()));
    }
    let base_root = Path::new(&cfg.base_dataset);
    if !base_root.is_dir() {
        bail!(format!(
            "base dataset {} is not a directory",
            cfg.base_dataset
        ));
    }

    let defended_list = list_traces(input)?;
    if defended_list.is_empty() {
        bail!("input dataset is empty, nothing to compare against");
    }
    let base_list = list_traces(base_root)?;
    if base_list.is_empty() {
        bail!("base dataset is empty, nothing to compare against");
    }
    // check that defended list is a multiple of base list
    if defended_list.len() > base_list.len() && defended_list.len() % base_list.len() != 0 {
        bail!(
            "defended dataset has {} traces, base dataset has {} traces, but defended is not a multiple of base",
            defended_list.len(),
            base_list.len()
        );
    }

    info!(
        "found {} defended traces in input directory {}",
        defended_list.len(),
        input.display()
    );
    info!(
        "found {} base traces in base directory {}",
        base_list.len(),
        cfg.base_dataset
    );

    // augmentation factor, will be multiple of base traces
    let aug = defended_list.len() / base_list.len();
    if aug > 1 {
        info!(
            "detected {aug}x augmentation factor, will compare each defended trace with the corresponding base trace"
        );
    }

    info!("analyzing defended traces...");
    let defended_stats =
        create_per_trace_stats(&defended_list, input, base_root, get_max_sample(&base_list))?;

    let mut fixed_metrics = HashMap::<String, f64>::new();

    info!("");
    info!(
        "{:<25}{:>8} {:>8} {:>8} {:>7}",
        "Metric", "Mean", "StdDev", "Median", "Unit"
    );
    info!("===========================================================");
    print_absolute_state_line(
        "base 🌐",
        "packets",
        defended_stats
            .iter()
            .map(DefendedTraceStats::base_packets)
            .collect(),
        "base",
        &mut fixed_metrics,
    );
    print_absolute_state_line(
        "-sent",
        "packets",
        defended_stats
            .iter()
            .map(DefendedTraceStats::base_packets_sent)
            .collect(),
        "base_sent",
        &mut fixed_metrics,
    );
    print_absolute_state_line(
        "-recv",
        "packets",
        defended_stats
            .iter()
            .map(DefendedTraceStats::base_packets_received)
            .collect(),
        "base_recv",
        &mut fixed_metrics,
    );

    info!("");
    print_absolute_state_line(
        "defended 🛡️",
        "packets",
        defended_stats
            .iter()
            .map(DefendedTraceStats::defended_packets)
            .collect(),
        "defended",
        &mut fixed_metrics,
    );
    print_absolute_state_line(
        "-sent",
        "packets",
        defended_stats
            .iter()
            .map(DefendedTraceStats::defended_packets_sent)
            .collect(),
        "defended_sent",
        &mut fixed_metrics,
    );
    print_absolute_state_line(
        "-recv",
        "packets",
        defended_stats
            .iter()
            .map(DefendedTraceStats::defended_packets_received)
            .collect(),
        "defended_recv",
        &mut fixed_metrics,
    );

    info!("");
    print_absolute_state_line(
        "missing ⚠️",
        "packets",
        defended_stats
            .iter()
            .map(DefendedTraceStats::missing_packets)
            .collect(),
        "missing",
        &mut fixed_metrics,
    );
    print_absolute_state_line(
        "-sent",
        "packets",
        defended_stats
            .iter()
            .map(|s| s.missing_normal_sent)
            .collect(),
        "missing_sent",
        &mut fixed_metrics,
    );
    print_absolute_state_line(
        "-recv",
        "packets",
        defended_stats
            .iter()
            .map(|s| s.missing_normal_received)
            .collect(),
        "missing_recv",
        &mut fixed_metrics,
    );

    info!("");
    print_absolute_state_line(
        "total padding 📦",
        "packets",
        defended_stats
            .iter()
            .map(DefendedTraceStats::padding_total)
            .collect(),
        "padding_total",
        &mut fixed_metrics,
    );
    print_absolute_state_line(
        "-sent",
        "packets",
        defended_stats.iter().map(|s| s.padding_sent).collect(),
        "padding_sent",
        &mut fixed_metrics,
    );
    print_absolute_state_line(
        "-recv",
        "packets",
        defended_stats.iter().map(|s| s.padding_received).collect(),
        "padding_received",
        &mut fixed_metrics,
    );

    info!("");
    print_absolute_state_line(
        "tail padding 🔚",
        "packets",
        defended_stats
            .iter()
            .map(DefendedTraceStats::tail_padding)
            .collect(),
        "tail_padding",
        &mut fixed_metrics,
    );
    print_absolute_state_line(
        "-sent",
        "packets",
        defended_stats.iter().map(|s| s.tail_sent).collect(),
        "tail_sent",
        &mut fixed_metrics,
    );
    print_absolute_state_line(
        "-recv",
        "packets",
        defended_stats.iter().map(|s| s.tail_received).collect(),
        "tail_received",
        &mut fixed_metrics,
    );

    info!("");
    info!("durations ⏱️");
    print_absolute_state_line(
        "base",
        "seconds",
        defended_stats
            .iter()
            .map(|s| s.base_last_undefended.as_secs_f64())
            .collect(),
        "base_duration",
        &mut fixed_metrics,
    );
    print_absolute_state_line(
        "defended",
        "seconds",
        defended_stats
            .iter()
            .map(|s| s.last_packet.as_secs_f64())
            .collect(),
        "defended_duration",
        &mut fixed_metrics,
    );
    print_absolute_state_line(
        "-last normal",
        "seconds",
        defended_stats
            .iter()
            .map(|s| s.last_normal.as_secs_f64())
            .collect(),
        "defended_duration_last_normal",
        &mut fixed_metrics,
    );

    info!("");
    info!("overheads (last normal) 💸");
    // only count the padding sent until the last normal packet, so we don't
    // count the tail (padding) packets
    print_relative_state_line(
        "data",
        "multiple",
        defended_stats
            .iter()
            .filter_map(DefendedTraceStats::overhead_data)
            .collect(),
        &mut fixed_metrics,
        "overhead_data",
    );
    print_relative_state_line(
        "-sent",
        "multiple",
        defended_stats
            .iter()
            .filter_map(DefendedTraceStats::overhead_data_sent)
            .collect(),
        &mut fixed_metrics,
        "overhead_data_sent",
    );
    print_relative_state_line(
        "-recv",
        "multiple",
        defended_stats
            .iter()
            .filter_map(DefendedTraceStats::overhead_data_recv)
            .collect(),
        &mut fixed_metrics,
        "overhead_data_recv",
    );
    print_relative_state_line(
        "duration",
        "multiple",
        defended_stats
            .iter()
            .filter_map(DefendedTraceStats::overhead_duration)
            .collect(),
        &mut fixed_metrics,
        "overhead_duration",
    );

    // run classifiers if configured
    let mut classifier_metrics = BTreeMap::<String, String>::new();
    if let Some(classifiers) = &cfg.classifiers {
        info!("");
        info!("running classifiers on defended traces...");
        for classifier in classifiers {
            info!("running classifier: {classifier}");
            let result = run_classifier(classifier, input)?;
            info!("result: {result}");
            classifier_metrics.insert(classifier.to_string(), result);
        }
    } else {
        info!("no classifiers configured, skipping");
    }

    if let Some(output) = output.or(cfg.output.as_ref()) {
        let mut out = Vec::<EvalOutput>::new();
        let output_exists = output.exists();

        if output_exists {
            let existing_data: Vec<EvalOutput> =
                from_str(&read_to_string(output).with_context(|| {
                    format!("failed to read existing output file: {}", output.display())
                })?)
                .with_context(|| "failed to parse existing output file".to_string())?;
            out.extend(existing_data);
        }

        // the BTreeMap and iterators ensure the order is stable, unlike HashMap
        let output_data = EvalOutput {
            defended_dataset: input.display().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            fixed_metrics: fixed_metrics.into_iter().collect(),
            classifier_metrics: classifier_metrics.into_iter().collect(),
        };
        out.push(output_data);
        let json_output = to_string_pretty(&out)
            .with_context(|| "failed to serialize output data to JSON".to_string())?;
        fs::write(output, json_output)
            .with_context(|| format!("failed to write output to file: {}", output.display()))?;

        if output_exists {
            info!(
                "appended results to existing output file {}",
                output.display()
            );
        } else {
            info!("created new output file {}", output.display());
        }
    }

    Ok(())
}

/// Output structure for evaluation results. Contains fixed metrics and
/// classifier metrics for the defended dataset. The `defended_dataset` is the
/// path to the defended dataset, and `timestamp` is the time when the
/// evaluation was run.
#[derive(Deserialize, Serialize)]
pub struct EvalOutput {
    defended_dataset: String,
    timestamp: String,
    fixed_metrics: BTreeMap<String, f64>,
    classifier_metrics: BTreeMap<String, String>,
}

pub fn brief_eval_print(input: &Path) -> Result<()> {
    let data: Vec<EvalOutput> =
        from_str(&read_to_string(input).with_context(|| {
            format!("failed to read existing output file: {}", input.display())
        })?)
        .with_context(|| "failed to parse existing output file".to_string())?;
    if data.is_empty() {
        bail!("no evaluation data found in {}", input.display());
    }

    info!(
        "{:^40} | {:^20} | {:^20} | {:^20} | {:^16}",
        "Dataset",
        "Data Overhead (x)",
        "Duration Overhead (x)",
        "Missing Packets (f)",
        "Classifiers"
    );
    info!("{}", "=".repeat(130));

    for result in data {
        let dataset = if result.defended_dataset.len() > 40 {
            result.defended_dataset[result.defended_dataset.len() - 40..].to_string()
        } else {
            result.defended_dataset.clone()
        };

        // data overhead multiple
        let overhead_data_mean = result
            .fixed_metrics
            .get("overhead_data_mean_multiple")
            .unwrap_or(&0.0);
        let overhead_data_std_dev = result
            .fixed_metrics
            .get("overhead_data_std_dev_multiple")
            .unwrap_or(&0.0);
        let overhead_data_median = result
            .fixed_metrics
            .get("overhead_data_median_multiple")
            .unwrap_or(&0.0);
        let data_str = format!(
            "{overhead_data_mean:>5.2}±{overhead_data_std_dev:<5.2} {overhead_data_median:>5.2}",
        );

        // duration overhead multiple
        let overhead_duration_mean = result
            .fixed_metrics
            .get("overhead_duration_mean_multiple")
            .unwrap_or(&0.0);
        let overhead_duration_std_dev = result
            .fixed_metrics
            .get("overhead_duration_std_dev_multiple")
            .unwrap_or(&0.0);
        let overhead_duration_median = result
            .fixed_metrics
            .get("overhead_duration_median_multiple")
            .unwrap_or(&0.0);
        let duration_str = format!(
            "{overhead_duration_mean:>5.2}±{overhead_duration_std_dev:<5.2} {overhead_duration_median:>5.2}",
        );

        // fractions of missing packets compared to the base trace
        let missing_mean_frac = result
            .fixed_metrics
            .get("missing_mean_packets")
            .unwrap_or(&0.0)
            / result
                .fixed_metrics
                .get("base_mean_packets")
                .unwrap_or(&1.0);
        let missing_std_dev_frac = result
            .fixed_metrics
            .get("missing_std_dev_packets")
            .unwrap_or(&0.0)
            / result
                .fixed_metrics
                .get("base_std_dev_packets")
                .unwrap_or(&1.0);
        let missing_median_frac = result
            .fixed_metrics
            .get("missing_median_packets")
            .unwrap_or(&0.0)
            / result
                .fixed_metrics
                .get("base_median_packets")
                .unwrap_or(&1.0);
        let missing_str = format!(
            "{missing_mean_frac:>5.2}±{missing_std_dev_frac:<5.2} {missing_median_frac:>5.2}"
        );

        // attempt to parse classifier values as floats, if it fails, just use
        // the string value
        let classifier_str = result
            .classifier_metrics
            .values()
            .map(|s| {
                s.parse::<f64>()
                    .map_or_else(|_| s.to_string(), |v| format!("{v:5.2}"))
            })
            .collect::<Vec<String>>()
            .join(" ");

        info!(
            "{dataset:<40} | {data_str:<20} | {duration_str:<21} | {missing_str:<20} | {classifier_str:<16}"
        );
    }

    Ok(())
}

fn print_absolute_state_line(
    print_prefix: &str,
    unit: &str,
    data: Vec<f64>,
    metrics_prefix: &str,
    metrics: &mut HashMap<String, f64>,
) {
    let data = Data::new(data);
    let mean = data.mean().unwrap_or(0.0);
    let std_dev = data.std_dev().unwrap_or(0.0);
    let median = data.median();

    info!("{print_prefix:<20}\t{mean:8.0} {std_dev:8.0} {median:8.0} {unit:8}",);

    metrics.insert(format!("{metrics_prefix}_mean_{unit}"), mean);
    metrics.insert(format!("{metrics_prefix}_std_dev_{unit}"), std_dev);
    metrics.insert(format!("{metrics_prefix}_median_{unit}"), median);
}

fn print_relative_state_line(
    print_prefix: &str,
    unit: &str,
    data: Vec<f64>,
    metrics: &mut HashMap<String, f64>,
    base_key: &str,
) {
    let data = Data::new(data);
    let mean = data.mean().unwrap_or(0.0);
    let std_dev = data.std_dev().unwrap_or(0.0);
    let median = data.median();
    info!("{print_prefix:<20}\t{mean:8.2} {std_dev:8.2} {median:8.2} {unit:>7}",);

    metrics.insert(format!("{base_key}_mean_{unit}"), mean);
    metrics.insert(format!("{base_key}_std_dev_{unit}"), std_dev);
    metrics.insert(format!("{base_key}_median_{unit}"), median);
}

/// Returns the maximum sample number from the filename of defended traces
fn get_max_sample(defended_list: &[String]) -> usize {
    defended_list
        .par_iter()
        .map(|trace| {
            if trace.contains('-') {
                // this is the subpage format
                let parts = trace.split('-').collect::<Vec<&str>>();
                let last_part = parts.last().and_then(|s| s.strip_suffix(".log"));
                last_part.and_then(|s| s.parse::<usize>().ok()).unwrap_or(0)
            } else {
                // this is the sample format, <dir>/<sample>.log
                let last_part = trace.strip_suffix(".log");
                last_part
                    .and_then(|s| s.rsplit('/').next())
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(0)
            }
        })
        .max()
        .unwrap_or(0)
}

/// Returns the corresponding base trace for a defended trace. This is needed in
/// case the defended trace is augmented, i.e. has a higher sample number than
/// the base trace.
fn get_corresponding_base_trace(defended: &str, max_base_sample: usize) -> Result<String> {
    if defended.contains('-') {
        // this is the subpage format
        let parts = defended.split('-').collect::<Vec<&str>>();
        let last_part = parts.last().and_then(|s| s.strip_suffix(".log"));
        if let Some(last_part) = last_part {
            let is_zero_padded = last_part.starts_with('0');
            // if the last part is a number, we can use it to find the corresponding base trace
            if let Ok(sample_num) = last_part.parse::<usize>() {
                // calculate the corresponding base trace number
                let base_sample_num = sample_num % max_base_sample;
                // replace the last part with the base sample number
                let new_last_part = if is_zero_padded {
                    format!("{base_sample_num:04}.log")
                } else {
                    // FIXME: broken for supages without zero padding
                    format!("{base_sample_num}.log")
                };
                let mut new_parts = parts.clone();
                new_parts.pop(); // remove the last part
                new_parts.push(&new_last_part);
                Ok(new_parts.join("-"))
            } else {
                Err(anyhow!(
                    "last part of defended trace is not a number: {last_part}"
                ))
            }
        } else {
            Err(anyhow!(
                "defended trace does not have a valid last part: {defended}"
            ))
        }
    } else {
        // this is the sample format, <dir>/<sample>.log
        let last_part = defended
            .strip_suffix(".log")
            .ok_or_else(|| anyhow!("defended trace does not have a valid suffix: {defended}"))?;
        let parts = last_part.split('/').collect::<Vec<&str>>();
        if let Some(last_part) = parts.last() {
            if let Ok(sample_num) = last_part.parse::<usize>() {
                // calculate the corresponding base trace number
                let base_sample_num = sample_num % max_base_sample;
                // replace the last part with the base sample number
                let new_last_part = format!("{base_sample_num}.log");
                let mut new_parts = parts.clone();
                new_parts.pop(); // remove the last part
                new_parts.push(&new_last_part);
                Ok(new_parts.join("/"))
            } else {
                Err(anyhow!(
                    "last part of defended trace is not a number: {last_part}"
                ))
            }
        } else {
            Err(anyhow!(
                "defended trace does not have a valid last part: {defended}"
            ))
        }
    }
}

/// Creates a vector of statistics for each defended trace. It reads the
/// defended trace and the corresponding base trace, and computes the statistics
/// for each trace. Supports the same augmentation structure as produced by the
/// sim command.
fn create_per_trace_stats(
    defended_list: &[String],
    defended_root: &Path,
    base_root: &Path,
    max_base_sample: usize,
) -> Result<Vec<DefendedTraceStats>> {
    let mut stats = Vec::new();
    defended_list
        .par_iter()
        .progress_with_style(get_progress_style())
        .map(|trace| {
            let defended_trace = defended_root.join(trace);
            let base_trace = base_root.join(get_corresponding_base_trace(trace, max_base_sample)?);
            Ok(DefendedTraceStats::new(
                &read_to_string(&defended_trace).with_context(|| {
                    format!("failed reading defended trace at: {defended_trace:?}")
                })?,
                &read_to_string(&base_trace)
                    .with_context(|| format!("failed reading base trace at: {base_trace:?}"))?,
            ))
        })
        .collect_into_vec(&mut stats);
    let stats = stats.into_iter().collect::<Result<Vec<_>>>()?;
    Ok(stats)
}

/// Recursively lists all traces in the given directory. A trace is considered a
/// file with a `.log` extension. The paths are returned relative to the input
/// directory.
fn list_traces(input: &Path) -> Result<Vec<String>> {
    fn list_traces_inner(base: &Path, current: &Path) -> Result<Vec<String>> {
        let mut traces = Vec::new();
        for entry in current.read_dir()? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                traces.extend(list_traces_inner(base, &path)?);
            } else if path.is_file() && path.extension().is_some_and(|ext| ext == "log") {
                // if the file has a .log extension, save its relative path from the base directory
                if let Ok(relative_path) = path.strip_prefix(base) {
                    traces.push(relative_path.to_string_lossy().to_string());
                }
            }
        }
        Ok(traces)
    }
    list_traces_inner(input, input)
}

fn run_classifier(classifier: &str, defended_root: &Path) -> Result<String> {
    let mut parts = classifier.split_whitespace();
    let prog = parts
        .next()
        .ok_or_else(|| anyhow!("invalid classifier command: {classifier}"))?;
    let output = Command::new(prog)
        .args(parts)
        .arg(defended_root)
        .output()
        .with_context(|| format!("failed to run classifier: {classifier}"))?;
    if !output.status.success() {
        bail!(
            "classifier {classifier} failed with status: {}",
            output.status
        );
    }
    let stdout = String::from_utf8(output.stdout)
        .with_context(|| format!("failed to parse stdout of classifier: {classifier}"))?;
    // discard all but the last line of stdout
    let stdout = stdout
        .lines()
        .last()
        .ok_or_else(|| anyhow!("classifier {classifier} did not produce any output"))?;
    if stdout.is_empty() {
        bail!("classifier {classifier} produced empty output");
    }
    Ok(stdout.trim().to_string())
}

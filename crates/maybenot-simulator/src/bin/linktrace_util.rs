use clap::{Parser, Subcommand};
use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs::File;
use std::io::Write;

use maybenot_simulator::linktrace::{
    load_linktrace_from_file, save_linktrace_to_file, LinkTrace, SizebinLookupTable,
};

//use maybenot_simulator::network::{Network, NetworkLinktrace};

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Creates a high resolution trace binary file (1 us slots)
    CreateTracebinHi {
        #[arg(long)]
        client_bw_tracefile: String,

        #[arg(long)]
        server_bw_tracefile: String,

        #[arg(long)]
        save_file: String,

        #[arg(long)]
        sizebins: String,

        #[arg(long)]
        binpktsizes: String,
    },
    /// Creates a standard resolution trace binary file (1 ms slots)
    CreateTracebinStd {
        #[arg(long)]
        client_bw_tracefile: String,

        #[arg(long)]
        server_bw_tracefile: String,

        #[arg(long)]
        save_file: String,
    },
    /// Generates synthetic link trace
    CreateSynthlinktrace {
        #[arg(long)]
        save_file: String,

        #[arg(long, default_value_t = 10_000_000)]
        linecount: usize,

        #[arg(long, default_value_t = 10000)]
        burst_interval: usize,

        #[arg(long, default_value_t = 5000)]
        burst_length: usize,

        #[arg(long, default_value_t = 1000)]
        sub_burst_interval: usize,

        #[arg(long, default_value_t = 700)]
        sub_burst_length: usize,

        #[arg(long, default_value_t = 100)]
        frame_burst_interval: usize,

        #[arg(long, default_value_t = 10)]
        frame_burst_length: usize,

        #[arg(long, default_value_t = 1500.0)]
        slot_bytes: f64,

        #[arg(long)]
        preset: Option<String>,
    },
    /// Print out binary trace information
    TraceInfo {
        #[arg(long)]
        filename: String,
    },
    /// List available presets
    ListPresets,
}

struct TraceParams {
    burst_interval: usize,
    burst_length: usize,
    sub_burst_interval: usize,
    sub_burst_length: usize,
    frame_burst_interval: usize,
    frame_burst_length: usize,
    slot_bytes: f64,
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::CreateTracebinHi {
            client_bw_tracefile,
            server_bw_tracefile,
            save_file,
            sizebins,
            binpktsizes,
        } => {
            create_tracebin_hi(
                client_bw_tracefile,
                server_bw_tracefile,
                save_file,
                sizebins,
                binpktsizes,
            );
        }
        Commands::CreateTracebinStd {
            client_bw_tracefile,
            server_bw_tracefile,
            save_file,
        } => {
            create_tracebin_std(client_bw_tracefile, server_bw_tracefile, save_file);
        }
        Commands::CreateSynthlinktrace {
            save_file,
            linecount,
            burst_interval,
            burst_length,
            sub_burst_interval,
            sub_burst_length,
            frame_burst_interval,
            frame_burst_length,
            slot_bytes,
            preset,
        } => {
            let params = TraceParams {
                burst_interval: *burst_interval,
                burst_length: *burst_length,
                sub_burst_interval: *sub_burst_interval,
                sub_burst_length: *sub_burst_length,
                frame_burst_interval: *frame_burst_interval,
                frame_burst_length: *frame_burst_length,
                slot_bytes: *slot_bytes,
            };
            match create_synthlinktrace(save_file, *linecount, params, preset.clone()) {
                Ok(_) => {
                    println!("Synthetic link trace created successfully");
                }
                Err(err) => {
                    eprintln!("{}", err);
                    list_presets();
                }
            }
        }
        Commands::ListPresets => {
            list_presets();
        }
        Commands::TraceInfo { filename } => {
            trace_info(filename);
        }
    }
}

fn trace_info(filename: &str) {
    if !filename.ends_with(".ltbin.gz") {
        panic!("The binary tracefile must end with .ltbin.gz");
    }
    let linktrace = load_linktrace_from_file(filename).unwrap();
    println!("{}", linktrace);
}

fn create_tracebin_hi(
    // ul = uplink = client,  dl = downlink = server  directions
    ul_bw_tracefile: &str,
    dl_bw_tracefile: &str,
    save_file: &str,
    sizebins: &str,
    binpktsizes: &str,
) {
    if !ul_bw_tracefile.ends_with(".tr") && !ul_bw_tracefile.ends_with(".tr.gz") {
        panic!("The uplink tracefile must end with .tr or .tr.gz");
    }
    if !dl_bw_tracefile.ends_with(".tr") && !dl_bw_tracefile.ends_with(".tr.gz") {
        panic!("The downlink tracefile must end with .tr or .tr.gz");
    }

    println!(
        "Creating trace binary file with uplink tracefile: {}, downlink tracefile: {}, sizebins: {}, binpktsizes: {}",
        ul_bw_tracefile, dl_bw_tracefile, sizebins, binpktsizes
    );

    let sizebinvec: Vec<i32> = sizebins
        .split(',')
        .map(|s| s.trim().parse::<i32>().expect("Failed to parse number"))
        .collect();

    let binpktvec: Vec<i32> = binpktsizes
        .split(',')
        .map(|s| s.trim().parse::<i32>().expect("Failed to parse number"))
        .collect();

    let sizebin_lookuptable = SizebinLookupTable::new(&sizebinvec, &binpktvec);

    let linktrace = LinkTrace::new_hi_res(dl_bw_tracefile, ul_bw_tracefile, sizebin_lookuptable);

    save_linktrace_to_file(&format!("{}{}", save_file, ".ltbin.gz"), &linktrace)
        .expect("Failed to save LinkTrace to ltbin file");
}

fn create_tracebin_std(
    // ul = uplink = client,  dl = downlink = server  directions
    ul_bw_tracefile: &str,
    dl_bw_tracefile: &str,
    save_file: &str,
) {
    if !ul_bw_tracefile.ends_with(".tr") && !ul_bw_tracefile.ends_with(".tr.gz") {
        panic!("The uplink tracefile must end with .tr or .tr.gz");
    }
    if !dl_bw_tracefile.ends_with(".tr") && !dl_bw_tracefile.ends_with(".tr.gz") {
        panic!("The downlink tracefile must end with .tr or .tr.gz");
    }

    println!(
        "Creating trace binary file with uplink tracefile: {}, downlink tracefile: {}",
        ul_bw_tracefile, dl_bw_tracefile
    );

    let linktrace = LinkTrace::new_std_res(dl_bw_tracefile, ul_bw_tracefile);

    save_linktrace_to_file(&format!("{}{}", save_file, ".ltbin.gz"), &linktrace)
        .expect("Failed to save LinkTrace to ltbin file");
}

fn list_presets() {
    println!("Available presets:");
    println!("  hires_starlink_dl");
    println!("  hires_starlink_ul");
    println!("  hires_ether1G");
    println!("  hires_ether100M");
    println!("  hires_ether10M");
    println!("  stdres_ether1G");
    println!("  stdres_ether100M");
    println!("  stdres_ether10M");
    println!("  stdres_test100K");
}

fn create_synthlinktrace(
    filename: &str,
    linecount: usize,
    traceparams: TraceParams,
    preset: Option<String>,
) -> Result<(), String> {
    if !filename.ends_with(".tr") && !filename.ends_with(".tr.gz") {
        panic!("The tracefile must end with .tr or .tr.gz");
    }
    let TraceParams {
        burst_interval,
        burst_length,
        sub_burst_interval,
        sub_burst_length,
        frame_burst_interval,
        frame_burst_length,
        slot_bytes,
    } = match preset.as_deref() {
        Some("hires_starlink_dl") => TraceParams {
            burst_interval: 13333,
            burst_length: 5000,
            sub_burst_interval: 1333,
            sub_burst_length: 700,
            frame_burst_interval: 12,
            frame_burst_length: 1,
            slot_bytes: 1500.0,
        },
        Some("hires_starlink_ul") => TraceParams {
            burst_interval: 13333,
            burst_length: 5000,
            sub_burst_interval: 1333,
            sub_burst_length: 350,
            frame_burst_interval: 60,
            frame_burst_length: 1,
            slot_bytes: 1500.0,
        },
        Some("hires_ether1G") => TraceParams {
            burst_interval: 1,
            burst_length: 1,
            sub_burst_interval: 1,
            sub_burst_length: 1,
            frame_burst_interval: 1,
            frame_burst_length: 1,
            slot_bytes: 125.0,
        },
        Some("hires_ether100M") => TraceParams {
            burst_interval: 1,
            burst_length: 1,
            sub_burst_interval: 1,
            sub_burst_length: 1,
            frame_burst_interval: 1,
            frame_burst_length: 1,
            slot_bytes: 12.5,
        },
        Some("hires_ether10M") => TraceParams {
            burst_interval: 2,
            burst_length: 1,
            sub_burst_interval: 1,
            sub_burst_length: 1,
            frame_burst_interval: 1,
            frame_burst_length: 1,
            slot_bytes: 2.5,
        },
        Some("hires_test1M") => TraceParams {
            burst_interval: 40,
            burst_length: 1,
            sub_burst_interval: 1,
            sub_burst_length: 1,
            frame_burst_interval: 1,
            frame_burst_length: 1,
            slot_bytes: 5.0,
        },
        Some("stdres_ether1G") => TraceParams {
            burst_interval: 1,
            burst_length: 1,
            sub_burst_interval: 1,
            sub_burst_length: 1,
            frame_burst_interval: 1,
            frame_burst_length: 1,
            slot_bytes: 125000.0,
        },
        Some("stdres_ether100M") => TraceParams {
            burst_interval: 1,
            burst_length: 1,
            sub_burst_interval: 1,
            sub_burst_length: 1,
            frame_burst_interval: 1,
            frame_burst_length: 1,
            slot_bytes: 12500.0,
        },
        Some("stdres_ether10M") => TraceParams {
            burst_interval: 1,
            burst_length: 1,
            sub_burst_interval: 1,
            sub_burst_length: 1,
            frame_burst_interval: 1,
            frame_burst_length: 1,
            slot_bytes: 1250.0,
        },
        Some("stdres_test100K") => TraceParams {
            burst_interval: 1,
            burst_length: 1,
            sub_burst_interval: 1,
            sub_burst_length: 1,
            frame_burst_interval: 1,
            frame_burst_length: 1,
            slot_bytes: 12.5,
        },
        None => traceparams,
        _ => return Err(format!("Invalid preset provided: {:?}", preset)),
    };

    let mut file: Box<dyn Write> = if filename.ends_with(".tr.gz") {
        let f = File::create(filename).expect("Failed to create file");
        Box::new(GzEncoder::new(f, Compression::default()))
    } else {
        Box::new(File::create(filename).expect("Failed to create file"))
    };

    // Slot_bytes are allowed to be either .0 or .5 so we need to handle this by alternating
    let fract = slot_bytes.fract();
    if (fract - 0.0).abs() > f64::EPSILON && (fract - 0.5).abs() > f64::EPSILON {
        panic!("slot_bytes must be either a whole number or a half (.0 or .5)");
    }

    let is_half = (fract - 0.5).abs() < f64::EPSILON;
    let mut toggle = false; // Used to alternate if slot_bytes has a .5 fractional part

    for line in 0..linecount {
        let within_burst = line % burst_interval < burst_length;
        let within_sub_burst = (line % burst_interval) % sub_burst_interval < sub_burst_length;
        let frame_position = (line % sub_burst_interval) % frame_burst_interval;
        let on_frame_burst = frame_position < frame_burst_length;

        let value = if within_burst && within_sub_burst && on_frame_burst {
            if is_half {
                let result = if toggle {
                    slot_bytes.ceil() as u32
                } else {
                    slot_bytes.floor() as u32
                };
                toggle = !toggle;
                result
            } else {
                slot_bytes as u32
            }
        } else {
            0
        };
        writeln!(file, "{}", value).expect("Failed to write to file");
    }
    file.flush().expect("Failed to flush file");
    Ok(())
}

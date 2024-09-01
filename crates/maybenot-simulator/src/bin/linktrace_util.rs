use clap::{Parser, Subcommand};
use std::fs::File;
use std::io::Write;
use flate2::write::GzEncoder;
use flate2::Compression;


use maybenot_simulator::linktrace::{save_linktrace_to_file, LinkTrace, SizebinLookupTable};

//use maybenot_simulator::network::{Network, NetworkLinktrace};

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Creates a trace binary file
    CreateTracebin {
        #[arg(long)]
        tracefile: String,

        #[arg(long)]
        sizebins: String,

        #[arg(long)]
        binpktsizes: String,
    },
    /// Generates synthetic link trace
    CreateSynthlinktrace {
        #[arg(long)]
        filename: String,

        #[arg(long, default_value_t = 10_000_000)]
        total_lines: usize,

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

        #[arg(long, default_value_t = 1500)]
        slot_bytes: usize,

        #[arg(long)]
        preset: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::CreateTracebin {
            tracefile,
            sizebins,
            binpktsizes,
        } => {
            create_tracebin(tracefile, sizebins, binpktsizes);
        }
        Commands::CreateSynthlinktrace {
            filename,
            total_lines,
            burst_interval,
            burst_length,
            sub_burst_interval,
            sub_burst_length,
            frame_burst_interval,
            frame_burst_length,
            slot_bytes,
            preset,
        } => {
            create_synthlinktrace(
                filename,
                *total_lines,
                *burst_interval,
                *burst_length,
                *sub_burst_interval,
                *sub_burst_length,
                *frame_burst_interval,
                *frame_burst_length,
                *slot_bytes,
                preset.clone(),
            );
        }
    }
}

fn create_tracebin(tracefile: &str, sizebins: &str, binpktsizes: &str) {
    if !tracefile.ends_with(".tr") && !tracefile.ends_with(".tr.gz") {
        panic!("The tracefile must end with .tr or .tr.gz");
    }

    println!(
        "Creating trace bin with tracefile: {}, sizebins: {}, binpktsizes: {}",
        tracefile, sizebins, binpktsizes
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

    let linktrace = LinkTrace::new(tracefile, tracefile, sizebin_lookuptable);

    let save_filname = if tracefile.ends_with(".tr.gz") {
        tracefile.replace(".tr.gz", ".ltbin.gz")
    } else {
        tracefile.replace(".tr", ".ltbin.gz")
    };

    save_linktrace_to_file(&save_filname, &linktrace)
        .expect("Failed to save LinkTrace to ltbin file");
}

fn create_synthlinktrace(
    filename: &str,
    total_lines: usize,
    burst_interval: usize,
    burst_length: usize,
    sub_burst_interval: usize,
    sub_burst_length: usize,
    frame_burst_interval: usize,
    frame_burst_length: usize,
    slot_bytes: usize,
    preset: Option<String>,
) {
    if !filename.ends_with(".tr") && !filename.ends_with(".tr.gz") {
        panic!("The tracefile must end with .tr or .tr.gz");
    }
    let (
        total_lines,
        burst_interval,
        burst_length,
        sub_burst_interval,
        sub_burst_length,
        frame_burst_interval,
        frame_burst_length,
        slot_bytes,
    ) = match preset.as_deref() {
        Some("starlink") => (total_lines, 13333, 5000, 1333, 700, 12, 1, slot_bytes),
        Some("test1T") => (total_lines, 20, 1, 1, 1, 1, 1, 25),
        Some("ether1G") => (total_lines, 1, 1, 1, 1, 1, 1, 125),
        Some("ether10M") => (total_lines, 20, 1, 1, 1, 1, 1, 25),
        Some("ether100M_5K") => (5000, 2, 1, 1, 1, 1, 1, 25),
        Some("ether100M_5M") => (5_000_000, 2, 1, 1, 1, 1, 1, 25),
        Some("test1M") => (total_lines, 200, 1, 1, 1, 1, 1, 25),
        _ => (
            total_lines,
            burst_interval,
            burst_length,
            sub_burst_interval,
            sub_burst_length,
            frame_burst_interval,
            frame_burst_length,
            slot_bytes,
        ),
    };

    //let mut file = File::create(filename).expect("Failed to create file");

    let mut file: Box<dyn Write> = if filename.ends_with(".tr.gz") {
        let f = File::create(filename).expect("Failed to create file");
        Box::new(GzEncoder::new(f, Compression::default()))
    } else {
        Box::new(File::create(filename).expect("Failed to create file"))
    };

    for line in 0..total_lines {
        let within_burst = line % burst_interval < burst_length;
        let within_sub_burst = (line % burst_interval) % sub_burst_interval < sub_burst_length;
        let frame_position = (line % sub_burst_interval) % frame_burst_interval;
        let on_frame_burst = frame_position < frame_burst_length;

        let value = if within_burst && within_sub_burst && on_frame_burst {
            slot_bytes
        } else {
            0
        };
        writeln!(file, "{}", value).expect("Failed to write to file");
    }
    file.flush().expect("Failed to flush file");
}

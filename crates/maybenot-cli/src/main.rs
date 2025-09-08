mod config;
mod find;
mod storage;
mod tweak;
use anyhow::Result;

use clap::{Parser, Subcommand};
use config::Config;
use env_logger::{Builder, Env, Target};
use indicatif::ProgressStyle;
use log::error;
use std::{
    fs::remove_dir_all,
    path::{Path, PathBuf},
    process::exit,
};

#[derive(Parser)]
#[command(name = "maybenot")]
#[command(about = "A CLI tool for defense generation using Maybenot")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Search for defenses based on the provided configuration.
    Search {
        /// Path to the configuration file.
        #[arg(short, long)]
        config: PathBuf,
        /// Path to the output file where defenses will be saved.
        #[arg(short, long)]
        output: PathBuf,
        /// Optional number of defenses to search for, overrides config.
        #[arg(short, long)]
        n: Option<usize>,
        /// Optional Seed for deterministic search, overrides config. If no seed
        /// set, uses a cryptographically secure random generator.
        #[arg(short, long)]
        seed: Option<String>,
    },
    /// Derive a defense from a seed using the provided configuration.
    Derive {
        /// Path to the configuration file.
        #[arg(short, long)]
        config: PathBuf,
        /// Seed for deriving the defense.
        #[arg(short, long)]
        seed: String,
    },
    /// Combine machines of existing defenses into new defenses.
    Combo {
        /// Path to the configuration file.
        #[arg(short, long)]
        config: PathBuf,
        /// Path to defenses to combine (can be specified multiple times).
        #[arg(short, long, num_args = 1..)]
        input: Vec<PathBuf>,
        /// Output path to write the combined defenses to.
        #[arg(short, long)]
        output: PathBuf,
        /// Optional number of defenses to create, overrides config.
        #[arg(short, long)]
        n: Option<usize>,
        /// Optional maximum height of defenses, overrides config.
        #[arg(short, long)]
        height: Option<usize>,
        /// Optional seed for random number generation, overrides config seed.
        #[arg(short, long)]
        seed: Option<String>,
    },
    /// Simulate defenses on a dataset.
    Sim {
        /// Path to the configuration file.
        #[arg(short, long)]
        config: PathBuf,
        /// Path to defenses (can be specified multiple times).
        #[arg(short, long, num_args = 1..)]
        input: Vec<PathBuf>,
        /// Output path to write dataset to.
        #[arg(short, long)]
        output: PathBuf,
        /// Optional seed, overrides config seed. If no seed, uses a random
        /// seed.
        #[arg(short, long)]
        seed: Option<String>,
        /// Flag, if set, run evaluation on the dataset after simulation.
        #[arg(short, long, action)]
        eval: bool,
    },
    /// Evaluate defenses on a dataset.
    Eval {
        /// Path to the configuration file.
        #[arg(short, long)]
        config: PathBuf,
        /// Path to the input dataset.
        #[arg(short, long)]
        input: PathBuf,
        /// Optional path to the output JSON file.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the results of an evaluation in a human-readable format.
    #[command(name = "eval-print")]
    EvalPrint {
        /// Path to the output results JSON from the Eval command.
        input: PathBuf,
    },
    /// Create or update defenses by adding fixed static machines.
    Fixed {
        /// Optional input path containing defenses to load.
        #[arg(short, long)]
        input: Option<PathBuf>,
        /// Path to the output file where defenses will be saved.
        #[arg(short, long)]
        output: PathBuf,
        /// Client machines to use, can be specified multiple times.
        #[arg(short, long, num_args = 1..)]
        client: Vec<String>,
        /// Server machines to use, can be specified multiple times.
        #[arg(short, long, num_args = 1..)]
        server: Vec<String>,
        /// Optional number of defenses to create, or repeat the existing ones.
        #[arg(short, long)]
        n: Option<usize>,
        /// Optional seed for random number generation.
        #[arg(short, long)]
        seed: Option<String>,
    },
    /// Update budgets for existing defenses.
    Budget {
        /// Path to the input file containing defenses to update.
        #[arg(short, long)]
        input: PathBuf,
        /// Path to the output file where updated defenses will be saved.
        #[arg(short, long)]
        output: PathBuf,
        /// Client budgets to apply, specified as name=range, can be specified
        /// multiple times.
        #[arg(short, long, num_args = 1..)]
        client: Vec<String>,
        /// Server budgets to apply, specified as name=range, can be specified
        /// multiple times.
        #[arg(short, long, num_args = 1..)]
        server: Vec<String>,
        /// Optional flag to indicate if budgets are soft, defaults to false.
        #[arg(short, long)]
        soft: Option<bool>,
        /// Optional seed for random number generation.
        #[arg(short, long)]
        seed: Option<String>,
    },
    /// Create a release JSON with placeholder values.
    Release {
        /// Input path to defenses.
        #[arg(short, long)]
        input: PathBuf,
        /// Output path to write release defenses to.
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Tune config by randomly replacing values to search for better defenses.
    TuneRng {
        /// Path to the configuration file.
        #[arg(short, long)]
        config: PathBuf,
        /// probability to change each config value (set low).
        #[arg(short, long)]
        probability: f64,
        /// temporary output path to write to (ramdisk good).
        #[arg(short, long)]
        output: PathBuf,
        /// optional number of defenses to search for, overrides config n.
        #[arg(short, long)]
        n: Option<usize>,
        /// optional seed for deterministic tuning, otherwise 0
        #[arg(short, long)]
        seed: Option<u64>,
    },
}

fn main() {
    let mut builder = Builder::from_env(Env::default().default_filter_or("info"));
    builder.target(Target::Stdout);
    builder.init();

    if let Err(e) = do_main() {
        error!("error: {e}");
        exit(1);
    }
}

fn do_main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Search {
            config,
            output,
            n,
            seed,
        } => find::search::search(Config::from_file(&config)?, &output, n, seed),
        Commands::Derive { config, seed } => {
            find::derive::derive(Config::from_file(&config)?, seed)
        }
        Commands::Combo {
            config,
            input,
            output,
            n,
            height,
            seed,
        } => find::combo::combo(Config::from_file(&config)?, input, &output, n, height, seed),
        Commands::Sim {
            input,
            output,
            config,
            seed,
            eval,
        } => {
            let cfg = Config::from_file(&config)?;
            tweak::sim::sim(cfg.clone(), input, output.clone(), seed)?;
            if eval {
                let sim_cfg = cfg.clone().sim.unwrap();
                if sim_cfg.tunable_defense_limits.is_none() {
                    tweak::eval::eval(cfg, &output, None)?;
                } else {
                    let limits = sim_cfg.tunable_defense_limits.as_ref().unwrap();
                    for limit in limits.iter() {
                        let output = Path::new(&output).join(format!("limit-{limit}"));
                        tweak::eval::eval(cfg.clone(), &output, None)?;
                    }
                }
                remove_dir_all(output)?;
            }
            Ok(())
        }
        Commands::Eval {
            config,
            input,
            output,
        } => tweak::eval::eval(Config::from_file(&config)?, &input, output.as_ref()),
        Commands::EvalPrint { input } => tweak::eval::brief_eval_print(&input),
        Commands::Fixed {
            input,
            output,
            client,
            server,
            n,
            seed,
        } => tweak::fixed::fixed(input, output, client, server, n, seed),
        Commands::Budget {
            input,
            output,
            client,
            server,
            soft,
            seed,
        } => tweak::budget::budget(input, output, client, server, soft, seed),
        Commands::Release { input, output } => tweak::release::do_release(input, output),
        Commands::TuneRng {
            config,
            probability,
            output,
            n,
            seed,
        } => {
            let cfg = Config::from_file(&config)?;
            find::tune_rng::tune_rng(cfg, probability, output, n, seed)
        }
    }
}

fn get_progress_style() -> ProgressStyle {
    ProgressStyle::default_bar().template(
        "{spinner:.green} [{elapsed_precise:.green}] [{eta_precise:.cyan}] ({percent:.bold}%) [{bar:50.cyan/blue}] {pos}/{human_len} {msg:.magenta}",
    )
    .unwrap().progress_chars("█░")
}

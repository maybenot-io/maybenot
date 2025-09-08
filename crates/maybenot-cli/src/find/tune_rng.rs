use std::{
    fs::{create_dir, metadata, read_to_string, remove_dir_all},
    path::{Path, PathBuf},
};

use crate::{
    config::Config,
    find::search::search,
    storage::load_defenses,
    tweak::{eval::eval, sim::sim},
};
use anyhow::{Result, bail};
use log::info;
use maybenot_gen::{environment::Traces, random_machine::round_f64};
use rand::{Rng, seq::SliceRandom};
use rand_seeder::Seeder;
use rand_xoshiro::Xoshiro256StarStar;

pub fn tune_rng(
    cfg: Config,
    probability: f64,
    output: PathBuf,
    n: Option<usize>,
    seed: Option<u64>,
) -> Result<()> {
    if cfg.search.is_none() {
        bail!("search config is missing");
    }
    if cfg.derive.is_none() {
        bail!("derive config is missing, required by search");
    }
    if cfg.sim.is_none() {
        bail!("sim config is missing, required by search");
    }
    if cfg.eval.is_none() {
        bail!("eval config is missing, required by search");
    }
    if !(0.0..=1.0).contains(&probability) {
        bail!("probability must be in [0, 1]");
    }
    if metadata(&output).is_ok() {
        bail!("output {} already exists", output.display());
    }
    let n_check = n.unwrap_or(cfg.search.as_ref().unwrap().n);
    if n_check == 0 {
        bail!("n must be at least 1");
    }

    let cfg_is_cf = if cfg
        .derive
        .as_ref()
        .unwrap()
        .env
        .traces
        .contains(&Traces::TorCircuit)
    {
        info!("using circuit fingerprinting traces");
        true
    } else {
        info!("using web fingerprinting traces");
        false
    };

    let seed = seed.unwrap_or(0);
    // FIXME: adding the config here is good for "lazy" work, since manual
    // tuning ends up creating new configs (per definition), so multiple
    // iterations with the same seed above leads to different combined seeds.
    // This approach is bad though for reproducibility, since the config
    // contains many paths.
    let cfg_str = serde_json::to_string(&cfg)
        .map_err(|e| anyhow::anyhow!("failed to serialize config for seeding: {}", e))?;
    let combined_seed = format!("{}{}", seed, cfg_str);
    let mut rng: Xoshiro256StarStar = Seeder::from(combined_seed).into_rng();
    info!(
        "deterministic, using seed {} combined with the serialized configuration file",
        seed
    );

    let output_json = cfg.eval.as_ref().unwrap().output.as_ref().unwrap();

    let original = cfg.clone();

    loop {
        info!(
            "🧂🧂 start of random tune loop, probability {}, checking for new config... 🧂🧂",
            probability
        );
        let mut cfg = original.clone();

        // make some change with some probability only if the results file is
        // here: if not, we run with unchanged config as a baseline
        let mut fname = "starting-config".to_string();
        if metadata(output_json).is_ok() {
            let contents = read_to_string(output_json)?;
            loop {
                // found a new config?
                if !contents.contains(&fname) {
                    break;
                }
                // wiggle the config
                cfg = original.clone();
                fname = if cfg_is_cf {
                    wiggle_cf_cfg(&mut cfg, probability, &mut rng)
                } else {
                    wiggle_wf_cfg(&mut cfg, probability, &mut rng)
                };

                // lazy csv escape, removing "," with good formatting
                fname = fname.replace(", ", "..");
                fname = fname.replace(",", "..");
            }
        }

        // create the output folder
        create_dir(&output)?;

        info!("🧂🧂 searching with def: {}", fname);
        let def = output.join(format!("{}.def", fname));
        search(cfg.clone(), &def, n, None)?;

        let loaded = load_defenses(&def)?;
        if loaded.defenses.is_empty() {
            info!("🧂🧂 no defenses found, removing tmp output and trying again");
            remove_dir_all(&output)?;
            continue;
        }

        let sim_folder = Path::new(&output).join(format!("{}-{}", loaded.defenses.len(), fname));

        // sim and eval
        info!("🧂🧂 sim for def: {}", fname);
        sim(cfg.clone(), vec![def.clone()], sim_folder.clone(), None)?;
        let sim = cfg.clone().sim.unwrap();
        info!("🧂🧂 eval for def: {}", fname);
        if sim.tunable_defense_limits.is_none() {
            eval(cfg.clone(), &sim_folder, None)?;
        } else {
            let limits = sim.tunable_defense_limits.as_ref().unwrap();
            for limit in limits.iter() {
                let output = Path::new(&sim_folder).join(format!("limit-{}", limit));
                eval(cfg.clone(), &output, None)?;
            }
        }
        info!("🧂🧂 done, removing tmp output");
        remove_dir_all(&output)?;
    }
}

fn wiggle_wf_cfg(cfg: &mut Config, prob: f64, rng: &mut Xoshiro256StarStar) -> String {
    // what we want to wiggle with some probability: attempts, states,
    // allow_frac_limits, duration ref point, count int ref point, min action
    // timeout, traces, num_traces, sim steps, client load, server load, delay,
    // client min normal packets, server min normal packets, include after last
    // normal

    // for each change we make, we build a new filename
    let mut fname = String::new();

    let derive = cfg.derive.as_mut().unwrap();
    let machine = &mut derive.machine;
    let env = &mut derive.env;
    let constraints = &mut derive.constraints;

    // attempts
    if rng.random_bool(prob) {
        derive.max_attempts = Some(rng.random_range(1..1024));
        fname.push_str(format!("att{}", derive.max_attempts.unwrap()).as_str());
    }

    // states
    if rng.random_bool(prob) {
        let max = rng.random_range(1..=5);
        let min = rng.random_range(1..=max);
        machine.num_states = min..=max;
        fname.push_str(format!("states{:?}", machine.num_states).as_str());
    }

    // allow_frac_limits
    if rng.random_bool(prob) {
        machine.allow_frac_limits = Some(rng.random_bool(0.5));
        fname.push_str(format!("fl{}", machine.allow_frac_limits.unwrap()).as_str());
    }

    // duration ref point
    if rng.random_bool(prob) {
        let max = round_f64(rng.random_range(1.0..=1_000_000.0));
        let min = round_f64(rng.random_range(1.0..=max));
        machine.duration_point = Some(min..=max);
        fname.push_str(format!("drp{:?}", machine.duration_point.clone().unwrap()).as_str());
    }

    // count ref point
    if rng.random_bool(prob) {
        let max = rng.random_range(1..=1_000);
        let min = rng.random_range(1..=max);
        machine.count_point = Some(min..=max);
        fname.push_str(format!("crp{:?}", machine.count_point.clone().unwrap()).as_str());
    }

    // min action timeout
    if rng.random_bool(prob) {
        let max = round_f64(rng.random_range(1.0..=1_000.0));
        let min = round_f64(rng.random_range(1.0..=max));
        machine.min_action_timeout = Some(min..=max);
        fname.push_str(format!("mat{:?}", machine.min_action_timeout.clone().unwrap()).as_str());
    }

    // traces
    let mut updated_traces = false;
    if rng.random_bool(prob) {
        // clone the original traces (it's a superset)
        let mut traces = env.traces.clone();
        traces.shuffle(rng);
        let num_traces = rng.random_range(1..=traces.len());
        traces.truncate(num_traces);
        env.traces = traces;
        fname.push_str(format!("traces{:?}", env.traces).as_str());

        updated_traces = true;
    }

    // num traces
    if updated_traces || rng.random_bool(prob) {
        // FIXME: magic constant 14, correct for now for WF but not for other
        // types of traces
        let m = env.traces.len() * 14;
        let max = rng.random_range(1..=m);
        let min = rng.random_range(1..=max);
        env.num_traces = min..=max;
        fname.push_str(format!("num{:?}", env.num_traces).as_str());
    }

    // sim steps
    if rng.random_bool(prob) {
        let max = rng.random_range(1..=100_000);
        let min = rng.random_range(1..=max);
        env.sim_steps = min..=max;
        fname.push_str(format!("steps{:?}", env.sim_steps).as_str());
    }

    // client load
    if rng.random_bool(prob) {
        let max = round_f64(rng.random_range(0.0..=10.0));
        let min = round_f64(rng.random_range(0.0..=max));
        constraints.client_load = Some(min..=max);
        fname.push_str(format!("cl{:?}", constraints.client_load).as_str());
    }
    // server load
    if rng.random_bool(prob) {
        let max = round_f64(rng.random_range(0.0..=10.0));
        let min = round_f64(rng.random_range(0.0..=max));
        constraints.server_load = Some(min..=max);
        fname.push_str(format!("sl{:?}", constraints.server_load).as_str());
    }
    // delay
    if let Some(delay) = constraints.delay.clone()
        && *delay.end() > 0.0
        && rng.random_bool(prob)
    {
        let max = round_f64(rng.random_range(0.0..=5.0));
        let min = round_f64(rng.random_range(0.0..=max));
        constraints.delay = Some(min..=max);
        fname.push_str(format!("d{:?}", constraints.delay).as_str());
    }

    // client min normal packets
    if rng.random_bool(prob) {
        constraints.client_min_normal_packets = Some(rng.random_range(0..=80));
        fname.push_str(format!("cmin{}", constraints.client_min_normal_packets.unwrap()).as_str());
    }
    // server min normal packets
    if rng.random_bool(prob) {
        constraints.server_min_normal_packets = Some(rng.random_range(0..=200));
        fname.push_str(format!("smin{}", constraints.server_min_normal_packets.unwrap()).as_str());
    }
    // include after last normal
    if rng.random_bool(prob) {
        constraints.include_after_last_normal = Some(rng.random_bool(0.5));
        fname.push_str(format!("inc{}", constraints.include_after_last_normal.unwrap()).as_str());
    }

    fname
}

// wiggle for circuit fingerprinting
fn wiggle_cf_cfg(cfg: &mut Config, prob: f64, rng: &mut Xoshiro256StarStar) -> String {
    // for each change we make, we build a new filename
    let mut fname = String::new();

    let derive = cfg.derive.as_mut().unwrap();
    let machine = &mut derive.machine;
    let env = &mut derive.env;
    let constraints = &mut derive.constraints;

    // attempts
    if rng.random_bool(prob) {
        derive.max_attempts = Some(rng.random_range(1..1024));
        fname.push_str(format!("att{}", derive.max_attempts.unwrap()).as_str());
    }

    // states
    if rng.random_bool(prob) {
        let max = rng.random_range(1..=5);
        let min = rng.random_range(1..=max);
        machine.num_states = min..=max;
        fname.push_str(format!("states{:?}", machine.num_states).as_str());
    }

    // allow_frac_limits
    if rng.random_bool(prob) {
        machine.allow_frac_limits = Some(rng.random_bool(0.5));
        fname.push_str(format!("fl{}", machine.allow_frac_limits.unwrap()).as_str());
    }

    // duration ref point
    if rng.random_bool(prob) {
        let max = round_f64(rng.random_range(1.0..=1_000_000.0));
        let min = round_f64(rng.random_range(1.0..=max));
        machine.duration_point = Some(min..=max);
        fname.push_str(format!("drp{:?}", machine.duration_point.clone().unwrap()).as_str());
    }

    // count ref point
    if rng.random_bool(prob) {
        let max = rng.random_range(1..=1_000);
        let min = rng.random_range(1..=max);
        machine.count_point = Some(min..=max);
        fname.push_str(format!("crp{:?}", machine.count_point.clone().unwrap()).as_str());
    }

    // min action timeout
    if rng.random_bool(prob) {
        let max = round_f64(rng.random_range(1.0..=1_000.0));
        let min = round_f64(rng.random_range(1.0..=max));
        machine.min_action_timeout = Some(min..=max);
        fname.push_str(format!("mat{:?}", machine.min_action_timeout.clone().unwrap()).as_str());
    }

    // traces
    let mut updated_traces = false;
    if rng.random_bool(prob) {
        // clone the original traces (it's a superset)
        let mut traces = env.traces.clone();
        traces.shuffle(rng);
        let num_traces = rng.random_range(1..=traces.len());
        traces.truncate(num_traces);
        env.traces = traces;
        fname.push_str(format!("traces{:?}", env.traces).as_str());

        updated_traces = true;
    }

    // num traces
    if updated_traces || rng.random_bool(prob) {
        // FIXME: magic constant 14, correct for now for CF but not for other
        // types of traces
        let m = env.traces.len() * 14;
        let max = rng.random_range(1..=m);
        let min = rng.random_range(1..=max);
        env.num_traces = min..=max;
        fname.push_str(format!("num{:?}", env.num_traces).as_str());
    }

    // sim steps
    if rng.random_bool(prob) {
        let max = rng.random_range(1..=100_000);
        let min = rng.random_range(1..=max);
        env.sim_steps = min..=max;
        fname.push_str(format!("steps{:?}", env.sim_steps).as_str());
    }

    // client load
    if rng.random_bool(prob) {
        let max = round_f64(rng.random_range(0.0..=10.0));
        let min = round_f64(rng.random_range(0.0..=max));
        constraints.client_load = Some(min..=max);
        fname.push_str(format!("cl{:?}", constraints.client_load).as_str());
    }
    // server load
    if rng.random_bool(prob) {
        let max = round_f64(rng.random_range(0.0..=10.0));
        let min = round_f64(rng.random_range(0.0..=max));
        constraints.server_load = Some(min..=max);
        fname.push_str(format!("sl{:?}", constraints.server_load).as_str());
    }
    // delay
    if let Some(delay) = constraints.delay.clone()
        && *delay.end() > 0.0
        && rng.random_bool(prob)
    {
        let max = round_f64(rng.random_range(0.0..=5.0));
        let min = round_f64(rng.random_range(0.0..=max));
        constraints.delay = Some(min..=max);
        fname.push_str(format!("d{:?}", constraints.delay).as_str());
    }

    // client min normal packets makes no sense for CF
    // server min normal packets makes no sense for CF

    // include after last normal
    if rng.random_bool(prob) {
        constraints.include_after_last_normal = Some(rng.random_bool(0.5));
        fname.push_str(format!("inc{}", constraints.include_after_last_normal.unwrap()).as_str());
    }

    fname
}

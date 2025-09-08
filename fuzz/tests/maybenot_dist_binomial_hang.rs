// #[cfg(feature = "fuzz-tests")]
#[cfg(test)]
mod tests {
    use maybenot::dist::{Dist, DistType};
    use rand::SeedableRng;
    use rand_xoshiro::Xoshiro256StarStar;

    #[test]
    fn test_binomial_hang() {
        let artifacts = vec![
            include_bytes!("../artifacts/bionomial,id-000000,src-000018+000083,time-43455,execs-576361,op-splice,rep-4").to_vec(),
            include_bytes!("../artifacts/bionomial,id-000000,src-000049,time-1595,execs-25705,op-havoc,rep-1").to_vec(),
        ];

        for data in artifacts {
            fuzz_bionomial(&data);
        }
    }

    #[allow(dead_code)]
    fn fuzz_bionomial(data: &[u8]) {
        if data.len() < 24 {
            return;
        }

        let seed: [u8; 8] = match data[0..8].try_into() {
            Ok(arr) => arr,
            Err(_) => return,
        };
        let seed = u64::from_le_bytes(seed);
        let mut rng = Xoshiro256StarStar::seed_from_u64(seed);

        let trials: [u8; 8] = match data[8..16].try_into() {
            Ok(arr) => arr,
            Err(_) => return,
        };
        let trials = u64::from_le_bytes(trials);

        let probability: [u8; 8] = match data[16..24].try_into() {
            Ok(arr) => arr,
            Err(_) => return,
        };
        let probability = f64::from_le_bytes(probability);

        println!("trials: {trials}, probability: {probability}, seed: {seed}");
        let d = Dist {
            dist: DistType::Binomial {
                trials,
                probability,
            },
            start: 0.0,
            max: 0.0,
        };
        if d.validate().is_err() {
            return;
        }
        let _ = d.sample(&mut rng);
    }
}

// #[cfg(feature = "fuzz-tests")]
#[cfg(test)]
mod tests {
    use maybenot::dist::{Dist, DistType};
    use rand::SeedableRng;
    use rand_xoshiro::Xoshiro256StarStar;

    #[test]
    fn test_geometric_hang() {
        let artifacts = vec![
            include_bytes!("../artifacts/geometric,id-000000,src-000000,time-1023,execs-16,op-havoc,rep-7").to_vec(),
            include_bytes!("../artifacts/geometric,id-000001,src-000002,time-2586,execs-645,op-int16,pos-14,val:+0").to_vec(),
            include_bytes!("../artifacts/geometric,id-000002,src-000002,time-9545,execs-2175,op-havoc,rep-3").to_vec(),
            include_bytes!("../artifacts/geometric,id-000003,src-000002,time-19309,execs-4395,op-havoc,rep-6").to_vec(),
        ];

        for data in artifacts {
            fuzz_geometric(&data);
        }
    }

    #[allow(dead_code)]
    fn fuzz_geometric(data: &[u8]) {
        if data.len() < 16 {
            return;
        }

        let seed: [u8; 8] = match data[0..8].try_into() {
            Ok(arr) => arr,
            Err(_) => return,
        };
        let seed = u64::from_le_bytes(seed);
        let mut rng = Xoshiro256StarStar::seed_from_u64(seed);

        let probability: [u8; 8] = match data[8..16].try_into() {
            Ok(arr) => arr,
            Err(_) => return,
        };
        let probability = f64::from_le_bytes(probability);

        println!("probability: {probability}, seed: {seed}");
        let d = Dist {
            dist: DistType::Geometric { probability },
            start: 0.0,
            max: 0.0,
        };
        if d.validate().is_err() {
            return;
        }
        let _ = d.sample(&mut rng);
    }
}

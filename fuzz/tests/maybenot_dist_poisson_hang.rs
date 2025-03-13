// #[cfg(feature = "fuzz-tests")]
#[cfg(test)]
mod tests {
    use core::f64;

    use maybenot::dist::{Dist, DistType};
    use rand::SeedableRng;
    use rand_xoshiro::Xoshiro256StarStar;

    #[test]
    fn test_poisson_hang() {
        let artifacts = vec![
            include_bytes!("../artifacts/poisson,id-000000,src-000000,time-1051,execs-1886,op-havoc,rep-5").to_vec(),
            include_bytes!("../artifacts/poisson,id-000001,src-000000,time-2121,execs-3297,op-havoc,rep-8").to_vec(),
            include_bytes!("../artifacts/poisson,id-000002,src-000009,time-4942,execs-17364,op-havoc,rep-16").to_vec(),
            include_bytes!("../artifacts/poisson,id-000003,src-000008,time-6197,execs-18527,op-havoc,rep-6").to_vec(),
            include_bytes!("../artifacts/poisson,id-000004,src-000042+000043,time-7542,execs-22931,op-splice,rep-7").to_vec(),
            include_bytes!("../artifacts/poisson,id-000005,src-000012+000023,time-13127,execs-62809,op-splice,rep-2").to_vec(),
            include_bytes!("../artifacts/poisson,id-000006,src-000058,time-14198,execs-63456,op-havoc,rep-8").to_vec(),
            include_bytes!("../artifacts/poisson,id-000007,src-000025+000002,time-17458,execs-88688,op-splice,rep-8").to_vec(),
            include_bytes!("../artifacts/poisson,id-000008,src-000054,time-19691,execs-103602,op-havoc,rep-2").to_vec(),
            include_bytes!("../artifacts/poisson,id-000009,src-000005+000059,time-21292,execs-111246,op-splice,rep-2").to_vec(),
            include_bytes!("../artifacts/poisson,id-000010,src-000052,time-23053,execs-117337,op-havoc,rep-5").to_vec(),
            include_bytes!("../artifacts/poisson,id-000011,src-000009+000061,time-24801,execs-125907,op-splice,rep-13").to_vec(),
            include_bytes!("../artifacts/poisson,id-000012,src-000052+000019,time-27294,execs-143045,op-splice,rep-5").to_vec(),
            include_bytes!("../artifacts/poisson,id-000013,src-000025+000062,time-29537,execs-157370,op-splice,rep-2").to_vec(),
            include_bytes!("../artifacts/poisson,id-000014,src-000052,time-32343,execs-177887,op-havoc,rep-1").to_vec(),
            include_bytes!("../artifacts/poisson,id-000015,src-000005,time-37970,execs-253313,op-havoc,rep-16").to_vec(),
            include_bytes!("../artifacts/poisson,id-000016,src-000005,time-41581,execs-301419,op-havoc,rep-10").to_vec(),
            include_bytes!("../artifacts/poisson,id-000017,src-000009+000056,time-47578,execs-377242,op-splice,rep-29").to_vec(),
        ];

        for data in artifacts {
            fuzz_poisson(&data);
        }
    }

    #[allow(dead_code)]
    fn fuzz_poisson(data: &[u8]) {
        if data.len() < 16 {
            return;
        }

        let seed: [u8; 8] = match data[0..8].try_into() {
            Ok(arr) => arr,
            Err(_) => return,
        };
        let seed = u64::from_le_bytes(seed);
        let mut rng = &mut Xoshiro256StarStar::seed_from_u64(seed);

        let lambda: [u8; 8] = match data[8..16].try_into() {
            Ok(arr) => arr,
            Err(_) => return,
        };
        let lambda = f64::from_le_bytes(lambda);
        println!("lambda: {}", lambda);
        //assert!(false);

        let d = Dist {
            dist: DistType::Poisson { lambda },
            start: 0.0,
            max: 0.0,
        };
        if d.validate().is_err() {
            return;
        }
        let _ = d.sample(&mut rng);
    }
}

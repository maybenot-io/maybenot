// #[cfg(feature = "fuzz-tests")]
#[cfg(test)]
mod tests {
    use maybenot::dist::{Dist, DistType};
    use rand::SeedableRng;
    use rand_xoshiro::Xoshiro256StarStar;

    #[test]
    fn test_uniform_crash() {
        let artifacts = vec![
            include_bytes!("../artifacts/uniform,id-000000,sig-06,src-000000,time-7,execs-303,op-havoc,rep-15").to_vec(),
            include_bytes!("../artifacts/uniform,id-000001,sig-06,src-000001,time-48,execs-3481,op-colorization,rep-2").to_vec(),
            include_bytes!("../artifacts/uniform,id-000002,sig-06,src-000003,time-9977,execs-788634,op-havoc,rep-3").to_vec(),
            include_bytes!("../artifacts/uniform,id-000003,sig-06,src-000009+000002,time-29455,execs-2157264,op-splice,rep-34").to_vec(),
        ];

        for data in artifacts {
            fuzz_uniform(&data);
        }
    }

    #[allow(dead_code)]
    fn fuzz_uniform(data: &[u8]) {
        if data.len() < 24 {
            return;
        }

        let seed: [u8; 8] = match data[0..8].try_into() {
            Ok(arr) => arr,
            Err(_) => return,
        };
        let seed = u64::from_le_bytes(seed);
        let mut rng = &mut Xoshiro256StarStar::seed_from_u64(seed);

        let low: [u8; 8] = match data[8..16].try_into() {
            Ok(arr) => arr,
            Err(_) => return,
        };
        let low = f64::from_le_bytes(low);

        let high: [u8; 8] = match data[16..24].try_into() {
            Ok(arr) => arr,
            Err(_) => return,
        };
        let high = f64::from_le_bytes(high);

        let d = Dist {
            dist: DistType::Uniform { low, high },
            start: 0.0,
            max: 0.0,
        };
        if d.validate().is_err() {
            return;
        }
        println!("seed: {seed}, low: {low}, high: {high}");
        let _ = d.sample(&mut rng);
    }
}

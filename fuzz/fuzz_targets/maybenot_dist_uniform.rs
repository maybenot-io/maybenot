use maybenot::dist::{Dist, DistType};
use rand::SeedableRng;
use rand_xoshiro::Xoshiro256StarStar;

fn main() {
    afl::fuzz!(|data: &[u8]| {
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
        let _ = d.sample(&mut rng);
    });
}

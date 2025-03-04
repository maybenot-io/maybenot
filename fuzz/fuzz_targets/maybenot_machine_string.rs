use maybenot::Machine;
use std::str::FromStr;

fn main() {
    afl::fuzz!(|data: &[u8]| {
        if data.len() < 3 {
            return;
        }

        let s = String::from_utf8_lossy(data);
        if Machine::from_str(&s).is_err() {
            return;
        }
    });
}

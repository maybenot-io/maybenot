use std::{collections::HashMap, error::Error, io::Read};

use byteorder::{ByteOrder, LittleEndian};
use flate2::read::ZlibDecoder;
use hex::decode;
use simple_error::{bail, map_err_with};
use std::slice::Iter;

use crate::{
    action::Action,
    dist::{Dist, DistType},
    event::Event,
    machine::Machine,
    state::State,
};

// The size (in bytes) of a serialized distribution for a
// [`State`](crate::state) in v1.
const SERIALIZEDDISTSIZE: usize = 2 + 8 * 4;

// helper function to iterate over all v1 events
fn v1_events_iter() -> Iter<'static, Event> {
    static EVENTS: [Event; 7] = [
        Event::NonPaddingRecv,
        Event::PaddingRecv,
        Event::NonPaddingSent,
        Event::PaddingSent,
        Event::BlockingBegin,
        Event::BlockingEnd,
        Event::LimitReached,
    ];
    EVENTS.iter()
}

/// parses a v1 machine from a hex string into a [`Machine`](crate::machine).
/// This format is deprecated and should not be used for new machines.
/// Therefore, no support for writing machines in this format is provided.
pub fn parse_v1_machine(s: &str) -> Result<Machine, Box<dyn Error + Send + Sync>> {
    // hex -> zlib -> vec
    let compressed = map_err_with!(decode(s), "failed to decode hex")?;

    let mut d = ZlibDecoder::new(compressed.as_slice());
    let mut buf = vec![];
    d.read_to_end(&mut buf)?;

    if buf.len() < 2 {
        bail!("cannot read version")
    }

    let (version, payload) = buf.split_at(2);

    match u16::from_le_bytes(version.try_into().unwrap()) {
        1 => parse_v1(payload),
        //2 => Machine::parse_v2(payload),
        v => bail!("unsupported version: {}", v),
    }
}

fn parse_v1(buf: &[u8]) -> Result<Machine, Box<dyn Error + Send + Sync>> {
    // note that we already read 2 bytes of version in fn parse_machine()
    if buf.len() < 4 * 8 + 1 + 2 {
        bail!("not enough data for version 1 machine")
    }

    let mut r: usize = 0;
    // 4 8-byte values
    let allowed_padding_bytes = LittleEndian::read_u64(&buf[r..r + 8]);
    r += 8;
    let max_padding_frac = LittleEndian::read_f64(&buf[r..r + 8]);
    r += 8;
    let allowed_blocked_microsec = LittleEndian::read_u64(&buf[r..r + 8]);
    r += 8;
    let max_blocking_frac = LittleEndian::read_f64(&buf[r..r + 8]);
    r += 8;

    // 1-byte flag
    //let include_small_packets = buf[r] == 1;
    r += 1;

    // 2-byte num of states
    let num_states: usize = LittleEndian::read_u16(&buf[r..r + 2]) as usize;
    r += 2;

    // each state has 3 distributions + 4 flags + next_state matrix
    let expected_state_len: usize =
        3 * SERIALIZEDDISTSIZE + 4 + (num_states + 2) * 8 * (v1_events_iter().len() + 1);
    if buf[r..].len() != expected_state_len * num_states {
        bail!(format!(
            "expected {} bytes for {} states, but got {} bytes",
            expected_state_len * num_states,
            num_states,
            buf[r..].len()
        ))
    }

    let mut states = vec![];
    for _ in 0..num_states {
        let s = parse_state(buf[r..r + expected_state_len].to_vec(), num_states)?;
        r += expected_state_len;
        states.push(s);
    }

    let m = Machine {
        allowed_padding_bytes,
        max_padding_frac,
        allowed_blocked_microsec,
        max_blocking_frac,
        states,
    };
    m.validate()?;
    Ok(m)
}

pub fn parse_state(buf: Vec<u8>, num_states: usize) -> Result<State, Box<dyn Error + Send + Sync>> {
    // len: 3 distributions + 4 flags + next_state
    if buf.len() < 3 * SERIALIZEDDISTSIZE + 4 + (num_states + 2) * 8 * (v1_events_iter().len() + 1) {
        bail!("too small")
    }

    // distributions
    let mut r: usize = 0;
    let action_dist = parse_dist(buf[r..r + SERIALIZEDDISTSIZE].to_vec())?;
    r += SERIALIZEDDISTSIZE;
    let limit_dist = parse_dist(buf[r..r + SERIALIZEDDISTSIZE].to_vec())?;
    r += SERIALIZEDDISTSIZE;
    let timeout_dist = parse_dist(buf[r..r + SERIALIZEDDISTSIZE].to_vec())?;
    r += SERIALIZEDDISTSIZE;

    // flags
    let action_is_block: bool = buf[r] == 1;
    r += 1;
    let bypass: bool = buf[r] == 1;
    r += 1;
    let replace: bool = buf[r] == 1;
    r += 1;

    let action = if action_is_block {
        Action::BlockOutgoing { bypass, replace }
    } else {
        Action::InjectPadding { bypass, replace }
    };

    let limit_includes_nonpadding: bool = buf[r] == 1;
    r += 1;

    // next state
    let mut next_state: HashMap<Event, Vec<f64>> = HashMap::new();
    for event in v1_events_iter() {
        let mut m = vec![];

        let mut all_zeroes = true;
        for _ in 0..num_states + 2 {
            let v = LittleEndian::read_f64(&buf[r..r + 8]);
            m.push(v);
            r += 8; // for f64
            if v != 0.0 {
                all_zeroes = false;
            }
        }
        if !all_zeroes {
            next_state.insert(*event, m);
        }
    }

    Ok(State {
        timeout_dist,
        action_dist,
        limit_dist,
        action,
        limit_includes_nonpadding,
        next_state,
    })
}

fn parse_dist(buf: Vec<u8>) -> Result<Dist, Box<dyn Error + Send + Sync>> {
    if buf.len() < SERIALIZEDDISTSIZE {
        bail!("too small")
    }

    let mut d: Dist = Dist {
        dist: DistType::None,
        param1: 0.0,
        param2: 0.0,
        start: 0.0,
        max: 0.0,
    };

    d.dist = DistType::from(LittleEndian::read_u16(&buf[..2]));
    d.param1 = LittleEndian::read_f64(&buf[2..10]);
    d.param2 = LittleEndian::read_f64(&buf[10..18]);
    d.start = LittleEndian::read_f64(&buf[18..26]);
    d.max = LittleEndian::read_f64(&buf[26..34]);

    Ok(d)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_parse_v1_machine() {
        // some examples machines, from noop to manually more complex and two
        // larger generated
        let machines = vec![
            "789cedca2101000000c230e85f1a8387009f9e351d051503ca0003",
            "789cd5cfbb0900200c04d08b833886adb889389f5bb9801be811acb58ae2837ce02010c158b070555c9538b6377a64dbb0ceff242c20b79038507dd169fbede9f629bf6f021efa1b66",
            "789ce5935128435118c7cfbd17799a91e4c564258437d29eceb9697958a9514292f2c03c281ea4947858accc1e94a4141e28f222ad95c931e5aeb1b2f062c9a825594dc9c3d6eedab7b5ad6ef7616badd6daefe174be7f7da7afefd761500af7439c0086ab04868323132cf2a8bda165978e581cffad63960a6ae227fc8fea530ce98c7d779370a8d1f8a3b78d77d01bd781d63ad94bd9f6b56de1a5998f3e2f1aeca32d3c6298e434bfb221b243dee70e9e985f231fb2bc74e190f54f848d13aa1cd65c388f06c8f95ef0f8ee729004f4369551dc202c12743d267e454b6fe32a594ca14d0a78ea2f8f38ceae3ce9cd8e88abaab6a6af742d456e2657a6f7abea94739fb8ebdaf7f4dee0cddbbbc54825527482bda96eb2555f36a430f7110813ecccd6704bf7d5f0a7a028109a0543edbacf89e70ffde137e1bb684dc50082b66b69",
            "789ccdd14b4802411807f0d122d630a80e75e920646a9db2d24bd48c9587b012bc04415d32e856eca107d4210f792809a38804e910f400835ca88387d8961e144920b551aed8b59032cc0e59d16c0f41962510dafa0d0cc3cc77f8bef9cbc0b7e0092f06f131832c076f3f21c0e88d464f4c1b51449d3731df6b432feb0fa1f6e20e841f3fc801e5bd5f3d28efa43d8bbc1a1a5f6692e12589b860c84f62f752fbcd3e14605fb549f6bb6de86e0c1a7a028d88f09575d9a7dad2491120ff6279b0a1ca84ecf551ab6b418502adca267a486bc28f5fb20d4a7cb2db0d32fe34c94067ccda6d64afe1dba926585a782e5a2fb5dcdd9496721e42dfd5e35aed5e04865a0a9a13c3ec9ff62707db89d7b391233d1ae7a35458d219ce3049dd40b40827966d52e24a1c4a0be362a05fcde9923b97d0ecf1fa2b9f39c14f181ceeb914c74273f52cb9143e862b7d1554dd565850f7dfbd03f1ca70ff"
            ];

        for m in machines.iter() {
            let machine = parse_v1_machine(m).unwrap();
            println!("{:?}", machine);
            assert_eq!(
                machine,
                Machine::from_str(machine.serialize().as_str()).unwrap()
            );
        }
    }
}

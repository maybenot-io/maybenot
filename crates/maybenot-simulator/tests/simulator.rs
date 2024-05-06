use log::debug;
use maybenot_simulator::{network::Network, parse_trace, queue::SimQueue, sim, SimEvent};

use std::{
    cmp::Reverse,
    collections::HashMap,
    time::{Duration, Instant},
};

use maybenot::{
    dist::{Dist, DistType},
    event::Event,
    framework::TriggerEvent,
    machine::Machine,
    state::State,
};

fn run_test_sim(
    input: &str,
    output: &str,
    delay: Duration,
    machines_client: &[Machine],
    machines_server: &[Machine],
    client: bool,
    max_trace_length: usize,
    only_packets: bool,
) {
    let starting_time = Instant::now();
    let mut sq = make_sq(input.to_string(), delay, starting_time);
    let trace = sim(
        machines_client,
        machines_server,
        &mut sq,
        delay,
        max_trace_length,
        only_packets,
    );
    let mut fmt = fmt_trace(trace.clone(), client);
    if fmt.len() > output.len() {
        fmt = fmt.get(0..output.len()).unwrap().to_string();
    }
    debug!("input: {}", input);
    assert_eq!(output, fmt);
}

fn fmt_trace(trace: Vec<SimEvent>, client: bool) -> String {
    let base = trace[0].time.clone();
    let mut s: String = "".to_string();
    for i in 0..trace.len() {
        if trace[i].client == client {
            s = format!("{} {}", s, fmt_event(&trace[i], base));
        }
    }
    s.trim().to_string()
}

fn fmt_event(e: &SimEvent, base: Instant) -> String {
    format!(
        "{:1},{}",
        e.time.duration_since(base).as_micros(),
        e.event.to_string()
    )
}

fn make_sq(s: String, delay: Duration, starting_time: Instant) -> SimQueue {
    let mut sq = SimQueue::new();
    let integration_delay = Duration::from_micros(0);

    // 0,s,100 18,s,200 25,r,300 25,r,300 30,s,500 35,r,600
    let lines: Vec<&str> = s.split(" ").collect();
    for l in lines {
        let parts: Vec<&str> = l.split(",").collect();
        if parts.len() == 3 {
            let timestamp = starting_time + Duration::from_micros(parts[0].parse::<u64>().unwrap());
            let size = parts[2].trim().parse::<u64>().unwrap();

            match parts[1] {
                "s" | "sn" => {
                    // client sent at the given time
                    sq.push(
                        TriggerEvent::NonPaddingSent {
                            bytes_sent: size as u16,
                        },
                        true,
                        timestamp,
                        integration_delay,
                        Reverse(timestamp),
                    );
                }
                "r" | "rn" => {
                    // sent by server delay time ago
                    let sent = timestamp - delay;
                    sq.push(
                        TriggerEvent::NonPaddingSent {
                            bytes_sent: size as u16,
                        },
                        false,
                        sent,
                        integration_delay,
                        Reverse(sent),
                    );
                }
                _ => {
                    panic!("invalid direction")
                }
            }
        }
    }

    sq
}

#[test_log::test]
fn test_no_machine() {
    let input = "0,sn,100 18,sn,200 25,rn,300 25,rn,300 30,sn,500 35,rn,600";
    // client
    run_test_sim(
        input,
        input,
        Duration::from_micros(5),
        &[],
        &[],
        true,
        0,
        false,
    );
    // server
    run_test_sim(
        input,
        "5,rn,100 20,sn,300 20,sn,300 23,rn,200 30,sn,600 35,rn,500",
        Duration::from_micros(5),
        &[],
        &[],
        false,
        0,
        false,
    );
}

#[test_log::test]
fn test_simple_pad_machine() {
    // a simple machine that pads every 8us
    let num_states = 2;
    let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    let mut e: HashMap<usize, f64> = HashMap::new();
    e.insert(1, 1.0);
    t.insert(Event::NonPaddingSent, e);
    let s0 = State::new(t, num_states);
    let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    let mut e: HashMap<usize, f64> = HashMap::new();
    e.insert(1, 1.0);
    t.insert(Event::PaddingSent, e);
    let mut s1 = State::new(t, num_states);
    s1.timeout = Dist {
        dist: DistType::Uniform,
        param1: 8.0,
        param2: 8.0,
        start: 0.0,
        max: 0.0,
    };
    let m = Machine {
        allowed_padding_bytes: 10000,
        max_padding_frac: 1.0,
        allowed_blocked_microsec: 0,
        max_blocking_frac: 0.0,
        states: vec![s0, s1],
        include_small_packets: true,
    };

    // client machine and client output
    run_test_sim(
        "0,sn,100 18,sn,200 25,rn,300 25,rn,300 30,sn,500 35,rn,600",
        "0,sn,100 8,sp,1420 16,sp,1420 18,sn,200 24,sp,1420 25,rn,300 25,rn,300 30,sn,500 32,sp,1420 35,rn,600",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        20,
        false,
    );

    // client machine and server output
    run_test_sim(
        "0,sn,100 18,sn,200 25,rn,300 25,rn,300 30,sn,500 35,rn,600",
        "5,rn,100 13,rp,1420 20,sn,300 20,sn,300 21,rp,1420 23,rn,200 29,rp,1420 30,sn,600 35,rn,500 37,rp,1420 45,rp,1420",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        false,
        50,
        false,
    );

    // server machine and client output
    run_test_sim(
        "0,sn,100 18,sn,200 25,rn,300 25,rn,300 30,sn,500 35,rn,600",
        "0,sn,100 18,sn,200 25,rn,300 25,rn,300 30,sn,500 33,rp,1420 35,rn,600",
        Duration::from_micros(5),
        &[],
        &[m.clone()],
        true,
        30,
        false,
    );

    // server machine and server output
    run_test_sim(
        "0,sn,100 18,sn,200 25,rn,300 25,rn,300 30,sn,500 35,rn,600",
        "5,rn,100 20,sn,300 20,sn,300 23,rn,200 28,sp,1420 30,sn,600 35,rn,500 36,sp,1420 44,sp,1420",
        Duration::from_micros(5),
        &[],
        &[m],
        false,
        30,
        false,
    );
}

#[test_log::test]
fn test_simple_block_machine() {
    // a simple machine that waits for 5us, blocks for 5us, and then repeats forever
    let num_states = 2;
    let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    let mut e: HashMap<usize, f64> = HashMap::new();
    e.insert(1, 1.0);
    t.insert(Event::NonPaddingSent, e);
    let s0 = State::new(t, num_states);
    let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    let mut e: HashMap<usize, f64> = HashMap::new();
    e.insert(1, 1.0);
    t.insert(Event::BlockingEnd, e);
    let mut s1 = State::new(t, num_states);
    s1.timeout = Dist {
        dist: DistType::Uniform,
        param1: 5.0,
        param2: 5.0,
        start: 0.0,
        max: 0.0,
    };
    s1.action = Dist {
        dist: DistType::Uniform,
        param1: 5.0,
        param2: 5.0,
        start: 0.0,
        max: 0.0,
    };
    s1.action_is_block = true;
    let m = Machine {
        allowed_padding_bytes: 0,
        max_padding_frac: 0.0,
        allowed_blocked_microsec: 1000,
        max_blocking_frac: 1.0,
        states: vec![s0, s1],
        include_small_packets: true,
    };

    // client
    // note in the output how 18,sn,200 should be delayed until 20,sn,200 due to blocking
    run_test_sim(
        "0,sn,100 18,sn,200 25,rn,300 25,rn,300 30,sn,500 35,rn,600",
        "0,sn,100 5,bb 10,be 15,bb 20,sn,200 20,be 25,rn,300 25,rn,300 25,bb 30,sn,500 30,be 35,rn,600 35,bb",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        100,
        false,
    );

    // server
    run_test_sim(
        "0,sn,100 18,sn,200 25,rn,300 25,rn,300 30,sn,500 35,rn,600",
        "5,rn,100 20,sn,300 20,sn,300 23,rn,200 25,bb 30,sn,600 30,be 35,rn,500 35,bb 40,be",
        Duration::from_micros(5),
        &[],
        &[m.clone()],
        false,
        100,
        false,
    );
}

#[test_log::test]
fn test_both_block_machine() {
    // a simple machine that waits for 5us, blocks for 5us, and then repeats forever
    let num_states = 2;
    let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    let mut e: HashMap<usize, f64> = HashMap::new();
    e.insert(1, 1.0);
    t.insert(Event::NonPaddingSent, e);
    let s0 = State::new(t, num_states);
    let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    let mut e: HashMap<usize, f64> = HashMap::new();
    e.insert(1, 1.0);
    t.insert(Event::BlockingEnd, e);
    let mut s1 = State::new(t, num_states);
    s1.timeout = Dist {
        dist: DistType::Uniform,
        param1: 5.0,
        param2: 5.0,
        start: 0.0,
        max: 0.0,
    };
    s1.action = Dist {
        dist: DistType::Uniform,
        param1: 5.0,
        param2: 5.0,
        start: 0.0,
        max: 0.0,
    };
    s1.action_is_block = true;
    let client = Machine {
        allowed_padding_bytes: 0,
        max_padding_frac: 0.0,
        allowed_blocked_microsec: 1000,
        max_blocking_frac: 1.0,
        states: vec![s0, s1],
        include_small_packets: true,
    };

    let server = client.clone();

    run_test_sim(
        "0,sn,100 7,rn,150 8,sn,200 14,rn,250 18,sn,300",
        "0,sn,100 5,bb 7,rn,150 10,sn,200 10,be 15,bb 17,rn,250 20,sn,300 20,be",
        Duration::from_micros(5),
        &[client],
        &[server],
        true,
        50,
        false,
    );
}

#[test_log::test]
fn test_blockpadding() {
    // a simple machine that blocks for 10us, then queues up 3 padding
    // packets that should be blocked
    let num_states = 3;
    let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    let mut e: HashMap<usize, f64> = HashMap::new();
    e.insert(1, 1.0);
    t.insert(Event::NonPaddingSent, e);
    let s0 = State::new(t, num_states);
    let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    let mut e: HashMap<usize, f64> = HashMap::new();
    e.insert(2, 1.0);
    t.insert(Event::BlockingBegin, e);
    let mut s1 = State::new(t, num_states);
    s1.timeout = Dist {
        dist: DistType::Uniform,
        param1: 5.0,
        param2: 5.0,
        start: 0.0,
        max: 0.0,
    };
    s1.action = Dist {
        dist: DistType::Uniform,
        param1: 10.0,
        param2: 10.0,
        start: 0.0,
        max: 0.0,
    };
    s1.action_is_block = true;
    let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    let mut e: HashMap<usize, f64> = HashMap::new();
    e.insert(2, 1.0);
    t.insert(Event::PaddingSent, e);
    let mut s2 = State::new(t, num_states);
    s2.timeout = Dist {
        dist: DistType::Uniform,
        param1: 1.0,
        param2: 1.0,
        start: 0.0,
        max: 0.0,
    };
    s2.limit = Dist {
        dist: DistType::Uniform,
        param1: 3.0,
        param2: 3.0,
        start: 0.0,
        max: 0.0,
    };
    let m = Machine {
        allowed_padding_bytes: 10000,
        max_padding_frac: 1.0,
        allowed_blocked_microsec: 1000,
        max_blocking_frac: 1.0,
        states: vec![s0, s1, s2],
        include_small_packets: true,
    };

    // client
    run_test_sim(
        "0,sn,100 6,rn,200 14,sn,300",
        "0,sn,100 5,bb 6,rn,200 15,sp,1420 15,sn,300 15,be 16,sp,1420 17,sp,1420",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        20,
        false,
    );

    // server log of client machine
    run_test_sim(
        "0,sn,100 6,rn,200 14,sn,300",
        "1,sn,200 5,rn,100 20,rp,1420 20,rn,300 21,rp,1420 22,rp,1420",
        Duration::from_micros(5),
        &[m],
        &[],
        false,
        20,
        false,
    );
}

#[test_log::test]
fn test_bypass_machine() {
    // a simple machine that blocks for 10us, then queues up 3 padding
    // packets that should NOT be blocked (bypass block and padding)
    let num_states = 3;
    let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    let mut e: HashMap<usize, f64> = HashMap::new();
    e.insert(1, 1.0);
    t.insert(Event::NonPaddingSent, e);
    let s0 = State::new(t, num_states);
    let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    let mut e: HashMap<usize, f64> = HashMap::new();
    e.insert(2, 1.0);
    t.insert(Event::BlockingBegin, e);
    let mut s1 = State::new(t, num_states);
    s1.timeout = Dist {
        dist: DistType::Uniform,
        param1: 5.0,
        param2: 5.0,
        start: 0.0,
        max: 0.0,
    };
    s1.action = Dist {
        dist: DistType::Uniform,
        param1: 10.0,
        param2: 10.0,
        start: 0.0,
        max: 0.0,
    };
    s1.action_is_block = true;
    s1.bypass = true;
    let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    let mut e: HashMap<usize, f64> = HashMap::new();
    e.insert(2, 1.0);
    t.insert(Event::PaddingSent, e);
    let mut s2 = State::new(t, num_states);
    s2.timeout = Dist {
        dist: DistType::Uniform,
        param1: 1.0,
        param2: 1.0,
        start: 0.0,
        max: 0.0,
    };
    s2.limit = Dist {
        dist: DistType::Uniform,
        param1: 3.0,
        param2: 3.0,
        start: 0.0,
        max: 0.0,
    };
    s2.bypass = true;
    let mut m = Machine {
        allowed_padding_bytes: 10000,
        max_padding_frac: 1.0,
        allowed_blocked_microsec: 1000,
        max_blocking_frac: 1.0,
        states: vec![s0, s1, s2],
        include_small_packets: true,
    };

    // client
    run_test_sim(
        "0,sn,100 6,rn,200 14,sn,300",
        "0,sn,100 5,bb 6,rn,200 6,sp,1420 7,sp,1420 8,sp,1420 15,sn,300 15,be",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        20,
        false,
    );

    // server log of client machine
    run_test_sim(
        "0,sn,100 6,rn,200 14,sn,300",
        "1,sn,200 5,rn,100 11,rp,1420 12,rp,1420 13,rp,1420 20,rn,300",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        false,
        20,
        false,
    );

    // make the blocking not bypassable
    m.states[1].bypass = false;

    // client
    run_test_sim(
        "0,sn,100 6,rn,200 14,sn,300",
        "0,sn,100 5,bb 6,rn,200 15,sp,1420 15,sn,300 15,be 16,sp,1420 17,sp,1420",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        20,
        false,
    );

    // server log of client machine
    run_test_sim(
        "0,sn,100 6,rn,200 14,sn,300",
        "1,sn,200 5,rn,100 20,rp,1420 20,rn,300 21,rp,1420 22,rp,1420",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        false,
        20,
        false,
    );

    // make the blocking bypassable but the padding not
    m.states[1].bypass = true;
    m.states[2].bypass = false;

    // client
    run_test_sim(
        "0,sn,100 6,rn,200 14,sn,300",
        "0,sn,100 5,bb 6,rn,200 15,sp,1420 15,sn,300 15,be 16,sp,1420 17,sp,1420",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        20,
        false,
    );

    // server log of client machine
    run_test_sim(
        "0,sn,100 6,rn,200 14,sn,300",
        "1,sn,200 5,rn,100 20,rp,1420 20,rn,300 21,rp,1420 22,rp,1420",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        false,
        20,
        false,
    );

    // make the blocking not bypassable but the padding is
    m.states[1].bypass = false;
    m.states[2].bypass = true;

    // client
    run_test_sim(
        "0,sn,100 6,rn,200 14,sn,300",
        "0,sn,100 5,bb 6,rn,200 15,sp,1420 15,sn,300 15,be 16,sp,1420 17,sp,1420",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        20,
        false,
    );

    // server log of client machine
    run_test_sim(
        "0,sn,100 6,rn,200 14,sn,300",
        "1,sn,200 5,rn,100 20,rp,1420 20,rn,300 21,rp,1420 22,rp,1420",
        Duration::from_micros(5),
        &[m],
        &[],
        false,
        20,
        false,
    );
}

#[test_log::test]
fn test_replace_machine() {
    // test replace within the network replace window

    // a simple machine that pads every 2us six times
    let num_states = 2;
    let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    let mut e: HashMap<usize, f64> = HashMap::new();
    e.insert(1, 1.0);
    t.insert(Event::NonPaddingSent, e);
    let s0 = State::new(t, num_states);
    let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    let mut e: HashMap<usize, f64> = HashMap::new();
    e.insert(1, 1.0);
    t.insert(Event::PaddingSent, e);
    let mut s1 = State::new(t, num_states);
    s1.timeout = Dist {
        dist: DistType::Uniform,
        param1: 2.0,
        param2: 2.0,
        start: 0.0,
        max: 0.0,
    };
    s1.limit = Dist {
        dist: DistType::Uniform,
        param1: 6.0,
        param2: 6.0,
        start: 0.0,
        max: 0.0,
    };
    s1.action = Dist {
        dist: DistType::Uniform,
        param1: 200.0,
        param2: 200.0,
        start: 0.0,
        max: 0.0,
    };

    let mut m = Machine {
        allowed_padding_bytes: 10000,
        max_padding_frac: 1.0,
        allowed_blocked_microsec: 0,
        max_blocking_frac: 0.0,
        states: vec![s0, s1],
        include_small_packets: true,
    };

    // client machine and client output
    run_test_sim(
        "0,sn,100 4,sn,200 6,rn,300 6,rn,300 7,sn,500",
        "0,sn,100 2,sp,200 4,sn,200 4,sp,200 6,rn,300 6,rn,300 6,sp,200 7,sn,500",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        40,
        true,
    );
    // client machine and server output
    run_test_sim(
        "0,sn,100 4,sn,200 6,rn,300 6,rn,300 7,sn,500",
        "1,sn,300 1,sn,300 5,rn,100 7,rp,200 9,rp,200 9,rn,200",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        false,
        40,
        true,
    );

    // with replace, one padding packet is replaced at 4,sp,200
    m.states[1].replace = true;

    // client machine and client output
    run_test_sim(
        "0,sn,100 4,sn,200 6,rn,300 6,rn,300 7,sn,500",
        "0,sn,100 2,sp,200 4,sn,200 6,rn,300 6,rn,300 6,sp,200 7,sn,500",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        40,
        true,
    );
    // client machine and server output
    run_test_sim(
        "0,sn,100 4,sn,200 6,rn,300 6,rn,300 7,sn,500",
        "1,sn,300 1,sn,300 5,rn,100 7,rp,200 9,rn,200",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        false,
        40,
        true,
    );

    // we make the machine pad once every 1us, and disable replace
    m.states[1].timeout = Dist {
        dist: DistType::Uniform,
        param1: 1.0,
        param2: 1.0,
        start: 0.0,
        max: 0.0,
    };
    m.states[1].replace = false;
    // client machine and client output
    run_test_sim(
        "0,sn,100 4,sn,200 6,rn,300 6,rn,300 7,sn,500",
        "0,sn,100 1,sp,200 2,sp,200 3,sp,200 4,sn,200 4,sp,200 5,sp,200 6,rn,300 6,rn,300 6,sp,200 7,sn,500",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        40,
        true,
    );
    // enable replace again
    m.states[1].replace = true;
    // client machine and client output
    run_test_sim(
        "0,sn,100 4,sn,200 6,rn,300 6,rn,300 7,sn,500",
        // padding at 1us is replaced by 0,sn,200
        // padding at 3us is replaced by 2,sn,200
        // padding at 4us is replaced by 4,sn,200
        // padding at 5us is replaced by 4,sn,200
        "0,sn,100 2,sp,200 4,sn,200 6,rn,300 6,rn,300 6,sp,200 7,sn,500",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        40,
        true,
    );
    m.states[1].timeout = Dist {
        dist: DistType::Uniform,
        param1: 0.0,
        param2: 0.0,
        start: 0.0,
        max: 0.0,
    };
    // client machine and client output
    run_test_sim(
        "0,sn,100 4,sn,200 6,rn,300 6,rn,300 7,sn,500",
        "0,sn,100 4,sn,200 6,rn,300 6,rn,300 7,sn,500",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        40,
        true,
    );
    run_test_sim(
        "0,sn,100 4,sn,200 6,rn,300 6,rn,300 7,sn,500",
        "0,sn,100 0,sp,200 0,sp,200 0,sp,200 0,sp,200 0,sp,200 0,sp,200 4,sn,200 6,rn,300 6,rn,300 7,sn,500",
        Duration::from_micros(5),
        &[m],
        &[],
        true,
        40,
        false,
    );
}

#[test_log::test]
fn test_bypass_replace_machine() {
    // test a machine that uses bypass and replace to construct a client-side
    // constant-rate defense

    let num_states = 3;
    // 0->1 on NonPaddingSent
    let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    let mut e: HashMap<usize, f64> = HashMap::new();
    e.insert(1, 1.0);
    t.insert(Event::NonPaddingSent, e);
    let s0 = State::new(t, num_states);
    // 1: block for 1000us after 1us, bypassable
    // 1->2 on BlockingBegin
    let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    let mut e: HashMap<usize, f64> = HashMap::new();
    e.insert(2, 1.0);
    t.insert(Event::BlockingBegin, e);
    let mut s1 = State::new(t, num_states);
    s1.action_is_block = true;
    s1.timeout = Dist {
        dist: DistType::Uniform,
        param1: 1.0,
        param2: 1.0,
        start: 0.0,
        max: 0.0,
    };
    s1.action = Dist {
        dist: DistType::Uniform,
        param1: 1000.0,
        param2: 1000.0,
        start: 0.0,
        max: 0.0,
    };
    // 2: send padding every 2us, 3 times
    let mut t: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    let mut e: HashMap<usize, f64> = HashMap::new();
    e.insert(2, 1.0);
    t.insert(Event::PaddingSent, e);
    let mut s2 = State::new(t, num_states);
    s2.timeout = Dist {
        dist: DistType::Uniform,
        param1: 2.0,
        param2: 2.0,
        start: 0.0,
        max: 0.0,
    };
    s2.limit = Dist {
        dist: DistType::Uniform,
        param1: 3.0,
        param2: 3.0,
        start: 0.0,
        max: 0.0,
    };

    let mut m = Machine {
        allowed_padding_bytes: 10000,
        max_padding_frac: 1.0,
        allowed_blocked_microsec: 10000,
        max_blocking_frac: 0.0,
        states: vec![s0, s1, s2],
        include_small_packets: true,
    };

    // client, without any bypass or replace
    run_test_sim(
        "0,sn,100 4,sn,1420 6,rn,300 6,rn,300 7,sn,500",
        "0,sn,100 1,bb 6,rn,300 6,rn,300 1001,sp,1420 1001,sn,1420 1001,sn,500 1001,be 1003,sp,1420",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        40,
        false,
    );

    // client, with bypass
    m.states[1].bypass = true;
    m.states[2].bypass = true;
    run_test_sim(
        "0,sn,100 4,sn,1420 6,rn,300 6,rn,300 7,sn,500",
        "0,sn,100 1,bb 3,sp,1420 5,sp,1420 6,rn,300 6,rn,300 7,sp,1420 1001,sn,1420 1001,sn,500 1001,be",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        40,
        false,
    );
    // client, with bypass and only packets on wire
    run_test_sim(
        "0,sn,100 4,sn,1420 6,rn,300 6,rn,300 7,sn,500",
        "0,sn,100 3,sp,1420 5,sp,1420 6,rn,300 6,rn,300 7,sp,1420 1001,sn,1420 1001,sn,500",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        40,
        true, // NOTE only packets  as-is on the wire
    );

    // client, with bypass and replace, only packets on wire
    m.states[2].replace = true;
    run_test_sim(
        "0,sn,1420 4,sn,1420 6,rn,1420 6,rn,1420 7,sn,1420",
        // sp 3 is replaced by sn 3, then sp at 7 replaced by sn 7
        "0,sn,1420 3,sn,1420 5,sp,1420 6,rn,1420 6,rn,1420 7,sn,1420",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        40,
        true, // NOTE only packets as-is on the wire
    );

    // client, with bypass and replace, events as seen by framework
    run_test_sim(
        "0,sn,1420 4,sn,1420 6,rn,1420 6,rn,1420 7,sn,1420",
        // wuth all events, we also get SP events and blocking events
        "0,sn,1420 1,bb 3,sp,1420 3,sn,1420 5,sp,1420 6,rn,1420 6,rn,1420 7,sp,1420 7,sn,1420 1001,be",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        40,
        false, // NOTE false, all events
    );

    // another important detail: the window is 1us, what about non-padding
    // packets queued up earlier than that?  They should also replace padding
    run_test_sim(
        "0,sn,1420 2,sn,1420 2,sn,1420 6,rn,1420 6,rn,1420 7,sn,1420",
        "0,sn,1420 3,sn,1420 5,sn,1420 6,rn,1420 6,rn,1420 7,sn,1420",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        40,
        true, // only packets
    );
    run_test_sim(
        "0,sn,1420 2,sn,1420 2,sn,1420 6,rn,1420 6,rn,1420 7,sn,1420",
        // wuth all events, we also get SP events and blocking events
        "0,sn,1420 1,bb 3,sp,1420 3,sn,1420 5,sp,1420 5,sn,1420 6,rn,1420 6,rn,1420 7,sp,1420 7,sn,1420 1001,be",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        40,
        false, // all events
    );

    // same as above, we just queue up more packets: note that the machine above
    // only does 3 padding packets due to limit
    run_test_sim(
        "0,sn,1420 2,sn,1420 2,sn,1420 2,sn,1420 2,sn,1420 6,rn,1420 6,rn,1420 7,sn,1420",
        "0,sn,1420 3,sn,1420 5,sn,1420 6,rn,1420 6,rn,1420 7,sn,1420 1001,sn,1420 1001,sn,1420",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        40,
        true, // only packets
    );
    // bump the limit to 5
    m.states[2].limit = Dist {
        dist: DistType::Uniform,
        param1: 5.0,
        param2: 5.0,
        start: 0.0,
        max: 0.0,
    };
    run_test_sim(
        "0,sn,1420 2,sn,1420 2,sn,1420 2,sn,1420 2,sn,1420 6,rn,1420 6,rn,1420 7,sn,1420",
        "0,sn,1420 3,sn,1420 5,sn,1420 6,rn,1420 6,rn,1420 7,sn,1420 9,sn,1420 11,sn,1420",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        40,
        true, // only packets
    );

    // we've been lazy so far, not checking the server
    run_test_sim(
        "0,sn,1420 2,sn,1420 2,sn,1420 2,sn,1420 2,sn,1420 6,rn,1420 6,rn,1420 7,sn,1420",
        "1,sn,1420 1,sn,1420 5,rn,1420 8,rn,1420 10,rn,1420 12,rn,1420 14,rn,1420 16,rn,1420",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        false, // server
        40,
        true, // only packets
    );
    run_test_sim(
        "0,sn,1420 2,sn,1420 2,sn,1420 2,sn,1420 2,sn,1420 6,rn,1420 6,rn,1420 7,sn,1420",
        "1,sn,1420 1,sn,1420 5,rn,1420 8,rn,1420 10,rn,1420 12,rn,1420 14,rn,1420 16,rn,1420",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        false, // server
        40,
        false, // all events
    );
}

#[test_log::test]
fn test_excessive_sim_delay() {
    const EARLY_TRACE: &str = include_str!("EARLY_TEST_TRACE.log");

    // start with a reasonable 10ms delay: we should get events at the client
    let network = Network::new(Duration::from_millis(10));
    let pq = parse_trace(EARLY_TRACE, &network);
    let trace = sim(&[], &[], &mut pq.clone(), network.delay, 10000, true);
    let client_trace = trace
        .clone()
        .into_iter()
        .filter(|t| t.client)
        .collect::<Vec<_>>();
    assert!(client_trace.len() > 0);

    // set a silly delay of 10s: this should result in zero events at the
    // client, because we hit the limit of events below before we get to the
    // first event at the client
    let network = Network::new(Duration::from_millis(10000));
    let pq = parse_trace(EARLY_TRACE, &network);
    let trace = sim(&[], &[], &mut pq.clone(), network.delay, 10000, true);
    let client_trace = trace
        .clone()
        .into_iter()
        .filter(|t| t.client)
        .collect::<Vec<_>>();
    assert!(client_trace.len() == 0);

    // increase the limit of events to 100000: this should result in all events
    let trace = sim(&[], &[], &mut pq.clone(), network.delay, 100000, true);
    let client_trace = trace
        .clone()
        .into_iter()
        .filter(|t| t.client)
        .collect::<Vec<_>>();
    // 21574 is the number of events in EARLY_TRACE
    assert_eq!(client_trace.len(), 21574);
}

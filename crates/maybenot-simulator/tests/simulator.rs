pub mod common;

use common::{run_test_sim, set_bypass, set_replace};

use std::time::Duration;

use maybenot::{
    action::Action,
    counter::{Counter, Operation},
    dist::{Dist, DistType},
    event::Event,
    state::{State, Trans},
    Machine, Timer,
};

use enum_map::enum_map;

#[test_log::test]
fn test_no_machine() {
    let input = "0,sn 18,sn 25,rn 25,rn 30,sn 35,rn";
    // client
    run_test_sim(
        input,
        "0,st 18,st 25,rt 25,rt 30,st 35,rt",
        Duration::from_micros(5),
        &[],
        &[],
        true,
        0,
        true,
        false,
    );
    // server
    run_test_sim(
        input,
        "5,rt 20,st 20,st 23,rt 30,st 35,rt",
        Duration::from_micros(5),
        &[],
        &[],
        false,
        0,
        true,
        false,
    );
}

#[test_log::test]
fn test_simple_pad_machine() {
    // a simple machine that pads every 8us
    let s0 = State::new(enum_map! {
        Event::NormalSent => vec![Trans(1, 1.0)],
        _ => vec![],
    });
    let mut s1 = State::new(enum_map! {
        Event::PaddingSent => vec![Trans(1, 1.0)],
        _ => vec![],
    });
    s1.action = Some(Action::SendPadding {
        bypass: false,
        replace: false,
        timeout: Dist {
            dist: DistType::Uniform {
                low: 8.0,
                high: 8.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    let m = Machine::new(0, 1.0, 0, 1.0, vec![s0, s1]).unwrap();

    // client machine and client output
    run_test_sim(
        "0,sn 18,sn 25,rn 25,rn 30,sn 35,rn",
        "0,sn 0,st 8,sp 8,st 16,sp 16,st 18,sn 18,st 24,sp 24,st 25,rt 25,rt 25,rn 25,rn 30,sn 30,st 32,sp 32,st 35,rt 35,rn",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        40,
        false,
        false,
    );

    // client machine and server output
    run_test_sim(
        "0,sn 18,sn 25,rn 25,rn 30,sn 35,rn",
        "5,rt 5,rn 13,rt 13,rp 20,sn 20,st 20,sn 20,st 21,rt 21,rp 23,rt 23,rn 29,rt 29,rp 30,sn 30,st 35,rt 35,rn 37,rt 37,rp 45,rt 45,rp",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        false,
        50,
        false,
        false,
    );

    // server machine and client output
    run_test_sim(
        "0,sn 18,sn 25,rn 25,rn 30,sn 35,rn",
        "0,sn 0,st 18,sn 18,st 25,rt 25,rt 25,rn 25,rn 30,sn 30,st 33,rt 33,rp 35,rt 35,rn",
        Duration::from_micros(5),
        &[],
        &[m.clone()],
        true,
        50,
        false,
        false,
    );

    // server machine and server output
    run_test_sim(
        "0,sn 18,sn 25,rn 25,rn 30,sn 35,rn",
        "5,rt 5,rn 20,sn 20,st 20,sn 20,st 23,rt 23,rn 28,sp 28,st 30,sn 30,st 35,rt 35,rn 36,sp 36,st 44,sp 44,st",
        Duration::from_micros(5),
        &[],
        &[m],
        false,
        100,
        false,
        false,
    );
}

#[test_log::test]
fn test_simple_block_machine() {
    // a simple machine that waits for 5us, blocks for 5us, and then repeats forever
    let s0 = State::new(enum_map! {
        Event::NormalSent => vec![Trans(1, 1.0)],
        _ => vec![],
    });

    let mut s1 = State::new(enum_map! {
        Event::BlockingEnd => vec![Trans(1, 1.0)],
        _ => vec![],
    });
    s1.action = Some(Action::BlockOutgoing {
        bypass: false,
        replace: false,
        timeout: Dist {
            dist: DistType::Uniform {
                low: 5.0,
                high: 5.0,
            },
            start: 0.0,
            max: 0.0,
        },
        duration: Dist {
            dist: DistType::Uniform {
                low: 5.0,
                high: 5.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    let m = Machine::new(0, 0.0, 0, 0.0, vec![s0, s1]).unwrap();

    // client
    // note in the output how 18,sn should be delayed until 20,sn due to blocking
    run_test_sim(
        "0,sn 18,sn 25,rn 25,rn 30,sn 35,rn",
        "0,sn 0,st 5,bb 10,be 15,bb 18,sn 20,be 20,st 25,rt 25,rt 25,rn 25,rn 25,bb 30,be 30,sn 30,st 35,rt 35,rn 35,bb",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        100,
        false,
        false,
    );

    // server
    run_test_sim(
        "0,sn 18,sn 25,rn 25,rn 30,sn 35,rn",
        "5,rt 5,rn 20,sn 20,st 20,sn 20,st 23,rt 23,rn 25,bb 30,be 30,sn 30,st 35,rt 35,rn 35,bb 40,be",
        Duration::from_micros(5),
        &[],
        &[m.clone()],
        false,
        100,
        false,
        false,
    );
}

#[test_log::test]
fn test_both_block_machine() {
    // a simple machine that waits for 5us, blocks for 5us, and then repeats forever
    let s0 = State::new(enum_map! {
        Event::NormalSent => vec![Trans(1, 1.0)],
        _ => vec![],
    });

    let mut s1 = State::new(enum_map! {
        Event::BlockingEnd => vec![Trans(1, 1.0)],
        _ => vec![],
    });
    s1.action = Some(Action::BlockOutgoing {
        bypass: false,
        replace: false,
        timeout: Dist {
            dist: DistType::Uniform {
                low: 5.0,
                high: 5.0,
            },
            start: 0.0,
            max: 0.0,
        },
        duration: Dist {
            dist: DistType::Uniform {
                low: 5.0,
                high: 5.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    let client = Machine::new(0, 0.0, 0, 0.0, vec![s0, s1]).unwrap();

    let server = client.clone();

    run_test_sim(
        "0,sn 7,rn 8,sn 14,rn 18,sn",
        // blocking starts client at 5, server at 7
        // client is blocked until 10, server until 12
        // the delay at client, from 8-10, adds delay 2 in effect at 10+3x5=25
        // at 12, blocking ends and the server sends queued from 9, adding 3 to delay
        // the blocking from the server goes into effect at 15, adding 3 to base delay
        // at 18,sn, we now have 3 base delay in total, so its turned into 21,sn
        "0,sn 0,st 5,bb 7,rt 7,rn 8,sn 10,be 10,st 15,bb 17,rt 17,rn 20,be 21,sn 21,st",
        Duration::from_micros(5),
        &[client],
        &[server],
        true,
        100,
        false,
        false,
    );
}

#[test_log::test]
fn test_block_and_padding() {
    // a simple machine that blocks for 10us, then queues up 3 padding
    // packets that should be blocked
    let s0 = State::new(enum_map! {
        Event::NormalSent => vec![Trans(1, 1.0)],
        _ => vec![],
    });
    let mut s1 = State::new(enum_map! {
        Event::BlockingBegin => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    s1.action = Some(Action::BlockOutgoing {
        bypass: false,
        replace: false,
        timeout: Dist {
            dist: DistType::Uniform {
                low: 5.0,
                high: 5.0,
            },
            start: 0.0,
            max: 0.0,
        },
        duration: Dist {
            dist: DistType::Uniform {
                low: 10.0,
                high: 10.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    let mut s2 = State::new(enum_map! {
        Event::PaddingSent => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    s2.action = Some(Action::SendPadding {
        bypass: false,
        replace: false,
        timeout: Dist {
            dist: DistType::Uniform {
                low: 1.0,
                high: 1.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: Some(Dist {
            dist: DistType::Uniform {
                low: 3.0,
                high: 3.0,
            },
            start: 0.0,
            max: 0.0,
        }),
    });
    let m = Machine::new(0, 0.0, 0, 0.0, vec![s0, s1, s2]).unwrap();

    // client
    run_test_sim(
        "0,sn 6,rn 14,sn",
        "0,sn 0,st 5,bb 6,rt 6,rn 6,sp 7,sp 8,sp 14,sn 15,be 15,st 15,st 15,st 15,st",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        20,
        false,
        false,
    );

    // server log of client machine
    run_test_sim(
        "0,sn 6,rn 14,sn",
        "1,sn 1,st 5,rt 5,rn 20,rt 20,rt 20,rt 20,rt 20,rn 20,rp 20,rp 20,rp",
        Duration::from_micros(5),
        &[m],
        &[],
        false,
        40,
        false,
        false,
    );
}

#[test_log::test]
fn test_bypass_machine() {
    // a simple machine that blocks for 10us, then queues up 3 padding
    // packets that should NOT be blocked (bypass block and padding)
    let s0 = State::new(enum_map! {
        Event::NormalSent => vec![Trans(1, 1.0)],
        _ => vec![],
    });
    let mut s1 = State::new(enum_map! {
        Event::BlockingBegin => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    s1.action = Some(Action::BlockOutgoing {
        bypass: true,
        replace: false,
        timeout: Dist {
            dist: DistType::Uniform {
                low: 5.0,
                high: 5.0,
            },
            start: 0.0,
            max: 0.0,
        },
        duration: Dist {
            dist: DistType::Uniform {
                low: 10.0,
                high: 10.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    let mut s2 = State::new(enum_map! {
        Event::PaddingSent => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    s2.action = Some(Action::SendPadding {
        bypass: true,
        replace: false,
        timeout: Dist {
            dist: DistType::Uniform {
                low: 1.0,
                high: 1.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: Some(Dist {
            dist: DistType::Uniform {
                low: 3.0,
                high: 3.0,
            },
            start: 0.0,
            max: 0.0,
        }),
    });
    let mut m = Machine::new(0, 0.0, 0, 0.0, vec![s0, s1, s2]).unwrap();

    // client
    run_test_sim(
        "0,sn 6,rn 14,sn",
        "0,sn 0,st 5,bb 6,rt 6,rn 6,sp 6,st 7,sp 7,st 8,sp 8,st 14,sn 15,be 15,st",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        40,
        false,
        false,
    );

    // server log of client machine
    run_test_sim(
        "0,sn 6,rn 14,sn",
        "1,sn 1,st 5,rt 5,rn 11,rt 11,rp 12,rt 12,rp 13,rt 13,rp 20,rt 20,rn",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        false,
        40,
        false,
        false,
    );

    // make the blocking not bypassable
    set_bypass(&mut m.states[1], false);

    // client
    run_test_sim(
        "0,sn 6,rn 14,sn",
        "0,sn 0,st 5,bb 6,rt 6,rn 6,sp 7,sp 8,sp 14,sn 15,be 15,st 15,st 15,st 15,st",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        40,
        false,
        false,
    );

    // server log of client machine
    run_test_sim(
        "0,sn 6,rn 14,sn",
        "1,sn 1,st 5,rt 5,rn 20,rt 20,rt 20,rt 20,rt 20,rn 20,rp 20,rp 20,rp",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        false,
        40,
        false,
        false,
    );

    // make the blocking bypassable but the padding not
    set_bypass(&mut m.states[1], true);
    set_bypass(&mut m.states[2], false);

    // client
    run_test_sim(
        "0,sn 6,rn 14,sn",
        "0,sn 0,st 5,bb 6,rt 6,rn 6,sp 7,sp 8,sp 14,sn 15,be 15,st 15,st 15,st 15,st",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        20,
        false,
        false,
    );

    // server log of client machine
    run_test_sim(
        "0,sn 6,rn 14,sn",
        "1,sn 1,st 5,rt 5,rn 20,rt 20,rt 20,rt 20,rt 20,rn 20,rp 20,rp 20,rp",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        false,
        40,
        false,
        false,
    );

    // make the blocking not bypassable but the padding is
    set_bypass(&mut m.states[1], false);
    set_bypass(&mut m.states[2], true);

    // client
    run_test_sim(
        "0,sn 6,rn 14,sn",
        "0,sn 0,st 5,bb 6,rt 6,rn 6,sp 7,sp 8,sp 14,sn 15,be 15,st 15,st 15,st 15,st",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        40,
        false,
        false,
    );

    // server log of client machine
    run_test_sim(
        "0,sn 6,rn 14,sn",
        "1,sn 1,st 5,rt 5,rn 20,rt 20,rt 20,rt 20,rt 20,rn 20,rp 20,rp 20,rp",
        Duration::from_micros(5),
        &[m],
        &[],
        false,
        40,
        false,
        false,
    );
}

#[test_log::test]
fn test_bypass_replace_machine() {
    // test a machine that uses bypass and replace to construct a client-side
    // constant-rate defense
    let s0 = State::new(enum_map! {
        Event::NormalSent => vec![Trans(1, 1.0)],
        _ => vec![],
    });
    // 1: block for 1000us after 1us, bypassable
    // 1->2 on BlockingBegin
    let mut s1 = State::new(enum_map! {
        Event::BlockingBegin => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    s1.action = Some(Action::BlockOutgoing {
        bypass: false,
        replace: false,
        timeout: Dist {
            dist: DistType::Uniform {
                low: 1.0,
                high: 1.0,
            },
            start: 0.0,
            max: 0.0,
        },
        duration: Dist {
            dist: DistType::Uniform {
                low: 1000.0,
                high: 1000.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    // 2: send padding every 2us, 3 times
    let mut s2 = State::new(enum_map! {
        Event::PaddingSent => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    s2.action = Some(Action::SendPadding {
        bypass: false,
        replace: false,
        timeout: Dist {
            dist: DistType::Uniform {
                low: 2.0,
                high: 2.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: Some(Dist {
            dist: DistType::Uniform {
                low: 3.0,
                high: 3.0,
            },
            start: 0.0,
            max: 0.0,
        }),
    });
    let mut m = Machine::new(0, 0.0, 0, 0.0, vec![s0, s1, s2]).unwrap();

    // client, without any bypass or replace
    run_test_sim(
        "0,sn 4,sn 6,rn 6,rn 7,sn",
        "0,sn 0,st 1,bb 3,sp 4,sn 5,sp 6,rt 6,rt 6,rn 6,rn 7,sn 7,sp 1001,be 1001,st 1001,st 1001,st 1001,st 1001,st",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        40,
        false,
        false,
    );

    // client, with bypass
    set_bypass(&mut m.states[1], true);
    set_bypass(&mut m.states[2], true);
    run_test_sim(
        "0,sn 4,sn 6,rn 6,rn 7,sn",
        "0,sn 0,st 1,bb 3,sp 3,st 4,sn 5,sp 5,st 6,rt 6,rt 6,rn 6,rn 7,sn 7,sp 7,st 1001,be 1001,st 1001,st",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        100,
        false,
        false,
    );
    // client, with bypass and only packets on wire
    run_test_sim(
        "0,sn 4,sn 6,rn 6,rn 7,sn",
        "0,st 3,st 5,st 6,rt 6,rt 7,st 1001,st 1001,st",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        40,
        true, // NOTE only packets as-is on the wire
        false,
    );

    // client, with bypass *and replace*, only packets on wire
    set_replace(&mut m.states[2], true);
    run_test_sim(
        "0,sn 4,sn 6,rn 6,rn 7,sn",
        // padding at 5us is replaced by sending queued up 4,sn, and padding at 7us is replaced by queued up 7,sn
        "0,st 3,st 5,st 6,rt 6,rt 7,st",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        100,
        true, // NOTE only packets as-is on the wire
        false,
    );

    // client, with bypass and replace, events as seen by framework
    run_test_sim(
        "0,sn 4,sn 6,rn 6,rn 7,sn",
        // with all events, we also get SP events and blocking events
        "0,sn 0,st 1,bb 3,sp 3,st 4,sn 5,sp 5,st 6,rt 6,rt 6,rn 6,rn 7,sn 7,sp 7,st 1001,be",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        40,
        false, // NOTE false, all events
        false,
    );

    // another important detail: the window is 1us, what about normal packets
    // queued up earlier than that?  They should also replace padding
    run_test_sim(
        "0,sn 2,sn 2,sn 6,rn 6,rn 7,sn",
        "0,st 3,st 5,st 6,rt 6,rt 7,st",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        40,
        true, // only packets
        false,
    );
    run_test_sim(
        "0,sn 2,sn 2,sn 6,rn 6,rn 7,sn",
        // with all events, we also get SP events and blocking events
        "0,sn 0,st 1,bb 2,sn 2,sn 3,sp 3,st 5,sp 5,st 6,rt 6,rt 6,rn 6,rn 7,sn 7,sp 7,st 1001,be",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        40,
        false, // all events
        false,
    );

    // same as above, we just queue up more packets: note that the machine above
    // only does 3 padding packets due to limit
    run_test_sim(
        "0,sn 2,sn 2,sn 2,sn 2,sn 6,rn 6,rn 7,sn",
        "0,st 3,st 5,st 6,rt 6,rt 7,st 1001,st 1001,st",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        40,
        true, // only packets
        false,
    );
    // bump the limit to 5
    if let Some(Action::SendPadding { ref mut limit, .. }) = m.states[2].action {
        *limit = Some(Dist {
            dist: DistType::Uniform {
                low: 5.0,
                high: 5.0,
            },
            start: 0.0,
            max: 0.0,
        });
    };
    run_test_sim(
        "0,sn 2,sn 2,sn 2,sn 2,sn 6,rn 6,rn 7,sn",
        "0,st 3,st 5,st 6,rt 6,rt 7,st 9,st 11,st",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        40,
        true, // only packets
        false,
    );

    // we've been lazy so far, not checking the server
    run_test_sim(
        "0,sn 2,sn 2,sn 2,sn 2,sn 6,rn 6,rn 7,sn",
        "1,st 1,st 5,rt 8,rt 10,rt 12,rt 14,rt 16,rt",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        false, // server
        40,
        true, // only packets
        false,
    );
    run_test_sim(
        "0,sn 2,sn 2,sn 2,sn 2,sn 6,rn 6,rn 7,sn",
        "1,sn 1,st 1,sn 1,st 5,rt 5,rn 8,rt 8,rn 10,rt 10,rn 12,rt 12,rn 14,rt 14,rn 16,rt 16,rn",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        false, // server
        40,
        false, // all events
        false,
    );
}

#[test_log::test]
fn test_timer_action_basic() {
    // a machine that starts a timer after sending a packet, and then sends a
    // packet after the timer ends
    let s0 = State::new(enum_map! {
        Event::NormalSent => vec![Trans(1, 1.0)],
        _ => vec![],
    });
    let mut s1 = State::new(enum_map! {
        Event::TimerBegin => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    s1.action = Some(Action::UpdateTimer {
        replace: false,
        duration: Dist {
            dist: DistType::Uniform {
                low: 2.0,
                high: 2.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    let s2 = State::new(enum_map! {
        Event::TimerEnd => vec![Trans(3, 1.0)],
        _ => vec![],
    });
    let mut s3 = State::new(enum_map! {
        _ => vec![],
    });
    s3.action = Some(Action::SendPadding {
        bypass: false,
        replace: false,
        timeout: Dist {
            dist: DistType::Uniform {
                low: 1.0,
                high: 1.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    let m = Machine::new(0, 0.0, 0, 0.0, vec![s0, s1, s2, s3]).unwrap();

    run_test_sim(
        "0,sn 3,sn 6,rn 6,rn 7,sn",
        "0,sn 0,st 0,tb 2,te 3,sn 3,st 3,sp 3,st 6,rt 6,rt 6,rn 6,rn 7,sn 7,st",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        100,
        false,
        false,
    );
}

#[test_log::test]
fn test_timer_action_longest() {
    // a machine that starts a timer after sending a packet, and then sends a
    // packet after the timer ends
    let s0 = State::new(enum_map! {
        Event::NormalSent => vec![Trans(1, 1.0)],
        _ => vec![],
    });
    let mut s1 = State::new(enum_map! {
        Event::TimerBegin => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    s1.action = Some(Action::UpdateTimer {
        replace: false,
        duration: Dist {
            dist: DistType::Uniform {
                low: 10.0,
                high: 10.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    let mut s2 = State::new(enum_map! {
        Event::TimerEnd => vec![Trans(3, 1.0)],
        _ => vec![],
    });
    s2.action = Some(Action::UpdateTimer {
        replace: false,
        duration: Dist {
            dist: DistType::Uniform {
                low: 2.0,
                high: 2.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    let mut s3 = State::new(enum_map! {
        _ => vec![],
    });
    s3.action = Some(Action::SendPadding {
        bypass: false,
        replace: false,
        timeout: Dist {
            dist: DistType::Uniform {
                low: 1.0,
                high: 1.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    let m = Machine::new(0, 0.0, 0, 0.0, vec![s0, s1, s2, s3]).unwrap();

    run_test_sim(
        "0,sn 3,sn 6,rn 6,rn 7,sn",
        "0,sn 0,st 0,tb 3,sn 3,st 6,rt 6,rt 6,rn 6,rn 7,sn 7,st 10,te 11,sp 11,st",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        100,
        false,
        false,
    );
}

#[test_log::test]
fn test_timer_action_replace() {
    // a machine that starts a timer after sending a packet, and then sends a
    // packet after the timer ends
    let s0 = State::new(enum_map! {
        Event::NormalSent => vec![Trans(1, 1.0)],
        _ => vec![],
    });
    let mut s1 = State::new(enum_map! {
        Event::TimerBegin => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    s1.action = Some(Action::UpdateTimer {
        replace: false,
        duration: Dist {
            dist: DistType::Uniform {
                low: 10.0,
                high: 10.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    let mut s2 = State::new(enum_map! {
        Event::TimerEnd => vec![Trans(3, 1.0)],
        _ => vec![],
    });
    s2.action = Some(Action::UpdateTimer {
        replace: true,
        duration: Dist {
            dist: DistType::Uniform {
                low: 2.0,
                high: 2.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    let mut s3 = State::new(enum_map! {
        _ => vec![],
    });
    s3.action = Some(Action::SendPadding {
        bypass: false,
        replace: false,
        timeout: Dist {
            dist: DistType::Uniform {
                low: 1.0,
                high: 1.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    let m = Machine::new(0, 0.0, 0, 0.0, vec![s0, s1, s2, s3]).unwrap();

    run_test_sim(
        "0,sn 3,sn 6,rn 6,rn 7,sn",
        "0,sn 0,st 0,tb 0,tb 2,te 3,sn 3,st 3,sp 3,st 6,rt 6,rt 6,rn 6,rn 7,sn 7,st",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        100,
        false,
        false,
    );
}

#[test_log::test]
fn test_action_cancel_timer_internal() {
    // start a padding action, start a timer, then cancel the timer yet observe
    // the padding
    let s0 = State::new(enum_map! {
        Event::NormalSent => vec![Trans(1, 1.0)],
        _ => vec![],
    });
    let mut s1 = State::new(enum_map! {
        Event::NormalSent => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    s1.action = Some(Action::SendPadding {
        bypass: false,
        replace: false,
        timeout: Dist {
            dist: DistType::Uniform {
                low: 4.0,
                high: 4.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    let mut s2 = State::new(enum_map! {
        Event::TimerBegin => vec![Trans(3, 1.0)],
        _ => vec![],
    });
    s2.action = Some(Action::UpdateTimer {
        replace: false,
        duration: Dist {
            dist: DistType::Uniform {
                low: 2.0,
                high: 2.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    let mut s3 = State::new(enum_map! {
        _ => vec![],
    });
    s3.action = Some(Action::Cancel {
        timer: Timer::Internal,
    });

    let m = Machine::new(0, 0.0, 0, 0.0, vec![s0, s1, s2, s3]).unwrap();

    run_test_sim(
        "0,sn 1,sn 6,rn 7,sn",
        "0,sn 0,st 1,sn 1,st 1,tb 4,sp 4,st 6,rt 6,rn 7,sn 7,st",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        100,
        false,
        false,
    );
}

#[test_log::test]
fn test_action_cancel_timer_action() {
    // start a padding action, start a timer, then cancel the action and observe
    // the time ending
    let s0 = State::new(enum_map! {
        Event::NormalSent => vec![Trans(1, 1.0)],
        _ => vec![],
    });
    let mut s1 = State::new(enum_map! {
        Event::NormalSent => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    s1.action = Some(Action::SendPadding {
        bypass: false,
        replace: false,
        timeout: Dist {
            dist: DistType::Uniform {
                low: 4.0,
                high: 4.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    let mut s2 = State::new(enum_map! {
        Event::TimerBegin => vec![Trans(3, 1.0)],
        _ => vec![],
    });
    s2.action = Some(Action::UpdateTimer {
        replace: false,
        duration: Dist {
            dist: DistType::Uniform {
                low: 2.0,
                high: 2.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    let mut s3 = State::new(enum_map! {
        _ => vec![],
    });
    s3.action = Some(Action::Cancel {
        timer: Timer::Action,
    });

    let m = Machine::new(0, 0.0, 0, 0.0, vec![s0, s1, s2, s3]).unwrap();

    run_test_sim(
        "0,sn 1,sn 6,rn 7,sn",
        "0,sn 0,st 1,sn 1,st 1,tb 3,te 6,rt 6,rn 7,sn 7,st",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        100,
        false,
        false,
    );
}

#[test_log::test]
fn test_action_cancel_timer_both() {
    // start a padding action, start a timer, then cancel both and observe
    // no padding and no timer ending
    let s0 = State::new(enum_map! {
        Event::NormalSent => vec![Trans(1, 1.0)],
        _ => vec![],
    });
    let mut s1 = State::new(enum_map! {
        Event::NormalSent => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    s1.action = Some(Action::SendPadding {
        bypass: false,
        replace: false,
        timeout: Dist {
            dist: DistType::Uniform {
                low: 4.0,
                high: 4.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    let mut s2 = State::new(enum_map! {
        Event::TimerBegin => vec![Trans(3, 1.0)],
        _ => vec![],
    });
    s2.action = Some(Action::UpdateTimer {
        replace: false,
        duration: Dist {
            dist: DistType::Uniform {
                low: 2.0,
                high: 2.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    let mut s3 = State::new(enum_map! {
        _ => vec![],
    });
    s3.action = Some(Action::Cancel { timer: Timer::All });

    let m = Machine::new(0, 0.0, 0, 0.0, vec![s0, s1, s2, s3]).unwrap();

    run_test_sim(
        "0,sn 1,sn 6,rn 7,sn",
        "0,sn 0,st 1,sn 1,st 1,tb 6,rt 6,rn 7,sn 7,st",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        100,
        false,
        false,
    );
}

#[test_log::test]
fn test_counter_machine() {
    // Add 5 to the counter in the first state, then subtract 2 in the second,
    // then subtract 1 in the third with self-transitions until we hit the
    // CounterZero event, then transition to the last 4th state
    let s0 = State::new(enum_map! {
        Event::NormalSent => vec![Trans(1, 1.0)],
        _ => vec![],
    });
    let mut s1 = State::new(enum_map! {
        Event::NormalRecv => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    s1.counter = (
        Some(Counter::new_dist(
            Operation::Increment,
            Dist {
                dist: DistType::Uniform {
                    low: 5.0,
                    high: 5.0,
                },
                start: 0.0,
                max: 0.0,
            },
        )),
        None,
    );
    let mut s2 = State::new(enum_map! {
        Event::NormalRecv => vec![Trans(3, 1.0)],
        _ => vec![],
    });
    s2.counter = (
        Some(Counter::new_dist(
            Operation::Decrement,
            Dist {
                dist: DistType::Uniform {
                    low: 2.0,
                    high: 2.0,
                },
                start: 0.0,
                max: 0.0,
            },
        )),
        None,
    );
    let mut s3 = State::new(enum_map! {
        Event::NormalSent => vec![Trans(3, 1.0)],
        Event::CounterZero => vec![Trans(4, 1.0)],
        _ => vec![],
    });
    s3.counter = (Some(Counter::new(Operation::Decrement)), None);
    let mut s4 = State::new(enum_map! {
        _ => vec![],
    });
    s4.action = Some(Action::SendPadding {
        bypass: false,
        replace: false,
        timeout: Dist {
            dist: DistType::Uniform {
                low: 3.0,
                high: 3.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    let mut m = Machine::new(0, 0.0, 0, 0.0, vec![s0, s1, s2, s3, s4]).unwrap();

    run_test_sim(
        "0,sn 6,rn 6,rn 7,sn 7,sn 7,sn",
        "0,sn 0,st 6,rt 6,rt 6,rn 6,rn 7,sn 7,st 7,sn 7,st 7,sn 7,st 10,sp 10,st",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        100,
        false,
        false,
    );

    // set counter in state 3 to Counter B, to prevent the CounterZero event
    // from firing
    m.states[3].counter = (None, Some(Counter::new(Operation::Decrement)));
    run_test_sim(
        "0,sn 6,rn 6,rn 7,sn 7,sn 7,sn",
        "0,sn 0,st 6,rt 6,rt 6,rn 6,rn 7,sn 7,st 7,sn 7,st 7,sn 7,st",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        100,
        false,
        false,
    );

    // update state 1 and 2 to also use Counter B
    m.states[1].counter = (
        None,
        Some(Counter::new_dist(
            Operation::Increment,
            Dist {
                dist: DistType::Uniform {
                    low: 5.0,
                    high: 5.0,
                },
                start: 0.0,
                max: 0.0,
            },
        )),
    );
    m.states[2].counter = (
        None,
        Some(Counter::new_dist(
            Operation::Decrement,
            Dist {
                dist: DistType::Uniform {
                    low: 2.0,
                    high: 2.0,
                },
                start: 0.0,
                max: 0.0,
            },
        )),
    );
    run_test_sim(
        "0,sn 6,rn 6,rn 7,sn 7,sn 7,sn",
        "0,sn 0,st 6,rt 6,rt 6,rn 6,rn 7,sn 7,st 7,sn 7,st 7,sn 7,st 10,sp 10,st",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        100,
        false,
        false,
    );

    // replace increment in state 1 with set operation, should make no difference
    m.states[1].counter = (
        None,
        Some(Counter::new_dist(
            Operation::Set,
            Dist {
                dist: DistType::Uniform {
                    low: 5.0,
                    high: 5.0,
                },
                start: 0.0,
                max: 0.0,
            },
        )),
    );
    run_test_sim(
        "0,sn 6,rn 6,rn 7,sn 7,sn 7,sn",
        "0,sn 0,st 6,rt 6,rt 6,rn 6,rn 7,sn 7,st 7,sn 7,st 7,sn 7,st 10,sp 10,st",
        Duration::from_micros(5),
        &[m.clone()],
        &[],
        true,
        100,
        false,
        false,
    );
}

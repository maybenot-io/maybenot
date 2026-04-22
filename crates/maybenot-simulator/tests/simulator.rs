pub mod common;

use common::{run_test_sim, set_bypass, set_replace};

use std::{slice, time::Duration};

use maybenot::{
    Machine, Timer,
    action::Action,
    counter::{Counter, Operation},
    dist::{Dist, DistType},
    event::Event,
    state::{State, Trans},
};

use enum_map::enum_map;

#[test_log::test]
fn test_no_machine() {
    let input = "0,nq 18,nq 25,nr 25,nr 30,nq 35,nr";
    // client
    run_test_sim(
        input,
        "0,ps 18,ps 25,pr 25,pr 30,ps 35,pr",
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
        "5,pr 20,ps 20,ps 23,pr 30,ps 35,pr",
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
fn test_simple_decoy_machine() {
    // a simple machine that sends a decoy every 8us
    let s0 = State::new(enum_map! {
        Event::NormalQueued => vec![Trans(1, 1.0)],
        _ => vec![],
    });
    let mut s1 = State::new(enum_map! {
        Event::DecoyQueued => vec![Trans(1, 1.0)],
        _ => vec![],
    });
    s1.action = Some(Action::DecoyTraffic {
        bypass: false,
        replace: false,
        n: Dist {
            dist: DistType::Uniform {
                low: 1.0,
                high: 1.0,
            },
            start: 0.0,
            max: 0.0,
        },
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
    let m = Machine::new(0, 0, vec![s0, s1]).unwrap();

    // client machine and client output
    run_test_sim(
        "0,nq 18,nq 25,nr 25,nr 30,nq 35,nr",
        "0,nq 0,ps 8,dq 8,ps 16,dq 16,ps 18,nq 18,ps 24,dq 24,ps 25,pr 25,pr 25,nr 25,nr 30,nq 30,ps 32,dq 32,ps 35,pr 35,nr",
        Duration::from_micros(5),
        slice::from_ref(&m),
        &[],
        true,
        40,
        false,
        false,
    );

    // client machine and server output
    run_test_sim(
        "0,nq 18,nq 25,nr 25,nr 30,nq 35,nr",
        "5,pr 5,nr 13,pr 13,dr 20,nq 20,ps 20,nq 20,ps 21,pr 21,dr 23,pr 23,nr 29,pr 29,dr 30,nq 30,ps 35,pr 35,nr",
        // previous netsim output below, included packet at the end which are not "normal" packets
        //"5,pr 5,nr 13,pr 13,dr 20,nq 20,ps 20,nq 20,ps 21,pr 21,dr 23,pr 23,nr 29,pr 29,dr 30,nq 30,ps 35,pr 35,nr 37,pr 37,dr",
        Duration::from_micros(5),
        slice::from_ref(&m),
        &[],
        false,
        50,
        false,
        false,
    );

    // server machine and client output
    run_test_sim(
        "0,nq 18,nq 25,nr 25,nr 30,nq 35,nr",
        "0,nq 0,ps 18,nq 18,ps 25,pr 25,pr 25,nr 25,nr 30,nq 30,ps 33,pr 33,dr 35,pr 35,nr",
        Duration::from_micros(5),
        &[],
        slice::from_ref(&m),
        true,
        50,
        false,
        false,
    );

    // server machine and server output
    run_test_sim(
        "0,nq 18,nq 25,nr 25,nr 30,nq 35,nr",
        "5,pr 5,nr 20,nq 20,ps 20,nq 20,ps 23,pr 23,nr 28,dq 28,ps 30,nq 30,ps 35,pr 35,nr",
        // previous netsim output below, included packet at the end which are not "normal" packets
        //"5,pr 5,nr 20,nq 20,ps 20,nq 20,ps 23,pr 23,nr 28,dq 28,ps 30,nq 30,ps 35,pr 35,nr 36,dq 36,ps",
        Duration::from_micros(5),
        &[],
        &[m],
        false,
        50,
        false,
        false,
    );
}

#[test_log::test]
fn test_simple_delay_machine() {
    // a simple machine that waits for 5us, delays for 5us, and then repeats forever
    let s0 = State::new(enum_map! {
        Event::NormalQueued => vec![Trans(1, 1.0)],
        _ => vec![],
    });

    let mut s1 = State::new(enum_map! {
        Event::DelayEnd => vec![Trans(1, 1.0)],
        _ => vec![],
    });
    s1.action = Some(Action::DelayTraffic {
        bypass: false,
        replace: false,
        n: Dist {
            dist: DistType::Uniform {
                low: 100.0,
                high: 100.0,
            },
            start: 0.0,
            max: 0.0,
        },
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
    let m = Machine::new(0, 0, vec![s0, s1]).unwrap();

    // client
    // note in the output how 18,nq should be delayed until 20,nq due to delay
    run_test_sim(
        "0,nq 18,nq 25,nr 25,nr 30,nq 35,nr",
        "0,nq 0,ps 5,db 10,de 15,db 18,nq 20,de 20,ps 25,pr 25,pr 25,nr 25,nr 25,db 30,de 30,nq 30,ps 35,pr 35,nr",
        // previous netsim output below, included packet at the end which are not "normal" packets
        //"0,nq 0,ps 5,db 10,de 15,db 18,nq 20,de 20,ps 25,pr 25,pr 25,nr 25,nr 25,db 30,de 30,nq 30,ps 35,pr 35,nr 35,db",
        Duration::from_micros(5),
        slice::from_ref(&m),
        &[],
        true,
        100,
        false,
        false,
    );

    // server
    run_test_sim(
        "0,nq 18,nq 25,nr 25,nr 30,nq 35,nr",
        "5,pr 5,nr 20,nq 20,ps 20,nq 20,ps 23,pr 23,nr 25,db 30,de 30,nq 30,ps 35,pr 35,nr",
        // previous netsim output below, included packet at the end which are not "normal" packets
        //"5,pr 5,nr 20,nq 20,ps 20,nq 20,ps 23,pr 23,nr 25,db 30,de 30,nq 30,ps 35,pr 35,nr 35,db 40,de",
        Duration::from_micros(5),
        &[],
        slice::from_ref(&m),
        false,
        100,
        false,
        false,
    );
}

#[test_log::test]
fn test_both_delay_machine() {
    // a simple machine that waits for 5us, delays for 5us, and then repeats forever
    let s0 = State::new(enum_map! {
        Event::NormalQueued => vec![Trans(1, 1.0)],
        _ => vec![],
    });

    let mut s1 = State::new(enum_map! {
        Event::DelayEnd => vec![Trans(1, 1.0)],
        _ => vec![],
    });
    s1.action = Some(Action::DelayTraffic {
        bypass: false,
        replace: false,
        n: Dist {
            dist: DistType::Uniform {
                low: 100.0,
                high: 100.0,
            },
            start: 0.0,
            max: 0.0,
        },
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
    let client = Machine::new(0, 0, vec![s0, s1]).unwrap();

    let server = client.clone();

    run_test_sim(
        "0,nq 7,nr 8,nq 14,nr 18,nq",
        // delay starts client at 5, server at 7
        // client is delayed until 10, server until 12
        // the delay at client, from 8-10, adds delay 2 in effect at 10+3x5=25
        // at 12, delay ends and the server sends queued from 9, adding 3 to delay
        // the delay from the server goes into effect at 15, adding 3 to base delay
        // at 18,nq, we now have 3 base delay in total, so its turned into 21,nq
        "0,nq 0,ps 5,db 7,pr 7,nr 8,nq 10,de 10,ps 15,db 17,pr 17,nr 20,de 21,nq 21,ps",
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
fn test_delay_and_decoy() {
    // a simple machine that delays for 10us, then queues up 3 decoy packets
    // that should be delayed
    let s0 = State::new(enum_map! {
        Event::NormalQueued => vec![Trans(1, 1.0)],
        _ => vec![],
    });
    let mut s1 = State::new(enum_map! {
        Event::DelayBegin => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    s1.action = Some(Action::DelayTraffic {
        bypass: false,
        replace: false,
        n: Dist {
            dist: DistType::Uniform {
                low: 100.0,
                high: 100.0,
            },
            start: 0.0,
            max: 0.0,
        },
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
        Event::DecoyQueued => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    s2.action = Some(Action::DecoyTraffic {
        bypass: false,
        replace: false,
        n: Dist {
            dist: DistType::Uniform {
                low: 1.0,
                high: 1.0,
            },
            start: 0.0,
            max: 0.0,
        },
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
    let m = Machine::new(0, 0, vec![s0, s1, s2]).unwrap();

    // client
    run_test_sim(
        "0,nq 6,nr 14,nq",
        "0,nq 0,ps 5,db 6,pr 6,nr 6,dq 7,dq 8,dq 14,nq 15,de 15,ps 15,ps 15,ps 15,ps",
        Duration::from_micros(5),
        slice::from_ref(&m),
        &[],
        true,
        20,
        false,
        false,
    );

    // server log of client machine
    run_test_sim(
        "0,nq 6,nr 14,nq",
        "1,nq 1,ps 5,pr 5,nr 20,pr 20,pr 20,pr 20,pr 20,nr",
        // previous netsim output below, included packet at the end which are not "normal"
        //"1,nq 1,ps 5,pr 5,nr 20,pr 20,pr 20,pr 20,pr 20,nr 20,dr 20,dr 20,dr",
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
    // a simple machine that delays for 10us, then queues up 3 decoy packets
    // that should NOT be delayed (bypass delay and decoy)
    let s0 = State::new(enum_map! {
        Event::NormalQueued => vec![Trans(1, 1.0)],
        _ => vec![],
    });
    let mut s1 = State::new(enum_map! {
        Event::DelayBegin => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    s1.action = Some(Action::DelayTraffic {
        bypass: true,
        replace: false,
        n: Dist {
            dist: DistType::Uniform {
                low: 100.0,
                high: 100.0,
            },
            start: 0.0,
            max: 0.0,
        },
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
        Event::DecoyQueued => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    s2.action = Some(Action::DecoyTraffic {
        bypass: true,
        replace: false,
        n: Dist {
            dist: DistType::Uniform {
                low: 1.0,
                high: 1.0,
            },
            start: 0.0,
            max: 0.0,
        },
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
    let mut m = Machine::new(0, 0, vec![s0, s1, s2]).unwrap();

    // client
    run_test_sim(
        "0,nq 6,nr 14,nq",
        "0,nq 0,ps 5,db 6,pr 6,nr 6,dq 6,ps 7,dq 7,ps 8,dq 8,ps 14,nq 15,de 15,ps",
        Duration::from_micros(5),
        slice::from_ref(&m),
        &[],
        true,
        40,
        false,
        false,
    );

    // server log of client machine
    run_test_sim(
        "0,nq 6,nr 14,nq",
        "1,nq 1,ps 5,pr 5,nr 11,pr 11,dr 12,pr 12,dr 13,pr 13,dr 20,pr 20,nr",
        Duration::from_micros(5),
        slice::from_ref(&m),
        &[],
        false,
        40,
        false,
        false,
    );

    // make the delay not bypassable
    set_bypass(&mut m.states[1], false);

    // client
    run_test_sim(
        "0,nq 6,nr 14,nq",
        "0,nq 0,ps 5,db 6,pr 6,nr 6,dq 7,dq 8,dq 14,nq 15,de 15,ps 15,ps 15,ps 15,ps",
        Duration::from_micros(5),
        slice::from_ref(&m),
        &[],
        true,
        40,
        false,
        false,
    );

    // server log of client machine
    run_test_sim(
        "0,nq 6,nr 14,nq",
        "1,nq 1,ps 5,pr 5,nr 20,pr 20,pr 20,pr 20,pr 20,nr",
        // previous netsim output below, included packet at the end which are not "normal"
        //"1,nq 1,ps 5,pr 5,nr 20,pr 20,pr 20,pr 20,pr 20,nr 20,dr 20,dr 20,dr",
        Duration::from_micros(5),
        slice::from_ref(&m),
        &[],
        false,
        40,
        false,
        false,
    );

    // make the delay bypassable but the decoy not
    set_bypass(&mut m.states[1], true);
    set_bypass(&mut m.states[2], false);

    // client
    run_test_sim(
        "0,nq 6,nr 14,nq",
        "0,nq 0,ps 5,db 6,pr 6,nr 6,dq 7,dq 8,dq 14,nq 15,de 15,ps 15,ps 15,ps 15,ps",
        Duration::from_micros(5),
        slice::from_ref(&m),
        &[],
        true,
        20,
        false,
        false,
    );

    // server log of client machine
    run_test_sim(
        "0,nq 6,nr 14,nq",
        "1,nq 1,ps 5,pr 5,nr 20,pr 20,pr 20,pr 20,pr 20,nr",
        // previous netsim output below, included packet at the end which are not "normal"
        //"1,nq 1,ps 5,pr 5,nr 20,pr 20,pr 20,pr 20,pr 20,nr 20,dr 20,dr 20,dr",
        Duration::from_micros(5),
        slice::from_ref(&m),
        &[],
        false,
        40,
        false,
        false,
    );

    // make the delay not bypassable but the decoy is
    set_bypass(&mut m.states[1], false);
    set_bypass(&mut m.states[2], true);

    // client
    run_test_sim(
        "0,nq 6,nr 14,nq",
        "0,nq 0,ps 5,db 6,pr 6,nr 6,dq 7,dq 8,dq 14,nq 15,de 15,ps 15,ps 15,ps 15,ps",
        Duration::from_micros(5),
        slice::from_ref(&m),
        &[],
        true,
        40,
        false,
        false,
    );

    // server log of client machine
    run_test_sim(
        "0,nq 6,nr 14,nq",
        "1,nq 1,ps 5,pr 5,nr 20,pr 20,pr 20,pr 20,pr 20,nr",
        // previous netsim output below, included packet at the end which are not "normal"
        //"1,nq 1,ps 5,pr 5,nr 20,pr 20,pr 20,pr 20,pr 20,nr 20,dr 20,dr 20,dr",
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
        Event::NormalQueued => vec![Trans(1, 1.0)],
        _ => vec![],
    });
    // 1: delay for 1000us after 1us, bypassable
    // 1->2 on DelayBegin
    let mut s1 = State::new(enum_map! {
        Event::DelayBegin => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    s1.action = Some(Action::DelayTraffic {
        bypass: false,
        replace: false,
        n: Dist {
            dist: DistType::Uniform {
                low: 100.0,
                high: 100.0,
            },
            start: 0.0,
            max: 0.0,
        },
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
    // 2: send a decoy every 2us, 3 times
    let mut s2 = State::new(enum_map! {
        Event::DecoyQueued => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    s2.action = Some(Action::DecoyTraffic {
        bypass: false,
        replace: false,
        n: Dist {
            dist: DistType::Uniform {
                low: 1.0,
                high: 1.0,
            },
            start: 0.0,
            max: 0.0,
        },
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
    let mut m = Machine::new(0, 0, vec![s0, s1, s2]).unwrap();

    // client, without any bypass or replace
    run_test_sim(
        "0,nq 4,nq 6,nr 6,nr 7,nq",
        "0,nq 0,ps 1,db 3,dq 4,nq 5,dq 6,pr 6,pr 6,nr 6,nr 7,nq 7,dq 1001,de 1001,ps 1001,ps 1001,ps 1001,ps 1001,ps",
        Duration::from_micros(5),
        slice::from_ref(&m),
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
        "0,nq 4,nq 6,nr 6,nr 7,nq",
        "0,nq 0,ps 1,db 3,dq 3,ps 4,nq 5,dq 5,ps 6,pr 6,pr 6,nr 6,nr 7,nq 7,dq 7,ps 1001,de 1001,ps 1001,ps",
        Duration::from_micros(5),
        slice::from_ref(&m),
        &[],
        true,
        100,
        false,
        false,
    );
    // client, with bypass and only packets on wire
    run_test_sim(
        "0,nq 4,nq 6,nr 6,nr 7,nq",
        "0,ps 3,ps 5,ps 6,pr 6,pr 7,ps 1001,ps 1001,ps",
        Duration::from_micros(5),
        slice::from_ref(&m),
        &[],
        true,
        40,
        true, // NOTE only packets as-is on the wire
        false,
    );

    // client, with bypass *and replace*, only packets on wire
    set_replace(&mut m.states[2], true);
    run_test_sim(
        "0,nq 4,nq 6,nr 6,nr 7,nq",
        // decoy at 5us is replaced by sending queued up 4,nq, and decoy at 7us
        // is replaced by queued up 7,nq
        "0,ps 3,ps 5,ps 6,pr 6,pr 7,ps",
        Duration::from_micros(5),
        slice::from_ref(&m),
        &[],
        true,
        100,
        true, // NOTE only packets as-is on the wire
        false,
    );

    // client, with bypass and replace, events as seen by framework
    run_test_sim(
        "0,nq 4,nq 6,nr 6,nr 7,nq",
        // with all events, we also get SP events and delay events
        "0,nq 0,ps 1,db 3,dq 3,ps 4,nq 5,dq 5,ps 6,pr 6,pr 6,nr 6,nr 7,nq 7,dq 7,ps",
        // previous netsim output below, included packet at the end which are not "normal" packets
        //"0,nq 0,ps 1,db 3,dq 3,ps 4,nq 5,dq 5,ps 6,pr 6,pr 6,nr 6,nr 7,nq 7,dq 7,ps 1001,de",
        Duration::from_micros(5),
        slice::from_ref(&m),
        &[],
        true,
        40,
        false, // NOTE false, all events
        false,
    );

    // another important detail: the window is 1us, what about normal packets
    // queued up earlier than that? They should also replace decoy
    run_test_sim(
        "0,nq 2,nq 2,nq 6,nr 6,nr 7,nq",
        "0,ps 3,ps 5,ps 6,pr 6,pr 7,ps",
        Duration::from_micros(5),
        slice::from_ref(&m),
        &[],
        true,
        40,
        true, // only packets
        false,
    );
    run_test_sim(
        "0,nq 2,nq 2,nq 6,nr 6,nr 7,nq",
        // with all events, we also get SP events and delay events
        "0,nq 0,ps 1,db 2,nq 2,nq 3,dq 3,ps 5,dq 5,ps 6,pr 6,pr 6,nr 6,nr 7,nq 7,dq 7,ps",
        // previous netsim output below, included packet at the end which are not "normal" packets
        //"0,nq 0,ps 1,db 2,nq 2,nq 3,dq 3,ps 5,dq 5,ps 6,pr 6,pr 6,nr 6,nr 7,nq 7,dq 7,ps 1001,de",
        Duration::from_micros(5),
        slice::from_ref(&m),
        &[],
        true,
        40,
        false, // all events
        false,
    );

    // same as above, we just queue up more packets: note that the machine above
    // only does 3 decoy packets due to limit
    run_test_sim(
        "0,nq 2,nq 2,nq 2,nq 2,nq 6,nr 6,nr 7,nq",
        "0,ps 3,ps 5,ps 6,pr 6,pr 7,ps 1001,ps 1001,ps",
        Duration::from_micros(5),
        slice::from_ref(&m),
        &[],
        true,
        40,
        true, // only packets
        false,
    );
    // bump the limit to 5
    if let Some(Action::DecoyTraffic { ref mut limit, .. }) = m.states[2].action {
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
        "0,nq 2,nq 2,nq 2,nq 2,nq 6,nr 6,nr 7,nq",
        "0,ps 3,ps 5,ps 6,pr 6,pr 7,ps 9,ps 11,ps",
        Duration::from_micros(5),
        slice::from_ref(&m),
        &[],
        true,
        40,
        true, // only packets
        false,
    );

    // we've been lazy so far, not checking the server
    run_test_sim(
        "0,nq 2,nq 2,nq 2,nq 2,nq 6,nr 6,nr 7,nq",
        "1,ps 1,ps 5,pr 8,pr 10,pr 12,pr 14,pr 16,pr",
        Duration::from_micros(5),
        slice::from_ref(&m),
        &[],
        false, // server
        40,
        true, // only packets
        false,
    );
    run_test_sim(
        "0,nq 2,nq 2,nq 2,nq 2,nq 6,nr 6,nr 7,nq",
        "1,nq 1,ps 1,nq 1,ps 5,pr 5,nr 8,pr 8,nr 10,pr 10,nr 12,pr 12,nr 14,pr 14,nr 16,pr 16,nr",
        Duration::from_micros(5),
        slice::from_ref(&m),
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
        Event::NormalQueued => vec![Trans(1, 1.0)],
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
    s3.action = Some(Action::DecoyTraffic {
        bypass: false,
        replace: false,
        n: Dist {
            dist: DistType::Uniform {
                low: 1.0,
                high: 1.0,
            },
            start: 0.0,
            max: 0.0,
        },
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
    let m = Machine::new(0, 0, vec![s0, s1, s2, s3]).unwrap();

    run_test_sim(
        "0,nq 3,nq 6,nr 6,nr 7,nq",
        "0,nq 0,ps 0,tb 2,te 3,nq 3,ps 3,dq 3,ps 6,pr 6,pr 6,nr 6,nr 7,nq 7,ps",
        Duration::from_micros(5),
        slice::from_ref(&m),
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
        Event::NormalQueued => vec![Trans(1, 1.0)],
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
    s3.action = Some(Action::DecoyTraffic {
        bypass: false,
        replace: false,
        n: Dist {
            dist: DistType::Uniform {
                low: 1.0,
                high: 1.0,
            },
            start: 0.0,
            max: 0.0,
        },
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
    let m = Machine::new(0, 0, vec![s0, s1, s2, s3]).unwrap();

    run_test_sim(
        "0,nq 3,nq 6,nr 6,nr 7,nq",
        "0,nq 0,ps 0,tb 3,nq 3,ps 6,pr 6,pr 6,nr 6,nr 7,nq 7,ps 10,te 11,dq 11,ps",
        Duration::from_micros(5),
        slice::from_ref(&m),
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
        Event::NormalQueued => vec![Trans(1, 1.0)],
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
    s3.action = Some(Action::DecoyTraffic {
        bypass: false,
        replace: false,
        n: Dist {
            dist: DistType::Uniform {
                low: 1.0,
                high: 1.0,
            },
            start: 0.0,
            max: 0.0,
        },
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
    let m = Machine::new(0, 0, vec![s0, s1, s2, s3]).unwrap();

    run_test_sim(
        "0,nq 3,nq 6,nr 6,nr 7,nq",
        "0,nq 0,ps 0,tb 0,tb 2,te 3,nq 3,ps 3,dq 3,ps 6,pr 6,pr 6,nr 6,nr 7,nq 7,ps",
        Duration::from_micros(5),
        slice::from_ref(&m),
        &[],
        true,
        100,
        false,
        false,
    );
}

#[test_log::test]
fn test_action_cancel_timer_internal() {
    // start a decoy action, start a timer, then cancel the timer yet observe
    // the decoy
    let s0 = State::new(enum_map! {
        Event::NormalQueued => vec![Trans(1, 1.0)],
        _ => vec![],
    });
    let mut s1 = State::new(enum_map! {
        Event::NormalQueued => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    s1.action = Some(Action::DecoyTraffic {
        bypass: false,
        replace: false,
        n: Dist {
            dist: DistType::Uniform {
                low: 1.0,
                high: 1.0,
            },
            start: 0.0,
            max: 0.0,
        },
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

    let m = Machine::new(0, 0, vec![s0, s1, s2, s3]).unwrap();

    run_test_sim(
        "0,nq 1,nq 6,nr 7,nq",
        "0,nq 0,ps 1,nq 1,ps 1,tb 4,dq 4,ps 6,pr 6,nr 7,nq 7,ps",
        Duration::from_micros(5),
        slice::from_ref(&m),
        &[],
        true,
        100,
        false,
        false,
    );
}

#[test_log::test]
fn test_action_cancel_timer_action() {
    // start a decoy action, start a timer, then cancel the action and observe
    // the time ending
    let s0 = State::new(enum_map! {
        Event::NormalQueued => vec![Trans(1, 1.0)],
        _ => vec![],
    });
    let mut s1 = State::new(enum_map! {
        Event::NormalQueued => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    s1.action = Some(Action::DecoyTraffic {
        bypass: false,
        replace: false,
        n: Dist {
            dist: DistType::Uniform {
                low: 1.0,
                high: 1.0,
            },
            start: 0.0,
            max: 0.0,
        },
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

    let m = Machine::new(0, 0, vec![s0, s1, s2, s3]).unwrap();

    run_test_sim(
        "0,nq 1,nq 6,nr 7,nq",
        "0,nq 0,ps 1,nq 1,ps 1,tb 3,te 6,pr 6,nr 7,nq 7,ps",
        Duration::from_micros(5),
        slice::from_ref(&m),
        &[],
        true,
        100,
        false,
        false,
    );
}

#[test_log::test]
fn test_action_cancel_timer_both() {
    // start a decoy action, start a timer, then cancel both and observe no
    // decoy and no timer ending
    let s0 = State::new(enum_map! {
        Event::NormalQueued => vec![Trans(1, 1.0)],
        _ => vec![],
    });
    let mut s1 = State::new(enum_map! {
        Event::NormalQueued => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    s1.action = Some(Action::DecoyTraffic {
        bypass: false,
        replace: false,
        n: Dist {
            dist: DistType::Uniform {
                low: 1.0,
                high: 1.0,
            },
            start: 0.0,
            max: 0.0,
        },
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

    let m = Machine::new(0, 0, vec![s0, s1, s2, s3]).unwrap();

    run_test_sim(
        "0,nq 1,nq 6,nr 7,nq",
        "0,nq 0,ps 1,nq 1,ps 1,tb 6,pr 6,nr 7,nq 7,ps",
        Duration::from_micros(5),
        slice::from_ref(&m),
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
        Event::NormalQueued => vec![Trans(1, 1.0)],
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
        Event::NormalQueued => vec![Trans(3, 1.0)],
        Event::CounterZero => vec![Trans(4, 1.0)],
        _ => vec![],
    });
    s3.counter = (Some(Counter::new(Operation::Decrement)), None);
    let mut s4 = State::new(enum_map! {
        _ => vec![],
    });
    s4.action = Some(Action::DecoyTraffic {
        bypass: false,
        replace: false,
        n: Dist {
            dist: DistType::Uniform {
                low: 1.0,
                high: 1.0,
            },
            start: 0.0,
            max: 0.0,
        },
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
    let mut m = Machine::new(0, 0, vec![s0, s1, s2, s3, s4]).unwrap();

    run_test_sim(
        "0,nq 6,nr 6,nr 7,nq 7,nq 7,nq",
        "0,nq 0,ps 6,pr 6,pr 6,nr 6,nr 7,nq 7,ps 7,nq 7,ps 7,nq 7,ps 10,dq 10,ps",
        Duration::from_micros(5),
        slice::from_ref(&m),
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
        "0,nq 6,nr 6,nr 7,nq 7,nq 7,nq",
        "0,nq 0,ps 6,pr 6,pr 6,nr 6,nr 7,nq 7,ps 7,nq 7,ps 7,nq 7,ps",
        Duration::from_micros(5),
        slice::from_ref(&m),
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
        "0,nq 6,nr 6,nr 7,nq 7,nq 7,nq",
        "0,nq 0,ps 6,pr 6,pr 6,nr 6,nr 7,nq 7,ps 7,nq 7,ps 7,nq 7,ps 10,dq 10,ps",
        Duration::from_micros(5),
        slice::from_ref(&m),
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
        "0,nq 6,nr 6,nr 7,nq 7,nq 7,nq",
        "0,nq 0,ps 6,pr 6,pr 6,nr 6,nr 7,nq 7,ps 7,nq 7,ps 7,nq 7,ps 10,dq 10,ps",
        Duration::from_micros(5),
        slice::from_ref(&m),
        &[],
        true,
        100,
        false,
        false,
    );
}

// helper: build a one-shot DelayTraffic machine with the given n, duration,
// timeout and bypass; the machine fires the action exactly once on the first
// NormalQueued and then idles.
#[allow(dead_code)]
fn one_shot_delay_machine(n: f64, duration_us: f64, timeout_us: f64, bypass: bool) -> Machine {
    let s0 = State::new(enum_map! {
        Event::NormalQueued => vec![Trans(1, 1.0)],
        _ => vec![],
    });
    let mut s1 = State::new(enum_map! {
        _ => vec![],
    });
    s1.action = Some(Action::DelayTraffic {
        bypass,
        replace: false,
        n: Dist {
            dist: DistType::Uniform { low: n, high: n },
            start: 0.0,
            max: 0.0,
        },
        timeout: Dist {
            dist: DistType::Uniform {
                low: timeout_us,
                high: timeout_us,
            },
            start: 0.0,
            max: 0.0,
        },
        duration: Dist {
            dist: DistType::Uniform {
                low: duration_us,
                high: duration_us,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    Machine::new(0, 0, vec![s0, s1]).unwrap()
}

#[test_log::test]
fn test_delay_n_cap_ends_early() {
    // n=2, duration=100us: the second packet queued into the delay hits the
    // N-cap and ends the delay at the time of that queue, releasing both
    // queued packets immediately.
    let m = one_shot_delay_machine(2.0, 100.0, 5.0, false);
    run_test_sim(
        "0,nq 7,nq 9,nq 11,nq",
        "0,nq 0,ps 5,db 7,nq 9,nq 9,de 9,ps 9,ps 11,nq 11,ps",
        Duration::from_micros(5),
        slice::from_ref(&m),
        &[],
        true,
        100,
        false,
        false,
    );
}

#[test_log::test]
fn test_delay_n_cap_one() {
    // n=1, duration=100us: the very first packet to be delayed terminates
    // the delay immediately.
    let m = one_shot_delay_machine(1.0, 100.0, 5.0, false);
    run_test_sim(
        "0,nq 7,nq 11,nq",
        "0,nq 0,ps 5,db 7,nq 7,de 7,ps 11,nq 11,ps",
        Duration::from_micros(5),
        slice::from_ref(&m),
        &[],
        true,
        100,
        false,
        false,
    );
}

#[test_log::test]
fn test_delay_n_cap_with_decoys() {
    // decoy packets queued during a delay must count against the N-cap just
    // like normal packets. n=1, single decoy fired into an active
    // non-bypassable delay -> delay ends as soon as the decoy hits the queue.
    let s0 = State::new(enum_map! {
        Event::NormalQueued => vec![Trans(1, 1.0)],
        _ => vec![],
    });
    let mut s1 = State::new(enum_map! {
        Event::DelayBegin => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    s1.action = Some(Action::DelayTraffic {
        bypass: false,
        replace: false,
        n: Dist {
            dist: DistType::Uniform {
                low: 1.0,
                high: 1.0,
            },
            start: 0.0,
            max: 0.0,
        },
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
                low: 100.0,
                high: 100.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    let mut s2 = State::new(enum_map! {
        _ => vec![],
    });
    s2.action = Some(Action::DecoyTraffic {
        bypass: false,
        replace: false,
        n: Dist {
            dist: DistType::Uniform {
                low: 1.0,
                high: 1.0,
            },
            start: 0.0,
            max: 0.0,
        },
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
                low: 1.0,
                high: 1.0,
            },
            start: 0.0,
            max: 0.0,
        }),
    });
    let m = Machine::new(0, 0, vec![s0, s1, s2]).unwrap();
    run_test_sim(
        "0,nq 10,nq",
        "0,nq 0,ps 5,db 6,dq 6,de 6,ps 10,nq 10,ps",
        Duration::from_micros(5),
        slice::from_ref(&m),
        &[],
        true,
        20,
        false,
        false,
    );
}

#[test_log::test]
fn test_delay_n_cap_bypass_does_not_count() {
    // bypassable delay with n=1; decoys with bypass set do NOT enter the
    // delay queue and therefore must NOT decrement the N-cap. The delay
    // should end at duration expiry, not when the first bypass decoy fires.
    let s0 = State::new(enum_map! {
        Event::NormalQueued => vec![Trans(1, 1.0)],
        _ => vec![],
    });
    let mut s1 = State::new(enum_map! {
        Event::DelayBegin => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    s1.action = Some(Action::DelayTraffic {
        bypass: true,
        replace: false,
        n: Dist {
            dist: DistType::Uniform {
                low: 1.0,
                high: 1.0,
            },
            start: 0.0,
            max: 0.0,
        },
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
                low: 20.0,
                high: 20.0,
            },
            start: 0.0,
            max: 0.0,
        },
        limit: None,
    });
    let mut s2 = State::new(enum_map! {
        Event::DecoyQueued => vec![Trans(2, 1.0)],
        _ => vec![],
    });
    s2.action = Some(Action::DecoyTraffic {
        bypass: true,
        replace: false,
        n: Dist {
            dist: DistType::Uniform {
                low: 1.0,
                high: 1.0,
            },
            start: 0.0,
            max: 0.0,
        },
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
    let m = Machine::new(0, 0, vec![s0, s1, s2]).unwrap();
    run_test_sim(
        "0,nq 30,nq",
        "0,nq 0,ps 5,db 6,dq 6,ps 7,dq 7,ps 8,dq 8,ps 25,de 30,nq 30,ps",
        Duration::from_micros(5),
        slice::from_ref(&m),
        &[],
        true,
        40,
        false,
        false,
    );
}

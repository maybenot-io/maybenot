use maybenot::{
    Machine,
    action::Action,
    dist::{Dist, DistType},
    event::Event,
    state::{State, Trans},
};

use enum_map::enum_map;
use rand::Rng;
use rand::RngCore;

// based on
// https://github.com/pylls/padding-machines-for-tor/blob/master/machines/phase3/interspace-mc.c
pub fn interspace_client<R: RngCore>(rng: &mut R) -> Vec<Machine> {
    let mut states = vec![];

    let start = State::new(enum_map! {
        Event::PaddingRecv => vec![Trans(1, 1.0)],
       _ => vec![],
    });
    states.push(start);

    let wait = if rng.random_bool(0.5) {
        State::new(enum_map! {
            Event::NormalRecv => vec![Trans(2, 1.0)],
            _ => vec![],
        })
    } else {
        State::new(enum_map! {
            Event::NormalRecv => vec![Trans(2, 1.0)],
            Event::PaddingRecv => vec![Trans(2, 1.0)],
            _ => vec![],
        })
    };
    states.push(wait);

    let mut padding = if rng.random_bool(0.5) {
        State::new(enum_map! {
            Event::NormalSent => vec![Trans(1, 1.0)],
            Event::PaddingSent => vec![Trans(2, 1.0)],
        _ => vec![],
        })
    } else {
        State::new(enum_map! {
            Event::NormalSent => vec![Trans(1, 1.0)],
            Event::PaddingSent => vec![Trans(2, 1.0)],
            Event::NormalRecv => vec![Trans(1, 1.0)],
        _ => vec![],
        })
    };
    padding.action = Some(Action::SendPadding {
        bypass: false,
        replace: false,
        timeout: Dist {
            dist: DistType::Pareto {
                scale: 3.3,
                shape: 7.2,
            },
            start: 0.0,
            max: 9445.0,
        },
        limit: Some(Dist {
            dist: DistType::Pareto {
                scale: 4.7,
                shape: 4.8,
            },
            start: 1.0,
            max: 0.0,
        }),
    });
    states.push(padding);

    vec![Machine::new(1500, 0.5, 0, 0.0, states).unwrap()]
}

// based on
// https://github.com/pylls/padding-machines-for-tor/blob/master/machines/phase3/interspace-mr.c
pub fn interspace_server<R: RngCore>(rng: &mut R) -> Vec<Machine> {
    if rng.random_bool(0.5) {
        interspace_server_manual(rng)
    } else {
        interspace_server_spring(rng)
    }
}

fn interspace_server_manual<R: RngCore>(rng: &mut R) -> Vec<Machine> {
    let mut states = vec![];

    let start = State::new(enum_map! {
        Event::NormalRecv => vec![Trans(1, 1.0)],
       _ => vec![],
    });
    states.push(start);

    if rng.random_bool(0.5) {
        // wait: extend real burst
        let wait = State::new(enum_map! {
            Event::NormalSent => vec![Trans(2, 1.0)],
           _ => vec![],
        });
        states.push(wait);
    } else {
        // wait: inject a fake burst after a while
        let mut wait = State::new(enum_map! {
            Event::PaddingSent => vec![Trans(3, 1.0)],
           _ => vec![],
        });
        // special log_logistic distribution parameters here, see
        // random_log_logistic() below for details
        let alpha = rng.random_range(0.01..1000.0);
        let beta = rng.random_range(0.01..10000.0);
        wait.action = Some(Action::SendPadding {
            bypass: false,
            replace: false,
            timeout: Dist {
                dist: DistType::Gamma {
                    scale: alpha * beta,
                    shape: 1.0 / beta,
                },
                start: 0.0,
                max: 100000.0,
            },
            limit: None,
        });
        states.push(wait);
    }

    let mut extend = State::new(enum_map! {
        Event::NormalSent => vec![Trans(1, 1.0)],
        Event::PaddingSent => vec![Trans(2, 1.0)],
       _ => vec![],
    });
    extend.action = Some(Action::SendPadding {
        bypass: false,
        replace: false,
        timeout: random_pareto(0.0, 10000.0, rng),
        limit: Some(random_pareto(1.0, 0.0, rng)),
    });
    states.push(extend);

    let mut fake = State::new(enum_map! {
        Event::NormalSent => vec![Trans(1, 1.0)],
        Event::PaddingSent => vec![Trans(3, 1.0)],
       _ => vec![],
    });
    fake.action = Some(Action::SendPadding {
        bypass: false,
        replace: false,
        timeout: random_pareto(0.0, 10000.0, rng),
        limit: Some(random_pareto(1.0, 4.0, rng)),
    });
    states.push(fake);

    vec![Machine::new(1500, 0.5, 0, 0.0, states).unwrap()]
}

fn interspace_server_spring<R: RngCore>(rng: &mut R) -> Vec<Machine> {
    let mut states = vec![];

    let mut s0 = State::new(enum_map! {
        Event::NormalRecv => vec![Trans(1, 1.0)],
        Event::PaddingRecv => vec![Trans(1, 1.0)],
       _ => vec![],
    });
    s0.action = Some(Action::SendPadding {
        bypass: false,
        replace: false,
        timeout: random_log_logistic(0.0, 10000.0, rng),
        limit: None,
    });
    states.push(s0);

    let mut s1 = State::new(enum_map! {
        Event::NormalSent => vec![Trans(2, 1.0)],
       _ => vec![],
    });
    s1.action = Some(Action::SendPadding {
        bypass: false,
        replace: false,
        timeout: random_log_logistic(0.0, 31443.0, rng),
        limit: None,
    });
    states.push(s1);

    let mut s2 = State::new(enum_map! {
        Event::PaddingSent => vec![Trans(2, 1.0)],
        Event::PaddingRecv => vec![Trans(3, 1.0)],
       _ => vec![],
    });
    s2.action = Some(Action::SendPadding {
        bypass: false,
        replace: false,
        timeout: random_log_logistic(0.0, 100000.0, rng),
        limit: Some(random_log_logistic(5.0, 0.0, rng)),
    });
    states.push(s2);

    let mut s3 = State::new(enum_map! {
        Event::NormalRecv => vec![Trans(3, 1.0)],
        Event::NormalSent => vec![Trans(0, 1.0)],
        Event::PaddingRecv => vec![Trans(2, 1.0)],
       _ => vec![],
    });
    s3.action = Some(Action::SendPadding {
        bypass: false,
        replace: false,
        timeout: random_log_logistic(0.0, 55878.0, rng),
        limit: Some(random_log_logistic(5.0, 0.0, rng)),
    });
    states.push(s3);

    vec![Machine::new(1500, 0.5, 0, 0.0, states).unwrap()]
}

fn random_pareto<R: RngCore>(start: f64, max: f64, rng: &mut R) -> Dist {
    Dist {
        dist: DistType::Pareto {
            scale: rng.random_range(0.0..10.0),
            shape: rng.random_range(0.0..10.0),
        },
        start,
        max,
    }
}

fn random_log_logistic<R: RngCore>(start: f64, max: f64, rng: &mut R) -> Dist {
    // Problem: we don't have a log-logistic distribution in Maybenot. We
    // approximate it with a Gamma distribution. We also have to take into
    // account how the circuit padding framework (see
    // https://gitlab.torproject.org/tpo/core/tor/-/blob/main/src/core/or/circuitpadding.c?ref_type=heads:)
    // provides the parameters to the log logistic distribution.

    // param1 is alpha
    let alpha = rng.random_range(0.01..10.0);
    // param2 is beta
    let beta = rng.random_range(0.01..10.0);
    // we avoid exactly 0.0 because the gamma distribution is not defined for
    // 0.0
    let shape = 1.0 / beta;
    let scale = alpha * beta;

    Dist {
        dist: DistType::Gamma { scale, shape },
        start,
        max,
    }
}

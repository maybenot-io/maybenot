use super::*;

#[test]
fn no_machines() {
    let machines = vec![];
    let f = Framework::new(
        &machines,
        LimitDecoyNone,
        LimitDelayNone,
        Instant::now(),
        rand::rng(),
    );
    assert!(f.is_ok());
}

#[test]
fn reuse_machines() {
    let machines = vec![];
    let f1 = Framework::new(
        &machines,
        LimitDecoyNone,
        LimitDelayNone,
        Instant::now(),
        rand::rng(),
    );
    assert!(f1.is_ok());
    let f2 = Framework::new(
        &machines,
        LimitDecoyNone,
        LimitDelayNone,
        Instant::now(),
        rand::rng(),
    );
    assert!(f2.is_ok());
}

#[test]
fn noop_machine() {
    let s0 = State::new(enum_map! {
    _ => vec![],
    });
    let m = Machine::new(0, 0, vec![s0]).unwrap();
    assert_eq!(m.serialize(), "02eNpjYGBkQAcAACYAAg==");
}

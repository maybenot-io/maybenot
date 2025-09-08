pub mod circpad;
pub mod default;
use std::ops::RangeInclusive;

use maybenot::{Machine, constants::STATE_SIGNAL, event::Event, state::State};
use petgraph::{
    Graph,
    algo::{connected_components, kosaraju_scc},
};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::{
    random_machine::{circpad::random_circpad_compatible_machine, default::random_machine},
    rng_range,
};

/// Default reference point for durations.
pub const DEFAULT_REF_DURATION_POINT: f64 = 100_000.0;
/// Default reference point for counts.
pub const DEFAULT_REF_COUNT_POINT: usize = 100;
/// Default reference point for minimum action timeouts.
pub const DEFAULT_REF_MIN_ACTION_TIMEOUT: f64 = 0.0;

/// Round parameters to 3 decimal places for sake of readability. Public since
/// other modules may need to round numbers similarly and we want to ensure
/// consistency.
pub fn round_f32(num: f32) -> f32 {
    const THREE_DECIMAL_PLACES: f32 = 1000.0;
    (num * THREE_DECIMAL_PLACES).round() / THREE_DECIMAL_PLACES
}
pub fn round_f64(num: f64) -> f64 {
    const THREE_DECIMAL_PLACES: f64 = 1000.0;
    (num * THREE_DECIMAL_PLACES).round() / THREE_DECIMAL_PLACES
}

/// Configuration for generating random machines. None bools are randomly
/// sampled while ranges have defaults.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RandomMachineConfig {
    /// Range of the number of states in the machine.
    pub num_states: RangeInclusive<usize>,
    /// Whether the client machine can block.
    pub allow_blocking_client: Option<bool>,
    /// Whether the server machine can block.
    pub allow_blocking_server: Option<bool>,
    /// Whether the machine can use expressive actions (counters and timers).
    pub allow_expressive: Option<bool>,
    /// Whether the machine can use fixed budgets.
    pub allow_fixed_budget: Option<bool>,
    /// Whether the machine can use fractional limits.
    pub allow_frac_limits: Option<bool>,
    /// Reference point for actions involving durations of time, such as action
    /// timeouts or blocking duration.
    pub duration_point: Option<RangeInclusive<f64>>,
    /// Reference point for randomized parameters involving counts of actions or
    /// packets.
    pub count_point: Option<RangeInclusive<usize>>,
    /// Reference point for the minimum action timeout, i.e., the minimum time
    /// of any timer sampled for an action.
    pub min_action_timeout: Option<RangeInclusive<f64>>,
    /// Whether the random machine should be possible to also express within the
    /// Tor Circuit Padding Framework.
    pub circpad_compatible: Option<bool>,
}

impl RandomMachineConfig {
    /// Based on the configuration, generate a random machine.
    pub fn get_random_machine<R: Rng>(&self, is_client: bool, rng: &mut R) -> Machine {
        let num_states = rng_range!(rng, self.num_states);

        let action_block = if is_client {
            self.allow_blocking_client.unwrap_or(rng.random_bool(0.5))
        } else {
            self.allow_blocking_server.unwrap_or(rng.random_bool(0.5))
        };

        let expressive = self.allow_expressive.unwrap_or(rng.random_bool(0.5));
        let fixed_budget = self.allow_fixed_budget.unwrap_or(rng.random_bool(0.5));
        let frac_limit = self.allow_frac_limits.unwrap_or(rng.random_bool(0.5));

        let duration_ref_point = self
            .duration_point
            .clone()
            .unwrap_or(DEFAULT_REF_DURATION_POINT..=DEFAULT_REF_DURATION_POINT);
        let count_ref_point = self
            .count_point
            .clone()
            .unwrap_or(DEFAULT_REF_COUNT_POINT..=DEFAULT_REF_COUNT_POINT);
        let min_action_timeout = self
            .min_action_timeout
            .clone()
            .unwrap_or(DEFAULT_REF_MIN_ACTION_TIMEOUT..=DEFAULT_REF_MIN_ACTION_TIMEOUT);

        // usize for config, u64 internally due to use in Maybenot machines
        let count_ref_point = *count_ref_point.start() as u64..=*count_ref_point.end() as u64;

        match self.circpad_compatible {
            Some(true) => random_circpad_compatible_machine(
                num_states,
                fixed_budget,
                frac_limit,
                duration_ref_point,
                count_ref_point,
                min_action_timeout,
                rng,
            ),
            _ => random_machine(
                num_states,
                action_block,
                expressive,
                fixed_budget,
                frac_limit,
                duration_ref_point,
                count_ref_point,
                min_action_timeout,
                rng,
            ),
        }
    }
}

/// Check if the machine states are valid, i.e., if they are strongly connected
/// (all states can reach each other) and have liveness (cannot get stuck in a
/// state without the possibility of transitioning out).
pub fn check_machine_states(states: &[State]) -> bool {
    // FIXME: does check_liveness imply strongly connected? I think so?
    check_strongly_connected(states) && check_liveness(states)
}

/// The minimum probability of a transition to be considered connected in the
/// state graph.
pub const CONNECTED_MIN_EDGE_PROBABILITY: f32 = 0.05;

fn check_strongly_connected(states: &[State]) -> bool {
    let mut g = Graph::<usize, usize>::new();

    let mut nodes = vec![];
    for i in 0..states.len() {
        nodes.push(g.add_node(i));
    }
    for (si, state) in states.iter().enumerate() {
        let transitions = state.get_transitions();
        for (_, ts) in transitions {
            for t in ts {
                if t.1 >= CONNECTED_MIN_EDGE_PROBABILITY && t.0 != STATE_SIGNAL {
                    g.add_edge(nodes[si], nodes[t.0], 1);
                }
            }
        }
    }

    if connected_components(&g) != 1 {
        return false;
    }

    let s = kosaraju_scc(&g);
    if s.is_empty() {
        return false;
    }

    states.len() == s[0].len()
}

// the events that are relevant for liveness checking
const LIVENESS_EVENTS: [Event; 4] = [
    Event::NormalRecv,
    Event::NormalSent,
    Event::TunnelRecv,
    Event::TunnelSent,
];

fn check_liveness(states: &[State]) -> bool {
    // If a strongly connected graph based only on events that are guaranteed to
    // happen (NormalRecv, NormalSent, TunnelRecv, TunnelSent) regardless of
    // what machines are running, then the machine is alive.
    let mut g = Graph::<usize, usize>::new();

    let mut nodes = vec![];
    for i in 0..states.len() {
        nodes.push(g.add_node(i));
    }
    for (si, state) in states.iter().enumerate() {
        let transitions = state.get_transitions();
        for (event, ts) in transitions {
            if !LIVENESS_EVENTS.contains(&event) {
                continue;
            }
            for t in ts {
                if t.1 >= CONNECTED_MIN_EDGE_PROBABILITY {
                    g.add_edge(nodes[si], nodes[t.0], 1);
                }
            }
        }
    }

    if connected_components(&g) != 1 {
        return false;
    }

    let s = kosaraju_scc(&g);
    if s.is_empty() {
        return false;
    }

    states.len() == s[0].len()
}

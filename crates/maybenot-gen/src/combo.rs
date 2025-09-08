use std::cmp;

use crate::{
    constraints::ConstraintsConfig,
    defense::Defense,
    environment::{Environment, EnvironmentConfig},
};
use anyhow::{Result, bail};
use log::{Level, debug, log_enabled};
use maybenot::Machine;
use num_bigint::BigUint;
use num_integer::binomial;
use num_traits::Zero;
use rand::{Rng, seq::IndexedRandom};

/// Create a new defense by randomly combining machines. Repeatedly samples
/// [1,height] machines from the clients and servers, independently, combining
/// them into a defense. The constraints and environment configurations are used
/// to ensure the defense is valid, if provided. The `max_attempts` parameter
/// controls how many times the function will try to find a valid defense before
/// giving up.
pub fn combine_machines<R: Rng>(
    clients: &[Machine],
    servers: &[Machine],
    height: usize,
    max_attempts: usize,
    constraints: Option<ConstraintsConfig>,
    env: Option<EnvironmentConfig>,
    rng: &mut R,
) -> Result<Option<Defense>> {
    if clients.is_empty() {
        bail!("no client machines provided");
    }
    if servers.is_empty() {
        bail!("no server machines provided");
    }
    if height == 0 {
        bail!("height must be at least 1");
    }
    if max_attempts == 0 {
        bail!("max_attempts must be greater than 0");
    }
    if constraints.is_some() && env.is_none() {
        bail!("constraints provided but no environment configuration");
    }
    if env.is_some() && constraints.is_none() {
        bail!("environment provided but no constraints configuration");
    }

    if constraints.is_none() && env.is_none() {
        // no constraints or environment, we can skip validation
        let n_client = rng.random_range(1..=height);
        let n_server = rng.random_range(1..=height);
        let client = clients.choose_multiple(rng, n_client).cloned().collect();
        let server = servers.choose_multiple(rng, n_server).cloned().collect();
        return Ok(Some(Defense::new(client, server)));
    }

    let constraints = constraints.unwrap();
    let env = Environment::new(&env.unwrap(), &constraints, rng)?;

    let mut attempts = 0;
    while attempts < max_attempts {
        attempts += 1;

        let n_client = rng.random_range(1..=height);
        let n_server = rng.random_range(1..=height);
        let client: Vec<Machine> = clients.choose_multiple(rng, n_client).cloned().collect();
        let server: Vec<Machine> = servers.choose_multiple(rng, n_server).cloned().collect();

        match constraints.check(&client, &server, &env, rng.next_u64()) {
            Ok(_) => {
                return Ok(Some(Defense::new(client, server)));
            }
            Err(e) => {
                if log_enabled!(Level::Debug) {
                    debug!("Constraint check failed: {e}");
                }
            }
        }
    }

    Ok(None)
}

/// Computes the number of possible combinations when picking between 1 and M
/// items from each of two lists.
pub fn count_stacked_combinations(a_size: usize, b_size: usize, m: usize) -> BigUint {
    // sum of binomial coefficients for choosing 1 to M elements from A and B
    let s_a: BigUint = (1..=cmp::min(a_size, m))
        .map(|k| binomial(BigUint::from(a_size), BigUint::from(k)))
        .sum();
    let s_b: BigUint = (1..=cmp::min(b_size, m))
        .map(|k| binomial(BigUint::from(b_size), BigUint::from(k)))
        .sum();

    // total combinations is the Cartesian product of S_A and S_B
    s_a * s_b
}

/// Convert a BigUint to a string in scientific notation, where `precision` is
/// the number of digits to show in the mantissa (excluding the decimal point).
pub fn big_uint_to_scientific(n: &BigUint, precision: usize) -> String {
    if n.is_zero() {
        return "0e+0".to_string();
    }
    let s = n.to_string();
    let len = s.len();

    // the exponent is the position of the first digit (0-indexed) in a number
    // where only one digit is left of the decimal point
    let exponent = len - 1;

    // Prepare the mantissa. The first digit is always shown. We then include
    // the next (precision - 1) digits (if available) after a decimal point.
    let first_digit = &s[0..1];
    let remainder = if len > 1 {
        // Ensure we don't exceed the string length
        &s[1..std::cmp::min(len, precision)]
    } else {
        ""
    };
    let mantissa = if remainder.is_empty() {
        first_digit.to_string()
    } else {
        format!("{first_digit}.{remainder}")
    };

    format!("{mantissa}e+{exponent}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_count_stacked_ombinations_deck_combinations() {
        assert_eq!(count_stacked_combinations(0, 0, 0), BigUint::from(0usize));
        assert_eq!(count_stacked_combinations(1, 1, 6), BigUint::from(1usize));
        assert_eq!(
            count_stacked_combinations(10, 10, 6),
            BigUint::from(717409usize)
        );
        assert_eq!(
            count_stacked_combinations(100, 100, 6),
            BigUint::from(1616528892184131025usize)
        );
        // now over usize::MAX
        assert_eq!(
            count_stacked_combinations(1000, 1000, 6),
            BigUint::from(1894656375328312261315752602500u128)
        );
        // next 10000x10000 is over u128 so we stop
    }
}

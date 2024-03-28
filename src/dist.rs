//! Distributions sampled as part of a [`State`](crate::state).

use rand_distr::{
    Beta, Binomial, Distribution, Gamma, Geometric, LogNormal, Normal, Pareto, Poisson, Uniform,
    Weibull,
};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
extern crate simple_error;
use simple_error::bail;

/// DistType represents the type of a [`Dist`]. Supports a wide range of
/// different distributions. Some are probably useless and some are probably
/// missing. Uses the [`rand_distr`] crate for sampling.
#[derive(Debug, PartialEq, Clone, Copy, Serialize, Deserialize)]
#[repr(u16)]
pub enum DistType {
    /// Uniformly random [low, high). If low == high, constant.
    Uniform {
        /// The lower bound of the distribution.
        low: f64,
        /// The upper bound of the distribution.
        high: f64,
    },
    /// Normal distribution with set mean and standard deviation. Useful for
    /// real-valued quantities.
    Normal {
        /// The mean of the distribution.
        mean: f64,
        /// The standard deviation of the distribution.
        stdev: f64,
    },
    /// LogNormal distribution with set mu and sigma. Useful for real-valued
    /// quantities.
    LogNormal {
        /// The mu of the distribution.
        mu: f64,
        /// The sigma of the distribution.
        sigma: f64,
    },
    /// Binomial distribution with set trials and probability. Useful for yes/no
    /// events.
    Binomial {
        /// The number of trials.
        trials: u64,
        /// The probability of success.
        probability: f64,
    },
    /// Geometric distribution with set probability. Useful for yes/no events.
    Geometric {
        /// The probability of success.
        probability: f64,
    },
    /// Pareto distribution with set scale and shape. Useful for occurrence of
    /// independent events at a given rate.
    Pareto {
        /// The scale of the distribution.
        scale: f64,
        /// The shape of the distribution.
        shape: f64,
    },
    /// Poisson distribution with set lambda. Useful for occurrence of
    /// independent events at a given rate.
    Poisson {
        /// The lambda of the distribution.
        lambda: f64,
    },
    /// Weibull distribution with set scale and shape. Useful for occurrence of
    /// independent events at a given rate.
    Weibull {
        /// The scale of the distribution.
        scale: f64,
        /// The shape of the distribution.
        shape: f64,
    },
    /// Gamma distribution with set scale and shape.
    Gamma {
        /// The scale of the distribution.
        scale: f64,
        /// The shape of the distribution.
        shape: f64,
    },
    /// Beta distribution with set alpha and beta.
    Beta {
        /// The alpha of the distribution.
        alpha: f64,
        /// The beta of the distribution.
        beta: f64,
    },
}

impl fmt::Display for DistType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// A distribution used in a [`State`](crate::state). Ugly struct for the sake
/// of serializability with a type and two parameters that depend on the type of
/// the dist. Also has an optional starting value and max value enforced after
/// sampling.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Dist {
    /// The type of distribution.
    pub dist: DistType,
    /// The starting value that the sampled value is added to.
    pub start: f64,
    /// The maximum value that can be sampled (including starting value).
    pub max: f64,
}

impl fmt::Display for Dist {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut clamp = String::new();
        if self.start > 0.0 && self.max > 0.0 {
            clamp = format!(", clamped to [{}, {}]", self.start, self.max);
        } else if self.start > 0.0 {
            clamp = format!(", clamped to [{}, ∞]", self.start);
        } else if self.max > 0.0 {
            clamp = format!(", clamped to [0.0, {}]", self.max);
        }
        write!(f, "{}{}", self.dist, clamp)
    }
}

impl Default for Dist {
    fn default() -> Self {
        Self::new(
            DistType::Uniform {
                low: f64::MAX,
                high: f64::MAX,
            },
            0.0,
            0.0,
        )
    }
}

impl Dist {
    /// Create a new [`Dist`].
    pub fn new(dist: DistType, start: f64, max: f64) -> Self {
        Dist { dist, start, max }
    }

    /// Validate that the parameters are valid for the set [`DistType`].
    pub fn validate(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        match self.dist {
            DistType::Uniform { low, high } => {
                if low > high {
                    bail!("for Uniform dist, got low > high")
                }
            }
            DistType::Normal { mean, stdev } => {
                Normal::new(mean, stdev)?;
            }
            DistType::LogNormal { mu, sigma } => {
                LogNormal::new(mu, sigma)?;
            }
            DistType::Binomial {
                trials,
                probability,
            } => {
                Binomial::new(trials, probability)?;
            }
            DistType::Geometric { probability } => {
                Geometric::new(probability)?;
            }
            DistType::Pareto { scale, shape } => {
                Pareto::new(scale, shape)?;
            }
            DistType::Poisson { lambda } => {
                Poisson::new(lambda)?;
            }
            DistType::Weibull { scale, shape } => {
                Weibull::new(scale, shape)?;
            }
            DistType::Gamma { scale, shape } => {
                // note order below in inverse from others for some reason in
                // rand_distr
                Gamma::new(shape, scale)?;
            }
            DistType::Beta { alpha, beta } => {
                Beta::new(alpha, beta)?;
            }
        };

        Ok(())
    }

    /// Sample the distribution. May panic if not valid (see [`Self::validate()`]).
    pub fn sample(self) -> f64 {
        let mut r: f64 = 0.0;
        r = r.max(self.distsample() + self.start);
        if self.max > 0.0 {
            return r.min(self.max);
        }
        r
    }

    fn distsample(self) -> f64 {
        match self.dist {
            DistType::Uniform { low, high } => {
                // special common case for handcrafted machines, also not
                // supported by rand_dist::Uniform
                if low == high {
                    return low;
                }
                Uniform::new(low, high).sample(&mut rand::thread_rng())
            }
            DistType::Normal { mean, stdev } => Normal::new(mean, stdev)
                .unwrap()
                .sample(&mut rand::thread_rng()),
            DistType::LogNormal { mu, sigma } => LogNormal::new(mu, sigma)
                .unwrap()
                .sample(&mut rand::thread_rng()),
            DistType::Binomial {
                trials,
                probability,
            } => Binomial::new(trials, probability)
                .unwrap()
                .sample(&mut rand::thread_rng()) as f64,
            DistType::Geometric { probability } => Geometric::new(probability)
                .unwrap()
                .sample(&mut rand::thread_rng())
                as f64,
            DistType::Pareto { scale, shape } => Pareto::new(scale, shape)
                .unwrap()
                .sample(&mut rand::thread_rng()),
            DistType::Poisson { lambda } => Poisson::new(lambda)
                .unwrap()
                .sample(&mut rand::thread_rng()) as f64,
            DistType::Weibull { scale, shape } => Weibull::new(scale, shape)
                .unwrap()
                .sample(&mut rand::thread_rng()),
            DistType::Gamma { scale, shape } => {
                // note order below in inversed from others for some reason in
                // rand_distr
                Gamma::new(shape, scale)
                    .unwrap()
                    .sample(&mut rand::thread_rng())
            }
            DistType::Beta { alpha, beta } => Beta::new(alpha, beta)
                .unwrap()
                .sample(&mut rand::thread_rng()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_dist() {
        // valid dist
        let d = Dist {
            dist: DistType::Uniform {
                low: 10.0,
                high: 10.0,
            },
            start: 0.0,
            max: 0.0,
        };

        let r = d.validate();
        assert!(r.is_ok());

        // dist with low > high
        let d = Dist {
            dist: DistType::Uniform {
                low: 15.0,
                high: 5.0,
            },
            start: 0.0,
            max: 0.0,
        };

        let r = d.validate();
        assert!(r.is_err());
    }
}

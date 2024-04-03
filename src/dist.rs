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

/// A distribution used in a [`State`](crate::state). Can be sampled to get a
/// value. The value is clamped to the range [start, max] if both are set.
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
        r = r.max(self.dist_sample() + self.start);
        if self.max > 0.0 {
            return r.min(self.max);
        }
        r
    }

    fn dist_sample(self) -> f64 {
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
                .sample(&mut rand::thread_rng()) as f64,
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
                // note order below inverted from others for some reason in
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
    fn validate_uniform_dist() {
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

    #[test]
    fn validate_normal_dist() {
        // valid dist
        let d = Dist {
            dist: DistType::Normal {
                mean: 100.0,
                stdev: 15.0,
            },
            start: 0.0,
            max: 0.0,
        };

        let r = d.validate();
        assert!(r.is_ok());

        // dist with infinite variance
        let d = Dist {
            dist: DistType::Normal {
                mean: 100.0,
                stdev: f64::INFINITY,
            },
            start: 0.0,
            max: 0.0,
        };

        let r = d.validate();
        assert!(r.is_err());
    }

    #[test]
    fn validate_lognormal_dist() {
        // valid dist
        let d = Dist {
            dist: DistType::LogNormal {
                mu: 100.0,
                sigma: 15.0,
            },
            start: 0.0,
            max: 0.0,
        };

        let r = d.validate();
        assert!(r.is_ok());

        // dist with infinite variance
        let d = Dist {
            dist: DistType::LogNormal {
                mu: 100.0,
                sigma: f64::INFINITY,
            },
            start: 0.0,
            max: 0.0,
        };

        let r = d.validate();
        assert!(r.is_err());
    }

    #[test]
    fn validate_binomial_dist() {
        // valid dist
        let d = Dist {
            dist: DistType::Binomial {
                trials: 10,
                probability: 0.5,
            },
            start: 0.0,
            max: 0.0,
        };

        let r = d.validate();
        assert!(r.is_ok());

        // dist with invalid probability
        let d = Dist {
            dist: DistType::Binomial {
                trials: 10,
                probability: 1.1,
            },
            start: 0.0,
            max: 0.0,
        };

        let r = d.validate();
        assert!(r.is_err());
    }

    #[test]
    fn validate_geometric_dist() {
        // valid dist
        let d = Dist {
            dist: DistType::Geometric {
                probability: 0.5,
            },
            start: 0.0,
            max: 0.0,
        };

        let r = d.validate();
        assert!(r.is_ok());

        // dist with invalid probability
        let d = Dist {
            dist: DistType::Geometric {
                probability: 1.1,
            },
            start: 0.0,
            max: 0.0,
        };

        let r = d.validate();
        assert!(r.is_err());
    }

    #[test]
    fn validate_pareto_dist() {
        // valid dist
        let d = Dist {
            dist: DistType::Pareto {
                scale: 1.0,
                shape: 0.5,
            },
            start: 0.0,
            max: 0.0,
        };

        let r = d.validate();
        assert!(r.is_ok());

        // dist with negative scale
        let d = Dist {
            dist: DistType::Pareto {
                scale: -1.0,
                shape: 0.5,
            },
            start: 0.0,
            max: 0.0,
        };

        let r = d.validate();
        assert!(r.is_err());
    }

    #[test]
    fn validate_poisson_dist() {
        // valid dist
        let d = Dist {
            dist: DistType::Poisson {
                lambda: 1.0,
            },
            start: 0.0,
            max: 0.0,
        };

        let r = d.validate();
        assert!(r.is_ok());

        // dist with negative lambda
        let d = Dist {
            dist: DistType::Poisson {
                lambda: -1.0,
            },
            start: 0.0,
            max: 0.0,
        };

        let r = d.validate();
        assert!(r.is_err());
    }

    #[test]
    fn validate_weibull_dist() {
        // valid dist
        let d = Dist {
            dist: DistType::Weibull {
                scale: 1.0,
                shape: 0.5,
            },
            start: 0.0,
            max: 0.0,
        };

        let r = d.validate();
        assert!(r.is_ok());

        // dist with negative shape
        let d = Dist {
            dist: DistType::Weibull {
                scale: 1.0,
                shape: -0.5,
            },
            start: 0.0,
            max: 0.0,
        };

        let r = d.validate();
        assert!(r.is_err());
    }

    #[test]
    fn validate_gamma_dist() {
        // valid dist
        let d = Dist {
            dist: DistType::Gamma {
                scale: 1.0,
                shape: 0.5,
            },
            start: 0.0,
            max: 0.0,
        };

        let r = d.validate();
        assert!(r.is_ok());

        // dist with negative shape
        let d = Dist {
            dist: DistType::Gamma {
                scale: 1.0,
                shape: -0.5,
            },
            start: 0.0,
            max: 0.0,
        };

        let r = d.validate();
        assert!(r.is_err());
    }

    #[test]
    fn validate_beta_dist() {
        // valid dist
        let d = Dist {
            dist: DistType::Beta {
                alpha: 1.0,
                beta: 0.5,
            },
            start: 0.0,
            max: 0.0,
        };

        let r = d.validate();
        assert!(r.is_ok());

        // dist with negative beta
        let d = Dist {
            dist: DistType::Beta {
                alpha: 1.0,
                beta: -0.5,
            },
            start: 0.0,
            max: 0.0,
        };

        let r = d.validate();
        assert!(r.is_err());
    }

    #[test]
    fn sample_clamp() {
        // make sure start and max are applied

        // start: uniform 0, ensure sampled value is != 0
        let d = Dist {
            dist: DistType::Uniform {
                low: 0.0,
                high: 0.0,
            },
            start: 5.0,
            max: 0.0,
        };
        assert_eq!(d.sample(), 5.0);

        // max: uniform 10, ensure sampled value is < 10
        let d = Dist {
            dist: DistType::Uniform {
                low: 10.0,
                high: 10.0,
            },
            start: 0.0,
            max: 5.0,
        };
        assert_eq!(d.sample(), 5.0);

        // finally, make sure values < 0.0 cannot be sampled
        let d = Dist {
            dist: DistType::Uniform {
                low: -20.0,
                high: -10.0,
            },
            start: 0.0,
            max: 0.0,
        };
        assert_eq!(d.sample(), 0.0);
    }
}

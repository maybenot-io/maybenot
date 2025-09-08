//! Distributions sampled as part of a [`State`](crate::state).

use rand_core::RngCore;
use rand_distr::{
    Beta, Binomial, Distribution, Gamma, Geometric, LogNormal, Normal, Pareto, Poisson, SkewNormal,
    Weibull,
};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::Error;

/// The minimum probability of a [`Dist`](crate::dist) with a probability
/// parameter. This is set to prevent poor sampling performance for low
/// probabilities. Set to 1e-9.
pub const DIST_MIN_PROBABILITY: f64 = 0.000_000_001;

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
    /// SkewNormal distribution with set location, scale, and shape. Useful for
    /// real-valued quantities.
    SkewNormal {
        /// The location of the distribution.
        location: f64,
        /// The scale of the distribution.
        scale: f64,
        /// The shape of the distribution.
        shape: f64,
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let clamp;
        if self.start > 0.0 && self.max > 0.0 {
            clamp = format!(", start {}, clamped to [0.0, {}]", self.start, self.max);
        } else if self.start > 0.0 {
            clamp = format!(", start {}, clamped to [0.0, f64::MAX]", self.start);
        } else if self.max > 0.0 {
            clamp = format!(", clamped to [0.0, {}]", self.max);
        } else {
            clamp = ", clamped to [0.0, f64::MAX]".to_string();
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
    pub fn validate(&self) -> Result<(), Error> {
        match self.dist {
            DistType::Uniform { low, high } => {
                if low.is_nan() || high.is_nan() {
                    Err(Error::Machine(
                        "for Uniform dist, got low or high as NaN".to_string(),
                    ))?;
                }
                if low.is_infinite() || high.is_infinite() {
                    Err(Error::Machine(
                        "for Uniform dist, got low or high as infinite".to_string(),
                    ))?;
                }
                if low > high {
                    Err(Error::Machine(
                        "for Uniform dist, got low > high".to_string(),
                    ))?;
                }
                let range = high - low;
                if range.is_infinite() {
                    Err(Error::Machine(
                        "for Uniform dist, range hig - low overflows".to_string(),
                    ))?;
                }
            }
            DistType::Normal { mean, stdev } => {
                Normal::new(mean, stdev).map_err(|e| Error::Machine(e.to_string()))?;
            }
            DistType::SkewNormal {
                location,
                scale,
                shape,
            } => {
                SkewNormal::new(location, scale, shape)
                    .map_err(|e| Error::Machine(e.to_string()))?;
            }
            DistType::LogNormal { mu, sigma } => {
                LogNormal::new(mu, sigma).map_err(|e| Error::Machine(e.to_string()))?;
            }
            DistType::Binomial {
                trials,
                probability,
            } => {
                if probability != 0.0 && probability < DIST_MIN_PROBABILITY {
                    Err(Error::Machine(format!(
                        "for Binomial dist, probability 0.0 > {probability:?} < DIST_MIN_PROBABILITY (1e-9), error due to too slow sampling"
                    )))?;
                }
                if trials > 1_000_000_000 {
                    Err(Error::Machine(format!(
                        "for Binomial dist, {trials} trials > 1e9, error due to too slow sampling"
                    )))?;
                }
                Binomial::new(trials, probability).map_err(|e| Error::Machine(e.to_string()))?;
            }
            DistType::Geometric { probability } => {
                if probability != 0.0 && probability < DIST_MIN_PROBABILITY {
                    Err(Error::Machine(format!(
                        "for Geometric dist, probability 0.0 > {probability:?} < DIST_MIN_PROBABILITY (1e-9), error due to too slow sampling"
                    )))?;
                }
                Geometric::new(probability).map_err(|e| Error::Machine(e.to_string()))?;
            }
            DistType::Pareto { scale, shape } => {
                Pareto::new(scale, shape).map_err(|e| Error::Machine(e.to_string()))?;
            }
            DistType::Poisson { lambda } => {
                if lambda > 1_000_000_000_000_000_000_000_000_000_000_000_000_000_000.0 {
                    Err(Error::Machine(format!(
                        "for Poisson dist, lambda {lambda} > 1e42, error due to too slow sampling"
                    )))?;
                }
                Poisson::new(lambda).map_err(|e| Error::Machine(e.to_string()))?;
            }
            DistType::Weibull { scale, shape } => {
                Weibull::new(scale, shape).map_err(|e| Error::Machine(e.to_string()))?;
            }
            DistType::Gamma { scale, shape } => {
                // note order below in inverse from others for some reason in
                // rand_distr
                Gamma::new(shape, scale).map_err(|e| Error::Machine(e.to_string()))?;
            }
            DistType::Beta { alpha, beta } => {
                Beta::new(alpha, beta).map_err(|e| Error::Machine(e.to_string()))?;
            }
        }

        Ok(())
    }

    /// Sample the distribution. May panic if not valid (see [`Self::validate()`]).
    pub fn sample<R: RngCore>(self, rng: &mut R) -> f64 {
        let sampled = self.dist_sample(rng);
        let mut r: f64 = 0.0;
        let adjusted = sampled + self.start;

        // Ensure the addition didn't produce NaN/inf (also catches NaN/inf from sampled)
        if !adjusted.is_finite() {
            return 0.0;
        }

        r = r.max(adjusted);
        if self.max > 0.0 {
            let clamped = r.min(self.max);
            // Final safety check in case min() produced NaN
            return if clamped.is_finite() { clamped } else { 0.0 };
        }
        r
    }

    fn dist_sample<R: RngCore>(self, rng: &mut R) -> f64 {
        use rand::Rng;
        match self.dist {
            DistType::Uniform { low, high } => {
                // special common case for handcrafted machines, also not
                // supported by rand_dist::Uniform
                if low == high {
                    return low;
                }
                rng.random_range(low..high)
            }
            DistType::Normal { mean, stdev } => Normal::new(mean, stdev).unwrap().sample(rng),
            DistType::SkewNormal {
                location,
                scale,
                shape,
            } => SkewNormal::new(location, scale, shape).unwrap().sample(rng),
            DistType::LogNormal { mu, sigma } => LogNormal::new(mu, sigma).unwrap().sample(rng),
            DistType::Binomial {
                trials,
                probability,
            } => Binomial::new(trials, probability).unwrap().sample(rng) as f64,
            DistType::Geometric { probability } => {
                Geometric::new(probability).unwrap().sample(rng) as f64
            }
            DistType::Pareto { scale, shape } => Pareto::new(scale, shape).unwrap().sample(rng),
            DistType::Poisson { lambda } => Poisson::new(lambda).unwrap().sample(rng),
            DistType::Weibull { scale, shape } => Weibull::new(scale, shape).unwrap().sample(rng),
            DistType::Gamma { scale, shape } => {
                // note order below inverted from others for some reason in
                // rand_distr
                Gamma::new(shape, scale).unwrap().sample(rng)
            }
            DistType::Beta { alpha, beta } => Beta::new(alpha, beta).unwrap().sample(rng),
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
    fn validate_skewnormal_dist() {
        // valid dist
        let d = Dist {
            dist: DistType::SkewNormal {
                location: 100.0,
                scale: 15.0,
                shape: -3.0,
            },
            start: 0.0,
            max: 0.0,
        };

        let r = d.validate();
        assert!(r.is_ok());

        // dist with infinite shape
        let d = Dist {
            dist: DistType::SkewNormal {
                location: 100.0,
                scale: 15.0,
                shape: f64::INFINITY,
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
            dist: DistType::Geometric { probability: 0.5 },
            start: 0.0,
            max: 0.0,
        };

        let r = d.validate();
        assert!(r.is_ok());

        // dist with invalid probability
        let d = Dist {
            dist: DistType::Geometric { probability: 1.1 },
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
            dist: DistType::Poisson { lambda: 1.0 },
            start: 0.0,
            max: 0.0,
        };

        let r = d.validate();
        assert!(r.is_ok());

        // dist with negative lambda
        let d = Dist {
            dist: DistType::Poisson { lambda: -1.0 },
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
        assert_eq!(d.sample(&mut rand::rng()), 5.0);

        // max: uniform 10, ensure sampled value is < 10
        let d = Dist {
            dist: DistType::Uniform {
                low: 10.0,
                high: 10.0,
            },
            start: 0.0,
            max: 5.0,
        };
        assert_eq!(d.sample(&mut rand::rng()), 5.0);

        // finally, make sure values < 0.0 cannot be sampled
        let d = Dist {
            dist: DistType::Uniform {
                low: -20.0,
                high: -10.0,
            },
            start: 0.0,
            max: 0.0,
        };
        assert_eq!(d.sample(&mut rand::rng()), 0.0);
    }

    #[test]
    fn sample_nan_inf_robustness() {
        // Test handling of distributions that could potentially produce problematic values

        // Test with extreme parameter combinations that might cause numerical issues
        // Note: These would be caught by validate(), but we test the sampling robustness

        // Test with a distribution that has valid parameters but might produce edge case values
        let d = Dist {
            dist: DistType::Normal {
                mean: 0.0,
                stdev: 1e300, // Very large standard deviation (still passes validation)
            },
            start: 0.0,
            max: 0.0,
        };

        // Sample multiple times to increase chance of hitting edge cases
        for _ in 0..100 {
            let sampled = d.sample(&mut rand::rng());
            assert!(
                sampled.is_finite(),
                "Normal distribution with large stdev should not produce non-finite values"
            );
            assert!(sampled >= 0.0, "Sample should respect minimum bound of 0.0");
        }

        // Test with Pareto distribution (known for heavy tails)
        let d_pareto = Dist {
            dist: DistType::Pareto {
                scale: 1.0,
                shape: 0.1, // Very small shape parameter creates heavy tail
            },
            start: 0.0,
            max: 1000.0, // Clamp to prevent extreme values
        };

        for _ in 0..100 {
            let sampled = d_pareto.sample(&mut rand::rng());
            assert!(
                sampled.is_finite(),
                "Pareto distribution should not produce non-finite values"
            );
            assert!(sampled >= 0.0, "Sample should respect minimum bound of 0.0");
            assert!(sampled <= 1000.0, "Sample should respect maximum bound");
        }

        // Test with extreme start value that could cause overflow
        let d_extreme_start = Dist {
            dist: DistType::Uniform {
                low: 1e300,
                high: 1e300,
            },
            start: 1e300, // Adding two very large numbers
            max: 0.0,
        };

        let sampled = d_extreme_start.sample(&mut rand::rng());
        assert!(
            sampled.is_finite(),
            "Large start value should not produce non-finite values"
        );
        assert!(sampled >= 0.0, "Sample should respect minimum bound of 0.0");

        // Test with NaN-producing scenario (if we could construct one, but validation prevents this)
        // Instead, test that our robustness handles the clamping correctly
        let d_with_max = Dist {
            dist: DistType::Uniform {
                low: 100.0,
                high: 200.0,
            },
            start: 0.0,
            max: 50.0, // Max smaller than possible samples
        };

        for _ in 0..20 {
            let sampled = d_with_max.sample(&mut rand::rng());
            assert!(sampled.is_finite(), "Clamped sample should be finite");
            assert!(sampled <= 50.0, "Sample should respect max bound");
            assert!(sampled >= 0.0, "Sample should respect minimum bound of 0.0");
        }
    }
}

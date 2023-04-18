//! Distributions sampled as part of a [`State`](crate::state).

use byteorder::ByteOrder;
use byteorder::{LittleEndian, WriteBytesExt};
use rand_distr::{
    Beta, Binomial, Distribution, Gamma, Geometric, LogNormal, Normal, Pareto, Poisson, Uniform,
    Weibull,
};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
extern crate simple_error;
use simple_error::bail;

use crate::constants::*;

/// DistType represents the type of a [`Dist`]. Supports a wide range of
/// different distributions. Some are probably useless and some are probably
/// missing. Uses the [`rand_distr`] crate for sampling.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
#[repr(u16)]
pub enum DistType {
    /// Default: represents a dist that should not be sampled.
    None,
    /// Uniformly random [low, high). If low == high, constant.
    Uniform,
    /// Normal distribution with set mean and standard deviation. Useful for
    /// real-valued quantities.
    Normal,
    /// LogNormal distribution with set mu and sigma. Useful for real-valued
    /// quantities.
    LogNormal,
    /// Binomial distribution with set trials and probability. Useful for yes/no
    /// events.
    Binomial,
    /// Geometric distribution with set probability. Useful for yes/no events.
    Geometric,
    /// Pareto distribution with set scale and shape. Useful for occurrence of
    /// independent events at a given rate.
    Pareto,
    /// Poisson distribution with set lambda. Useful for occurrence of
    /// independent events at a given rate.
    Poisson,
    /// Weibull distribution with set scale and shape. Useful for occurrence of
    /// independent events at a given rate.
    Weibull,
    /// Gamma distribution with set scale and shape.
    Gamma,
    /// Beta distribution with set alpha and beta.
    Beta,
}
impl fmt::Display for DistType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<u16> for DistType {
    fn from(buf: u16) -> DistType {
        match buf {
            0 => DistType::None,
            1 => DistType::Uniform,
            2 => DistType::Normal,
            3 => DistType::LogNormal,
            4 => DistType::Binomial,
            5 => DistType::Geometric,
            6 => DistType::Pareto,
            7 => DistType::Poisson,
            8 => DistType::Weibull,
            9 => DistType::Gamma,
            10 => DistType::Beta,
            _ => DistType::None,
        }
    }
}

impl From<DistType> for u16 {
    fn from(buf: DistType) -> u16 {
        match buf {
            DistType::None => 0,
            DistType::Uniform => 1,
            DistType::Normal => 2,
            DistType::LogNormal => 3,
            DistType::Binomial => 4,
            DistType::Geometric => 5,
            DistType::Pareto => 6,
            DistType::Poisson => 7,
            DistType::Weibull => 8,
            DistType::Gamma => 9,
            DistType::Beta => 10,
        }
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
    /// The first parameter, depends on type. Used by all types.
    pub param1: f64,
    /// The second parameter, depends on type. Ignored by some types.
    pub param2: f64,
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

        match &self.dist {
            DistType::None => write!(f, "none"),
            DistType::Uniform => {
                write!(f, "Uniform [{:?}, {:?}]{}", self.param1, self.param2, clamp)
            }
            DistType::Normal => {
                write!(
                    f,
                    "Normal mean {:?} stdev {:?}{}",
                    self.param1, self.param2, clamp
                )
            }
            DistType::LogNormal => {
                write!(
                    f,
                    "LogNormal mu {:?} sigma {:?}{}",
                    self.param1, self.param2, clamp
                )
            }
            DistType::Binomial => {
                write!(
                    f,
                    "Binomial trials {:?} probability {:?}{}",
                    self.param1, self.param2, clamp
                )
            }
            DistType::Geometric => {
                write!(f, "Geometric probability {:?}{}", self.param1, clamp)
            }
            DistType::Pareto => {
                write!(
                    f,
                    "Pareto scale {:?} shape {:?}{}",
                    self.param1, self.param2, clamp
                )
            }
            DistType::Poisson => {
                write!(f, "Poisson lambda {:?}{}", self.param1, clamp)
            }
            DistType::Weibull => {
                write!(
                    f,
                    "Weibull scale {:?} shape {:?}{}",
                    self.param1, self.param2, clamp
                )
            }
            DistType::Gamma => {
                write!(
                    f,
                    "Gamma scale {:?} shape {:?}{}",
                    self.param1, self.param2, clamp
                )
            }
            DistType::Beta => {
                write!(
                    f,
                    "Beta alpha {:?} beta {:?}{}",
                    self.param1, self.param2, clamp
                )
            }
        }
    }
}

impl Default for Dist {
    fn default() -> Self {
        Self::new()
    }
}

impl Dist {
    /// Create a new [`None`](DistType) distribution.
    pub fn new() -> Self {
        Dist {
            dist: DistType::None,
            param1: 0.0,
            param2: 0.0,
            start: 0.0,
            max: 0.0,
        }
    }

    /// Validate that the parameters is valid for the set [`DistType`].
    pub fn validate(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        match &self.dist {
            DistType::None => {}
            DistType::Uniform => {
                if self.param1 > self.param2 {
                    bail!("for Uniform dist, got param2 > param1")
                }
            }
            DistType::Normal => {
                let mean = self.param1;
                let stdev = self.param2;
                Normal::new(mean, stdev)?;
            }
            DistType::LogNormal => {
                let mu = self.param1;
                let sigma = self.param2;
                LogNormal::new(mu, sigma)?;
            }
            DistType::Binomial => {
                let trials = self.param1 as u64;
                let probability = self.param2;
                Binomial::new(trials, probability)?;
            }
            DistType::Geometric => {
                let probability = self.param1;
                Geometric::new(probability)?;
            }
            DistType::Pareto => {
                let scale = self.param1;
                let shape = self.param2;
                Pareto::new(scale, shape)?;
            }
            DistType::Poisson => {
                let lambda = self.param1;
                Poisson::new(lambda)?;
            }
            DistType::Weibull => {
                let scale = self.param1;
                let shape = self.param2;
                Weibull::new(scale, shape)?;
            }
            DistType::Gamma => {
                let scale = self.param1;
                let shape = self.param2;
                // note order below in inversed from others for some reason in rand_distr
                Gamma::new(shape, scale)?;
            }
            DistType::Beta => {
                let alpha = self.param1;
                let beta = self.param2;
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
        match &self.dist {
            DistType::None => f64::MAX,
            DistType::Uniform => {
                let min = self.param1;
                let max = self.param2;
                // special common case for handcrafted machines, also not
                // supported by rand_dist::Uniform
                if min == max {
                    return min;
                }
                Uniform::new(min, max).sample(&mut rand::thread_rng())
            }
            DistType::Normal => {
                let mean = self.param1;
                let stdev = self.param2;
                Normal::new(mean, stdev)
                    .unwrap()
                    .sample(&mut rand::thread_rng())
            }
            DistType::LogNormal => {
                let mu = self.param1;
                let sigma = self.param2;
                LogNormal::new(mu, sigma)
                    .unwrap()
                    .sample(&mut rand::thread_rng())
            }
            DistType::Binomial => {
                let trials = self.param1 as u64;
                let probability = self.param2;
                Binomial::new(trials, probability)
                    .unwrap()
                    .sample(&mut rand::thread_rng()) as f64
            }
            DistType::Geometric => {
                let probability = self.param1;
                Geometric::new(probability)
                    .unwrap()
                    .sample(&mut rand::thread_rng()) as f64
            }
            DistType::Pareto => {
                let scale = self.param1;
                let shape = self.param2;
                Pareto::new(scale, shape)
                    .unwrap()
                    .sample(&mut rand::thread_rng())
            }
            DistType::Poisson => {
                let lambda = self.param1;
                Poisson::new(lambda)
                    .unwrap()
                    .sample(&mut rand::thread_rng())
            }
            DistType::Weibull => {
                let scale = self.param1;
                let shape = self.param2;
                Weibull::new(scale, shape)
                    .unwrap()
                    .sample(&mut rand::thread_rng())
            }
            DistType::Gamma => {
                let scale = self.param1;
                let shape = self.param2;
                // note order below in inversed from others for some reason in rand_distr
                Gamma::new(shape, scale)
                    .unwrap()
                    .sample(&mut rand::thread_rng())
            }
            DistType::Beta => {
                let alpha = self.param1;
                let beta = self.param2;
                Beta::new(alpha, beta)
                    .unwrap()
                    .sample(&mut rand::thread_rng())
            }
        }
    }

    /// Returns the serialized distribution of [`SERIALIZEDDISTSIZE`] bytes.
    pub fn serialize(self) -> Vec<u8> {
        let mut wtr = vec![];
        wtr.write_u16::<LittleEndian>(self.dist.into()).unwrap();
        wtr.write_f64::<LittleEndian>(self.param1).unwrap();
        wtr.write_f64::<LittleEndian>(self.param2).unwrap();
        wtr.write_f64::<LittleEndian>(self.start).unwrap();
        wtr.write_f64::<LittleEndian>(self.max).unwrap();
        wtr
    }
}

/// Try to parse a [`Dist`] from the provided bytes.
pub fn parse_dist(buf: Vec<u8>) -> Result<Dist, Box<dyn Error + Send + Sync>> {
    if buf.len() < SERIALIZEDDISTSIZE {
        bail!("too small")
    }

    let mut d: Dist = Dist {
        dist: DistType::None,
        param1: 0.0,
        param2: 0.0,
        start: 0.0,
        max: 0.0,
    };

    d.dist = DistType::from(LittleEndian::read_u16(&buf[..2]));
    d.param1 = LittleEndian::read_f64(&buf[2..10]);
    d.param2 = LittleEndian::read_f64(&buf[10..18]);
    d.start = LittleEndian::read_f64(&buf[18..26]);
    d.max = LittleEndian::read_f64(&buf[26..34]);

    Ok(d)
}

#[cfg(test)]
mod tests {
    use super::parse_dist;
    use crate::dist::*;

    #[test]
    fn formatting() {
        let mut d = Dist {
            dist: DistType::None,
            param1: 1.0,
            param2: 2.0,
            start: 0.0,
            max: 0.0,
        };
        assert_eq!(d.to_string(), "none");
        d.dist = DistType::Uniform;
        assert_eq!(d.to_string(), "Uniform [1.0, 2.0]");
        d.dist = DistType::Normal;
        assert_eq!(d.to_string(), "Normal mean 1.0 stdev 2.0");
        d.dist = DistType::LogNormal;
        assert_eq!(d.to_string(), "LogNormal mu 1.0 sigma 2.0");
        d.dist = DistType::Binomial;
        assert_eq!(d.to_string(), "Binomial trials 1.0 probability 2.0");
        d.dist = DistType::Geometric;
        assert_eq!(d.to_string(), "Geometric probability 1.0");
        d.dist = DistType::Pareto;
        assert_eq!(d.to_string(), "Pareto scale 1.0 shape 2.0");
        d.dist = DistType::Poisson;
        assert_eq!(d.to_string(), "Poisson lambda 1.0");
        d.dist = DistType::Weibull;
        assert_eq!(d.to_string(), "Weibull scale 1.0 shape 2.0");
        d.dist = DistType::Gamma;
        assert_eq!(d.to_string(), "Gamma scale 1.0 shape 2.0");
        d.dist = DistType::Beta;
        assert_eq!(d.to_string(), "Beta alpha 1.0 beta 2.0");
    }
    #[test]
    fn none() {
        let d = Dist {
            dist: DistType::None,
            param1: 200.0,
            param2: 1.0,
            start: 0.0,
            max: 0.0,
        };

        assert_eq!(d.sample(), f64::MAX);
    }

    #[test]
    fn serialize_all_distributions() {
        let mut d = Dist {
            dist: DistType::Pareto,
            param1: 123.45,
            param2: 67.89,
            start: 2.1,
            max: 4.5,
        };

        let s = d.serialize();
        let r = parse_dist(s).unwrap();
        assert_eq!(d.dist, r.dist);

        for i in 0..100 {
            d.dist = DistType::from(i);
            if i > 10 {
                // NOTE: fragile, depends on number of dists
                assert_eq!(d.dist, DistType::None);
            } else if i > 0 {
                assert_ne!(d.dist, DistType::None);
            }
            let s = d.serialize();
            let r = parse_dist(s).unwrap();
            assert_eq!(d.dist, r.dist);
        }
    }
}

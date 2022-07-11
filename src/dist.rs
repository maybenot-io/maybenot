use byteorder::ByteOrder;
use byteorder::{LittleEndian, WriteBytesExt};
use std::error::Error;
use std::fmt;
extern crate simple_error;
use simple_error::bail;

use crate::constants::*;

#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(u16)]
pub enum DistType {
    None,
    Uniform,
    Logistic,
    LogLogistic,
    Geometric,
    Weibull,
    GenPareto,
    Poisson,
}

impl fmt::Display for DistType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<u16> for DistType {
    fn from(buf: u16) -> Self {
        match buf {
            0 => DistType::None,
            1 => DistType::Uniform,
            2 => DistType::Logistic,
            3 => DistType::LogLogistic,
            4 => DistType::Geometric,
            5 => DistType::Weibull,
            6 => DistType::GenPareto,
            7 => DistType::Poisson,
            _ => DistType::None,
        }
    }
}

impl Into<u16> for DistType {
    fn into(self) -> u16 {
        match self {
            DistType::None => 0,
            DistType::Uniform => 1,
            DistType::Logistic => 2,
            DistType::LogLogistic => 3,
            DistType::Geometric => 4,
            DistType::Weibull => 5,
            DistType::GenPareto => 6,
            DistType::Poisson => 7,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Dist {
    pub dist: DistType,
    pub param1: f64,
    pub param2: f64,
    pub start: f64,
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
            DistType::Logistic => {
                write!(
                    f,
                    "Logistic mu {:?} sigma {:?}{}",
                    self.param1, self.param2, clamp
                )
            }
            DistType::LogLogistic => write!(
                f,
                "LogLogistic alpha {:?} 1/beta {:?}{}",
                self.param1, self.param2, clamp
            ),
            DistType::Geometric => write!(f, "Geometric p {:?}{}", self.param1, clamp),
            DistType::Weibull => write!(
                f,
                "Weibull k {:?} lambda {:?}{}",
                self.param1, self.param2, clamp
            ),
            DistType::GenPareto => {
                write!(
                    f,
                    "GenPareto sigma {:?} xi {:?}{}",
                    self.param1, self.param2, clamp
                )
            }
            DistType::Poisson => write!(f, "Poisson lambda {:?}{}", self.param1, clamp),
        }
    }
}

impl Dist {
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
                min + rand::random::<f64>() * (max - min)
            }
            DistType::Logistic => {
                // FIXME: is below really correct?
                let mu = self.param1;
                let sigma = self.param2;
                mu + sigma * ((rand::random::<f64>() / (1.0 - rand::random::<f64>())).ln())
            }
            DistType::LogLogistic => {
                let alpha = self.param1;
                let param2 = self.param2;
                let x: f64 = rand::random::<f64>();
                // HERE BE DRAGONS, really unsure about this one. Best effort of
                // "InTeRnEt" and tor/src/lib/math/prob_dist.c.
                if rand::random::<f64>() < 0.5 {
                    return alpha * ((x / (1.0 - x)).powf(param2));
                }
                alpha * (((1.0 - x) / x).powf(param2))
            }
            DistType::Geometric => {
                let p = (self.param1.min(1.0)).max(0.0);
                (rand::random::<f64>().ln() / (1.0 - p).ln()).floor()
            }
            DistType::Weibull => {
                let k = self.param1;
                let lambda = self.param2;
                lambda * (-(1.0 - rand::random::<f64>()).ln()).powf(1.0 / k)
            }
            DistType::GenPareto => {
                // FIXME: a best-effort, really needs to be audited
                let mu = 0.0; // location
                let sigma = self.param1; // scale
                let xi = self.param2; // shape
                mu + sigma * (rand::random::<f64>().powf(-xi) - 1.0) / xi
            }
            DistType::Poisson => {
                let lambda = self.param1;
                let l = std::f64::consts::E.powf(-lambda);
                let mut k: i64 = 0;
                let mut p: f64 = 1.0;

                while p > l {
                    k += 1;
                    p *= rand::random::<f64>();
                }
                (k as f64) - 1.0
            }
        }
    }

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

pub fn parse_dist(buf: Vec<u8>) -> Result<Dist, Box<dyn Error>> {
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

    const TESTN: i32 = 1000;
    const TESTERR: f64 = 1.5;

    #[test]
    fn formatting() {
        let mut d = crate::dist::Dist {
            dist: crate::dist::DistType::None,
            param1: 1.0,
            param2: 2.0,
            start: 0.0,
            max: 0.0,
        };
        assert_eq!(d.to_string(), "none");
        d.dist = crate::dist::DistType::Uniform;
        assert_eq!(d.to_string(), "Uniform [1.0, 2.0]");
        d.dist = crate::dist::DistType::Logistic;
        assert_eq!(d.to_string(), "Logistic mu 1.0 sigma 2.0");
        d.dist = crate::dist::DistType::LogLogistic;
        assert_eq!(d.to_string(), "LogLogistic alpha 1.0 1/beta 2.0");
        d.dist = crate::dist::DistType::Geometric;
        assert_eq!(d.to_string(), "Geometric p 1.0");
        d.dist = crate::dist::DistType::Weibull;
        assert_eq!(d.to_string(), "Weibull k 1.0 lambda 2.0");
        d.dist = crate::dist::DistType::GenPareto;
        assert_eq!(d.to_string(), "GenPareto sigma 1.0 xi 2.0");
        d.dist = crate::dist::DistType::Poisson;
        assert_eq!(d.to_string(), "Poisson lambda 1.0");
    }

    #[test]
    fn geometric() {
        let p = 0.33;
        let d = crate::dist::Dist {
            dist: crate::dist::DistType::Geometric,
            param1: p,
            param2: 0.0,
            start: 0.0,
            max: 0.0,
        };

        let mut s = 0.0;
        for _ in 1..TESTN {
            s += d.sample()
        }
        let mean = s / (TESTN as f64);
        let expect = (1.0 - p) / p;
        assert!(mean * TESTERR > expect);
        assert!(mean < expect * TESTERR);
    }

    #[test]
    fn loglogistic() {
        let alpha = 0.5;
        let d = crate::dist::Dist {
            dist: crate::dist::DistType::LogLogistic,
            param1: alpha,
            param2: 1.0 / 4.0,
            start: 0.0,
            max: 0.0,
        };

        let mut s = Vec::new();
        for _ in 1..TESTN {
            s.push(d.sample());
        }
        s.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let median = s[s.len() / 2];
        let expect = alpha;
        assert!(median * TESTERR > expect);
        assert!(median < expect * TESTERR);
    }

    #[test]
    fn logistic() {
        let mu: f64 = 5.0;
        let d = crate::dist::Dist {
            dist: crate::dist::DistType::Logistic,
            param1: mu,
            param2: 1.0,
            start: 0.0,
            max: 0.0,
        };

        let mut s = 0.0;
        for _ in 1..TESTN {
            s += d.sample()
        }
        let mean = s / TESTN as f64;
        let expect = mu;
        assert!(mean * TESTERR > expect);
        assert!(mean < expect * TESTERR);
    }

    #[test]
    fn none() {
        let d = crate::dist::Dist {
            dist: crate::dist::DistType::None,
            param1: 200.0,
            param2: 1.0,
            start: 0.0,
            max: 0.0,
        };

        assert_eq!(d.sample(), f64::MAX);
    }

    #[test]
    fn genpareto() {
        let sigma = 3.0;
        let xi = 2.0;
        let d = crate::dist::Dist {
            dist: crate::dist::DistType::GenPareto,
            param1: sigma,
            param2: xi,
            start: 0.0,
            max: 0.0,
        };

        let mut s = Vec::new();
        for _ in 1..TESTN {
            s.push(d.sample());
        }
        s.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let median = s[s.len() / 2];
        let base: f64 = 2.0;
        // expect = sigma * (2^xi -1) / xi
        let expect = sigma * ((base.powf(xi) - 1.0) / xi);
        assert!(median * TESTERR > expect);
        assert!(median < expect * TESTERR);
    }

    #[test]
    fn uniform() {
        let d = crate::dist::Dist {
            dist: crate::dist::DistType::Uniform,
            param1: 1.0,
            param2: 2.0,
            start: 0.0,
            max: 0.0,
        };

        for _ in 1..TESTN {
            let s = d.sample();
            assert!(s >= 1.0);
            assert!(s < 2.0);
        }
    }

    #[test]
    fn weibull() {
        let k = 3.0;
        let lambda = 2.0;
        let d = crate::dist::Dist {
            dist: crate::dist::DistType::Weibull,
            param1: k,
            param2: lambda,
            start: 0.0,
            max: 0.0,
        };

        let mut s = Vec::new();
        for _ in 1..TESTN {
            s.push(d.sample());
        }
        s.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let median = s[s.len() / 2];
        // expect = lambda * (ln(2)) ^ (1/k)
        let expect = lambda * std::f64::consts::LN_2.powf(1.0 / k);
        assert!(median * TESTERR > expect);
        assert!(median < expect * TESTERR);
    }

    #[test]
    fn serialization() {
        let d = crate::dist::Dist {
            dist: crate::dist::DistType::LogLogistic,
            param1: 123.45,
            param2: 67.89,
            start: 2.1,
            max: 4.5,
        };

        let s = d.serialize();
        let r = parse_dist(s).unwrap();
        assert_eq!(d.dist, r.dist);
    }
}

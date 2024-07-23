use std::ops::AddAssign;

/// Trait representing instants in time. Allows using maybenot frameworks with
/// custom time sources. If you want to use maybenot with a different time source
/// than `std::time::Instant`, implement this trait for your instant type, and the
/// [`Duration`] trait for your corresponding duration type.
pub trait Instant: Clone + Copy {
    type Duration: Duration;

    /// Returns the amount of time elapsed from another instant to this one.
    ///
    /// Should return a zero duration if `earlier` is later than `self`
    fn saturating_duration_since(&self, earlier: Self) -> Self::Duration;
}

pub trait Duration: Clone + Copy + AddAssign + PartialOrd {
    /// Creates a new duration, spanning no time.
    fn zero() -> Self;

    /// Creates a new duration from the specified number of microseconds.
    fn from_micros(micros: u64) -> Self;

    /// Returns true if this duration spans no time.
    fn is_zero(&self) -> bool;

    /// Divide this duration by another Duration and return f64.
    fn div_duration_f64(self, rhs: Self) -> f64;
}

impl Instant for std::time::Instant {
    type Duration = std::time::Duration;

    #[inline(always)]
    fn saturating_duration_since(&self, earlier: Self) -> Self::Duration {
        self.saturating_duration_since(earlier)
    }
}

impl Duration for std::time::Duration {
    #[inline(always)]
    fn zero() -> Self {
        Self::ZERO
    }

    #[inline(always)]
    fn from_micros(micros: u64) -> Self {
        Self::from_micros(micros)
    }

    #[inline(always)]
    fn is_zero(&self) -> bool {
        self.is_zero()
    }

    #[inline(always)]
    fn div_duration_f64(self, rhs: Self) -> f64 {
        // TODO: Can be changed to just `self.div_duration_f64(rhs)` when Rust 1.80 has
        // been released and we are fine with that being the oldest working Rust version.
        self.as_secs_f64() / rhs.as_secs_f64()
    }
}

#[macro_export]
/// Generates a random value within the specified range using the provided RNG.
/// The range is inclusive of both ends. We use this macro to avoid repeating
/// the range syntax throughout the codebase.
macro_rules! rng_range {
    ($rng:expr, $range:expr) => {
        $rng.random_range(*$range.start()..=*$range.end())
    };
}

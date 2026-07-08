//! Deterministic RNG helper so scenarios are reproducible from a seed.

use rand::rngs::StdRng;
use rand::SeedableRng;

/// A deterministic RNG seeded from `seed`.
pub fn seeded(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

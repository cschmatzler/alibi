//! Random opaque verification identifiers. Physical model primary IDs remain
//! the responsibility of the application's database schema.
use rand::{Rng, distributions::Alphanumeric, rngs::OsRng};

#[must_use]
pub fn generate_id(length: usize) -> String {
    OsRng
        .sample_iter(Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

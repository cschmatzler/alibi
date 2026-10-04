//! Random opaque verification identifiers. Physical model primary IDs remain
//! the responsibility of the application's database schema.
use rand::RngExt;

#[must_use]
pub fn generate_id(length: usize) -> String {
    rand::rng()
        .sample_iter(rand::distr::Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

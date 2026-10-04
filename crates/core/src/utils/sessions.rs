//! Session identifiers shared by SQL stores and the in-memory test store.
use rand::RngExt;

/// Generate the pinned upstream session-token shape using operating-system entropy.
pub fn generate_session_token() -> String {
    rand::rng()
        .sample_iter(rand::distr::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

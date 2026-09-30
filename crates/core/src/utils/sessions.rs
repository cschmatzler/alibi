//! Session identifiers shared by SQL stores and the in-memory test store.

use rand::{Rng, distributions::Alphanumeric, rngs::OsRng};

/// Generate the pinned upstream session-token shape using operating-system entropy.
pub fn generate_session_token() -> String {
    OsRng
        .sample_iter(Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

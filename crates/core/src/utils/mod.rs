//! Shared utility modules for `alibi-core`.

pub mod cookie_utils;
pub mod datetime;
pub mod id;
pub mod javascript;
pub mod json;
pub mod jwe;
pub mod password;
pub mod sessions;
pub mod username;
pub mod wildcard;

use std::sync::{Mutex, MutexGuard};

/// Normalize a user identity email to the canonical persisted form.
pub(crate) fn normalize_user_email(email: &str) -> String {
    email.to_lowercase()
}

/// Lock a mutex whose critical sections cannot leave the guarded data inconsistent.
pub(crate) trait LockUnpoisoned<T> {
    fn lock_unpoisoned(&self) -> MutexGuard<'_, T>;
}

impl<T> LockUnpoisoned<T> for Mutex<T> {
    fn lock_unpoisoned(&self) -> MutexGuard<'_, T> {
        self.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

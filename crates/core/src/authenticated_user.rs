//! Authenticated identity without inventing an application-owned storage model.
//!
//! A cookie cache deliberately retains the authenticated output snapshot until
//! its expiry. The stored variant keeps the complete real model for callers
//! whose contracts require fields absent from that public snapshot.

use crate::{AuthSchema, AuthUser, UserView};
use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer};
use std::{borrow::Cow, fmt};

/// The identity established by a cache-aware session read.
///
/// This type does not imply that a cached identity still has a database row or
/// current permissions. Sensitive stateful operations must use storage-backed
/// authentication instead.
pub enum AuthenticatedUser<S: AuthSchema> {
    Stored(S::User),
    Cached(Box<UserView>),
}

impl<S: AuthSchema> Clone for AuthenticatedUser<S> {
    fn clone(&self) -> Self {
        match self {
            Self::Stored(user) => Self::Stored(user.clone()),
            Self::Cached(user) => Self::Cached(user.clone()),
        }
    }
}

impl<S: AuthSchema> fmt::Debug for AuthenticatedUser<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stored(user) => formatter.debug_tuple("Stored").field(user).finish(),
            Self::Cached(user) => formatter.debug_tuple("Cached").field(user).finish(),
        }
    }
}

impl<S: AuthSchema> Serialize for AuthenticatedUser<S> {
    fn serialize<T: Serializer>(&self, serializer: T) -> Result<T::Ok, T::Error> {
        match self {
            Self::Stored(user) => user.serialize(serializer),
            Self::Cached(user) => user.serialize(serializer),
        }
    }
}

macro_rules! delegate {
    ($name:ident, $output:ty) => {
        fn $name(&self) -> $output {
            match self {
                Self::Stored(user) => user.$name(),
                Self::Cached(user) => user.$name(),
            }
        }
    };
}

impl<S: AuthSchema> AuthUser for AuthenticatedUser<S> {
    delegate!(id, Cow<'_, str>);
    delegate!(email, Option<&str>);
    delegate!(name, Option<&str>);
    delegate!(email_verified, bool);
    delegate!(image, Option<&str>);
    delegate!(created_at, DateTime<Utc>);
    delegate!(updated_at, DateTime<Utc>);
    delegate!(username, Option<&str>);
    delegate!(display_username, Option<&str>);
    delegate!(two_factor_enabled, bool);
    delegate!(two_factor_enabled_value, Option<bool>);
    delegate!(role, Option<&str>);
    delegate!(banned, bool);
    delegate!(banned_value, Option<bool>);
    delegate!(ban_reason, Option<&str>);
    delegate!(ban_expires, Option<DateTime<Utc>>);
    delegate!(metadata, &serde_json::Value);
    delegate!(is_anonymous, Option<bool>);
    delegate!(phone_number, Option<&str>);
    delegate!(phone_number_verified, Option<bool>);
    delegate!(last_login_method, Option<&str>);
}

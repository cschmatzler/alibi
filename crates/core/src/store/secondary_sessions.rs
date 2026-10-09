//! Session persistence through an application-owned secondary backend.
use super::PluginStore;
use crate::field_policy::FieldValues;
use crate::{AuthError, AuthResult, AuthSchema, AuthSession, AuthUser};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct CachedSession {
    session: serde_json::Value,
    user: serde_json::Value,
    absent_fields: std::collections::BTreeSet<String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Reference {
    token: String,
    expires_at: DateTime<Utc>,
}

impl<S: AuthSchema> PluginStore<S> {
    pub(super) fn secondary(&self) -> Option<&std::sync::Arc<dyn super::CacheAdapter>> {
        self.config.session.secondary_storage.as_ref()
    }

    pub(super) fn session_uses_database(&self) -> bool {
        !self.config.session.stateless
            && (self.secondary().is_none() || self.config.session.store_in_database)
    }

    pub(super) fn remember_ephemeral_session(&self, session: &S::Session) -> AuthResult<()> {
        if self.config.session.stateless {
            _ = self
                .ephemeral()?
                .insert(session.token().to_owned(), session.clone());
        }
        Ok(())
    }

    /// Set one nullable session scope field (`activeOrganizationId`, `activeTeamId`).
    pub(super) async fn update_session_scope(
        &self,
        token: &str,
        field: &str,
        value: Option<&str>,
    ) -> AuthResult<S::Session> {
        let mut fields = crate::field_policy::FieldValues::new();
        _ = fields.insert(
            field.into(),
            value.map_or(crate::utils::json::JsValue::Null, |value| {
                crate::utils::json::JsValue::String(value.to_owned())
            }),
        );
        let updated = if self.config.session.stateless {
            self.update_ephemeral_session(token, None, fields).await?
        } else {
            self.update_secondary_session(token, None, fields).await?
        };
        updated.ok_or(AuthError::SessionNotFound)
    }

    pub(super) async fn update_ephemeral_session(
        &self,
        token: &str,
        expires_at: Option<DateTime<Utc>>,
        fields: FieldValues,
    ) -> AuthResult<Option<S::Session>> {
        let original = self.ephemeral()?.get(token).cloned();
        let Some(original) = original else {
            return Ok(None);
        };
        let Some((session, fields)) = self
            .inner
            .prepare_secondary_session_update(original, expires_at, fields)
            .await?
        else {
            return Ok(None);
        };
        // Never resurrect a session concurrently removed while hooks awaited.
        {
            let mut sessions = self.ephemeral()?;
            let Some(destination) = sessions.get_mut(token) else {
                return Ok(None);
            };
            *destination = session.clone();
        }
        self.inner
            .complete_secondary_session_update(session, expires_at, fields, false)
            .await
    }

    async fn references(&self, user_id: &str) -> AuthResult<Vec<Reference>> {
        let Some(cache) = self.secondary() else {
            return Ok(Vec::new());
        };
        let Some(raw) = cache.get(&format!("active-sessions-{user_id}")).await? else {
            return Ok(Vec::new());
        };
        Ok(serde_json::from_str(&raw).unwrap_or_default())
    }

    async fn write_references(
        &self,
        user_id: &str,
        mut references: Vec<Reference>,
    ) -> AuthResult<()> {
        let Some(cache) = self.secondary() else {
            return Ok(());
        };
        let now = Utc::now();
        references.retain(|reference| reference.expires_at > now);
        references.sort_by_key(|reference| reference.expires_at);
        let key = format!("active-sessions-{user_id}");
        if let Some(last) = references.last() {
            let ttl = Duration::seconds((last.expires_at - now).num_seconds());
            if ttl > Duration::zero() {
                return cache
                    .set(&key, &serde_json::to_string(&references)?, ttl)
                    .await;
            }
        }
        cache.delete(&key).await
    }

    async fn stored_session(&self, token: &str) -> AuthResult<Option<(S::Session, S::User)>> {
        let Some(cache) = self.secondary() else {
            return Ok(None);
        };
        let Some(raw) = cache.get(token).await? else {
            return Ok(None);
        };
        let Ok(snapshot) = serde_json::from_str::<CachedSession>(&raw) else {
            return Ok(None);
        };
        let Ok(session) = S::Session::from_secondary_snapshot(snapshot.session) else {
            return Ok(None);
        };
        let Ok(user) = S::User::from_secondary_snapshot(snapshot.user) else {
            return Ok(None);
        };
        // Stored authority must identify the requested credential and its owner.
        if session.token() != token || session.user_id() != user.id() {
            return Ok(None);
        }
        Ok(Some((session, user)))
    }

    pub(super) async fn cached_session(
        &self,
        token: &str,
    ) -> AuthResult<Option<(S::Session, S::User)>> {
        Ok(self
            .stored_session(token)
            .await?
            .filter(|(session, _)| session.expires_at() > Utc::now() && session.active()))
    }

    pub(super) async fn mirror_session(
        &self,
        session: &S::Session,
        user: &S::User,
    ) -> AuthResult<()> {
        self.mirror_session_fields(session, user, None).await
    }

    pub(super) async fn mirror_session_fields(
        &self,
        session: &S::Session,
        user: &S::User,
        updated_fields: Option<&FieldValues>,
    ) -> AuthResult<()> {
        let Some(cache) = self.secondary() else {
            return Ok(());
        };
        let now = Utc::now();
        let mut references = self.references(session.user_id().as_ref()).await?;
        references.retain(|reference| reference.token != session.token());
        references.push(Reference {
            token: session.token().to_owned(),
            expires_at: session.expires_at(),
        });
        // Creation writes the index first; updates write the credential first.
        // Keep both partial failure boundaries visible.
        let updating = updated_fields.is_some();
        if !updating {
            self.write_references(session.user_id().as_ref(), references.clone())
                .await?;
        }
        let ttl = Duration::seconds((session.expires_at() - now).num_seconds());
        if ttl > Duration::zero() {
            let mut absent_fields = if let Some(raw) = cache.get(session.token()).await? {
                serde_json::from_str::<CachedSession>(&raw)
                    .map(|cached| cached.absent_fields)
                    .unwrap_or_default()
            } else if !self.config.session.store_in_database {
                let mut absent = std::collections::BTreeSet::new();
                for (name, value) in [
                    ("impersonatedBy", session.impersonated_by()),
                    ("activeOrganizationId", session.active_organization_id()),
                    ("activeTeamId", session.active_team_id()),
                ] {
                    if value.is_none() {
                        _ = absent.insert(name.to_owned());
                    }
                }
                for (name, value) in session.additional_fields() {
                    if value.is_null()
                        && self
                            .config
                            .session
                            .additional_fields
                            .get(&name)
                            .is_none_or(|field| field.default.is_none())
                    {
                        _ = absent.insert(name);
                    }
                }
                absent
            } else {
                std::collections::BTreeSet::new()
            };
            if let Some(fields) = updated_fields {
                for name in fields.keys() {
                    _ = absent_fields.remove(name);
                }
            }
            let snapshot = CachedSession {
                session: session.secondary_snapshot()?,
                user: user.secondary_snapshot()?,
                absent_fields,
            };
            cache
                .set(session.token(), &serde_json::to_string(&snapshot)?, ttl)
                .await?;
            if updating {
                self.write_references(session.user_id().as_ref(), references)
                    .await?;
            }
        }
        Ok(())
    }

    pub(super) async fn secondary_absent_fields(
        &self,
        token: &str,
    ) -> AuthResult<std::collections::BTreeSet<String>> {
        let Some(cache) = self.secondary() else {
            return Ok(std::collections::BTreeSet::new());
        };
        let Some(raw) = cache.get(token).await? else {
            return Ok(std::collections::BTreeSet::new());
        };
        Ok(serde_json::from_str::<CachedSession>(&raw)
            .map(|cached| cached.absent_fields)
            .unwrap_or_default())
    }

    pub(super) async fn mirror_created_session(&self, session: &S::Session) -> AuthResult<()> {
        if self.secondary().is_none() {
            return Ok(());
        }
        let user = self
            .inner
            .get_user_by_id(session.user_id().as_ref())
            .await?
            .ok_or_else(|| AuthError::internal("Secondary session owner not found"))?;
        self.mirror_session(session, &user).await
    }

    pub(super) async fn cached_user_sessions(&self, user_id: &str) -> AuthResult<Vec<S::Session>> {
        let now = Utc::now();
        let mut sessions = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for reference in self.references(user_id).await? {
            if reference.expires_at <= now || !seen.insert(reference.token.clone()) {
                continue;
            }
            if let Some((session, _)) = self.cached_session(&reference.token).await?
                && session.user_id().as_ref() == user_id
            {
                sessions.push(session);
            }
        }
        Ok(sessions)
    }

    pub(super) async fn cached_user_tokens(&self, user_id: &str) -> AuthResult<Vec<String>> {
        Ok(self
            .references(user_id)
            .await?
            .into_iter()
            .map(|reference| reference.token)
            .collect())
    }

    pub(super) async fn remove_cached_user_sessions(
        &self,
        user_id: &str,
        tokens: Vec<String>,
    ) -> AuthResult<()> {
        let Some(cache) = self.secondary() else {
            return Ok(());
        };
        for token in &tokens {
            // An index is only a locator: the issued snapshot establishes ownership.
            if let Some((session, _)) = self.stored_session(token).await?
                && session.user_id().as_ref() == user_id
            {
                cache.delete(token).await?;
            }
        }
        let mut current = self.references(user_id).await?;
        let removed = std::collections::BTreeSet::from_iter(tokens);
        current.retain(|reference| !removed.contains(&reference.token));
        self.write_references(user_id, current).await
    }

    pub(super) async fn remove_cached_session(&self, token: &str) -> AuthResult<()> {
        let Some(cache) = self.secondary() else {
            return Ok(());
        };
        if let Some((session, _)) = self.stored_session(token).await? {
            let mut references = self.references(session.user_id().as_ref()).await?;
            references.retain(|reference| reference.token != token);
            self.write_references(session.user_id().as_ref(), references)
                .await?;
        }
        cache.delete(token).await
    }

    pub(super) async fn refresh_cached_user(&self, user: &S::User) -> AuthResult<()> {
        let Some(cache) = self.secondary() else {
            return Ok(());
        };
        let now = Utc::now();
        for session in self.cached_user_sessions(user.id().as_ref()).await? {
            let Some(raw) = cache.get(session.token()).await? else {
                continue;
            };
            let Ok(mut snapshot) = serde_json::from_str::<CachedSession>(&raw) else {
                continue;
            };
            snapshot.user = user.secondary_snapshot()?;
            let ttl = Duration::seconds((session.expires_at() - now).num_seconds());
            if ttl > Duration::zero() {
                cache
                    .set(session.token(), &serde_json::to_string(&snapshot)?, ttl)
                    .await?;
            }
        }
        Ok(())
    }

    pub(super) async fn update_secondary_session(
        &self,
        token: &str,
        expires_at: Option<DateTime<Utc>>,
        fields: FieldValues,
    ) -> AuthResult<Option<S::Session>> {
        let Some((session, user)) = self.cached_session(token).await? else {
            // A combined database write may still occur, but it must not revive
            // an absent authoritative secondary session in preserved mode.
            return if self.session_uses_database() {
                if let Some(expiry) = expires_at {
                    self.inner
                        .refresh_session_with_fields(token, expiry, fields)
                        .await
                } else {
                    self.inner.update_session_fields(token, fields).await
                }
            } else {
                Ok(None)
            };
        };
        let Some((updated, fields)) = self
            .inner
            .prepare_secondary_session_update(session, expires_at, fields)
            .await?
        else {
            return Ok(None);
        };
        self.mirror_session_fields(&updated, &user, Some(&fields))
            .await?;
        self.inner
            .complete_secondary_session_update(
                updated,
                expires_at,
                fields,
                self.session_uses_database(),
            )
            .await
    }
}

use crate::store::UserStore;
use crate::store::stateless::{StatelessSchema, StatelessStore, members};
use crate::{AuthError, AuthResult, CreateUser, ListUsersParams, UpdateUser, UserView};
use async_trait::async_trait;
use chrono::Utc;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn utf16_email_queries_do_not_match_absent_emails() {
        async fn check<S: crate::AuthSchema>(store: &impl UserStore<S>) {
            use crate::AuthUser as _;
            store.create_user(CreateUser::new()).await.unwrap();
            let user = store
                .create_user(CreateUser::new().with_email("person@example.test"))
                .await
                .unwrap();
            for units in [vec![0xd800], vec![0xdc00], vec![0x61, 0xd800]] {
                let email = crate::utils::json::JsString::from_code_units(units);
                assert!(store.get_user_by_email(&email).await.unwrap().is_none());
            }
            let found = store
                .get_user_by_email(&"PERSON@EXAMPLE.TEST".into())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(found.id(), user.id());
        }
        check::<StatelessSchema>(&StatelessStore::default()).await;
        check::<crate::test_store::BundledSchema>(&crate::test_store::MemoryStore::default()).await;
    }

    #[tokio::test]
    async fn false_ban_patch_keeps_omissions_and_applies_explicit_values() {
        let store = StatelessStore::default();
        let user = store
            .create_user(CreateUser::new().with_email("false-ban@example.test"))
            .await
            .unwrap();
        let expiry = Utc::now() + chrono::Duration::hours(1);
        store
            .update_user(
                &user.id,
                UpdateUser {
                    banned: Some(true),
                    ban_reason: Some("preserved".into()),
                    ban_expires: Some(Some(expiry)),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        for (update, reason, expected_expiry) in [
            (
                UpdateUser {
                    banned: Some(false),
                    ..Default::default()
                },
                Some("preserved"),
                Some(expiry),
            ),
            (
                UpdateUser {
                    banned: Some(false),
                    ban_reason: Some("replacement".into()),
                    ban_expires: Some(Some(expiry + chrono::Duration::hours(1))),
                    ..Default::default()
                },
                Some("replacement"),
                Some(expiry + chrono::Duration::hours(1)),
            ),
            (
                UpdateUser {
                    banned: Some(false),
                    clear_ban_reason: true,
                    ban_expires: Some(None),
                    ..Default::default()
                },
                None,
                None,
            ),
        ] {
            store.update_user(&user.id, update).await.unwrap();
            let stored = store.get_user_by_id(&user.id).await.unwrap().unwrap();
            assert_eq!(stored.banned, Some(false));
            assert_eq!(stored.ban_reason.as_deref(), reason);
            assert_eq!(stored.ban_expires, expected_expiry);
        }
    }

    #[tokio::test]
    async fn clear_ban_reason_keeps_stateless_ban_and_expiry() {
        let store = StatelessStore::default();
        let user = store
            .create_user(CreateUser::new().with_email("banned@example.test"))
            .await
            .unwrap();
        let expiry = Utc::now() + chrono::Duration::hours(1);
        store
            .update_user(
                &user.id,
                UpdateUser {
                    banned: Some(true),
                    ban_reason: Some("remove".into()),
                    ban_expires: Some(Some(expiry)),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        store
            .update_user(
                &user.id,
                UpdateUser {
                    clear_ban_reason: true,
                    ban_reason: Some("must not win".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let stored = store.get_user_by_id(&user.id).await.unwrap().unwrap();
        assert_eq!(stored.banned, Some(true));
        assert_eq!(stored.ban_reason, None);
        assert_eq!(stored.ban_expires, Some(expiry));
    }
}
#[async_trait]
impl UserStore<StatelessSchema> for StatelessStore {
    async fn create_user(&self, mut create_user: CreateUser) -> AuthResult<UserView> {
        create_user.email = create_user.email.map(|email| email.to_lowercase());
        UserStore::<StatelessSchema>::create_user_prepared(
            self,
            crate::user_validation::PreparedUserCreation::from_data(create_user),
        )
        .await
    }

    async fn create_user_prepared(
        &self,
        prepared: crate::user_validation::PreparedUserCreation,
    ) -> AuthResult<UserView> {
        let (create_user, defaults) = prepared.into_parts();
        let mut create_user = defaults.apply(create_user)?;
        create_user
            .additional_fields
            .apply_adapter_transforms_async()
            .await?;
        let now = Utc::now();
        let supplied_id = crate::store::memory_user_id::MemoryUserId::supplied(
            create_user.adapter_native_fields.get("id"),
        )?;
        let (physical_id, id) = supplied_id.unwrap_or_else(|| {
            let id = create_user
                .id
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            (crate::store::memory_user_id::MemoryUserId::string(&id), id)
        });
        let mut omitted_fields = std::collections::BTreeSet::new();
        for (name, absent) in [
            ("name", create_user.name.is_none()),
            ("email", create_user.email.is_none()),
            ("image", create_user.image.is_none()),
            ("username", create_user.username.is_none()),
            ("displayUsername", create_user.display_username.is_none()),
        ] {
            if absent && !create_user.additional_fields.contains_key(name) {
                _ = omitted_fields.insert(name.to_owned());
            }
        }
        let username = create_user.username;
        let native_fields = create_user.adapter_native_fields;
        let mut user = UserView {
            omitted_fields,
            id: id.clone(),
            name: create_user.name,
            email: create_user.email,
            email_verified: create_user.email_verified.unwrap_or(false),
            image: create_user.image,
            created_at: create_user.created_at.unwrap_or(now),
            updated_at: create_user.updated_at.unwrap_or(now),
            username,
            display_username: create_user.display_username,
            two_factor_enabled: create_user.two_factor_enabled,
            role: create_user.role,
            banned: create_user.banned,
            ban_reason: None,
            ban_expires: None,
            metadata: create_user
                .metadata
                .unwrap_or_else(|| serde_json::json!({}))
                .into(),
            is_anonymous: create_user.is_anonymous,
            phone_number: create_user.phone_number,
            phone_number_verified: create_user.phone_number_verified,
            last_login_method: create_user.last_login_method,
            extension_fields: create_user
                .additional_fields
                .into_iter()
                .map(|(key, value)| (key.into(), value))
                .collect(),
        };
        user.retain_native_user_fields(native_fields);
        let mut state = self.lock()?;
        if state.users.contains_key(&physical_id)
            || state
                .users
                .values()
                .any(|existing| user.email.is_some() && existing.email == user.email)
        {
            return Err(AuthError::bad_request("User already exists"));
        }
        _ = state.users.insert(physical_id, user.clone());
        Ok(user)
    }

    async fn native_user_output_for(
        &self,
        user: &UserView,
    ) -> AuthResult<std::collections::BTreeMap<String, crate::utils::json::JsValue>> {
        Ok(user.native_user_fields())
    }

    async fn native_user_output(
        &self,
        id: &str,
    ) -> AuthResult<std::collections::BTreeMap<String, crate::utils::json::JsValue>> {
        Ok(self
            .get_user_by_id(id)
            .await?
            .map_or_else(Default::default, |user| user.native_user_fields()))
    }

    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<UserView>> {
        Ok(self
            .lock()?
            .users
            .get(&crate::store::memory_user_id::MemoryUserId::string(id))
            .cloned())
    }

    async fn list_users_by_ids(&self, ids: &[String]) -> AuthResult<Vec<UserView>> {
        let state = self.lock()?;
        Ok(ids
            .iter()
            .filter_map(|id| {
                state
                    .users
                    .get(&crate::store::memory_user_id::MemoryUserId::string(id))
                    .cloned()
            })
            .collect())
    }

    async fn list_users_by_ids_page(
        &self,
        ids: &[String],
        limit: f64,
    ) -> AuthResult<Vec<UserView>> {
        let mut users: Vec<_> = self
            .lock()?
            .users
            .iter()
            .filter(|(key, _)| {
                ids.iter()
                    .any(|id| **key == crate::store::memory_user_id::MemoryUserId::string(id))
            })
            .map(|(_, user)| user.clone())
            .collect();
        users.truncate(members::slice_index(limit, users.len()));
        Ok(users)
    }

    async fn get_user_by_email(
        &self,
        email: &crate::utils::json::JsString,
    ) -> AuthResult<Option<UserView>> {
        let normalized = email.to_lowercase();
        let Some(normalized) = normalized.as_str() else {
            return Ok(None);
        };
        Ok(self
            .lock()?
            .users
            .values()
            .find(|user| user.email.as_deref() == Some(normalized))
            .cloned())
    }

    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<UserView>> {
        let normalized = username.to_lowercase();
        Ok(self
            .lock()?
            .users
            .values()
            .find(|user| user.username.as_deref() == Some(&normalized))
            .cloned())
    }

    async fn get_user_by_username_value(
        &self,
        username: &crate::utils::json::JsValue,
    ) -> AuthResult<Option<UserView>> {
        Ok(self
            .lock()?
            .users
            .values()
            .find(|user| {
                user.extension_fields
                    .get("username")
                    .cloned()
                    .or_else(|| {
                        user.username
                            .clone()
                            .map(|value| crate::utils::json::JsValue::String(value.into()))
                    })
                    .map(crate::utils::json::JsValue::from)
                    .as_ref()
                    == Some(username)
            })
            .cloned())
    }

    async fn get_user_by_phone_number(&self, phone_number: &str) -> AuthResult<Option<UserView>> {
        Ok(self
            .lock()?
            .users
            .values()
            .find(|user| user.phone_number.as_deref() == Some(phone_number))
            .cloned())
    }

    async fn update_user(&self, id: &str, mut update: UpdateUser) -> AuthResult<UserView> {
        update
            .additional_fields
            .apply_adapter_transforms_async()
            .await?;
        let mut state = self.lock()?;
        let user = state
            .users
            .get_mut(&crate::store::memory_user_id::MemoryUserId::string(id))
            .ok_or(AuthError::UserNotFound)?;
        user.clear_native_user_update(&update)?;
        if let Some(email) = update.email {
            user.email = Some(email.to_lowercase());
        }
        if let Some(name) = update.name {
            user.name = Some(name);
        }
        if let Some(image) = update.image {
            user.image = Some(image);
        }
        if update.provider_image == Some(crate::utils::json::JsValue::Null) {
            user.image = None;
        }
        if let Some(email_verified) = update.email_verified {
            user.email_verified = email_verified;
        }
        if let Some(username) = update.username {
            user.username = Some(username);
        }
        if let Some(display_username) = update.display_username {
            user.display_username = Some(display_username);
        }
        if let Some(role) = update.role {
            user.role = Some(role);
        }
        if let Some(banned) = update.banned {
            user.banned = Some(banned);
        }
        if update.clear_ban_reason {
            user.ban_reason = None;
        } else if let Some(ban_reason) = update.ban_reason {
            user.ban_reason = Some(ban_reason);
        }
        if let Some(ban_expires) = update.ban_expires {
            user.ban_expires = ban_expires;
        }
        if let Some(two_factor_enabled) = update.two_factor_enabled {
            user.two_factor_enabled = Some(two_factor_enabled);
        }
        if let Some(metadata) = update.metadata {
            user.metadata = metadata.into();
        }
        if let Some(is_anonymous) = update.is_anonymous {
            user.is_anonymous = Some(is_anonymous);
        }
        if let Some(phone_number) = update.phone_number {
            user.phone_number = phone_number;
        }
        if let Some(phone_number_verified) = update.phone_number_verified {
            user.phone_number_verified = Some(phone_number_verified);
        }
        if let Some(last_login_method) = update.last_login_method {
            user.last_login_method = last_login_method;
        }
        for (key, value) in update.additional_fields {
            _ = user.extension_fields.insert(key.into(), value);
        }
        for (name, present) in [
            ("name", user.name.is_some()),
            ("email", user.email.is_some()),
            ("image", user.image.is_some()),
            ("username", user.username.is_some()),
            ("displayUsername", user.display_username.is_some()),
        ] {
            if present {
                _ = user.omitted_fields.remove(name);
            }
        }
        user.updated_at = Utc::now();
        user.retain_native_user_fields(update.adapter_native_fields);
        Ok(user.clone())
    }

    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        _ = self
            .lock()?
            .users
            .shift_remove(&crate::store::memory_user_id::MemoryUserId::string(id));
        Ok(())
    }

    async fn list_users(&self, _params: ListUsersParams) -> AuthResult<(Vec<UserView>, usize)> {
        let state = self.lock()?;
        crate::store::memory_user_id::MemoryUserId::apply_list(state.users.iter(), &_params)
    }
}

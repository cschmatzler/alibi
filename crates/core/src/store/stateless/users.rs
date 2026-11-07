use crate::store::UserStore;
use crate::store::stateless::{StatelessSchema, StatelessStore, members};
use crate::{AuthResult, CreateUser, ListUsersParams, UpdateUser, UserView};
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
        let expiry = chrono::DateTime::from_timestamp_millis(
            (Utc::now() + chrono::Duration::hours(1)).timestamp_millis(),
        )
        .unwrap();
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
        let expiry = chrono::DateTime::from_timestamp_millis(
            (Utc::now() + chrono::Duration::hours(1)).timestamp_millis(),
        )
        .unwrap();
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
        state.users.push((physical_id, user.clone()));
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
            .iter()
            .find(|(key, _)| *key == crate::store::memory_user_id::MemoryUserId::string(id))
            .map(|(_, user)| user.clone()))
    }

    async fn list_users_by_ids(&self, ids: &[String]) -> AuthResult<Vec<UserView>> {
        let state = self.lock()?;
        Ok(state
            .users
            .iter()
            .filter(|(key, _)| {
                ids.iter()
                    .any(|id| *key == crate::store::memory_user_id::MemoryUserId::string(id))
            })
            .map(|(_, user)| user.clone())
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
                    .any(|id| *key == crate::store::memory_user_id::MemoryUserId::string(id))
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
            .iter()
            .map(|(_, user)| user)
            .find(|user| user.email.as_deref() == Some(normalized))
            .cloned())
    }

    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<UserView>> {
        let normalized = username.to_lowercase();
        Ok(self
            .lock()?
            .users
            .iter()
            .map(|(_, user)| user)
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
            .iter()
            .map(|(_, user)| user)
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
            .iter()
            .map(|(_, user)| user)
            .find(|user| user.phone_number.as_deref() == Some(phone_number))
            .cloned())
    }

    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<UserView> {
        self.update_user_prepared(id, crate::store::PreparedUserUpdate::from_typed(&update))
            .await
    }

    async fn update_user_prepared(
        &self,
        id: &str,
        mut update: crate::store::PreparedUserUpdate,
    ) -> AuthResult<UserView> {
        update.apply_adapter_transforms().await?;
        let mut state = self.lock()?;
        let data = update
            .data
            .iter()
            .filter(|(key, _)| key.as_str().is_some_and(|key| update.declares(key)))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        crate::store::memory_user_id::MemoryUserId::update_rows(&mut state.users, id, data)
    }

    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        self.lock()?
            .users
            .retain(|(key, _)| *key != crate::store::memory_user_id::MemoryUserId::string(id));
        Ok(())
    }

    async fn list_users(&self, _params: ListUsersParams) -> AuthResult<(Vec<UserView>, usize)> {
        let state = self.lock()?;
        crate::store::memory_user_id::MemoryUserId::apply_list(
            state.users.iter().map(|(id, user)| (id, user)),
            &_params,
        )
    }
}

use super::*;
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
        let id = create_user
            .id
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let mut omitted_fields = std::collections::BTreeSet::new();
        for (name, absent) in [
            ("name", create_user.name.is_none()),
            ("email", create_user.email.is_none()),
            ("image", create_user.image.is_none()),
            ("username", create_user.username.is_none()),
            ("displayUsername", create_user.display_username.is_none()),
        ] {
            if absent && !create_user.additional_fields.contains_key(name) {
                let _ = omitted_fields.insert(name.to_owned());
            }
        }
        let username = create_user.username.map(|username| username.to_lowercase());
        let user = UserView {
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
                .unwrap_or_else(|| serde_json::json!({})),
            is_anonymous: create_user.is_anonymous,
            phone_number: create_user.phone_number,
            phone_number_verified: create_user.phone_number_verified,
            last_login_method: create_user.last_login_method,
            extension_fields: create_user
                .additional_fields
                .into_iter()
                .map(|(key, value)| value.to_json_value().map(|value| (key, value)))
                .collect::<Result<_, _>>()?,
        };
        let mut state = self.lock()?;
        if state.users.contains_key(&id)
            || state
                .users
                .values()
                .any(|existing| user.email.is_some() && existing.email == user.email)
        {
            return Err(AuthError::bad_request("User already exists"));
        }
        _ = state.users.insert(id, user.clone());
        Ok(user)
    }

    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<UserView>> {
        Ok(self.lock()?.users.get(id).cloned())
    }

    async fn list_users_by_ids(&self, ids: &[String]) -> AuthResult<Vec<UserView>> {
        let state = self.lock()?;
        Ok(ids
            .iter()
            .filter_map(|id| state.users.get(id).cloned())
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
            .values()
            .filter(|user| ids.contains(&user.id))
            .cloned()
            .collect();
        users.truncate(members::slice_index(limit, users.len()));
        Ok(users)
    }

    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<UserView>> {
        Ok(self
            .lock()?
            .users
            .values()
            .find(|user| user.email.as_deref() == Some(&email.to_lowercase()))
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
        let user = state.users.get_mut(id).ok_or(AuthError::UserNotFound)?;
        if let Some(email) = update.email {
            user.email = Some(email.to_lowercase());
        }
        if let Some(name) = update.name {
            user.name = Some(name);
        }
        if let Some(image) = update.image {
            user.image = Some(image);
        }
        if let Some(email_verified) = update.email_verified {
            user.email_verified = email_verified;
        }
        if let Some(username) = update.username {
            user.username = Some(username.to_lowercase());
        }
        if let Some(display_username) = update.display_username {
            user.display_username = Some(display_username);
        }
        if let Some(role) = update.role {
            user.role = Some(role);
        }
        if let Some(banned) = update.banned {
            user.banned = Some(banned);
            if !banned {
                user.ban_reason = None;
                user.ban_expires = None;
            }
        }
        if let Some(ban_reason) = update.ban_reason {
            user.ban_reason = Some(ban_reason);
        }
        if let Some(ban_expires) = update.ban_expires {
            user.ban_expires = ban_expires;
        }
        if let Some(two_factor_enabled) = update.two_factor_enabled {
            user.two_factor_enabled = Some(two_factor_enabled);
        }
        if let Some(metadata) = update.metadata {
            user.metadata = metadata;
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
            _ = user.extension_fields.insert(key, value.to_json_value()?);
        }
        for name in ["name", "email", "image", "username", "displayUsername"] {
            let present = match name {
                "name" => user.name.is_some(),
                "email" => user.email.is_some(),
                "image" => user.image.is_some(),
                "username" => user.username.is_some(),
                _ => user.display_username.is_some(),
            };
            if present {
                let _ = user.omitted_fields.remove(name);
            }
        }
        user.updated_at = Utc::now();
        let locked_result = Ok(user.clone());
        drop(state);
        locked_result
    }

    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        _ = self.lock()?.users.shift_remove(id);
        Ok(())
    }

    async fn list_users(&self, _params: ListUsersParams) -> AuthResult<(Vec<UserView>, usize)> {
        let users: Vec<_> = self.lock()?.users.values().cloned().collect();
        Ok(crate::user_query::apply_list_users(users, &_params))
    }
}

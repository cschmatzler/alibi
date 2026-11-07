use crate::utils::json::JsValue;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum MemoryUserId {
    String(String),
    Number(u64),
    Bool(bool),
}

impl MemoryUserId {
    pub(crate) fn string(value: &str) -> Self {
        Self::String(value.to_owned())
    }

    pub(crate) fn supplied(native: Option<&JsValue>) -> crate::AuthResult<Option<(Self, String)>> {
        let Some(value) = native else {
            return Ok(None);
        };
        if !value.is_truthy() {
            return Ok(None);
        }
        let key = match &value {
            JsValue::String(value) => Self::String(value.to_utf8().map_err(|_| {
                crate::AuthError::not_implemented(
                    "UTF-16 user identity requires a canonical identity API",
                )
            })?),
            JsValue::Number(value) => Self::Number(if *value == 0.0 { 0 } else { value.to_bits() }),
            JsValue::Bool(value) => Self::Bool(*value),
            _ => return Ok(None),
        };
        Ok(Some((
            key,
            value.coerce_string().expect("primitive ID conversion"),
        )))
    }

    fn native(&self) -> JsValue {
        match self {
            Self::String(value) => JsValue::String(value.clone().into()),
            Self::Number(bits) => JsValue::Number(f64::from_bits(*bits)),
            Self::Bool(value) => JsValue::Bool(*value),
        }
    }

    pub(crate) fn update_rows(
        users: &mut [(Self, crate::UserView)],
        id: &str,
        data: crate::utils::json::JsObject,
    ) -> crate::AuthResult<crate::UserView> {
        let locator = Self::string(id);
        let mut updates = Vec::new();
        for (index, (key, existing)) in users.iter().enumerate() {
            if *key == locator {
                let mut user = existing.clone();
                user.apply_user_update(data.clone())?;
                updates.push((index, user));
            }
        }
        let output = updates
            .first()
            .map(|(_, user)| user.clone())
            .ok_or(crate::AuthError::UserNotFound)?;
        for (index, user) in updates {
            users[index] = (Self::string(&user.id), user);
        }
        Ok(output)
    }

    pub(crate) fn apply_list<'a>(
        users: impl Iterator<Item = (&'a Self, &'a crate::UserView)>,
        params: &crate::ListUsersParams,
    ) -> crate::AuthResult<(Vec<crate::UserView>, usize)> {
        let operator = params.filter_operator.as_deref().unwrap_or("eq");
        let filter = params.filter_value.as_ref().filter(|_| {
            matches!(params.filter_field.as_deref(), Some("id" | "_id"))
                && matches!(
                    operator,
                    "eq" | "ne" | "in" | "not_in" | "lt" | "lte" | "gt" | "gte"
                )
        });
        let operand = filter.map(crate::types::UserFilterValue::native);
        let users = users.filter(|(id, _)| {
            operand.as_ref().is_none_or(|operand| {
                crate::user_query::matches_native_operand(&id.native(), operand, operator)
            })
        });
        let mut params = params.clone();
        if filter.is_some() {
            params.filter_value = None;
        }
        let mut filtered = Vec::new();
        for (id, user) in users {
            if crate::user_query::matches_list_user(user, &params)? {
                filtered.push((id, user));
            }
        }
        params.filter_value = None;
        params.search_value = None;
        let mut users = filtered;
        if users.len() > 1 && matches!(params.sort_by.as_deref(), Some("id" | "_id")) {
            let numeric = users.iter().all(|(id, _)| matches!(id, Self::Number(_)));
            let collation = if numeric {
                None
            } else {
                let collator = icu_collator::Collator::try_new(
                    icu_collator::CollatorPreferences::default(),
                    icu_collator::options::CollatorOptions::default(),
                )
                .map_err(|error| crate::AuthError::internal(error.to_string()))?;
                let text = users
                    .iter()
                    .map(|(id, _)| {
                        id.native()
                            .coerce_string()
                            .expect("primitive ID conversion")
                    })
                    .collect::<Vec<_>>();
                Some((collator, text))
            };
            let ascending = params.sort_direction.as_deref().unwrap_or("asc") == "asc";
            let indices = super::memory_user_sort::indices(users.len(), |lhs, rhs| {
                let order = match (users[lhs].0, users[rhs].0) {
                    (Self::Number(lhs), Self::Number(rhs)) => f64::from_bits(*lhs)
                        .partial_cmp(&f64::from_bits(*rhs))
                        .expect("supplied numeric IDs are not NaN"),
                    (Self::Bool(lhs), Self::Bool(rhs)) => lhs.cmp(rhs),
                    _ => {
                        let (collator, text) = collation
                            .as_ref()
                            .expect("non-numeric IDs prepare collation");
                        collator.compare(&text[lhs], &text[rhs])
                    }
                };
                if ascending { order } else { order.reverse() }
            });
            users = indices.into_iter().map(|index| users[index]).collect();
            params.sort_by = None;
        }
        crate::user_query::apply_list_users(
            users.into_iter().map(|(_, user)| user.clone()).collect(),
            &params,
        )
    }
}

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

    pub(crate) fn supplied(native: Option<&serde_json::Value>) -> Option<(Self, String)> {
        let value = JsValue::from(native?.clone());
        if !value.is_truthy() {
            return None;
        }
        let key = match &value {
            JsValue::String(value) => {
                Self::String(value.to_utf8().expect("native JSON ID is UTF-8"))
            }
            JsValue::Number(value) => Self::Number(if *value == 0.0 { 0 } else { value.to_bits() }),
            JsValue::Bool(value) => Self::Bool(*value),
            _ => return None,
        };
        Some((key, value.coerce_string().expect("primitive ID conversion")))
    }

    pub(crate) fn apply_list<'a>(
        users: impl Iterator<Item = (&'a Self, &'a crate::UserView)>,
        params: &crate::ListUsersParams,
    ) -> (Vec<crate::UserView>, usize) {
        let filter = params.filter_value.as_ref().filter(|_| {
            matches!(params.filter_field.as_deref(), Some("id" | "_id"))
                && matches!(
                    params.filter_operator.as_deref().unwrap_or("eq"),
                    "eq" | "ne" | "in" | "not_in"
                )
        });
        let users = users
            .filter(|(id, _)| {
                let Some(filter) = filter else { return true };
                let equal = match filter {
                    crate::types::UserFilterValue::Scalar(value) => **id == Self::string(value),
                    crate::types::UserFilterValue::Multiple(values) => {
                        values.iter().any(|value| **id == Self::string(value))
                    }
                };
                if matches!(params.filter_operator.as_deref(), Some("ne" | "not_in")) {
                    !equal
                } else {
                    equal
                }
            })
            .map(|(_, user)| user.clone())
            .collect();
        let mut params = params.clone();
        if filter.is_some() {
            params.filter_value = None;
        }
        crate::user_query::apply_list_users(users, &params)
    }
}

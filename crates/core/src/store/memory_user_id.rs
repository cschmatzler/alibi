use crate::utils::{javascript::string_to_number, json::JsValue};
use std::borrow::Cow;

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

    fn matches_relational(&self, value: &str, operator: &str) -> bool {
        let comparison = match self {
            Self::String(string) => Some(string.encode_utf16().cmp(value.encode_utf16())),
            Self::Number(bits) => {
                string_to_number(value).and_then(|value| f64::from_bits(*bits).partial_cmp(&value))
            }
            Self::Bool(boolean) => string_to_number(value)
                .and_then(|value| f64::from(u8::from(*boolean)).partial_cmp(&value)),
        };
        comparison.is_some_and(|ordering| match operator {
            "lt" => ordering.is_lt(),
            "lte" => ordering.is_le(),
            "gt" => ordering.is_gt(),
            "gte" => ordering.is_ge(),
            _ => false,
        })
    }

    pub(crate) fn apply_list<'a>(
        users: impl Iterator<Item = (&'a Self, &'a crate::UserView)>,
        params: &crate::ListUsersParams,
    ) -> (Vec<crate::UserView>, usize) {
        let operator = params.filter_operator.as_deref().unwrap_or("eq");
        let filter = params.filter_value.as_ref().filter(|_| {
            matches!(params.filter_field.as_deref(), Some("id" | "_id"))
                && matches!(
                    operator,
                    "eq" | "ne" | "in" | "not_in" | "lt" | "lte" | "gt" | "gte"
                )
        });
        let relational_value = filter
            .filter(|_| matches!(operator, "lt" | "lte" | "gt" | "gte"))
            .map(|value| match value {
                crate::types::UserFilterValue::Scalar(value) => Cow::Borrowed(value.as_str()),
                // Array ToPrimitive uses its comma-joined string, not membership.
                crate::types::UserFilterValue::Multiple(values) => Cow::Owned(values.join(",")),
            });
        let users = users
            .filter(|(id, _)| {
                let Some(filter) = filter else { return true };
                if let Some(value) = &relational_value {
                    return id.matches_relational(value, operator);
                }
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

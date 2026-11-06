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

    fn native(&self) -> JsValue {
        match self {
            Self::String(value) => JsValue::String(value.clone().into()),
            Self::Number(bits) => JsValue::Number(f64::from_bits(*bits)),
            Self::Bool(value) => JsValue::Bool(*value),
        }
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
        let operand = filter.map(crate::types::UserFilterValue::native);
        let users = users
            .filter(|(id, _)| {
                operand.as_ref().is_none_or(|operand| {
                    crate::user_query::matches_native_operand(&id.native(), operand, operator)
                })
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

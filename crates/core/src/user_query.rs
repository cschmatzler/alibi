//! Internal helpers for applying admin user-list query semantics.

use crate::entity::AuthUser;
use crate::types::ListUsersParams;
use crate::utils::{
    javascript::{number_from_i64, string_to_number},
    json::JsValue,
};
use chrono::{DateTime, Utc};
use std::cmp::Ordering;

fn string_field(user: &impl AuthUser, field: &str) -> Option<String> {
    match field {
        "id" | "_id" => Some(user.id().into_owned()),
        "email" => user.email().map(str::to_owned),
        "name" => user.name().map(str::to_owned),
        "username" => user.username().map(str::to_owned),
        "role" => user.role().map(str::to_owned),
        _ => None,
    }
}

fn bool_field(user: &impl AuthUser, field: &str) -> Option<bool> {
    (field == "banned").then(|| user.banned())
}

fn date_field(user: &impl AuthUser, field: &str) -> Option<DateTime<Utc>> {
    match field {
        "createdAt" => Some(user.created_at()),
        "updatedAt" => Some(user.updated_at()),
        "banExpires" => user.ban_expires(),
        _ => None,
    }
}

fn matches_search(user: &impl AuthUser, params: &ListUsersParams) -> bool {
    let Some(search_value) = params
        .search_value
        .as_deref()
        .filter(|value| !value.is_empty())
    else {
        return true;
    };

    let field = params
        .search_field
        .as_deref()
        .filter(|field| !field.is_empty())
        .unwrap_or("email");
    let operator = params.search_operator.as_deref().unwrap_or("contains");
    let Some(haystack) = string_field(user, field) else {
        return false;
    };

    match operator {
        "contains" => haystack.contains(search_value),
        "starts_with" => haystack.starts_with(search_value),
        "ends_with" => haystack.ends_with(search_value),
        _ => false,
    }
}

fn relational_primitive(value: &JsValue) -> Option<JsValue> {
    match value {
        JsValue::Array(_) => value.coerce_js_string().ok().map(JsValue::String),
        JsValue::Object(_) => None,
        _ => Some(value.clone()),
    }
}

fn operand_number(value: &JsValue) -> Option<f64> {
    match value {
        JsValue::Number(value) => Some(*value),
        JsValue::Bool(value) => Some(f64::from(u8::from(*value))),
        JsValue::Null => Some(0.0),
        JsValue::String(value) => value.as_str().and_then(string_to_number),
        JsValue::Date(value) => Some(number_from_i64(value.timestamp_millis())),
        _ => None,
    }
}

/// Compare physical primitive values, not their public string projections.
pub(crate) fn matches_native_operand(lhs: &JsValue, rhs: &JsValue, operator: &str) -> bool {
    let equal = || match (lhs, rhs) {
        (JsValue::String(lhs), JsValue::String(rhs)) => lhs == rhs,
        (JsValue::Number(lhs), JsValue::Number(rhs)) => lhs == rhs,
        (JsValue::Bool(lhs), JsValue::Bool(rhs)) => lhs == rhs,
        (JsValue::Null, JsValue::Null) | (JsValue::Undefined, JsValue::Undefined) => true,
        _ => false,
    };
    match operator {
        "eq" => equal(),
        "ne" => !equal(),
        "in" | "not_in" => rhs.as_array().is_some_and(|values| {
            let found = values
                .iter()
                .any(|value| matches_native_operand(lhs, value, "eq"));
            if operator == "in" { found } else { !found }
        }),
        "lt" | "lte" | "gt" | "gte" => {
            let (Some(lhs), Some(rhs)) = (relational_primitive(lhs), relational_primitive(rhs))
            else {
                return false;
            };
            let comparison = match (&lhs, &rhs) {
                (JsValue::String(lhs), JsValue::String(rhs)) => {
                    Some(lhs.code_units().cmp(rhs.code_units()))
                }
                _ => operand_number(&lhs)
                    .and_then(|lhs| operand_number(&rhs).and_then(|rhs| lhs.partial_cmp(&rhs))),
            };
            comparison.is_some_and(|ordering| match operator {
                "lt" => ordering.is_lt(),
                "lte" => ordering.is_le(),
                "gt" => ordering.is_gt(),
                _ => ordering.is_ge(),
            })
        }
        "contains" | "starts_with" | "ends_with" => {
            let JsValue::String(lhs) = lhs else {
                return false;
            };
            let Ok(rhs) = rhs.coerce_js_string() else {
                return false;
            };
            let lhs = lhs.code_units();
            let rhs = rhs.code_units();
            match operator {
                "contains" => rhs.is_empty() || lhs.windows(rhs.len()).any(|part| part == rhs),
                "starts_with" => lhs.starts_with(rhs),
                _ => lhs.ends_with(rhs),
            }
        }
        _ => false,
    }
}

fn matches_typed_filter(user: &impl AuthUser, field: &str, rhs: &JsValue, operator: &str) -> bool {
    // Physical IDs are handled by the store before public UserView projection.
    if matches!(field, "id" | "_id") {
        return false;
    }
    let lhs = match field {
        "email" | "name" | "username" | "role" => Some(
            string_field(user, field).map_or(JsValue::Null, |value| JsValue::String(value.into())),
        ),
        "image" => Some(
            user.image()
                .map_or(JsValue::Null, |value| JsValue::String(value.into())),
        ),
        "displayUsername" => Some(
            user.display_username()
                .map_or(JsValue::Null, |value| JsValue::String(value.into())),
        ),
        "banReason" => Some(
            user.ban_reason()
                .map_or(JsValue::Null, |value| JsValue::String(value.into())),
        ),
        "phoneNumber" => Some(
            user.phone_number()
                .map_or(JsValue::Null, |value| JsValue::String(value.into())),
        ),
        "lastLoginMethod" => Some(
            user.last_login_method()
                .map_or(JsValue::Null, |value| JsValue::String(value.into())),
        ),
        "emailVerified" => Some(JsValue::Bool(user.email_verified())),
        "banned" => Some(user.banned_value().map_or(JsValue::Null, JsValue::Bool)),
        "twoFactorEnabled" => Some(
            user.two_factor_enabled_value()
                .map_or(JsValue::Null, JsValue::Bool),
        ),
        "isAnonymous" => Some(user.is_anonymous().map_or(JsValue::Null, JsValue::Bool)),
        "phoneNumberVerified" => Some(
            user.phone_number_verified()
                .map_or(JsValue::Null, JsValue::Bool),
        ),
        "createdAt" | "updatedAt" | "banExpires" => {
            Some(date_field(user, field).map_or(JsValue::Null, JsValue::Date))
        }
        _ => user
            .additional_fields()
            .get(field)
            .cloned()
            .map(JsValue::from),
    };
    let Some(lhs) = lhs else { return false };
    let rhs = if matches!(lhs, JsValue::Bool(_)) {
        match rhs {
            JsValue::String(value) => JsValue::Bool(value == "true"),
            _ => rhs.clone(),
        }
    } else {
        rhs.clone()
    };
    matches_native_operand(&lhs, &rhs, operator)
}

fn matches_filter(user: &impl AuthUser, params: &ListUsersParams) -> bool {
    let Some(filter_value) = params.filter_value.as_ref() else {
        return true;
    };
    matches_typed_filter(
        user,
        params
            .filter_field
            .as_deref()
            .filter(|field| !field.is_empty())
            .unwrap_or("email"),
        &filter_value.native(),
        params.filter_operator.as_deref().unwrap_or("eq"),
    )
}

fn compare_options<T: Ord + Copy>(lhs: Option<T>, rhs: Option<T>, direction: &str) -> Ordering {
    match direction {
        "asc" => lhs.cmp(&rhs),
        _ => rhs.cmp(&lhs),
    }
}

/// Apply Better Auth admin list-users semantics to a user collection.
#[must_use]
pub fn apply_list_users<T: AuthUser + Clone>(
    users: Vec<T>,
    params: &ListUsersParams,
) -> (Vec<T>, usize) {
    apply(users, params, false)
}

/// Filter and page users whose configured column order was applied by storage.
#[must_use]
pub fn apply_list_users_presorted<T: AuthUser + Clone>(
    users: Vec<T>,
    params: &ListUsersParams,
) -> (Vec<T>, usize) {
    apply(users, params, true)
}

fn apply<T: AuthUser + Clone>(
    mut users: Vec<T>,
    params: &ListUsersParams,
    presorted: bool,
) -> (Vec<T>, usize) {
    users.retain(|user| matches_search(user, params) && matches_filter(user, params));

    if !presorted && let Some(sort_by) = params.sort_by.as_deref().filter(|field| !field.is_empty())
    {
        let sort_direction = params.sort_direction.as_deref().unwrap_or("asc");
        users.sort_by(|lhs, rhs| match sort_by {
            "id" | "_id" | "email" | "name" | "username" | "role" => compare_options(
                string_field(lhs, sort_by).as_deref(),
                string_field(rhs, sort_by).as_deref(),
                sort_direction,
            ),
            "createdAt" | "updatedAt" | "banExpires" => compare_options(
                date_field(lhs, sort_by),
                date_field(rhs, sort_by),
                sort_direction,
            ),
            "banned" => match sort_direction {
                "asc" => bool_field(lhs, sort_by).cmp(&bool_field(rhs, sort_by)),
                _ => bool_field(rhs, sort_by).cmp(&bool_field(lhs, sort_by)),
            },
            _ => compare_options(
                date_field(lhs, "createdAt"),
                date_field(rhs, "createdAt"),
                sort_direction,
            ),
        });
    }

    let total = users.len();
    let offset = params.offset.unwrap_or(0);
    let limit = params.limit.unwrap_or(total);
    let paged = users.into_iter().skip(offset).take(limit).collect();

    (paged, total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn typed_user_filter_native_typed_fields() {
        let user: crate::UserView = serde_json::from_value(json!({
            "id": "2", "name": "2", "email": "2", "emailVerified": true, "banned": true,
            "createdAt": "1970-01-01T00:00:02.000Z", "updatedAt": "1970-01-01T00:00:02.000Z",
            "score": 2, "image": "2", "displayUsername": "2", "banReason": "2",
            "phoneNumber": "2", "lastLoginMethod": "2"
        }))
        .unwrap();
        for (field, op, operand, expected) in [
            ("name", "lt", json!(10), true),
            ("image", "lt", json!(10), true),
            ("displayUsername", "lt", json!(10), true),
            ("banReason", "eq", json!(2), false),
            ("phoneNumber", "ne", json!(2), true),
            ("lastLoginMethod", "in", json!([2, 10]), false),
            ("name", "eq", json!(2), false),
            ("name", "ne", json!(2), true),
            ("name", "in", json!([2, 10]), false),
            ("name", "not_in", json!([2, 10]), true),
            ("banned", "lte", json!(true), true),
            ("banned", "eq", json!(true), true),
            ("banned", "eq", json!(1), false),
            ("banned", "ne", json!(1), true),
            ("banned", "in", json!([1]), false),
            ("banned", "not_in", json!([1]), true),
            ("emailVerified", "eq", json!(true), true),
            ("emailVerified", "gte", json!(true), true),
            ("createdAt", "gt", json!(1999), true),
            ("createdAt", "eq", json!(2000), false),
            ("score", "eq", json!(2), true),
            ("score", "in", json!([2, 10]), true),
            ("score", "not_in", json!([2, 10]), false),
            ("id", "eq", json!(2), false),
        ] {
            let params = ListUsersParams {
                filter_field: Some(field.into()),
                filter_operator: Some(op.into()),
                filter_value: Some(serde_json::from_value(operand.clone()).unwrap()),
                ..Default::default()
            };
            let (users, count) = apply_list_users(vec![user.clone()], &params);
            assert_eq!(count == 1, expected, "{field} {op} {operand}");
            assert_eq!(users.len(), count);
        }
    }
}

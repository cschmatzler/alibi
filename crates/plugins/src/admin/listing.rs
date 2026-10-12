//! Source query admission and JavaScript scalar conversion for logical listing.
use super::types::ListUsersQueryParams;
use alibi_core::endpoint::{EndpointCall, EndpointInput};
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthError, AuthResult, UserFilterValue};

pub(super) fn validate(call: &EndpointCall) -> AuthResult<EndpointInput> {
    let Some(object) = call.query().and_then(JsValue::as_object) else {
        return Err(crate::endpoint::validation(format!(
            "[query] Invalid input: expected object, received {}",
            crate::authentication_helpers::json_type(call.query())
        )));
    };
    let mut parsed = indexmap::IndexMap::new();
    let mut issues = Vec::new();
    for name in [
        "searchValue",
        "searchField",
        "searchOperator",
        "limit",
        "offset",
        "sortBy",
        "sortDirection",
        "filterField",
        "filterValue",
        "filterOperator",
    ] {
        let Some(value) = object.get(name) else {
            continue;
        };
        let choices: Option<&[&str]> = match name {
            "searchField" => Some(&["email", "name"]),
            "searchOperator" => Some(&["contains", "starts_with", "ends_with"]),
            "sortDirection" => Some(&["asc", "desc"]),
            "filterOperator" => Some(&[
                "eq",
                "ne",
                "lt",
                "lte",
                "gt",
                "gte",
                "in",
                "not_in",
                "contains",
                "starts_with",
                "ends_with",
            ]),
            _ => None,
        };
        let issue = if let Some(choices) = choices {
            (!value.as_str().is_some_and(|value| choices.contains(&value))).then(|| {
                format!(
                    "[query.{name}] Invalid option: expected one of {}",
                    choices
                        .iter()
                        .map(|value| format!("\"{value}\""))
                        .collect::<Vec<_>>()
                        .join("|")
                )
            })
        } else if matches!(name, "limit" | "offset") {
            (!value.is_string() && !value.as_f64().is_some_and(f64::is_finite))
                .then(|| format!("[query.{name}] Invalid input"))
        } else if name == "filterValue" {
            let valid = value.is_string()
                || value.as_f64().is_some_and(f64::is_finite)
                || matches!(value, JsValue::Bool(_))
                || value.as_array().is_some_and(|values| {
                    values.iter().all(JsValue::is_string)
                        || values
                            .iter()
                            .all(|value| value.as_f64().is_some_and(f64::is_finite))
                });
            (!valid).then(|| "[query.filterValue] Invalid input".to_owned())
        } else {
            (!value.is_string()).then(|| {
                format!(
                    "[query.{name}] Invalid input: expected string, received {}",
                    crate::authentication_helpers::json_type(Some(value))
                )
            })
        };
        if let Some(issue) = issue {
            issues.push(issue);
        } else {
            _ = parsed.insert(name.into(), value.clone());
        }
    }
    if !issues.is_empty() {
        return Err(crate::endpoint::validation(issues.join("; ")));
    }
    Ok(EndpointInput {
        query: Some(JsValue::Object(parsed)),
        body: call.body().cloned(),
    })
}

pub(super) fn params(call: &EndpointCall) -> AuthResult<ListUsersQueryParams> {
    let query = call
        .query()
        .ok_or_else(|| AuthError::internal("Missing admitted list query"))?;
    let text = |name| query.get(name).and_then(JsValue::as_str).map(str::to_owned);
    let number = |name| {
        query
            .get(name)
            .and_then(|value| match value {
                JsValue::String(value) => alibi_core::utils::javascript::string_to_number(value),
                JsValue::Number(value) => Some(*value),
                _ => None,
            })
            .filter(|value| !value.is_nan() && *value != 0.0)
    };
    let source_limit = number("limit");
    let source_offset = number("offset");
    let page = |value: Option<f64>| {
        value
            .filter(|value| value.is_finite() && *value > 0.0)
            .and_then(|value| format!("{:.0}", value.floor()).parse::<usize>().ok())
    };
    let filter_value = query
        .get("filterValue")
        .map(|value| match value {
            JsValue::Array(values) => values
                .iter()
                .map(JsValue::coerce_string)
                .collect::<Result<Vec<_>, _>>()
                .map(UserFilterValue::Multiple),
            value => value.coerce_string().map(UserFilterValue::Scalar),
        })
        .transpose()
        .map_err(AuthError::internal)?;
    Ok(ListUsersQueryParams {
        source_limit,
        source_offset,
        limit: page(source_limit),
        offset: page(source_offset),
        search_field: text("searchField"),
        search_value: text("searchValue").filter(|value| !value.is_empty()),
        search_operator: text("searchOperator"),
        sort_by: text("sortBy").filter(|value| !value.is_empty()),
        sort_direction: text("sortDirection"),
        filter_field: text("filterField"),
        filter_value,
        filter_operator: text("filterOperator"),
    })
}

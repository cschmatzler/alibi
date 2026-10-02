//! Raw configuration for bounded profiles, without fixture-side policy coercion.
pub(crate) fn numeric_setting(name: &str, kind: &str, default: f64) -> f64 {
    let Some(mode) = name
        .split("-numeric-")
        .nth(1)
        .and_then(|mode| mode.strip_prefix(kind))
        .and_then(|suffix| suffix.strip_prefix('-'))
    else {
        return default;
    };
    match mode {
        "zero" => 0.0,
        "fraction" => {
            if kind == "lifetime" {
                30.0005
            } else {
                1.5
            }
        }
        "negative" => -1.0,
        "nan" => f64::NAN,
        "infinity" => f64::INFINITY,
        "negative-infinity" => f64::NEG_INFINITY,
        _ => default,
    }
}

pub(in crate::runtime) fn route_path_matches(pattern: &str, path: &str) -> bool {
    let pattern_parts = pattern.split('/');
    let mut path_parts = path.split('/');
    for part in pattern_parts {
        if part == "*" {
            return true;
        }
        let Some(actual) = path_parts.next() else {
            return false;
        };
        let parameter = part.starts_with(':') || (part.starts_with('{') && part.ends_with('}'));
        if (parameter && actual.is_empty()) || (!parameter && part != actual) {
            return false;
        }
    }
    path_parts.next().is_none()
}

use crate::{AuthResult, utils::json};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;

/// Replay the source memory adapter's base-to-snapshot delta onto live rows.
/// Duplicate IDs intentionally use the last base/snapshot row for reconciliation.
pub(crate) fn merge_rows<'a, K, T>(
    live: impl IntoIterator<Item = (&'a K, &'a T)>,
    base: impl IntoIterator<Item = (&'a K, &'a T)>,
    changed: impl IntoIterator<Item = (&'a K, &'a T)>,
) -> AuthResult<Vec<(K, T)>>
where
    K: Clone + Eq + Hash + 'a,
    T: Clone + Serialize + 'a,
{
    let base: HashMap<_, _> = base.into_iter().collect();
    let changed: Vec<_> = changed.into_iter().collect();
    let changed_by_id: HashMap<_, _> = changed.iter().copied().collect();
    let mut merged = Vec::new();
    let mut placed = HashSet::new();
    for (id, row) in live {
        let before = base.get(id);
        let after = changed_by_id.get(id);
        let row = match (before, after) {
            (Some(_), None) => continue,
            (Some(before), Some(after)) if json::to_vec(before)? == json::to_vec(after)? => row,
            (_, Some(after)) => *after,
            (None, None) => row,
        };
        merged.push((id.clone(), row.clone()));
        _ = placed.insert(id.clone());
    }
    for (id, row) in changed {
        if !base.contains_key(id) && !placed.contains(id) {
            merged.push((id.clone(), row.clone()));
        }
    }
    Ok(merged)
}

pub(crate) fn merge_indexed<K, T>(
    live: &mut indexmap::IndexMap<K, T>,
    base: &indexmap::IndexMap<K, T>,
    changed: &indexmap::IndexMap<K, T>,
) -> AuthResult<()>
where
    K: Clone + Eq + Hash,
    T: Clone + Serialize,
{
    *live = merge_rows(live.iter(), base.iter(), changed.iter())?
        .into_iter()
        .collect();
    Ok(())
}

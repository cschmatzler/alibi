use crate::store::{
    UserStore,
    stateless::{StatelessSchema, StatelessStore},
};
use crate::test_store::{BundledSchema, MemoryStore};
use crate::utils::json::JsValue;
use crate::{AuthSchema, CreateUser, ListUsersParams, UserView};

#[derive(serde::Deserialize)]
struct Oracle {
    node: String,
    v8: String,
    icu: String,
    locale: String,
    better_auth: String,
    cases: Vec<Case>,
}

#[derive(serde::Deserialize)]
struct Case {
    name: String,
    ids: Vec<JsValue>,
    asc: Vec<usize>,
    desc: Vec<usize>,
    filtered_asc: Vec<usize>,
    filtered_desc: Vec<usize>,
}

fn oracle() -> Oracle {
    let data: Oracle = serde_json::from_str(include_str!("memory_user_sort_cases.json")).unwrap();
    assert_eq!(data.node, "v26.13.0");
    assert_eq!(data.v8, "14.6.202.34-node.40");
    assert_eq!(data.icu, "78.3");
    assert_eq!(data.locale, "en-US");
    assert_eq!(data.better_auth, "1.7.18");
    assert_eq!(data.cases.len(), 77);
    data
}

async fn compare_case<S: AuthSchema<User = UserView>>(store: &impl UserStore<S>, case: &Case) {
    for (index, id) in case.ids.iter().enumerate() {
        store
            .create_user(CreateUser {
                name: Some(index.to_string()),
                email: Some(format!(
                    "{index}@{}.fixture.test",
                    if index % 3 == 0 { "keep" } else { "other" },
                )),
                adapter_native_fields: [("id".into(), id.clone())].into(),
                ..Default::default()
            })
            .await
            .unwrap();
    }
    for field in ["id", "_id"] {
        for direction in [None, Some("asc"), Some("desc")] {
            for filtered in [false, true] {
                let expected = match (direction, filtered) {
                    (Some("desc"), false) => &case.desc,
                    (Some("desc"), true) => &case.filtered_desc,
                    (_, false) => &case.asc,
                    (_, true) => &case.filtered_asc,
                };
                for (offset, limit) in [
                    (0, case.ids.len() + 1),
                    (2, 5),
                    (expected.len().saturating_sub(2), 5),
                    (expected.len() + 3, 2),
                    (0, 0),
                ] {
                    let (users, count) = store
                        .list_users(ListUsersParams {
                            sort_by: Some(field.into()),
                            sort_direction: direction.map(str::to_owned),
                            search_field: filtered.then(|| "email".into()),
                            search_value: filtered.then(|| "@keep.".into()),
                            offset: Some(offset),
                            limit: Some(limit),
                            ..Default::default()
                        })
                        .await
                        .unwrap();
                    let actual = users
                        .iter()
                        .map(|user| user.name.as_ref().unwrap().parse::<usize>().unwrap())
                        .collect::<Vec<_>>();
                    assert_eq!(count, expected.len(), "{}", case.name);
                    assert_eq!(
                        actual,
                        expected
                            .iter()
                            .copied()
                            .skip(offset)
                            .take(limit)
                            .collect::<Vec<_>>(),
                        "{} {field} {direction:?} filtered={filtered} offset={offset} limit={limit}",
                        case.name,
                    );
                }
            }
        }
    }
    let (users, count) = store
        .list_users(ListUsersParams {
            limit: Some(case.ids.len() + 1),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(count, case.ids.len());
    assert_eq!(
        users
            .iter()
            .map(|user| user.name.as_ref().unwrap().parse::<usize>().unwrap())
            .collect::<Vec<_>>(),
        (0..case.ids.len()).collect::<Vec<_>>(),
        "{}: sorting mutated physical insertion order",
        case.name,
    );
}

#[tokio::test]
async fn mixed_id_sorting_memory_matches_pinned_runtime() {
    for case in oracle().cases {
        compare_case::<BundledSchema>(&MemoryStore::default(), &case).await;
    }
}

#[tokio::test]
async fn mixed_id_sorting_stateless_matches_pinned_runtime() {
    for case in oracle().cases {
        compare_case::<StatelessSchema>(&StatelessStore::default(), &case).await;
    }
}

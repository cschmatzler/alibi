use super::memory_user_id::MemoryUserId;
use crate::store::{
    UserStore,
    stateless::{StatelessSchema, StatelessStore},
};
use crate::test_store::{BundledSchema, MemoryStore};
use crate::{AuthSchema, CreateUser, ListUsersParams, UpdateUser, UserView};
use serde_json::json;

async fn physical_primitives<S: AuthSchema<User = UserView>>(
    store: &impl UserStore<S>,
    supports_page: bool,
) {
    for (raw, label) in [(json!(2), "number"), (json!(true), "boolean")] {
        let output = crate::utils::json::JsValue::from(raw.clone())
            .coerce_string()
            .unwrap();
        let numeric = store
            .create_user(CreateUser {
                name: Some(label.to_owned()),
                email: Some(format!("{label}@example.test")),
                adapter_native_fields: [("id".to_owned(), raw)].into(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(numeric.id, output);
        assert!(store.get_user_by_id(&output).await.unwrap().is_none());
        assert!(
            store
                .list_users_by_ids(&[output.clone()])
                .await
                .unwrap()
                .is_empty()
        );
        if supports_page {
            assert!(
                store
                    .list_users_by_ids_page(&[output.clone()], 10.0)
                    .await
                    .unwrap()
                    .is_empty()
            );
        } else {
            assert!(matches!(
                store.list_users_by_ids_page(&[output.clone()], 10.0).await,
                Err(crate::AuthError::NotImplemented(_))
            ));
        }
        assert!(
            store
                .update_user(
                    &output,
                    UpdateUser {
                        name: Some("must not mutate".into()),
                        ..Default::default()
                    }
                )
                .await
                .is_err()
        );
        store.delete_user(&output).await.unwrap();
        assert_eq!(
            store
                .get_user_by_email(&format!("{label}@example.test").into())
                .await
                .unwrap()
                .unwrap()
                .name
                .as_deref(),
            Some(label)
        );

        let string = store
            .create_user(CreateUser {
                id: Some(output.clone()),
                name: Some("string".to_owned()),
                email: Some(format!("string-{label}@example.test")),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(numeric.id, string.id);
        assert_eq!(
            store
                .get_user_by_id(&output)
                .await
                .unwrap()
                .unwrap()
                .name
                .as_deref(),
            Some("string")
        );
        assert_eq!(
            store
                .list_users_by_ids(&[output.clone()])
                .await
                .unwrap()
                .len(),
            1
        );
        if supports_page {
            assert_eq!(
                store
                    .list_users_by_ids_page(&[output.clone()], 10.0)
                    .await
                    .unwrap()
                    .len(),
                1
            );
        }
        for (operator, expected) in [("eq", 1), ("in", 1)] {
            let filter_value = if operator == "in" {
                vec![output.clone()].into()
            } else {
                output.clone().into()
            };
            let (users, count) = store
                .list_users(ListUsersParams {
                    filter_field: Some("id".into()),
                    filter_operator: Some(operator.into()),
                    filter_value: Some(filter_value),
                    ..Default::default()
                })
                .await
                .unwrap();
            assert_eq!(count, expected);
            assert_eq!(users[0].name.as_deref(), Some("string"));
        }
        let (other, _) = store
            .list_users(ListUsersParams {
                filter_field: Some("id".into()),
                filter_operator: Some("ne".into()),
                filter_value: Some(output.clone().into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(other.iter().any(|user| user.name.as_deref() == Some(label)));
        store
            .update_user(
                &output,
                UpdateUser {
                    name: Some("changed string".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .get_user_by_email(&format!("{label}@example.test").into())
                .await
                .unwrap()
                .unwrap()
                .name
                .as_deref(),
            Some(label)
        );
        store.delete_user(&output).await.unwrap();
        assert!(store.get_user_by_id(&output).await.unwrap().is_none());
        assert!(
            store
                .get_user_by_email(&format!("{label}@example.test").into())
                .await
                .unwrap()
                .is_some()
        );
    }
    let (users, count) = store.list_users(ListUsersParams::default()).await.unwrap();
    assert_eq!(count, 2);
    assert_eq!(users.len(), 2);
}

#[tokio::test]
async fn stateless_physical_primitive_ids_do_not_alias_string_ids() {
    physical_primitives::<StatelessSchema>(&StatelessStore::default(), true).await;
}

#[tokio::test]
async fn memory_physical_primitive_ids_do_not_alias_string_ids() {
    physical_primitives::<BundledSchema>(&MemoryStore::default(), false).await;
}

#[test]
fn primitive_identity_keys_use_javascript_number_values() {
    assert_eq!(
        MemoryUserId::supplied(Some(&json!(2))).unwrap().0,
        MemoryUserId::supplied(Some(&json!(2.0))).unwrap().0
    );
    assert_ne!(
        MemoryUserId::supplied(Some(&json!(1))).unwrap().0,
        MemoryUserId::supplied(Some(&json!(true))).unwrap().0
    );
    for raw in [
        json!(0),
        json!(-0.0),
        json!(false),
        json!(null),
        json!(""),
        json!([]),
        json!({}),
    ] {
        assert!(MemoryUserId::supplied(Some(&raw)).is_none());
    }
}

async fn physical_relational_filters<S: AuthSchema<User = UserView>>(store: &impl UserStore<S>) {
    for (raw, label) in [
        (json!(2), "n2"),
        (json!("2"), "s2"),
        (json!(10), "n10"),
        (json!("10"), "s10"),
        (json!(true), "btrue"),
        (json!("true"), "strue"),
    ] {
        store
            .create_user(CreateUser {
                name: Some(label.into()),
                email: Some(format!("{label}@example.test")),
                adapter_native_fields: [("id".to_owned(), raw)].into(),
                ..Default::default()
            })
            .await
            .unwrap();
    }

    // Expected sets come from the memory adapter's physical record[field] comparisons.
    let scalar_cases = [
        (
            "10",
            [
                "btrue n2",
                "btrue n10 n2 s10",
                "s2 strue",
                "n10 s10 s2 strue",
            ],
        ),
        (
            "2",
            [
                "btrue s10",
                "btrue n2 s10 s2",
                "n10 strue",
                "n10 n2 s2 strue",
            ],
        ),
        ("notnumeric", ["s10 s2", "s10 s2", "strue", "strue"]),
        (
            "",
            [
                "",
                "",
                "btrue n10 n2 s10 s2 strue",
                "btrue n10 n2 s10 s2 strue",
            ],
        ),
        (
            " \t\u{feff}",
            [
                "",
                "",
                "btrue n10 n2 s10 s2 strue",
                "btrue n10 n2 s10 s2 strue",
            ],
        ),
        (
            " 2 ",
            [
                "btrue",
                "btrue n2",
                "n10 s10 s2 strue",
                "n10 n2 s10 s2 strue",
            ],
        ),
        (
            "0x10",
            [
                "btrue n10 n2",
                "btrue n10 n2",
                "s10 s2 strue",
                "s10 s2 strue",
            ],
        ),
        (
            "0b10",
            [
                "btrue",
                "btrue n2",
                "n10 s10 s2 strue",
                "n10 n2 s10 s2 strue",
            ],
        ),
        (
            "0o10",
            [
                "btrue n2",
                "btrue n2",
                "n10 s10 s2 strue",
                "n10 s10 s2 strue",
            ],
        ),
        (
            "2e0",
            [
                "btrue s10 s2",
                "btrue n2 s10 s2",
                "n10 strue",
                "n10 n2 strue",
            ],
        ),
        (
            "Infinity",
            [
                "btrue n10 n2 s10 s2",
                "btrue n10 n2 s10 s2",
                "strue",
                "strue",
            ],
        ),
        (
            "-Infinity",
            [
                "",
                "",
                "btrue n10 n2 s10 s2 strue",
                "btrue n10 n2 s10 s2 strue",
            ],
        ),
        ("+0x10", ["", "", "s10 s2 strue", "s10 s2 strue"]),
        ("1_0", ["s10", "s10", "s2 strue", "s2 strue"]),
        ("inf", ["s10 s2", "s10 s2", "strue", "strue"]),
        ("\u{0085}", ["s10 s2 strue", "s10 s2 strue", "", ""]),
    ];
    let array_cases = [
        (
            vec![],
            [
                "",
                "",
                "btrue n10 n2 s10 s2 strue",
                "btrue n10 n2 s10 s2 strue",
            ],
        ),
        (
            vec!["2"],
            [
                "btrue s10",
                "btrue n2 s10 s2",
                "n10 strue",
                "n10 n2 s2 strue",
            ],
        ),
        (vec!["1", "0"], ["", "", "s10 s2 strue", "s10 s2 strue"]),
        (vec!["", ""], ["", "", "s10 s2 strue", "s10 s2 strue"]),
        (vec!["notnumeric"], ["s10 s2", "s10 s2", "strue", "strue"]),
    ];
    let cases = scalar_cases
        .into_iter()
        .map(|(value, expected)| (crate::UserFilterValue::from(value), expected))
        .chain(array_cases.into_iter().map(|(values, expected)| {
            (
                values
                    .into_iter()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
                    .into(),
                expected,
            )
        }));
    for (value, expected) in cases {
        for field in ["id", "_id"] {
            for (operator, expected) in ["lt", "lte", "gt", "gte"].into_iter().zip(expected) {
                let (users, count) = store
                    .list_users(ListUsersParams {
                        filter_field: Some(field.into()),
                        filter_operator: Some(operator.into()),
                        filter_value: Some(value.clone()),
                        sort_by: Some("name".into()),
                        sort_direction: Some("asc".into()),
                        ..Default::default()
                    })
                    .await
                    .unwrap();
                let names = users
                    .iter()
                    .map(|user| user.name.as_deref().unwrap())
                    .collect::<Vec<_>>();
                assert_eq!(names.join(" "), expected, "{field} {operator} {value:?}");
                assert_eq!(count, names.len(), "{field} {operator} {value:?}");
            }
        }
    }

    for (operator, value, expected) in [
        ("eq", "2".into(), "s2"),
        ("ne", "2".into(), "btrue n10 n2 s10 strue"),
        (
            "in",
            vec!["2".to_owned(), "10".to_owned(), "true".to_owned()].into(),
            "s10 s2 strue",
        ),
        (
            "not_in",
            vec!["2".to_owned(), "10".to_owned(), "true".to_owned()].into(),
            "btrue n10 n2",
        ),
    ] {
        let (users, count) = store
            .list_users(ListUsersParams {
                filter_field: Some("id".into()),
                filter_operator: Some(operator.into()),
                filter_value: Some(value),
                sort_by: Some("name".into()),
                sort_direction: Some("asc".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        let names = users
            .iter()
            .map(|user| user.name.as_deref().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(names.join(" "), expected, "{operator}");
        assert_eq!(count, names.len());
    }

    let (page, count) = store
        .list_users(ListUsersParams {
            filter_field: Some("id".into()),
            filter_operator: Some("gte".into()),
            filter_value: Some("10".into()),
            sort_by: Some("name".into()),
            sort_direction: Some("asc".into()),
            offset: Some(1),
            limit: Some(1),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(count, 4);
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].name.as_deref(), Some("s10"));
}

async fn physical_relational_utf16<S: AuthSchema<User = UserView>>(store: &impl UserStore<S>) {
    for (raw, label) in [
        (json!("\u{10000}"), "astral"),
        (json!("\u{e000}"), "bmp"),
        (json!(2), "number"),
    ] {
        store
            .create_user(CreateUser {
                name: Some(label.into()),
                email: Some(format!("{label}@example.test")),
                adapter_native_fields: [("id".to_owned(), raw)].into(),
                ..Default::default()
            })
            .await
            .unwrap();
    }
    for (value, expected) in [
        ("\u{e000}", ["astral", "astral bmp", "", "bmp"]),
        ("\u{10000}", ["", "astral", "bmp", "astral bmp"]),
    ] {
        for (operator, expected) in ["lt", "lte", "gt", "gte"].into_iter().zip(expected) {
            let (users, count) = store
                .list_users(ListUsersParams {
                    filter_field: Some("id".into()),
                    filter_operator: Some(operator.into()),
                    filter_value: Some(value.into()),
                    sort_by: Some("name".into()),
                    sort_direction: Some("asc".into()),
                    ..Default::default()
                })
                .await
                .unwrap();
            let names = users
                .iter()
                .map(|user| user.name.as_deref().unwrap())
                .collect::<Vec<_>>();
            assert_eq!(names.join(" "), expected, "{operator} {value:?}");
            assert_eq!(count, names.len());
        }
    }
}

#[tokio::test]
async fn stateless_physical_primitive_id_relational_filters() {
    physical_relational_filters::<StatelessSchema>(&StatelessStore::default()).await;
}

#[tokio::test]
async fn memory_physical_primitive_id_relational_filters() {
    physical_relational_filters::<BundledSchema>(&MemoryStore::default()).await;
}

#[tokio::test]
async fn stateless_physical_primitive_id_relational_utf16() {
    physical_relational_utf16::<StatelessSchema>(&StatelessStore::default()).await;
}

#[tokio::test]
async fn memory_physical_primitive_id_relational_utf16() {
    physical_relational_utf16::<BundledSchema>(&MemoryStore::default()).await;
}

async fn typed_filter_operands<S: AuthSchema<User = UserView>>(store: &impl UserStore<S>) {
    for (raw, label) in [
        (json!(2), "n2"),
        (json!("2"), "s2"),
        (json!(10), "n10"),
        (json!("10"), "s10"),
        (json!(true), "btrue"),
        (json!("true"), "strue"),
    ] {
        store
            .create_user(CreateUser {
                name: Some(label.into()),
                email: Some(format!("{label}@example.test")),
                adapter_native_fields: [("id".to_owned(), raw)].into(),
                ..Default::default()
            })
            .await
            .unwrap();
    }
    for (operator, raw, expected) in [
        ("lt", json!(10), "btrue n2 s2"),
        ("lt", json!("10"), "btrue n2"),
        ("lte", json!(true), "btrue"),
        ("lte", json!("true"), "s10 s2 strue"),
        ("eq", json!(2), "n2"),
        ("eq", json!(false), ""),
        ("ne", json!(false), "btrue n10 n2 s10 s2 strue"),
        ("eq", json!(["2"]), ""),
        ("ne", json!(["2"]), "btrue n10 n2 s10 s2 strue"),
        ("ne", json!(2), "btrue n10 s10 s2 strue"),
        ("eq", json!(true), "btrue"),
        ("ne", json!(true), "n10 n2 s10 s2 strue"),
        ("in", json!([2, 10]), "n10 n2"),
        ("not_in", json!([2, 10]), "btrue s10 s2 strue"),
        ("in", json!(["2", "10"]), "s10 s2"),
        ("not_in", json!(["2", "10"]), "btrue n10 n2 strue"),
        ("eq", json!([2]), ""),
        ("ne", json!([2]), "btrue n10 n2 s10 s2 strue"),
        ("lt", json!([10]), "btrue n2"),
        ("lte", json!([]), ""),
    ] {
        for field in ["id", "_id"] {
            let operand = serde_json::from_value(raw.clone()).unwrap();
            let (users, count) = store
                .list_users(ListUsersParams {
                    filter_field: Some(field.into()),
                    filter_operator: Some(operator.into()),
                    filter_value: Some(operand),
                    sort_by: Some("name".into()),
                    sort_direction: Some("asc".into()),
                    ..Default::default()
                })
                .await
                .unwrap();
            let names = users
                .iter()
                .map(|user| user.name.as_deref().unwrap())
                .collect::<Vec<_>>();
            assert_eq!(names.join(" "), expected, "{field} {operator} {raw}");
            assert_eq!(count, names.len());
        }
    }
}

#[tokio::test]
async fn typed_user_filter_memory_operands() {
    typed_filter_operands::<BundledSchema>(&MemoryStore::default()).await;
}

#[tokio::test]
async fn typed_user_filter_stateless_operands() {
    typed_filter_operands::<StatelessSchema>(&StatelessStore::default()).await;
}

async fn legacy_filter_operands<S: AuthSchema<User = UserView>>(store: &impl UserStore<S>) {
    use crate::UserFilterValue::{Multiple, Native, Scalar};

    let user = store
        .create_user(CreateUser {
            id: Some("unicode-filter".into()),
            name: Some("\u{10000}".into()),
            email: Some("alpha@example.test".into()),
            email_verified: Some(true),
            banned: Some(false),
            ..Default::default()
        })
        .await
        .unwrap();

    for (field, operator, operand, expected) in [
        ("name", "lt", Scalar("\u{e000}".into()), true),
        ("name", "gte", Scalar("\u{e000}".into()), false),
        ("email", "lt", Multiple(vec!["z".into()]), true),
        ("email", "gt", Multiple(vec!["a".into()]), true),
        (
            "email",
            "lte",
            Multiple(vec!["alpha@example.test".into()]),
            true,
        ),
        ("banned", "eq", Scalar("not-true".into()), true),
        ("emailVerified", "eq", Scalar("true".into()), true),
        (
            "createdAt",
            "eq",
            Scalar(user.created_at.to_rfc3339()),
            false,
        ),
        (
            "createdAt",
            "ne",
            Scalar(user.created_at.to_rfc3339()),
            true,
        ),
        (
            "createdAt",
            "lte",
            Scalar(user.created_at.to_rfc3339()),
            false,
        ),
        (
            "createdAt",
            "gte",
            Scalar(user.created_at.timestamp_millis().to_string()),
            true,
        ),
        (
            "email",
            "in",
            Multiple(vec!["alpha@example.test".into()]),
            true,
        ),
    ] {
        for operand in [operand.clone(), Native(operand.native())] {
            let (users, count) = store
                .list_users(ListUsersParams {
                    filter_field: Some(field.into()),
                    filter_operator: Some(operator.into()),
                    filter_value: Some(operand.clone()),
                    ..Default::default()
                })
                .await
                .unwrap();
            assert_eq!(
                count,
                usize::from(expected),
                "{field} {operator} {operand:?}"
            );
            assert_eq!(users.len(), count);
            if expected {
                assert_eq!(users[0].id, user.id);
            }
        }
    }
}

#[tokio::test]
async fn legacy_user_filter_memory_operands_match_native_channel() {
    legacy_filter_operands::<BundledSchema>(&MemoryStore::default()).await;
}

#[tokio::test]
async fn legacy_user_filter_stateless_operands_match_native_channel() {
    legacy_filter_operands::<StatelessSchema>(&StatelessStore::default()).await;
}

async fn optional_user_sort<S: AuthSchema<User = UserView>>(store: &impl UserStore<S>) {
    for (id, day, verified) in [
        ("b", 2, true),
        ("c", 1, true),
        ("a", 3, true),
        ("d", 4, false),
    ] {
        store
            .create_user(CreateUser {
                id: Some(id.into()),
                email: Some(format!("{id}@example.test")),
                email_verified: Some(verified),
                created_at: Some(
                    chrono::DateTime::parse_from_rfc3339(&format!("2020-01-{day:02}T00:00:00Z"))
                        .unwrap()
                        .with_timezone(&chrono::Utc),
                ),
                ..Default::default()
            })
            .await
            .unwrap();
    }
    let params = ListUsersParams {
        search_value: Some("@example.test".into()),
        filter_field: Some("emailVerified".into()),
        filter_value: Some("true".into()),
        ..Default::default()
    };
    let ids = |users: &[UserView]| {
        users
            .iter()
            .map(|user| user.id.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    };
    let native_order = "b c a";
    for sort_by in [None, Some("")] {
        for sort_direction in [None, Some("asc"), Some("desc")] {
            let query = ListUsersParams {
                sort_by: sort_by.map(str::to_owned),
                sort_direction: sort_direction.map(str::to_owned),
                ..params.clone()
            };
            let (users, count) = store.list_users(query.clone()).await.unwrap();
            assert_eq!(ids(&users), native_order, "{sort_by:?} {sort_direction:?}");
            assert_eq!(count, 3);
            for (offset, limit) in [(0, 2), (1, 1), (2, 2), (3, 1)] {
                let (page, total) = store
                    .list_users(ListUsersParams {
                        offset: Some(offset),
                        limit: Some(limit),
                        ..query.clone()
                    })
                    .await
                    .unwrap();
                let expected = native_order
                    .split(' ')
                    .skip(offset)
                    .take(limit)
                    .collect::<Vec<_>>();
                assert_eq!(ids(&page), expected.join(" "));
                assert_eq!(total, 3);
            }
        }
    }
    for (direction, expected) in [
        (None, "c b a"),
        (Some("asc"), "c b a"),
        (Some("desc"), "a b c"),
    ] {
        let (users, count) = store
            .list_users(ListUsersParams {
                sort_by: Some("createdAt".into()),
                sort_direction: direction.map(str::to_owned),
                ..params.clone()
            })
            .await
            .unwrap();
        assert_eq!(ids(&users), expected, "{direction:?}");
        assert_eq!(count, 3);
    }
    store
        .update_user(
            "c",
            UpdateUser {
                name: Some("renamed".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let (users, count) = store.list_users(params.clone()).await.unwrap();
    assert_eq!(ids(&users), "b c a");
    assert_eq!(count, 3);
    store.delete_user("c").await.unwrap();
    let (users, count) = store.list_users(params.clone()).await.unwrap();
    assert_eq!(ids(&users), "b a");
    assert_eq!(count, 2);
    store
        .create_user(CreateUser {
            id: Some("c".into()),
            email: Some("c@example.test".into()),
            email_verified: Some(true),
            ..Default::default()
        })
        .await
        .unwrap();
    let (users, count) = store.list_users(params).await.unwrap();
    assert_eq!(ids(&users), "b a c");
    assert_eq!(count, 3);
}

#[tokio::test]
async fn optional_user_sort_memory_preserves_insertion_order() {
    optional_user_sort::<BundledSchema>(&MemoryStore::default()).await;
}

#[tokio::test]
async fn optional_user_sort_stateless_preserves_insertion_order() {
    optional_user_sort::<StatelessSchema>(&StatelessStore::default()).await;
}

async fn empty_user_list_selectors<S: AuthSchema<User = UserView>>(store: &impl UserStore<S>) {
    store
        .create_user(CreateUser {
            id: Some("no-email".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    store
        .create_user(CreateUser {
            id: Some("with-email".into()),
            email: Some("alpha@example.test".into()),
            ..Default::default()
        })
        .await
        .unwrap();

    for (params, expected) in [
        (
            ListUsersParams {
                search_value: Some("".into()),
                ..Default::default()
            },
            vec!["no-email", "with-email"],
        ),
        (
            ListUsersParams {
                search_value: Some("".into()),
                search_field: Some("username".into()),
                search_operator: Some("starts_with".into()),
                ..Default::default()
            },
            vec!["no-email", "with-email"],
        ),
        (
            ListUsersParams {
                search_value: Some("alpha".into()),
                search_field: Some("".into()),
                ..Default::default()
            },
            vec!["with-email"],
        ),
        (
            ListUsersParams {
                filter_field: Some("".into()),
                filter_value: Some("alpha@example.test".into()),
                ..Default::default()
            },
            vec!["with-email"],
        ),
        (
            ListUsersParams {
                filter_value: Some("".into()),
                ..Default::default()
            },
            vec![],
        ),
    ] {
        let (users, count) = store.list_users(params.clone()).await.unwrap();
        let ids = users
            .iter()
            .map(|user| user.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ids, expected, "{params:?}");
        assert_eq!(count, expected.len());
    }
}

#[tokio::test]
async fn empty_user_list_selectors_memory_follow_admin_truthiness() {
    empty_user_list_selectors::<BundledSchema>(&MemoryStore::default()).await;
}

#[tokio::test]
async fn empty_user_list_selectors_stateless_follow_admin_truthiness() {
    empty_user_list_selectors::<StatelessSchema>(&StatelessStore::default()).await;
}

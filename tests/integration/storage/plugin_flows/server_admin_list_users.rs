//! Logical listing retains source query types, stored authority and SQL semantics.
use super::*;
use alibi::UpdateUser;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{AdminListUsersQuery, AdminPlugin, RolePermissions};
use alibi::utils::json::JsValue;

backend_tests!(server_admin_list_users_preserves_query_pagination_and_sql_behavior);

async fn server_admin_list_users_preserves_query_pagination_and_sql_behavior<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config.clone()), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(AdminPlugin::new())
        .endpoint_hook(super::server_admin_support::AdminObserver)
        .build()
        .await?;
    let mut people = Vec::new();
    for name in ["Admin", "Alpha", "Beta", "Foreign", "Gamma"] {
        people.push(call(&auth,request("/sign-up/email",Some(json!({"name":name,"email":format!("listing-{name}@example.test"),"password":PASSWORD})),""),200).await);
    }
    let admin_id = body(&people[0])["user"]["id"].as_str().unwrap().to_owned();
    drop(
        auth.store()
            .update_user(
                &admin_id,
                UpdateUser {
                    role: Some("admin".into()),
                    ..Default::default()
                },
            )
            .await?,
    );
    let admin = EndpointOptions {
        headers: Some(
            [("cookie".into(), cookies(&people[0]))]
                .into_iter()
                .collect(),
        ),
        ..Default::default()
    };
    let member = EndpointOptions {
        headers: Some(
            [("cookie".into(), cookies(&people[1]))]
                .into_iter()
                .collect(),
        ),
        ..Default::default()
    };
    let before = db.tables(&["user", "account", "session"]).await?;
    for (query, options, status) in [
        (None, EndpointOptions::default(), 400),
        (Some(json!(null)), EndpointOptions::default(), 400),
        (Some(json!(7)), EndpointOptions::default(), 400),
        (Some(json!({"limit":true})), EndpointOptions::default(), 400),
        (
            Some(json!({"offset":null})),
            EndpointOptions::default(),
            400,
        ),
        (Some(json!({"searchField":"role"})), admin.clone(), 400),
        (
            Some(json!({"sortDirection":"sideways"})),
            EndpointOptions::default(),
            400,
        ),
        (
            Some(json!({"filterValue":["x",7]})),
            EndpointOptions::default(),
            400,
        ),
        (
            Some(json!({"filterOperator":"bogus"})),
            EndpointOptions::default(),
            400,
        ),
        (Some(json!({})), EndpointOptions::default(), 401),
        (
            Some(json!({})),
            EndpointOptions {
                headers: Some(Default::default()),
                ..Default::default()
            },
            401,
        ),
        (Some(json!({"role":"admin","userId":admin_id})), member, 403),
    ] {
        let mut endpoint = ServerEndpoint::<JsValue>::new("admin", "listUsers")
            .with_body(&json!({"role":"admin"}))?;
        if let Some(query) = query {
            endpoint = endpoint.with_query(&query)?;
        }
        let error = auth.dispatch_endpoint(endpoint, options).await.unwrap_err();
        assert_eq!(error.error.status_code(), status);
        if status == 401 {
            assert!(error.body_absent);
        }
    }
    let deny_all = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .plugin(SessionManagementPlugin::new())
        .plugin(
            AdminPlugin::new().roles(std::collections::HashMap::<String, RolePermissions>::new()),
        )
        .build()
        .await?;
    let error = deny_all
        .dispatch_endpoint(
            ServerEndpoint::<JsValue>::new("admin", "listUsers").with_query(&json!({}))?,
            admin.clone(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.error.status_code(), 403);
    let all = vec!["Admin", "Alpha", "Beta", "Foreign", "Gamma"];
    for (query, names, total, pagination) in [
        (json!({}), all.clone(), 5, json!({})),
        (
            json!({"searchField":"name","searchValue":"alpha"}),
            vec!["Alpha"],
            1,
            json!({}),
        ),
        (
            json!({"filterField":"name","filterOperator":"contains","filterValue":"beta"}),
            vec!["Beta"],
            1,
            json!({}),
        ),
        (
            json!({"searchField":"name","searchValue":"a","filterField":"name","filterOperator":"in","filterValue":["Alpha","Beta","Gamma"]}),
            vec!["Alpha", "Beta", "Gamma"],
            3,
            json!({}),
        ),
        (
            json!({"limit":2,"offset":1}),
            vec!["Alpha", "Beta"],
            5,
            json!({"limit":2,"offset":1}),
        ),
        (
            json!({"limit":"2","offset":"1"}),
            vec!["Alpha", "Beta"],
            5,
            json!({"limit":2,"offset":1}),
        ),
        (json!({"limit":0,"offset":0}), all.clone(), 5, json!({})),
        (json!({"limit":"junk"}), all.clone(), 5, json!({})),
        (
            json!({"limit":"0x2"}),
            vec!["Admin", "Alpha"],
            5,
            json!({"limit":2}),
        ),
        (json!({"limit":-1}), all.clone(), 5, json!({"limit":-1})),
        (json!({"offset":-1}), all.clone(), 5, json!({"offset":-1})),
        (json!({"limit":1.5}), vec![], 0, json!({})),
        (json!({"offset":"1.5"}), vec![], 0, json!({})),
        (json!({"limit":"Infinity"}), vec![], 0, json!({})),
        (
            json!({"filterField":"name","filterOperator":"in","filterValue":["Beta","Alpha","Alpha"]}),
            vec!["Alpha", "Beta"],
            2,
            json!({}),
        ),
        (
            json!({"filterField":"emailVerified","filterOperator":"in","filterValue":[0]}),
            all.clone(),
            5,
            json!({}),
        ),
        (
            json!({"filterField":"banned","filterValue":false}),
            all.clone(),
            5,
            json!({}),
        ),
        (json!({"sortBy":"unknown"}), vec![], 0, json!({})),
        (
            json!({"filterField":"unknown","filterValue":"x"}),
            vec![],
            0,
            json!({}),
        ),
    ] {
        let mut full =
            json!({"sortBy":"name","sortDirection":"asc","userId":body(&people[1])["user"]["id"]})
                .as_object()
                .unwrap()
                .clone();
        full.extend(query.as_object().unwrap().clone());
        let typed: AdminListUsersQuery = serde_json::from_value(json!(full))?;
        let output = auth
            .dispatch_endpoint(
                AdminPlugin::list_users_endpoint(&typed)?
                    .with_query(&full)?
                    .with_body(&json!(7))?,
                admin.clone(),
            )
            .await?;
        assert_eq!(output.decode()?.total, total);
        let value: Value = alibi::utils::json::from_value(output.value().clone())?;
        assert_eq!(
            value["users"]
                .as_array()
                .unwrap()
                .iter()
                .map(|user| user["name"].as_str().unwrap())
                .collect::<Vec<_>>(),
            names
        );
        assert_eq!(value["total"], total);
        for key in ["limit", "offset"] {
            assert_eq!(value.get(key), pagination.get(key));
        }
        for user in value["users"].as_array().unwrap() {
            assert!(user.get("password").is_none());
            assert!(user.get("token").is_none());
        }
        assert_eq!(output.headers().get("x-admin-principal"), Some(&admin_id));
        assert_eq!(
            output
                .headers()
                .get_all("set-cookie")
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec![
                "application_a=first; Path=/; HttpOnly",
                "application_b=second; Path=/; HttpOnly"
            ]
        );
    }
    assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    B::close(connection).await
}

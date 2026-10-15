//! User input errors retain field paths and precede bearer authentication.
use super::*;
use alibi::endpoint::{EndpointOptions, EndpointResponse};
use alibi::plugins::ScimPlugin;
backend_tests!(
    scim_user_input_reports_reference_field_errors_before_authentication,
    scim_user_size_bounds_validated_input_before_authentication
);
postgres_tests!(
    scim_user_input_reports_reference_field_errors_before_authentication,
    scim_user_size_bounds_validated_input_before_authentication
);
async fn scim_user_input_reports_reference_field_errors_before_authentication<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(ScimPlugin::new().connections(super::scim_group_read::connections()))
        .build()
        .await?;
    let schema = "urn:ietf:params:scim:schemas:core:2.0:User";
    let valid = json!({"schemas":[schema],"userName":"owner@example.com"});
    let mut cases=vec![(json!({}),"[body.schemas] Invalid input: expected array, received undefined; [body.userName] Invalid input: expected string, received undefined".to_owned()),(json!({"schemas":[schema]}),"[body.userName] Invalid input: expected string, received undefined".into())];
    for (key,value,detail) in [
 ("userName",Value::Null,"[body.userName] Invalid input: expected string, received null".to_owned()),
 ("userName",json!(" "),"[body.userName] Too small: expected string to have >=1 characters; [body.emails] emails must contain an email when userName is not an email address".into()),
 ("userName",json!("x".repeat(513)),"[body.userName] Too big: expected string to have <=512 characters; [body.emails] emails must contain an email when userName is not an email address".into()),
 ("active",Value::Null,"[body.active] Invalid input: expected boolean, received null".into()),
 ("active",json!("false"),"[body.active] Invalid input: expected boolean, received string".into()),
 ("userName",json!("not-email"),"[body.emails] emails must contain an email when userName is not an email address".into()),
 ("schemas",json!([]),format!("[body.schemas] Too small: expected array to have >=1 items; [body.schemas] schemas must contain {schema}")),
 ("schemas",json!(["bad"]),format!("[body.schemas] Unsupported SCIM User schema bad; [body.schemas] schemas must contain {schema}")),
 ("schemas",Value::Null,"[body.schemas] Invalid input: expected array, received null".into()),
 ("schemas",json!([schema,schema]),format!("[body.schemas] SCIM User schema {schema} must not be duplicated; [body.schemas] SCIM User schema {schema} must not be duplicated")),
 ("externalId",Value::Null,"[body.externalId] Invalid input: expected string, received null".into()),
 ("displayName",json!(42),"[body.displayName] Invalid input: expected string, received number".into()),
 ("name",Value::Null,"[body.name] Invalid input: expected object, received null".into()),
 ("emails",Value::Null,"[body.emails] Invalid input: expected array, received null".into()),
 ("emails",json!([{"value":"bad"}]),"[body.emails.0.value] Invalid email address".into()),
 ("emails",json!([{"value":"a@example.com","primary":null}]),"[body.emails.0.primary] Invalid input: expected boolean, received null".into()),
 ("userName",json!(123),"[body.userName] Invalid input: expected string, received number".into()),
 ("schemas",json!([1]),"[body.schemas.0] Invalid input: expected string, received number".into()),
 ("name",json!({"givenName":" "}),"[body.name.givenName] Too small: expected string to have >=1 characters".into()),
 ("title",json!([]),"[body.title] Invalid input: expected string, received array; [body.title] Too small: expected array to have >=1 items".into()),
 ("title",json!(["a","b"]),"[body.title] Invalid input: expected string, received array".into()),
 ("title",json!([null]),"[body.title] Invalid input: expected string, received null".into()),
 ("emails",json!([{}]),"[body.emails.0.value] Invalid input: expected string, received undefined".into()),
 ("emails",json!([{"value":"a@example.com","type":" "}]),"[body.emails.0.type] Too small: expected string to have >=1 characters".into()),
 ] {let mut input=valid.clone();input[key]=value;cases.push((input,detail));}
    cases.extend([
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"owner@example.com","emails":[{"value":"a@example.com","primary":true},{"value":"b@example.com","primary":true}]}), "[body.emails] emails cannot contain multiple primary values".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"owner@example.com","emails":[{"value":"a@example.com","type":"WORK"},{"value":"a@example.com","type":"work"}]}), "[body.emails] emails cannot contain duplicate type and value pairs; [body.emails] emails cannot contain duplicate defined types".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"owner@example.com","emails":[{"value":"a@example.com","type":"WORK"},{"value":"b@example.com","type":"work"}]}), "[body.emails] emails cannot contain duplicate defined types".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"owner@example.com","emails":[{"value":"a0@example.com"},{"value":"a1@example.com"},{"value":"a2@example.com"},{"value":"a3@example.com"},{"value":"a4@example.com"},{"value":"a5@example.com"},{"value":"a6@example.com"},{"value":"a7@example.com"},{"value":"a8@example.com"},{"value":"a9@example.com"},{"value":"a10@example.com"},{"value":"a11@example.com"},{"value":"a12@example.com"},{"value":"a13@example.com"},{"value":"a14@example.com"},{"value":"a15@example.com"},{"value":"a16@example.com"},{"value":"a17@example.com"},{"value":"a18@example.com"},{"value":"a19@example.com"},{"value":"a20@example.com"}]}), "[body.emails] Too big: expected array to have <=20 items".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"owner@example.com","phoneNumbers":null}), "[body.phoneNumbers] Invalid input: expected array, received null".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"owner@example.com","phoneNumbers":[null]}), "[body.phoneNumbers.0] Invalid input: expected object, received null".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"owner@example.com","phoneNumbers":[{}]}), "[body.phoneNumbers.0.value] Invalid input: expected string, received undefined".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"owner@example.com","phoneNumbers":[{"value":42}]}), "[body.phoneNumbers.0.value] Invalid input: expected string, received number".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"owner@example.com","phoneNumbers":[{"value":"123","primary":null}]}), "[body.phoneNumbers.0.primary] Invalid input: expected boolean, received null".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"owner@example.com","phoneNumbers":[{"value":"123","type":"WORK"},{"value":"456","type":"work"}]}), "[body.phoneNumbers] phoneNumbers cannot contain duplicate defined types".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"owner@example.com","phoneNumbers":[{"value":"123","primary":true},{"value":"456","primary":true}]}), "[body.phoneNumbers] phoneNumbers cannot contain multiple primary values".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"owner@example.com","phoneNumbers":[{"value":"0"},{"value":"1"},{"value":"2"},{"value":"3"},{"value":"4"},{"value":"5"},{"value":"6"},{"value":"7"},{"value":"8"},{"value":"9"},{"value":"10"}]}), "[body.phoneNumbers] Too big: expected array to have <=10 items".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"owner@example.com","addresses":[{}]}), "[body.addresses.0] addresses must contain at least one address value".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"owner@example.com","addresses":[{"type":"home","primary":true}]}), "[body.addresses.0] addresses must contain at least one address value".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"owner@example.com","addresses":[{"locality":42}]}), "[body.addresses.0.locality] Invalid input: expected string, received number".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"owner@example.com","addresses":[{"formatted":"a","type":"HOME"},{"formatted":"b","type":"home"}]}), "[body.addresses] addresses cannot contain duplicate defined types".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"owner@example.com","roles":[{}]}), "[body.roles.0.value] Invalid input: expected string, received undefined".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"owner@example.com","roles":[{"value":"a","display":null}]}), "[body.roles.0.display] Invalid input: expected string, received null".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"owner@example.com","roles":[{"value":"a","primary":true},{"value":"b","primary":true}]}), "[body.roles] roles cannot contain multiple primary values".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"owner@example.com","roles":[{"value":"a","type":"WORK"},{"value":"b","type":"work"}]}), "[body.roles] roles cannot contain duplicate defined types".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"owner@example.com","entitlements":null}), "[body.entitlements] Invalid input: expected array, received null".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"owner@example.com","entitlements":[{"value":""}]}), "[body.entitlements.0.value] Too small: expected string to have >=1 characters".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"owner@example.com","entitlements":[{"value":"a","type":"WORK"},{"value":"b","type":"work"}]}), "[body.entitlements] entitlements cannot contain duplicate defined types".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"owner@example.com","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{}}), "[body.schemas] The Enterprise User extension requires urn:ietf:params:scim:schemas:extension:enterprise:2.0:User in schemas".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],"userName":"owner@example.com","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":null}), "[body.urn:ietf:params:scim:schemas:extension:enterprise:2.0:User] Invalid input: expected object, received null".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],"userName":"owner@example.com","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"employeeNumber":42}}), "[body.urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.employeeNumber] Invalid input: expected string, received number".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],"userName":"owner@example.com","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"employeeNumber":[]}}), "[body.urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.employeeNumber] Invalid input: expected string, received array; [body.urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.employeeNumber] Too small: expected array to have >=1 items".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],"userName":"owner@example.com","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"manager":42}}), "[body.urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.manager] Invalid input".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],"userName":"owner@example.com","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"manager":{"value":null}}}), "[body.urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.manager] Invalid input".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],"userName":"owner@example.com","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"manager":[]}}), "[body.urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.manager] Too small: expected array to have exactly 1 items".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],"userName":"owner@example.com","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"manager":[{},{}]}}), "[body.urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.manager] Too big: expected array to have exactly 1 items".into()),
    ]);
    cases.extend([
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],"userName":"owner@example.com","emails":[{"value":"bad","primary":true},{"value":"bad","primary":true}]}), "[body.emails.0.value] Invalid email address; [body.emails.1.value] Invalid email address; [body.emails] emails cannot contain multiple primary values; [body.emails] emails cannot contain duplicate type and value pairs".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],"userName":"owner@example.com","emails":[{"value":"a@example.com","type":" ","primary":true},{"value":"b@example.com","type":" ","primary":true}]}), "[body.emails.0.type] Too small: expected string to have >=1 characters; [body.emails.1.type] Too small: expected string to have >=1 characters; [body.emails] emails cannot contain multiple primary values; [body.emails] emails cannot contain duplicate defined types".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],"userName":"owner@example.com","roles":[{"value":" ","primary":true},{"value":" ","primary":true}]}), "[body.roles.0.value] Too small: expected string to have >=1 characters; [body.roles.1.value] Too small: expected string to have >=1 characters; [body.roles] roles cannot contain multiple primary values".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],"userName":"owner@example.com","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"manager":""}}), "[body.urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.manager] Too small: expected string to have >=1 characters".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],"userName":"owner@example.com","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"manager":{"value":""}}}), "[body.urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.manager.value] Too small: expected string to have >=1 characters".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],"userName":"owner@example.com","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"manager":[{"value":""}]}}), "[body.urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.manager.0.value] Too small: expected string to have >=1 characters".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],"userName":"owner@example.com","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"manager":{"value":42}}}), "[body.urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.manager] Invalid input".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],"userName":"owner@example.com","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"manager":{"displayName":42}}}), "[body.urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.manager] Invalid input".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"owner@example.com","emails":[{"value":"bad"},{"value":"a1@example.com"},{"value":"a2@example.com"},{"value":"a3@example.com"},{"value":"a4@example.com"},{"value":"a5@example.com"},{"value":"a6@example.com"},{"value":"a7@example.com"},{"value":"a8@example.com"},{"value":"a9@example.com"},{"value":"a10@example.com"},{"value":"a11@example.com"},{"value":"a12@example.com"},{"value":"a13@example.com"},{"value":"a14@example.com"},{"value":"a15@example.com"},{"value":"a16@example.com"},{"value":"a17@example.com"},{"value":"a18@example.com"},{"value":"a19@example.com"},{"value":"a20@example.com"}]}), "[body.emails.0.value] Invalid email address; [body.emails] Too big: expected array to have <=20 items".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"owner@example.com","phoneNumbers":[{"value":null},{"value":"1"},{"value":"2"},{"value":"3"},{"value":"4"},{"value":"5"},{"value":"6"},{"value":"7"},{"value":"8"},{"value":"9"},{"value":"10"}]}), "[body.phoneNumbers.0.value] Invalid input: expected string, received null; [body.phoneNumbers] Too big: expected array to have <=10 items".into()),
        (json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User",1,"bad"],"userName":"owner@example.com"}), "[body.schemas.1] Invalid input: expected string, received number; [body.schemas] Too big: expected array to have <=2 items".into()),
    ]);
    for (input, detail) in cases {
        for replace in [false, true] {
            let endpoint = if replace {
                ScimPlugin::replace_user_endpoint("missing")?
            } else {
                ScimPlugin::create_user_endpoint()
            }
            .with_body(&input)?;
            let response = match Box::pin(
                auth.dispatch_endpoint(endpoint, EndpointOptions::default()),
            )
            .await
            {
                Ok(output) => output.into_response()?,
                Err(error) => {
                    let mut response = EndpointResponse::error(error.error);
                    if let Some(body) = error.body {
                        response = response.with_error_body(*body);
                    }
                    if let Some(headers) = error.headers {
                        response.merge_headers(headers);
                    }
                    response.to_response()?
                }
            };
            assert_eq!(response.status, 400, "input: {input}");
            assert_eq!(
                body(&response),
                json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"400","detail":detail,"scimType":"invalidValue"})
            );
        }
    }
    for replace in [false, true] {
        let mut request = request(
            if replace {
                "/scim/v2/Users/missing"
            } else {
                "/scim/v2/Users"
            },
            Some(json!({"schemas":[schema],"userName":null})),
            "",
        );
        if replace {
            request.method = HttpMethod::Put;
        }
        let response = call(&auth, request, 400).await;
        assert_eq!(
            body(&response)["detail"],
            "[body.userName] Invalid input: expected string, received null"
        );
        assert_eq!(body(&response)["scimType"], "invalidValue");
    }
    for table in ["user", "scimUser", "scimSubject"] {
        assert_eq!(
            serde_json::from_str::<Value>(&db.table(table).await?)?,
            json!([])
        );
    }
    let enterprise = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
    let mut invalid_manager =
        json!({"schemas":[schema,enterprise],"userName":"invalid-manager@example.com"});
    invalid_manager[enterprise] = json!({"manager":42});
    let rejected =
        super::scim_user_create::create(&auth, &invalid_manager, Some("group-reader")).await?;
    assert_eq!(rejected.status, 400);
    assert_eq!(body(&rejected)["scimType"], "invalidValue");
    assert_eq!(db.count("user").await?, 0);
    assert_eq!(db.count("scimUser").await?, 0);
    for (index, (manager, normalized)) in [
        (json!("manager-a"), json!({"value":"manager-a"})),
        (
            json!({"$ref":"https://directory.example/Users/manager-b"}),
            json!({"$ref":"https://directory.example/Users/manager-b"}),
        ),
        (
            json!([{"value":"manager-c","displayName":"Ignored"}]),
            json!({"value":"manager-c"}),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let mut input = json!({"schemas":[schema,enterprise],"userName":format!("valid-manager-{index}@example.com")});
        input[enterprise] = json!({"manager":manager});
        let created = super::scim_user_create::create(&auth, &input, Some("group-reader")).await?;
        assert_eq!(created.status, 201);
        assert_eq!(body(&created)[enterprise]["manager"], normalized);
    }
    Ok(())
}

async fn scim_user_size_bounds_validated_input_before_authentication<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(ScimPlugin::new().connections(super::scim_group_read::connections()))
        .build()
        .await?;
    for size in [65534, 65535, 65536, 65000] {
        let value = "x".repeat(1024);
        let mut input = json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"owner@example.com","roles":vec![json!({"value":value,"display":value});10],"entitlements":vec![json!({"value":value,"display":value});10],"addresses":vec![json!({"formatted":value,"streetAddress":value});10],"phoneNumbers":vec![json!({"value":"x".repeat(250)});10]});
        input["phoneNumbers"][9]["value"] = json!("");
        let length = serde_json::to_string(&input)?.encode_utf16().count();
        input["phoneNumbers"][9]["value"] = json!("x".repeat(size - length));
        assert_eq!(serde_json::to_string(&input)?.encode_utf16().count(), size);
        for replace in [false, true] {
            let endpoint = if replace {
                ScimPlugin::replace_user_endpoint("missing")?
            } else {
                ScimPlugin::create_user_endpoint()
            }
            .with_body(&input)?;
            let rejected = auth
                .dispatch_endpoint(endpoint, EndpointOptions::default())
                .await
                .unwrap_err();
            assert_eq!(
                rejected.error.status_code(),
                if size <= 65535 { 401 } else { 400 },
                "size {size}, replace {replace}: {rejected}"
            );
            if size > 65535 {
                assert_eq!(
                    rejected
                        .body
                        .as_deref()
                        .unwrap()
                        .get("detail")
                        .and_then(alibi::utils::json::JsValue::as_str),
                    Some("[body] SCIM User attributes exceed the supported serialized size")
                );
            }
        }
        if size == 65535 {
            let mut unknown = input.clone();
            unknown["ignored"] = json!("x".repeat(70000));
            unknown["roles"][0]["ignored"] = json!("x".repeat(70000));
            let mut padded = input.clone();
            padded["userName"] = json!(" owner@example.com ");
            padded["roles"][0]["value"] = json!(format!(" {} ", "x".repeat(1024)));
            let mut scalar = input.clone();
            scalar["title"] = json!("bounded");
            let delta = serde_json::to_string(&scalar)?.encode_utf16().count() - size;
            let fill = scalar["phoneNumbers"][9]["value"].as_str().unwrap().len();
            scalar["phoneNumbers"][9]["value"] = json!("x".repeat(fill - delta));
            scalar["title"] = json!([" bounded "]);
            let mut unicode = input.clone();
            unicode["roles"][0]["value"] = json!("🦀".repeat(512));
            for variant in [unknown, padded, scalar, unicode] {
                for replace in [false, true] {
                    let endpoint = if replace {
                        ScimPlugin::replace_user_endpoint("missing")?
                    } else {
                        ScimPlugin::create_user_endpoint()
                    }
                    .with_body(&variant)?;
                    let rejected = auth
                        .dispatch_endpoint(endpoint, EndpointOptions::default())
                        .await
                        .unwrap_err();
                    assert_eq!(
                        rejected.error.status_code(),
                        401,
                        "normalized size must ignore transport padding: {rejected}"
                    );
                }
            }
        }
        let authenticated =
            super::scim_user_create::create(&auth, &input, Some("group-reader")).await?;
        assert_eq!(
            authenticated.status,
            if size == 65000 {
                201
            } else if size <= 65535 {
                500
            } else {
                400
            }
        );
        if size == 65000 {
            assert_eq!(body(&authenticated)["userName"], "owner@example.com");
            assert_eq!(body(&authenticated)["roles"].as_array().unwrap().len(), 10);
        } else if size <= 65535 {
            assert_eq!(
                body(&authenticated)["detail"],
                "Stored SCIM User attribute state is invalid"
            );
        }
    }
    for table in ["user", "scimUser", "scimSubject"] {
        assert_eq!(db.count(table).await?, 1);
    }
    B::close(connection).await
}

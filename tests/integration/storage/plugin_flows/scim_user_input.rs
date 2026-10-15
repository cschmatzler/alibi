//! User input errors retain field paths and precede bearer authentication.
use super::*;
use alibi::endpoint::{EndpointOptions, EndpointResponse};
use alibi::plugins::ScimPlugin;
backend_tests!(scim_user_input_reports_reference_field_errors_before_authentication);
postgres_tests!(scim_user_input_reports_reference_field_errors_before_authentication);
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
            assert_eq!(response.status, 400);
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
    Ok(())
}

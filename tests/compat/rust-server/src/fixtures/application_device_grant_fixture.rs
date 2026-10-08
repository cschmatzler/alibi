//! Actual application grant callbacks, durable receipts, and trusted database controls.
use crate::TestSchema;
use alibi::plugins::device_authorization::*;
use alibi::{AuthError, AuthResult};
use alibi_core::{AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthRoute, AuthUser};
use alibi_seaorm::store::entities::device_code;
use alibi_seaorm::{
    DatabaseConnection,
    sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, Statement, sea_query::Expr},
};
use axum::{Json, Router, extract::Query, routing::get};
use serde_json::{Map, Value, json};
use std::sync::Arc;
static EVENTS: std::sync::Mutex<Vec<Value>> = std::sync::Mutex::new(Vec::new());
fn event(value: Value) {
    EVENTS.lock().unwrap().push(value);
}
pub struct Grant;
#[async_trait::async_trait]
impl DeviceAuthorizationGrant for Grant {
    fn request_schema_fields(&self) -> Map<String, Value> {
        json!({"audience":{"type":"string","minLength":1},"nonce":{"type":"string","minLength":1}})
            .as_object()
            .unwrap()
            .clone()
    }
    fn on_request_validation_error(&self, issues: &[String]) -> DeviceGrantFailure {
        event(json!({"phase":"validation","issueCount":issues.len()}));
        DeviceGrantFailure::oauth(
            400,
            "application_invalid_request",
            "Application audience and nonce are required",
        )
    }
    async fn authorize_request(
        &self,
        request: &Map<String, Value>,
        _: &AuthRequest,
    ) -> Result<DeviceGrantAuthorization, DeviceGrantFailure> {
        event(json!({"phase":"authorize","audience":request["audience"],"nonce":request["nonce"]}));
        if request["audience"] != "application-api" {
            return Err(DeviceGrantFailure::oauth(
                422,
                "invalid_audience",
                "Audience is not allowed",
            ));
        }
        Ok(DeviceGrantAuthorization {
            client_id: "application-client".into(),
            user_id: None,
            fields: json!({"grantAudience":request["audience"],"grantNonce":request["nonce"]})
                .as_object()
                .unwrap()
                .clone(),
        })
    }
    async fn assert_session_redemption(
        &self,
        record: &DeviceGrantRecord,
    ) -> Result<(), DeviceGrantFailure> {
        event(json!({"phase":"session-redemption","nonce":record.fields["grantNonce"]}));
        Err(DeviceGrantFailure::oauth(
            400,
            "invalid_grant",
            "Application grant cannot issue a standalone session",
        ))
    }
    async fn verification_context(
        &self,
        record: &DeviceGrantRecord,
    ) -> AuthResult<Map<String, Value>> {
        event(json!({"phase":"verification","nonce":record.fields["grantNonce"]}));
        Ok(
            json!({"audience":record.fields["grantAudience"],"nonce":record.fields["grantNonce"]})
                .as_object()
                .unwrap()
                .clone(),
        )
    }
    fn device_code_schema_fields(&self) -> Vec<alibi_core::OpenApiField> {
        vec![
            alibi_core::OpenApiField::new("grantAudience", json!({"type":"string"}), false),
            alibi_core::OpenApiField::new("grantNonce", json!({"type":"string"}), false),
        ]
    }
    fn request_error_codes(&self) -> Vec<String> {
        vec![
            "invalid_audience".into(),
            "application_invalid_request".into(),
        ]
    }
    fn request_openapi_responses(&self) -> Map<String, Value> {
        json!({"422":{"description":"Application audience rejected"}})
            .as_object()
            .unwrap()
            .clone()
    }
    fn verification_openapi_properties(&self) -> Map<String, Value> {
        json!({"audience":{"type":"string"},"nonce":{"type":"string"}})
            .as_object()
            .unwrap()
            .clone()
    }
}
struct Policy {
    nonce: Value,
    prepare_failure: bool,
}
#[async_trait::async_trait]
impl DeviceRedemptionPolicy for Policy {
    async fn authorize(
        &self,
        record: &DeviceGrantRecord,
    ) -> AuthResult<DeviceRedemptionAuthorization> {
        event(json!({"phase":"redemption-authorize","nonce":record.fields["grantNonce"]}));
        Ok(DeviceRedemptionAuthorization {
            ownership: json!({"grantNonce":self.nonce})
                .as_object()
                .unwrap()
                .clone(),
            context: json!({"nonce":record.fields["grantNonce"]}),
        })
    }
    async fn prepare(
        &self,
        record: &DeviceGrantRecord,
        authorization: &Value,
    ) -> AuthResult<Value> {
        event(json!({"phase":"prepare","nonce":authorization["nonce"]}));
        if self.prepare_failure {
            return Err(AuthError::Api {
                status: 403,
                code: Some("APPLICATION_PREPARE_REJECTED".into()),
                message: "Application preparation rejected".into(),
            });
        }
        Ok(json!({"audience":record.fields["grantAudience"]}))
    }
}
pub struct ApplicationToken(pub DatabaseConnection);
#[async_trait::async_trait]
impl AuthPlugin<TestSchema> for ApplicationToken {
    fn static_openapi_metadata(&self) -> alibi_core::PluginOpenApiMetadata {
        alibi_core::PluginOpenApiMetadata::default().endpoint(alibi_core::HttpMethod::Post,"/device/application-token",alibi_core::OpenApiEndpoint { request_body:Some(json!({"required":true,"content":{"application/json":{"schema":{"type":"object","properties":{"device_code":{"type":"string"},"claimNonce":{"type":"string"},"prepareFailure":{"type":"boolean"}},"required":["device_code","claimNonce"]}}}})),..Default::default() })
    }

    fn name(&self) -> &'static str {
        "application-device-grant"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::post(
            "/device/application-token",
            "application_token",
        )]
    }
    async fn on_request(
        &self,
        request: &AuthRequest,
        ctx: &AuthContext<TestSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        if request.path() != "/device/application-token" {
            return Ok(None);
        }
        let body: Value = request.body_as_json()?;
        let result = match redeem_device_code(
            ctx,
            body["device_code"]
                .as_str()
                .ok_or_else(|| AuthError::bad_request("device_code is required"))?,
            &Policy {
                nonce: body["claimNonce"].clone(),
                prepare_failure: body["prepareFailure"] == true,
            },
        )
        .await
        {
            Ok(result) => result,
            Err(error) => return error.into_response().map(Some),
        };
        _ = self
            .0
            .execute_raw(Statement::from_sql_and_values(
                self.0.get_database_backend(),
                "INSERT INTO application_grant_receipts (row_id,owner_id,audience) VALUES (?,?,?)",
                [
                    result.claimed_device_code.device_code.id.into(),
                    result.user.id().into_owned().into(),
                    result.redemption_context["audience"]
                        .as_str()
                        .unwrap()
                        .to_owned()
                        .into(),
                ],
            ))
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        event(json!({"phase":"completed","nonce":result.authorization_context["nonce"]}));
        Ok(Some(AuthResponse::json(
            200,
            &json!({"userId":result.user.id(),"audience":result.redemption_context["audience"],"nonce":result.authorization_context["nonce"]}),
        )?))
    }
}
pub async fn initialize(db: &DatabaseConnection) -> AuthResult<()> {
    _ = db.execute_unprepared("CREATE TABLE IF NOT EXISTS application_grant_receipts (row_id TEXT,owner_id TEXT,audience TEXT)").await.map_err(|error|AuthError::internal(error.to_string()))?;
    Ok(())
}
pub async fn reset(db: &DatabaseConnection) -> AuthResult<()> {
    EVENTS.lock().unwrap().clear();
    _ = db
        .execute_unprepared("DELETE FROM application_grant_receipts")
        .await
        .map_err(|error| AuthError::internal(error.to_string()))?;
    Ok(())
}
async fn observation(db: &DatabaseConnection, code: &str) -> Value {
    let rows = device_code::Entity::find()
        .filter(device_code::Column::DeviceCode.eq(code))
        .all(db)
        .await
        .unwrap();
    let mut values = Vec::new();
    for row in rows {
        let fields = db
            .query_one_raw(Statement::from_sql_and_values(
                db.get_database_backend(),
                "SELECT fields FROM device_code_fields WHERE device_code_id=?",
                [row.id.clone().into()],
            ))
            .await
            .unwrap()
            .map(|row| {
                serde_json::from_str::<Value>(&row.try_get::<String>("", "fields").unwrap())
                    .unwrap()
            })
            .unwrap_or(Value::Null);
        values.push(json!({"id":row.id,"deviceCode":row.device_code,"userCode":row.user_code,"userId":row.user_id,"status":row.status,"clientId":row.client_id,"audience":fields["grantAudience"],"nonce":fields["grantNonce"]}));
    }
    let receipts=db.query_all_raw(Statement::from_string(db.get_database_backend(),"SELECT row_id,owner_id,audience FROM application_grant_receipts")).await.unwrap().iter().map(|row|json!({"rowId":row.try_get::<String>("","row_id").unwrap(),"userId":row.try_get::<String>("","owner_id").unwrap(),"audience":row.try_get::<String>("","audience").unwrap()})).collect::<Vec<_>>();
    json!({"rows":values,"events":*EVENTS.lock().unwrap(),"receipts":receipts})
}
pub fn router(db: DatabaseConnection) -> Router<Arc<alibi::BetterAuth<TestSchema>>> {
    let read = db.clone();
    Router::new().route(
        "/__test/device-grant/control",
        get(
            move |Query(query): Query<std::collections::HashMap<String, String>>| {
                let db = read.clone();
                async move {
                    Json(
                        observation(
                            &db,
                            query.get("deviceCode").map(String::as_str).unwrap_or(""),
                        )
                        .await,
                    )
                }
            },
        )
        .post(move |Json(body): Json<Value>| {
            let db = db.clone();
            async move {
                if let Some(expires) = body["expiresAt"].as_str() {
                    let date = expires.parse::<chrono::DateTime<chrono::Utc>>().unwrap();
                    _ = device_code::Entity::update_many()
                        .filter(
                            device_code::Column::DeviceCode
                                .eq(body["deviceCode"].as_str().unwrap()),
                        )
                        .col_expr(device_code::Column::ExpiresAt, Expr::value(date))
                        .exec(&db)
                        .await
                        .unwrap();
                }
                Json(observation(&db, body["deviceCode"].as_str().unwrap_or("")).await)
            }
        }),
    )
}

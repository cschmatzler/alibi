use super::*;
impl JwtPlugin {
    pub(in crate::jwt) async fn session_token(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<String> {
        let read = alibi_core::session::cookie_cache::runtime::authenticated(ctx, req, false)
            .await
            .map_err(|_error| unauthorized())?
            .ok_or_else(unauthorized)?;
        let session = JwtSession {
            user: match read.user {
                alibi_core::AuthenticatedUser::Stored(user) => ctx.user_view(&user),
                alibi_core::AuthenticatedUser::Cached(user) => *user,
            },
            // A virtual principal already carries its exact runtime snapshot;
            // applying persisted-session output defaults would add fields.
            session: req.virtual_session().cloned().unwrap_or(read.session),
            needs_refresh: read.needs_refresh,
            updated_at: None,
            version: None,
        };
        self.sign_session_token(Some(req), ctx, &session).await
    }

    pub(in crate::jwt) async fn sign_session_token(
        &self,
        req: Option<&AuthRequest>,
        ctx: &AuthContext<impl AuthSchema>,
        session: &JwtSession,
    ) -> AuthResult<String> {
        let application_payload = match &self.config.define_payload {
            Some(define) => define.define_payload(session).await?,
            None => serde_json::to_value(&session.user)?
                .as_object()
                .cloned()
                .ok_or_else(|| AuthError::internal("User payload was not an object"))?,
        };
        // getJwtToken starts with iat before spreading the application payload;
        // an explicit application iat replaces the value in that position.
        let mut payload = Map::new();
        drop(payload.insert("iat".to_owned(), json!(Utc::now().timestamp())));
        payload.extend(application_payload);
        let subject = match &self.config.define_subject {
            Some(define) => define
                .subject(session)
                .await?
                .unwrap_or_else(|| session.user.id.clone()),
            None => session.user.id.clone(),
        };
        drop(payload.insert("sub".to_owned(), json!(subject)));
        self.sign_jwt(payload, &JwtSignOptions::default(), req, ctx)
            .await
    }

    pub(in crate::jwt) async fn jwks(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        if self.config.remote_url.is_some() {
            return Ok(AuthResponse::new(404).with_header("content-type", "application/json"));
        }
        Ok(AuthResponse::json(
            200,
            &self.jwks_value(Some(req), ctx).await?,
        )?)
    }

    pub(in crate::jwt) async fn jwks_value(
        &self,
        request: Option<&AuthRequest>,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<Value> {
        if self.config.remote_url.is_some() {
            return Err(AuthError::Api {
                status: 404,
                code: None,
                message: String::new(),
            });
        }
        let mut keys = self.keys(request, ctx).await?;
        if keys.is_empty() {
            drop(self.create_jwk(None, request, ctx).await?);
            keys = self.keys(request, ctx).await?;
        }
        if keys.is_empty() {
            return Err(AuthError::config(
                "No key sets found. Make sure you have a key in your database.",
            ));
        }
        let now = Utc::now();
        let keys = keys
            .into_iter()
            .filter(|key| {
                key.expires_at
                    .is_none_or(|expires| expires + self.config.grace_period > now)
            })
            .map(|key| {
                let mut public = Map::new();
                drop(public.insert(
                    "alg".to_owned(),
                    json!(
                        key.alg
                            .as_deref()
                            .unwrap_or(self.config.key_pair.algorithm.as_str())
                    ),
                ));
                if let Some(curve) = &key.crv {
                    drop(public.insert("crv".to_owned(), json!(curve)));
                }
                let parsed: Map<String, Value> = serde_json::from_str(&key.public_key)?;
                public.extend(parsed);
                drop(public.insert("kid".to_owned(), json!(key.id)));
                Ok::<_, AuthError>(public)
            })
            .collect::<AuthResult<Vec<_>>>()?;
        Ok(json!({ "keys": keys }))
    }
}

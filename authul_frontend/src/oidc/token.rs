use actix_web::{
	web::{self, ServiceConfig},
	HttpResponse,
};
use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{middleware::Cors, Config, Error};
use crate::db;
use authul_crypto::{JwkSet, Jwt};
use authul_oauth2::error_code::TokenEndpoint as TokenErrCode;
use authul_util::Base64Uuid;

pub(super) fn routes(cfg: &mut ServiceConfig) {
	cfg.service(
		web::resource("/oidc/token")
			.wrap(Cors::POST)
			.route(web::post().to(post_oidc_token))
			.route(web::to(|| HttpResponse::MethodNotAllowed())),
	);
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct TokenRequest {
	grant_type: Option<String>,
	code: Option<String>,
	redirect_uri: Option<String>,
	client_assertion_type: Option<String>,
	client_assertion: Option<String>,
	code_verifier: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct TokenResponse {
	id_token: String,
	token_type: String,
	expires_in: u32,
}

pub(super) async fn post_oidc_token(
	cfg: web::Data<Config>,
	token_req: web::Form<TokenRequest>,
) -> Result<HttpResponse, Error> {
	let token_req = token_req.into_inner();

	let grant_type = token_req
		.grant_type
		.ok_or_else(|| Error::oidc_token("no grant_type", TokenErrCode::InvalidRequest))?;
	let code = token_req
		.code
		.ok_or_else(|| Error::oidc_token("no code", TokenErrCode::InvalidRequest))?;
	let redirect_uri = token_req
		.redirect_uri
		.ok_or_else(|| Error::oidc_token("no redirect_uri", TokenErrCode::InvalidRequest))?;
	let client_assertion_type = token_req.client_assertion_type.ok_or_else(|| {
		Error::oidc_token("no client_assertion_type", TokenErrCode::InvalidRequest)
	})?;
	let client_assertion = token_req
		.client_assertion
		.ok_or_else(|| Error::oidc_token("no client_assertion", TokenErrCode::InvalidClient))?;
	let code_verifier = token_req
		.code_verifier
		.ok_or_else(|| Error::oidc_token("no code_challenge", TokenErrCode::InvalidRequest))?;

	let token = cfg
		.db()
		.oidc_token()
		.await?
		.find(
			&Uuid::from_base64(&code)
				.map_err(|_| Error::oidc_token("invalid code", TokenErrCode::InvalidGrant))?,
		)
		.await
		.map_err(|e| match e {
			db::Error::NotFound(..) => {
				Error::oidc_token("unknown code", TokenErrCode::InvalidGrant)
			}
			e => e.into(),
		})?;

	if grant_type != "authorization_code" {
		return Err(Error::oidc_token(
			format!("unsupported grant_type {grant_type}"),
			TokenErrCode::UnsupportedGrantType,
		));
	}
	if client_assertion_type != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		return Err(Error::oidc_token(
			format!("unsupported client_assertion_type {client_assertion_type}"),
			TokenErrCode::InvalidClient,
		));
	}

	if &BASE64_URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier)) != token.code_challenge() {
		return Err(Error::oidc_token(
			"incorrect code_verifier",
			TokenErrCode::InvalidGrant,
		));
	}

	let Ok(client_jwt): Result<Jwt, _> = client_assertion.parse() else {
		return Err(Error::oidc_token(
			"invalid client JWT",
			TokenErrCode::InvalidClient,
		));
	};

	// What I love(*) about JWTs is that in order to be able to trust them, you have to pull them
	// apart before you trust them.
	let Some(claimed_client_id) = client_jwt.peek_sub() else {
		return Err(Error::oidc_token(
			"client JWT lacks sub",
			TokenErrCode::InvalidClient,
		));
	};

	let claimed_oidc_client = cfg
		.db()
		.oidc_client()
		.await?
		.find(&Uuid::from_base64(claimed_client_id).map_err(|e| {
			Error::oidc_token(
				format!("invalid client_id: {e}"),
				TokenErrCode::InvalidClient,
			)
		})?)
		.await
		.map_err(|e| match e {
			authul_db::Error::NotFound { .. } => Error::oidc_token(
				format!("unknown client_id {claimed_client_id}"),
				TokenErrCode::InvalidClient,
			),
			_ => e.into(),
		})?;

	if !JwkSet::from_url(claimed_oidc_client.jwks_uri(), cfg.http_client())
		.await?
		.iter()
		.any(|k| client_jwt.verify(k))
	{
		return Err(Error::oidc_token(
			"invalid client JWT signature",
			TokenErrCode::InvalidClient,
		));
	};

	// Houston, we have verification!
	let oidc_client = claimed_oidc_client;

	let Some(jti) = client_jwt.peek_jti() else {
		return Err(Error::oidc_token(
			"client JWT lacks jti",
			TokenErrCode::InvalidClient,
		));
	};

	if jti != code {
		return Err(Error::oidc_token(
			"client JWT jti not code",
			TokenErrCode::InvalidGrant,
		));
	}

	if token.is_expired() {
		return Err(Error::oidc_token(
			"grant expired",
			TokenErrCode::InvalidGrant,
		));
	}

	if token.redirect_uri() != &redirect_uri {
		return Err(Error::oidc_token(
			"incorrect redirect_uri",
			TokenErrCode::InvalidGrant,
		));
	}

	if token.oidc_client().id() != oidc_client.id() {
		return Err(Error::oidc_token(
			"incorrect client_id",
			TokenErrCode::InvalidGrant,
		));
	}

	let token_string = token.token().to_string();
	cfg.db().delete(token).await?;

	Ok(HttpResponse::Ok().json(TokenResponse {
		id_token: token_string,
		token_type: "Bearer".to_string(),
		expires_in: 60,
	}))
}

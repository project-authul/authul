use actix_web::{cookie::Cookie, HttpMessage as _};
use authul_db::types::OAuthProviderKind;
use authul_frontend::AuthContext;
use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, time::Duration};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use crate::{encode_params, util};
use authul_util::Base64Uuid;

#[actix_rt::test]
async fn post_disallowed() {
	let srv = util::setup(util::default).await;

	let res = srv
		.post("/authenticate/oauth_callback")
		.send()
		.await
		.unwrap();

	assert_eq!(405, res.status().as_u16());
	assert_eq!("", res.content_type());
}

fn oauth_providers(mut cfg: authul_frontend::ConfigBuilder) -> authul_frontend::ConfigBuilder {
	cfg.github_oauth_client("clientid:clients3kr1t".parse().expect("cred parse failed"));
	util::vcr("tests/cassettes/github_oauth.json")(cfg)
}

async fn req_setup(cfg: &authul_frontend::Config) -> (String, String, String) {
	let csrf_token = "randomstring".to_string();

	let oidc_client = cfg
		.db()
		.oidc_client()
		.await
		.expect("db")
		.new()
		.with_name("OAuth Proxy")
		.with_redirect_uris(["https://example.com/oidc/callback"])
		.with_jwks_uri("https://example.com/jwks.json")
		.with_token_forward_jwk_uri(Some(
			"https://example.com/token_forward_jwk.json".to_string(),
		))
		.save()
		.await
		.expect("oidc_client save");

	let ctx = AuthContext::new(
		cfg.clone().into(),
		oidc_client.id(),
		"https://example.com/oidc/callback",
		"",
	);

	let state = cfg
		.db()
		.oauth_callback_state()
		.await
		.expect("db")
		.new()
		.with_oidc_client(oidc_client.clone())
		.with_provider_kind(OAuthProviderKind::GitHub)
		.with_csrf_token(Sha256::digest(&csrf_token).to_vec())
		.with_context(ctx.to_string())
		.with_expired_from(OffsetDateTime::now_utc() + Duration::from_secs(300))
		.save()
		.await
		.expect("state save");

	(
		csrf_token,
		BASE64_URL_SAFE_NO_PAD.encode(state.id().as_bytes()),
		"420".to_string(),
	)
}

fn attr_eq(json: &Value, kind: &str, value: &str) -> bool {
	let attr = json.as_object().expect("json object");

	attr.get("kind").expect("kind").as_str().expect("kind str") == kind
		&& attr
			.get("value")
			.expect("value")
			.as_str()
			.expect("value str")
			== value
}

#[actix_rt::test]
async fn successful_request() {
	let srv = util::setup(oauth_providers).await;

	let (csrf_token, state, code) = req_setup(&srv.cfg).await;

	let res = srv
		.get(
			"/authenticate/oauth_callback?".to_string()
				+ encode_params!(state: &state, code: &code),
		)
		.cookie(Cookie::new("csrf_token", csrf_token))
		.send()
		.await
		.unwrap();

	assert_eq!(302, res.status().as_u16());
	assert_eq!("", res.content_type());

	let redirect_url =
		Url::parse(res.headers().get("location").unwrap().to_str().unwrap()).unwrap();

	assert_eq!("https", redirect_url.scheme());
	assert_eq!("example.com", redirect_url.authority());
	assert_eq!("/oidc/callback", redirect_url.path());

	let redirect_params: HashMap<String, String> =
		url::form_urlencoded::parse(redirect_url.query().unwrap().as_bytes())
			.into_owned()
			.collect();
	let auth_code = redirect_params
		.get("code")
		.expect("no code param in redirect URI");

	let token = srv
		.db
		.oidc_token()
		.await
		.expect("oidc_token")
		.find(&Uuid::from_base64(auth_code).expect("uuid"))
		.await
		.expect("token not found");
	let json_value = serde_json::from_slice::<Value>(
		&BASE64_URL_SAFE_NO_PAD
			.decode(
				token
					.token()
					.split('.')
					.collect::<Vec<_>>()
					.get(1)
					.expect("payload part"),
			)
			.expect("base64 payload"),
	)
	.expect("json payload");
	let jwt_payload = json_value.as_object().expect("json map");
	dbg!(&jwt_payload);

	let principal = srv
		.db
		.principal()
		.await
		.expect("principal")
		.find(
			&jwt_payload
				.get("sub")
				.expect("sub")
				.as_str()
				.expect("sub str")
				.parse()
				.expect("sub uuid"),
		)
		.await
		.expect("principal find");
	let identities = srv
		.db
		.oauth_identity()
		.await
		.expect("oauth_identity")
		.find_all_by_principal(&principal)
		.await
		.expect("identity find");
	assert_eq!(1, identities.len());
	let identity = identities.first().expect("uhm...");

	assert_eq!(OAuthProviderKind::GitHub, *identity.provider_kind());
	assert_eq!("42", identity.provider_identifier());

	let attrs = jwt_payload
		.get("attrs")
		.expect("attrs")
		.as_array()
		.expect("attrs array");

	assert!(
		attrs.iter().any(|a| attr_eq(a, "Username", "jaime")),
		"attributes missing Username"
	);
	assert!(
		attrs
			.iter()
			.any(|a| attr_eq(a, "DisplayName", "Jaime Jaimington")),
		"attributes missing DisplayName"
	);
	assert!(
		attrs
			.iter()
			.any(|a| attr_eq(a, "PrimaryEmail", "jaime@example.com")),
		"attributes missing PrimaryEmail"
	);
	assert!(
		attrs
			.iter()
			.any(|a| attr_eq(a, "VerifiedEmail", "j.jaimington@company.example")),
		"attributes missing VerifiedEmail"
	);
	assert!(
		attrs
			.iter()
			.any(|a| attr_eq(a, "Email", "someoneelse@example.net")),
		"attributes missing Email"
	);
	assert!(
		attrs
			.iter()
			.any(|a| a.as_object().unwrap().get("kind").unwrap() == "AccessToken"),
		"attributes missing AccessToken"
	);

	assert_eq!(6, attrs.len());
}

#[actix_rt::test]
async fn successful_request_for_known_user() {
	let srv = util::setup(oauth_providers).await;

	let (csrf_token, state, code) = req_setup(&srv.cfg).await;

	let principal = srv
		.db
		.principal()
		.await
		.expect("principal")
		.new()
		.save()
		.await
		.expect("save principal");
	srv.db
		.oauth_identity()
		.await
		.expect("oauth_identity")
		.new()
		.with_principal(principal.clone())
		.with_provider_kind(OAuthProviderKind::GitHub)
		.with_provider_identifier("42")
		.save()
		.await
		.expect("oauth_identity save");

	let res = srv
		.get(
			"/authenticate/oauth_callback?".to_string()
				+ encode_params!(state: &state, code: &code),
		)
		.cookie(Cookie::new("csrf_token", csrf_token))
		.send()
		.await
		.unwrap();

	assert_eq!(302, res.status().as_u16());
	assert_eq!("", res.content_type());

	let redirect_url =
		Url::parse(res.headers().get("location").unwrap().to_str().unwrap()).unwrap();

	assert_eq!("https", redirect_url.scheme());
	assert_eq!("example.com", redirect_url.authority());
	assert_eq!("/oidc/callback", redirect_url.path());

	let redirect_params: HashMap<String, String> =
		url::form_urlencoded::parse(redirect_url.query().unwrap().as_bytes())
			.into_owned()
			.collect();
	let auth_code = redirect_params
		.get("code")
		.expect("no code param in redirect URI");

	let token = srv
		.db
		.oidc_token()
		.await
		.expect("oidc_token")
		.find(&Uuid::from_base64(auth_code).expect("uuid"))
		.await
		.expect("token not found");
	let json_value = serde_json::from_slice::<Value>(
		&BASE64_URL_SAFE_NO_PAD
			.decode(
				token
					.token()
					.split('.')
					.collect::<Vec<_>>()
					.get(1)
					.expect("payload part"),
			)
			.expect("base64 payload"),
	)
	.expect("json payload");
	let jwt_payload = json_value.as_object().expect("json map");
	dbg!(&jwt_payload);

	let jwt_principal = srv
		.db
		.principal()
		.await
		.expect("principal")
		.find(
			&jwt_payload
				.get("sub")
				.expect("sub")
				.as_str()
				.expect("sub str")
				.parse()
				.expect("sub uuid"),
		)
		.await
		.expect("principal find");

	assert_eq!(
		principal.id(),
		jwt_principal.id(),
		"did not associate login with existing principal"
	);
	let jwt_identities = srv
		.db
		.oauth_identity()
		.await
		.expect("oauth_identity")
		.find_all_by_principal(&jwt_principal)
		.await
		.expect("identity find");
	assert_eq!(1, jwt_identities.len());
	let jwt_identity = jwt_identities.first().expect("uhm...");

	assert_eq!(OAuthProviderKind::GitHub, *jwt_identity.provider_kind());
	assert_eq!("42", jwt_identity.provider_identifier());

	let attrs = jwt_payload
		.get("attrs")
		.expect("attrs")
		.as_array()
		.expect("attrs array");

	assert!(
		attrs.iter().any(|a| attr_eq(a, "Username", "jaime")),
		"attributes missing Username"
	);
	assert!(
		attrs
			.iter()
			.any(|a| attr_eq(a, "DisplayName", "Jaime Jaimington")),
		"attributes missing DisplayName"
	);
	assert!(
		attrs
			.iter()
			.any(|a| attr_eq(a, "PrimaryEmail", "jaime@example.com")),
		"attributes missing PrimaryEmail"
	);
	assert!(
		attrs
			.iter()
			.any(|a| attr_eq(a, "VerifiedEmail", "j.jaimington@company.example")),
		"attributes missing VerifiedEmail"
	);
	assert!(
		attrs
			.iter()
			.any(|a| attr_eq(a, "Email", "someoneelse@example.net")),
		"attributes missing Email"
	);
	assert!(
		attrs
			.iter()
			.any(|a| a.as_object().unwrap().get("kind").unwrap() == "AccessToken"),
		"attributes missing AccessToken"
	);

	assert_eq!(6, attrs.len());
}

#[actix_rt::test]
async fn get_without_params_is_not_happy() {
	let srv = util::setup(util::default).await;

	let mut res = srv
		.get("/authenticate/oauth_callback")
		.send()
		.await
		.unwrap();

	assert_eq!(400, res.status().as_u16());
	assert_eq!("application/json", res.content_type());
	assert_eq!(
		json!({ "error": "invalid_request" }),
		res.json::<Value>().await.expect("json response")
	);
}

#[actix_rt::test]
async fn give_an_error_get_an_error() {
	let srv = util::setup(util::default).await;

	let mut res = srv
		.get("/authenticate/oauth_callback?error=something_funny")
		.send()
		.await
		.unwrap();

	assert_eq!(400, res.status().as_u16());
	assert_eq!("application/json", res.content_type());
	assert_eq!(
		json!({ "error": "invalid_request" }),
		res.json::<Value>().await.expect("json response")
	);
}

#[actix_rt::test]
async fn get_without_code_is_not_happy() {
	let srv = util::setup(util::default).await;

	let mut res = srv
		.get("/authenticate/oauth_callback?state=inebriation")
		.send()
		.await
		.unwrap();

	assert_eq!(400, res.status().as_u16());
	assert_eq!("application/json", res.content_type());
	assert_eq!(
		json!({ "error": "invalid_request" }),
		res.json::<Value>().await.expect("json response")
	);
}

#[actix_rt::test]
async fn get_without_state_is_not_happy() {
	let srv = util::setup(util::default).await;

	let mut res = srv
		.get("/authenticate/oauth_callback?code=s3kr1t")
		.send()
		.await
		.unwrap();

	assert_eq!(400, res.status().as_u16());
	assert_eq!("application/json", res.content_type());
	assert_eq!(
		json!({ "error": "invalid_request" }),
		res.json::<Value>().await.expect("json response")
	);
}

#[actix_rt::test]
async fn get_with_invalid_state_is_not_happy() {
	let srv = util::setup(util::default).await;

	let mut res = srv
		.get("/authenticate/oauth_callback?code=s3kr1t&state=inebriation")
		.send()
		.await
		.unwrap();

	assert_eq!(400, res.status().as_u16());
	assert_eq!("application/json", res.content_type());
	assert_eq!(
		json!({ "error": "invalid_request" }),
		res.json::<Value>().await.expect("json response")
	);
}

#[actix_rt::test]
async fn get_with_unknown_state_is_not_happy() {
	let srv = util::setup(util::default).await;

	let mut res = srv
		.get("/authenticate/oauth_callback?code=s3kr1t&state=5c7c8687-50d7-47de-9cd7-648aead06e48")
		.send()
		.await
		.unwrap();

	assert_eq!(400, res.status().as_u16());
	assert_eq!("application/json", res.content_type());
	assert_eq!(
		json!({ "error": "invalid_request" }),
		res.json::<Value>().await.expect("json response")
	);
}

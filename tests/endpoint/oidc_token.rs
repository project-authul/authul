use actix_web::HttpMessage;
use serde_json::{json, Value};
use std::{collections::HashMap, time::Duration};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::util;
use authul_crypto::{Jwk, Jwt};
use authul_db::model::{OidcClient, OidcToken};
use authul_frontend::Config as FrontendConfig;
use authul_util::Base64Uuid;

#[actix_rt::test]
async fn get_does_not_work() {
	let srv = util::setup(util::default).await;

	let res = srv.get("/oidc/token").send().await.unwrap();

	assert_eq!(405, res.status().as_u16());
}

fn jwt_signing_key() -> Jwk {
	serde_json::from_str(r#"{"Ed25519":[0, 168, 50, 245, 78, 42, 57, 251, 163, 95, 74, 205, 191, 22, 96, 105, 10, 96, 109, 226, 1, 66, 246, 13, 86, 47, 113, 29, 41, 225, 78, 136]}"#).expect("JWK decode failed")
}

async fn creds_and_client(cfg: &FrontendConfig) -> (String, OidcClient, OidcToken) {
	let client = cfg
		.db()
		.oidc_client()
		.await
		.expect("oidc_client")
		.new()
		.with_name("Caves")
		.with_redirect_uris(["https://example.com/callback"])
		.with_jwks_uri("https://example.com/jwks.json")
		.save()
		.await
		.expect("client save failed");

	let token = cfg
		.db()
		.oidc_token()
		.await
		.expect("oidc_token")
		.new()
		.with_oidc_client(client.clone())
		.with_token("thisisnotarealtoken")
		.with_redirect_uri("https://example.com/callback")
		.with_code_challenge("xkvndgXSG7Ic99LmZ0g07LfnQiie4uAQwxXzaMADYoo")
		.save()
		.await
		.expect("token saved");

	let client_jwt = Jwt::new()
		.with_iss(client.id().to_base64())
		.with_sub(client.id().to_base64())
		.with_aud(cfg.base_url().as_str())
		.with_jti(token.id().to_base64())
		.sign(&jwt_signing_key())
		.expect("signing failed");

	(client_jwt, client, token)
}

#[actix_rt::test]
async fn can_retrieve_valid_token() {
	let srv = util::setup(util::vcr("tests/cassettes/example_jwks.json")).await;
	let (client_jwt, _, token) = creds_and_client(&srv.cfg).await;

	let mut res = srv
		.post("/oidc/token")
		.send_form(&[
			("grant_type", "authorization_code"),
			("code", &token.id().to_base64()),
			("redirect_uri", "https://example.com/callback"),
			(
				"client_assertion_type",
				"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			),
			("client_assertion", &client_jwt),
			("code_verifier", "uniques3kr1t"),
		])
		.await
		.unwrap();

	assert_eq!(200, res.status().as_u16());
	assert_eq!("application/json", res.content_type());

	let doc: HashMap<String, Value> = res.json().await.expect("invalid JSON response body");

	assert_eq!(
		Some("Bearer"),
		doc.get("token_type")
			.map(|v| v.as_str().expect("token_type should be string"))
	);
	assert_eq!(
		Some("thisisnotarealtoken"),
		doc.get("id_token")
			.map(|v| v.as_str().expect("id_token should be string"))
	);
	assert_eq!(
		None,
		doc.get("access_token"),
		"we don't hand out access tokens"
	);
	assert_eq!(
		None,
		doc.get("refresh_token"),
		"we don't hand out refresh tokens"
	);
}

#[actix_rt::test]
async fn can_retrieve_token_only_once() {
	let srv = util::setup(util::vcr("tests/cassettes/example_jwks.json")).await;
	let (client_jwt, _, token) = creds_and_client(&srv.cfg).await;

	let res = srv
		.post("/oidc/token")
		.send_form(&[
			("grant_type", "authorization_code"),
			("code", &token.id().to_base64()),
			("redirect_uri", "https://example.com/callback"),
			(
				"client_assertion_type",
				"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			),
			("client_assertion", &client_jwt),
			("code_verifier", "uniques3kr1t"),
		])
		.await
		.unwrap();

	assert_eq!(200, res.status().as_u16());
	assert_eq!("application/json", res.content_type());

	let mut res = srv
		.post("/oidc/token")
		.send_form(&[
			("grant_type", "authorization_code"),
			("code", &token.id().to_base64()),
			("redirect_uri", "https://example.com/callback"),
			(
				"client_assertion_type",
				"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			),
			("client_assertion", &client_jwt),
			("code_verifier", "uniques3kr1t"),
		])
		.await
		.unwrap();

	assert_eq!(400, res.status().as_u16());
	assert_eq!("application/json", res.content_type());
	assert_eq!(
		json!({"error": "invalid_grant"}),
		res.json::<Value>().await.expect("json response")
	);
}

#[actix_rt::test]
async fn post_without_client_assertion_fails() {
	let srv = util::setup(util::vcr("tests/cassettes/example_jwks.json")).await;
	let (_, _, token) = creds_and_client(&srv.cfg).await;

	let mut res = srv
		.post("/oidc/token")
		.send_form(&[
			("grant_type", "authorization_code"),
			("code", &token.id().to_base64()),
			("redirect_uri", "https://example.com/callback"),
			(
				"client_assertion_type",
				"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			),
			("code_verifier", "uniques3kr1t"),
		])
		.await
		.unwrap();

	assert_eq!(400, res.status().as_u16());
	assert_eq!("application/json", res.content_type());
	assert_eq!(
		json!({"error": "invalid_client"}),
		res.json::<Value>().await.expect("json doc")
	);
}

#[actix_rt::test]
async fn post_without_client_assertion_type_fails() {
	let srv = util::setup(util::vcr("tests/cassettes/example_jwks.json")).await;
	let (client_jwt, _, token) = creds_and_client(&srv.cfg).await;

	let mut res = srv
		.post("/oidc/token")
		.send_form(&[
			("grant_type", "authorization_code"),
			("code", &token.id().to_base64()),
			("redirect_uri", "https://example.com/callback"),
			("client_assertion", &client_jwt),
			("code_verifier", "uniques3kr1t"),
		])
		.await
		.unwrap();

	assert_eq!(400, res.status().as_u16());
	assert_eq!("application/json", res.content_type());
	assert_eq!(
		json!({"error": "invalid_request"}),
		res.json::<Value>().await.expect("json doc")
	);
}

#[actix_rt::test]
async fn post_with_invalid_creds_fails() {
	let srv = util::setup(util::vcr("tests/cassettes/example_jwks.json")).await;
	let (_, _, token) = creds_and_client(&srv.cfg).await;

	let mut res = srv
		.post("/oidc/token")
		.send_form(&[
			("grant_type", "authorization_code"),
			("code", &token.id().to_base64()),
			("redirect_uri", "https://example.com/callback"),
			(
				"client_assertion_type",
				"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			),
			("client_assertion", "not.a.jwt"),
			("code_verifier", "uniques3kr1t"),
		])
		.await
		.unwrap();

	assert_eq!(400, res.status().as_u16());
	assert_eq!("application/json", res.content_type());
	assert_eq!(
		json!({"error": "invalid_client"}),
		res.json::<Value>().await.expect("json doc")
	);
}

#[actix_rt::test]
async fn post_with_future_jwt_fails() {
	let srv = util::setup(util::vcr("tests/cassettes/example_jwks.json")).await;
	let (_, client, token) = creds_and_client(&srv.cfg).await;

	let client_jwt = Jwt::new()
		.with_iss(client.id().to_base64())
		.with_sub(client.id().to_base64())
		.with_aud(srv.cfg.base_url().as_str())
		.with_jti(token.id().to_base64())
		.with_broken_iat()
		.sign(&jwt_signing_key())
		.expect("signing failed");

	let mut res = srv
		.post("/oidc/token")
		.send_form(&[
			("grant_type", "authorization_code"),
			("code", &token.id().to_base64()),
			("redirect_uri", "https://example.com/callback"),
			(
				"client_assertion_type",
				"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			),
			("client_assertion", &client_jwt),
			("code_verifier", "uniques3kr1t"),
		])
		.await
		.unwrap();

	assert_eq!(400, res.status().as_u16());
	assert_eq!("application/json", res.content_type());
	assert_eq!(
		json!({"error": "invalid_client"}),
		res.json::<Value>().await.expect("json doc")
	);
}

#[actix_rt::test]
async fn post_with_expired_jwt_fails() {
	let srv = util::setup(util::vcr("tests/cassettes/example_jwks.json")).await;
	let (_, client, token) = creds_and_client(&srv.cfg).await;

	let client_jwt = Jwt::new()
		.with_iss(client.id().to_base64())
		.with_sub(client.id().to_base64())
		.with_aud(srv.cfg.base_url().as_str())
		.with_jti(token.id().to_base64())
		.with_broken_exp()
		.sign(&jwt_signing_key())
		.expect("signing failed");

	let mut res = srv
		.post("/oidc/token")
		.send_form(&[
			("grant_type", "authorization_code"),
			("code", &token.id().to_base64()),
			("redirect_uri", "https://example.com/callback"),
			(
				"client_assertion_type",
				"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			),
			("client_assertion", &client_jwt),
			("code_verifier", "uniques3kr1t"),
		])
		.await
		.unwrap();

	assert_eq!(400, res.status().as_u16());
	assert_eq!("application/json", res.content_type());
	assert_eq!(
		json!({"error": "invalid_client"}),
		res.json::<Value>().await.expect("json doc")
	);
}

#[actix_rt::test]
async fn post_with_no_jti_in_jwt_fails() {
	let srv = util::setup(util::vcr("tests/cassettes/example_jwks.json")).await;
	let (_, client, token) = creds_and_client(&srv.cfg).await;

	let client_jwt = Jwt::new()
		.with_iss(client.id().to_base64())
		.with_sub(client.id().to_base64())
		.with_aud(srv.cfg.base_url().as_str())
		.sign(&jwt_signing_key())
		.expect("signing failed");

	let mut res = srv
		.post("/oidc/token")
		.send_form(&[
			("grant_type", "authorization_code"),
			("code", &token.id().to_base64()),
			("redirect_uri", "https://example.com/callback"),
			(
				"client_assertion_type",
				"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			),
			("client_assertion", &client_jwt),
			("code_verifier", "uniques3kr1t"),
		])
		.await
		.unwrap();

	assert_eq!(400, res.status().as_u16());
	assert_eq!("application/json", res.content_type());
	assert_eq!(
		json!({"error": "invalid_client"}),
		res.json::<Value>().await.expect("json doc")
	);
}

#[actix_rt::test]
async fn post_with_wrong_jti_fails() {
	let srv = util::setup(util::vcr("tests/cassettes/example_jwks.json")).await;
	let (_, client, token) = creds_and_client(&srv.cfg).await;

	let client_jwt = Jwt::new()
		.with_iss(client.id().to_base64())
		.with_sub(client.id().to_base64())
		.with_aud(srv.cfg.base_url().as_str())
		.with_jti("bob")
		.sign(&jwt_signing_key())
		.expect("signing failed");

	let mut res = srv
		.post("/oidc/token")
		.send_form(&[
			("grant_type", "authorization_code"),
			("code", &token.id().to_base64()),
			("redirect_uri", "https://example.com/callback"),
			(
				"client_assertion_type",
				"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			),
			("client_assertion", &client_jwt),
			("code_verifier", "uniques3kr1t"),
		])
		.await
		.unwrap();

	assert_eq!(400, res.status().as_u16());
	assert_eq!("application/json", res.content_type());
	assert_eq!(
		json!({"error": "invalid_grant"}),
		res.json::<Value>().await.expect("json doc")
	);
}

#[actix_rt::test]
async fn missing_grant_type_is_rejected() {
	let srv = util::setup(util::vcr("tests/cassettes/example_jwks.json")).await;
	let (client_jwt, _, token) = creds_and_client(&srv.cfg).await;

	let mut res = srv
		.post("/oidc/token")
		.send_form(&[
			("code", token.id().to_base64().as_str()),
			("redirect_uri", "https://example.com/callback"),
			(
				"client_assertion_type",
				"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			),
			("client_assertion", &client_jwt),
			("code_verifier", "uniques3kr1t"),
		])
		.await
		.unwrap();

	assert_eq!(400, res.status().as_u16());
	assert_eq!("application/json", res.content_type());
	assert_eq!(
		json!({"error": "invalid_request"}),
		res.json::<Value>().await.expect("json doc")
	);
}

#[actix_rt::test]
async fn incorrect_grant_type_is_rejected() {
	let srv = util::setup(util::vcr("tests/cassettes/example_jwks.json")).await;
	let (client_jwt, _, token) = creds_and_client(&srv.cfg).await;

	let mut res = srv
		.post("/oidc/token")
		.send_form(&[
			("grant_type", "something_funny"),
			("code", &token.id().to_base64()),
			("redirect_uri", "https://example.com/callback"),
			(
				"client_assertion_type",
				"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			),
			("client_assertion", &client_jwt),
			("code_verifier", "uniques3kr1t"),
		])
		.await
		.unwrap();

	assert_eq!(400, res.status().as_u16());
	assert_eq!("application/json", res.content_type());
	assert_eq!(
		json!({"error": "unsupported_grant_type"}),
		res.json::<Value>().await.expect("json doc")
	);
}

#[actix_rt::test]
async fn missing_code_is_rejected() {
	let srv = util::setup(util::vcr("tests/cassettes/example_jwks.json")).await;
	let (client_jwt, _, _) = creds_and_client(&srv.cfg).await;

	let mut res = srv
		.post("/oidc/token")
		.send_form(&[
			("grant_type", "authorization_code"),
			("redirect_uri", "https://example.com/callback"),
			(
				"client_assertion_type",
				"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			),
			("client_assertion", &client_jwt),
			("code_verifier", "uniques3kr1t"),
		])
		.await
		.unwrap();

	assert_eq!(400, res.status().as_u16());
	assert_eq!("application/json", res.content_type());
	assert_eq!(
		json!({"error": "invalid_request"}),
		res.json::<Value>().await.expect("json doc")
	);
}

#[actix_rt::test]
async fn missing_redirect_uri_is_rejected() {
	let srv = util::setup(util::vcr("tests/cassettes/example_jwks.json")).await;
	let (client_jwt, _, token) = creds_and_client(&srv.cfg).await;

	let mut res = srv
		.post("/oidc/token")
		.send_form(&[
			("grant_type", "authorization_code"),
			("code", &token.id().to_base64()),
			(
				"client_assertion_type",
				"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			),
			("client_assertion", &client_jwt),
			("code_verifier", "uniques3kr1t"),
		])
		.await
		.unwrap();

	assert_eq!(400, res.status().as_u16());
	assert_eq!("application/json", res.content_type());
	assert_eq!(
		json!({"error": "invalid_request"}),
		res.json::<Value>().await.expect("json doc")
	);
}

#[actix_rt::test]
async fn missing_code_verifier_is_rejected() {
	let srv = util::setup(util::vcr("tests/cassettes/example_jwks.json")).await;
	let (client_jwt, _, token) = creds_and_client(&srv.cfg).await;

	let mut res = srv
		.post("/oidc/token")
		.send_form(&[
			("grant_type", "authorization_code"),
			("code", &token.id().to_base64()),
			("redirect_uri", "https://example.com/callback"),
			(
				"client_assertion_type",
				"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			),
			("client_assertion", &client_jwt),
		])
		.await
		.unwrap();

	assert_eq!(400, res.status().as_u16());
	assert_eq!("application/json", res.content_type());
	assert_eq!(
		json!({"error": "invalid_request"}),
		res.json::<Value>().await.expect("json doc")
	);
}

#[actix_rt::test]
async fn incorrect_code_verifier_is_rejected() {
	let srv = util::setup(util::vcr("tests/cassettes/example_jwks.json")).await;
	let (client_jwt, _, token) = creds_and_client(&srv.cfg).await;

	let mut res = srv
		.post("/oidc/token")
		.send_form(&[
			("grant_type", "authorization_code"),
			("code", &token.id().to_base64()),
			("redirect_uri", "https://example.com/callback"),
			(
				"client_assertion_type",
				"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			),
			("client_assertion", &client_jwt),
			("code_verifier", "thewrongs3kr1t"),
		])
		.await
		.unwrap();

	assert_eq!(400, res.status().as_u16());
	assert_eq!("application/json", res.content_type());
	assert_eq!(
		json!({"error": "invalid_grant"}),
		res.json::<Value>().await.expect("json doc")
	);
}

#[actix_rt::test]
async fn nonexistent_token_returns_fail() {
	let srv = util::setup(util::vcr("tests/cassettes/example_jwks.json")).await;
	let (client_jwt, _, _) = creds_and_client(&srv.cfg).await;

	let mut res = srv
		.post("/oidc/token")
		.send_form(&[
			("grant_type", "authorization_code"),
			("code", &Uuid::now_v7().to_base64()),
			("redirect_uri", "https://example.com/callback"),
			(
				"client_assertion_type",
				"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			),
			("client_assertion", &client_jwt),
			("code_verifier", "uniques3kr1t"),
		])
		.await
		.unwrap();

	assert_eq!(400, res.status().as_u16());
	assert_eq!("application/json", res.content_type());
	assert_eq!(
		json!({"error": "invalid_grant"}),
		res.json::<Value>().await.expect("json response")
	);
}

#[actix_rt::test]
async fn cannot_retrieve_expired_token() {
	let srv = util::setup(util::vcr("tests/cassettes/example_jwks.json")).await;
	let (client_jwt, oidc_client, _) = creds_and_client(&srv.cfg).await;

	let token = srv
		.db
		.oidc_token()
		.await
		.expect("oidc_token")
		.new()
		.with_oidc_client(oidc_client)
		.with_token("thisisnotarealtoken")
		.with_redirect_uri("https://example.com/callback")
		.with_code_challenge("xyzzy123")
		.with_valid_before(OffsetDateTime::now_utc() - Duration::from_secs(60))
		.save()
		.await
		.expect("token saved");

	let mut res = srv
		.post("/oidc/token")
		.send_form(&[
			("grant_type", "authorization_code"),
			("code", &token.id().to_base64()),
			("redirect_uri", "https://example.com/callback"),
			(
				"client_assertion_type",
				"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			),
			("client_assertion", &client_jwt),
			("code_verifier", "uniques3kr1t"),
		])
		.await
		.unwrap();

	assert_eq!(400, res.status().as_u16());
	assert_eq!("application/json", res.content_type());
	assert_eq!(
		json!({"error": "invalid_grant"}),
		res.json::<Value>().await.expect("json response")
	);
}

#[actix_rt::test]
async fn cannot_use_different_redirect_uri() {
	let srv = util::setup(util::vcr("tests/cassettes/example_jwks.json")).await;
	let (client_jwt, _, token) = creds_and_client(&srv.cfg).await;

	let mut res = srv
		.post("/oidc/token")
		.send_form(&[
			("grant_type", "authorization_code"),
			("code", &token.id().to_base64()),
			("redirect_uri", "https://example.com/somewhere/else"),
			(
				"client_assertion_type",
				"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			),
			("client_assertion", &client_jwt),
			("code_verifier", "uniques3kr1t"),
		])
		.await
		.unwrap();

	assert_eq!(400, res.status().as_u16());
	assert_eq!("application/json", res.content_type());
	assert_eq!(
		json!({"error": "invalid_grant"}),
		res.json::<Value>().await.expect("json response")
	);
}

#[actix_rt::test]
async fn cannot_get_someone_elses_token() {
	let srv = util::setup(util::vcr("tests/cassettes/example_jwks.json")).await;
	let (client_jwt, _, _) = creds_and_client(&srv.cfg).await;
	let (_, _, token) = creds_and_client(&srv.cfg).await;

	let mut res = srv
		.post("/oidc/token")
		.send_form(&[
			("grant_type", "authorization_code"),
			("code", &token.id().to_base64()),
			("redirect_uri", "https://example.com/callback"),
			(
				"client_assertion_type",
				"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			),
			("client_assertion", &client_jwt),
			("code_verifier", "uniques3kr1t"),
		])
		.await
		.unwrap();

	assert_eq!(400, res.status().as_u16());
	assert_eq!("application/json", res.content_type());
	assert_eq!(
		json!({"error": "invalid_grant"}),
		res.json::<Value>().await.expect("json response")
	);
}

#[actix_rt::test]
async fn cors_preflight() {
	let srv = util::setup(util::default).await;
	let res = srv.options("/oidc/token").send().await.unwrap();

	assert_eq!(204, res.status().as_u16());
	assert_eq!("", res.content_type());

	let headers = res.headers();

	for (hdr, val) in [
		("access-control-allow-origin", "*"),
		("access-control-allow-methods", "POST, OPTIONS"),
		("access-control-max-age", "604800"),
	] {
		assert_eq!(1, headers.get_all(hdr).count(), "no {hdr} header");
		let actual = headers.get(hdr).unwrap().to_str().unwrap();
		assert_eq!(
			val, actual,
			"bad {hdr} header value (expected {val}, got {actual}"
		);
	}
}

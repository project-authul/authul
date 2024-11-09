use actix_web::HttpMessage;
use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};
use futures_util::FutureExt;
use jwt_simple::prelude::{Audiences, Ed25519PublicKey, EdDSAPublicKeyLike, NoCustomClaims};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
	borrow::Cow,
	collections::HashMap,
	panic::AssertUnwindSafe,
	time::{SystemTime, UNIX_EPOCH},
};
use url::Url;

use crate::util::{self, Browser, BrowserLocator};

#[actix_rt::test]
async fn password_auth() {
	let b = Browser::new().await;

	let result = AssertUnwindSafe(run_password_auth(b.clone()))
		.catch_unwind()
		.await;

	b.close().await;

	if let Err(e) = result {
		panic!("{:?}", e);
	}
}

async fn run_password_auth(b: Browser) {
	let srv = util::setup(None).await;

	srv.db
		.oidc_client()
		.await
		.expect("oidc_client")
		.new()
		.with_client_id("xyzzy123")
		.with_client_secret(&Sha256::digest("s3kr1t")[..])
		.with_redirect_uris(["https://example.com/oidc/callback"])
		.save()
		.await
		.expect("OidcClient save");
	let user = srv
		.db
		.user()
		.await
		.expect("user")
		.new()
		.with_email("jaime@example.com")
		.with_pwhash(bcrypt::hash("hunter2", 4).expect("bcrypt"))
		.save()
		.await
		.expect("User save");
	let user_id = user.id();

	// Step 1: Relying Party (the website) collects needed information from the IdP's metadata
	let metadata: HashMap<String, Value> = srv
		.get("/.well-known/openid-configuration")
		.send()
		.await
		.expect("get openid-configuration")
		.json()
		.await
		.expect("openid-configuration json");

	// Step 2: RP constructs the /authorize endpoint from the OIDC config
	let mut authorize_url = Url::parse(
		metadata
			.get("authorization_endpoint")
			.expect("authorization_endpoint")
			.as_str()
			.expect("authorization_endpoint as_str"),
	)
	.expect("authorization_endpoint URL");
	authorize_url
		.query_pairs_mut()
		.append_pair("redirect_uri", "https://example.com/oidc/callback")
		.append_pair("client_id", "xyzzy123")
		.append_pair("scope", "openid")
		.append_pair("state", "inebriation")
		.append_pair("nonce", "rolf")
		.append_pair("response_type", "code");

	// Step 3: Relying Party (the website) redirects the user to the IdP
	b.goto(authorize_url.as_str())
		.await
		.expect("goto /oidc/authorize");

	b.screenshot("password_auth_email_form")
		.await
		.expect("email screen");

	// Step 2: User enters email
	let f = b
		.form(BrowserLocator::Id("email-form"))
		.await
		.expect("email-form");

	f.set_by_name("email", "jaime@example.com")
		.await
		.expect("email entry");
	f.submit().await.expect("email submit");

	b.screenshot("password_auth_password_form")
		.await
		.expect("password screen");

	// Step 3: User enters password
	let f = b
		.form(BrowserLocator::Id("password-form"))
		.await
		.expect("password-form");

	f.set_by_name("password", "hunter2")
		.await
		.expect("password entry");
	f.submit().await.expect("password submit");

	// Step 4: User gets sent back to website, with details needed for the RP to get the ID token
	let redirect_url = b.current_url().await.expect("get redirect_url");

	let redirect_params = redirect_url
		.query_pairs()
		.collect::<HashMap<Cow<'_, str>, Cow<'_, str>>>();
	eprintln!("redirect params: {redirect_params:?}");
	assert_eq!("inebriation", redirect_params.get("state").expect("state"));
	let code = redirect_params.get("code").expect("redirect_params code");

	// Step 5: RP hits IdP to get the ID token
	let token_url = Url::parse(
		metadata
			.get("token_endpoint")
			.expect("token_endpoint")
			.as_str()
			.expect("token_endpoint as_str"),
	)
	.expect("token_endpoint URL");

	// Let's just make sure we'd be sent to the right place in the Real World
	assert_eq!(srv.base_url().scheme(), token_url.scheme());
	assert_eq!(srv.base_url().authority(), token_url.authority());

	let mut res = srv
		.post(token_url.path())
		.insert_header(("Authorization", "Basic eHl6enkxMjM6czNrcjF0"))
		.send_form(&[
			("grant_type", "authorization_code"),
			("code", code),
			("redirect_uri", "https://example.com/oidc/callback"),
		])
		.await
		.expect("token post");

	assert_eq!(200, res.status().as_u16());
	assert_eq!("application/json", res.content_type());

	let doc: HashMap<String, Value> = res.json().await.expect("token JSON");

	let id_token = doc
		.get("id_token")
		.expect("id_token")
		.as_str()
		.expect("id_token as_str");
	eprintln!("ID token: {id_token}");

	// Step 6: RP validates token
	let jwks_url = Url::parse(
		metadata
			.get("jwks_uri")
			.expect("jwks_uri")
			.as_str()
			.expect("jwks_uri as_str"),
	)
	.expect("jwks_uri URL");

	// Again, a "Real World" double-check
	assert_eq!(srv.base_url().scheme(), jwks_url.scheme());
	assert_eq!(srv.base_url().authority(), jwks_url.authority());

	let mut res = srv.get(jwks_url.path()).send().await.expect("jwks get");
	assert_eq!(200, res.status().as_u16());
	assert_eq!("application/json", res.content_type());

	let keys_doc: HashMap<String, Value> = res.json().await.expect("jwks json");
	let keys = keys_doc
		.get("keys")
		.expect("jwks keys")
		.as_array()
		.expect("jwks keys array");

	let claims = keys
		.into_iter()
		.filter_map(|k| {
			eprintln!("key: {:?}", k);
			let jwk = k.as_object().expect("jwk not an object");
			if Some("OKP") != jwk.get("kty").map(|v| v.as_str().expect("kty str")) {
				eprintln!("skipping non-OKP key");
				return None;
			}
			if Some("EdDSA") != jwk.get("alg").map(|v| v.as_str().expect("alg str")) {
				eprintln!("skipping non-EdDSA key");
				return None;
			}
			if Some("Ed25519") != jwk.get("crv").map(|v| v.as_str().expect("crv str")) {
				eprintln!("skipping non-Ed25519 key");
				return None;
			}
			let b64_public_key = jwk
				.get("x")
				.expect("EdDSA key does not have x")
				.as_str()
				.expect("x str");
			let key = Ed25519PublicKey::from_bytes(
				&BASE64_URL_SAFE_NO_PAD
					.decode(b64_public_key)
					.expect("invalid b64 x"),
			)
			.expect("invalid Ed25519 key");

			key.verify_token::<NoCustomClaims>(id_token, None)
				.map_err(|e| {
					eprintln!("verify failed: {e}");
					e
				})
				.ok()
		})
		.next()
		.expect("token to be signed by an available key");

	let now = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.expect("now")
		.into();
	assert!(claims.issued_at.expect("issued_at") < now);
	assert!(claims.expires_at.expect("expires_at") > now);
	assert_eq!(srv.base_url().as_str(), claims.issuer.expect("issuer"));
	assert_eq!(user_id.to_string(), claims.subject.expect("subject"));
	assert_eq!(Some("rolf"), claims.nonce.as_deref());
	assert_eq!(
		Audiences::AsString("xyzzy123".to_string()),
		claims.audiences.expect("audiences")
	);
}

// Test: does the user get a suitably pleasant error if the OidcClient gets deleted between the
// time the user starts authenticating, and when it's time to generate the token

use actix_web::HttpMessage as _;
use serde_json::{json, Value};
use std::collections::HashMap;
use url::Url;

use crate::{
	encode_params,
	util::{self, WithCsrfCookie as _},
};
use authul_db::model::OidcClient;
use authul_frontend::AuthContext;
use authul_util::Base64Uuid;

async fn create_test_records(db: &authul_db::Pool) -> (OidcClient, OidcClient) {
	(
		db.oidc_client()
			.await
			.expect("oidc_client")
			.new()
			.with_name("Caves")
			.with_redirect_uris(["https://example.com/oidc/callback"])
			.with_jwks_uri("https://example.com/jwks.json")
			.save()
			.await
			.expect("OidcClient create"),
		db.oidc_client()
			.await
			.expect("oidc_client")
			.new()
			.with_name("Kilroy")
			.with_redirect_uris(["https://example.com/hackers/rule"])
			.with_jwks_uri("https://example.com/jwks.json")
			.save()
			.await
			.expect("OidcClient create"),
	)
}

#[actix_rt::test]
async fn check_for_cookie_support() {
	let srv = util::setup(util::default).await;

	let res = srv.get("/oidc/authorize").send().await.unwrap();

	assert_eq!(307, res.status().as_u16());
	assert_eq!("", res.content_type());

	assert_eq!(
		1,
		res.headers().get_all("location").count(),
		"bad location header(s)"
	);
	let redirect_url = Url::parse(
		res.headers()
			.get("location")
			.expect("a location header")
			.to_str()
			.expect("an ASCII location header"),
	)
	.expect("a valid redirect header");

	assert_eq!(srv.base_url().scheme(), redirect_url.scheme());
	assert_eq!(srv.base_url().authority(), redirect_url.authority());
	assert_eq!("/oidc/cookie_check", redirect_url.path());

	assert!(matches!(res.cookie("csrf_token"), Some(_)));
}

#[actix_rt::test]
async fn cookie_check_with_a_cookie_redirects_back() {
	let srv = util::setup(util::default).await;

	let res = srv
		.get("/oidc/cookie_check?foo=bar&baz=wombat")
		.with_csrf_cookie()
		.send()
		.await
		.unwrap();

	assert_eq!(307, res.status().as_u16());
	assert_eq!("", res.content_type());

	assert_eq!(
		1,
		res.headers().get_all("location").count(),
		"bad location header(s)"
	);
	let redirect_url = Url::parse(
		res.headers()
			.get("location")
			.expect("a location header")
			.to_str()
			.expect("an ASCII location header"),
	)
	.expect("a valid redirect header");

	assert_eq!(srv.base_url().scheme(), redirect_url.scheme());
	assert_eq!(srv.base_url().authority(), redirect_url.authority());
	assert_eq!("/oidc/authorize", redirect_url.path());
	assert_eq!(Some("foo=bar&baz=wombat"), redirect_url.query());
}

#[actix_rt::test]
async fn without_a_cookie_explains_why() {
	let srv = util::setup(util::default).await;

	let res = srv
		.get("/oidc/cookie_check?foo=bar&baz=wombat")
		.send()
		.await
		.unwrap();

	assert_eq!(200, res.status().as_u16());
	assert_eq!("text/html", res.content_type());
}

#[actix_rt::test]
async fn get_basic_successful_code_flow_authorize_request() {
	let srv = util::setup(util::default).await;

	let (client, _) = create_test_records(&srv.db).await;

	let res = srv.get("/oidc/authorize?".to_string() + encode_params!(redirect_uri: "https://example.com/oidc/callback", client_id: &client.id().to_base64(), scope: "openid", response_type: "code", code_challenge_method: "S256", code_challenge: "xyzzy123")).with_csrf_cookie().send().await.unwrap();

	assert_eq!(303, res.status().as_u16());
	assert_eq!(res.content_type(), "");

	assert_eq!(
		1,
		res.headers().get_all("location").count(),
		"bad location header(s)"
	);
	let redirect_url = Url::parse(
		res.headers()
			.get("location")
			.expect("a location header")
			.to_str()
			.expect("an ASCII location header"),
	)
	.expect("a valid redirect header");
	assert_eq!("/authenticate", redirect_url.path());
	assert!(
		redirect_url.query().is_some(),
		"no query parameters on redirect URL"
	);
	let redirect_params: HashMap<String, String> =
		url::form_urlencoded::parse(redirect_url.query().unwrap().as_bytes())
			.into_owned()
			.collect();
	assert_eq!(
		Some("Caves"),
		redirect_params.get("target").map(|s| s.as_str())
	);

	// Make sure the context got everything out of the request
	let ctx = AuthContext::from_str(
		redirect_params
			.get("ctx")
			.expect("redirect_params doesn't have ctx"),
		&srv.cfg,
	)
	.expect("AuthContext decrypt/decode failed");
	assert_eq!(client.id(), ctx.oidc_client_id());
	assert_eq!("https://example.com/oidc/callback", ctx.redirect_uri());
	assert_eq!("xyzzy123", ctx.code_challenge());
	assert_eq!(None, ctx.principal());
	assert_eq!(None, ctx.nonce());
	assert_eq!(None, ctx.state());
	assert_eq!(None, ctx.pwhash());
}

#[actix_rt::test]
async fn post_basic_successful_code_flow_authorize_request() {
	let srv = util::setup(util::default).await;

	let (client, _) = create_test_records(&srv.db).await;

	let res = srv
		.post("/oidc/authorize")
		.with_csrf_cookie()
		.send_form(&[
			("redirect_uri", "https://example.com/oidc/callback"),
			("client_id", &client.id().to_base64()),
			("scope", "openid"),
			("response_type", "code"),
			("code_challenge_method", "S256"),
			("code_challenge", "xyzzy123"),
		])
		.await
		.unwrap();

	assert_eq!(303, res.status().as_u16());
	assert_eq!(res.content_type(), "");

	assert_eq!(
		1,
		res.headers().get_all("location").count(),
		"bad location header(s)"
	);
	let redirect_url = Url::parse(
		res.headers()
			.get("location")
			.expect("a location header")
			.to_str()
			.expect("an ASCII location header"),
	)
	.expect("a valid redirect header");
	assert_eq!("/authenticate", redirect_url.path());
	assert!(
		redirect_url.query().is_some(),
		"no query parameters on redirect URL"
	);
	let redirect_params: HashMap<String, String> =
		url::form_urlencoded::parse(redirect_url.query().unwrap().as_bytes())
			.into_owned()
			.collect();

	// Make sure the context got everything out of the request
	let ctx = AuthContext::from_str(
		redirect_params
			.get("ctx")
			.expect("redirect_params doesn't have ctx"),
		&srv.cfg,
	)
	.expect("AuthContext decrypt/decode failed");
	assert_eq!(client.id(), ctx.oidc_client_id());
	assert_eq!("https://example.com/oidc/callback", ctx.redirect_uri());
	assert_eq!("xyzzy123", ctx.code_challenge());
	assert_eq!(None, ctx.principal());
	assert_eq!(None, ctx.nonce());
	assert_eq!(None, ctx.state());
	assert_eq!(None, ctx.pwhash());
}

#[actix_rt::test]
async fn get_with_nonce_captures_correctly() {
	let srv = util::setup(util::default).await;

	let (client, _) = create_test_records(&srv.db).await;

	let res = srv.get("/oidc/authorize?".to_string() + encode_params!(redirect_uri: "https://example.com/oidc/callback", client_id: &client.id().to_base64(), scope: "openid", response_type: "code", code_challenge_method: "S256", code_challenge: "xyzzy123", nonce: "noreuseplz")).with_csrf_cookie().send().await.unwrap();

	assert_eq!(303, res.status().as_u16());
	assert_eq!(res.content_type(), "");

	assert_eq!(
		1,
		res.headers().get_all("location").count(),
		"bad location header(s)"
	);
	let redirect_url = Url::parse(
		res.headers()
			.get("location")
			.expect("a location header")
			.to_str()
			.expect("an ASCII location header"),
	)
	.expect("a valid redirect header");
	assert_eq!("/authenticate", redirect_url.path());
	assert!(
		redirect_url.query().is_some(),
		"no query parameters on redirect URL"
	);
	let redirect_params: HashMap<String, String> =
		url::form_urlencoded::parse(redirect_url.query().unwrap().as_bytes())
			.into_owned()
			.collect();
	assert_eq!(
		Some("Caves"),
		redirect_params.get("target").map(|s| s.as_str())
	);

	// Make sure the context got everything out of the request
	let ctx = AuthContext::from_str(
		redirect_params
			.get("ctx")
			.expect("redirect_params doesn't have ctx"),
		&srv.cfg,
	)
	.expect("AuthContext decrypt/decode failed");
	assert_eq!(client.id(), ctx.oidc_client_id());
	assert_eq!("https://example.com/oidc/callback", ctx.redirect_uri());
	assert_eq!("xyzzy123", ctx.code_challenge());
	assert_eq!(None, ctx.principal());
	assert_eq!(Some("noreuseplz"), ctx.nonce().map(|s| s.as_str()));
	assert_eq!(None, ctx.state());
	assert_eq!(None, ctx.pwhash());
}

#[actix_rt::test]
async fn get_with_state_captures_correctly() {
	let srv = util::setup(util::default).await;

	let (client, _) = create_test_records(&srv.db).await;

	let res = srv.get("/oidc/authorize?".to_string() + encode_params!(redirect_uri: "https://example.com/oidc/callback", client_id: &client.id().to_base64(), scope: "openid", response_type: "code", code_challenge_method: "S256", code_challenge: "xyzzy123", state: "inebriation")).with_csrf_cookie().send().await.unwrap();

	assert_eq!(303, res.status().as_u16());
	assert_eq!(res.content_type(), "");

	assert_eq!(
		1,
		res.headers().get_all("location").count(),
		"bad location header(s)"
	);
	let redirect_url = Url::parse(
		res.headers()
			.get("location")
			.expect("a location header")
			.to_str()
			.expect("an ASCII location header"),
	)
	.expect("a valid redirect header");
	assert_eq!("/authenticate", redirect_url.path());
	assert!(
		redirect_url.query().is_some(),
		"no query parameters on redirect URL"
	);
	let redirect_params: HashMap<String, String> =
		url::form_urlencoded::parse(redirect_url.query().unwrap().as_bytes())
			.into_owned()
			.collect();
	assert_eq!(
		Some("Caves"),
		redirect_params.get("target").map(|s| s.as_str())
	);

	// Make sure the context got everything out of the request
	let ctx = AuthContext::from_str(
		redirect_params
			.get("ctx")
			.expect("redirect_params doesn't have ctx"),
		&srv.cfg,
	)
	.expect("AuthContext decrypt/decode failed");
	assert_eq!(client.id(), ctx.oidc_client_id());
	assert_eq!("https://example.com/oidc/callback", ctx.redirect_uri());
	assert_eq!("xyzzy123", ctx.code_challenge());
	assert_eq!(None, ctx.principal());
	assert_eq!(None, ctx.nonce());
	assert_eq!(Some("inebriation"), ctx.state().map(|s| s.as_str()));
	assert_eq!(None, ctx.pwhash());
}

#[actix_rt::test]
async fn accept_not_understood_scope() {
	let srv = util::setup(util::default).await;

	let (client, _) = create_test_records(&srv.db).await;

	let res = srv.get("/oidc/authorize?".to_string() + encode_params!(redirect_uri: "https://example.com/oidc/callback", client_id: &client.id().to_base64(), scope: "openid token", response_type: "code", code_challenge_method: "S256", code_challenge: "xyzzy123")).with_csrf_cookie().send().await.unwrap();

	assert_eq!(303, res.status().as_u16());
	assert_eq!(res.content_type(), "");

	assert_eq!(
		1,
		res.headers().get_all("location").count(),
		"bad location header(s)"
	);
	let redirect_url = Url::parse(
		res.headers()
			.get("location")
			.expect("a location header")
			.to_str()
			.expect("an ASCII location header"),
	)
	.expect("a valid redirect header");
	assert_eq!("/authenticate", redirect_url.path());
	assert!(
		redirect_url.query().is_some(),
		"no query parameters on redirect URL"
	);
	let redirect_params: HashMap<String, String> =
		url::form_urlencoded::parse(redirect_url.query().unwrap().as_bytes())
			.into_owned()
			.collect();
	assert!(redirect_params.contains_key("ctx"));
}

#[actix_rt::test]
async fn accept_default_response_mode() {
	let srv = util::setup(util::default).await;

	let (client, _) = create_test_records(&srv.db).await;

	let res = srv.get("/oidc/authorize?".to_string() + encode_params!(redirect_uri: "https://example.com/oidc/callback", client_id: &client.id().to_base64(), scope: "openid", response_mode: "query", response_type: "code", code_challenge_method: "S256", code_challenge: "xyzzy123")).with_csrf_cookie().send().await.unwrap();

	assert_eq!(303, res.status().as_u16());
	assert_eq!(res.content_type(), "");

	assert_eq!(
		1,
		res.headers().get_all("location").count(),
		"bad location header(s)"
	);
	let redirect_url = Url::parse(
		res.headers()
			.get("location")
			.expect("a location header")
			.to_str()
			.expect("an ASCII location header"),
	)
	.expect("a valid redirect header");
	assert_eq!("/authenticate", redirect_url.path());
	assert!(
		redirect_url.query().is_some(),
		"no query parameters on redirect URL"
	);
	let redirect_params: HashMap<String, String> =
		url::form_urlencoded::parse(redirect_url.query().unwrap().as_bytes())
			.into_owned()
			.collect();
	assert!(redirect_params.contains_key("ctx"));
}

#[actix_rt::test]
async fn reject_any_other_response_mode() {
	let srv = util::setup(util::default).await;

	let (client, _) = create_test_records(&srv.db).await;

	let res = srv.get("/oidc/authorize?".to_string() + encode_params!(redirect_uri: "https://example.com/oidc/callback", client_id: &client.id().to_base64(), scope: "openid", response_mode: "fragment", response_type: "code", code_challenge_method: "S256", code_challenge: "xyzzy123")).with_csrf_cookie().send().await.unwrap();

	assert_eq!(302, res.status().as_u16());
	assert_eq!(
		1,
		res.headers().get_all("location").count(),
		"bad location header(s)"
	);
	let redirect_url = Url::parse(
		res.headers()
			.get("location")
			.expect("a location header")
			.to_str()
			.expect("an ASCII location header"),
	)
	.expect("a valid redirect header");
	assert_eq!("https", redirect_url.scheme());
	assert_eq!("example.com", redirect_url.authority());
	assert_eq!("/oidc/callback", redirect_url.path());
	assert!(
		redirect_url.query().is_some(),
		"no query parameters on redirect URL"
	);
	let redirect_params: HashMap<String, String> =
		url::form_urlencoded::parse(redirect_url.query().unwrap().as_bytes())
			.into_owned()
			.collect();
	assert_eq!(
		Some("invalid_request"),
		redirect_params.get("error").map(|x| x.as_str())
	);
}

#[actix_rt::test]
async fn no_pkce_returns_error_redirect() {
	let srv = util::setup(util::default).await;

	let (client, _) = create_test_records(&srv.db).await;

	let res = srv.get("/oidc/authorize?".to_string() + encode_params!(redirect_uri: "https://example.com/oidc/callback", client_id: &client.id().to_base64(), scope: "openid", response_type: "code")).with_csrf_cookie().send().await.unwrap();

	assert_eq!(302, res.status().as_u16());
	assert_eq!(
		1,
		res.headers().get_all("location").count(),
		"bad location header(s)"
	);
	let redirect_url = Url::parse(
		res.headers()
			.get("location")
			.expect("a location header")
			.to_str()
			.expect("an ASCII location header"),
	)
	.expect("a valid redirect header");
	assert_eq!("https", redirect_url.scheme());
	assert_eq!("example.com", redirect_url.authority());
	assert_eq!("/oidc/callback", redirect_url.path());
	assert!(
		redirect_url.query().is_some(),
		"no query parameters on redirect URL"
	);
	let redirect_params: HashMap<String, String> =
		url::form_urlencoded::parse(redirect_url.query().unwrap().as_bytes())
			.into_owned()
			.collect();
	assert_eq!(
		Some("invalid_request"),
		redirect_params.get("error").map(|x| x.as_str())
	);
}

#[actix_rt::test]
async fn unsupported_pkce_alg_returns_error_redirect() {
	let srv = util::setup(util::default).await;

	let (client, _) = create_test_records(&srv.db).await;

	let res = srv.get("/oidc/authorize?".to_string() + encode_params!(redirect_uri: "https://example.com/oidc/callback", client_id: &client.id().to_base64(), scope: "openid", response_type: "code", code_challenge_method: "plain", code_challenge: "lolnotasecret")).with_csrf_cookie().send().await.unwrap();

	assert_eq!(302, res.status().as_u16());
	assert_eq!(
		1,
		res.headers().get_all("location").count(),
		"bad location header(s)"
	);
	let redirect_url = Url::parse(
		res.headers()
			.get("location")
			.expect("a location header")
			.to_str()
			.expect("an ASCII location header"),
	)
	.expect("a valid redirect header");
	assert_eq!("https", redirect_url.scheme());
	assert_eq!("example.com", redirect_url.authority());
	assert_eq!("/oidc/callback", redirect_url.path());
	assert!(
		redirect_url.query().is_some(),
		"no query parameters on redirect URL"
	);
	let redirect_params: HashMap<String, String> =
		url::form_urlencoded::parse(redirect_url.query().unwrap().as_bytes())
			.into_owned()
			.collect();
	assert_eq!(
		Some("invalid_request"),
		redirect_params.get("error").map(|x| x.as_str())
	);
}

#[actix_rt::test]
async fn unknown_redirect_uri_is_rejected() {
	let srv = util::setup(util::default).await;

	let (client, _) = create_test_records(&srv.db).await;

	let mut res = srv.get("/oidc/authorize?".to_string() + encode_params!(redirect_uri: "https://example.com/hackers/rule", client_id: &client.id().to_base64(), scope: "openid", response_type: "code", code_challenge_method: "S256", code_challenge: "xyzzy123")).with_csrf_cookie().send().await.unwrap();

	assert_eq!(400, res.status().as_u16());
	assert_eq!(res.content_type(), "application/json");
	assert_eq!(
		json!({"error": "invalid_request"}),
		res.json::<Value>().await.expect("json response")
	);
}

#[actix_rt::test]
async fn mismatched_redirect_url_is_rejected() {
	let srv = util::setup(util::default).await;

	let (client, _) = create_test_records(&srv.db).await;

	let mut res = srv.get("/oidc/authorize?".to_string() + encode_params!(redirect_uri: "https://example.com/hackers/rule", client_id: &client.id().to_base64(), scope: "openid", response_type: "code", code_challenge_method: "S256", code_challenge: "xyzzy123")).with_csrf_cookie().send().await.unwrap();

	assert_eq!(400, res.status().as_u16());
	assert_eq!(res.content_type(), "application/json");
	assert_eq!(
		json!({"error": "invalid_request"}),
		res.json::<Value>().await.expect("json response")
	);
}

#[actix_rt::test]
async fn accept_additional_query_parameters() {
	let srv = util::setup(util::default).await;

	let (client, _) = create_test_records(&srv.db).await;

	let res = srv.get("/oidc/authorize?".to_string() + encode_params!(redirect_uri: "https://example.com/oidc/callback", client_id: &client.id().to_base64(), something: "funny", scope: "openid", response_type: "code", code_challenge_method: "S256", code_challenge: "xyzzy123")).with_csrf_cookie().send().await.unwrap();

	assert_eq!(303, res.status().as_u16());
}

#[actix_rt::test]
async fn missing_response_type_reports_error() {
	let srv = util::setup(util::default).await;

	let (client, _) = create_test_records(&srv.db).await;

	let res = srv.get("/oidc/authorize?".to_string() + encode_params!(redirect_uri: "https://example.com/oidc/callback", client_id: &client.id().to_base64(), scope: "openid", code_challenge_method: "S256", code_challenge: "xyzzy123")).with_csrf_cookie().send().await.unwrap();

	assert_eq!(302, res.status().as_u16());
	assert_eq!(
		1,
		res.headers().get_all("location").count(),
		"bad location header(s)"
	);
	let redirect_url = Url::parse(
		res.headers()
			.get("location")
			.expect("a location header")
			.to_str()
			.expect("an ASCII location header"),
	)
	.expect("a valid redirect header");
	assert_eq!("https", redirect_url.scheme());
	assert_eq!("example.com", redirect_url.authority());
	assert_eq!("/oidc/callback", redirect_url.path());
	assert!(
		redirect_url.query().is_some(),
		"no query parameters on redirect URL"
	);
	let redirect_params: HashMap<String, String> =
		url::form_urlencoded::parse(redirect_url.query().unwrap().as_bytes())
			.into_owned()
			.collect();
	assert_eq!(
		Some("invalid_request"),
		redirect_params.get("error").map(|x| x.as_str())
	);
}

#[actix_rt::test]
async fn missing_redirect_uri_reports_error() {
	let srv = util::setup(util::default).await;

	let (client, _) = create_test_records(&srv.db).await;

	let mut res = srv
		.get(
			"/oidc/authorize?".to_string()
				+ encode_params!(client_id: &client.id().to_base64(), scope: "openid", response_type: "code", code_challenge_method: "S256", code_challenge: "xyzzy123"),
		)
		.with_csrf_cookie().send()
		.await
		.unwrap();

	assert_eq!(400, res.status().as_u16());
	assert_eq!(res.content_type(), "application/json");
	assert_eq!(
		json!({"error": "invalid_request"}),
		res.json::<Value>().await.expect("json response")
	);
}

#[actix_rt::test]
async fn missing_client_id_reports_error() {
	let srv = util::setup(util::default).await;

	create_test_records(&srv.db).await;

	let mut res = srv.get("/oidc/authorize?".to_string() + encode_params!(redirect_uri: "https://example.com/oidc/callback", scope: "openid", response_type: "code", code_challenge_method: "S256", code_challenge: "xyzzy123")).with_csrf_cookie().send().await.unwrap();

	assert_eq!(400, res.status().as_u16());
	assert_eq!(res.content_type(), "application/json");
	assert_eq!(
		json!({"error": "invalid_request"}),
		res.json::<Value>().await.expect("json response")
	);
}

#[actix_rt::test]
async fn unsupported_response_type_reports_error() {
	let srv = util::setup(util::default).await;

	let (client, _) = create_test_records(&srv.db).await;

	let res = srv.get("/oidc/authorize?".to_string() + encode_params!(redirect_uri: "https://example.com/oidc/callback", client_id: &client.id().to_base64(), scope: "openid", response_type: "id_token", code_challenge_method: "S256", code_challenge: "xyzzy123")).with_csrf_cookie().send().await.unwrap();

	assert_eq!(302, res.status().as_u16());
	assert_eq!(
		1,
		res.headers().get_all("location").count(),
		"bad location header(s)"
	);
	let redirect_url = Url::parse(
		res.headers()
			.get("location")
			.expect("a location header")
			.to_str()
			.expect("an ASCII location header"),
	)
	.expect("a valid redirect header");
	assert_eq!("https", redirect_url.scheme());
	assert_eq!("example.com", redirect_url.authority());
	assert_eq!("/oidc/callback", redirect_url.path());
	assert!(
		redirect_url.query().is_some(),
		"no query parameters on redirect URL"
	);
	let redirect_params: HashMap<String, String> =
		url::form_urlencoded::parse(redirect_url.query().unwrap().as_bytes())
			.into_owned()
			.collect();
	assert_eq!(
		Some("unsupported_response_type"),
		redirect_params.get("error").map(|x| x.as_str())
	);
}

#[actix_rt::test]
async fn unsupported_scope_reports_error() {
	let srv = util::setup(util::default).await;

	let (client, _) = create_test_records(&srv.db).await;

	let res = srv.get("/oidc/authorize?".to_string() + encode_params!(redirect_uri: "https://example.com/oidc/callback", client_id: &client.id().to_base64(), scope: "bob goblin", response_type: "code", code_challenge_method: "S256", code_challenge: "xyzzy123")).with_csrf_cookie().send().await.unwrap();

	assert_eq!(302, res.status().as_u16());
	assert_eq!(
		1,
		res.headers().get_all("location").count(),
		"bad location header(s)"
	);
	let redirect_url = Url::parse(
		res.headers()
			.get("location")
			.expect("a location header")
			.to_str()
			.expect("an ASCII location header"),
	)
	.expect("a valid redirect header");
	assert_eq!("https", redirect_url.scheme());
	assert_eq!("example.com", redirect_url.authority());
	assert_eq!("/oidc/callback", redirect_url.path());
	assert!(
		redirect_url.query().is_some(),
		"no query parameters on redirect URL"
	);
	let redirect_params: HashMap<String, String> =
		url::form_urlencoded::parse(redirect_url.query().unwrap().as_bytes())
			.into_owned()
			.collect();
	assert_eq!(
		Some("invalid_scope"),
		redirect_params.get("error").map(|x| x.as_str())
	);
}

use actix_web::HttpMessage as _;
use serde_json::Value;
use std::{collections::HashMap, time::Duration};
use time::OffsetDateTime;

use crate::util;

#[actix_rt::test]
async fn get_oidc_provider_metadata() {
	let srv = util::setup(util::default).await;

	let mut res = srv
		.get("/.well-known/openid-configuration")
		.send()
		.await
		.unwrap();

	assert_eq!(200, res.status().as_u16());
	assert_eq!("application/json", res.content_type());

	let doc: HashMap<String, Value> = res.json().await.expect("invalid JSON response body");

	assert_eq!(
		Some(srv.url("").as_str()),
		doc.get("issuer").map(|v| v.as_str().unwrap())
	);
}

#[actix_rt::test]
async fn post_to_oidc_provider_metadata_is_rejected() {
	let srv = util::setup(util::default).await;

	let res = srv
		.post("/.well-known/openid-configuration")
		.send_form(&[&("foo", "bar")])
		.await
		.unwrap();

	assert_eq!(405, res.status().as_u16());
}

#[actix_rt::test]
async fn get_oidc_keys() {
	let srv = util::setup(util::default).await;

	// Remove the managed keys generated by the background task system
	srv.db
		.conn()
		.await
		.expect("db conn")
		.execute("DELETE FROM signing_keys", &[])
		.await
		.expect("key nuke");

	// This key should be in the jwks, it's the currently used one
	srv.db
		.signing_key()
		.await
		.expect("signing_key")
		.new()
		.with_usage("oidc")
		.with_used_from(OffsetDateTime::now_utc() - Duration::from_secs(10000))
		.with_not_used_from(OffsetDateTime::now_utc() + Duration::from_secs(10000))
		.with_expired_from(OffsetDateTime::now_utc() + Duration::from_secs(30000))
		.with_key(
			srv.cfg
				.new_oidc_signing_key()
				.expect("successful encryption"),
		)
		.save()
		.await
		.expect("SigningKey save");
	// This one, too, because it's the next one to use
	srv.db
		.signing_key()
		.await
		.expect("signing_key")
		.new()
		.with_usage("oidc")
		.with_used_from(OffsetDateTime::now_utc() + Duration::from_secs(10000))
		.with_not_used_from(OffsetDateTime::now_utc() + Duration::from_secs(30000))
		.with_expired_from(OffsetDateTime::now_utc() + Duration::from_secs(50000))
		.with_key(
			srv.cfg
				.new_oidc_signing_key()
				.expect("successful encryption"),
		)
		.save()
		.await
		.expect("SigningKey save");
	// As should this one, even though we're not longer using it
	srv.db
		.signing_key()
		.await
		.expect("signing_key")
		.new()
		.with_usage("oidc")
		.with_used_from(OffsetDateTime::now_utc() - Duration::from_secs(30000))
		.with_not_used_from(OffsetDateTime::now_utc() - Duration::from_secs(10000))
		.with_expired_from(OffsetDateTime::now_utc() + Duration::from_secs(10000))
		.with_key(
			srv.cfg
				.new_oidc_signing_key()
				.expect("successful encryption"),
		)
		.save()
		.await
		.expect("SigningKey save");
	// This one shouldn't appear, as it's expired
	srv.db
		.signing_key()
		.await
		.expect("signing_key")
		.new()
		.with_usage("oidc")
		.with_used_from(OffsetDateTime::now_utc() - Duration::from_secs(50000))
		.with_not_used_from(OffsetDateTime::now_utc() - Duration::from_secs(30000))
		.with_expired_from(OffsetDateTime::now_utc() - Duration::from_secs(10000))
		.with_key(b"xyzzy")
		.save()
		.await
		.expect("SigningKey save");
	// This one shouldn't appear, as it's not an OIDC key
	srv.db
		.signing_key()
		.await
		.expect("signing_key")
		.new()
		.with_usage("madness")
		.with_used_from(OffsetDateTime::now_utc() - Duration::from_secs(10000))
		.with_not_used_from(OffsetDateTime::now_utc() + Duration::from_secs(10000))
		.with_expired_from(OffsetDateTime::now_utc() + Duration::from_secs(30000))
		.with_key(b"xyzzy")
		.save()
		.await
		.expect("SigningKey save");

	let mut res = srv.get("/oidc/jwks.json").send().await.unwrap();

	assert_eq!(200, res.status().as_u16());
	assert_eq!("application/json", res.content_type());

	let doc: HashMap<String, Value> = res.json().await.expect("invalid JSON response body");

	let keys = doc
		.get("keys")
		.expect("doc should have keys")
		.as_array()
		.expect("keys isn't array");

	assert_eq!(3, keys.len());

	let _ = keys[0].as_object().expect("key to be an object");
}

#[actix_rt::test]
async fn post_to_oidc_keys_is_rejected() {
	let srv = util::setup(util::default).await;

	let res = srv
		.post("/oidc/jwks.json")
		.send_form(&[&("foo", "bar")])
		.await
		.unwrap();

	assert_eq!(405, res.status().as_u16());
}

#[actix_rt::test]
async fn cors_preflight_openid_config() {
	let srv = util::setup(util::default).await;

	let res = srv
		.options("/.well-known/openid-configuration")
		.send()
		.await
		.unwrap();

	assert_eq!(204, res.status().as_u16());
	assert_eq!("", res.content_type());

	let headers = res.headers();

	for (hdr, val) in [
		("access-control-allow-origin", "*"),
		("access-control-allow-methods", "GET, HEAD, OPTIONS"),
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

#[actix_rt::test]
async fn cors_preflight_jwks() {
	let srv = util::setup(util::default).await;

	let res = srv.options("/oidc/jwks.json").send().await.unwrap();

	assert_eq!(204, res.status().as_u16());
	assert_eq!("", res.content_type());

	let headers = res.headers();

	for (hdr, val) in [
		("access-control-allow-origin", "*"),
		("access-control-allow-methods", "GET, HEAD, OPTIONS"),
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
use actix_web::{cookie::SameSite, HttpMessage as _};
use uuid::Uuid;

use crate::{css, util};
use authul_frontend::AuthContext;

mod oauth_callback;
mod password_auth;

#[actix_rt::test]
async fn get_with_no_context_returns_helpful_page() {
	let srv = util::setup(util::default).await;

	let mut res = srv
		.get("/authenticate")
		.insert_header(("accept", "text/html"))
		.send()
		.await
		.unwrap();

	assert_eq!(200, res.status().as_u16());
	assert_eq!(res.content_type(), "text/html");

	let doc = util::doc(&mut res).await;
	assert_eq!(0, doc.select(css!("form")).count(), "page has a form in it");
	assert!(
		doc.html().contains("authenticate you to another website"),
		"page is not helpful"
	);
}

#[actix_rt::test]
async fn get_with_valid_context_sets_csrf_token() {
	let srv = util::setup(util::default).await;

	let ctx = AuthContext::new(srv.cfg.clone(), Uuid::now_v7(), "", "").to_string();

	let res = srv
		.get(&format!("/authenticate?ctx={ctx}"))
		.insert_header(("accept", "text/html"))
		.send()
		.await
		.unwrap();

	assert_eq!(200, res.status().as_u16());
	assert_eq!(res.content_type(), "text/html");

	let cookie = res.cookie("csrf_token").expect("no csrf_token cookie");
	assert_eq!(
		srv.base_url().host().unwrap().to_string(),
		cookie.domain().expect("csrf_token cookie has no domain")
	);
	assert_eq!(
		srv.base_url().path(),
		cookie.path().expect("csrf_token cookie has no path")
	);
	assert!(cookie
		.secure()
		.expect("csrf_token cookie has no secure setting"));
	assert_eq!(
		SameSite::Strict,
		cookie
			.same_site()
			.expect("csrf_token cookie has no sameSite setting")
	);
	assert!(cookie
		.http_only()
		.expect("csrf_token cookie has no httpOnly setting"));
}

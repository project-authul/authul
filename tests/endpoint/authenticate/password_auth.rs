use actix_web::HttpMessage as _;
use authul_frontend::AuthContext;
use std::collections::HashMap;
use url::Url;
use uuid::Uuid;

use crate::{css, util};
use authul_util::Base64Uuid;

#[actix_rt::test]
async fn get_with_valid_context_asks_for_email() {
	let srv = util::setup(util::default).await;

	let ctx = AuthContext::new(srv.cfg.clone(), Uuid::now_v7(), "", "").to_string();

	let mut res = srv
		.get(&format!("/authenticate?ctx={ctx}"))
		.insert_header(("accept", "text/html"))
		.send()
		.await
		.unwrap();

	assert_eq!(200, res.status().as_u16());
	assert_eq!(res.content_type(), "text/html");

	let doc = util::doc(&mut res).await;

	let form_sel = css!("form");
	let mut forms = doc.select(form_sel);
	assert_eq!(1, forms.clone().count(), "page needs an email form");
	let form = forms.next().unwrap();

	let email_box_sel = css!("input[name='email']");
	let mut email_box = form.select(email_box_sel);
	assert_eq!(1, email_box.clone().count(), "form needs an email box");
	let email_box = email_box.next().unwrap();

	assert_eq!(Some("email"), email_box.attr("name"));
	assert_eq!(Some("email"), email_box.attr("type"));
	assert_eq!(None, email_box.attr("value"));
	assert_eq!(Some("false"), email_box.attr("aria-invalid"));
	assert_eq!(Some(""), email_box.attr("aria-errormessage"));
}

#[actix_rt::test]
async fn post_with_nothing_returns_helpful_page() {
	let srv = util::setup(util::default).await;

	let res = srv
		.post("/authenticate/submit_email")
		.insert_header(("accept", "text/html"))
		.send_form::<[&str; 0]>(&[])
		.await
		.unwrap();

	assert_eq!(302, res.status().as_u16());
	let redirect_url =
		Url::parse(res.headers().get("location").unwrap().to_str().unwrap()).unwrap();

	let mut res = srv
		.get(
			srv.base_url()
				.make_relative(&redirect_url)
				.unwrap()
				.as_str(),
		)
		.insert_header(("accept", "text/html"))
		.send()
		.await
		.unwrap();

	assert_eq!(200, res.status().as_u16());
	assert_eq!("text/html", res.content_type());

	let doc = util::doc(&mut res).await;
	assert_eq!(0, doc.select(css!("form")).count(), "page has a form in it");
	assert!(
		doc.html().contains("authenticate you to another website"),
		"page is not helpful"
	);
}

#[actix_rt::test]
async fn post_with_invalid_context_returns_helpful_page() {
	let srv = util::setup(util::default).await;

	let res = srv
		.post("/authenticate/submit_email")
		.insert_header(("accept", "text/html"))
		.send_form(&[("ctx", "l33th4x0r"), ("email", "bob@example.com")])
		.await
		.unwrap();

	assert_eq!(302, res.status().as_u16());
	let redirect_url =
		Url::parse(res.headers().get("location").unwrap().to_str().unwrap()).unwrap();

	let mut res = srv
		.get(
			srv.base_url()
				.make_relative(&redirect_url)
				.unwrap()
				.as_str(),
		)
		.insert_header(("accept", "text/html"))
		.send()
		.await
		.unwrap();

	assert_eq!(200, res.status().as_u16());
	assert_eq!("text/html", res.content_type());

	let doc = util::doc(&mut res).await;
	assert_eq!(0, doc.select(css!("form")).count(), "page has a form in it");
	assert!(
		doc.html()
			.contains("the authentication context was invalid"),
		"page is not helpful"
	);
}

#[actix_rt::test]
async fn post_with_empty_email_provides_helpful_error() {
	let srv = util::setup(util::default).await;

	let ctx = AuthContext::new(srv.cfg.clone(), Uuid::now_v7(), "", "").to_string();

	let res = srv
		.post("/authenticate/submit_email")
		.insert_header(("accept", "text/html"))
		.send_form(&[("ctx", ctx)])
		.await
		.unwrap();

	assert_eq!(302, res.status().as_u16());
	let redirect_url =
		Url::parse(res.headers().get("location").unwrap().to_str().unwrap()).unwrap();

	let mut res = srv
		.get(
			srv.base_url()
				.make_relative(&redirect_url)
				.unwrap()
				.as_str(),
		)
		.insert_header(("accept", "text/html"))
		.send()
		.await
		.unwrap();

	assert_eq!(200, res.status().as_u16());
	assert_eq!("text/html", res.content_type());

	let doc = util::doc(&mut res).await;

	let form_sel = css!("form");
	let mut forms = doc.select(form_sel);
	assert_eq!(1, forms.clone().count(), "page needs an email form");
	let form = forms.next().unwrap();

	assert_eq!(
		1,
		form.select(css!("input[name='ctx']")).count(),
		"form doesn't re-submit auth context"
	);

	let email_box_sel = css!("input[name='email']");
	let mut email_box = form.select(email_box_sel);
	assert_eq!(1, email_box.clone().count(), "form needs an email box");
	let email_box = email_box.next().unwrap();

	assert_eq!(Some("email"), email_box.attr("name"));
	assert_eq!(Some("email"), email_box.attr("type"));
	assert_eq!(None, email_box.attr("value"));
	assert_eq!(Some("true"), email_box.attr("aria-invalid"));
	assert_eq!(Some("email-error"), email_box.attr("aria-errormessage"));

	let err_sel = css!("small[class='error-text']");
	let mut error_text = form.select(err_sel);
	assert_eq!(1, error_text.clone().count(), "form should show an error");
	let error_text = error_text.next().unwrap();
	assert!(
		error_text.inner_html().contains("enter your email"),
		"helpful message not so helpful (got {})",
		error_text.inner_html()
	);
}

#[actix_rt::test]
async fn post_with_invalid_email_provides_helpful_error() {
	let srv = util::setup(util::default).await;

	let ctx = AuthContext::new(srv.cfg.clone(), Uuid::now_v7(), "", "").to_string();

	let res = srv
		.post("/authenticate/submit_email")
		.insert_header(("accept", "text/html"))
		.send_form(&[("ctx", ctx), ("email", "Jaime Bloggs".to_string())])
		.await
		.unwrap();

	assert_eq!(302, res.status().as_u16());
	let redirect_url =
		Url::parse(res.headers().get("location").unwrap().to_str().unwrap()).unwrap();

	let mut res = srv
		.get(
			srv.base_url()
				.make_relative(&redirect_url)
				.unwrap()
				.as_str(),
		)
		.insert_header(("accept", "text/html"))
		.send()
		.await
		.unwrap();

	assert_eq!(200, res.status().as_u16());
	assert_eq!("text/html", res.content_type());

	let doc = util::doc(&mut res).await;

	let form_sel = css!("form");
	let mut forms = doc.select(form_sel);
	assert_eq!(1, forms.clone().count(), "page needs an email form");
	let form = forms.next().unwrap();

	assert_eq!(
		1,
		form.select(css!("input[name='ctx']")).count(),
		"form doesn't re-submit auth context"
	);

	let email_box_sel = css!("input[name='email']");
	let mut email_box = form.select(email_box_sel);
	assert_eq!(1, email_box.clone().count(), "form needs an email box");
	let email_box = email_box.next().unwrap();

	assert_eq!(Some("email"), email_box.attr("name"));
	assert_eq!(Some("email"), email_box.attr("type"));
	assert_eq!(Some("Jaime Bloggs"), email_box.attr("value"));
	assert_eq!(Some("true"), email_box.attr("aria-invalid"));
	assert_eq!(Some("email-error"), email_box.attr("aria-errormessage"));

	let err_sel = css!("small[class='error-text']");
	let mut error_text = form.select(err_sel);
	assert_eq!(1, error_text.clone().count(), "form should show an error");
	let error_text = error_text.next().unwrap();
	assert!(
		error_text.inner_html().contains("Invalid email"),
		"helpful message not so helpful (got {})",
		error_text.inner_html()
	);
}

/*
#[actix_rt::test]
async fn post_with_valid_looking_email_asks_for_password() {
	let srv = util::setup(util::default).await;

	let ctx = AuthContext::new(
		srv.cfg.clone(),
		Uuid::now_v7(),
		"https://example.com/oidc/callback",
		"",
	);

	let res = srv
		.post("/authenticate/submit_email")
		.insert_header(("accept", "text/html"))
		.send_form(&[
			("ctx", ctx.to_string()),
			("email", "jaime@example.com".to_string()),
		])
		.await
		.unwrap();

	assert_eq!(302, res.status().as_u16());
	dbg!(res.headers().get("location"));
	let redirect_url = Url::parse(res.headers().get("location").unwrap().to_str().unwrap()).unwrap();

	let mut res = srv
		.get(srv.base_url().make_relative(&redirect_url).unwrap().as_str())
		.insert_header(("accept", "text/html"))
		.send()
		.await
		.unwrap();

	assert_eq!(200, res.status().as_u16());
	assert_eq!("text/html", res.content_type());

	let doc = util::doc(&mut res).await;

	let form_sel = css!("form");
	let mut forms = doc.select(form_sel);
	assert_eq!(1, forms.clone().count(), "page needs a password form");
	let form = forms.next().unwrap();

	let ctx_sel = css!("input[name='ctx']");
	let mut ctxs = form.select(ctx_sel);
	assert_eq!(
		1,
		ctxs.clone().count(),
		"form doesn't re-submit auth context"
	);
	let ctx = ctxs.next().unwrap();

	assert_eq!(Some("ctx"), ctx.attr("name"));
	assert_eq!(Some("hidden"), ctx.attr("type"));
	let ctx = ctx.attr("value").expect("ctx input has no value?!");

	let ctx = AuthContext::from_str(ctx, &srv.cfg).expect("cannot decrypt ctx");
	assert_eq!(Some(srv.cfg.dummy_pwhash()), ctx.pwhash().map(|p| p.as_str()));
	assert_eq!(Some(AuthContext::UNKNOWN_USER), ctx.uid().copied());

	let pw_box_sel = css!("input[name='password']");
	let mut pw_box = form.select(pw_box_sel);
	assert_eq!(1, pw_box.clone().count(), "form needs a password box");
	let pw_box = pw_box.next().unwrap();

	assert_eq!(Some("password"), pw_box.attr("name"));
	assert_eq!(Some("password"), pw_box.attr("type"));
	assert_eq!(None, pw_box.attr("value"));
	assert_eq!(Some("false"), pw_box.attr("aria-invalid"));
	assert_eq!(Some(""), pw_box.attr("aria-errormessage"));
}
*/

#[actix_rt::test]
async fn post_with_password_to_unknown_user_fails() {
	let srv = util::setup(util::default).await;

	let ctx = AuthContext::new(srv.cfg.clone(), Uuid::now_v7(), "", "")
		.with_principal(AuthContext::UNKNOWN_USER)
		.with_pwhash(srv.cfg.dummy_pwhash());

	let res = srv
		.post("/authenticate/submit_password")
		.insert_header(("accept", "text/html"))
		.send_form(&[
			("ctx", ctx.to_string()),
			("password", "hunter2".to_string()),
		])
		.await
		.unwrap();

	assert_eq!(302, res.status().as_u16());
	let redirect_url =
		Url::parse(res.headers().get("location").unwrap().to_str().unwrap()).unwrap();

	let mut res = srv
		.get(
			srv.base_url()
				.make_relative(&redirect_url)
				.unwrap()
				.as_str(),
		)
		.insert_header(("accept", "text/html"))
		.send()
		.await
		.unwrap();

	assert_eq!(res.content_type(), "text/html");

	let doc = util::doc(&mut res).await;

	let form_sel = css!("form");
	let mut forms = doc.select(form_sel);
	assert_eq!(1, forms.clone().count(), "page needs a password form");
	let form = forms.next().unwrap();

	let ctx_sel = css!("input[name='ctx']");
	let mut ctxs = form.select(ctx_sel);
	assert_eq!(
		1,
		ctxs.clone().count(),
		"form doesn't re-submit auth context"
	);
	let ctx = ctxs.next().unwrap();

	assert_eq!(Some("ctx"), ctx.attr("name"));
	assert_eq!(Some("hidden"), ctx.attr("type"));
	let ctx = ctx.attr("value").expect("ctx input has no value?!");

	assert!(
		AuthContext::from_str(ctx, &srv.cfg).is_ok(),
		"can't decrypt ctx"
	);

	let pw_box_sel = css!("input[name='password']");
	let mut pw_box = form.select(pw_box_sel);
	assert_eq!(1, pw_box.clone().count(), "form needs a password box");
	let pw_box = pw_box.next().unwrap();

	assert_eq!(Some("password"), pw_box.attr("name"));
	assert_eq!(Some("password"), pw_box.attr("type"));
	assert_eq!(None, pw_box.attr("value"));
	assert_eq!(Some("true"), pw_box.attr("aria-invalid"));
	assert_eq!(Some("password-error"), pw_box.attr("aria-errormessage"));

	let err_sel = css!("small[class='error-text']");
	let mut error_text = form.select(err_sel);
	assert_eq!(1, error_text.clone().count(), "form should show an error");
	let error_text = error_text.next().unwrap();
	assert!(
		error_text
			.inner_html()
			.contains("Incorrect password or unknown email address"),
		"helpful message not so helpful (got {})",
		error_text.inner_html()
	);
}

#[actix_rt::test]
async fn post_with_incorrect_password_for_known_user_fails() {
	let srv = util::setup(util::default).await;

	let ctx = AuthContext::new(srv.cfg.clone(), Uuid::now_v7(), "", "")
		.with_principal(Uuid::now_v7())
		.with_pwhash(srv.cfg.dummy_pwhash());

	let res = srv
		.post("/authenticate/submit_password")
		.insert_header(("accept", "text/html"))
		.send_form(&[
			("ctx", ctx.to_string()),
			("password", "hunter2".to_string()),
		])
		.await
		.unwrap();

	assert_eq!(302, res.status().as_u16());
	let redirect_url =
		Url::parse(res.headers().get("location").unwrap().to_str().unwrap()).unwrap();

	let mut res = srv
		.get(
			srv.base_url()
				.make_relative(&redirect_url)
				.unwrap()
				.as_str(),
		)
		.insert_header(("accept", "text/html"))
		.send()
		.await
		.unwrap();

	assert_eq!(200, res.status().as_u16());
	assert_eq!("text/html", res.content_type());

	let doc = util::doc(&mut res).await;

	let form_sel = css!("form");
	let mut forms = doc.select(form_sel);
	assert_eq!(1, forms.clone().count(), "page needs a password form");
	let form = forms.next().unwrap();

	let ctx_sel = css!("input[name='ctx']");
	let mut ctxs = form.select(ctx_sel);
	assert_eq!(
		1,
		ctxs.clone().count(),
		"form doesn't re-submit auth context"
	);
	let ctx = ctxs.next().unwrap();

	assert_eq!(Some("ctx"), ctx.attr("name"));
	assert_eq!(Some("hidden"), ctx.attr("type"));
	let ctx = ctx.attr("value").expect("ctx input has no value?!");

	assert!(
		AuthContext::from_str(ctx, &srv.cfg).is_ok(),
		"can't decrypt ctx"
	);

	let pw_box_sel = css!("input[name='password']");
	let mut pw_box = form.select(pw_box_sel);
	assert_eq!(1, pw_box.clone().count(), "form needs a password box");
	let pw_box = pw_box.next().unwrap();

	assert_eq!(Some("password"), pw_box.attr("name"));
	assert_eq!(Some("password"), pw_box.attr("type"));
	assert_eq!(None, pw_box.attr("value"));
	assert_eq!(Some("true"), pw_box.attr("aria-invalid"));
	assert_eq!(Some("password-error"), pw_box.attr("aria-errormessage"));

	let err_sel = css!("small[class='error-text']");
	let mut error_text = form.select(err_sel);
	assert_eq!(1, error_text.clone().count(), "form should show an error");
	let error_text = error_text.next().unwrap();
	assert!(
		error_text
			.inner_html()
			.contains("Incorrect password or unknown email address"),
		"helpful message not so helpful (got {})",
		error_text.inner_html()
	);
}

#[actix_rt::test]
async fn post_with_correct_password_for_known_user() {
	let srv = util::setup(util::default).await;

	let oidc_client = srv
		.db
		.oidc_client()
		.await
		.expect("oidc_client")
		.new()
		.with_name("Oh, I Dee Cee")
		.with_redirect_uris(["https://example.com/cb"])
		.with_jwks_uri("https://example.com/jwks.json")
		.save()
		.await
		.expect("OidcClient");

	let ctx = AuthContext::new(
		srv.cfg.clone(),
		oidc_client.id(),
		"https://example.com/all_good",
		"bobble",
	)
	.with_principal(Uuid::now_v7())
	.with_pwhash(bcrypt::hash("hunter2", 5).unwrap());

	let res = srv
		.post("/authenticate/submit_password")
		.insert_header(("accept", "text/html"))
		.send_form(&[
			("ctx", ctx.to_string()),
			("password", "hunter2".to_string()),
		])
		.await
		.unwrap();

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
	assert_eq!(
		"example.com",
		redirect_url.host_str().expect("no host in redirect URL")
	);
	assert_eq!("/all_good", redirect_url.path());
	assert!(
		redirect_url.query().is_some(),
		"no query parameters on redirect URL"
	);

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
		.find(&Uuid::from_base64(&auth_code).expect("valid UUID"))
		.await
		.expect("token was not saved in DB");

	// Make sure the DB token got everything
	assert_eq!("bobble", token.code_challenge());
	assert_eq!("https://example.com/all_good", token.redirect_uri());
}

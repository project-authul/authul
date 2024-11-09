//! OIDC initial entrypoint
use actix_web::{
	web::{self, ServiceConfig},
	HttpRequest, HttpResponse,
};
use std::collections::HashMap;
use url::Url;
use uuid::Uuid;

use super::{AuthContext, Error};
use crate::db;
use authul_oauth2::error_code::AuthorizeEndpoint as ErrCode;
use authul_util::Base64Uuid;

pub(super) fn routes(cfg: &mut ServiceConfig) {
	cfg.service(
		web::resource("/oidc/authorize")
			.route(web::get().to(get_authorize))
			.route(web::post().to(post_authorize))
			.route(web::to(|| HttpResponse::MethodNotAllowed())),
	)
	.route("/oidc/cookie_check", web::to(cookie_check));
}

pub(super) async fn get_authorize(
	cfg: web::Data<super::Config>,
	req: HttpRequest,
	params: web::Query<HashMap<String, String>>,
) -> Result<HttpResponse, Error> {
	do_authorize(cfg, req, params.into_inner()).await
}

pub(super) async fn post_authorize(
	cfg: web::Data<super::Config>,
	req: HttpRequest,
	params: web::Form<HashMap<String, String>>,
) -> Result<HttpResponse, Error> {
	do_authorize(cfg, req, params.into_inner()).await
}

async fn do_authorize(
	cfg: web::Data<super::Config>,
	req: HttpRequest,
	params: HashMap<String, String>,
) -> Result<HttpResponse, Error> {
	if req.cookie("csrf_token").is_none() {
		let mut target = cfg
			.base_url()
			.join("oidc/cookie_check")
			.expect("failed to construct URL");
		if req.query_string() != "" {
			target.set_query(Some(req.query_string()));
		}

		return Ok(HttpResponse::TemporaryRedirect()
			.insert_header(("location", target.as_str()))
			.finish());
	}

	// Start off by ensuring that the "unforgivable curses" (request params that, if invalid,
	// result in an error document rather than an error redirect) are in place
	let Some(client_id) = params.get("client_id") else {
		return Err(Error::oidc_authorize(
			"missing client_id",
			ErrCode::InvalidRequest,
		));
	};

	let Some(redirect_uri) = params.get("redirect_uri") else {
		return Err(Error::oidc_authorize(
			"missing redirect_uri",
			ErrCode::InvalidRequest,
		));
	};

	let client = match cfg
		.db()
		.oidc_client()
		.await?
		.find(&Uuid::from_base64(&client_id).map_err(|e| {
			Error::oidc_authorize(format!("invalid client_id: {e}"), ErrCode::InvalidRequest)
		})?)
		.await
	{
		Ok(c) => c,
		Err(db::Error::NotFound(..)) => {
			return Err(Error::oidc_authorize(
				format!("unknown client_id {client_id}"),
				ErrCode::InvalidRequest,
			));
		}
		Err(e) => return Err(e.into()),
	};
	if !client.has_redirect_uri(&redirect_uri) {
		return Err(Error::oidc_authorize(
			format!("invalid redirect_uri {redirect_uri}"),
			ErrCode::InvalidRequest,
		));
	}
	let Ok(redirect_uri) = Url::parse(&redirect_uri) else {
		return Err(Error::oidc_authorize(
			format!("unparseable redirect_uri {redirect_uri:?}"),
			ErrCode::InvalidRequest,
		));
	};

	// PKCE params can now be verified, because we've got a trusted redirect_uri to use for errors
	if let Some(code_challenge_method) = params.get("code_challenge_method") {
		if code_challenge_method != "S256" {
			return Err(Error::oidc_authorize_redirect(
				redirect_uri,
				format!("unsupported code_challenge_method {code_challenge_method}"),
				ErrCode::InvalidRequest,
			));
		}
	} else {
		tracing::debug!("/authorize request rejected for missing code_challenge_method");
		return Err(Error::oidc_authorize_redirect(
			redirect_uri,
			"missing code_challenge_method",
			ErrCode::InvalidRequest,
		));
	}

	let Some(code_challenge) = params.get("code_challenge") else {
		return Err(Error::oidc_authorize_redirect(
			redirect_uri,
			"missing code_challenge",
			ErrCode::InvalidRequest,
		));
	};

	if let Some(response_type) = params.get("response_type") {
		if response_type != "code" {
			return Err(Error::oidc_authorize_redirect(
				redirect_uri,
				format!("unsupported response_type {response_type}"),
				ErrCode::UnsupportedResponseType,
			));
		}
	} else {
		return Err(Error::oidc_authorize_redirect(
			redirect_uri,
			"missing response_type",
			ErrCode::InvalidRequest,
		));
	};

	if let Some(scope) = params.get("scope") {
		if !scope.split(' ').any(|s| s == "openid") {
			return Err(Error::oidc_authorize_redirect(
				redirect_uri,
				format!("invalid scope {scope}"),
				ErrCode::InvalidScope,
			));
		}
	} else {
		return Err(Error::oidc_authorize_redirect(
			redirect_uri,
			"missing scope",
			ErrCode::InvalidRequest,
		));
	};

	if let Some(response_mode) = params.get("response_mode") {
		if response_mode != "query" {
			return Err(Error::oidc_authorize_redirect(
				redirect_uri,
				format!("unsupported response_mode {response_mode}"),
				ErrCode::InvalidRequest,
			));
		}
	}

	// Reject all the otherwise valid params we don't (yet) support
	// This seems more polite than silently accepting them and then not doing what the RP wanted
	for param in [
		"display",
		"prompt",
		"max_age",
		"ui_locales",
		"token_hint",
		"login_hint",
		"acr",
	] {
		if params.contains_key(param) {
			tracing::debug!("/authorize request rejected for invalid {param}");
			return Err(Error::oidc_authorize_redirect(
				redirect_uri,
				format!("unsupported param {param}"),
				ErrCode::InvalidRequest,
			));
		}
	}

	let cfg = cfg.into_inner();
	let mut ctx = AuthContext::new(cfg.clone(), client.id(), redirect_uri, code_challenge);

	if let Some(nonce) = params.get("nonce") {
		ctx.set_nonce(nonce.clone());
	}
	if let Some(state) = params.get("state") {
		ctx.set_state(state.clone());
	}

	let mut redirect_url = cfg.base_url().join("authenticate")?;
	redirect_url
		.query_pairs_mut()
		.append_pair("ctx", &ctx.to_string())
		.append_pair("target", client.name());

	Ok(HttpResponse::SeeOther()
		.insert_header(("location", redirect_url.as_str()))
		.finish())
}

pub async fn cookie_check(
	cfg: web::Data<super::Config>,
	req: HttpRequest,
) -> Result<HttpResponse, Error> {
	if req.cookie("csrf_token").is_some() {
		let mut target = cfg
			.base_url()
			.join("oidc/authorize")
			.expect("failed to construct URL");
		if req.query_string() != "" {
			target.set_query(Some(req.query_string()));
		}

		Ok(HttpResponse::TemporaryRedirect()
			.insert_header(("location", target.as_str()))
			.finish())
	} else {
		let no_cookies = r#"
			<!DOCTYPE html>
			<html style="display: flex; font-family: sans-serif; justify-content: center">
			<head>
				<meta charset="utf-8">
				<meta name="viewport" content="width=device-width, initial-scale=1"/>
				<title>Cookie Support Disabled</title>
			</head>
			<body style="width: 80%; max-width: 60rem">
				<h1>It looks like you've disabled cookies</h1>
				<p>
				<em>Generally</em>, that's a great idea.
				Authul's lead developer does it too.
				We are all in favour of minimising the practice of creepy tracking on the web.
				</p>
				<p>
				However, in this case, we need cookies to be able to protect against security vulnerabilities.
				</p>
				<p>
				Please configure your browser to accept cookies for this domain, and then hit the "back" button to try again.
				</p>
				<h2>Our Cookies</h2>
				<p>
				There is only one cookie we set: <tt>csrf_token</tt>.
				This token contains a small, random string that we use to protect against <a href="https://owasp.org/www-community/attacks/csrf">Cross-Site Request Forgery</a> attacks during authentication.
				</p>
				<p>
				The cookie's value is not logged anywhere, is not accessible from outside the authentication process, and is not otherwise used for any purpose other than to protect the security of your authentication process.
				</p>
			</body>
			</html>
		"#;

		Ok(HttpResponse::Ok()
			.content_type("text/html")
			.body(no_cookies))
	}
}

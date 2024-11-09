use actix_web::{
	web::{self, ServiceConfig},
	HttpRequest, HttpResponse,
};
use std::collections::HashMap;

use super::{successful_authentication, AuthContext, Config, Error};
use authul_oauth2::error_code::Callback;

pub(super) fn routes(cfg: &mut ServiceConfig) {
	cfg.route(
		"/authenticate/oauth_callback",
		web::get().to(get_oauth_callback),
	)
	.route(
		"/authenticate/oauth_callback",
		web::to(|| HttpResponse::MethodNotAllowed()),
	);
}

pub(super) async fn get_oauth_callback(
	cfg: web::Data<Config>,
	params: web::Query<HashMap<String, String>>,
	req: HttpRequest,
) -> Result<HttpResponse, Error> {
	if params.contains_key("error") {
		tracing::warn!("OAuth callback got error from provider: {params:?}");
		return Err(Error::oauth_callback(
			"got error from provider",
			Callback::InvalidRequest,
		));
	}

	let Some(code) = params.get("code") else {
		return Err(Error::oauth_callback(
			"it lacks a code",
			Callback::InvalidRequest,
		));
	};

	let (ctx, principal, attrs) = match params.get("state") {
		None => Err(Error::oauth_callback(
			"it lacks state",
			Callback::InvalidRequest,
		)),
		Some(s) => Ok(authul_oauth2::process_oauth_callback(
			s,
			code,
			&req,
			cfg.oauth_provider_map(),
			cfg.db(),
		)
		.await
		.map_err(|e| match e {
			authul_oauth2::Error::Base64Uuid(_, _) => {
				Error::oauth_callback("invalid state UUID", Callback::InvalidRequest)
			}
			e => e.into(),
		})?),
	}?;

	let ctx = AuthContext::from_str(&ctx, &cfg)?.with_principal(*principal.id());

	Ok(HttpResponse::Found()
		.insert_header((
			"location",
			successful_authentication(&cfg, &ctx, attrs).await?.as_str(),
		))
		.finish())
}

use actix_web::{
	web::{self, ServiceConfig},
	HttpResponse,
};
use serde::Serialize;
use serde_json::json;

use super::{middleware::Cors, Error};

pub(super) fn routes(cfg: &mut ServiceConfig) {
	cfg.service(
		web::resource("/.well-known/openid-configuration")
			.wrap(Cors::GET)
			.route(web::get().to(get_openid_configuration))
			.route(web::to(|| HttpResponse::MethodNotAllowed())),
	)
	.service(
		web::resource("/oidc/jwks.json")
			.wrap(Cors::GET)
			.route(web::get().to(get_jwks_json))
			.route(web::to(|| HttpResponse::MethodNotAllowed())),
	);
}

#[derive(Clone, Debug, Serialize)]
struct ProviderMetadata {
	issuer: String,
	authorization_endpoint: String,
	token_endpoint: String,
	jwks_uri: String,
	scopes_supported: Vec<&'static str>,
	response_types_supported: Vec<&'static str>,
	response_modes_supported: Vec<&'static str>,
	grant_types_supported: Vec<&'static str>,
	subject_types_supported: Vec<&'static str>,
	id_token_signing_alg_values_supported: Vec<&'static str>,
	token_endpoint_auth_methods_supported: Vec<&'static str>,
	token_endpoint_auth_signing_alg_values_supported: Vec<&'static str>,
	request_uri_parameter_supported: bool,
}

pub(super) async fn get_openid_configuration(
	cfg: web::Data<super::Config>,
) -> Result<HttpResponse, Error> {
	Ok(HttpResponse::Ok().json(ProviderMetadata {
		issuer: cfg.base_url().to_string(),
		authorization_endpoint: cfg.base_url().join("oidc/authorize")?.to_string(),
		token_endpoint: cfg.base_url().join("oidc/token")?.to_string(),
		jwks_uri: cfg.base_url().join("oidc/jwks.json")?.to_string(),
		scopes_supported: vec!["openid"],
		response_types_supported: vec!["code"],
		response_modes_supported: vec!["query"],
		grant_types_supported: vec!["authorization_code"],
		subject_types_supported: vec!["public"],
		id_token_signing_alg_values_supported: vec!["EdDSA"],
		token_endpoint_auth_methods_supported: vec!["private_key_jwt"],
		token_endpoint_auth_signing_alg_values_supported: vec!["EdDSA"],
		request_uri_parameter_supported: false,
	}))
}

pub(super) async fn get_jwks_json(cfg: web::Data<super::Config>) -> Result<HttpResponse, Error> {
	let keys = cfg.oidc_jwks().await?;
	tracing::debug!("Returning {} keys", keys.len());

	Ok(HttpResponse::Ok().json(json!({ "keys": keys })))
}

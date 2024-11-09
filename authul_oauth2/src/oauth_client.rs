use actix_web::HttpRequest;
use oauth2::{basic::BasicClient, CsrfToken, RedirectUrl, Scope};
use reqwest_middleware::ClientWithMiddleware;
use sha2::{Digest, Sha256};
use std::{borrow::Cow, fmt::Debug, marker::PhantomData, time::Duration};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use super::{provider, Error, OAuthProvider, OAuthProviderMap};
use authul_db::{
	self as db,
	model::{OidcClient, Principal},
	types::{IdentityAttributes, OAuthProviderKind},
};
use authul_util::Base64Uuid;

const CALLBACK_STATE_VALIDITY_PERIOD: Duration = Duration::from_secs(4 * 3600); // Four hours

pub trait OAuthClient: Debug {
	fn new(
		oauth_client: BasicClient,
		http_client: reqwest_middleware::ClientWithMiddleware,
		base_url: Url,
	) -> Self;

	fn basic_client(&self) -> &BasicClient;
	fn http_client(&self) -> &ClientWithMiddleware;
	fn base_url(&self) -> &Url;

	fn scope(&self) -> &'static str;
	fn kind(&self) -> OAuthProviderKind;

	#[allow(async_fn_in_trait)]
	async fn identity_from_auth_code(
		&self,
		code: &str,
		db: authul_db::Pool,
		token_key: Option<Url>,
	) -> Result<(Principal, IdentityAttributes), Error>;

	#[allow(async_fn_in_trait)]
	#[tracing::instrument(ret, level = "debug", skip(ctx, db))]
	async fn oauth_login_url(
		&self,
		ctx: &str,
		oidc_client: OidcClient,
		req: &HttpRequest,
		db: db::Pool,
	) -> Result<Url, Error> {
		let csrf_cookie = req
			.cookie("csrf_token")
			.ok_or_else(|| Error::no_csrf_protection())?;
		let csrf_token = csrf_cookie.value();
		if csrf_token.len() < 20 {
			// Juuuuuuust in case...
			return Err(Error::no_csrf_protection());
		}

		let state = db
			.oauth_callback_state()
			.await?
			.new()
			.with_oidc_client(oidc_client)
			.with_provider_kind(self.kind())
			.with_context(ctx)
			.with_csrf_token(Sha256::digest(csrf_token).to_vec())
			.with_expired_from(OffsetDateTime::now_utc() + CALLBACK_STATE_VALIDITY_PERIOD)
			.save()
			.await?;

		Ok(self
			.basic_client()
			.authorize_url(|| CsrfToken::new(state.id().to_base64()))
			.add_scope(Scope::new(self.scope().to_string()))
			.set_redirect_uri(self.redirect_url()?)
			.url()
			.0)
	}

	#[allow(async_fn_in_trait)]
	async fn make_oauth_code_request(
		&self,
		req: oauth2::HttpRequest,
	) -> Result<oauth2::HttpResponse, reqwest_middleware::Error> {
		let mut req_builder = self
			.http_client()
			.request(
				req.method
					.as_ref()
					.parse()
					.expect("somehow got an invalid HTTP method"),
				req.url.as_str(),
			)
			.body(req.body);
		for (k, v) in &req.headers {
			req_builder = req_builder.header(k.as_str(), v.as_bytes());
		}
		let res = self.http_client().execute(req_builder.build()?).await?;

		// I absolutely adore incompatible sub-dependencies...
		// This can go once oauth2 moves to http@1 (I hope...)
		let status_code = oauth2::http::StatusCode::from_u16(res.status().as_u16().into())
			.expect("somehow got an invalid status code");
		let mut headers = oauth2::http::HeaderMap::new();
		for (k, v) in res.headers() {
			headers.append::<oauth2::http::HeaderName>(
				k.as_str()
					.parse()
					.expect("somehow got an invalid HTTP header name"),
				v.to_str()
					.expect("HTTP headers values are strings, ffs")
					.parse()
					.expect("still strings!"),
			);
		}
		let body = res.bytes().await?.to_vec();

		Ok(oauth2::HttpResponse {
			status_code,
			headers,
			body: body,
		})
	}

	fn redirect_url(&self) -> Result<Cow<RedirectUrl>, Error> {
		Ok(Cow::Owned(RedirectUrl::from_url(
			self.base_url().join("authenticate/oauth_callback")?,
		)))
	}
}

pub async fn process_oauth_callback(
	state: impl AsRef<str>,
	code: impl AsRef<str>,
	req: &HttpRequest,
	provider_map: &OAuthProviderMap,
	db: db::Pool,
) -> Result<(String, Principal, IdentityAttributes), Error> {
	let callback_state = db
		.oauth_callback_state()
		.await?
		.find(&Uuid::from_base64(state.as_ref())?)
		.await?;
	let token_key_url = callback_state
		.oidc_client()
		.token_forward_jwk_uri()
		.as_ref()
		.map_or(Ok(None), |s| Ok::<_, Error>(Some(Url::parse(s)?)))?;

	let csrf_cookie = req
		.cookie("csrf_token")
		.ok_or_else(|| Error::no_csrf_protection())?;
	let csrf_token = csrf_cookie.value();

	let submitted_csrf_token_hash = Sha256::digest(csrf_token).to_vec();

	if &submitted_csrf_token_hash != callback_state.csrf_token() {
		return Err(Error::invalid_csrf_token());
	}

	if callback_state.expired_from() <= &OffsetDateTime::now_utc() {
		return Err(Error::invalid_callback_state());
	}

	let (principal, identity_attributes) = match callback_state.provider_kind() {
		// fkkn async... this could all be done with a .map() if we had async closures
		OAuthProviderKind::GitHub => match provider_map.get::<provider::GitHub>() {
			None => None,
			Some(c) => Some(
				c.identity_from_auth_code(code.as_ref(), db, token_key_url)
					.await?,
			),
		},
		OAuthProviderKind::GitLab => match provider_map.get::<provider::GitLab>() {
			None => None,
			Some(c) => Some(
				c.identity_from_auth_code(code.as_ref(), db, token_key_url)
					.await?,
			),
		},
		OAuthProviderKind::Google => match provider_map.get::<provider::Google>() {
			None => None,
			Some(c) => Some(
				c.identity_from_auth_code(code.as_ref(), db, token_key_url)
					.await?,
			),
		},
	}
	.ok_or_else(|| Error::unsupported_oauth_provider(callback_state.provider_kind().clone()))?;

	return Ok((
		callback_state.context().clone(),
		principal,
		identity_attributes,
	));
}

#[derive(Clone, Debug)]
pub struct OAuthClientBuilder<P> {
	oauth_client: BasicClient,
	base_url: Option<Url>,
	http_client: Option<ClientWithMiddleware>,
	__provider: PhantomData<P>,
}

// The http_client, which is what is not unwind-safe, only crosses the boundary when None, and
// we never use it in the builder anyway so it couldn't panic anyway
impl<P: OAuthProvider> std::panic::UnwindSafe for OAuthClientBuilder<P> {}

impl<P: OAuthProvider> std::str::FromStr for OAuthClientBuilder<P> {
	type Err = &'static str;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let bits = s.splitn(2, ':').collect::<Vec<_>>();
		if let Some(id) = bits.get(0) {
			if id == &"" {
				Err("missing ID")
			} else if let Some(secret) = bits.get(1) {
				if secret == &"" {
					Err("missing secret")
				} else {
					use oauth2::{AuthUrl, ClientId, ClientSecret, TokenUrl};

					Ok(Self {
						oauth_client: BasicClient::new(
							ClientId::new(id.to_string()),
							Some(ClientSecret::new(secret.to_string())),
							AuthUrl::new(P::AUTHORIZE_URL.to_string())
								.expect("invalid AUTHORIZE_URL"),
							Some(
								TokenUrl::new(P::TOKEN_URL.to_string()).expect("invalid TOKEN_URL"),
							),
						),
						base_url: None,
						http_client: None,
						__provider: PhantomData,
					})
				}
			} else {
				Err("missing secret")
			}
		} else {
			// Apparently this can't happen, but let's not make assumptions
			Err("missing id")
		}
	}
}

impl<P: OAuthProvider> OAuthClientBuilder<P> {
	pub fn base_url(mut self, url: impl Into<Url>) -> Self {
		self.base_url = Some(url.into());
		self
	}

	pub fn http_client(mut self, c: impl Into<ClientWithMiddleware>) -> Self {
		self.http_client = Some(c.into());
		self
	}

	pub fn build(self) -> Result<P::Client, Error> {
		Ok(P::Client::new(
			self.oauth_client,
			self.http_client
				.ok_or_else(|| Error::incomplete_build("OAuthClient", "http_client"))?,
			self.base_url
				.ok_or_else(|| Error::incomplete_build("OAuthClient", "base_url"))?,
		))
	}
}

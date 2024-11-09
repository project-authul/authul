/// The Major Page(or)
use leptos::{component, use_context, view, IntoSignal, IntoView, Params, SignalGet as _};
use leptos_router::{use_query, Outlet, Params, Route, SsrMode};

cfg_if::cfg_if! {
	if #[cfg(feature = "ssr")] {
		use actix_web::web::ServiceConfig;
		use std::sync::Arc;
		use url::Url;

		use authul_db::types::IdentityAttributes;
		use authul_crypto::Jwt;
		use authul_util::Base64Uuid;
		use super::{AuthContext, Config, Error};
	}
}

use super::RenderConfig;

mod password_auth;
use password_auth::{AuthenticateWithEmail, PasswordAuthRoutes};
mod github_auth;
use github_auth::AuthenticateWithGitHub;
mod gitlab_auth;
use gitlab_auth::AuthenticateWithGitLab;
mod google_auth;
use google_auth::AuthenticateWithGoogle;

#[cfg(feature = "ssr")]
mod oauth_callback;

#[cfg(feature = "ssr")]
pub(super) fn routes(cfg: &mut ServiceConfig) {
	oauth_callback::routes(cfg);
}

#[component(transparent)]
pub(super) fn AuthenticateRoutes() -> impl IntoView {
	view! {
		<Route path="authenticate" view=move || view! { <Outlet/> }>
			<PasswordAuthRoutes />
			<Route path="" view=Authenticate ssr=SsrMode::PartiallyBlocked />
		</Route>
	}
}

macro_rules! param_signal {
	($name:ident, $params:ident) => {
		let $name =
			(move || $params.get().map(|params| params.$name).unwrap_or(None)).into_signal();
	};
}

#[component]
pub(super) fn Authenticate() -> impl IntoView {
	#[derive(Clone, Debug, Default, Params, PartialEq)]
	struct QueryParams {
		ctx: Option<String>,
		err: Option<String>,
		email: Option<String>,
		target: Option<String>,
	}

	let params = use_query::<QueryParams>();

	param_signal!(ctx, params);
	param_signal!(err, params);
	param_signal!(email, params);
	param_signal!(target, params);

	view! {
		<section class="container login-box">
			{move || match (ctx.get().unwrap_or_default().as_str(), err.get().unwrap_or_default().as_str()) {
				("", _) => view! { <NoContext /> }.into_view(),
				(_, "no_context") => view! { <NoContext /> }.into_view(),
				(_, "invalid_context") => view! { <BadContext /> }.into_view(),
				_ => view! {
					{move ||
						if let Some(target) = target.get() {
							view! {
								<h1>
									"Sign in to " {target}
								</h1>
							}.into_view()
						} else {
							view! {}.into_view()
						}
					}
					<AuthenticateWithEmail ctx err email />
					<AuthSeparator />
					<AuthenticateWithGitHub ctx />
					<AuthenticateWithGitLab ctx />
					<AuthenticateWithGoogle ctx />
				}.into_view(),
			}}
		</section>
	}
}

#[component]
fn AuthSeparator() -> impl IntoView {
	let render_config = use_context::<RenderConfig>().expect("no RenderConfig available");

	if render_config.password_auth && render_config.oauth_buttons() {
		view! {
			<div class="auth-separator"><span>OR</span></div>
		}
		.into_view()
	} else {
		view! {}.into_view()
	}
}

#[cfg(feature = "ssr")]
async fn successful_authentication(
	cfg: &Arc<Config>,
	ctx: &AuthContext,
	attrs: IdentityAttributes,
) -> Result<Url, Error> {
	let Some(uid) = ctx.principal() else {
		return Err(Error::cant_happen(
			"successful_authentication called without completed AuthContext",
		));
	};

	let k = cfg.current_oidc_signing_jwk().await?;
	let oidc_client = cfg
		.db()
		.oidc_client()
		.await?
		.find(ctx.oidc_client_id())
		.await?;
	let mut jwt = Jwt::new()
		.with_iss(cfg.base_url().to_string())
		.with_sub(uid.to_string())
		.with_aud(oidc_client.id().to_base64())
		.with_attrs(serde_json::value::to_value(attrs)?);
	if let Some(nonce) = ctx.nonce() {
		jwt.set_nonce(nonce);
	}

	let jwt = jwt.sign(&k)?;

	let token = cfg
		.db()
		.oidc_token()
		.await?
		.new()
		.with_token(jwt)
		.with_oidc_client(oidc_client)
		.with_redirect_uri(ctx.redirect_uri())
		.with_code_challenge(ctx.code_challenge())
		.save()
		.await?;

	let mut redirect_uri = Url::parse(ctx.redirect_uri())?;
	redirect_uri
		.query_pairs_mut()
		.append_pair("code", &token.id().to_base64());

	if let Some(state) = ctx.state() {
		redirect_uri.query_pairs_mut().append_pair("state", state);
	}
	Ok(redirect_uri)
}

#[component]
fn NoContext() -> impl IntoView {
	view! {
		<p>
			"Hello!"
		</p>
		<p>
			"This page is used to authenticate you to another website. "
			"If you have been redirected here by another website, please let them know that their site is broken, and needs to be fixed."
		</p>
	}
}

#[component]
fn BadContext() -> impl IntoView {
	view! {
		<p>
			"Hello!"
		</p>
		<p>
			"You have attempted to authenticate to a website, but that attempt failed because, in technical terms, \"the authentication context was invalid\". "
			"If you got here because you attempted to login to a website, please let the administrator of that site know what has gone wrong. "
		</p>
		<p>
			"On the other hand, if you have no idea why you got sent here, it's possible that someone on the Internet is doing something shady. "
			"Rest assured that nothing bad has actually happened, please continue your day."
		</p>
	}
}

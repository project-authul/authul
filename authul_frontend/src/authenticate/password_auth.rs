use leptos::{
	component, create_server_action, server, use_context, view, IntoAttribute, IntoSignal,
	IntoView, Params, ServerFnError, Signal, SignalGet as _,
};
use leptos_router::{use_query, ActionForm, Params, Route};

cfg_if::cfg_if! {
	if #[cfg(feature = "ssr")] {
		use actix_web::{rt::task::spawn_blocking, web::Data};
		use email_address::EmailAddress;
		use leptos_actix::{extract, redirect};
		use std::sync::Arc;
		use tap::prelude::*;
		use crate::db;
		use super::{
			successful_authentication, Config, AuthContext, Error,
		};
	}
}

use super::{BadContext, NoContext, RenderConfig};

#[component(transparent)]
pub(crate) fn PasswordAuthRoutes() -> impl IntoView {
	let render_config = use_context::<RenderConfig>().expect("no RenderConfig available");

	if render_config.password_auth {
		view! {
			<Route path="pw" view=AuthenticatePassword />
		}
		.into_view()
	} else {
		view! {}.into_view()
	}
}

#[component]
pub(crate) fn AuthenticateWithEmail(
	ctx: Signal<Option<String>>,
	err: Signal<Option<String>>,
	email: Signal<Option<String>>,
) -> impl IntoView {
	let render_config = use_context::<RenderConfig>().expect("no RenderConfig available");

	if !render_config.password_auth {
		return view! {}.into_view();
	}

	let submit_email = create_server_action::<SubmitEmail>();

	let error_desc = move || {
		err.get().as_ref().map_or(None, |s| match s.as_str() {
			"" => None,
			"invalid_email" => Some("Invalid email address"),
			"no_email" => Some("Please enter your email address"),
			e => {
				tracing::debug!("non-email err: {e}");
				None
			}
		})
	};
	let show_error = move || error_desc().is_some();

	view! {
		<ActionForm action=submit_email attributes=vec![("id", "email-form".into_attribute())]>
			<input type="hidden" name="ctx" value=ctx/>
			<label for="email-input">"Enter your email address to begin"</label>
			<input id="email-input" type="email" name="email"
				required autocomplete="email" placeholder="user@example.com"
				value=email
				aria-invalid={move || if show_error() { "true" } else { "false" }}
				aria-errormessage={move || if show_error() { "email-error" } else { "" }}
			/>
			{move || if show_error() {
				view! {
					<small id="email-error" class="error-text">{move || error_desc()}</small>
				}.into_view()
			} else {
				view! {}.into_view()
			}}
			<input type="submit" value="Next" />
		</ActionForm>
	}
	.into_view()
}

#[server(SubmitEmail, "/authenticate", "Url", "submit_email")]
async fn submit_email(email: Option<String>, ctx: Option<String>) -> Result<(), ServerFnError> {
	let cfg: Data<Config> = extract().await?;

	let Some(ctx) = ctx else {
		let mut redirect_url = cfg.base_url().join("authenticate")?;
		redirect_url
			.query_pairs_mut()
			.append_pair("err", "no_context");
		redirect(redirect_url.as_str());
		return Ok(());
	};

	let Some(email) = email else {
		let mut redirect_url = cfg.base_url().join("authenticate")?;
		redirect_url
			.query_pairs_mut()
			.append_pair("ctx", &ctx)
			.append_pair("err", "no_email");
		redirect(redirect_url.as_str());
		return Ok(());
	};

	match AuthContext::from_str(&ctx, &*cfg) {
		Ok(mut ctx) => {
			tracing::debug!("email submitted: {email}");
			if EmailAddress::is_valid(&email) {
				tracing::debug!("email is valid");
				match cfg.db().user().await?.find_by_email(email).await {
					Ok(user) => {
						tracing::debug!("Known user");
						ctx.set_principal(*user.id());
						ctx.set_pwhash(user.pwhash());
					}
					Err(db::Error::NotFound(..)) => {
						tracing::debug!("Unknown user");
						ctx.set_principal(AuthContext::UNKNOWN_USER);
						ctx.set_pwhash(cfg.dummy_pwhash());
					}
					Err(e) => {
						tracing::debug!("db error: {e}");
						return Err(e.into());
					}
				};
				tracing::debug!("successful email submission");
				let mut redirect_url = cfg.base_url().join("authenticate/pw")?;
				redirect_url
					.query_pairs_mut()
					.append_pair("ctx", &ctx.to_string());
				redirect(redirect_url.as_str());
			} else {
				tracing::debug!("invalid email");
				let mut redirect_url = cfg.base_url().join("authenticate")?;
				redirect_url
					.query_pairs_mut()
					.append_pair("ctx", &ctx.to_string())
					.append_pair("err", "invalid_email")
					.append_pair("email", &email);
				redirect(redirect_url.as_str());
			}
		}
		Err(e) => {
			tracing::debug!("invalid auth context: {e}");
			let mut redirect_url = cfg.base_url().join("authenticate")?;
			redirect_url
				.query_pairs_mut()
				.append_pair("ctx", &ctx)
				.append_pair("err", "invalid_context");
			redirect(redirect_url.as_str());
		}
	}

	Ok(())
}

#[component]
pub(crate) fn AuthenticatePassword() -> impl IntoView {
	#[derive(Clone, Debug, Default, Params, PartialEq)]
	struct QueryParams {
		ctx: Option<String>,
		err: Option<String>,
	}

	let params = use_query::<QueryParams>();

	let ctx = (move || params.get().map(|params| params.ctx).unwrap_or(None)).into_signal();
	let err = (move || params.get().map(|params| params.err).unwrap_or(None)).into_signal();

	let error_desc = move || {
		err.get().map_or(None, |s| match s.as_str() {
			"" => None,
			"wrong_password" => Some("Incorrect password or unknown email address"),
			e => {
				tracing::debug!("unhandled err: {e}");
				None
			}
		})
	};
	let show_error = move || error_desc().is_some();
	let submit_password = create_server_action::<SubmitPassword>();

	view! {
		<section class="container login-box">
			{move || match (ctx.get().as_ref().map(|s| s.as_str()), err.get().as_ref().map(|s| s.as_str())) {
				(None, _) | (Some(""), _) => view! { <NoContext /> }.into_view(),
				(_, Some("no_context")) => view! { <NoContext /> }.into_view(),
				(_, Some("invalid_context")) => view! { <BadContext /> }.into_view(),
				_ => view! {
					<ActionForm action=submit_password  attributes=vec![("id", "password-form".into_attribute())]>
						<input type="hidden" name="ctx" value=move || ctx.get() />
						<label for="password-input">"Enter your password"</label>
						<input id="password-input" type="password" name="password"
							autocomplete="current-password"
							required
							aria-invalid={move || if show_error() { "true" } else { "false" }}
							aria-errormessage={move || if show_error() { "password-error" } else { "" }}
						/>
						{move || if show_error() {
							view! {
								<small id="password-error" class="error-text">{move || error_desc()}</small>
							}.into_view()
						} else {
							view! {}.into_view()
						}}
						<input type="submit" value="Next" />
						<a href={move || format!("..?ctx={}", ctx.get().unwrap_or_default())}>Change email address</a>
					</ActionForm>
				}
			}}
		</section>
	}
}

#[server(SubmitPassword, "/authenticate", "Url", "submit_password")]
async fn submit_password(password: String, ctx: String) -> Result<(), ServerFnError> {
	let cfg: Data<Config> = extract().await?;

	Ok(process_submit_password(password, ctx, cfg.into_inner())
		.await
		.tap_err(|e| tracing::warn!("failed to process submitted password: {e}"))?)
}

#[cfg(feature = "ssr")]
async fn process_submit_password(
	password: String,
	ctx: String,
	cfg: Arc<Config>,
) -> Result<(), Error> {
	match AuthContext::from_str(&ctx, &cfg) {
		Ok(ctx) => {
			if let Some(pwhash) = ctx.pwhash() {
				let pw = password.clone();
				let pwhash = pwhash.clone();
				if spawn_blocking(move || bcrypt::verify(&pw, &pwhash)).await??
					&& ctx.principal().is_some()
					&& ctx.principal() != Some(&AuthContext::UNKNOWN_USER)
				{
					redirect(
						successful_authentication(&cfg, &ctx, Default::default())
							.await?
							.as_str(),
					);
				} else {
					let mut redirect_url = cfg.base_url().join("authenticate/pw")?;
					redirect_url
						.query_pairs_mut()
						.append_pair("ctx", &ctx.to_string())
						.append_pair("err", "wrong_password");
					redirect(redirect_url.as_str());
				}
			} else {
				tracing::debug!("password submitted without pwhash in ctx");
				let mut redirect_url = cfg.base_url().join("authenticate/pw")?;
				redirect_url
					.query_pairs_mut()
					.append_pair("ctx", &ctx.to_string())
					.append_pair("err", "invalid_context");
				redirect(redirect_url.as_str());
			}
		}
		Err(e) => {
			tracing::debug!("invalid auth context: {e}");
			let mut redirect_url = cfg.base_url().join("authenticate/pw")?;
			redirect_url
				.query_pairs_mut()
				.append_pair("ctx", &ctx)
				.append_pair("err", "invalid_context");
			redirect(redirect_url.as_str());
		}
	}

	Ok(())
}

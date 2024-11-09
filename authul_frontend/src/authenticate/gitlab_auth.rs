use leptos::{
	component, create_blocking_resource, server, use_context, view, IntoView, ServerFnError,
	Signal, SignalGet as _, Suspense,
};

cfg_if::cfg_if! {
	if #[cfg(feature = "ssr")] {
		use actix_web::{web, HttpRequest};
		use leptos_actix::extract;

		use authul_oauth2::{OAuthClient, provider};
		use super::{AuthContext, Config};
	}
}

use super::RenderConfig;

#[component]
pub(crate) fn AuthenticateWithGitLab(ctx: Signal<Option<String>>) -> impl IntoView {
	let render_config = use_context::<RenderConfig>().expect("no RenderConfig available");

	if render_config.gitlab_auth {
		let oauth_login_url = create_blocking_resource(
			move || ctx.get(),
			move |ctx| async move { oauth_login_url(ctx).await.unwrap_or(None) },
		);

		view! {
			<Suspense fallback=|| view! { <Button url=|| None /> }>
				<Button url=move || oauth_login_url.get().unwrap_or_default() />
			</Suspense>
		}
		.into_view()
	} else {
		view! {}.into_view()
	}
}

#[component]
fn Button<F>(url: F) -> impl IntoView
where
	F: Fn() -> Option<String> + 'static,
{
	view! {
		<a class="oauth-login" href=move || url()>
			<button>
				<span class="gitlab logo"></span>
				"Continue with GitLab"
			</button>
		</a>
	}
}

#[server(AuthUrl)]
async fn oauth_login_url(ctx: Option<String>) -> Result<Option<String>, ServerFnError> {
	let req: HttpRequest = extract().await?;
	let cfg: web::Data<Config> = extract().await?;

	let Some(ctx) = ctx else {
		tracing::debug!("No context");
		return Ok(None);
	};

	let Ok(ctx_obj) = AuthContext::from_str(&ctx, &*cfg) else {
		tracing::debug!("Busted context");
		return Ok(None);
	};

	let oidc_client = cfg
		.db()
		.oidc_client()
		.await?
		.find(ctx_obj.oidc_client_id())
		.await?;

	Ok(match cfg.oauth_provider_map().get::<provider::GitLab>() {
		None => None,
		Some(c) => Some(
			c.oauth_login_url(&ctx, oidc_client, &req, cfg.db())
				.await?
				.to_string(),
		),
	})
}

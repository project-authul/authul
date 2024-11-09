#[cfg(feature = "ssr")]
mod actix_app;
#[cfg(feature = "ssr")]
mod assets;
#[cfg(feature = "ssr")]
mod auth_context;
mod authenticate;
#[cfg(feature = "ssr")]
mod config;
mod error;
#[cfg(feature = "ssr")]
mod middleware;
#[cfg(feature = "ssr")]
mod oidc;
#[cfg(feature = "ssr")]
pub mod periodic_tasks;
mod render_config;

#[cfg(feature = "ssr")]
pub use actix_app::actix_app;
#[cfg_attr(authul_expose_privates, visibility::make(pub))]
#[cfg(feature = "ssr")]
#[cfg_attr(authul_expose_privates, visibility::make(pub))]
use auth_context::AuthContext;
use authenticate::AuthenticateRoutes;
#[cfg(feature = "ssr")]
use authul_db as db;
#[cfg(feature = "ssr")]
pub use config::{Config, ConfigBuilder};
pub use error::Error;
pub use render_config::RenderConfig;

#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub async fn hydrate() {
	use leptos::*;

	console_error_panic_hook::set_once();

	mount_to_body(root_component(
		frontend_render_config()
			.await
			.expect("Failed to retrieve render config"),
	));
}

#[leptos::server(FrontendRenderConfig)]
async fn frontend_render_config() -> Result<RenderConfig, leptos::ServerFnError> {
	let cfg: actix_web::web::Data<Config> = leptos_actix::extract().await?;
	let cfg = cfg.into_inner();

	Ok((&*cfg).into())
}

fn root_component(cfg: RenderConfig) -> impl Fn() -> leptos::View + Clone + 'static {
	use leptos::{provide_context, view, IntoView as _};
	use leptos_meta::{provide_meta_context, Stylesheet};
	use leptos_router::{Route, Router, Routes};

	let css_url = cfg.css_url();
	let css_url = css_url.to_string();

	move || {
		let css_url = css_url.clone();
		provide_meta_context();
		provide_context(cfg.clone());

		view! {
			<Router>
				<main>
					<Stylesheet href={css_url} />
					<Routes>
						<Route path="/" view=HomePage />
						<AuthenticateRoutes />
					</Routes>
				</main>
			</Router>
		}
		.into_view()
	}
}

#[leptos::component]
fn HomePage() -> impl leptos::IntoView {
	leptos::view! {
		<section class="container">
			<h1>Welcome to Authul</h1>
			<p>"This is an "<a href="https://authul.com">Authul</a>" application. "
			"If you have been redirected here from another site, while trying to login, please let the people running the site you came from that they've broken something. "
			"Otherwise, please enjoy this almost entirely blank webpage."
			</p>
		</section>
	}
}

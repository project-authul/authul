use actix_web::{
	body::MessageBody,
	dev::{Service as _, ServiceFactory, ServiceRequest, ServiceResponse},
	http::header::{HeaderName, HeaderValue},
	middleware, web, App, Error as ActixError,
};
use futures_util::future::FutureExt;
use leptos::LeptosOptions;
use leptos_actix::{generate_route_list, LeptosRoutes};

use super::{assets, authenticate, middleware::Csrf, oidc, root_component, Config};

const FRAME_OPTIONS: HeaderName = HeaderName::from_static("x-frame-options");
const DENY: HeaderValue = HeaderValue::from_static("DENY");

pub fn actix_app(
	cfg: Config,
) -> App<
	impl ServiceFactory<
		ServiceRequest,
		Response = ServiceResponse<impl MessageBody>,
		Config = (),
		InitError = (),
		Error = ActixError,
	>,
> {
	let frontend_component = root_component((&cfg).into());

	let routes = generate_route_list(frontend_component.clone());
	let options = LeptosOptions::builder()
		.output_name("authul")
		.site_pkg_dir(cfg.base_url().path().trim_start_matches('/').to_string() + "pkg")
		.build();

	let csrf_middleware = Csrf::new(
		cfg.base_url()
			.host_str()
			.expect("base URL does not have a domain"),
		cfg.base_url().path(),
	);

	App::new()
		.wrap_fn(|req, srv| {
			srv.call(req).map(|mut res| {
				res.as_mut()
					.unwrap()
					.headers_mut()
					.insert(FRAME_OPTIONS, DENY);
				res
			})
		})
		.wrap(middleware::Compress::default())
		.wrap(middleware::NormalizePath::trim())
		.wrap(csrf_middleware)
		.app_data(web::Data::new(cfg))
		.configure(oidc::routes)
		.configure(authenticate::routes)
		.leptos_routes(options, routes.to_owned(), frontend_component)
		// Remember, kids, middleware runs bottom-to-top, so this one will run
		// *first*, not last, like a sane system would do it
		.wrap(tracing_actix_web::TracingLogger::default())
		// Don't put anything after these, just in case
		.service(assets::serve_pkg)
		.service(assets::serve_assets)
}

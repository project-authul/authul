#![allow(unused)]

use actix_test::{ClientRequest, TestServer, TestServerConfig};
use actix_web::cookie::Cookie;
//use image::ImageFormat;
use rand::{thread_rng, RngCore};
use reqwest_tracing::TracingMiddleware;
use std::{env, path::PathBuf, sync::Arc};
use tokio::sync::OnceCell;
use tracing_subscriber::{filter::EnvFilter, layer::SubscriberExt as _, registry::Registry};
use url::Url;

mod browser;
pub(crate) use browser::{Browser, BrowserLocator};

static TEST_SETUP: OnceCell<()> = OnceCell::const_new();

async fn one_time_setup() {
	let layer = tracing_tree::HierarchicalLayer::default()
		.with_writer(tracing_subscriber::fmt::TestWriter::new())
		.with_indent_lines(true)
		.with_indent_amount(2)
		.with_targets(true);

	let sub = Registry::default()
		.with(layer)
		.with(EnvFilter::from_default_env());
	tracing::subscriber::set_global_default(sub).unwrap();

	tracing_log::LogTracer::init().expect("LogTracer init failed");

	authul_db::Pool::migrate_test_template(env::var("TEST_DB_URL").expect("TEST_DB_URL not set"))
		.await
		.expect("test_template migration failed");
}

// This was less painful than the hefty type annotation required on None::<T> if we wanted to make the cfg
// mangler an Option<impl Fn(...) -> ...>
pub(crate) fn default(
	mangle_cfg: authul_frontend::ConfigBuilder,
) -> authul_frontend::ConfigBuilder {
	mangle_cfg
}

pub(crate) fn vcr(
	cassette_name: &'static str,
) -> impl Fn(authul_frontend::ConfigBuilder) -> authul_frontend::ConfigBuilder {
	move |cfg| {
		let mut cassette = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
		cassette.push(cassette_name);

		let vcr_middleware = rvcr::VCRMiddleware::try_from(cassette)
			.expect("failed to load VCR")
			.with_rich_diff(true);
		let http_client =
			reqwest_middleware::ClientBuilder::new(reqwest_middleware::reqwest::Client::new())
				.with(vcr_middleware)
				.with(TracingMiddleware::default())
				.build();

		cfg.http_client(http_client)
	}
}

pub(crate) async fn setup(
	cfg: impl Fn(authul_frontend::ConfigBuilder) -> authul_frontend::ConfigBuilder,
) -> ConfiguredTestServer {
	TEST_SETUP.get_or_init(one_time_setup).await;

	let db = db();
	srv(db.await, cfg).await
}

async fn srv(
	db: authul_db::Pool,
	mangle_cfg: impl Fn(authul_frontend::ConfigBuilder) -> authul_frontend::ConfigBuilder,
) -> ConfiguredTestServer {
	let listen_addr = env::var("TESTSERVER_LISTEN_ADDRESS").unwrap_or("127.0.0.1".to_string());
	let listen_port = thread_rng().next_u32() % 32767 + 32767;

	let base_url = if listen_addr.contains(':') {
		format!("http://[{listen_addr}]:{listen_port}")
	} else {
		format!("http://{listen_addr}:{listen_port}")
	};

	let mut app_cfg = mangle_cfg(
		authul_frontend::ConfigBuilder::default()
			.base_url(base_url.clone())
			.unwrap()
			.root_encryption_key(&secrecy::Secret::new("test".to_string()))
			.unwrap()
			.database_handle(db.clone()),
	)
	.password_auth(true)
	.build()
	.expect("invalid config");

	authul_frontend::periodic_tasks::spawn(app_cfg.clone())
		.await
		.expect("background tasks shat themselves");

	let cfg = Arc::new(app_cfg.clone());
	let srv = actix_test::start_with(
		TestServerConfig::default()
			.disable_redirects()
			.listen_address(listen_addr)
			.port(listen_port as u16),
		move || authul_frontend::actix_app(app_cfg.clone()),
	);

	ConfiguredTestServer { db, srv, cfg }
}

pub(crate) struct ConfiguredTestServer {
	srv: TestServer,
	pub(crate) db: authul_db::Pool,
	pub(crate) cfg: Arc<authul_frontend::Config>,
}

impl ConfiguredTestServer {
	pub(crate) fn base_url(&self) -> Url {
		Url::parse(&self.url("")).expect("valid base_url")
	}
}

impl std::ops::Deref for ConfiguredTestServer {
	type Target = TestServer;

	fn deref(&self) -> &Self::Target {
		&self.srv
	}
}

async fn db() -> authul_db::Pool {
	let test_name = std::thread::current()
		.name()
		.expect("I've been through the desert on a test with no name")
		.replace("::", "_");
	let schema = format!("test_{}", test_name);
	let db = authul_db::Pool::new_on_schema(
		&schema,
		env::var("TEST_DB_URL").expect("TEST_DB_URL not set"),
	)
	.await
	.expect("DB creation failed");
	db.reset_schema(&schema)
		.await
		.expect("DB reset to complete successfully");
	db
}

pub(crate) trait WithCsrfCookie {
	fn with_csrf_cookie(self) -> Self;
}

impl WithCsrfCookie for ClientRequest {
	fn with_csrf_cookie(mut self) -> Self {
		self.cookie(Cookie::new("csrf_token", "somerandomvalue"))
	}
}

// Since this is utterly unreadable, here's how to use this:
//
// encode_params!(foo: "bar", baz: "wombat") will produce an &str "foo=bar&baz=wombat"
#[macro_export]
macro_rules! encode_params {
	($($name:ident : $val:expr),+) => {{
		let mut __serializer = ::url::form_urlencoded::Serializer::new(String::new());
		let __serializer = $crate::encode_params_inner!(__serializer, $($name : $val),+);
		__serializer.finish().as_str()
	}};
}

#[macro_export]
macro_rules! encode_params_inner {
	($ser:tt, $name:ident : $val:expr) => {
		$ser.append_pair(stringify!($name), $val)
	};
	($ser:tt, $name:ident : $val:expr, $($rest_name:ident : $rest_val:expr),+) => {
		{
			let __serializer = $ser.append_pair(stringify!($name), $val);
			$crate::encode_params_inner!(__serializer, $($rest_name : $rest_val),+)
		}
	};
}

#[macro_export]
macro_rules! css {
	($sel:literal) => {
		&::scraper::Selector::parse($sel).unwrap()
	};
}

pub(crate) async fn doc(res: &mut actix_test::ClientResponse) -> scraper::Html {
	let doc = scraper::Html::parse_document(
		&String::from_utf8(Vec::from(res.body().await.unwrap())).unwrap(),
	);
	assert!(
		doc.errors.is_empty(),
		"page has parsing errors: {:?}",
		doc.errors
	);
	doc
}

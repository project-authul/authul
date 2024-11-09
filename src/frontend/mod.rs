use actix_web::HttpServer;
use authul_frontend::{actix_app, periodic_tasks, Config as FrontendConfig};

use super::Config;

pub fn main() {
	service_skeleton::service("Authul").run(|cfg: Config| run(cfg));
}

#[allow(clippy::expect_used)] // Crapping out is permitted
#[actix_web::main]
async fn run(cfg: Config) {
	let db = authul_db::Pool::new(cfg.database_url())
		.await
		.expect("database initialization failed");

	db.migrate().await.expect("database migration failed");

	let app_cfg: FrontendConfig = cfg.clone().into_frontend_config(db);

	periodic_tasks::spawn(app_cfg.clone())
		.await
		.expect("background tasks did not spawn");

	let server = HttpServer::new(move || actix_app(app_cfg.clone())).disable_signals();

	let server = if cfg.listen_on_socket() {
		let path = cfg.listen_socket_path();
		match std::fs::remove_file(&path) {
			Ok(()) => tracing::debug!("Removed stale socket {path}"),
			Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {
				tracing::debug!("No stale socket found");
			}
			Err(e) => tracing::warn!("Failed to remove listening socket: {e}"),
		};
		file_mode::set_umask(0o117);
		tracing::info!(socket_path = cfg.listen_socket_path(), "Starting up");
		server.bind_uds(cfg.listen_socket_path()).unwrap()
	} else {
		tracing::info!(address = cfg.listen_address, "Starting up");
		server.bind(cfg.listen_address).unwrap()
	};

	let _unused = server.run().await;
}

use actix_web::rt::{spawn as spawn_task, time::interval};
use rand::Rng;
use std::time::Duration;

use super::{Config, Error};

pub(super) async fn spawn(cfg: Config) -> Result<(), Error> {
	let mut rng = rand::thread_rng();
	let splay = rng.gen_range(10..100);

	// Nuke expired oauth callbacks every hour or so
	spawn_task(async move {
		let mut interval = interval(Duration::from_secs(3600 + splay));
		loop {
			interval.tick().await;
			if let Err(e) = remove_expired_callback_states(&cfg).await {
				tracing::error!("failed to remove expired callback states: {e}");
			}
		}
	});

	Ok(())
}

#[tracing::instrument(level = "debug", skip(cfg))]
async fn remove_expired_callback_states(cfg: &Config) -> Result<(), Error> {
	cfg.db()
		.oauth_callback_state()
		.await?
		.delete_expired()
		.await?;
	Ok(())
}

use actix_web::rt::{spawn as spawn_task, time::interval};
use rand::Rng;
use std::time::Duration;

use super::{Config, Error};

pub(super) async fn spawn(cfg: Config) -> Result<(), Error> {
	let mut rng = rand::thread_rng();
	let splay = rng.gen_range(10..100);

	// Nuke expired OIDC tokens every hour or so
	spawn_task(async move {
		let mut interval = interval(Duration::from_secs(3600 + splay));
		loop {
			interval.tick().await;
			if let Err(e) = remove_expired_oidc_tokens(&cfg).await {
				tracing::error!("failed to remove expired OIDC tokens: {e}");
			}
		}
	});

	Ok(())
}

#[tracing::instrument(level = "debug", skip(cfg))]
async fn remove_expired_oidc_tokens(cfg: &Config) -> Result<(), Error> {
	cfg.db().oidc_token().await?.delete_expired().await?;
	Ok(())
}

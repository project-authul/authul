use actix_web::rt::{spawn as spawn_task, time::interval};
use rand::Rng;
use std::time::Duration;
use time::OffsetDateTime;

use super::{Config, Error};

const SIGNING_KEYS_LOCK_ID: i32 = 1088700994;

pub(super) async fn spawn(cfg: Config) -> Result<(), Error> {
	let mut db = cfg.db().conn().await?;
	let txn = db.transaction().await?;

	if txn
		.try_advisory_lock(cfg.lock_space(), SIGNING_KEYS_LOCK_ID)
		.await?
	{
		// First thing to do is to re-encrypt all existing signing keys under the current encrypting
		// key.  This makes sure that, if root keys are rotated faster than signing keys for some
		// reason, we don't eventually lose access to the signing keys.
		let sk = txn.signing_key();

		for mut k in sk.all().await? {
			k.update_key(cfg.re_encrypt_signing_key(k.key())?);
			k.save(&sk).await?;
		}

		// Next, make sure that we have both a current OIDC signing key, as well as one for the next signing
		// period
		{
			let now = OffsetDateTime::now_utc();

			let mut have_current = false;
			let mut current_end: Option<OffsetDateTime> = None;
			let mut have_next = false;

			for k in sk.find_all_by_usage("oidc").await? {
				if k.used_from() <= &now && k.not_used_from() > &now {
					have_current = true;
					current_end = Some(k.not_used_from().clone());
				} else if k.used_from() > &now {
					have_next = true;
				}
			}

			if !have_current {
				sk.new()
					.with_usage("oidc")
					.with_used_from(now.clone())
					.with_not_used_from(now + Config::OIDC_SIGNING_KEY_ROTATION_PERIOD)
					.with_expired_from(now + 2 * Config::OIDC_SIGNING_KEY_ROTATION_PERIOD)
					.with_key(cfg.new_oidc_signing_key()?)
					.save()
					.await?;
				current_end = Some(now + Config::OIDC_SIGNING_KEY_ROTATION_PERIOD);
			}

			if !have_next {
				let current_end = current_end.unwrap_or(now);

				sk.new()
					.with_usage("oidc")
					.with_used_from(current_end.clone())
					.with_not_used_from(current_end + Config::OIDC_SIGNING_KEY_ROTATION_PERIOD)
					.with_expired_from(current_end + 2 * Config::OIDC_SIGNING_KEY_ROTATION_PERIOD)
					.with_key(cfg.new_oidc_signing_key()?)
					.save()
					.await?;
			}
		}
	}

	txn.commit().await?;

	// And finally, we can fire off the periodic checker to do cleanup / key rotation every hour
	spawn_task(async move {
		let mut rng = rand::thread_rng();
		let splay = rng.gen_range(10..100);

		let mut interval = interval(Duration::from_secs(3600 + splay));
		loop {
			interval.tick().await;
			if let Err(e) = refresh_signing_keys(&cfg).await {
				tracing::error!("failed to refresh signing keys: {e}");
			}
		}
	});

	Ok(())
}

#[tracing::instrument(level = "debug", skip(cfg))]
async fn refresh_signing_keys(cfg: &Config) -> Result<(), Error> {
	let mut db = cfg.db().conn().await?;
	let txn = db.transaction().await?;

	if !txn
		.try_advisory_lock(cfg.lock_space(), SIGNING_KEYS_LOCK_ID)
		.await?
	{
		// Someone else is doing this already, that's fine
		return Ok(());
	}

	let sk = txn.signing_key();

	let now = OffsetDateTime::now_utc();

	let uncovered_period_from = sk.no_keys_valid_from_for("oidc").await?;

	if uncovered_period_from < now {
		sk.new()
			.with_usage("oidc")
			.with_used_from(uncovered_period_from.clone())
			.with_not_used_from(uncovered_period_from + Config::OIDC_SIGNING_KEY_ROTATION_PERIOD)
			.with_expired_from(uncovered_period_from + 2 * Config::OIDC_SIGNING_KEY_ROTATION_PERIOD)
			.with_key(cfg.new_oidc_signing_key()?)
			.save()
			.await?;
	}

	sk.delete_expired().await?;

	drop(sk);

	txn.commit().await?;

	Ok(())
}

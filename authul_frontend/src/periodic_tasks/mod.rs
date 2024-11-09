mod oauth_callback_states;
mod oidc_tokens;
mod signing_keys;

use super::{Config, Error};

pub async fn spawn(cfg: Config) -> Result<(), Error> {
	oauth_callback_states::spawn(cfg.clone()).await?;
	oidc_tokens::spawn(cfg.clone()).await?;
	signing_keys::spawn(cfg.clone()).await?;

	Ok(())
}

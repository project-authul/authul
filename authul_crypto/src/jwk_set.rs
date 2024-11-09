use serde::Deserialize;

use super::{Error, PublicJwk};

pub struct JwkSet(Vec<PublicJwk>);

#[derive(Deserialize)]
pub struct JwksJson {
	keys: Vec<PublicJwk>,
}

impl JwkSet {
	pub async fn from_url(
		url: &str,
		http_client: &reqwest_middleware::ClientWithMiddleware,
	) -> Result<Self, Error> {
		let res = http_client.get(url).send().await?;
		if !res.status().is_success() {
			return Err(Error::jwks_fetch(
				url,
				res.status().as_u16(),
				res.text().await?,
			));
		}
		Ok(Self(res.json::<JwksJson>().await?.keys))
	}
}

impl std::ops::Deref for JwkSet {
	type Target = Vec<PublicJwk>;

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

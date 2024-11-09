use reqwest_middleware::ClientWithMiddleware;
use std::{
	any::{Any, TypeId},
	collections::HashMap,
	sync::Arc,
	sync::Mutex,
	time::Duration,
};
use strong_box::SharedStrongBox;
use url::Url;

use super::{Error, OAuthClient};
use authul_crypto::PublicJwk;
use authul_db::types::OAuthProviderKind;

mod github;
pub use github::GitHub;
mod gitlab;
pub use gitlab::GitLab;
mod google;
pub use google::Google;

// We don't want to hang token issuance too long, so you're either quick or you're SOL
const TOKEN_KEY_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Debug)]
pub struct OAuthProviderMap {
	map: Arc<Mutex<HashMap<TypeId, Box<dyn Any + Send>>>>,
}

impl OAuthProviderMap {
	pub fn new() -> Self {
		Self {
			map: Arc::new(Mutex::new(HashMap::default())),
		}
	}

	pub fn insert<T: Send + 'static>(&mut self, v: T) -> Option<T> {
		let mut m = self.map.lock().expect("Mutex poisoned");

		m.insert(TypeId::of::<T>(), Box::new(v))
			.and_then(|o| o.downcast().ok().map(|b| *b))
	}

	pub fn get<T: 'static + Clone>(&self) -> Option<T> {
		let m = self.map.lock().expect("Mutex poisoned");

		m.get(&TypeId::of::<T>())
			.and_then(|b| b.downcast_ref().cloned())
	}

	pub fn has<T: 'static>(&self) -> bool {
		let m = self.map.lock().expect("Mutex poisoned");

		m.contains_key(&TypeId::of::<T>())
	}
}

async fn token_box_from_token_key_url(
	url: Option<Url>,
	http_client: &ClientWithMiddleware,
) -> Option<SharedStrongBox> {
	let Some(url) = url else {
		tracing::debug!("not forwarding token");
		return None;
	};

	match http_client
		.get(url.as_str())
		.timeout(TOKEN_KEY_REQUEST_TIMEOUT)
		.send()
		.await
	{
		Err(e) => {
			tracing::debug!(?e, "failed to retrieve token forwarding key");
			None
		}
		Ok(res) if res.status().as_u16() != 200 => {
			tracing::debug!(?res, "token forwarding key request resturned non-200");
			None
		}
		Ok(res) => {
			let Ok(jwk) = res
				.json::<PublicJwk>()
				.await
				.inspect_err(|e| tracing::debug!(?e, "parsing token forwarding key failed"))
			else {
				return None;
			};

			Some(jwk.to_shared_strong_box())
		}
	}
}

pub trait OAuthProvider {
	const AUTHORIZE_URL: &'static str;
	const TOKEN_URL: &'static str;
	const KIND: OAuthProviderKind;

	type Client: OAuthClient;
}

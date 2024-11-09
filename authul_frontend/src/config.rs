use rand::Rng as _;
use reqwest_middleware::ClientWithMiddleware;
use reqwest_tracing::TracingMiddleware;
use secrecy::{ExposeSecret, Secret};
use sha2::{Digest, Sha256};
use std::time::Duration;
use strong_box::{RotatingStrongBox, StemStrongBox, StrongBox};
use time::OffsetDateTime;
use url::Url;
use zxcvbn::zxcvbn;

use super::Error;
use crate::db;
use authul_crypto::{Jwk, PublicJwk};
use authul_oauth2::{provider, OAuthClientBuilder, OAuthProviderMap};

#[derive(Clone, Debug)]
pub struct Config {
	base_url: Url,
	root_keys: StemStrongBox,
	db: db::Pool,
	http_client: ClientWithMiddleware,
	lock_space: i32,
	css_url: Option<String>,

	password_auth: bool,
	dummy_pwhash: String,
	//pwhash_cost: u32,
	oauth_provider_map: OAuthProviderMap,
}

/// Associated constants
impl Config {
	pub const OIDC_SIGNING_KEY_ROTATION_PERIOD: Duration = Duration::from_secs(7 * 86_400); // aka "one week"
	pub const AUTH_CONTEXT_ENCRYPTION_KEY_LIFESPAN: Duration = Duration::from_secs(3600); // aka "one hour"
	pub const OAUTH_STATE_KEY_LIFESPAN: Duration = Duration::from_secs(3600); // aka "one hour"
	pub const OAUTH_STATE_KEY_BACKTRACK: u16 = 4; // allow us to decrypt oauth states at least four hours old
}

impl Config {
	pub fn builder() -> ConfigBuilder {
		ConfigBuilder::default()
	}

	pub fn base_url(&self) -> &Url {
		&self.base_url
	}

	pub fn oauth_provider_map(&self) -> &OAuthProviderMap {
		&self.oauth_provider_map
	}

	pub fn password_auth(&self) -> bool {
		self.password_auth
	}

	pub fn dummy_pwhash(&self) -> &str {
		&self.dummy_pwhash
	}

	pub fn db(&self) -> db::Pool {
		self.db.clone()
	}

	pub fn http_client(&self) -> &ClientWithMiddleware {
		&self.http_client
	}

	pub fn lock_space(&self) -> i32 {
		self.lock_space
	}

	pub(super) fn css_url(&self) -> Option<&str> {
		self.css_url.as_ref().map(|s| s.as_str())
	}

	pub fn auth_context_strong_box(&self) -> RotatingStrongBox {
		self.root_keys.derive_rotating(
			b"AuthContext",
			Config::AUTH_CONTEXT_ENCRYPTION_KEY_LIFESPAN,
			1,
		)
	}

	pub fn oauth_identity_attribute_strong_box(&self) -> StrongBox {
		self.root_keys.derive(b"OauthIdentity::Attribute")
	}
}

/// Signing key functionality
///
/// The bright line between "does it go in here, vs in db::model::signing_key" is whether or not
/// the functionality involves dealing with the config -- specifically, encrypting/decrypting keys.
impl Config {
	#[tracing::instrument(level = "debug", skip(self))]
	pub fn re_encrypt_signing_key(&self, k: &[u8]) -> Result<Vec<u8>, Error> {
		let strong_box = self.signing_key_strong_box();

		Ok(strong_box.encrypt(strong_box.decrypt(k, b"")?, b"")?)
	}

	#[tracing::instrument(level = "debug", skip(self))]
	pub async fn oidc_jwks(&self) -> Result<Vec<PublicJwk>, Error> {
		let strong_box = self.signing_key_strong_box();
		let now = OffsetDateTime::now_utc();

		Ok(self
			.db
			.signing_key()
			.await?
			.find_all_by_usage("oidc")
			.await?
			.into_iter()
			.filter(|k| k.expired_from() > &now)
			.map(|k| {
				Ok::<Jwk, Error>(ciborium::from_reader::<Jwk, &[u8]>(
					&strong_box.decrypt(k.key(), b"")?[..],
				)?)
			})
			.map(|k| Ok::<PublicJwk, Error>(k?.to_public_jwk()))
			.collect::<Result<Vec<_>, _>>()?)
	}

	#[tracing::instrument(level = "debug", skip(self))]
	pub async fn current_oidc_signing_jwk(&self) -> Result<Jwk, Error> {
		let strong_box = self.signing_key_strong_box();

		let now = OffsetDateTime::now_utc();

		Ok(ciborium::from_reader::<Jwk, &[u8]>(
			&strong_box.decrypt(
				&self
					.db
					.signing_key()
					.await?
					.find_all_by_usage("oidc")
					.await?
					.into_iter()
					.find(|k| k.used_from() <= &now && k.not_used_from() > &now)
					.ok_or(Error::no_signing_key("OIDC"))?
					.key(),
				b"",
			)?,
		)?)
	}

	#[tracing::instrument(level = "debug", skip(self))]
	pub fn new_oidc_signing_key(&self) -> Result<Vec<u8>, Error> {
		let strong_box = self.signing_key_strong_box();

		Ok(strong_box.encrypt_secret(Jwk::new_ed25519().to_bytes(), b"")?)
	}

	#[tracing::instrument(level = "debug", skip(self))]
	fn signing_key_strong_box(&self) -> StrongBox {
		self.root_keys.derive(b"signing_key")
	}
}

#[derive(Clone, Debug, Default)]
pub struct ConfigBuilder {
	base_url: Option<Url>,
	root_encryption_key: Option<Secret<[u8; 32]>>,
	root_decryption_keys: Vec<Secret<[u8; 32]>>,
	db: Option<db::Pool>,
	http_client: Option<ClientWithMiddleware>,
	css_url: Option<String>,
	password_auth: bool,
	github_oauth_client: Option<OAuthClientBuilder<provider::GitHub>>,
	gitlab_oauth_client: Option<OAuthClientBuilder<provider::GitLab>>,
	google_oauth_client: Option<OAuthClientBuilder<provider::Google>>,
}

impl ConfigBuilder {
	pub fn base_url(mut self, url: impl AsRef<str>) -> Result<Self, Error> {
		let url = Url::parse(url.as_ref())?;

		if Self::bad_base_url(&url) {
			return Err(Error::bad_base_url());
		}

		self.base_url = Some(url);
		Ok(self)
	}

	pub fn root_encryption_key(mut self, key: &Secret<String>) -> Result<Self, Error> {
		if Self::bad_key(&key) {
			return Err(Error::bad_key());
		}

		self.root_encryption_key = Some(Secret::new(Sha256::digest(key.expose_secret()).into()));
		self.root_decryption_keys
			.push(Secret::new(Sha256::digest(key.expose_secret()).into()));

		Ok(self)
	}

	pub fn root_decryption_keys<'a>(
		mut self,
		keys: impl IntoIterator<Item = &'a Secret<String>>,
	) -> Result<Self, Error> {
		for key in keys {
			if Self::bad_key(&key) {
				return Err(Error::bad_key());
			}

			self.root_decryption_keys
				.push(Secret::new(Sha256::digest(key.expose_secret()).into()));
		}

		Ok(self)
	}

	pub fn database_handle(mut self, db: db::Pool) -> Self {
		self.db = Some(db);
		self
	}

	#[cfg(not(authul_allow_bad_keys))]
	fn bad_key(key: &Secret<String>) -> bool {
		zxcvbn(key.expose_secret(), &[])
			.map(|e| e.guesses_log10())
			.unwrap_or(0.0)
			<= 18.0
	}

	#[cfg(authul_allow_bad_keys)]
	fn bad_key(key: &Secret<String>) -> bool {
		if zxcvbn(key.expose_secret(), &[])
			.map(|e| e.guesses_log10())
			.unwrap_or(0.0)
			<= 18.0
		{
			tracing::warn!("Allowing a weak key because we are running in debug mode; if you are in production, this is a *HUGE* problem");
		}
		false
	}

	#[cfg(not(authul_allow_http))]
	fn bad_base_url(base_url: &Url) -> bool {
		base_url.scheme() != "https"
	}

	#[cfg(authul_allow_http)]
	fn bad_base_url(base_url: &Url) -> bool {
		if base_url.scheme() != "https" {
			tracing::warn!("Allowing a HTTP base URL because we are running in debug mode; if you are in production, this is a *HUGE* problem");
		}
		false
	}

	pub fn css_url(&mut self, p: impl Into<String>) -> &mut Self {
		self.css_url = Some(p.into());
		self
	}

	#[cfg(authul_expose_privates)]
	pub fn http_client(mut self, c: ClientWithMiddleware) -> Self {
		self.http_client = Some(c);
		self
	}

	pub fn github_oauth_client(&mut self, c: OAuthClientBuilder<provider::GitHub>) -> &mut Self {
		self.github_oauth_client = Some(c);
		self
	}

	pub fn gitlab_oauth_client(&mut self, c: OAuthClientBuilder<provider::GitLab>) -> &mut Self {
		self.gitlab_oauth_client = Some(c);
		self
	}

	pub fn google_oauth_client(&mut self, c: OAuthClientBuilder<provider::Google>) -> &mut Self {
		self.google_oauth_client = Some(c);
		self
	}

	pub fn password_auth(mut self, b: bool) -> Self {
		self.password_auth = b;
		self
	}

	pub fn build(self) -> Result<Config, Error> {
		let (dummy_pwhash, _pwhash_cost) = Self::bcrypt_params()?;

		let base_url = self
			.base_url
			.ok_or_else(|| Error::missing_parameter("base_url"))?;
		let root_keys = StemStrongBox::new(
			self.root_encryption_key
				.ok_or_else(|| Error::missing_parameter("root_encryption_key"))?,
			self.root_decryption_keys,
		);

		let http_client = self.http_client.unwrap_or_else(|| {
			reqwest_middleware::ClientBuilder::new(
				reqwest_middleware::reqwest::ClientBuilder::new()
					.redirect(reqwest_middleware::reqwest::redirect::Policy::none())
					.user_agent("Authul")
					.build()
					.expect("failed to build default HTTP client"),
			)
			.with(TracingMiddleware::default())
			.with(http_cache_reqwest::Cache(http_cache_reqwest::HttpCache {
				mode: http_cache_reqwest::CacheMode::Default,
				manager: http_cache_reqwest::MokaManager::default(),
				options: http_cache_reqwest::HttpCacheOptions::default(),
			}))
			.build()
		});

		let mut oauth_provider_map = OAuthProviderMap::new();

		if let Some(c) = self.github_oauth_client.map(|b| {
			b.base_url(base_url.clone())
				.http_client(http_client.clone())
				.build()
				.expect("OAuthClient build failed")
		}) {
			oauth_provider_map.insert::<provider::GitHub>(c);
		}
		if let Some(c) = self.gitlab_oauth_client.map(|b| {
			b.base_url(base_url.clone())
				.http_client(http_client.clone())
				.build()
				.expect("OAuthClient build failed")
		}) {
			oauth_provider_map.insert::<provider::GitLab>(c);
		}
		if let Some(c) = self.google_oauth_client.map(|b| {
			b.base_url(base_url.clone())
				.http_client(http_client.clone())
				.build()
				.expect("OAuthClient build failed")
		}) {
			oauth_provider_map.insert::<provider::Google>(c);
		}

		Ok(Config {
			base_url,
			root_keys,
			db: self.db.ok_or_else(|| Error::missing_parameter("db"))?,
			http_client,
			lock_space: rand::thread_rng().gen(),
			css_url: self.css_url,

			password_auth: self.password_auth,
			dummy_pwhash,
			//pwhash_cost,
			oauth_provider_map,
		})
	}
}

impl ConfigBuilder {
	#[cfg(not(authul_allow_bad_keys))]
	fn bcrypt_params() -> Result<(String, u32), Error> {
		let mut cost = 12;
		let mut dummy_pwhash: Option<String> = None;
		let dummy_pw = strong_box::generate_key();

		while dummy_pwhash.is_none() {
			let start_time = std::time::Instant::now();
			let hash = bcrypt::hash(&dummy_pw, cost)?;
			if start_time.elapsed().as_millis() > 200 {
				dummy_pwhash = Some(hash);
			} else {
				cost += 1;
			}
		}

		tracing::info!("Using bcrypt cost of {cost}");

		Ok((dummy_pwhash.unwrap(), cost))
	}

	#[cfg(authul_allow_bad_keys)]
	fn bcrypt_params() -> Result<(String, u32), Error> {
		let dummy_pw = strong_box::generate_key();
		let dummy_pwhash = bcrypt::hash(&dummy_pw, 4)?;

		tracing::warn!("Using weak bcrypt parameters for testing -- if you're seeing this in production, you're in for a bad time");

		Ok((dummy_pwhash, 4))
	}
}

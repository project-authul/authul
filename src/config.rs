use secrecy::Secret;
use service_skeleton::ServiceConfig;
#[cfg(feature = "frontend-ssr")]
use url::Url;

#[cfg(feature = "frontend-ssr")]
use authul_frontend::Config as FrontendConfig;
#[cfg(feature = "frontend-ssr")]
use authul_oauth2::{provider, OAuthClientBuilder};

#[derive(Clone, Debug, ServiceConfig)]
pub(crate) struct Config {
	#[cfg(feature = "frontend-ssr")]
	pub(crate) listen_address: String,
	#[cfg(feature = "frontend-ssr")]
	#[config(default_value = "false")]
	enable_password_auth: bool,
	#[cfg(feature = "frontend-ssr")]
	base_url: Url,
	#[cfg(feature = "frontend-ssr")]
	frontend_css_url: Option<String>,

	#[config(encrypted, key_file_field = "secret_key")]
	database_url: Secret<String>,
	#[cfg(feature = "frontend-ssr")]
	#[config(encrypted, key_file_field = "secret_key")]
	root_keys: RootKeys,

	#[cfg(feature = "frontend-ssr")]
	#[config(encrypted, key_file_field = "secret_key")]
	github_oauth_creds: Option<OAuthClientBuilder<provider::GitHub>>,
	#[cfg(feature = "frontend-ssr")]
	#[config(encrypted, key_file_field = "secret_key")]
	gitlab_oauth_creds: Option<OAuthClientBuilder<provider::GitLab>>,
	#[cfg(feature = "frontend-ssr")]
	#[config(encrypted, key_file_field = "secret_key")]
	google_oauth_creds: Option<OAuthClientBuilder<provider::Google>>,
}

impl Config {
	pub(crate) fn database_url(&self) -> Secret<String> {
		self.database_url.clone()
	}
}

#[cfg(feature = "frontend-ssr")]
impl Config {
	pub(crate) fn listen_on_socket(&self) -> bool {
		self.listen_address.starts_with("unix:")
	}

	pub(crate) fn listen_socket_path(&self) -> String {
		self.listen_address
			.splitn(2, ':')
			.last()
			.expect("listen_socket_path called on non-Unix socket listen address")
			.to_string()
	}

	pub(crate) fn into_frontend_config(self, db: authul_db::Pool) -> FrontendConfig {
		let mut b = FrontendConfig::builder()
			.base_url(self.base_url)
			.expect("invalid base_url")
			.root_encryption_key(&self.root_keys.0[0])
			.expect("invalid root_key")
			.root_decryption_keys(&self.root_keys.0[1..])
			.expect("invalid root_key")
			.database_handle(db)
			.password_auth(self.enable_password_auth);

		if let Some(c) = self.github_oauth_creds {
			b.github_oauth_client(c);
		}
		if let Some(c) = self.gitlab_oauth_creds {
			b.gitlab_oauth_client(c);
		}
		if let Some(c) = self.google_oauth_creds {
			b.google_oauth_client(c);
		}
		if let Some(u) = self.frontend_css_url {
			b.css_url(u);
		}

		b.build().expect("invalid config")
	}
}

#[derive(Clone, Debug)]
#[cfg(feature = "frontend-ssr")]
struct RootKeys(Vec<Secret<String>>);

#[cfg(feature = "frontend-ssr")]
impl std::str::FromStr for RootKeys {
	type Err = &'static str;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Ok(RootKeys(
			s.split(':')
				.map(|s| s.to_string())
				.map(|s| {
					if s.len() == 0 {
						Err("found empty key; that's not going to work")
					} else {
						Ok(Secret::new(s))
					}
				})
				.collect::<Result<Vec<_>, Self::Err>>()?,
		))
	}
}

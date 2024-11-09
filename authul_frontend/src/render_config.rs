use serde::{Deserialize, Serialize};

cfg_if::cfg_if! {
	if #[cfg(feature = "ssr")] {
		use authul_oauth2::provider;
		use super::Config;
	}
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RenderConfig {
	pub password_auth: bool,
	pub github_auth: bool,
	pub gitlab_auth: bool,
	pub google_auth: bool,
	pub css_url: String,
}

impl RenderConfig {
	pub fn oauth_buttons(&self) -> bool {
		self.github_auth || self.gitlab_auth || self.google_auth
	}

	pub fn css_url(&self) -> &str {
		&self.css_url
	}
}

#[cfg(feature = "ssr")]
impl From<&Config> for RenderConfig {
	fn from(cfg: &Config) -> Self {
		Self {
			password_auth: cfg.password_auth(),
			github_auth: cfg.oauth_provider_map().has::<provider::GitHub>(),
			gitlab_auth: cfg.oauth_provider_map().has::<provider::GitLab>(),
			google_auth: cfg.oauth_provider_map().has::<provider::Google>(),
			css_url: cfg.css_url().unwrap_or_else(|| "/frontend.css").to_string(),
		}
	}
}

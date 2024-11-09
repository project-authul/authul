use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};
use oauth2::{basic::BasicClient, TokenResponse};
use reqwest_middleware::ClientWithMiddleware;
use secrecy::{ExposeSecret, Secret};
use serde::Deserialize;
use url::Url;

use super::{token_box_from_token_key_url, Error, OAuthClient, OAuthProvider};
use authul_db::{
	model::Principal,
	types::{IdentityAttributeKind as AttrKind, IdentityAttributes, OAuthProviderKind},
};

#[derive(Clone, Debug)]
pub struct GitLab {
	oauth_client: oauth2::basic::BasicClient,
	http_client: ClientWithMiddleware,
	base_url: Url,
}

#[derive(Clone, Debug, Deserialize)]
struct UserInfo {
	username: String,
	id: u64,
	name: Option<String>,
	email: String,
	public_email: Option<String>,
	commit_email: Option<String>,
}

impl GitLab {
	fn gitlab_get(
		&self,
		url: &str,
		token: Option<&Secret<String>>,
	) -> reqwest_middleware::RequestBuilder {
		let mut builder = self
			.http_client
			.get(url)
			.header("accept", "application/json");

		if let Some(t) = token {
			builder = builder.bearer_auth(t.expose_secret());
		}

		builder
	}
}

impl OAuthClient for GitLab {
	fn new(oauth_client: BasicClient, http_client: ClientWithMiddleware, base_url: Url) -> Self {
		Self {
			oauth_client,
			http_client,
			base_url,
		}
	}

	fn basic_client(&self) -> &BasicClient {
		&self.oauth_client
	}

	fn http_client(&self) -> &ClientWithMiddleware {
		&self.http_client
	}

	fn base_url(&self) -> &Url {
		&self.base_url
	}

	fn scope(&self) -> &'static str {
		"read_user"
	}

	fn kind(&self) -> OAuthProviderKind {
		OAuthProviderKind::GitLab
	}

	async fn identity_from_auth_code(
		&self,
		code: &str,
		db: authul_db::Pool,
		token_key_url: Option<Url>,
	) -> Result<(Principal, IdentityAttributes), Error> {
		let res = self
			.oauth_client
			.exchange_code(oauth2::AuthorizationCode::new(code.to_string()))
			.set_redirect_uri(self.redirect_url()?)
			.request_async(|req| self.make_oauth_code_request(req))
			.await?;
		let access_token = Secret::new(res.access_token().secret().clone());

		let res = self
			.http_client
			.execute(
				self.gitlab_get("https://gitlab.com/api/v4/user", Some(&access_token))
					.build()?,
			)
			.await?;
		if !res.status().is_success() {
			return Err(Error::user_info_request(
				"user",
				res.status().as_u16(),
				res.text().await?,
			));
		}
		let user_info = res.json::<UserInfo>().await?;

		let mut attrs = IdentityAttributes::new();

		attrs.push((AttrKind::Username, user_info.username).into());
		attrs.push((AttrKind::Email, user_info.email.clone()).into());

		if let Some(name) = user_info.name {
			attrs.push((AttrKind::DisplayName, name).into());
		}
		if let Some(email) = user_info.public_email {
			if email != user_info.email {
				attrs.push((AttrKind::Email, email).into());
			}
		}
		if let Some(email) = user_info.commit_email {
			if email != user_info.email {
				attrs.push((AttrKind::Email, email).into());
			}
		}

		if let Some(token_box) =
			token_box_from_token_key_url(token_key_url, &self.http_client).await
		{
			attrs.push(
				(
					AttrKind::AccessToken,
					BASE64_URL_SAFE_NO_PAD
						.encode(token_box.encrypt(access_token.expose_secret().as_bytes(), b"")?),
				)
					.into(),
			);
		}

		Ok((
			db.oauth_identity()
				.await?
				.find_or_create(OAuthProviderKind::GitLab, user_info.id.to_string())
				.await?
				.take_principal(),
			attrs,
		))
	}
}

impl OAuthProvider for GitLab {
	const AUTHORIZE_URL: &'static str = "https://gitlab.com/oauth/authorize";
	const TOKEN_URL: &'static str = "https://gitlab.com/oauth/token";
	const KIND: OAuthProviderKind = OAuthProviderKind::GitLab;

	type Client = GitLab;
}

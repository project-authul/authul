use uuid::Uuid;

use authul_macros::authul_table;

#[authul_table]
#[derive(Debug)]
pub struct OidcClient {
	// We use a v4 UUID here so as to not leak the client's age, which the default v7 UUID would
	// do, given that it's based on a timestamp
	#[column(v4_uuid)]
	id: Uuid,
	name: String,
	redirect_uris: Vec<String>,
	jwks_uri: String,
	token_forward_jwk_uri: Option<String>,
}

impl OidcClient {
	pub fn has_redirect_uri(&self, uri: impl AsRef<str>) -> bool {
		self.redirect_uris.iter().any(|u| u == uri.as_ref())
	}
}

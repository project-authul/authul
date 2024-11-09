use time::OffsetDateTime;
use uuid::Uuid;

use super::{types::OAuthProviderKind, Error, OidcClient};
use authul_macros::authul_table;

#[authul_table(name = "oauth_callback_states")]
#[derive(Debug)]
pub struct OAuthCallbackState {
	id: Uuid,
	#[relation(belongs_to)]
	oidc_client: OidcClient,
	provider_kind: OAuthProviderKind,
	csrf_token: Vec<u8>,
	context: String,
	expired_from: OffsetDateTime,
}

impl<C: deadpool_postgres::GenericClient> Handle<C> {
	#[tracing::instrument(level = "debug", skip(self))]
	pub async fn delete_expired(&self) -> Result<(), Error> {
		let sql = "DELETE FROM oauth_callback_states WHERE expired_from <= NOW()";
		tracing::debug!(sql);

		let stmt = self.prepare_typed_cached(sql, &[]).await?;
		self.execute(&stmt, &[]).await?;
		Ok(())
	}
}

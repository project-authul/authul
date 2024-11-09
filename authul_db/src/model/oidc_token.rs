use std::time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{Error, OidcClient};
use authul_macros::authul_table;

const ONE_MINUTE: Duration = Duration::from_secs(60);

#[authul_table]
#[derive(Debug)]
pub struct OidcToken {
	#[column(v4_uuid)]
	id: Uuid,
	#[relation(belongs_to)]
	oidc_client: OidcClient,
	token: String,
	redirect_uri: String,
	code_challenge: String,
	#[column(default(OffsetDateTime::now_utc() + ONE_MINUTE))]
	valid_before: OffsetDateTime,
}

impl OidcToken {
	pub fn is_expired(&self) -> bool {
		self.valid_before < OffsetDateTime::now_utc()
	}
}

impl<C: deadpool_postgres::GenericClient> Handle<C> {
	#[tracing::instrument(level = "debug", skip(self))]
	pub async fn delete_expired(&self) -> Result<(), Error> {
		let sql = "DELETE FROM oidc_tokens WHERE valid_before <= NOW()";
		tracing::debug!(sql);

		let stmt = self.prepare_typed_cached(sql, &[]).await?;
		self.execute(&stmt, &[]).await?;
		Ok(())
	}
}

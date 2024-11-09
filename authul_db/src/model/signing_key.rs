use time::OffsetDateTime;
use tokio_postgres::types::Type as SqlType;
use uuid::Uuid;

use super::Error;
use authul_macros::authul_table;

#[authul_table]
#[derive(Debug)]
pub struct SigningKey {
	id: Uuid,
	used_from: OffsetDateTime,
	not_used_from: OffsetDateTime,
	expired_from: OffsetDateTime,
	key: Vec<u8>,
	#[column(find_all_by)]
	usage: String,
}

impl<C: deadpool_postgres::GenericClient> Handle<C> {
	#[tracing::instrument(level = "debug", skip(self))]
	pub async fn all(&self) -> Result<Vec<SigningKey>, Error> {
		let sql = "SELECT * FROM signing_keys";
		tracing::debug!(sql);

		let stmt = self.prepare_typed_cached(sql, &[]).await?;
		Ok(self
			.query(&stmt, &[])
			.await?
			.into_iter()
			.map(|r| Ok::<SigningKey, Error>(SigningKey::from_row(&r)?))
			.collect::<Result<Vec<_>, Error>>()?)
	}

	#[tracing::instrument(level = "debug", skip(self))]
	pub async fn delete_expired(&self) -> Result<(), Error> {
		let sql = "DELETE FROM signing_keys WHERE expired_from <= NOW()";
		tracing::debug!(sql);

		let stmt = self.prepare_typed_cached(sql, &[]).await?;
		self.execute(&stmt, &[]).await?;
		Ok(())
	}

	/// Get the earliest time at which there are no valid signing keys for the specified usage.
	#[tracing::instrument(level = "debug", skip(self))]
	pub async fn no_keys_valid_from_for(
		&self,
		usage: impl AsRef<str> + tracing::Value + std::fmt::Debug,
	) -> Result<OffsetDateTime, Error> {
		let sql = "SELECT MAX(expired_from) FROM signing_keys WHERE usage=$1";
		tracing::debug!(sql, usage);

		let stmt = self.prepare_typed_cached(sql, &[SqlType::TEXT]).await?;
		Ok(self
			.query_opt(&stmt, &[&usage.as_ref()])
			.await?
			.map_or_else(
				|| OffsetDateTime::now_utc(),
				|row| {
					row.try_get::<_, OffsetDateTime>(0)
						.unwrap_or_else(|_| OffsetDateTime::now_utc())
				},
			))
	}
}

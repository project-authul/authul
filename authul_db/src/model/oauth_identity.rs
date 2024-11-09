use uuid::Uuid;

use super::{types::OAuthProviderKind, Error, Principal};
use authul_macros::authul_table;

#[authul_table(name = "oauth_identities")]
#[derive(Debug)]
pub struct OAuthIdentity {
	id: Uuid,
	#[relation(belongs_to)]
	principal: Principal,
	provider_kind: OAuthProviderKind,
	provider_identifier: String,
}

impl Handle<deadpool_postgres::Client> {
	#[tracing::instrument(level = "debug", skip(self))]
	pub async fn find_or_create(
		&mut self,
		provider: OAuthProviderKind,
		id: impl AsRef<str> + std::fmt::Debug,
	) -> Result<OAuthIdentity, Error> {
		let id = id.as_ref();

		loop {
			match self.find_or_create_txn(&provider, id).await {
				Ok(identity) => return Ok(identity),
				Err(e) => {
					if e.is_conflict() {
						tracing::debug!("conflict or deadlock detected; retrying");
					} else {
						return Err(e);
					}
				}
			}
		}
	}

	async fn find_or_create_txn(
		&mut self,
		provider: &OAuthProviderKind,
		id: &str,
	) -> Result<OAuthIdentity, Error> {
		let txn = self.transaction().await?;

		let sql = "SELECT principals AS principal,oauth_identities.* FROM oauth_identities JOIN principals ON oauth_identities.principal_id=principals.id WHERE provider_kind=$1 AND provider_identifier=$2 LIMIT 1";
		tracing::debug!(sql);
		let stmt = txn.prepare_cached(sql).await?;

		let identity = if let Some(row) = txn.query_opt(&stmt, &[&provider, &id]).await? {
			let principal = Principal::from_composite_type(&row.get("principal"))?;
			let identity = OAuthIdentity::from_row(&row, principal.clone())?;
			identity
		} else {
			let sql = "INSERT INTO principals VALUES ($1) RETURNING *";
			tracing::debug!(sql);
			let stmt = txn.prepare_cached(sql).await?;
			let principal = Principal::from_row(&txn.query_one(&stmt, &[&Uuid::now_v7()]).await?)?;

			let identity = txn
				.new()
				.with_provider_kind(provider)
				.with_provider_identifier(id)
				.with_principal(principal.clone())
				.save()
				.await?;

			identity
		};

		txn.commit().await?;

		Ok(identity)
	}
}

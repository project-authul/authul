use deadpool_postgres::{Config as DbConfig, Object as PoolObject, Pool as DeadPool};
#[cfg(test)]
use deadpool_postgres::{Hook as PoolHook, HookError};

use secrecy::{ExposeSecret, Secret};
use std::ops::DerefMut;
use tokio_postgres::{error::SqlState, Error as PostgresError, NoTls};

use super::{Conn, Error};

#[derive(Clone)]
pub struct Pool {
	pool: DeadPool,
}

impl std::fmt::Debug for Pool {
	fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
		fmt.debug_struct("Pool").finish_non_exhaustive()
	}
}

impl Pool {
	pub async fn new(url: Secret<String>) -> Result<Self, Error> {
		let url = url.expose_secret().to_owned();

		let pool = DbConfig {
			url: Some(url),
			..DbConfig::default()
		}
		.create_pool(None, NoTls)?;

		Ok(Pool { pool })
	}

	#[cfg(test)]
	pub async fn new_on_schema(
		schema: impl Into<String>,
		url: impl Into<String>,
	) -> Result<Self, Error> {
		let schema = schema.into();
		let url = url.into();

		let pool = DbConfig {
			url: Some(url.clone()),
			..DbConfig::default()
		}
		.builder(NoTls)?
		.post_create(PoolHook::async_fn(move |db, _| {
			let schema = schema.clone();
			Box::pin(async move {
				let sql = format!("SET search_path = {}", schema.clone());
				tracing::debug!(sql);

				db.execute(&sql, &[])
					.await
					.map_err(|e| HookError::Backend(e))?;
				Ok(())
			})
		}))
		.build()?;

		Ok(Pool { pool })
	}
}

impl Pool {
	pub async fn conn(&self) -> Result<Conn<PoolObject>, Error> {
		Ok(Conn::new(self.pool.get().await?.into()))
	}

	pub async fn delete(&self, record: impl super::DeleteRecord) -> Result<(), Error> {
		record.delete(self.pool.get().await?).await?;
		Ok(())
	}
}

pub enum ConflictableError<E> {
	Conflict,
	Error(E),
}

impl<E, T: Into<E> + std::error::Error + std::any::Any> From<T> for ConflictableError<E> {
	fn from(e: T) -> Self {
		let erry = &e as &dyn std::any::Any;

		match erry.downcast_ref::<PostgresError>() {
			Some(pe) => {
				if pe.code() == Some(&SqlState::T_R_DEADLOCK_DETECTED)
					|| pe.code() == Some(&SqlState::T_R_SERIALIZATION_FAILURE)
				{
					ConflictableError::Conflict
				} else {
					ConflictableError::Error(e.into())
				}
			}
			None => ConflictableError::Error(e.into()),
		}
	}
}

/*
Apparently this may all work once async_closures lands: https://github.com/rust-lang/rust/issues/106688
Until then, hand-rolled conflictable transactions for the win!

impl<E> ConflictableError<E> {
	fn is_conflicted(&self) -> bool {
		match self {
			Self::Conflict => true,
			Self::Error(_) => false,
		}
	}

	fn unwrap(self) -> E {
		match self {
			Self::Conflict => panic!("cannot unwrap conflicts"),
			Self::Error(e) => e,
		}
	}
}

impl Pool {
	pub async fn transaction<'t, T, E: From<Error>, F: Future<Output = Result<T, ConflictableError<E>>> + 't>(&self, txn_fn: impl Fn(Conn<Transaction<'t>>) -> F) -> Result<T, E> {
		loop {
			let mut conn = self.pool.get().await.map_err(|e| Error::from(e))?;
			let txn = conn.build_transaction().isolation_level(IsolationLevel::Serializable).start().await.map_err(|e| Error::from(e))?;
			let txn = Rc::new(txn);
			let res = txn_fn(Conn::new(txn.clone())).await;
			let txn = Rc::into_inner(txn).expect("txn still held elsewhere");
			match res {
				Ok(v) => {
					txn.commit().await.map_err(|e| Error::from(e))?;
					return Ok(v);
				},
				Err(e) if e.is_conflicted() => tracing::debug!("Conflict detected; retrying"),
				Err(e) => {
					tracing::debug!("Transaction failed; rolling back");
					txn.rollback().await.map_err(|e| Error::from(e))?;
					return Err(e.unwrap());
				}
			};
		}
	}
}
*/

impl Pool {
	pub async fn migrate(&self) -> Result<(), Error> {
		let mut db = self.pool.get().await?;

		let client = db.deref_mut().deref_mut();

		super::migrations::runner().run_async(client).await?;

		Ok(())
	}

	#[cfg(test)]
	pub async fn migrate_test_template(url: impl AsRef<str>) -> Result<(), Error> {
		let handle = Self::new_on_schema("test_template", url.as_ref()).await?;

		let mut db = handle.pool.get().await?;
		db.execute("CREATE SCHEMA IF NOT EXISTS test_template", &[])
			.await?;

		let client = db.deref_mut().deref_mut();

		super::migrations::runner().run_async(client).await?;

		Ok(())
	}

	#[cfg(test)]
	pub async fn reset_schema(&self, schema: impl AsRef<str>) -> Result<(), Error> {
		let db = self.pool.get().await?;

		db.execute(
			&format!("DROP SCHEMA IF EXISTS {} CASCADE", schema.as_ref()),
			&[],
		)
		.await?;
		db.execute(
			&format!(
				"SELECT test_template.clone_schema('test_template', '{}')",
				schema.as_ref()
			),
			&[],
		)
		.await?;

		Ok(())
	}
}

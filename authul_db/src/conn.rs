use deadpool_postgres::{Client, GenericClient, Transaction};
use std::rc::Rc;
use tokio_postgres::{types::Type as SqlType, IsolationLevel};

use super::Error;

#[derive(Debug)]
pub struct Conn<C: GenericClient>(Rc<C>);

impl<C: GenericClient> Conn<C> {
	pub fn new(c: Rc<C>) -> Self {
		Self(c)
	}
}

// Can't just #[derive(Clone)] because of https://github.com/rust-lang/rust/issues/26925
impl<C: GenericClient> Clone for Conn<C> {
	fn clone(&self) -> Self {
		Self(self.0.clone())
	}
}

impl Conn<Client> {
	#[tracing::instrument(level = "debug", skip(self))]
	pub async fn transaction(&mut self) -> Result<Conn<Transaction>, Error> {
		let inner = Rc::get_mut(&mut self.0).ok_or_else(|| {
			Error::cant_happen("cannot open transaction because Rc is held elsewhere")
		})?;
		Ok(Conn(Rc::new(
			inner
				.build_transaction()
				.isolation_level(IsolationLevel::Serializable)
				.start()
				.await?,
		)))
	}
}

impl Conn<Transaction<'_>> {
	/// Attempt to get a transaction-level exclusive advisory lock.
	///
	/// Returns `Ok(true)` if the lock was acquired, or `Ok(false)` if the lock is already held by
	/// someone else.
	#[tracing::instrument(level = "debug", skip(self))]
	pub async fn try_advisory_lock(&self, space_id: i32, lock_id: i32) -> Result<bool, Error> {
		let sql = "SELECT pg_try_advisory_xact_lock($1, $2)";
		tracing::debug!(sql, space_id, lock_id);

		let stmt = self
			.0
			.prepare_typed_cached(sql, &[SqlType::INT4, SqlType::INT4])
			.await?;
		Ok(self
			.0
			.query_one(&stmt, &[&space_id, &lock_id])
			.await?
			.try_get(0)
			.map_err(|_| Error::cant_happen("pg_try_advisory_xact_lock returned no values"))?)
	}

	#[tracing::instrument(level = "debug", skip(self))]
	pub async fn commit(self) -> Result<(), Error> {
		Ok(Rc::into_inner(self.0)
			.ok_or_else(|| {
				Error::cant_happen("someone else is also holding a ref to this transaction")
			})?
			.commit()
			.await?)
	}
}

impl<C: GenericClient> std::ops::Deref for Conn<C> {
	type Target = Rc<C>;

	fn deref(&self) -> &Rc<C> {
		&self.0
	}
}

mod conn;
mod error;
pub mod model;
mod pool;
pub mod quote;
pub mod types;

pub use conn::Conn;
pub use error::Error;
pub use pool::Pool;

refinery::embed_migrations!("migrations");

pub trait DatabaseRecord {
	fn table_name(&self) -> String;
	fn id(&self) -> &::uuid::Uuid;
}

pub trait DeleteRecord: DatabaseRecord {
	#[allow(async_fn_in_trait)]
	async fn delete(&self, client: ::deadpool_postgres::Object) -> Result<(), Error> {
		let sql = format!("DELETE FROM {} WHERE id=$1", self.table_name());
		tracing::debug!(sql, id = self.id().to_string());

		let stmt = client
			.prepare_typed_cached(&sql, &[::tokio_postgres::types::Type::UUID])
			.await?;
		client.execute(&stmt, &[&self.id()]).await?;
		Ok(())
	}
}

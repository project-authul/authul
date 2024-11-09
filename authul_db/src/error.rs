#[derive(Debug, thiserror::Error, thiserror_ext::Construct)]
pub enum Error {
	#[error("CBOR decoding failure: {0}")]
	CborDecoding(
		#[from] ciborium::de::Error<std::io::Error>,
		&'static std::panic::Location<'static>,
	),

	#[error("CBOR encoding failure: {0}")]
	CborEncoding(
		#[from] ciborium::ser::Error<std::io::Error>,
		&'static std::panic::Location<'static>,
	),

	#[error("migrations failed: {0}")]
	Migration(
		#[from] refinery::Error,
		&'static std::panic::Location<'static>,
	),

	#[error("{0} not found with {1}={2}")]
	NotFound(
		String,
		String,
		String,
		&'static std::panic::Location<'static>,
	),

	#[error("PostgreSQL error: {0}")]
	Postgres(
		#[from] tokio_postgres::Error,
		&'static std::panic::Location<'static>,
	),

	#[error("PostgreSQL config error: {0}")]
	PostgresConfig(
		#[from] deadpool_postgres::ConfigError,
		&'static std::panic::Location<'static>,
	),

	#[error("PostgreSQL pool error: {0}")]
	PostgresPool(
		#[from] deadpool_postgres::PoolError,
		&'static std::panic::Location<'static>,
	),

	#[error("PostgreSQL pool hook error: {0}")]
	PostgresPoolHook(
		#[from] deadpool_postgres::HookError,
		&'static std::panic::Location<'static>,
	),

	#[error("PostgreSQL pool builder error: {0}")]
	PostgresBuildPool(
		#[from] deadpool_postgres::BuildError,
		&'static std::panic::Location<'static>,
	),

	#[error("PostgreSQL pool creation error: {0}")]
	PostgresCreatePool(
		#[from] deadpool_postgres::CreatePoolError,
		&'static std::panic::Location<'static>,
	),

	#[error("Cryptography failure: {0}")]
	StrongBox(
		#[from] strong_box::Error,
		&'static std::panic::Location<'static>,
	),

	#[error("CAN'T HAPPEN: {0}")]
	CantHappen(String, &'static std::panic::Location<'static>),

	#[error("feature not yet implemented")]
	Unimplemented(&'static std::panic::Location<'static>),
}

impl Error {
	pub(crate) fn is_conflict(&self) -> bool {
		match self {
			Self::Postgres(e, _) => {
				e.code() == Some(&tokio_postgres::error::SqlState::T_R_DEADLOCK_DETECTED)
					|| e.code() == Some(&tokio_postgres::error::SqlState::T_R_SERIALIZATION_FAILURE)
			}
			_ => false,
		}
	}
}

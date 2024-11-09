#[derive(Debug, thiserror::Error, thiserror_ext::Construct)]
pub enum Error {
	#[error("failed to sign JWT: {0}")]
	JwtSignature(
		#[from] std::fmt::Error,
		&'static std::panic::Location<'static>,
	),

	#[error("failed to parse JWT: {0}")]
	JwtFormat(String, &'static std::panic::Location<'static>),

	#[error("received HTTP {http_status} while retrieving JWKS from {url}: {body}")]
	JwksFetch {
		url: String,
		http_status: u16,
		body: String,
		location: &'static std::panic::Location<'static>,
	},

	#[error("failed to make HTTP request")]
	Reqwest(
		#[from] reqwest_middleware::reqwest::Error,
		&'static std::panic::Location<'static>,
	),

	#[error("failed to make HTTP request")]
	ReqwestMiddleware(
		#[from] reqwest_middleware::Error,
		&'static std::panic::Location<'static>,
	),
}

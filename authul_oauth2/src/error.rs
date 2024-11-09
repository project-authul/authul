#[derive(Debug, thiserror::Error, thiserror_ext::Construct)]
pub enum Error {
	#[error("failed to decode base64 UUID: {0}")]
	Base64Uuid(
		#[from] authul_util::Base64UuidError,
		&'static std::panic::Location<'static>,
	),

	#[error("failed to construct URL: {0}")]
	Url(
		#[from] url::ParseError,
		&'static std::panic::Location<'static>,
	),

	#[error("HTTP client error: {0}")]
	Http(
		#[from] reqwest_middleware::reqwest::Error,
		&'static std::panic::Location<'static>,
	),

	#[error("HTTP client middleware error: {0}")]
	HttpMiddleware(
		#[from] reqwest_middleware::Error,
		&'static std::panic::Location<'static>,
	),

	#[error("failed to retrieve OAuth access token: {0}")]
	OauthToken(
		#[from]
		oauth2::RequestTokenError<
			reqwest_middleware::Error,
			oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>,
		>,
		&'static std::panic::Location<'static>,
	),

	#[error("failed to decode structure: {0}")]
	CborDecoding(
		#[from] ciborium::de::Error<std::io::Error>,
		&'static std::panic::Location<'static>,
	),

	#[error("failed to encode structure: {0}")]
	CborEncoding(
		#[from] ciborium::ser::Error<std::io::Error>,
		&'static std::panic::Location<'static>,
	),

	#[error("cryptographic failure: {0}")]
	Cryptography(
		#[from] strong_box::Error,
		&'static std::panic::Location<'static>,
	),

	#[error("database error: {0}")]
	Database(
		#[from] authul_db::Error,
		&'static std::panic::Location<'static>,
	),

	#[error("missing required field on builder {0}: {1}")]
	IncompleteBuild(String, String, &'static std::panic::Location<'static>),

	#[error("no CSRF protection available")]
	NoCsrfProtection(&'static std::panic::Location<'static>),

	#[error("CSRF token did not match")]
	InvalidCsrfToken(&'static std::panic::Location<'static>),

	#[error("callback state was not valid")]
	InvalidCallbackState(&'static std::panic::Location<'static>),

	#[error("unsupported OAuth provider {0:?}")]
	UnsupportedOauthProvider(
		authul_db::types::OAuthProviderKind,
		&'static std::panic::Location<'static>,
	),

	#[error("failed to retrieve user info")]
	UserInfoRequest(String, u16, String, &'static std::panic::Location<'static>),

	#[error("failed to convert slice to array: {0}")]
	ArraySlice(
		#[from] std::array::TryFromSliceError,
		&'static std::panic::Location<'static>,
	),

	#[error("functionality not implemented")]
	Unimplemented(&'static std::panic::Location<'static>),
}

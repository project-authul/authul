#[cfg(feature = "ssr")]
use actix_web::{HttpResponse, ResponseError};

#[derive(Debug, thiserror::Error, thiserror_ext::Construct)]
pub enum Error {
	#[error("weak encryption or decryption key rejected")]
	BadKey,

	#[error("HTTP base URL rejected")]
	BadBaseUrl,

	#[error("missing required config parameter {0}")]
	MissingParameter(String, &'static std::panic::Location<'static>),

	#[error("invalid state found while generating response: {0}")]
	InvalidState(String, &'static std::panic::Location<'static>),

	#[cfg(feature = "ssr")]
	#[error("Database error: {0}")]
	Database(
		#[from] crate::db::Error,
		&'static std::panic::Location<'static>,
	),

	#[cfg(feature = "ssr")]
	#[error("failed to parse or generate URL: {0}")]
	Url(
		#[from] url::ParseError,
		&'static std::panic::Location<'static>,
	),

	#[cfg(feature = "ssr")]
	#[error("failed to parse UUID: {0}")]
	Uuid(#[from] uuid::Error, &'static std::panic::Location<'static>),

	#[cfg(feature = "ssr")]
	#[error("JSON error")]
	SerdeJson(
		#[from] serde_json::Error,
		&'static std::panic::Location<'static>,
	),

	#[cfg(feature = "ssr")]
	#[error("rejected OAuth callback because {reason}")]
	OauthCallback {
		reason: String,
		error_code: authul_oauth2::error_code::Callback,
		location: &'static std::panic::Location<'static>,
	},

	#[cfg(feature = "ssr")]
	#[error("rejected OAuth /authorize request because {reason}")]
	OidcAuthorize {
		reason: String,
		error_code: authul_oauth2::error_code::AuthorizeEndpoint,
		location: &'static std::panic::Location<'static>,
	},

	#[cfg(feature = "ssr")]
	#[error("rejected OAuth /authorize request because {reason}")]
	OidcAuthorizeRedirect {
		redirect_uri: url::Url,
		reason: String,
		error_code: authul_oauth2::error_code::AuthorizeEndpoint,
		location: &'static std::panic::Location<'static>,
	},

	#[cfg(feature = "ssr")]
	#[error("rejected OIDC token fetch because {reason}")]
	OidcToken {
		reason: String,
		error_code: authul_oauth2::error_code::TokenEndpoint,
		location: &'static std::panic::Location<'static>,
	},

	#[cfg(feature = "ssr")]
	#[error("failure during OAuth: {0}")]
	Oauth(
		#[from] authul_oauth2::Error,
		&'static std::panic::Location<'static>,
	),

	#[cfg(feature = "ssr")]
	#[error("decryption failure")]
	DecryptionFailed(
		#[from] strong_box::Error,
		&'static std::panic::Location<'static>,
	),

	#[cfg(feature = "ssr")]
	#[error("no {0} signing key available")]
	NoSigningKey(String, &'static std::panic::Location<'static>),

	#[cfg(feature = "ssr")]
	#[error("Bad Request: {0}")]
	BadRequest(String, &'static std::panic::Location<'static>),

	#[cfg(feature = "ssr")]
	#[error("Forbidden")]
	Forbidden(&'static std::panic::Location<'static>),

	#[cfg(feature = "ssr")]
	#[error("{0}")]
	ServerError(String, &'static std::panic::Location<'static>),

	#[cfg(feature = "ssr")]
	#[error("base64 decoding failed: {0}")]
	Base64Decoding(
		#[from] base64::DecodeError,
		&'static std::panic::Location<'static>,
	),

	#[cfg(feature = "ssr")]
	#[error("CBOR decoding failed: {0}")]
	CborDecoding(
		#[from] ciborium::de::Error<std::io::Error>,
		&'static std::panic::Location<'static>,
	),

	#[cfg(feature = "ssr")]
	#[error("CBOR encoding failed: {0}")]
	CborEncoding(
		#[from] ciborium::ser::Error<std::io::Error>,
		&'static std::panic::Location<'static>,
	),

	#[cfg(feature = "ssr")]
	#[error("failed to bcrypt: {0}")]
	Bcrypt(
		#[from] bcrypt::BcryptError,
		&'static std::panic::Location<'static>,
	),

	#[cfg(feature = "ssr")]
	#[error("failed to join spawned task: {0}")]
	Join(
		#[from] actix_web::rt::task::JoinError,
		&'static std::panic::Location<'static>,
	),

	#[cfg(feature = "ssr")]
	#[error("cryptographic failure: {0}")]
	Crypto(
		#[from] authul_crypto::Error,
		&'static std::panic::Location<'static>,
	),

	#[error("CAN'T HAPPEN: {0}")]
	CantHappen(String, &'static std::panic::Location<'static>),
}

#[cfg(feature = "ssr")]
impl ResponseError for Error {
	fn error_response(&self) -> HttpResponse {
		match self {
			Error::BadRequest(e, _) => HttpResponse::BadRequest()
				.content_type("text/plain")
				.body(e.clone()),
			Error::OauthCallback { error_code, .. } => {
				tracing::debug!("{self}");
				HttpResponse::BadRequest().json(serde_json::json!({ "error": error_code.as_str() }))
			}
			Error::OidcToken { error_code, .. } => {
				tracing::debug!("{self}");
				HttpResponse::BadRequest().json(serde_json::json!({ "error": error_code.as_str() }))
			}
			Error::OidcAuthorize { error_code, .. } => {
				tracing::debug!("{self}");
				HttpResponse::BadRequest().json(serde_json::json!({ "error": error_code.as_str() }))
			}
			Error::OidcAuthorizeRedirect {
				redirect_uri,
				error_code,
				..
			} => {
				tracing::debug!("{self}");
				let mut uri = redirect_uri.to_owned();
				uri.query_pairs_mut()
					.append_pair("error", error_code.as_str());

				HttpResponse::Found()
					.insert_header(("location", uri.to_string()))
					.finish()
			}
			Error::Uuid(e, _) => {
				tracing::debug!("failed to parse UUID: {e}");
				HttpResponse::BadRequest()
					.content_type("text/plain")
					.body("invalid input")
			}
			Error::Forbidden(_) => HttpResponse::Forbidden().finish(),
			_ => HttpResponse::InternalServerError().finish(),
		}
	}
}

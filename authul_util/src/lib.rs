use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};
use uuid::Uuid;

#[derive(Clone, Debug, thiserror::Error)]
pub enum Base64UuidError {
	#[error("invalid base64")]
	Base64(#[from] base64::DecodeError),

	#[error("invalid UUID")]
	Uuid(#[from] uuid::Error),
}

pub trait Base64Uuid: Sized {
	fn to_base64(&self) -> String;
	fn from_base64(s: &str) -> Result<Self, Base64UuidError>;
}

impl Base64Uuid for Uuid {
	fn to_base64(&self) -> String {
		BASE64_URL_SAFE_NO_PAD.encode(self.as_bytes())
	}

	fn from_base64(s: &str) -> Result<Self, Base64UuidError> {
		Ok(Uuid::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(s)?)?)
	}
}

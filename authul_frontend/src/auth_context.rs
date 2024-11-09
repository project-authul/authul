use super::{Config, Error};
use base64::prelude::{Engine as _, BASE64_URL_SAFE_NO_PAD as BASE64};
use paste::paste;
use serde::{Deserialize, Serialize};
use std::{
	fmt::{Display, Error as FmtError, Formatter},
	sync::Arc,
};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Inner {
	oidc_client_id: Uuid,
	redirect_uri: String,
	code_challenge: String,
	principal: Option<Uuid>,
	nonce: Option<String>,
	state: Option<String>,
	pwhash: Option<String>,
}

#[cfg_attr(authul_expose_privates, visibility::make(pub))]
#[derive(Clone, Debug)]
pub(super) struct AuthContext {
	cfg: Arc<Config>,
	inner: Inner,
}

// Yeah, I know, I really should build an attr macro and do this properly...
macro_rules! param {
	($name:ident, $type:ty) => {
		paste! {
			#[allow(dead_code)]
			pub fn [<set_ $name>](&mut self, $name: impl Into<$type>) {
				self.inner.$name = $name.into();
			}

			#[allow(dead_code)]
			pub fn [<with_ $name>](mut self, $name: impl Into<$type>) -> Self {
				self.inner.$name = $name.into();
				self
			}

			#[allow(dead_code)]
			pub fn $name(&self) -> &$type {
				&self.inner.$name
			}
		}
	};
}

macro_rules! opt_param {
	($name:ident, $type:ty) => {
		paste! {
			#[allow(dead_code)]
			pub fn [<set_ $name>](&mut self, $name: impl Into<$type>) {
				self.inner.$name = Some($name.into());
			}

			#[allow(dead_code)]
			pub fn [<with_ $name>](mut self, $name: impl Into<$type>) -> Self {
				self.inner.$name = Some($name.into());
				self
			}

			#[allow(dead_code)]
			pub fn $name(&self) -> Option<&$type> {
				self.inner.$name.as_ref()
			}
		}
	};
}

impl AuthContext {
	#[cfg_attr(authul_expose_privates, visibility::make(pub))]
	pub(super) const UNKNOWN_USER: Uuid = Uuid::max();

	#[cfg_attr(authul_expose_privates, visibility::make(pub))]
	pub(super) fn new(
		cfg: Arc<Config>,
		oidc_client_id: impl AsRef<Uuid>,
		redirect_uri: impl Into<String>,
		code_challenge: impl Into<String>,
	) -> Self {
		Self {
			inner: Inner {
				oidc_client_id: oidc_client_id.as_ref().clone(),
				redirect_uri: redirect_uri.into(),
				code_challenge: code_challenge.into(),
				principal: None,
				nonce: None,
				state: None,
				pwhash: None,
			},
			cfg,
		}
	}

	#[cfg_attr(authul_expose_privates, visibility::make(pub))]
	pub(super) fn from_str(s: &str, cfg: &Arc<Config>) -> Result<Self, Error> {
		let ciphertext = BASE64.decode(s)?;

		let serialized = Self::strong_box(cfg.clone()).decrypt(&ciphertext, b"")?;

		Ok(Self {
			cfg: cfg.clone(),
			inner: ciborium::from_reader(&serialized[..])?,
		})
	}

	param!(redirect_uri, String);
	opt_param!(principal, Uuid);
	opt_param!(nonce, String);
	opt_param!(state, String);
	opt_param!(pwhash, String);

	pub fn oidc_client_id(&self) -> &Uuid {
		&self.inner.oidc_client_id
	}

	pub fn code_challenge(&self) -> &str {
		&self.inner.code_challenge
	}

	fn strong_box(cfg: Arc<Config>) -> strong_box::RotatingStrongBox {
		cfg.auth_context_strong_box()
	}
}

impl Display for AuthContext {
	fn fmt(&self, fmt: &mut Formatter<'_>) -> Result<(), FmtError> {
		let mut serialized = vec![];

		ciborium::into_writer(&self.inner, &mut serialized).expect("CBOR serialization failed?!?");

		fmt.write_str(
			&BASE64.encode(
				Self::strong_box(self.cfg.clone())
					.encrypt(serialized, b"")
					.expect("encryption should never fail"),
			),
		)
	}
}

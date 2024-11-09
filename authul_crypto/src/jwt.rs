/// Our very own JWT implementation.
///
/// I really do love code reuse, but the existing implementations out there are (as of the time of
/// writing, June 2024) irritatingly incomplete.  The `RustCrypto` JWT implementation is just plain
/// *empty*, but the rest of the Jose crypto operations are more-or-less complete.  Frank
/// Denis' `jwt-simple` would be perfect, except it doesn't provide any mechanisms for working with
/// JWKs, either reading or serialising, and seems to be relatively deliberate (cf.
/// https://github.com/jedisct1/rust-jwt-simple/pull/17).
///
/// So, we get to do our own, tightly-scoped-to-what-we-need thing.  Yippee!
use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{Error, Jwk, PublicJwk};

/// How many seconds we'll let clocks be out before we start rejecting things
const TIME_FUDGE: u64 = 3;
/// How many seconds the ID tokens we issue are valid for.
/// This does not need to be long, because they're just a container for transporting claims, not a
/// long-term credential.
const JWT_VALIDITY_PERIOD: u64 = 60;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Jwt {
	iss: Option<String>,
	sub: Option<String>,
	aud: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	jti: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	nonce: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	// Making this an actual IdentityAttributes would require depending on authul_db, which we
	// can't do because it depends on authul_crypto
	attrs: Option<JsonValue>,

	exp: u64,
	iat: u64,

	// These are the verification parts
	#[serde(skip_serializing)]
	hdr: Option<String>,
	#[serde(skip_serializing)]
	payload: Option<String>,
	#[serde(skip_serializing)]
	sig: Option<String>,
}

impl Jwt {
	pub fn new() -> Self {
		let now = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.expect("time to exist")
			.as_secs();

		Self {
			exp: now + JWT_VALIDITY_PERIOD + TIME_FUDGE,
			iat: now - TIME_FUDGE,
			..Jwt::default()
		}
	}

	pub fn peek_sub(&self) -> Option<&str> {
		self.sub.as_ref().map(|s| s.as_str())
	}

	pub fn peek_jti(&self) -> Option<&str> {
		self.jti.as_ref().map(|s| s.as_str())
	}

	pub fn with_iss(mut self, iss: impl Into<String>) -> Self {
		self.iss = Some(iss.into());
		self
	}

	pub fn with_sub(mut self, sub: impl Into<String>) -> Self {
		self.sub = Some(sub.into());
		self
	}

	pub fn with_aud(mut self, aud: impl Into<String>) -> Self {
		self.aud = Some(aud.into());
		self
	}

	pub fn with_jti(mut self, jti: impl Into<String>) -> Self {
		self.jti = Some(jti.into());
		self
	}

	pub fn with_attrs(mut self, attrs: JsonValue) -> Self {
		self.attrs = Some(attrs);
		self
	}

	pub fn set_nonce(&mut self, nonce: impl Into<String>) -> &Self {
		self.nonce = Some(nonce.into());
		self
	}

	pub fn with_broken_iat(mut self) -> Self {
		self.iat = self.iat + 2 * JWT_VALIDITY_PERIOD;
		self
	}

	pub fn with_broken_exp(mut self) -> Self {
		self.exp = self.exp - 3 * JWT_VALIDITY_PERIOD;
		self
	}

	pub fn sign(&self, key: &Jwk) -> Result<String, Error> {
		let hdr = Self::encode(json!({ "typ": "JWT", "alg": key.alg(), "kid": key.id() }));
		let payload = Self::encode(self);

		let sig = key.sign(&format!("{hdr}.{payload}").as_bytes());

		Ok(format!(
			"{hdr}.{payload}.{}",
			BASE64_URL_SAFE_NO_PAD.encode(&sig)
		))
	}

	pub fn verify(&self, key: &PublicJwk) -> bool {
		let (Some(hdr), Some(payload)) = (self.hdr.as_ref(), self.payload.as_ref()) else {
			return false;
		};

		let signed_text = format!("{hdr}.{payload}");
		let Ok(sig) = BASE64_URL_SAFE_NO_PAD
			.decode(self.sig.as_ref().map(|s| s.as_str()).unwrap_or_else(|| ""))
		else {
			return false;
		};

		if !key.verify(signed_text.as_bytes(), &sig) {
			return false;
		}

		let now = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.expect("time to exist")
			.as_secs();

		if self.iat - TIME_FUDGE > now {
			return false;
		}

		if self.exp + TIME_FUDGE < now {
			return false;
		}

		true
	}

	fn encode(obj: impl Serialize) -> String {
		let mut buf: Vec<u8> = Vec::new();

		serde_json::to_writer(&mut buf, &obj).expect("serialize failed");

		BASE64_URL_SAFE_NO_PAD.encode(buf)
	}
}

impl std::str::FromStr for Jwt {
	type Err = Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let mut parts = s.split('.');
		let (Some(hdr), Some(payload), Some(sig), None) =
			(parts.next(), parts.next(), parts.next(), parts.next())
		else {
			return Err(Error::jwt_format("missing or trailing part"));
		};

		#[derive(Deserialize)]
		struct Hdr {
			typ: String,
		}
		let decoded_hdr: Hdr = serde_json::from_slice(
			&BASE64_URL_SAFE_NO_PAD
				.decode(&hdr)
				.map_err(|e| Error::jwt_format(e.to_string()))?,
		)
		.map_err(|e| Error::jwt_format(e.to_string()))?;

		if decoded_hdr.typ != "JWT" {
			return Err(Error::jwt_format("typ != JWT"));
		}

		let mut jwt: Jwt = serde_json::from_slice(
			&BASE64_URL_SAFE_NO_PAD
				.decode(&payload)
				.map_err(|e| Error::jwt_format(e.to_string()))?,
		)
		.map_err(|e| Error::jwt_format(e.to_string()))?;

		jwt.hdr = Some(hdr.to_string());
		jwt.payload = Some(payload.to_string());
		jwt.sig = Some(sig.to_string());

		Ok(jwt)
	}
}

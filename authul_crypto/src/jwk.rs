use base64::prelude::{Engine as _, BASE64_URL_SAFE_NO_PAD};
use bytes::BytesMut;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use jose_jwk::{
	jose_jwa::{Algorithm as Jwa, Signing as JwaSigning},
	Class as JwkUse, Jwk as JoseJwk, Key as JoseKey, Okp as JoseOkp, OkpCurves,
	Parameters as JwkParameters,
};
use postgres_types::{to_sql_checked, FromSql, IsNull, ToSql, Type};
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use std::error::Error as StdError;
use strong_box::SharedStrongBox;

/// Thin(ish) wrapper around jose_jwk::Jwk, with added functions to do strange things like
/// *actually create a key*.
///
/// This type deliberately does not implement `serde::Serialize`, because that would allow the
/// fuckup fairy to do things like "put private keys into the OIDC JWKS", which would be... bad.
/// You'll be wanting [`PublicJwk`] for things that can go into a JWKS.
///
/// To serialize this type, use [`Jwk.to_bytes`], which at least has basic `Secret` guardrails to make
/// it harder to cause a disaster.
#[derive(Clone, Debug, Deserialize)]
#[non_exhaustive]
pub enum Jwk {
	Ed25519(Secret<[u8; 32]>),
}

impl Jwk {
	pub fn new_ed25519() -> Self {
		let key = {
			let mut rng = rand::rngs::OsRng;
			SigningKey::generate(&mut rng)
		};

		Jwk::Ed25519(key.to_bytes().into())
	}

	pub fn id(&self) -> String {
		match self {
			Self::Ed25519(k) => {
				let key = SigningKey::from_bytes(k.expose_secret());

				BASE64_URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes())
			}
		}
	}

	pub fn alg(&self) -> &'static str {
		match self {
			Self::Ed25519(_) => "EdDSA",
		}
	}

	/// Serialize this key in a compact format suitable for storage.
	pub fn to_bytes(&self) -> Secret<Vec<u8>> {
		let mut out: Vec<u8> = Vec::new();

		match self {
			Self::Ed25519(k) => {
				let mut encoder = ciborium_ll::Encoder::from(&mut out);
				encoder
					.push(ciborium_ll::Header::Map(Some(1)))
					.expect("encoder push failed");
				encoder.text("Ed25519", None).expect("encoder text failed");
				encoder
					.bytes(k.expose_secret(), None)
					.expect("encoder bytes failed");
			}
		}

		Secret::new(out)
	}

	pub fn sign(&self, plaintext: impl AsRef<[u8]>) -> Vec<u8> {
		match self {
			Self::Ed25519(k) => {
				let key = SigningKey::from_bytes(k.expose_secret());

				key.sign(plaintext.as_ref()).to_vec()
			}
		}
	}

	pub fn to_public_jwk(&self) -> PublicJwk {
		PublicJwk(match self {
			Self::Ed25519(k) => {
				let key = SigningKey::from_bytes(k.expose_secret());

				JoseJwk {
					key: JoseKey::Okp(JoseOkp {
						crv: OkpCurves::Ed25519,
						x: key.verifying_key().to_bytes().to_vec().into(),
						d: None,
					}),
					prm: JwkParameters {
						alg: Some(Jwa::Signing(JwaSigning::EdDsa)),
						kid: Some(self.id()),
						cls: Some(JwkUse::Signing),
						..JwkParameters::default()
					},
				}
			}
		})
	}
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(transparent)]
pub struct PublicJwk(JoseJwk);

impl PublicJwk {
	pub fn verify(&self, input: &[u8], sig: &[u8]) -> bool {
		match &self.0.key {
			JoseKey::Okp(JoseOkp {
				crv: OkpCurves::Ed25519,
				x,
				..
			}) => {
				let Ok(key_bytes): Result<[u8; 32], _> = x.as_ref().try_into() else {
					return false;
				};

				let Ok(key) = VerifyingKey::from_bytes(&key_bytes) else {
					return false;
				};

				let Ok(sig) = Signature::from_slice(sig) else {
					return false;
				};

				key.verify(input, &sig).map(|_| true).unwrap_or(false)
			}
			k => panic!("cannot verify using unimplemented JWK {k:?}"),
		}
	}

	pub fn to_shared_strong_box(&self) -> SharedStrongBox {
		// Yeah, this is kinda cheating...
		let mut key = vec![1u8];

		key.extend_from_slice(match &self.0.key {
			JoseKey::Okp(JoseOkp {
				crv: OkpCurves::Ed25519,
				x,
				..
			}) => x.as_ref(),
			k => panic!("cannot convert unimplemented JWK {k:?} to SharedStrongBox"),
		});

		SharedStrongBox::new((&key).try_into().expect("invalid pubkey format"))
	}
}

impl FromSql<'_> for PublicJwk {
	fn from_sql(_: &Type, buf: &[u8]) -> Result<Self, Box<(dyn StdError + Send + Sync + 'static)>> {
		Ok(serde_json::from_slice::<Self>(buf)?)
	}

	fn accepts(t: &Type) -> bool {
		t == &Type::TEXT
	}
}

impl ToSql for PublicJwk {
	fn to_sql(
		&self,
		_: &Type,
		buf: &mut BytesMut,
	) -> Result<IsNull, Box<(dyn StdError + Send + Sync + 'static)>> {
		buf.extend_from_slice(&serde_json::to_vec(&self)?);
		Ok(IsNull::No)
	}

	fn accepts(t: &Type) -> bool {
		t == &Type::TEXT
	}

	to_sql_checked!();
}

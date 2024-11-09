//! These are "auxiliary" types that don't represent a database table, but are kept here because
//! they support the data model in one way or another.

use postgres_types::{FromSql, ToSql};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, FromSql, ToSql, Serialize, Deserialize)]
#[postgres(name = "oauth_provider")]
pub enum OAuthProviderKind {
	GitHub,
	GitLab,
	Google,
}

impl From<&OAuthProviderKind> for OAuthProviderKind {
	fn from(f: &OAuthProviderKind) -> Self {
		f.clone()
	}
}

pub type IdentityAttributes = Vec<IdentityAttribute>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityAttribute {
	kind: IdentityAttributeKind,
	value: String,
}

// A simple but ugly way to allow people to create an empty vec literal of identity attributes without
// needing to paste a ridiculous amount of boilerplate
impl From<()> for IdentityAttribute {
	fn from(_: ()) -> Self {
		panic!("don't do this, please");
	}
}

impl From<(IdentityAttributeKind, String)> for IdentityAttribute {
	fn from(args: (IdentityAttributeKind, String)) -> Self {
		Self {
			kind: args.0,
			value: args.1,
		}
	}
}

impl From<(IdentityAttributeKind, &str)> for IdentityAttribute {
	fn from(args: (IdentityAttributeKind, &str)) -> Self {
		Self {
			kind: args.0,
			value: args.1.to_string(),
		}
	}
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum IdentityAttributeKind {
	/// Some sort of "handle" or "login" for the service
	Username,
	/// Our best guess at what the user would want to be called
	DisplayName,
	/// If the service indicates it, the user's preferred location for receiving email
	PrimaryEmail,
	/// If the service suggests it verifies emails, this is an email which has been verified,
	/// whatever that might mean
	VerifiedEmail,
	/// Any email address which can't be reasonably assumed to either be "verified" or "primary",
	/// either because the service doesn't support those concepts, or because it has explicitly
	/// indicated that this address is neither of those
	Email,
	/// An (encrypted) access token returned from the upstream identity provider.
	AccessToken,
}

#[cfg(test)]
// A useful shorthand for test assembly; definitely not for production use
impl From<&str> for IdentityAttributeKind {
	fn from(s: &str) -> Self {
		match s {
			"Username" => Self::Username,
			"DisplayName" => Self::DisplayName,
			"PrimaryEmail" => Self::PrimaryEmail,
			"VerifiedEmail" => Self::VerifiedEmail,
			"Email" => Self::Email,
			_ => panic!("unrecognised attribute kind {s}"),
		}
	}
}

#[cfg(test)]
impl IdentityAttribute {
	pub fn eq(&self, kind: &str, value: &str) -> bool {
		self.kind == kind.into() && self.value == value
	}
}

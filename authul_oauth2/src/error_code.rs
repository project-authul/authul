//! The various error codes that OAuth / OIDC endpoints might emit.
//!
//! The primary source for these error codes and their meanings is
//! <https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#extensions-error>,
//! but other places are often authoritative instead, because OAuth is very inconsistently specified.

/// Errors we emit from our `/oauth/callback` endpoint, which is called by a downstream IdP (ie a
/// "social login" provider, or similar) redirecting the user's browser back to us after
/// authorization is complete.
///
/// Semantics defined... nowhere, as far as I can see.  Which is just peachy.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum Callback {
	InvalidRequest,
}

impl Callback {
	pub fn as_str(&self) -> &'static str {
		match self {
			Self::InvalidRequest => "invalid_request",
		}
	}
}

/// Errors that our `/oidc/authorize' endpoint can return, which is called when an OAuth Client (ie
/// a website that uses us for authentication) wants us to authorize a user on their behalf, which
/// they do by redirecting the user's browser to this endpoint.
///
/// Semantics defined in
/// <https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2.1>, with extensions permitted from
/// <https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#extensions-error> by
/// <https://www.rfc-editor.org/rfc/rfc6749.html#section-8.5>.
#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub enum AuthorizeEndpoint {
	InvalidRequest,
	UnsupportedResponseType,
	InvalidScope,
	ServerError,
	TemporarilyUnavailable,
}

impl AuthorizeEndpoint {
	pub fn as_str(&self) -> &'static str {
		match self {
			Self::InvalidRequest => "invalid_request",
			Self::UnsupportedResponseType => "unsupported_response_type",
			Self::InvalidScope => "invalid_scope",
			Self::ServerError => "server_error",
			Self::TemporarilyUnavailable => "temporarily_unavailable",
		}
	}
}

/// Errors that our `/oidc/token' endpoint can return, which is called by an OIDC Client (ie a
/// website that uses us for authentication) wants to get an ID token for a freshly-authorized user.
///
/// Semantics defined in
/// <https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2>, with extensions permitted from
/// <https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#extensions-error> by
/// <https://www.rfc-editor.org/rfc/rfc6749.html#section-8.5>.
#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub enum TokenEndpoint {
	InvalidRequest,
	InvalidClient,
	InvalidGrant,
	UnsupportedGrantType,
}

impl TokenEndpoint {
	pub fn as_str(&self) -> &'static str {
		match self {
			Self::InvalidRequest => "invalid_request",
			Self::InvalidClient => "invalid_client",
			Self::InvalidGrant => "invalid_grant",
			Self::UnsupportedGrantType => "unsupported_grant_type",
		}
	}
}

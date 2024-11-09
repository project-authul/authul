use clap::{Args, Subcommand};
use url::Url;

use authul_util::Base64Uuid;

#[derive(Clone, Debug, Subcommand)]
pub(super) enum Command {
	/// Add a new OIDC client (a website that uses us for authentication)
	Add(Add),
}

#[derive(Clone, Debug, Args)]
pub(super) struct Client {
	#[command(subcommand)]
	subcommand: Command,
}

pub(super) async fn main(
	cfg: Client,
	db: authul_db::Pool,
) -> Result<(), Box<dyn std::error::Error>> {
	match cfg.subcommand {
		Command::Add(add) => add.run(db).await,
	}
}

#[derive(Clone, Debug, Args)]
pub(super) struct Add {
	/// The name of the Client
	///
	/// This will be displayed to users when they are redirected to Authul from the client,
	/// so it should be HTML-safe and suitably descriptive.
	name: String,

	/// A valid redirect URI for this Client
	///
	/// All the redirect URIs that a client is permitted to use must be declared in advance,
	/// to prevent various attacks.
	///
	/// May be specified multiple times to define multiple redirect URIs for this client.
	#[arg(long, required = true)]
	redirect_uri: Vec<Url>,

	/// The URL from which the Client's signing JWK Set will be fetched
	///
	/// When requesting a token from Authul, the client must authenticate itself by providing a
	/// single-use JWT signed with a key in this JWK Set.  This URL will be retrieved whenever a
	/// token request is received, unless the JWK Set is "fresh" according to the caching
	/// configuration of the last HTTP response provided by the client.
	#[arg(long, required = true)]
	jwks_uri: Url,

	/// The URL from which the Client's token forwarding JWK will be fetched
	///
	/// When a user is authenticated via an external OAuth provider, an access token is typically
	/// obtained from the provider as part of the authentication process.  In some cases, it may be
	/// useful for the client to be provided that access token for its own purposes.  Since an
	/// access token is extremely sensitive, it will only be provided in the ID token if the client
	/// provides a JWK containing an Ed25519 public key at the URL specified by this option.
	#[arg(long)]
	token_forward_jwk_uri: Option<Url>,
}

impl Add {
	async fn run(self, db: authul_db::Pool) -> Result<(), Box<dyn std::error::Error>> {
		let mut conn = db.conn().await?;
		let txn = conn.transaction().await?;

		let client = txn
			.oidc_client()
			.new()
			.with_name(self.name)
			.with_redirect_uris(self.redirect_uri)
			.with_jwks_uri(self.jwks_uri)
			.with_token_forward_jwk_uri(self.token_forward_jwk_uri.map(|u| u.to_string()))
			.save()
			.await?;

		txn.commit().await?;

		println!("Client ID: {}", client.id().to_base64());
		Ok(())
	}
}

mod client;

use clap::Parser;
use service_skeleton::ServiceConfig;

/// Manage an Authul installation
///
/// All "system" configuration (database location, cryptographic keys, etc) are specified via
/// environment variables.  Thus, you should run this tool in an environment that has all the
/// necessary environment variables already setup.
#[derive(Clone, Debug, Parser)]
enum Cli {
	/// Run the Authul frontend web application
	#[cfg(feature = "frontend-ssr")]
	Frontend,
	/// Manage OIDC clients (the websites that use us to authenticate)
	Client(client::Client),
}

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
	let cli = Cli::parse();

	#[cfg(feature = "frontend-ssr")]
	if matches!(cli, Cli::Frontend) {
		return Ok(crate::frontend::main());
	}

	run_cli(cli)
}

#[tokio::main]
async fn run_cli(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
	let cfg = super::Config::from_env_vars("Authul", std::env::vars())?;
	let db = authul_db::Pool::new(cfg.database_url()).await?;

	db.migrate().await?;

	match cli {
		#[cfg(feature = "frontend-ssr")]
		Cli::Frontend => {
			panic!("CAN'T HAPPEN");
		}
		Cli::Client(cfg) => client::main(cfg, db).await,
	}
}

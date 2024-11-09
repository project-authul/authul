#[cfg(feature = "frontend-hydrate")]
#[allow(unused_imports)] // False positive, I think, we definitely need this
use authul_frontend::hydrate;

#[cfg(feature = "frontend-ssr")]
pub mod frontend;

#[cfg(feature = "cli")]
pub mod cli;

#[cfg(any(feature = "frontend-ssr", feature = "cli"))]
mod config;
#[cfg(any(feature = "frontend-ssr", feature = "cli"))]
pub(crate) use config::Config;

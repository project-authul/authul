use super::{middleware, AuthContext, Config, Error};
use actix_web::web::ServiceConfig;

mod authorize;
mod provider_metadata;
mod token;

pub(super) fn routes(cfg: &mut ServiceConfig) {
	authorize::routes(cfg);
	provider_metadata::routes(cfg);
	token::routes(cfg);
}

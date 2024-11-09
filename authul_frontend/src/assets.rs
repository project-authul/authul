use actix_web::{route, web};
use actix_web_rust_embed_responder::{EmbedResponse, EmbedableFileResponse, IntoResponse};
use rust_embed_for_web::RustEmbed;

#[derive(RustEmbed)]
#[folder = "assets"]
pub(super) struct Assets;

#[route("/{path:.*}", method = "GET", method = "POST")]
pub(super) async fn serve_assets(path: web::Path<String>) -> EmbedResponse<EmbedableFileResponse> {
	tracing::debug!(?path, "assets");
	Assets::get(&path).into_response()
}

#[derive(RustEmbed)]
#[folder = "../target/site/pkg"]
pub(super) struct Pkg;

#[route("/pkg/{path:.*}", method = "GET", method = "POST")]
pub(super) async fn serve_pkg(path: web::Path<String>) -> EmbedResponse<EmbedableFileResponse> {
	tracing::debug!(?path, "/pkg");
	Pkg::get(&path).into_response()
}

use image::ImageFormat;
use std::{env, path::PathBuf};

pub(crate) use fantoccini::Locator as BrowserLocator;

#[derive(Clone, Debug)]
pub(crate) struct Browser(fantoccini::Client);

impl Browser {
	pub(crate) async fn new() -> Self {
		Browser(
			fantoccini::ClientBuilder::native()
				.connect(&env::var("WEBDRIVER_URL").expect("set WEBDRIVER_URL"))
				.await
				.expect("failed to connect to webdriver"),
		)
	}

	pub(crate) async fn screenshot(&self, id: impl AsRef<str>) -> Result<(), String> {
		let screenshot = self
			.0
			.screenshot()
			.await
			.map_err(|e| format!("taking a screenshot failed: {e}"))?;

		let mut img_path = PathBuf::new()
			.join(env!("CARGO_MANIFEST_DIR"))
			.join("tests/screenshots")
			.join(env::var("TEST_BROWSER").unwrap_or("unknown".to_string()))
			.join(id.as_ref());
		img_path.set_extension("png");

		match image::open(&img_path) {
			Ok(ref_img) => {
				let new_img = image::load_from_memory_with_format(&screenshot, ImageFormat::Png)
					.map_err(|e| format!("invalid screenshot: {e}"))?;
				let result = image_compare::rgba_hybrid_compare(
					&ref_img.into_rgba8(),
					&new_img.clone().into_rgba8(),
				)
				.map_err(|e| format!("image comparison failed: {e}"))?;
				if result.score < 0.9 {
					let diff_img = result.image.to_color_map();

					let new_file = img_path.with_file_name(&format!("{}.new.png", id.as_ref()));
					let diff_file = img_path.with_file_name(&format!("{}.diff.png", id.as_ref()));

					new_img.save(&new_file).map_err(|e| {
						format!("failed to save screenshot to {}: {e}", new_file.display())
					})?;
					diff_img.save(&diff_file).map_err(|e| {
						format!("failed to save diff image to {}: {e}", diff_file.display())
					})?;

					Err(format!("Screenshot differed from reference image in {}\nScreenshot saved to {}\nDiff image saved to {}", img_path.display(), new_file.display(), diff_file.display()))
				} else {
					Ok(())
				}
			}
			Err(_) => {
				eprintln!(
					"No existing reference image {}; using current screenshot",
					img_path.display()
				);
				std::fs::write(&img_path, screenshot).map_err(|e| {
					format!(
						"failed to write initial screenshot to {}: {e}",
						img_path.display()
					)
				})
			}
		}
	}

	pub(crate) async fn close(self) {
		self.0.close().await.unwrap();
	}
}

impl std::ops::Deref for Browser {
	type Target = fantoccini::Client;

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

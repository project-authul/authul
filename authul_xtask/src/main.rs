use std::process::Command;

fn main() {
	let mut args = std::env::args();
	// Eat the binary name
	args.next();

	match args.next().as_ref().map(|s| s.as_str()) {
		Some("docker") => match args.next().as_ref().map(|s| s.as_str()) {
			Some("build") => build_docker_image(),
			Some("push") => push_docker_image(),
			Some(s) => barf(format!("unrecognised opt for 'docker' subcommand: '{s}'")),
			None => barf("'docker' xtask requires either 'build' or 'push'"),
		},
		Some(s) => barf(format!("unrecognised xtask '{s}'")),
		None => barf("please specify a subcommand (one of 'docker')"),
	};
}

fn barf(e: impl std::fmt::Display) -> ! {
	eprintln!("{e}");
	std::process::exit(1);
}

fn docker_image() -> String {
	std::env::var("DOCKER_IMAGE").unwrap_or_else(|_| "womble/authul".to_string())
}

fn docker_tag() -> String {
	std::env::var("DOCKER_TAG").unwrap_or_else(|_| "latest".to_string())
}

fn docker_ref() -> String {
	format!("{}:{}", docker_image(), docker_tag())
}

fn build_docker_image() {
	let rv = Command::new("docker")
		.args([
			"build",
			"--pull",
			&format!(
				"--build-arg=http_proxy={}",
				std::env::var("http_proxy").unwrap_or_default()
			),
			"-t",
			&docker_ref(),
			&format!(
				"{dir}/..",
				dir = std::env::var("CARGO_MANIFEST_DIR")
					.unwrap_or_else(|_| barf("CARGO_MANIFEST_DIR is not set?!?"))
			),
		])
		.status();

	match rv {
		Ok(status) if status.success() => (),
		Ok(status) => barf(format!("docker build failed with status {status}")),
		Err(e) => barf(format!("failed to run docker build: {e}")),
	};
}

fn push_docker_image() {
	build_docker_image();
	let rv = Command::new("docker")
		.args(["push", &docker_ref()])
		.status();

	match rv {
		Ok(status) if status.success() => (),
		Ok(status) => barf(format!("docker push failed with status {status}")),
		Err(e) => barf(format!("failed to run docker push: {e}")),
	};
}

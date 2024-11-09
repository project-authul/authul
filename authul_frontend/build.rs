fn main() {
	println!("cargo::rustc-check-cfg=cfg(authul_allow_bad_keys)");
	println!("cargo::rustc-check-cfg=cfg(authul_allow_http)");
	println!("cargo::rustc-check-cfg=cfg(authul_expose_privates)");
	println!("cargo::rustc-check-cfg=cfg(authul_hot_css)");

	if Ok("debug") == std::env::var("PROFILE").as_deref() {
		println!("cargo::rustc-cfg=authul_allow_bad_keys");
		println!("cargo::rustc-cfg=authul_allow_http");
		println!("cargo::rustc-cfg=authul_expose_privates");
		println!("cargo::rustc-cfg=authul_hot_css");
	}
}

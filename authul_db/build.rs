fn main() {
	// Migrations are embedded, so need a rebuild when changed
	println!("cargo::rerun-if-changed=migrations");
	for entry in glob::glob("migrations/*.{sql,rs}").expect("failed to glob migrations") {
		println!(
			"cargo::rerun-if-changed={}",
			entry.expect("glob file failed").display()
		);
	}
}

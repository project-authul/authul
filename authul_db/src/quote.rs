pub fn identifier(s: impl AsRef<str>) -> String {
	postgres_protocol::escape::escape_identifier(s.as_ref())
}

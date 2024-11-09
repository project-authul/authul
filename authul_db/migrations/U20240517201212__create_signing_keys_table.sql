CREATE TABLE signing_keys (
	id UUID PRIMARY KEY,
	used_from TIMESTAMPTZ NOT NULL,
	not_used_from TIMESTAMPTZ NOT NULL,
	expired_from TIMESTAMPTZ NOT NULL,
	key BYTEA NOT NULL,
	usage TEXT NOT NULL
);

CREATE INDEX signing_key_usage ON signing_keys(usage);

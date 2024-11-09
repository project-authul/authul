CREATE TABLE oauth_callback_states (
	id UUID PRIMARY KEY,
	oidc_client_id UUID NOT NULL REFERENCES oidc_clients ON DELETE CASCADE,
	provider_kind oauth_provider NOT NULL,
	csrf_token BYTEA NOT NULL,
	context TEXT NOT NULL,
	expired_from TIMESTAMPTZ NOT NULL
);

CREATE TABLE oidc_tokens (
	id UUID PRIMARY KEY,
	oidc_client_id UUID NOT NULL REFERENCES oidc_clients ON DELETE CASCADE,
	token TEXT NOT NULL,
	redirect_uri TEXT NOT NULL,
	code_challenge TEXT NOT NULL,
	valid_before TIMESTAMPTZ NOT NULL
);

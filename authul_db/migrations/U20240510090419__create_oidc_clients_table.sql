CREATE TABLE oidc_clients (
	id UUID PRIMARY KEY,
	name TEXT NOT NULL,
	redirect_uris TEXT[] NOT NULL,
	jwks_uri TEXT NOT NULL,
	token_forward_jwk_uri TEXT
);

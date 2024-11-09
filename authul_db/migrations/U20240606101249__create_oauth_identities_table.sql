CREATE TABLE oauth_identities (
	id UUID PRIMARY KEY,
	principal_id UUID NOT NULL REFERENCES principals ON DELETE CASCADE,
	provider_kind oauth_provider NOT NULL,
	provider_identifier TEXT NOT NULL
);

CREATE UNIQUE INDEX provider_identifier_uniqueness ON oauth_identities (provider_kind, provider_identifier);

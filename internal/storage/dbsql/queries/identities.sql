-- name: UpdateIdentityProviderID :exec
-- Uses a raw UPDATE rather than the ORM's primary-key update because
-- Identity's primary key is (provider, id), not provider_id.
UPDATE auth.identities SET provider_id = $1 WHERE id = $2;

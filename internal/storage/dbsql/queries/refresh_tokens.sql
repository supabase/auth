-- name: LockRefreshTokenForUpdate :one
SELECT id FROM auth.refresh_tokens WHERE token = $1 LIMIT 1 FOR UPDATE SKIP LOCKED;

-- name: RevokeTokenFamilyBySessionID :exec
UPDATE auth.refresh_tokens SET revoked = true, updated_at = now() WHERE session_id = $1 AND revoked = false;

-- name: RevokeTokenFamilyByParent :exec
WITH RECURSIVE token_family AS (
    SELECT rt.id, rt.user_id, rt.token, rt.revoked, rt.parent FROM auth.refresh_tokens rt WHERE rt.parent = $1
    UNION
    SELECT r.id, r.user_id, r.token, r.revoked, r.parent FROM auth.refresh_tokens r INNER JOIN token_family t ON t.token = r.parent
)
UPDATE auth.refresh_tokens r SET revoked = true FROM token_family WHERE token_family.id = r.id;

-- name: LockSessionForUpdate :one
-- Locks a session row so no other transaction using FOR UPDATE can touch it.
-- SKIP LOCKED means an already-locked row surfaces as "no rows" instead of blocking.
SELECT id FROM auth.sessions WHERE id = $1 LIMIT 1 FOR UPDATE SKIP LOCKED;

-- name: LockUserForUpdate :one
SELECT id FROM auth.users WHERE id = $1 LIMIT 1 FOR UPDATE SKIP LOCKED;

-- name: UpdateFactorAssociatedSessions :exec
UPDATE auth.sessions SET aal = $1, factor_id = NULL WHERE user_id = $2 AND factor_id = $3;

-- name: InvalidateSessionsWithAALLessThan :exec
DELETE FROM auth.sessions WHERE user_id = $1 AND aal < $2;

-- name: LogoutUserSessions :exec
DELETE FROM auth.sessions WHERE user_id = $1;

-- name: LogoutSession :exec
DELETE FROM auth.sessions WHERE id = $1;

-- name: LogoutAllExceptMe :exec
DELETE FROM auth.sessions WHERE id != $1 AND user_id = $2;

-- name: RevokeOAuthSessions :exec
DELETE FROM auth.sessions WHERE user_id = $1 AND oauth_client_id = $2;

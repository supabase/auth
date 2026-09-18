-- name: LockRecoveryCodeSetByUserID :one
SELECT id, user_id, mfa_factor_id, failed_verification_count, verification_locked_until, created_at, updated_at
FROM auth.mfa_recovery_code_sets WHERE user_id = $1 LIMIT 1 FOR UPDATE;

-- name: LockRecoveryCodeSetByID :one
SELECT id, user_id, mfa_factor_id, failed_verification_count, verification_locked_until, created_at, updated_at
FROM auth.mfa_recovery_code_sets WHERE id = $1 LIMIT 1 FOR UPDATE;

-- name: CountRecoveryCodes :one
SELECT COUNT(*) AS total, COUNT(*) FILTER (WHERE consumed_at IS NULL) AS remaining
FROM auth.mfa_recovery_codes WHERE mfa_recovery_code_set_id = $1;

-- name: MarkRecoveryCodeConsumed :execrows
UPDATE auth.mfa_recovery_codes SET consumed_at = $1 WHERE id = $2 AND consumed_at IS NULL;

-- name: DeleteRecoveryCodesBySetID :exec
DELETE FROM auth.mfa_recovery_codes WHERE mfa_recovery_code_set_id = $1;

-- name: ResetRecoveryCodeSetLockout :execrows
UPDATE auth.mfa_recovery_code_sets SET failed_verification_count = 0, verification_locked_until = NULL, updated_at = $1 WHERE id = $2;

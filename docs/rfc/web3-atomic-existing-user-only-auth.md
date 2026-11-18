# RFC: Atomic existing-user-only authentication for Web3 sign-in

## 1. Problem statement

Applications using Web3 sign-in often need **re-authentication** for an account that already has a provider identity, without any chance of creating a new user if resolution races with deletion, replacement, or concurrent sign-in attempts.

Today, the Web3 grant can follow paths that **create** users when no matching identity is found. A client-side check before calling Auth does not provide transactional guarantees against concurrent identity changes.

## 2. Current GoTrue behavior

`POST /token?grant_type=web3` validates SIWE/SIWS messages and either signs in an existing identity or **registers** a new user when policy allows. There is no first-class, server-issued challenge that binds a subsequent proof exclusively to a pre-resolved identity and user UUID.

## 3. Race condition / concurrency risk

Between a client-side “user exists” check and token issuance, another transaction may delete the identity, replace it, or complete a competing login. The standard grant may then enter account-creation logic. Downstream systems that require **UUID continuity** and **zero creation** on professional re-auth cannot rely on pre-checks alone.

## 4. Existing-user-only contract

Introduce an explicit mode:

1. **`POST /web3/challenge`** — resolves and locks an existing verified Web3 identity and active user; returns a one-time `nonce`, `request_id: WEB3_EXISTING_USER_ONLY`, and expiry. No session is created.
2. Wallet signs SIWE/SIWS including `Request ID: WEB3_EXISTING_USER_ONLY` and the server nonce.
3. **`POST /token?grant_type=web3`** with `existing_user_only: true` (and optional `expected_user_id` as an assertion, never a selector) consumes the challenge and issues tokens **only** if snapshots still match.

Failure modes refuse login; they do **not** fall back to signup.

## 5. Proposed transaction semantics

After cryptographic validation:

- `SELECT … FOR UPDATE` on challenge, identity, and user rows in one database transaction.
- Revalidate identity snapshot and user status against challenge binding.
- Verify expiration using database time after locks are acquired.
- Consume the nonce (single-use).
- Call the existing session issuance path; roll back nonce consumption and Auth writes if hooks or issuance fail.

The strict branch must not call user-creation or identity-creation helpers.

## 6. API compatibility

- Default `existing_user_only: false` preserves current Web3 signup/login.
- New endpoint and fields are additive.
- OpenAPI documents challenge request/response and token fields.

## 7. Security invariants

- Optional `expected_user_id` is checked against server-resolved identity; it cannot select an account.
- Signed `Request ID` prevents downgrading a strict proof by omitting the HTTP flag.
- Nonce replay and concurrent duplicate proofs: at most one session per consumed nonce.
- Identity replacement/transfer after challenge issuance does not satisfy the snapshot.

## 8. Regression coverage

- New scenario suite for the strict branch (success, refusal, concurrency, hook rollback).
- Existing Web3, OTP, and token tests unchanged on the default path.
- Migration adds a private challenge table with RLS; no cascading FK that would erase snapshots on identity deletion.

## 9. Migration / rollout considerations

- Requires a new Auth schema migration before the endpoint is enabled.
- Hosted Supabase needs a released Auth version including the migration and handlers.
- Client SDKs should expose challenge + strict grant explicitly; older issuers must not silently treat failures as signup.

## 10. Open questions for maintainers

- Preferred naming: `existing_user_only` vs `login_only` / `allow_create: false`?
- Challenge retention, cleanup, and wallet-enumeration privacy trade-offs.
- Rate limits and CAPTCHA parity with `/otp` vs `/verify`.
- Whether `expected_user_id` should be supported in v1 or deferred.
- JS/SDK surface and capability detection for hosted projects.

---

Implementation reference: branch `feat/web3-atomic-existing-user-only` (draft PR to follow). Design detail: `docs/web3-existing-user-only.md`.

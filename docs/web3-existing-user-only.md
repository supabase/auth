# Proposed Web3 existing-user-only grant

Local prototype based on Auth v2.197.0. Not available on hosted Supabase merely
because this patch exists. No managed project or SDK configuration is changed.

## Contract

Initial registration remains `POST /token?grant_type=web3` with the existing
`chain`, `message`, and `signature` fields. Do not fall back to registration
when an existing-only login fails.

1. `POST /web3/challenge` with `chain` (`ethereum` or `solana`), `address`,
   `chain_id`, `domain`, `uri` and optionally `expected_user_id`.
2. The server resolves and locks an existing, active, non-anonymous user and a
   previously authenticated provider identity. Ambiguous Ethereum case variants,
   inconsistent provider metadata, banned/deleted users, and UUID mismatches fail.
   The response contains only `nonce`, `issued_at`, `expires_at` and
   `request_id: "WEB3_EXISTING_USER_ONLY"`. It is not an authentication result.
3. Sign a SIWE/SIWS message containing those fields, the same address/domain/URI/
   network, an explicit expiration no later than the server expiration, and the
   signed `Request ID: WEB3_EXISTING_USER_ONLY`.
4. `POST /token?grant_type=web3` with `chain`, `message`, `signature`,
   `existing_user_only: true`, optionally `expected_user_id`.

The optional expected UUID is an assertion, never an account selector or proof
of authority. The signature and server-resolved identity are authoritative. The
challenge always binds the original identity row UUID and user UUID, even when
the optional assertion is omitted. Removing the HTTP mode flag from a signed
existing-only proof is refused, rather than interpreted as signup.

## Transaction and replay

The existing signature/domain validators run before the strict transaction.
Inside the transaction: lock the nonce row, lock/revalidate identity and user,
verify the snapshot binding, verify expiration against database wall time after
lock waits, consume the nonce, then call official Auth session issuance. There is
no user or identity creation call on this branch. The before/after-user-created
hooks are not invoked for an operation which cannot create a user.

Two requests with the same nonce serialize; at most one commits a new session.
Deletion or retargeting before the identity lock causes refusal. Deletion after
the issuer owns the identity/user locks waits until that login commits, giving a
defined serialization order. Session issuance errors roll back nonce consumption
and Auth writes. Unknown commit outcomes must not trigger signup or a different
identity: a committed proof remains consumed; a rolled-back proof has no session.

The refresh contract remains the official existing session contract. Refresh
does not change the UUID or renew `last_sign_in_at`; it is not reauthentication.
This change does not retroactively revoke already committed sessions on later
identity deletion. Account/session revocation is a separate existing Auth policy.

## Schema and operation

The additive engine migration creates an Auth-private challenge table with RLS,
no PUBLIC privileges, unique nonce digests, expiration index, and snapshot IDs.
There is deliberately no cascading FK that could erase a snapshot on deletion
and allow a replacement identity to satisfy it. No historic user backfill,
trigger, outbox, cron, worker, or email operation is added.

Challenges expire after five minutes. Expired rows may be removed by an
operator-owned bounded maintenance task; deleting an expired tombstone never
makes its nonce valid again because redemption requires an unexpired row. No
background task is enabled by this patch. Operators must provision retention and
capacity for this new table. Challenge requests use existing CAPTCHA and verify
rate-limiting middleware. Their generic refusal response intentionally excludes
UUIDs and account data, but observable wallet-existence differences must still be
considered in the upstream threat review.

No guarantee is claimed against a malicious database owner or Auth hook that
deliberately inserts accounts. The invariant concerns this grant under the trusted
Auth configuration, including the tested normal hook rejection path.

## Verification

`TestR8Web3ExistingOnly` executes real Ethereum/Solana signatures through Auth's
HTTP handlers and a real PostgreSQL 17 database, including actual lock waits and
user/identity/session counters. It is not a mocked resolver or JWT generator.
Run alongside the existing `TestWeb3`, `TestOtp`, and `TestToken` suites.

The Winstory transport sketch is packaged separately, not wired into its hosted
Application. The current JavaScript SDK does not serialize the new flag; it must
gain support or use an explicit supported transport for this proposed endpoint.

## Upstream and hosted deployment

The patch targets v2.197.0 as requested, not current master. Upstream contribution
requires a feature RFC/design discussion, review of API/retention/rate-limit
semantics, adaptation to current master, full upstream CI, SDK support and release
approval. No publication, acceptance date or managed deployment date is assumed.
Do not apply this engine migration by hand to a managed project's Auth schema.
Do not connect this local fork to a hosted project's Auth database.

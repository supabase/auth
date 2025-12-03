-- Normalize Ethereum addresses in provider_id to lowercase to prevent case-sensitivity issues
-- This migration must run BEFORE deploying the code change that lowercases addresses in parser.go
-- Background: Ethereum addresses are case-insensitive, but EIP-55 uses mixed case for checksums.
-- This migration ensures existing checksummed addresses are normalized to lowercase to match
-- the new behavior where addresses are lowercased at parse time.
--
-- Note: identity_data is NOT updated because it's only metadata for display purposes.
-- The provider_id field is the only field used for identity lookup and uniqueness.

/* auth_migration: 20251202014000 */

-- Update all web3:ethereum provider_id entries to use lowercase addresses
-- Format: "web3:ethereum:0xABCDEF..." -> "web3:ethereum:0xabcdef..."
update {{ index .Options "Namespace" }}.identities
set provider_id = lower(provider_id)
where provider = 'web3'
  and provider_id LIKE 'web3:ethereum:0x%';

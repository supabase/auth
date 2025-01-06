# Changelog

## [2.168.0](https://github.com/supabase/auth/compare/v2.167.0...v2.168.0) (2025-01-06)


### Features

* set `email_verified` to true on all identities with the verified email ([#1902](https://github.com/supabase/auth/issues/1902)) ([307892f](https://github.com/supabase/auth/commit/307892f85b39150074fbb80b9c8f45ac3312aae2))

## [2.167.0](https://github.com/supabase/auth/compare/v2.166.0...v2.167.0) (2024-12-24)


### Features

* fix argon2 parsing and comparison ([#1887](https://github.com/supabase/auth/issues/1887)) ([9dbe6ef](https://github.com/supabase/auth/commit/9dbe6ef931ae94e621d55a5f7aea4b7ee0449949))

## [2.166.0](https://github.com/supabase/auth/compare/v2.165.0...v2.166.0) (2024-12-23)


### Features

* switch to googleapis/release-please-action, bump to 2.166.0 ([#1883](https://github.com/supabase/auth/issues/1883)) ([11a312f](https://github.com/supabase/auth/commit/11a312fcf77771b3732f2f439078225895df7a85))


### Bug Fixes

* check if session is nil ([#1873](https://github.com/supabase/auth/issues/1873)) ([fd82601](https://github.com/supabase/auth/commit/fd82601917adcd9f8c38263953eb1ef098b26b7f))
* email_verified field not being updated on signup confirmation ([#1868](https://github.com/supabase/auth/issues/1868)) ([483463e](https://github.com/supabase/auth/commit/483463e49eec7b2974cca05eadca6b933b2145b5))
* handle user banned error code ([#1851](https://github.com/supabase/auth/issues/1851)) ([a6918f4](https://github.com/supabase/auth/commit/a6918f49baee42899b3ae1b7b6bc126d84629c99))
* Revert "fix: revert fallback on btree indexes when hash is unavailable" ([#1859](https://github.com/supabase/auth/issues/1859)) ([9fe5b1e](https://github.com/supabase/auth/commit/9fe5b1eebfafb385d6b5d10196aeb2a1964ab296))
* skip cleanup for non-2xx status ([#1877](https://github.com/supabase/auth/issues/1877)) ([f572ced](https://github.com/supabase/auth/commit/f572ced3699c7f920deccce1a3539299541ec94c))

## [2.165.1](https://github.com/supabase/auth/compare/v2.165.0...v2.165.1) (2024-12-06)


### Bug Fixes

* allow setting the mailer service headers as strings ([#1861](https://github.com/supabase/auth/issues/1861)) ([7907b56](https://github.com/supabase/auth/commit/7907b566228f7e2d76049b44cfe0cc808c109100))

## [2.165.0](https://github.com/supabase/auth/compare/v2.164.0...v2.165.0) (2024-12-05)


### Features

* add email validation function to lower bounce rates ([#1845](https://github.com/supabase/auth/issues/1845)) ([2c291f0](https://github.com/supabase/auth/commit/2c291f0356f3e91063b6b43bf2a21625b0ce0ebd))
* use embedded migrations for `migrate` command ([#1843](https://github.com/supabase/auth/issues/1843)) ([e358da5](https://github.com/supabase/auth/commit/e358da5f0e267725a77308461d0a4126436fc537))


### Bug Fixes

* fallback on btree indexes when hash is unavailable ([#1856](https://github.com/supabase/auth/issues/1856)) ([b33bc31](https://github.com/supabase/auth/commit/b33bc31c07549dc9dc221100995d6f6b6754fd3a))
* return the error code instead of status code ([#1855](https://github.com/supabase/auth/issues/1855)) ([834a380](https://github.com/supabase/auth/commit/834a380d803ae9ce59ce5ee233fa3a78a984fe68))
* revert fallback on btree indexes when hash is unavailable ([#1858](https://github.com/supabase/auth/issues/1858)) ([1c7202f](https://github.com/supabase/auth/commit/1c7202ff835856562ee66b33be131eca769acf1d))
* update ip mismatch error message ([#1849](https://github.com/supabase/auth/issues/1849)) ([49fbbf0](https://github.com/supabase/auth/commit/49fbbf03917a1085c58e9a1ff76c247ae6bb9ca7))

## [2.164.0](https://github.com/supabase/auth/compare/v2.163.2...v2.164.0) (2024-11-13)


### Features

* return validation failed error if captcha request was not json ([#1815](https://github.com/supabase/auth/issues/1815)) ([26d2e36](https://github.com/supabase/auth/commit/26d2e36bba29eb8a6ddba556acfd0820f3bfde5d))


### Bug Fixes

* add error codes to refresh token flow ([#1824](https://github.com/supabase/auth/issues/1824)) ([4614dc5](https://github.com/supabase/auth/commit/4614dc54ab1dcb5390cfed05441e7888af017d92))
* add test coverage for rate limits with 0 permitted events ([#1834](https://github.com/supabase/auth/issues/1834)) ([7c3cf26](https://github.com/supabase/auth/commit/7c3cf26cfe2a3e4de579d10509945186ad719855))
* correct web authn aaguid column naming ([#1826](https://github.com/supabase/auth/issues/1826)) ([0a589d0](https://github.com/supabase/auth/commit/0a589d04e1cd9310cb260d329bc8beb050adf8da))
* default to files:read scope for Figma provider ([#1831](https://github.com/supabase/auth/issues/1831)) ([9ce2857](https://github.com/supabase/auth/commit/9ce28570bf3da9571198d44d693c7ad7038cde33))
* improve error messaging for http hooks ([#1821](https://github.com/supabase/auth/issues/1821)) ([fa020d0](https://github.com/supabase/auth/commit/fa020d0fc292d5c381c57ecac6666d9ff657e4c4))
* make drop_uniqueness_constraint_on_phone idempotent ([#1817](https://github.com/supabase/auth/issues/1817)) ([158e473](https://github.com/supabase/auth/commit/158e4732afa17620cdd89c85b7b57569feea5c21))
* possible panic if refresh token has a null session_id ([#1822](https://github.com/supabase/auth/issues/1822)) ([a7129df](https://github.com/supabase/auth/commit/a7129df4e1d91a042b56ff1f041b9c6598825475))
* rate limits of 0 take precedence over MAILER_AUTO_CONFIRM ([#1837](https://github.com/supabase/auth/issues/1837)) ([cb7894e](https://github.com/supabase/auth/commit/cb7894e1119d27d527dedcca22d8b3d433beddac))

## [2.163.2](https://github.com/supabase/auth/compare/v2.163.1...v2.163.2) (2024-10-22)


### Bug Fixes

* ignore rate limits for autoconfirm ([#1810](https://github.com/supabase/auth/issues/1810)) ([9ce2340](https://github.com/supabase/auth/commit/9ce23409f960a8efa55075931138624cb681eca5))

## [2.163.1](https://github.com/supabase/auth/compare/v2.163.0...v2.163.1) (2024-10-22)


### Bug Fixes

* external host validation ([#1808](https://github.com/supabase/auth/issues/1808)) ([4f6a461](https://github.com/supabase/auth/commit/4f6a4617074e61ba3b31836ccb112014904ce97c)), closes [#1228](https://github.com/supabase/auth/issues/1228)

## [2.163.0](https://github.com/supabase/auth/compare/v2.162.2...v2.163.0) (2024-10-15)


### Features

* add mail header support via `GOTRUE_SMTP_HEADERS` with `$messageType` ([#1804](https://github.com/supabase/auth/issues/1804)) ([99d6a13](https://github.com/supabase/auth/commit/99d6a134c44554a8ad06695e1dff54c942c8335d))
* add MFA for WebAuthn ([#1775](https://github.com/supabase/auth/issues/1775)) ([8cc2f0e](https://github.com/supabase/auth/commit/8cc2f0e14d06d0feb56b25a0278fda9e213b6b5a))
* configurable email and sms rate limiting ([#1800](https://github.com/supabase/auth/issues/1800)) ([5e94047](https://github.com/supabase/auth/commit/5e9404717e1c962ab729cde150ef5b40ea31a6e8))
* mailer logging ([#1805](https://github.com/supabase/auth/issues/1805)) ([9354b83](https://github.com/supabase/auth/commit/9354b83a48a3edcb49197c997a1e96efc80c5383))
* preserve rate limiters in memory across configuration reloads ([#1792](https://github.com/supabase/auth/issues/1792)) ([0a3968b](https://github.com/supabase/auth/commit/0a3968b02b9f044bfb7e5ebc71dca970d2bb7807))


### Bug Fixes

* add twilio verify support on mfa ([#1714](https://github.com/supabase/auth/issues/1714)) ([aeb5d8f](https://github.com/supabase/auth/commit/aeb5d8f8f18af60ce369cab5714979ac0c208308))
* email header setting no longer misleading ([#1802](https://github.com/supabase/auth/issues/1802)) ([3af03be](https://github.com/supabase/auth/commit/3af03be6b65c40f3f4f62ce9ab989a20d75ae53a))
* enforce authorized address checks on send email only ([#1806](https://github.com/supabase/auth/issues/1806)) ([c0c5b23](https://github.com/supabase/auth/commit/c0c5b23728c8fb633dae23aa4b29ed60e2691a2b))
* fix `getExcludedColumns` slice allocation ([#1788](https://github.com/supabase/auth/issues/1788)) ([7f006b6](https://github.com/supabase/auth/commit/7f006b63c8d7e28e55a6d471881e9c118df80585))
* Fix reqPath for bypass check for verify EP ([#1789](https://github.com/supabase/auth/issues/1789)) ([646dc66](https://github.com/supabase/auth/commit/646dc66ea8d59a7f78bf5a5e55d9b5065a718c23))
* inline mailme package for easy development ([#1803](https://github.com/supabase/auth/issues/1803)) ([fa6f729](https://github.com/supabase/auth/commit/fa6f729a027eff551db104550fa626088e00bc15))

## [2.162.2](https://github.com/supabase/auth/compare/v2.162.1...v2.162.2) (2024-10-05)


### Bug Fixes

* refactor mfa validation into functions ([#1780](https://github.com/supabase/auth/issues/1780)) ([410b8ac](https://github.com/supabase/auth/commit/410b8acdd659fc4c929fe57a9e9dba4c76da305d))
* upgrade ci Go version ([#1782](https://github.com/supabase/auth/issues/1782)) ([97a48f6](https://github.com/supabase/auth/commit/97a48f6daaa2edda5b568939cbb1007ccdf33cfc))
* validateEmail should normalise emails ([#1790](https://github.com/supabase/auth/issues/1790)) ([2e9b144](https://github.com/supabase/auth/commit/2e9b144a0cbf2d26d3c4c2eafbff1899a36aeb3b))

## [2.162.1](https://github.com/supabase/auth/compare/v2.162.0...v2.162.1) (2024-10-03)


### Bug Fixes

* bypass check for token & verify endpoints ([#1785](https://github.com/supabase/auth/issues/1785)) ([9ac2ea0](https://github.com/supabase/auth/commit/9ac2ea0180826cd2f65e679524aabfb10666e973))

## [2.162.0](https://github.com/supabase/auth/compare/v2.161.0...v2.162.0) (2024-09-27)


### Features

* add support for migration of firebase scrypt passwords ([#1768](https://github.com/supabase/auth/issues/1768)) ([ba00f75](https://github.com/supabase/auth/commit/ba00f75c28d6708ddf8ee151ce18f2d6193689ef))


### Bug Fixes

* apply authorized email restriction to non-admin routes ([#1778](https://github.com/supabase/auth/issues/1778)) ([1af203f](https://github.com/supabase/auth/commit/1af203f92372e6db12454a0d319aad8ce3d149e7))
* magiclink failing due to passwordStrength check ([#1769](https://github.com/supabase/auth/issues/1769)) ([7a5411f](https://github.com/supabase/auth/commit/7a5411f1d4247478f91027bc4969cbbe95b7774c))

## [2.161.0](https://github.com/supabase/auth/compare/v2.160.0...v2.161.0) (2024-09-24)


### Features

* add `x-sb-error-code` header, show error code in logs ([#1765](https://github.com/supabase/auth/issues/1765)) ([ed91c59](https://github.com/supabase/auth/commit/ed91c59aa332738bd0ac4b994aeec2cdf193a068))
* add webauthn configuration variables ([#1773](https://github.com/supabase/auth/issues/1773)) ([77d5897](https://github.com/supabase/auth/commit/77d58976ae624dbb7f8abee041dd4557aab81109))
* config reloading ([#1771](https://github.com/supabase/auth/issues/1771)) ([6ee0091](https://github.com/supabase/auth/commit/6ee009163bfe451e2a0b923705e073928a12c004))


### Bug Fixes

* add additional information around errors for missing content type header ([#1576](https://github.com/supabase/auth/issues/1576)) ([c2b2f96](https://github.com/supabase/auth/commit/c2b2f96f07c97c15597cd972b1cd672238d87cdc))
* add token to hook payload for non-secure email change ([#1763](https://github.com/supabase/auth/issues/1763)) ([7e472ad](https://github.com/supabase/auth/commit/7e472ad72042e86882dab3fddce9fafa66a8236c))
* update aal requirements to update user ([#1766](https://github.com/supabase/auth/issues/1766)) ([25d9874](https://github.com/supabase/auth/commit/25d98743f6cc2cca2b490a087f468c8556ec5e44))
* update mfa admin methods ([#1774](https://github.com/supabase/auth/issues/1774)) ([567ea7e](https://github.com/supabase/auth/commit/567ea7ebd18eacc5e6daea8adc72e59e94459991))
* user sanitization should clean up email change info too ([#1759](https://github.com/supabase/auth/issues/1759)) ([9d419b4](https://github.com/supabase/auth/commit/9d419b400f0637b10e5c235b8fd5bac0d69352bd))

## [2.160.0](https://github.com/supabase/auth/compare/v2.159.2...v2.160.0) (2024-09-02)


### Features

* add authorized email address support ([#1757](https://github.com/supabase/auth/issues/1757)) ([f3a28d1](https://github.com/supabase/auth/commit/f3a28d182d193cf528cc72a985dfeaf7ecb67056))
* add option to disable magic links ([#1756](https://github.com/supabase/auth/issues/1756)) ([2ad0737](https://github.com/supabase/auth/commit/2ad07373aa9239eba94abdabbb01c9abfa8c48de))
* add support for saml encrypted assertions ([#1752](https://github.com/supabase/auth/issues/1752)) ([c5480ef](https://github.com/supabase/auth/commit/c5480ef83248ec2e7e3d3d87f92f43f17161ed25))


### Bug Fixes

* apply shared limiters before email / sms is sent ([#1748](https://github.com/supabase/auth/issues/1748)) ([bf276ab](https://github.com/supabase/auth/commit/bf276ab49753642793471815727559172fea4efc))
* simplify WaitForCleanup ([#1747](https://github.com/supabase/auth/issues/1747)) ([0084625](https://github.com/supabase/auth/commit/0084625ad0790dd7c14b412d932425f4b84bb4c8))

## [2.159.2](https://github.com/supabase/auth/compare/v2.159.1...v2.159.2) (2024-08-28)


### Bug Fixes

* allow anonymous user to update password ([#1739](https://github.com/supabase/auth/issues/1739)) ([2d51956](https://github.com/supabase/auth/commit/2d519569d7b8540886d0a64bf3e561ef5f91eb63))
* hide hook name ([#1743](https://github.com/supabase/auth/issues/1743)) ([7e38f4c](https://github.com/supabase/auth/commit/7e38f4cf37768fe2adf92bbd0723d1d521b3d74c))
* remove server side cookie token methods ([#1742](https://github.com/supabase/auth/issues/1742)) ([c6efec4](https://github.com/supabase/auth/commit/c6efec4cbc950e01e1fd06d45ed821bd27c2ad08))

## [2.159.1](https://github.com/supabase/auth/compare/v2.159.0...v2.159.1) (2024-08-23)


### Bug Fixes

* return oauth identity when user is created ([#1736](https://github.com/supabase/auth/issues/1736)) ([60cfb60](https://github.com/supabase/auth/commit/60cfb6063afa574dfe4993df6b0e087d4df71309))

## [2.159.0](https://github.com/supabase/auth/compare/v2.158.1...v2.159.0) (2024-08-21)


### Features

* Vercel marketplace OIDC ([#1731](https://github.com/supabase/auth/issues/1731)) ([a9ff361](https://github.com/supabase/auth/commit/a9ff3612196af4a228b53a8bfb9c11785bcfba8d))


### Bug Fixes

* add error codes to password login flow ([#1721](https://github.com/supabase/auth/issues/1721)) ([4351226](https://github.com/supabase/auth/commit/435122627a0784f1c5cb76d7e08caa1f6259423b))
* change phone constraint to per user ([#1713](https://github.com/supabase/auth/issues/1713)) ([b9bc769](https://github.com/supabase/auth/commit/b9bc769b93b6e700925fcbc1ebf8bf9678034205))
* custom SMS does not work with Twilio Verify ([#1733](https://github.com/supabase/auth/issues/1733)) ([dc2391d](https://github.com/supabase/auth/commit/dc2391d15f2c0725710aa388cd32a18797e6769c))
* ignore errors if transaction has closed already ([#1726](https://github.com/supabase/auth/issues/1726)) ([53c11d1](https://github.com/supabase/auth/commit/53c11d173a79ae5c004871b1b5840c6f9425a080))
* redirect invalid state errors to site url ([#1722](https://github.com/supabase/auth/issues/1722)) ([b2b1123](https://github.com/supabase/auth/commit/b2b11239dc9f9bd3c85d76f6c23ee94beb3330bb))
* remove TOTP field for phone enroll response ([#1717](https://github.com/supabase/auth/issues/1717)) ([4b04327](https://github.com/supabase/auth/commit/4b043275dd2d94600a8138d4ebf4638754ed926b))
* use signing jwk to sign oauth state ([#1728](https://github.com/supabase/auth/issues/1728)) ([66fd0c8](https://github.com/supabase/auth/commit/66fd0c8434388bbff1e1bf02f40517aca0e9d339))

## [2.158.1](https://github.com/supabase/auth/compare/v2.158.0...v2.158.1) (2024-08-05)


### Bug Fixes

* add last_challenged_at field to mfa factors ([#1705](https://github.com/supabase/auth/issues/1705)) ([29cbeb7](https://github.com/supabase/auth/commit/29cbeb799ff35ce528bfbd01b7103a24903d8061))
* allow enabling sms hook without setting up sms provider ([#1704](https://github.com/supabase/auth/issues/1704)) ([575e88a](https://github.com/supabase/auth/commit/575e88ac345adaeb76ab6aae077307fdab9cda3c))
* drop the MFA_ENABLED config ([#1701](https://github.com/supabase/auth/issues/1701)) ([078c3a8](https://github.com/supabase/auth/commit/078c3a8adcd51e57b68ab1b582549f5813cccd14))
* enforce uniqueness on verified phone numbers ([#1693](https://github.com/supabase/auth/issues/1693)) ([70446cc](https://github.com/supabase/auth/commit/70446cc11d70b0493d742fe03f272330bb5b633e))
* expose `X-Supabase-Api-Version` header in CORS ([#1612](https://github.com/supabase/auth/issues/1612)) ([6ccd814](https://github.com/supabase/auth/commit/6ccd814309dca70a9e3585543887194b05d725d3))
* include factor_id in query ([#1702](https://github.com/supabase/auth/issues/1702)) ([ac14e82](https://github.com/supabase/auth/commit/ac14e82b33545466184da99e99b9d3fe5f3876d9))
* move is owned by check to load factor ([#1703](https://github.com/supabase/auth/issues/1703)) ([701a779](https://github.com/supabase/auth/commit/701a779cf092e777dd4ad4954dc650164b09ab32))
* refactor TOTP MFA into separate methods ([#1698](https://github.com/supabase/auth/issues/1698)) ([250d92f](https://github.com/supabase/auth/commit/250d92f9a18d38089d1bf262ef9088022a446965))
* remove check for content-length ([#1700](https://github.com/supabase/auth/issues/1700)) ([81b332d](https://github.com/supabase/auth/commit/81b332d2f48622008469d2c5a9b130465a65f2a3))
* remove FindFactorsByUser ([#1707](https://github.com/supabase/auth/issues/1707)) ([af8e2dd](https://github.com/supabase/auth/commit/af8e2dda15a1234a05e7d2d34d316eaa029e0912))
* update openapi spec for MFA (Phone)  ([#1689](https://github.com/supabase/auth/issues/1689)) ([a3da4b8](https://github.com/supabase/auth/commit/a3da4b89820c37f03ea128889616aca598d99f68))

## [2.158.0](https://github.com/supabase/auth/compare/v2.157.0...v2.158.0) (2024-07-31)


### Features

* add hook log entry with `run_hook` action ([#1684](https://github.com/supabase/auth/issues/1684)) ([46491b8](https://github.com/supabase/auth/commit/46491b867a4f5896494417391392a373a453fa5f))
* MFA (Phone) ([#1668](https://github.com/supabase/auth/issues/1668)) ([ae091aa](https://github.com/supabase/auth/commit/ae091aa942bdc5bc97481037508ec3bb4079d859))


### Bug Fixes

* maintain backward compatibility for asymmetric JWTs ([#1690](https://github.com/supabase/auth/issues/1690)) ([0ad1402](https://github.com/supabase/auth/commit/0ad1402444348e47e1e42be186b3f052d31be824))
* MFA NewFactor to default to creating unverfied factors ([#1692](https://github.com/supabase/auth/issues/1692)) ([3d448fa](https://github.com/supabase/auth/commit/3d448fa73cb77eb8511dbc47bfafecce4a4a2150))
* minor spelling errors ([#1688](https://github.com/supabase/auth/issues/1688)) ([6aca52b](https://github.com/supabase/auth/commit/6aca52b56f8a6254de7709c767b9a5649f1da248)), closes [#1682](https://github.com/supabase/auth/issues/1682)
* treat `GOTRUE_MFA_ENABLED` as meaning TOTP enabled on enroll and verify ([#1694](https://github.com/supabase/auth/issues/1694)) ([8015251](https://github.com/supabase/auth/commit/8015251400bd52cbdad3ea28afb83b1cdfe816dd))
* update mfa phone migration to be idempotent ([#1687](https://github.com/supabase/auth/issues/1687)) ([fdff1e7](https://github.com/supabase/auth/commit/fdff1e703bccf93217636266f1862bd0a9205edb))

## [2.157.0](https://github.com/supabase/auth/compare/v2.156.0...v2.157.0) (2024-07-26)


### Features

* add asymmetric jwt support ([#1674](https://github.com/supabase/auth/issues/1674)) ([c7a2be3](https://github.com/supabase/auth/commit/c7a2be347b301b666e99adc3d3fed78c5e287c82))

## [2.156.0](https://github.com/supabase/auth/compare/v2.155.6...v2.156.0) (2024-07-25)


### Features

* add is_anonymous claim to Auth hook jsonschema ([#1667](https://github.com/supabase/auth/issues/1667)) ([f9df65c](https://github.com/supabase/auth/commit/f9df65c91e226084abfa2e868ab6bab892d16d2f))


### Bug Fixes

* restrict autoconfirm email change to anonymous users ([#1679](https://github.com/supabase/auth/issues/1679)) ([b57e223](https://github.com/supabase/auth/commit/b57e2230102280ed873acf70be1aeb5a2f6f7a4f))

## [2.155.6](https://github.com/supabase/auth/compare/v2.155.5...v2.155.6) (2024-07-22)


### Bug Fixes

* use deep equal ([#1672](https://github.com/supabase/auth/issues/1672)) ([8efd57d](https://github.com/supabase/auth/commit/8efd57dab40346762a04bac61b314ce05d6fa69c))

## [2.155.5](https://github.com/supabase/auth/compare/v2.155.4...v2.155.5) (2024-07-19)


### Bug Fixes

* check password max length in checkPasswordStrength ([#1659](https://github.com/supabase/auth/issues/1659)) ([1858c93](https://github.com/supabase/auth/commit/1858c93bba6f5bc41e4c65489f12c1a0786a1f2b))
* don't update attribute mapping if nil ([#1665](https://github.com/supabase/auth/issues/1665)) ([7e67f3e](https://github.com/supabase/auth/commit/7e67f3edbf81766df297a66f52a8e472583438c6))
* refactor mfa models and add observability to loadFactor ([#1669](https://github.com/supabase/auth/issues/1669)) ([822fb93](https://github.com/supabase/auth/commit/822fb93faab325ba3d4bb628dff43381d68d0b5d))

## [2.155.4](https://github.com/supabase/auth/compare/v2.155.3...v2.155.4) (2024-07-17)


### Bug Fixes

* treat empty string as nil in `encrypted_password` ([#1663](https://github.com/supabase/auth/issues/1663)) ([f99286e](https://github.com/supabase/auth/commit/f99286eaed505daf3db6f381265ef6024e7e36d2))

## [2.155.3](https://github.com/supabase/auth/compare/v2.155.2...v2.155.3) (2024-07-12)


### Bug Fixes

* serialize jwt as string ([#1657](https://github.com/supabase/auth/issues/1657)) ([98d8324](https://github.com/supabase/auth/commit/98d83245e40d606438eb0afdbf474276179fd91d))

## [2.155.2](https://github.com/supabase/auth/compare/v2.155.1...v2.155.2) (2024-07-12)


### Bug Fixes

* improve session error logging ([#1655](https://github.com/supabase/auth/issues/1655)) ([5a6793e](https://github.com/supabase/auth/commit/5a6793ee8fce7a089750fe10b3b63bb0a19d6d21))
* omit empty string from name & use case-insensitive equality for comparing SAML attributes ([#1654](https://github.com/supabase/auth/issues/1654)) ([bf5381a](https://github.com/supabase/auth/commit/bf5381a6b1c686955dc4e39fe5fb806ffd309563))
* set rate limit log level to warn ([#1652](https://github.com/supabase/auth/issues/1652)) ([10ca9c8](https://github.com/supabase/auth/commit/10ca9c806e4b67a371897f1b3f93c515764c4240))

## [2.155.1](https://github.com/supabase/auth/compare/v2.155.0...v2.155.1) (2024-07-04)


### Bug Fixes

* apply mailer autoconfirm config to update user email ([#1646](https://github.com/supabase/auth/issues/1646)) ([a518505](https://github.com/supabase/auth/commit/a5185058e72509b0781e0eb59910ecdbb8676fee))
* check for empty aud string ([#1649](https://github.com/supabase/auth/issues/1649)) ([42c1d45](https://github.com/supabase/auth/commit/42c1d4526b98203664d4a22c23014ecd0b4951f9))
* return proper error if sms rate limit is exceeded ([#1647](https://github.com/supabase/auth/issues/1647)) ([3c8d765](https://github.com/supabase/auth/commit/3c8d7656431ac4b2e80726b7c37adb8f0c778495))

## [2.155.0](https://github.com/supabase/auth/compare/v2.154.2...v2.155.0) (2024-07-03)


### Features

* add `password_hash` and `id` fields to admin create user ([#1641](https://github.com/supabase/auth/issues/1641)) ([20d59f1](https://github.com/supabase/auth/commit/20d59f10b601577683d05bcd7d2128ff4bc462a0))


### Bug Fixes

* improve mfa verify logs ([#1635](https://github.com/supabase/auth/issues/1635)) ([d8b47f9](https://github.com/supabase/auth/commit/d8b47f9d3f0dc8f97ad1de49e45f452ebc726481))
* invited users should have a temporary password generated ([#1644](https://github.com/supabase/auth/issues/1644)) ([3f70d9d](https://github.com/supabase/auth/commit/3f70d9d8974d0e9c437c51e1312ad17ce9056ec9))
* upgrade golang-jwt to v5 ([#1639](https://github.com/supabase/auth/issues/1639)) ([2cb97f0](https://github.com/supabase/auth/commit/2cb97f080fa4695766985cc4792d09476534be68))
* use pointer for `user.EncryptedPassword` ([#1637](https://github.com/supabase/auth/issues/1637)) ([bbecbd6](https://github.com/supabase/auth/commit/bbecbd61a46b0c528b1191f48d51f166c06f4b16))

## [2.154.2](https://github.com/supabase/auth/compare/v2.154.1...v2.154.2) (2024-06-24)


### Bug Fixes

* publish to ghcr.io/supabase/auth ([#1626](https://github.com/supabase/auth/issues/1626)) ([930aa3e](https://github.com/supabase/auth/commit/930aa3edb633823d4510c2aff675672df06f1211)), closes [#1625](https://github.com/supabase/auth/issues/1625)
* revert define search path in auth functions ([#1634](https://github.com/supabase/auth/issues/1634)) ([155e87e](https://github.com/supabase/auth/commit/155e87ef8129366d665968f64d1fc66676d07e16))
* update MaxFrequency error message to reflect number of seconds ([#1540](https://github.com/supabase/auth/issues/1540)) ([e81c25d](https://github.com/supabase/auth/commit/e81c25d19551fdebfc5197d96bc220ddb0f8227b))

## [2.154.1](https://github.com/supabase/auth/compare/v2.154.0...v2.154.1) (2024-06-17)


### Bug Fixes

* add ip based limiter ([#1622](https://github.com/supabase/auth/issues/1622)) ([06464c0](https://github.com/supabase/auth/commit/06464c013571253d1f18f7ae5e840826c4bd84a7))
* admin user update should update is_anonymous field ([#1623](https://github.com/supabase/auth/issues/1623)) ([f5c6fcd](https://github.com/supabase/auth/commit/f5c6fcd9c3fee0f793f96880a8caebc5b5cb0916))

## [2.154.0](https://github.com/supabase/auth/compare/v2.153.0...v2.154.0) (2024-06-12)


### Features

* add max length check for email ([#1508](https://github.com/supabase/auth/issues/1508)) ([f9c13c0](https://github.com/supabase/auth/commit/f9c13c0ad5c556bede49d3e0f6e5f58ca26161c3))
* add support for Slack OAuth V2 ([#1591](https://github.com/supabase/auth/issues/1591)) ([bb99251](https://github.com/supabase/auth/commit/bb992519cdf7578dc02cd7de55e2e6aa09b4c0f3))
* encrypt sensitive columns ([#1593](https://github.com/supabase/auth/issues/1593)) ([e4a4758](https://github.com/supabase/auth/commit/e4a475820b2dc1f985bd37df15a8ab9e781626f5))
* upgrade otel to v1.26 ([#1585](https://github.com/supabase/auth/issues/1585)) ([cdd13ad](https://github.com/supabase/auth/commit/cdd13adec02eb0c9401bc55a2915c1005d50dea1))
* use largest avatar from spotify instead ([#1210](https://github.com/supabase/auth/issues/1210)) ([4f9994b](https://github.com/supabase/auth/commit/4f9994bf792c3887f2f45910b11a9c19ee3a896b)), closes [#1209](https://github.com/supabase/auth/issues/1209)


### Bug Fixes

* define search path in auth functions ([#1616](https://github.com/supabase/auth/issues/1616)) ([357bda2](https://github.com/supabase/auth/commit/357bda23cb2abd12748df80a9d27288aa548534d))
* enable rls & update grants for auth tables ([#1617](https://github.com/supabase/auth/issues/1617)) ([28967aa](https://github.com/supabase/auth/commit/28967aa4b5db2363cc581c9da0d64e974eb7b64c))

## [2.153.0](https://github.com/supabase/auth/compare/v2.152.0...v2.153.0) (2024-06-04)


### Features

* add SAML specific external URL config ([#1599](https://github.com/supabase/auth/issues/1599)) ([b352719](https://github.com/supabase/auth/commit/b3527190560381fafe9ba2fae4adc3b73703024a))
* add support for verifying argon2i and argon2id passwords ([#1597](https://github.com/supabase/auth/issues/1597)) ([55409f7](https://github.com/supabase/auth/commit/55409f797bea55068a3fafdddd6cfdb78feba1b4))
* make the email client explicity set the format to be HTML ([#1149](https://github.com/supabase/auth/issues/1149)) ([53e223a](https://github.com/supabase/auth/commit/53e223abdf29f4abcad13f99baf00daedcb00c3f))


### Bug Fixes

* call write header in write if not written ([#1598](https://github.com/supabase/auth/issues/1598)) ([0ef7eb3](https://github.com/supabase/auth/commit/0ef7eb30619d4c365e06a94a79b9cb0333d792da))
* deadlock issue with timeout middleware write ([#1595](https://github.com/supabase/auth/issues/1595)) ([6c9fbd4](https://github.com/supabase/auth/commit/6c9fbd4bd5623c729906fca7857ab508166a3056))
* improve token OIDC logging ([#1606](https://github.com/supabase/auth/issues/1606)) ([5262683](https://github.com/supabase/auth/commit/526268311844467664e89c8329e5aaee817dbbaf))
* update contributing to use v1.22 ([#1609](https://github.com/supabase/auth/issues/1609)) ([5894d9e](https://github.com/supabase/auth/commit/5894d9e41e7681512a9904ad47082a705e948c98))

## [2.152.0](https://github.com/supabase/auth/compare/v2.151.0...v2.152.0) (2024-05-22)


### Features

* new timeout writer implementation ([#1584](https://github.com/supabase/auth/issues/1584)) ([72614a1](https://github.com/supabase/auth/commit/72614a1fce27888f294772b512f8e31c55a36d87))
* remove legacy lookup in users for one_time_tokens (phase II) ([#1569](https://github.com/supabase/auth/issues/1569)) ([39ca026](https://github.com/supabase/auth/commit/39ca026035f6c61d206d31772c661b326c2a424c))
* update chi version ([#1581](https://github.com/supabase/auth/issues/1581)) ([c64ae3d](https://github.com/supabase/auth/commit/c64ae3dd775e8fb3022239252c31b4ee73893237))
* update openapi spec with identity and is_anonymous fields ([#1573](https://github.com/supabase/auth/issues/1573)) ([86a79df](https://github.com/supabase/auth/commit/86a79df9ecfcf09fda0b8e07afbc41154fbb7d9d))


### Bug Fixes

* improve logging structure ([#1583](https://github.com/supabase/auth/issues/1583)) ([c22fc15](https://github.com/supabase/auth/commit/c22fc15d2a8383e95a2364f383dfa7dce5f5df88))
* sms verify should update is_anonymous field ([#1580](https://github.com/supabase/auth/issues/1580)) ([e5f98cb](https://github.com/supabase/auth/commit/e5f98cb9e24ecebb0b7dc88c495fd456cc73fcba))
* use api_external_url domain as localname ([#1575](https://github.com/supabase/auth/issues/1575)) ([ed2b490](https://github.com/supabase/auth/commit/ed2b4907244281e4c54aaef74b1f4c8a8e3d97c9))

## [2.151.0](https://github.com/supabase/auth/compare/v2.150.1...v2.151.0) (2024-05-06)


### Features

* refactor one-time tokens for performance ([#1558](https://github.com/supabase/auth/issues/1558)) ([d1cf8d9](https://github.com/supabase/auth/commit/d1cf8d9096e9183d7772b73031de8ecbd66e912b))


### Bug Fixes

* do call send sms hook when SMS autoconfirm is enabled ([#1562](https://github.com/supabase/auth/issues/1562)) ([bfe4d98](https://github.com/supabase/auth/commit/bfe4d988f3768b0407526bcc7979fb21d8cbebb3))
* format test otps ([#1567](https://github.com/supabase/auth/issues/1567)) ([434a59a](https://github.com/supabase/auth/commit/434a59ae387c35fd6629ec7c674d439537e344e5))
* log final writer error instead of handling ([#1564](https://github.com/supabase/auth/issues/1564)) ([170bd66](https://github.com/supabase/auth/commit/170bd6615405afc852c7107f7358dfc837bad737))

## [2.150.1](https://github.com/supabase/auth/compare/v2.150.0...v2.150.1) (2024-04-28)


### Bug Fixes

* add db conn max idle time setting ([#1555](https://github.com/supabase/auth/issues/1555)) ([2caa7b4](https://github.com/supabase/auth/commit/2caa7b4d75d2ff54af20f3e7a30a8eeec8cbcda9))

## [2.150.0](https://github.com/supabase/auth/compare/v2.149.0...v2.150.0) (2024-04-25)


### Features

* add support for Azure CIAM login ([#1541](https://github.com/supabase/auth/issues/1541)) ([1cb4f96](https://github.com/supabase/auth/commit/1cb4f96bdc7ef3ef995781b4cf3c4364663a2bf3))
* add timeout middleware ([#1529](https://github.com/supabase/auth/issues/1529)) ([f96ff31](https://github.com/supabase/auth/commit/f96ff31040b28e3a7373b4fd41b7334eda1b413e))
* allow for postgres and http functions on each extensibility point ([#1528](https://github.com/supabase/auth/issues/1528)) ([348a1da](https://github.com/supabase/auth/commit/348a1daee24f6e44b14c018830b748e46d34b4c2))
* merge provider metadata on link account ([#1552](https://github.com/supabase/auth/issues/1552)) ([bd8b5c4](https://github.com/supabase/auth/commit/bd8b5c41dd544575e1a52ccf1ef3f0fdee67458c))
* send over user in SendSMS Hook instead of UserID ([#1551](https://github.com/supabase/auth/issues/1551)) ([d4d743c](https://github.com/supabase/auth/commit/d4d743c2ae9490e1b3249387e3b0d60df6913c68))


### Bug Fixes

* return error if session id does not exist ([#1538](https://github.com/supabase/auth/issues/1538)) ([91e9eca](https://github.com/supabase/auth/commit/91e9ecabe33a1c022f8e82a6050c22a7ca42de48))

## [2.149.0](https://github.com/supabase/auth/compare/v2.148.0...v2.149.0) (2024-04-15)


### Features

* refactor generate accesss token to take in request ([#1531](https://github.com/supabase/auth/issues/1531)) ([e4f2b59](https://github.com/supabase/auth/commit/e4f2b59e8e1f8158b6461a384349f1a32cc1bf9a))


### Bug Fixes

* linkedin_oidc provider error ([#1534](https://github.com/supabase/auth/issues/1534)) ([4f5e8e5](https://github.com/supabase/auth/commit/4f5e8e5120531e5a103fbdda91b51cabcb4e1a8c))
* revert patch for linkedin_oidc provider error ([#1535](https://github.com/supabase/auth/issues/1535)) ([58ef4af](https://github.com/supabase/auth/commit/58ef4af0b4224b78cd9e59428788d16a8d31e562))
* update linkedin issuer url ([#1536](https://github.com/supabase/auth/issues/1536)) ([10d6d8b](https://github.com/supabase/auth/commit/10d6d8b1eafa504da2b2a351d1f64a3a832ab1b9))

## [2.148.0](https://github.com/supabase/auth/compare/v2.147.1...v2.148.0) (2024-04-10)


### Features

* add array attribute mapping for SAML ([#1526](https://github.com/supabase/auth/issues/1526)) ([7326285](https://github.com/supabase/auth/commit/7326285c8af5c42e5c0c2d729ab224cf33ac3a1f))

## [2.147.1](https://github.com/supabase/auth/compare/v2.147.0...v2.147.1) (2024-04-09)


### Bug Fixes

* add validation and proper decoding on send email hook ([#1520](https://github.com/supabase/auth/issues/1520)) ([e19e762](https://github.com/supabase/auth/commit/e19e762e3e29729a1d1164c65461427822cc87f1))
* remove deprecated LogoutAllRefreshTokens ([#1519](https://github.com/supabase/auth/issues/1519)) ([35533ea](https://github.com/supabase/auth/commit/35533ea100669559e1209ecc7b091db3657234d9))

## [2.147.0](https://github.com/supabase/auth/compare/v2.146.0...v2.147.0) (2024-04-05)


### Features

* add send email Hook ([#1512](https://github.com/supabase/auth/issues/1512)) ([cf42e02](https://github.com/supabase/auth/commit/cf42e02ec63779f52b1652a7413f64994964c82d))

## [2.146.0](https://github.com/supabase/auth/compare/v2.145.0...v2.146.0) (2024-04-03)


### Features

* add custom sms hook ([#1474](https://github.com/supabase/auth/issues/1474)) ([0f6b29a](https://github.com/supabase/auth/commit/0f6b29a46f1dcbf92aa1f7cb702f42e7640f5f93))
* forbid generating an access token without a session ([#1504](https://github.com/supabase/auth/issues/1504)) ([795e93d](https://github.com/supabase/auth/commit/795e93d0afbe94bcd78489a3319a970b7bf8e8bc))


### Bug Fixes

* add cleanup statement for anonymous users ([#1497](https://github.com/supabase/auth/issues/1497)) ([cf2372a](https://github.com/supabase/auth/commit/cf2372a177796b829b72454e7491ce768bf5a42f))
* generate signup link should not error ([#1514](https://github.com/supabase/auth/issues/1514)) ([4fc3881](https://github.com/supabase/auth/commit/4fc388186ac7e7a9a32ca9b963a83d6ac2eb7603))
* move all EmailActionTypes to mailer package ([#1510](https://github.com/supabase/auth/issues/1510)) ([765db08](https://github.com/supabase/auth/commit/765db08582669a1b7f054217fa8f0ed45804c0b5))
* refactor mfa and aal update methods ([#1503](https://github.com/supabase/auth/issues/1503)) ([31a5854](https://github.com/supabase/auth/commit/31a585429bf248aa919d94c82c7c9e0c1c695461))
* rename from CustomSMSProvider to SendSMS ([#1513](https://github.com/supabase/auth/issues/1513)) ([c0bc37b](https://github.com/supabase/auth/commit/c0bc37b44effaebb62ba85102f072db07fe57e48))

## [2.145.0](https://github.com/supabase/gotrue/compare/v2.144.0...v2.145.0) (2024-03-26)


### Features

* add error codes ([#1377](https://github.com/supabase/gotrue/issues/1377)) ([e4beea1](https://github.com/supabase/gotrue/commit/e4beea1cdb80544b0581f1882696a698fdf64938))
* add kakao OIDC ([#1381](https://github.com/supabase/gotrue/issues/1381)) ([b5566e7](https://github.com/supabase/gotrue/commit/b5566e7ac001cc9f2bac128de0fcb908caf3a5ed))
* clean up expired factors ([#1371](https://github.com/supabase/gotrue/issues/1371)) ([5c94207](https://github.com/supabase/gotrue/commit/5c9420743a9aef0675f823c30aa4525b4933836e))
* configurable NameID format for SAML provider ([#1481](https://github.com/supabase/gotrue/issues/1481)) ([ef405d8](https://github.com/supabase/gotrue/commit/ef405d89e69e008640f275bc37f8ec02ad32da40))
* HTTP Hook - Add custom envconfig decoding for HTTP Hook Secrets ([#1467](https://github.com/supabase/gotrue/issues/1467)) ([5b24c4e](https://github.com/supabase/gotrue/commit/5b24c4eb05b2b52c4177d5f41cba30cb68495c8c))
* refactor PKCE FlowState to reduce duplicate code ([#1446](https://github.com/supabase/gotrue/issues/1446)) ([b8d0337](https://github.com/supabase/gotrue/commit/b8d0337922c6712380f6dc74f7eac9fb71b1ae48))


### Bug Fixes

* add http support for https hooks on localhost ([#1484](https://github.com/supabase/gotrue/issues/1484)) ([5c04104](https://github.com/supabase/gotrue/commit/5c04104bf77a9c2db46d009764ec3ec3e484fc09))
* cleanup panics due to bad inactivity timeout code ([#1471](https://github.com/supabase/gotrue/issues/1471)) ([548edf8](https://github.com/supabase/gotrue/commit/548edf898161c9ba9a136fc99ec2d52a8ba1f856))
* **docs:** remove bracket on file name for broken link ([#1493](https://github.com/supabase/gotrue/issues/1493)) ([96f7a68](https://github.com/supabase/gotrue/commit/96f7a68a5479825e31106c2f55f82d5b2c007c0f))
* impose expiry on auth code instead of magic link ([#1440](https://github.com/supabase/gotrue/issues/1440)) ([35aeaf1](https://github.com/supabase/gotrue/commit/35aeaf1b60dd27a22662a6d1955d60cc907b55dd))
* invalidate email, phone OTPs on password change ([#1489](https://github.com/supabase/gotrue/issues/1489)) ([960a4f9](https://github.com/supabase/gotrue/commit/960a4f94f5500e33a0ec2f6afe0380bbc9562500))
* move creation of flow state into function ([#1470](https://github.com/supabase/gotrue/issues/1470)) ([4392a08](https://github.com/supabase/gotrue/commit/4392a08d68d18828005d11382730117a7b143635))
* prevent user email side-channel leak on verify ([#1472](https://github.com/supabase/gotrue/issues/1472)) ([311cde8](https://github.com/supabase/gotrue/commit/311cde8d1e82f823ae26a341e068034d60273864))
* refactor email sending functions ([#1495](https://github.com/supabase/gotrue/issues/1495)) ([285c290](https://github.com/supabase/gotrue/commit/285c290adf231fea7ca1dff954491dc427cf18e2))
* refactor factor_test to centralize setup ([#1473](https://github.com/supabase/gotrue/issues/1473)) ([c86007e](https://github.com/supabase/gotrue/commit/c86007e59684334b5e8c2285c36094b6eec89442))
* refactor mfa challenge and tests ([#1469](https://github.com/supabase/gotrue/issues/1469)) ([6c76f21](https://github.com/supabase/gotrue/commit/6c76f21cee5dbef0562c37df6a546939affb2f8d))
* Resend SMS when duplicate SMS sign ups are made ([#1490](https://github.com/supabase/gotrue/issues/1490)) ([73240a0](https://github.com/supabase/gotrue/commit/73240a0b096977703e3c7d24a224b5641ce47c81))
* unlink identity bugs ([#1475](https://github.com/supabase/gotrue/issues/1475)) ([73e8d87](https://github.com/supabase/gotrue/commit/73e8d8742de3575b3165a707b5d2f486b2598d9d))

## [2.144.0](https://github.com/supabase/gotrue/compare/v2.143.0...v2.144.0) (2024-03-04)


### Features

* add configuration for custom sms sender hook ([#1428](https://github.com/supabase/gotrue/issues/1428)) ([1ea56b6](https://github.com/supabase/gotrue/commit/1ea56b62d47edb0766d9e445406ecb43d387d920))
* anonymous sign-ins  ([#1460](https://github.com/supabase/gotrue/issues/1460)) ([130df16](https://github.com/supabase/gotrue/commit/130df165270c69c8e28aaa1b9421342f997c1ff3))
* clean up test setup in MFA tests ([#1452](https://github.com/supabase/gotrue/issues/1452)) ([7185af8](https://github.com/supabase/gotrue/commit/7185af8de4a269cdde2629054d222333d3522ebe))
* pass transaction to `invokeHook`, fixing pool exhaustion ([#1465](https://github.com/supabase/gotrue/issues/1465)) ([b536d36](https://github.com/supabase/gotrue/commit/b536d368f35adb31f937169e3f093d28352fa7be))
* refactor resource owner password grant ([#1443](https://github.com/supabase/gotrue/issues/1443)) ([e63ad6f](https://github.com/supabase/gotrue/commit/e63ad6ff0f67d9a83456918a972ecb5109125628))
* use dummy instance id to improve performance on refresh token queries ([#1454](https://github.com/supabase/gotrue/issues/1454)) ([656474e](https://github.com/supabase/gotrue/commit/656474e1b9ff3d5129190943e8c48e456625afe5))


### Bug Fixes

* expose `provider` under `amr` in access token ([#1456](https://github.com/supabase/gotrue/issues/1456)) ([e9f38e7](https://github.com/supabase/gotrue/commit/e9f38e76d8a7b93c5c2bb0de918a9b156155f018))
* improve MFA QR Code resilience so as to support providers like 1Password ([#1455](https://github.com/supabase/gotrue/issues/1455)) ([6522780](https://github.com/supabase/gotrue/commit/652278046c9dd92f5cecd778735b058ef3fb41c7))
* refactor request params to use generics ([#1464](https://github.com/supabase/gotrue/issues/1464)) ([e1cdf5c](https://github.com/supabase/gotrue/commit/e1cdf5c4b5c1bf467094f4bdcaa2e42a5cc51c20))
* revert refactor resource owner password grant ([#1466](https://github.com/supabase/gotrue/issues/1466)) ([fa21244](https://github.com/supabase/gotrue/commit/fa21244fa929709470c2e1fc4092a9ce947399e7))
* update file name so migration to Drop IP Address is applied ([#1447](https://github.com/supabase/gotrue/issues/1447)) ([f29e89d](https://github.com/supabase/gotrue/commit/f29e89d7d2c48ee8fd5bf8279a7fa3db0ad4d842))

## [2.143.0](https://github.com/supabase/gotrue/compare/v2.142.0...v2.143.0) (2024-02-19)


### Features

* calculate aal without transaction ([#1437](https://github.com/supabase/gotrue/issues/1437)) ([8dae661](https://github.com/supabase/gotrue/commit/8dae6614f1a2b58819f94894cef01e9f99117769))


### Bug Fixes

* deprecate hooks  ([#1421](https://github.com/supabase/gotrue/issues/1421)) ([effef1b](https://github.com/supabase/gotrue/commit/effef1b6ecc448b7927eff23df8d5b509cf16b5c))
* error should be an IsNotFoundError ([#1432](https://github.com/supabase/gotrue/issues/1432)) ([7f40047](https://github.com/supabase/gotrue/commit/7f40047aec3577d876602444b1d88078b2237d66))
* populate password verification attempt hook ([#1436](https://github.com/supabase/gotrue/issues/1436)) ([f974bdb](https://github.com/supabase/gotrue/commit/f974bdb58340395955ca27bdd26d57062433ece9))
* restrict mfa enrollment to aal2 if verified factors are present ([#1439](https://github.com/supabase/gotrue/issues/1439)) ([7e10d45](https://github.com/supabase/gotrue/commit/7e10d45e54010d38677f4c3f2f224127688eb9a2))
* update phone if autoconfirm is enabled ([#1431](https://github.com/supabase/gotrue/issues/1431)) ([95db770](https://github.com/supabase/gotrue/commit/95db770c5d2ecca4a1e960a8cb28ded37cccc100))
* use email change email in identity ([#1429](https://github.com/supabase/gotrue/issues/1429)) ([4d3b9b8](https://github.com/supabase/gotrue/commit/4d3b9b8841b1a5fa8f3244825153cc81a73ba300))

## [2.142.0](https://github.com/supabase/gotrue/compare/v2.141.0...v2.142.0) (2024-02-14)


### Features

* alter tag to use raw ([#1427](https://github.com/supabase/gotrue/issues/1427)) ([53cfe5d](https://github.com/supabase/gotrue/commit/53cfe5de57d4b5ab6e8e2915493856ecd96f4ede))
* update README.md to trigger release ([#1425](https://github.com/supabase/gotrue/issues/1425)) ([91e0e24](https://github.com/supabase/gotrue/commit/91e0e245f5957ebce13370f79fd4a6be8108ed80))

## [2.141.0](https://github.com/supabase/gotrue/compare/v2.140.0...v2.141.0) (2024-02-13)


### Features

* drop sha hash tag ([#1422](https://github.com/supabase/gotrue/issues/1422)) ([76853ce](https://github.com/supabase/gotrue/commit/76853ce6d45064de5608acc8100c67a8337ba791))
* prefix release with v ([#1424](https://github.com/supabase/gotrue/issues/1424)) ([9d398cd](https://github.com/supabase/gotrue/commit/9d398cd75fca01fb848aa88b4f545552e8b5751a))

## [2.140.0](https://github.com/supabase/gotrue/compare/v2.139.2...v2.140.0) (2024-02-13)


### Features

* deprecate existing webhook implementation ([#1417](https://github.com/supabase/gotrue/issues/1417)) ([5301e48](https://github.com/supabase/gotrue/commit/5301e481b0c7278c18b4578a5b1aa8d2256c2f5d))
* update publish.yml checkout repository so there is access to Dockerfile ([#1419](https://github.com/supabase/gotrue/issues/1419)) ([7cce351](https://github.com/supabase/gotrue/commit/7cce3518e8c9f1f3f93e4f6a0658ee08771c4f1c))

## [2.139.2](https://github.com/supabase/gotrue/compare/v2.139.1...v2.139.2) (2024-02-08)


### Bug Fixes

* improve perf in account linking ([#1394](https://github.com/supabase/gotrue/issues/1394)) ([8eedb95](https://github.com/supabase/gotrue/commit/8eedb95dbaa310aac464645ec91d6a374813ab89))
* OIDC provider validation log message ([#1380](https://github.com/supabase/gotrue/issues/1380)) ([27e6b1f](https://github.com/supabase/gotrue/commit/27e6b1f9a4394c5c4f8dff9a8b5529db1fc67af9))
* only create or update the email / phone identity after it's been verified ([#1403](https://github.com/supabase/gotrue/issues/1403)) ([2d20729](https://github.com/supabase/gotrue/commit/2d207296ec22dd6c003c89626d255e35441fd52d))
* only create or update the email / phone identity after it's been verified (again) ([#1409](https://github.com/supabase/gotrue/issues/1409)) ([bc6a5b8](https://github.com/supabase/gotrue/commit/bc6a5b884b43fe6b8cb924d3f79999fe5bfe7c5f))
* unmarshal is_private_email correctly ([#1402](https://github.com/supabase/gotrue/issues/1402)) ([47df151](https://github.com/supabase/gotrue/commit/47df15113ce8d86666c0aba3854954c24fe39f7f))
* use `pattern` for semver docker image tags ([#1411](https://github.com/supabase/gotrue/issues/1411)) ([14a3aeb](https://github.com/supabase/gotrue/commit/14a3aeb6c3f46c8d38d98cc840112dfd0278eeda))


### Reverts

* "fix: only create or update the email / phone identity after i… ([#1407](https://github.com/supabase/gotrue/issues/1407)) ([ff86849](https://github.com/supabase/gotrue/commit/ff868493169a0d9ac18b66058a735197b1df5b9b))

# Changelog

## [2.143.1](https://github.com/supabase/gotrue/compare/v2.143.0...v2.143.1) (2024-02-26)


### Bug Fixes

* expose `provider` under `amr` in access token ([#1457](https://github.com/supabase/gotrue/issues/1457)) ([3ffae78](https://github.com/supabase/gotrue/commit/3ffae785f8e0e2f474943add1830e50dbe851647))

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

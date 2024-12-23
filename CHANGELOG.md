# Changelog

## [2.165.2](https://github.com/supabase/auth/compare/v2.165.1...v2.165.2) (2024-12-23)


### Features

* add `GOTRUE_&lt;PROVIDER&gt;_SKIP_NONCE_CHECK` to skip nonce checks in ODIC flow ([#1264](https://github.com/supabase/auth/issues/1264)) ([4291959](https://github.com/supabase/auth/commit/4291959c4057332633265745073d26dc0e548898))
* add `kid`, `iss`, `iat` claims to the JWT ([#1148](https://github.com/supabase/auth/issues/1148)) ([3446197](https://github.com/supabase/auth/commit/34461975d04ddfa1ba3b6534600b9b6eb55a7832))
* add `password_hash` and `id` fields to admin create user ([#1641](https://github.com/supabase/auth/issues/1641)) ([20d59f1](https://github.com/supabase/auth/commit/20d59f10b601577683d05bcd7d2128ff4bc462a0))
* add `x-sb-error-code` header, show error code in logs ([#1765](https://github.com/supabase/auth/issues/1765)) ([ed91c59](https://github.com/supabase/auth/commit/ed91c59aa332738bd0ac4b994aeec2cdf193a068))
* add array attribute mapping for SAML ([#1526](https://github.com/supabase/auth/issues/1526)) ([7326285](https://github.com/supabase/auth/commit/7326285c8af5c42e5c0c2d729ab224cf33ac3a1f))
* add asymmetric jwt support ([#1674](https://github.com/supabase/auth/issues/1674)) ([c7a2be3](https://github.com/supabase/auth/commit/c7a2be347b301b666e99adc3d3fed78c5e287c82))
* add authorized email address support ([#1757](https://github.com/supabase/auth/issues/1757)) ([f3a28d1](https://github.com/supabase/auth/commit/f3a28d182d193cf528cc72a985dfeaf7ecb67056))
* add cleanup for session timebox and inactivity timeout ([#1298](https://github.com/supabase/auth/issues/1298)) ([9226979](https://github.com/supabase/auth/commit/92269796c7cb515f4c1e905220c1a1fd8c6764d5))
* add cleanup of unverified factors in 24 hour window ([#1379](https://github.com/supabase/auth/issues/1379)) ([0100a80](https://github.com/supabase/auth/commit/0100a80aa2a0e22a4ce0f281079a900cd06c1df0))
* add configuration for custom sms sender hook ([#1428](https://github.com/supabase/auth/issues/1428)) ([1ea56b6](https://github.com/supabase/auth/commit/1ea56b62d47edb0766d9e445406ecb43d387d920))
* add CORS allowed headers config ([#1197](https://github.com/supabase/auth/issues/1197)) ([7134000](https://github.com/supabase/auth/commit/71340009d9ed9cdc102f57bf7a6e1d96bea8d70c))
* add custom access token hook ([#1332](https://github.com/supabase/auth/issues/1332)) ([312f871](https://github.com/supabase/auth/commit/312f871614438245aa11ca8cde34b2500611de52))
* add custom sms hook ([#1474](https://github.com/supabase/auth/issues/1474)) ([0f6b29a](https://github.com/supabase/auth/commit/0f6b29a46f1dcbf92aa1f7cb702f42e7640f5f93))
* add database cleanup logic, runs after each request ([#875](https://github.com/supabase/auth/issues/875)) ([aaad5bd](https://github.com/supabase/auth/commit/aaad5bd813487062ca5e64de08c55a666b62219d))
* add different logout scopes ([#1112](https://github.com/supabase/auth/issues/1112)) ([df07540](https://github.com/supabase/auth/commit/df075408fbbde2179fd449d98841b4329b3798f3))
* add email rate limit breach metric ([#1208](https://github.com/supabase/auth/issues/1208)) ([4ff1fe0](https://github.com/supabase/auth/commit/4ff1fe058cfab418c445808004091e89dcf87124))
* add email validation function to lower bounce rates ([#1845](https://github.com/supabase/auth/issues/1845)) ([2c291f0](https://github.com/supabase/auth/commit/2c291f0356f3e91063b6b43bf2a21625b0ce0ebd))
* add endpoint to unlink identity from user ([#1315](https://github.com/supabase/auth/issues/1315)) ([af83b34](https://github.com/supabase/auth/commit/af83b34850dfe7d983a41a8fb5d02d325ee72985))
* add error codes ([#1377](https://github.com/supabase/auth/issues/1377)) ([e4beea1](https://github.com/supabase/auth/commit/e4beea1cdb80544b0581f1882696a698fdf64938))
* add Figma provider ([#1139](https://github.com/supabase/auth/issues/1139)) ([007324c](https://github.com/supabase/auth/commit/007324cb9607095eadd09a45fd52a37035959bb0))
* add fly oauth provider ([#1261](https://github.com/supabase/auth/issues/1261)) ([0fe4285](https://github.com/supabase/auth/commit/0fe4285873cea1f6815170a2da1589838b66d8af))
* add friendly name to enroll factor response ([#1277](https://github.com/supabase/auth/issues/1277)) ([3c72faf](https://github.com/supabase/auth/commit/3c72faf2b6c83d16f5a438d106c07fe40ec5f49e))
* add haveibeenpwned.org password strength check ([#1324](https://github.com/supabase/auth/issues/1324)) ([c3acfe7](https://github.com/supabase/auth/commit/c3acfe7cf4d17a3fdf98bd6376cd9a4ae645564b))
* add hook log entry with `run_hook` action ([#1684](https://github.com/supabase/auth/issues/1684)) ([46491b8](https://github.com/supabase/auth/commit/46491b867a4f5896494417391392a373a453fa5f))
* add idempotent refresh token algorithm ([#1278](https://github.com/supabase/auth/issues/1278)) ([b0426c6](https://github.com/supabase/auth/commit/b0426c6b7cfc3060ff0efa72e9d70a574e1f3ab6))
* add inactivity-timeout to sessions ([#1288](https://github.com/supabase/auth/issues/1288)) ([6c8a96e](https://github.com/supabase/auth/commit/6c8a96e39190e1d499ab667fcd24bed2b2fa01c8))
* add index on user_id of mfa_factors ([#1247](https://github.com/supabase/auth/issues/1247)) ([6ea135a](https://github.com/supabase/auth/commit/6ea135aa5e6745ff7cbd2e2df242218a66025ca8))
* add is_anonymous claim to Auth hook jsonschema ([#1667](https://github.com/supabase/auth/issues/1667)) ([f9df65c](https://github.com/supabase/auth/commit/f9df65c91e226084abfa2e868ab6bab892d16d2f))
* add kakao OIDC ([#1381](https://github.com/supabase/auth/issues/1381)) ([b5566e7](https://github.com/supabase/auth/commit/b5566e7ac001cc9f2bac128de0fcb908caf3a5ed))
* add log entries for pkce ([#1068](https://github.com/supabase/auth/issues/1068)) ([9c3ba87](https://github.com/supabase/auth/commit/9c3ba87d43fb0a7c77caa1d4decfa39b076d5d2c))
* add mail header support via `GOTRUE_SMTP_HEADERS` with `$messageType` ([#1804](https://github.com/supabase/auth/issues/1804)) ([99d6a13](https://github.com/supabase/auth/commit/99d6a134c44554a8ad06695e1dff54c942c8335d))
* add manual linking APIs ([#1317](https://github.com/supabase/auth/issues/1317)) ([80172a1](https://github.com/supabase/auth/commit/80172a1ff4921b9c1b81d7cef8edd23a065c2469))
* add max length check for email ([#1508](https://github.com/supabase/auth/issues/1508)) ([f9c13c0](https://github.com/supabase/auth/commit/f9c13c0ad5c556bede49d3e0f6e5f58ca26161c3))
* add mfa cleanup ([#1105](https://github.com/supabase/auth/issues/1105)) ([f5c9afb](https://github.com/supabase/auth/commit/f5c9afb81fa1dd039e4bb285ed744beda5dbae05))
* add MFA for WebAuthn ([#1775](https://github.com/supabase/auth/issues/1775)) ([8cc2f0e](https://github.com/supabase/auth/commit/8cc2f0e14d06d0feb56b25a0278fda9e213b6b5a))
* add mfa verification postgres hook ([#1314](https://github.com/supabase/auth/issues/1314)) ([db344d5](https://github.com/supabase/auth/commit/db344d54a5d433dd240a731b0b3974da37cfbe9b))
* Add new Kakao Provider ([#834](https://github.com/supabase/auth/issues/834)) ([bafb89b](https://github.com/supabase/auth/commit/bafb89b657253bca600d2cc4ad99bb992bc69298))
* add new Linkedin OIDC due to deprecated scopes for new linkedin applications ([#1248](https://github.com/supabase/auth/issues/1248)) ([f40acfe](https://github.com/supabase/auth/commit/f40acfe3d1f852dd806797c00997a4e04949ff51))
* add option to disable magic links ([#1756](https://github.com/supabase/auth/issues/1756)) ([2ad0737](https://github.com/supabase/auth/commit/2ad07373aa9239eba94abdabbb01c9abfa8c48de))
* add pkce recovery  ([#1022](https://github.com/supabase/auth/issues/1022)) ([1954560](https://github.com/supabase/auth/commit/19545601676675a923bb9850499717e89cf91a0b))
* add pkce to email_change routes ([#1082](https://github.com/supabase/auth/issues/1082)) ([0f8548f](https://github.com/supabase/auth/commit/0f8548fee9471fcfada0744f41ffa151b7e1731d))
* add required characters password strength check ([#1323](https://github.com/supabase/auth/issues/1323)) ([3991bdb](https://github.com/supabase/auth/commit/3991bdb269f72756becfacee5bd9e540c5b71250))
* add saml metadata force update every 24 hours ([#1020](https://github.com/supabase/auth/issues/1020)) ([965feb9](https://github.com/supabase/auth/commit/965feb943060d35f8817616288609833d7ad6129))
* add SAML specific external URL config ([#1599](https://github.com/supabase/auth/issues/1599)) ([b352719](https://github.com/supabase/auth/commit/b3527190560381fafe9ba2fae4adc3b73703024a))
* add send email Hook ([#1512](https://github.com/supabase/auth/issues/1512)) ([cf42e02](https://github.com/supabase/auth/commit/cf42e02ec63779f52b1652a7413f64994964c82d))
* add session id to required claim for output of custom access token hook ([#1360](https://github.com/supabase/auth/issues/1360)) ([31222d5](https://github.com/supabase/auth/commit/31222d5ad997bad1ea4e6509480c15eab8f4745a))
* add single session per user with tags support ([#1297](https://github.com/supabase/auth/issues/1297)) ([69feebc](https://github.com/supabase/auth/commit/69feebc43358f3462c527c2b5b777235e1e804bd))
* add sso pkce ([#1137](https://github.com/supabase/auth/issues/1137)) ([2c0e0a1](https://github.com/supabase/auth/commit/2c0e0a1e44b073770e02b101a357e80a11ba5b6e))
* add support for Azure CIAM login ([#1541](https://github.com/supabase/auth/issues/1541)) ([1cb4f96](https://github.com/supabase/auth/commit/1cb4f96bdc7ef3ef995781b4cf3c4364663a2bf3))
* add support for migration of firebase scrypt passwords ([#1768](https://github.com/supabase/auth/issues/1768)) ([ba00f75](https://github.com/supabase/auth/commit/ba00f75c28d6708ddf8ee151ce18f2d6193689ef))
* add support for saml encrypted assertions ([#1752](https://github.com/supabase/auth/issues/1752)) ([c5480ef](https://github.com/supabase/auth/commit/c5480ef83248ec2e7e3d3d87f92f43f17161ed25))
* add support for Slack OAuth V2 ([#1591](https://github.com/supabase/auth/issues/1591)) ([bb99251](https://github.com/supabase/auth/commit/bb992519cdf7578dc02cd7de55e2e6aa09b4c0f3))
* add support for Twilio Verify ([#1124](https://github.com/supabase/auth/issues/1124)) ([7e240f8](https://github.com/supabase/auth/commit/7e240f8b4112f7bf736e94b7cd8b6439f24af49b))
* add support for verifying argon2i and argon2id passwords ([#1597](https://github.com/supabase/auth/issues/1597)) ([55409f7](https://github.com/supabase/auth/commit/55409f797bea55068a3fafdddd6cfdb78feba1b4))
* add test OTP support for mobile app reviews ([#1166](https://github.com/supabase/auth/issues/1166)) ([2fb0cf5](https://github.com/supabase/auth/commit/2fb0cf54d3e390abd23dcf19fdc6db2b46f43adb))
* add time-boxed sessions ([#1286](https://github.com/supabase/auth/issues/1286)) ([9a1f461](https://github.com/supabase/auth/commit/9a1f4613eb3e6dd2af3ce76b07256fd80ddbc708))
* add timeout middleware ([#1529](https://github.com/supabase/auth/issues/1529)) ([f96ff31](https://github.com/supabase/auth/commit/f96ff31040b28e3a7373b4fd41b7334eda1b413e))
* add turnstile support ([#1094](https://github.com/supabase/auth/issues/1094)) ([b1d2f1c](https://github.com/supabase/auth/commit/b1d2f1c75fb1c38d1e3fa42a8b716d4c593226a2))
* add weak password check on sign in ([#1346](https://github.com/supabase/auth/issues/1346)) ([8785527](https://github.com/supabase/auth/commit/8785527a166fb2614abf99d3f2f911b1579721c2))
* add webauthn configuration variables ([#1773](https://github.com/supabase/auth/issues/1773)) ([77d5897](https://github.com/supabase/auth/commit/77d58976ae624dbb7f8abee041dd4557aab81109))
* allow `POST /verify` to accept a token hash ([#1165](https://github.com/supabase/auth/issues/1165)) ([e9ab555](https://github.com/supabase/auth/commit/e9ab55559f7e5e62f7a56005347993e4e9da527b))
* allow `whatsapp` channels with Twilio Verify ([#1207](https://github.com/supabase/auth/issues/1207)) ([ff98d2f](https://github.com/supabase/auth/commit/ff98d2fc43f4069b911a3037b338d283048ab92e))
* allow for postgres and http functions on each extensibility point ([#1528](https://github.com/supabase/auth/issues/1528)) ([348a1da](https://github.com/supabase/auth/commit/348a1daee24f6e44b14c018830b748e46d34b4c2))
* allow unverified email signins ([#1301](https://github.com/supabase/auth/issues/1301)) ([94293b7](https://github.com/supabase/auth/commit/94293b72b829436308050be5399069976b810cdb))
* allow updating saml providers `metadata_xml` ([#1096](https://github.com/supabase/auth/issues/1096)) ([20e503e](https://github.com/supabase/auth/commit/20e503e3b41f8a7a699c83ff4fca6cb78c4c314f))
* alter tag to use raw ([#1427](https://github.com/supabase/auth/issues/1427)) ([53cfe5d](https://github.com/supabase/auth/commit/53cfe5de57d4b5ab6e8e2915493856ecd96f4ede))
* anonymous sign-ins  ([#1460](https://github.com/supabase/auth/issues/1460)) ([130df16](https://github.com/supabase/auth/commit/130df165270c69c8e28aaa1b9421342f997c1ff3))
* azure oidc fix ([#1349](https://github.com/supabase/auth/issues/1349)) ([97b3595](https://github.com/supabase/auth/commit/97b359522d7bf5a314fe615a1abadbf493a4fc98))
* calculate aal without transaction ([#1437](https://github.com/supabase/auth/issues/1437)) ([8dae661](https://github.com/supabase/auth/commit/8dae6614f1a2b58819f94894cef01e9f99117769))
* clean up expired factors ([#1371](https://github.com/supabase/auth/issues/1371)) ([5c94207](https://github.com/supabase/auth/commit/5c9420743a9aef0675f823c30aa4525b4933836e))
* clean up test setup in MFA tests ([#1452](https://github.com/supabase/auth/issues/1452)) ([7185af8](https://github.com/supabase/auth/commit/7185af8de4a269cdde2629054d222333d3522ebe))
* complete OIDC support for Apple and Google providers ([#1108](https://github.com/supabase/auth/issues/1108)) ([aab7c34](https://github.com/supabase/auth/commit/aab7c3481219f136729d80d37731aa64fb8c380a))
* config reloading ([#1771](https://github.com/supabase/auth/issues/1771)) ([6ee0091](https://github.com/supabase/auth/commit/6ee009163bfe451e2a0b923705e073928a12c004))
* configurable email and sms rate limiting ([#1800](https://github.com/supabase/auth/issues/1800)) ([5e94047](https://github.com/supabase/auth/commit/5e9404717e1c962ab729cde150ef5b40ea31a6e8))
* configurable NameID format for SAML provider ([#1481](https://github.com/supabase/auth/issues/1481)) ([ef405d8](https://github.com/supabase/auth/commit/ef405d89e69e008640f275bc37f8ec02ad32da40))
* deprecate existing webhook implementation ([#1417](https://github.com/supabase/auth/issues/1417)) ([5301e48](https://github.com/supabase/auth/commit/5301e481b0c7278c18b4578a5b1aa8d2256c2f5d))
* drop restriction that PKCE cannot be used with autoconfirm ([#1176](https://github.com/supabase/auth/issues/1176)) ([0a6f218](https://github.com/supabase/auth/commit/0a6f2189a6e1f297ce152d04c3faca57d6900a6e))
* drop SAML RelayState IP address check ([#1376](https://github.com/supabase/auth/issues/1376)) ([6284d99](https://github.com/supabase/auth/commit/6284d99e38f2ea9920ff92406a9b17d8eae767ce))
* drop sha hash tag ([#1422](https://github.com/supabase/auth/issues/1422)) ([76853ce](https://github.com/supabase/auth/commit/76853ce6d45064de5608acc8100c67a8337ba791))
* encrypt sensitive columns ([#1593](https://github.com/supabase/auth/issues/1593)) ([e4a4758](https://github.com/supabase/auth/commit/e4a475820b2dc1f985bd37df15a8ab9e781626f5))
* expose email address being sent to for email change flow ([#1231](https://github.com/supabase/auth/issues/1231)) ([f7308ad](https://github.com/supabase/auth/commit/f7308ad9355db7526a30798b8aa17dabff9f543b))
* fix account linking ([#1098](https://github.com/supabase/auth/issues/1098)) ([93d12d9](https://github.com/supabase/auth/commit/93d12d904820ea6acc20386ef313e35fb28a5a40))
* fix empty string parsing for `GOTRUE_SMS_TEST_OTP_VALID_UNTIL` ([#1234](https://github.com/supabase/auth/issues/1234)) ([25f2dcb](https://github.com/supabase/auth/commit/25f2dcbc97bac18266f1d3583614656182154f85))
* fix refresh token reuse revocation ([#1312](https://github.com/supabase/auth/issues/1312)) ([6e313f8](https://github.com/supabase/auth/commit/6e313f813fc14337a3cd0bdd898f76fe02c9be40))
* fix SAML metadata XML update on fetched metadata ([#1135](https://github.com/supabase/auth/issues/1135)) ([aba0e24](https://github.com/supabase/auth/commit/aba0e241b56bd13b0a24e5064a52824fcc1ff208))
* forbid generating an access token without a session ([#1504](https://github.com/supabase/auth/issues/1504)) ([795e93d](https://github.com/supabase/auth/commit/795e93d0afbe94bcd78489a3319a970b7bf8e8bc))
* HTTP Hook - Add custom envconfig decoding for HTTP Hook Secrets ([#1467](https://github.com/supabase/auth/issues/1467)) ([5b24c4e](https://github.com/supabase/auth/commit/5b24c4eb05b2b52c4177d5f41cba30cb68495c8c))
* ignore common Azure issuer for ID tokens ([#1272](https://github.com/supabase/auth/issues/1272)) ([4c50357](https://github.com/supabase/auth/commit/4c50357841c51c2da0eff4d7f8920aed5e640df2))
* infer `Mail` in SAML assertion and allow deleting SSO user ([#1132](https://github.com/supabase/auth/issues/1132)) ([47ad9de](https://github.com/supabase/auth/commit/47ad9de4285a7f7a112f50e27a9634444e29e276))
* initial fix for invite followed by signup. ([#1262](https://github.com/supabase/auth/issues/1262)) ([76c8eeb](https://github.com/supabase/auth/commit/76c8eeb7275d47f2c7a4029219fa7b3ca4c26da8))
* mailer logging ([#1805](https://github.com/supabase/auth/issues/1805)) ([9354b83](https://github.com/supabase/auth/commit/9354b83a48a3edcb49197c997a1e96efc80c5383))
* make error message in factor creation more obvious ([#1374](https://github.com/supabase/auth/issues/1374)) ([74af993](https://github.com/supabase/auth/commit/74af9934c8e919ddf22a98996736d30c829fe01e))
* make the email client explicity set the format to be HTML ([#1149](https://github.com/supabase/auth/issues/1149)) ([53e223a](https://github.com/supabase/auth/commit/53e223abdf29f4abcad13f99baf00daedcb00c3f))
* merge provider metadata on link account ([#1552](https://github.com/supabase/auth/issues/1552)) ([bd8b5c4](https://github.com/supabase/auth/commit/bd8b5c41dd544575e1a52ccf1ef3f0fdee67458c))
* MFA (Phone) ([#1668](https://github.com/supabase/auth/issues/1668)) ([ae091aa](https://github.com/supabase/auth/commit/ae091aa942bdc5bc97481037508ec3bb4079d859))
* new timeout writer implementation ([#1584](https://github.com/supabase/auth/issues/1584)) ([72614a1](https://github.com/supabase/auth/commit/72614a1fce27888f294772b512f8e31c55a36d87))
* pass transaction to `invokeHook`, fixing pool exhaustion ([#1465](https://github.com/supabase/auth/issues/1465)) ([b536d36](https://github.com/supabase/auth/commit/b536d368f35adb31f937169e3f093d28352fa7be))
* password sign-up no longer blocks the db connection ([#1319](https://github.com/supabase/auth/issues/1319)) ([84d4b75](https://github.com/supabase/auth/commit/84d4b751ae71c9e5a7c8f61a6692486ff09d86a3))
* PKCE magic link ([#1016](https://github.com/supabase/auth/issues/1016)) ([6fdad13](https://github.com/supabase/auth/commit/6fdad133078b42ab45275e15d43e198e50b85ae1))
* prefix release with v ([#1424](https://github.com/supabase/auth/issues/1424)) ([9d398cd](https://github.com/supabase/auth/commit/9d398cd75fca01fb848aa88b4f545552e8b5751a))
* preserve rate limiters in memory across configuration reloads ([#1792](https://github.com/supabase/auth/issues/1792)) ([0a3968b](https://github.com/supabase/auth/commit/0a3968b02b9f044bfb7e5ebc71dca970d2bb7807))
* properly return hook error ([#1355](https://github.com/supabase/auth/issues/1355)) ([890663f](https://github.com/supabase/auth/commit/890663f6cdf21bc2889aa8e646f659c530837d57))
* refactor for central password strength check ([#1321](https://github.com/supabase/auth/issues/1321)) ([5524653](https://github.com/supabase/auth/commit/5524653b0c375872ab49694f0dc99a2093886187))
* refactor generate accesss token to take in request ([#1531](https://github.com/supabase/auth/issues/1531)) ([e4f2b59](https://github.com/supabase/auth/commit/e4f2b59e8e1f8158b6461a384349f1a32cc1bf9a))
* refactor hook error handling ([#1329](https://github.com/supabase/auth/issues/1329)) ([72fdb16](https://github.com/supabase/auth/commit/72fdb160119c4611cfd3eb276f19f2fa21e8eaeb))
* refactor one-time tokens for performance ([#1558](https://github.com/supabase/auth/issues/1558)) ([d1cf8d9](https://github.com/supabase/auth/commit/d1cf8d9096e9183d7772b73031de8ecbd66e912b))
* refactor password changes and logout ([#1162](https://github.com/supabase/auth/issues/1162)) ([b079c35](https://github.com/supabase/auth/commit/b079c3561c4e8166e3a562732c03c237e17abb82))
* refactor PKCE FlowState to reduce duplicate code ([#1446](https://github.com/supabase/auth/issues/1446)) ([b8d0337](https://github.com/supabase/auth/commit/b8d0337922c6712380f6dc74f7eac9fb71b1ae48))
* refactor resource owner password grant ([#1443](https://github.com/supabase/auth/issues/1443)) ([e63ad6f](https://github.com/supabase/auth/commit/e63ad6ff0f67d9a83456918a972ecb5109125628))
* reinstate upgrade whatsapp support on Twilio Programmable Messaging to support Content API ([#1266](https://github.com/supabase/auth/issues/1266)) ([00ee75c](https://github.com/supabase/auth/commit/00ee75c5509facc668295a57ba9130064c267b31))
* remove `SafeRoundTripper` and allow private-IP HTTP connections ([#1152](https://github.com/supabase/auth/issues/1152)) ([773e45e](https://github.com/supabase/auth/commit/773e45e1abb9e6ba3b72001f928c7ca75754f70b))
* remove flow state expiry on Magic Links (PKCE) ([#1179](https://github.com/supabase/auth/issues/1179)) ([caa9393](https://github.com/supabase/auth/commit/caa939382a33f7b6ab47f66f0bb60aca631dd061))
* remove legacy lookup in users for one_time_tokens (phase II) ([#1569](https://github.com/supabase/auth/issues/1569)) ([39ca026](https://github.com/supabase/auth/commit/39ca026035f6c61d206d31772c661b326c2a424c))
* remove non-SSO restriction for MFA ([#1378](https://github.com/supabase/auth/issues/1378)) ([9ca6970](https://github.com/supabase/auth/commit/9ca6970baeed8cfa3ec4fc17c32a41562b8db6c9))
* remove opentracing ([#1307](https://github.com/supabase/auth/issues/1307)) ([93e5f82](https://github.com/supabase/auth/commit/93e5f82ced83c08799ce99020be9dea82fc56d24))
* rename `gotrue` to `auth` ([#1340](https://github.com/supabase/auth/issues/1340)) ([8430113](https://github.com/supabase/auth/commit/843011384ebe8a73306a31f74dc80311dd9b5d5f))
* require different passwords on update ([#1163](https://github.com/supabase/auth/issues/1163)) ([154dd91](https://github.com/supabase/auth/commit/154dd9106f073a12935d4e49b95cf1fe783e91df))
* retry concurrent refresh token attempts ([#1202](https://github.com/supabase/auth/issues/1202)) ([d894012](https://github.com/supabase/auth/commit/d894012490582cab50283a4ad9407a1224194f6d))
* return `expires_at` in addition to `expires_in` ([#1183](https://github.com/supabase/auth/issues/1183)) ([3cd4bd5](https://github.com/supabase/auth/commit/3cd4bd5a077240655e6f881cfd7d3afb04dc7ab4))
* return bad request error when factor with duplicate friendly name is registered ([#1375](https://github.com/supabase/auth/issues/1375)) ([55febd2](https://github.com/supabase/auth/commit/55febd290d26b0abf5c2de2e1bdaf6923736831f))
* return SMS ID when possible ([#1145](https://github.com/supabase/auth/issues/1145)) ([02cb927](https://github.com/supabase/auth/commit/02cb9273ec759b2ff55bea1f6eedb7b8db7a2880))
* return validation failed error if captcha request was not json ([#1815](https://github.com/supabase/auth/issues/1815)) ([26d2e36](https://github.com/supabase/auth/commit/26d2e36bba29eb8a6ddba556acfd0820f3bfde5d))
* send over user in SendSMS Hook instead of UserID ([#1551](https://github.com/supabase/auth/issues/1551)) ([d4d743c](https://github.com/supabase/auth/commit/d4d743c2ae9490e1b3249387e3b0d60df6913c68))
* serialized access to session in `refresh_token` grant ([#1190](https://github.com/supabase/auth/issues/1190)) ([a8f1712](https://github.com/supabase/auth/commit/a8f171257c4517eab8a47925c0f4815a9f5bd0a4))
* set `updated_at` on `refresh_tokens` when revoking family ([#1167](https://github.com/supabase/auth/issues/1167)) ([bebd27a](https://github.com/supabase/auth/commit/bebd27ab6a679c9a27441e806af7af55af7dff18))
* simplify token reuse algorithm ([#1072](https://github.com/supabase/auth/issues/1072)) ([9ee3ab6](https://github.com/supabase/auth/commit/9ee3ab66f2f4b843fb37b1e559e1e63c8976e4f1))
* split validation and population of hook name ([#1337](https://github.com/supabase/auth/issues/1337)) ([c03ae09](https://github.com/supabase/auth/commit/c03ae091ab69c20afcd98577fb96a59719777c1b))
* spotify oauth ([#1296](https://github.com/supabase/auth/issues/1296)) ([cc07b4a](https://github.com/supabase/auth/commit/cc07b4aa2ace75d9c8e46ae5107dbabadf944e87))
* strip user-agent from otel tracing ([#1309](https://github.com/supabase/auth/issues/1309)) ([d76f439](https://github.com/supabase/auth/commit/d76f439b65413803ccf37cf8a217a932addfb477))
* switch to github.com/supabase/mailme package ([#1159](https://github.com/supabase/auth/issues/1159)) ([dbb9cf7](https://github.com/supabase/auth/commit/dbb9cf706985e15b72f28dd61cb29e13565b0d15)), closes [#870](https://github.com/supabase/auth/issues/870)
* unlinking primary identity should update email ([#1326](https://github.com/supabase/auth/issues/1326)) ([bdc3300](https://github.com/supabase/auth/commit/bdc33008d2af9e4e49b9efd4ff905cc14694faba))
* update chi version ([#1581](https://github.com/supabase/auth/issues/1581)) ([c64ae3d](https://github.com/supabase/auth/commit/c64ae3dd775e8fb3022239252c31b4ee73893237))
* update github.com/coreos/go-oidc/v3@v3.6.0 ([#1115](https://github.com/supabase/auth/issues/1115)) ([23c8b45](https://github.com/supabase/auth/commit/23c8b453cff181f29adab764baacec8362df11f0))
* update github.com/rs/cors to v1.9.0 ([#1198](https://github.com/supabase/auth/issues/1198)) ([27d3a7f](https://github.com/supabase/auth/commit/27d3a7f4d1d43e0cb7eec71573aeb1ce3cf60279))
* update oauth1.a flow ([#1382](https://github.com/supabase/auth/issues/1382)) ([4f39d2e](https://github.com/supabase/auth/commit/4f39d2e42fcaf77c201039e7bc60b0d663e62428))
* update openapi spec with identity and is_anonymous fields ([#1573](https://github.com/supabase/auth/issues/1573)) ([86a79df](https://github.com/supabase/auth/commit/86a79df9ecfcf09fda0b8e07afbc41154fbb7d9d))
* update primary key for identities table ([#1311](https://github.com/supabase/auth/issues/1311)) ([d8ec801](https://github.com/supabase/auth/commit/d8ec8015e50f6199786a9e5f05589888fa8862be))
* update publish.yml checkout repository so there is access to Dockerfile ([#1419](https://github.com/supabase/auth/issues/1419)) ([7cce351](https://github.com/supabase/auth/commit/7cce3518e8c9f1f3f93e4f6a0658ee08771c4f1c))
* update README.md to trigger release ([#1425](https://github.com/supabase/auth/issues/1425)) ([91e0e24](https://github.com/supabase/auth/commit/91e0e245f5957ebce13370f79fd4a6be8108ed80))
* upgrade otel to v1.26 ([#1585](https://github.com/supabase/auth/issues/1585)) ([cdd13ad](https://github.com/supabase/auth/commit/cdd13adec02eb0c9401bc55a2915c1005d50dea1))
* upgrade whatsapp support on Twilio Programmable Messaging ([#1249](https://github.com/supabase/auth/issues/1249)) ([c58febe](https://github.com/supabase/auth/commit/c58febed896c7152a03634ac32b7f596b7b65d6f))
* use `DO` blocks around SQL statements in migrations ([#1335](https://github.com/supabase/auth/issues/1335)) ([061391a](https://github.com/supabase/auth/commit/061391aceed64b2cac56e8a82b6a3da3e83cbb14))
* use `otherMails` with Azure ([#1130](https://github.com/supabase/auth/issues/1130)) ([fba1988](https://github.com/supabase/auth/commit/fba19885daa1e8d93c12bd2931383a5899b154e0))
* use `template/text` instead of `strings.Replace` for phone OTP messages ([#1188](https://github.com/supabase/auth/issues/1188)) ([5caacc1](https://github.com/supabase/auth/commit/5caacc1f81ff20f8f09f4598b510c767e589a1c5))
* use dummy instance id to improve performance on refresh token queries ([#1454](https://github.com/supabase/auth/issues/1454)) ([656474e](https://github.com/supabase/auth/commit/656474e1b9ff3d5129190943e8c48e456625afe5))
* use embedded migrations for `migrate` command ([#1843](https://github.com/supabase/auth/issues/1843)) ([e358da5](https://github.com/supabase/auth/commit/e358da5f0e267725a77308461d0a4126436fc537))
* use largest avatar from spotify instead ([#1210](https://github.com/supabase/auth/issues/1210)) ([4f9994b](https://github.com/supabase/auth/commit/4f9994bf792c3887f2f45910b11a9c19ee3a896b)), closes [#1209](https://github.com/supabase/auth/issues/1209)
* use OIDC ID token for Azure ([#1269](https://github.com/supabase/auth/issues/1269)) ([57e336e](https://github.com/supabase/auth/commit/57e336e9c0d8f8fc27e5efeecf06bff5507fef54))
* Vercel marketplace OIDC ([#1731](https://github.com/supabase/auth/issues/1731)) ([a9ff361](https://github.com/supabase/auth/commit/a9ff3612196af4a228b53a8bfb9c11785bcfba8d))


### Bug Fixes

* [#1218](https://github.com/supabase/auth/issues/1218) fixes existing migrations to allow namespaces!="auth" ([#1279](https://github.com/supabase/auth/issues/1279)) ([206fc09](https://github.com/supabase/auth/commit/206fc0908992e6c22a6343a7a7517f66322764b5))
* add additional information around errors for missing content type header ([#1576](https://github.com/supabase/auth/issues/1576)) ([c2b2f96](https://github.com/supabase/auth/commit/c2b2f96f07c97c15597cd972b1cd672238d87cdc))
* add check for max password length ([#1368](https://github.com/supabase/auth/issues/1368)) ([41aac69](https://github.com/supabase/auth/commit/41aac695029a8e8ae6aeed87e71abea63030c799))
* add cleanup statement for anonymous users ([#1497](https://github.com/supabase/auth/issues/1497)) ([cf2372a](https://github.com/supabase/auth/commit/cf2372a177796b829b72454e7491ce768bf5a42f))
* add db conn max idle time setting ([#1555](https://github.com/supabase/auth/issues/1555)) ([2caa7b4](https://github.com/supabase/auth/commit/2caa7b4d75d2ff54af20f3e7a30a8eeec8cbcda9))
* add discord `global_name` to custom_claims ([#1171](https://github.com/supabase/auth/issues/1171)) ([3b1a5b9](https://github.com/supabase/auth/commit/3b1a5b980ed49eb17b93f8fb43346cc5b1525b97))
* add error codes to password login flow ([#1721](https://github.com/supabase/auth/issues/1721)) ([4351226](https://github.com/supabase/auth/commit/435122627a0784f1c5cb76d7e08caa1f6259423b))
* add error codes to refresh token flow ([#1824](https://github.com/supabase/auth/issues/1824)) ([4614dc5](https://github.com/supabase/auth/commit/4614dc54ab1dcb5390cfed05441e7888af017d92))
* add error handling for hook ([#1339](https://github.com/supabase/auth/issues/1339)) ([7ac7586](https://github.com/supabase/auth/commit/7ac7586c114f581722f07eb54ff4ca193c34ddd9))
* add guard check in case factor, session, or user are missing ([#1099](https://github.com/supabase/auth/issues/1099)) ([b4a3fec](https://github.com/supabase/auth/commit/b4a3fec6d00566becc51f001b828187f736fb383))
* add http support for https hooks on localhost ([#1484](https://github.com/supabase/auth/issues/1484)) ([5c04104](https://github.com/supabase/auth/commit/5c04104bf77a9c2db46d009764ec3ec3e484fc09))
* add ip based limiter ([#1622](https://github.com/supabase/auth/issues/1622)) ([06464c0](https://github.com/supabase/auth/commit/06464c013571253d1f18f7ae5e840826c4bd84a7))
* add last_challenged_at field to mfa factors ([#1705](https://github.com/supabase/auth/issues/1705)) ([29cbeb7](https://github.com/supabase/auth/commit/29cbeb799ff35ce528bfbd01b7103a24903d8061))
* add profiler server ([#1158](https://github.com/supabase/auth/issues/1158)) ([58552d6](https://github.com/supabase/auth/commit/58552d6090a57367be92e32198ca1cf712d745af))
* add redirectTo to email templates ([#1276](https://github.com/supabase/auth/issues/1276)) ([40aed62](https://github.com/supabase/auth/commit/40aed622f24066b2718e4509a001026fe7d4b76d))
* add test coverage for rate limits with 0 permitted events ([#1834](https://github.com/supabase/auth/issues/1834)) ([7c3cf26](https://github.com/supabase/auth/commit/7c3cf26cfe2a3e4de579d10509945186ad719855))
* add token to hook payload for non-secure email change ([#1763](https://github.com/supabase/auth/issues/1763)) ([7e472ad](https://github.com/supabase/auth/commit/7e472ad72042e86882dab3fddce9fafa66a8236c))
* add twilio verify support on mfa ([#1714](https://github.com/supabase/auth/issues/1714)) ([aeb5d8f](https://github.com/supabase/auth/commit/aeb5d8f8f18af60ce369cab5714979ac0c208308))
* add validation and proper decoding on send email hook ([#1520](https://github.com/supabase/auth/issues/1520)) ([e19e762](https://github.com/supabase/auth/commit/e19e762e3e29729a1d1164c65461427822cc87f1))
* admin user update should update is_anonymous field ([#1623](https://github.com/supabase/auth/issues/1623)) ([f5c6fcd](https://github.com/supabase/auth/commit/f5c6fcd9c3fee0f793f96880a8caebc5b5cb0916))
* allow anonymous user to update password ([#1739](https://github.com/supabase/auth/issues/1739)) ([2d51956](https://github.com/supabase/auth/commit/2d519569d7b8540886d0a64bf3e561ef5f91eb63))
* allow enabling sms hook without setting up sms provider ([#1704](https://github.com/supabase/auth/issues/1704)) ([575e88a](https://github.com/supabase/auth/commit/575e88ac345adaeb76ab6aae077307fdab9cda3c))
* allow gotrue to work with multiple custom domains ([#999](https://github.com/supabase/auth/issues/999)) ([91a82ed](https://github.com/supabase/auth/commit/91a82ed468ec0f1e6edb4b4bbc560815ff0d8167))
* allow transactions to be committed while returning a custom error ([#1310](https://github.com/supabase/auth/issues/1310)) ([8565d26](https://github.com/supabase/auth/commit/8565d264014557f721b6d12afa3171a25a38b905))
* apply authorized email restriction to non-admin routes ([#1778](https://github.com/supabase/auth/issues/1778)) ([1af203f](https://github.com/supabase/auth/commit/1af203f92372e6db12454a0d319aad8ce3d149e7))
* apply mailer autoconfirm config to update user email ([#1646](https://github.com/supabase/auth/issues/1646)) ([a518505](https://github.com/supabase/auth/commit/a5185058e72509b0781e0eb59910ecdbb8676fee))
* apply shared limiters before email / sms is sent ([#1748](https://github.com/supabase/auth/issues/1748)) ([bf276ab](https://github.com/supabase/auth/commit/bf276ab49753642793471815727559172fea4efc))
* bypass check for token & verify endpoints ([#1785](https://github.com/supabase/auth/issues/1785)) ([9ac2ea0](https://github.com/supabase/auth/commit/9ac2ea0180826cd2f65e679524aabfb10666e973))
* call write header in write if not written ([#1598](https://github.com/supabase/auth/issues/1598)) ([0ef7eb3](https://github.com/supabase/auth/commit/0ef7eb30619d4c365e06a94a79b9cb0333d792da))
* change email update flow to return both ? messages and # messages ([#1129](https://github.com/supabase/auth/issues/1129)) ([77afd28](https://github.com/supabase/auth/commit/77afd2834201e50672502a48bdc365b4ba7a095b))
* change phone constraint to per user ([#1713](https://github.com/supabase/auth/issues/1713)) ([b9bc769](https://github.com/supabase/auth/commit/b9bc769b93b6e700925fcbc1ebf8bf9678034205))
* check err before using user ([#1154](https://github.com/supabase/auth/issues/1154)) ([53e1b3a](https://github.com/supabase/auth/commit/53e1b3aa31dc4ac87d0815491fd4c752a9f8e03d))
* check for empty aud string ([#1649](https://github.com/supabase/auth/issues/1649)) ([42c1d45](https://github.com/supabase/auth/commit/42c1d4526b98203664d4a22c23014ecd0b4951f9))
* check for pkce prefix ([#1291](https://github.com/supabase/auth/issues/1291)) ([05c629b](https://github.com/supabase/auth/commit/05c629b1b521e950e8951e9e8d328c9813ebe6bd))
* check freq on email change ([#1090](https://github.com/supabase/auth/issues/1090)) ([659ca66](https://github.com/supabase/auth/commit/659ca66386f818d707995dbcca2eaeebc4d0bfd7))
* check if session is nil ([#1873](https://github.com/supabase/auth/issues/1873)) ([fd82601](https://github.com/supabase/auth/commit/fd82601917adcd9f8c38263953eb1ef098b26b7f))
* check linking domain prefix ([#1336](https://github.com/supabase/auth/issues/1336)) ([9194ffc](https://github.com/supabase/auth/commit/9194ffc72d68ca45dfb18dc1b0eb7ce64e62592c))
* check password max length in checkPasswordStrength ([#1659](https://github.com/supabase/auth/issues/1659)) ([1858c93](https://github.com/supabase/auth/commit/1858c93bba6f5bc41e4c65489f12c1a0786a1f2b))
* cleanup panics due to bad inactivity timeout code ([#1471](https://github.com/supabase/auth/issues/1471)) ([548edf8](https://github.com/supabase/auth/commit/548edf898161c9ba9a136fc99ec2d52a8ba1f856))
* confirm email on email change ([#1084](https://github.com/supabase/auth/issues/1084)) ([0624655](https://github.com/supabase/auth/commit/0624655649c8de483fe8caa4a69bb3895fd967be))
* correct pkce redirect generation ([#1097](https://github.com/supabase/auth/issues/1097)) ([bdf93b4](https://github.com/supabase/auth/commit/bdf93b41b198a9d09813359ec285af1b3c47b4e3))
* correct web authn aaguid column naming ([#1826](https://github.com/supabase/auth/issues/1826)) ([0a589d0](https://github.com/supabase/auth/commit/0a589d04e1cd9310cb260d329bc8beb050adf8da))
* custom SMS does not work with Twilio Verify ([#1733](https://github.com/supabase/auth/issues/1733)) ([dc2391d](https://github.com/supabase/auth/commit/dc2391d15f2c0725710aa388cd32a18797e6769c))
* deadlock issue with timeout middleware write ([#1595](https://github.com/supabase/auth/issues/1595)) ([6c9fbd4](https://github.com/supabase/auth/commit/6c9fbd4bd5623c729906fca7857ab508166a3056))
* default to files:read scope for Figma provider ([#1831](https://github.com/supabase/auth/issues/1831)) ([9ce2857](https://github.com/supabase/auth/commit/9ce28570bf3da9571198d44d693c7ad7038cde33))
* define search path in auth functions ([#1616](https://github.com/supabase/auth/issues/1616)) ([357bda2](https://github.com/supabase/auth/commit/357bda23cb2abd12748df80a9d27288aa548534d))
* deprecate hooks  ([#1421](https://github.com/supabase/auth/issues/1421)) ([effef1b](https://github.com/supabase/auth/commit/effef1b6ecc448b7927eff23df8d5b509cf16b5c))
* disable allow unverified email sign ins if autoconfirm enabled ([#1313](https://github.com/supabase/auth/issues/1313)) ([9b93ac1](https://github.com/supabase/auth/commit/9b93ac1d988519354a59ecff573ba22718896971))
* do call send sms hook when SMS autoconfirm is enabled ([#1562](https://github.com/supabase/auth/issues/1562)) ([bfe4d98](https://github.com/supabase/auth/commit/bfe4d988f3768b0407526bcc7979fb21d8cbebb3))
* **docs:** remove bracket on file name for broken link ([#1493](https://github.com/supabase/auth/issues/1493)) ([96f7a68](https://github.com/supabase/auth/commit/96f7a68a5479825e31106c2f55f82d5b2c007c0f))
* don't encode query fragment ([#1153](https://github.com/supabase/auth/issues/1153)) ([e414cb3](https://github.com/supabase/auth/commit/e414cb3a98cff8598f4aa2c96a1ca63c78bd65a6))
* don't update attribute mapping if nil ([#1665](https://github.com/supabase/auth/issues/1665)) ([7e67f3e](https://github.com/supabase/auth/commit/7e67f3edbf81766df297a66f52a8e472583438c6))
* drop the MFA_ENABLED config ([#1701](https://github.com/supabase/auth/issues/1701)) ([078c3a8](https://github.com/supabase/auth/commit/078c3a8adcd51e57b68ab1b582549f5813cccd14))
* duplicate identity error on update user ([#1141](https://github.com/supabase/auth/issues/1141)) ([39ca89c](https://github.com/supabase/auth/commit/39ca89c67c2aee10b656d2c056039ee1eb9e99be))
* email header setting no longer misleading ([#1802](https://github.com/supabase/auth/issues/1802)) ([3af03be](https://github.com/supabase/auth/commit/3af03be6b65c40f3f4f62ce9ab989a20d75ae53a))
* email_verified field not being updated on signup confirmation ([#1868](https://github.com/supabase/auth/issues/1868)) ([483463e](https://github.com/supabase/auth/commit/483463e49eec7b2974cca05eadca6b933b2145b5))
* enable rls & update grants for auth tables ([#1617](https://github.com/supabase/auth/issues/1617)) ([28967aa](https://github.com/supabase/auth/commit/28967aa4b5db2363cc581c9da0d64e974eb7b64c))
* enforce authorized address checks on send email only ([#1806](https://github.com/supabase/auth/issues/1806)) ([c0c5b23](https://github.com/supabase/auth/commit/c0c5b23728c8fb633dae23aa4b29ed60e2691a2b))
* enforce code challenge validity across endpoints ([#1026](https://github.com/supabase/auth/issues/1026)) ([be7c082](https://github.com/supabase/auth/commit/be7c082cad77176dd1bc987e90fdd1502eafdd67))
* enforce uniqueness on verified phone numbers ([#1693](https://github.com/supabase/auth/issues/1693)) ([70446cc](https://github.com/supabase/auth/commit/70446cc11d70b0493d742fe03f272330bb5b633e))
* error should be an IsNotFoundError ([#1432](https://github.com/supabase/auth/issues/1432)) ([7f40047](https://github.com/supabase/auth/commit/7f40047aec3577d876602444b1d88078b2237d66))
* expose `provider` under `amr` in access token ([#1456](https://github.com/supabase/auth/issues/1456)) ([e9f38e7](https://github.com/supabase/auth/commit/e9f38e76d8a7b93c5c2bb0de918a9b156155f018))
* expose `X-Supabase-Api-Version` header in CORS ([#1612](https://github.com/supabase/auth/issues/1612)) ([6ccd814](https://github.com/supabase/auth/commit/6ccd814309dca70a9e3585543887194b05d725d3))
* expose factor type on challenge ([#1709](https://github.com/supabase/auth/issues/1709)) ([e1a21a3](https://github.com/supabase/auth/commit/e1a21a34779ca4b2254caf8b7578db4a50172751))
* external host validation ([#1808](https://github.com/supabase/auth/issues/1808)) ([4f6a461](https://github.com/supabase/auth/commit/4f6a4617074e61ba3b31836ccb112014904ce97c)), closes [#1228](https://github.com/supabase/auth/issues/1228)
* fallback on btree indexes when hash is unavailable ([#1856](https://github.com/supabase/auth/issues/1856)) ([b33bc31](https://github.com/supabase/auth/commit/b33bc31c07549dc9dc221100995d6f6b6754fd3a))
* fix `getExcludedColumns` slice allocation ([#1788](https://github.com/supabase/auth/issues/1788)) ([7f006b6](https://github.com/supabase/auth/commit/7f006b63c8d7e28e55a6d471881e9c118df80585))
* fix flow state expiry check ([#1088](https://github.com/supabase/auth/issues/1088)) ([6000e70](https://github.com/supabase/auth/commit/6000e70e9e1d6929f9d8c90c36fab2bf94bb6d85))
* Fix reqPath for bypass check for verify EP ([#1789](https://github.com/supabase/auth/issues/1789)) ([646dc66](https://github.com/supabase/auth/commit/646dc66ea8d59a7f78bf5a5e55d9b5065a718c23))
* format test otps ([#1567](https://github.com/supabase/auth/issues/1567)) ([434a59a](https://github.com/supabase/auth/commit/434a59ae387c35fd6629ec7c674d439537e344e5))
* generate signup link should not error ([#1514](https://github.com/supabase/auth/issues/1514)) ([4fc3881](https://github.com/supabase/auth/commit/4fc388186ac7e7a9a32ca9b963a83d6ac2eb7603))
* handle oauth email check separately ([#1348](https://github.com/supabase/auth/issues/1348)) ([757989c](https://github.com/supabase/auth/commit/757989c1d3856a1dc450c2e0a5cb1c8e0172a6a6))
* handle user banned error code ([#1851](https://github.com/supabase/auth/issues/1851)) ([a6918f4](https://github.com/supabase/auth/commit/a6918f49baee42899b3ae1b7b6bc126d84629c99))
* hide hook name ([#1743](https://github.com/supabase/auth/issues/1743)) ([7e38f4c](https://github.com/supabase/auth/commit/7e38f4cf37768fe2adf92bbd0723d1d521b3d74c))
* ignore errors if transaction has closed already ([#1726](https://github.com/supabase/auth/issues/1726)) ([53c11d1](https://github.com/supabase/auth/commit/53c11d173a79ae5c004871b1b5840c6f9425a080))
* ignore exchangeCodeForSession when captcha is enabled ([#1121](https://github.com/supabase/auth/issues/1121)) ([4970bbc](https://github.com/supabase/auth/commit/4970bbcba91a435cc0bfa8a75b4899a79d8d4dea))
* ignore rate limits for autoconfirm ([#1810](https://github.com/supabase/auth/issues/1810)) ([9ce2340](https://github.com/supabase/auth/commit/9ce23409f960a8efa55075931138624cb681eca5))
* impose expiry on auth code instead of magic link ([#1440](https://github.com/supabase/auth/issues/1440)) ([35aeaf1](https://github.com/supabase/auth/commit/35aeaf1b60dd27a22662a6d1955d60cc907b55dd))
* improve default settings used  ([4745451](https://github.com/supabase/auth/commit/4745451a931c2be5d36c07b37bd0eb3ab7780587))
* improve error messaging for http hooks ([#1821](https://github.com/supabase/auth/issues/1821)) ([fa020d0](https://github.com/supabase/auth/commit/fa020d0fc292d5c381c57ecac6666d9ff657e4c4))
* improve logging structure ([#1583](https://github.com/supabase/auth/issues/1583)) ([c22fc15](https://github.com/supabase/auth/commit/c22fc15d2a8383e95a2364f383dfa7dce5f5df88))
* improve MFA QR Code resilience so as to support providers like 1Password ([#1455](https://github.com/supabase/auth/issues/1455)) ([6522780](https://github.com/supabase/auth/commit/652278046c9dd92f5cecd778735b058ef3fb41c7))
* improve mfa verify logs ([#1635](https://github.com/supabase/auth/issues/1635)) ([d8b47f9](https://github.com/supabase/auth/commit/d8b47f9d3f0dc8f97ad1de49e45f452ebc726481))
* improve perf in account linking ([#1394](https://github.com/supabase/auth/issues/1394)) ([8eedb95](https://github.com/supabase/auth/commit/8eedb95dbaa310aac464645ec91d6a374813ab89))
* improve session error logging ([#1655](https://github.com/supabase/auth/issues/1655)) ([5a6793e](https://github.com/supabase/auth/commit/5a6793ee8fce7a089750fe10b3b63bb0a19d6d21))
* improve token OIDC logging ([#1606](https://github.com/supabase/auth/issues/1606)) ([5262683](https://github.com/supabase/auth/commit/526268311844467664e89c8329e5aaee817dbbaf))
* include `/organizations` in expected issuer exemption ([#1275](https://github.com/supabase/auth/issues/1275)) ([47cbe6e](https://github.com/supabase/auth/commit/47cbe6e481ccec9d7f533c7fdba0328c8f6227e5))
* include factor_id in query ([#1702](https://github.com/supabase/auth/issues/1702)) ([ac14e82](https://github.com/supabase/auth/commit/ac14e82b33545466184da99e99b9d3fe5f3876d9))
* include symbols in generated password ([#1364](https://github.com/supabase/auth/issues/1364)) ([f81a748](https://github.com/supabase/auth/commit/f81a748b10f26c11c9940ee864c3fb58e19a98a1))
* inline mailme package for easy development ([#1803](https://github.com/supabase/auth/issues/1803)) ([fa6f729](https://github.com/supabase/auth/commit/fa6f729a027eff551db104550fa626088e00bc15))
* invalidate email, phone OTPs on password change ([#1489](https://github.com/supabase/auth/issues/1489)) ([960a4f9](https://github.com/supabase/auth/commit/960a4f94f5500e33a0ec2f6afe0380bbc9562500))
* invited users should have a temporary password generated ([#1644](https://github.com/supabase/auth/issues/1644)) ([3f70d9d](https://github.com/supabase/auth/commit/3f70d9d8974d0e9c437c51e1312ad17ce9056ec9))
* IsDuplicatedEmail should filter out identities for the currentUser ([#1092](https://github.com/supabase/auth/issues/1092)) ([dd2b688](https://github.com/supabase/auth/commit/dd2b6883d666e9a714f9f05c65a44b293f76a6a6))
* linkedin_oidc provider error ([#1534](https://github.com/supabase/auth/issues/1534)) ([4f5e8e5](https://github.com/supabase/auth/commit/4f5e8e5120531e5a103fbdda91b51cabcb4e1a8c))
* log clearer internal error messages for verify ([#1292](https://github.com/supabase/auth/issues/1292)) ([aafad5c](https://github.com/supabase/auth/commit/aafad5c2b073f0f56239109eef2cf5f2ee5cfd70))
* log correct referer value ([#1178](https://github.com/supabase/auth/issues/1178)) ([a6950a0](https://github.com/supabase/auth/commit/a6950a0e606ed47cf9580eb4c35ad07b58afbd36))
* log final writer error instead of handling ([#1564](https://github.com/supabase/auth/issues/1564)) ([170bd66](https://github.com/supabase/auth/commit/170bd6615405afc852c7107f7358dfc837bad737))
* lowercase oauth emails for account linking ([#1125](https://github.com/supabase/auth/issues/1125)) ([df22915](https://github.com/supabase/auth/commit/df229158ac6d41daf5e17e9ccd9a9f4b9a1c5f32))
* magiclink failing due to passwordStrength check ([#1769](https://github.com/supabase/auth/issues/1769)) ([7a5411f](https://github.com/supabase/auth/commit/7a5411f1d4247478f91027bc4969cbbe95b7774c))
* maintain backward compatibility for asymmetric JWTs ([#1690](https://github.com/supabase/auth/issues/1690)) ([0ad1402](https://github.com/supabase/auth/commit/0ad1402444348e47e1e42be186b3f052d31be824))
* maintain query params order ([#1161](https://github.com/supabase/auth/issues/1161)) ([c925065](https://github.com/supabase/auth/commit/c925065059b69b86f64d9cd1509e4ad24bc37904))
* make drop_uniqueness_constraint_on_phone idempotent ([#1817](https://github.com/supabase/auth/issues/1817)) ([158e473](https://github.com/supabase/auth/commit/158e4732afa17620cdd89c85b7b57569feea5c21))
* make flow_state migrations idempotent, add index ([#1086](https://github.com/supabase/auth/issues/1086)) ([7ca755a](https://github.com/supabase/auth/commit/7ca755a2da24967a7fff56d37ee9d9ece24a5b69))
* make migration idempotent ([#1079](https://github.com/supabase/auth/issues/1079)) ([2be90c7](https://github.com/supabase/auth/commit/2be90c7ca08871576827c7e039c81ce0ae13b7b8))
* MFA NewFactor to default to creating unverfied factors ([#1692](https://github.com/supabase/auth/issues/1692)) ([3d448fa](https://github.com/supabase/auth/commit/3d448fa73cb77eb8511dbc47bfafecce4a4a2150))
* minor spelling errors ([#1688](https://github.com/supabase/auth/issues/1688)) ([6aca52b](https://github.com/supabase/auth/commit/6aca52b56f8a6254de7709c767b9a5649f1da248)), closes [#1682](https://github.com/supabase/auth/issues/1682)
* move all EmailActionTypes to mailer package ([#1510](https://github.com/supabase/auth/issues/1510)) ([765db08](https://github.com/supabase/auth/commit/765db08582669a1b7f054217fa8f0ed45804c0b5))
* move creation of flow state into function ([#1470](https://github.com/supabase/auth/issues/1470)) ([4392a08](https://github.com/supabase/auth/commit/4392a08d68d18828005d11382730117a7b143635))
* move is owned by check to load factor ([#1703](https://github.com/supabase/auth/issues/1703)) ([701a779](https://github.com/supabase/auth/commit/701a779cf092e777dd4ad4954dc650164b09ab32))
* OIDC provider validation log message ([#1380](https://github.com/supabase/auth/issues/1380)) ([27e6b1f](https://github.com/supabase/auth/commit/27e6b1f9a4394c5c4f8dff9a8b5529db1fc67af9))
* omit empty string from name & use case-insensitive equality for comparing SAML attributes ([#1654](https://github.com/supabase/auth/issues/1654)) ([bf5381a](https://github.com/supabase/auth/commit/bf5381a6b1c686955dc4e39fe5fb806ffd309563))
* only apply rate limit if autoconfirm is false ([#1184](https://github.com/supabase/auth/issues/1184)) ([46932da](https://github.com/supabase/auth/commit/46932da6baa95306df6c72f411b5e485f695c98e))
* only create or update the email / phone identity after it's been verified ([#1403](https://github.com/supabase/auth/issues/1403)) ([2d20729](https://github.com/supabase/auth/commit/2d207296ec22dd6c003c89626d255e35441fd52d))
* only create or update the email / phone identity after it's been verified (again) ([#1409](https://github.com/supabase/auth/issues/1409)) ([bc6a5b8](https://github.com/supabase/auth/commit/bc6a5b884b43fe6b8cb924d3f79999fe5bfe7c5f))
* pass through redirect query parameters ([#1224](https://github.com/supabase/auth/issues/1224)) ([577e320](https://github.com/supabase/auth/commit/577e3207aab8ee4c4661f5a8148f02296210f1d8))
* patch secure email change (double confirm) response format. ([#1241](https://github.com/supabase/auth/issues/1241)) ([064e8a1](https://github.com/supabase/auth/commit/064e8a1a1a71163d81f6c549b31148b88c3ef7be))
* pkce bug with magiclink ([#1074](https://github.com/supabase/auth/issues/1074)) ([4b84129](https://github.com/supabase/auth/commit/4b84129e668e9f3ab4fc8d768c73edc50106d2d5))
* pkce issues ([#1083](https://github.com/supabase/auth/issues/1083)) ([eb50ba1](https://github.com/supabase/auth/commit/eb50ba1de139de7a244637190cb1071c8d50bf9e))
* populate password verification attempt hook ([#1436](https://github.com/supabase/auth/issues/1436)) ([f974bdb](https://github.com/supabase/auth/commit/f974bdb58340395955ca27bdd26d57062433ece9))
* possible panic if refresh token has a null session_id ([#1822](https://github.com/supabase/auth/issues/1822)) ([a7129df](https://github.com/supabase/auth/commit/a7129df4e1d91a042b56ff1f041b9c6598825475))
* POST /verify should check pkce case ([#1085](https://github.com/supabase/auth/issues/1085)) ([7f42eaa](https://github.com/supabase/auth/commit/7f42eaa582b497859ba07d77e6db0eb18026117d))
* potential panics on error ([#1389](https://github.com/supabase/auth/issues/1389)) ([5ad703b](https://github.com/supabase/auth/commit/5ad703bddc6ec74f076cbe6ce1f942663343d47a))
* preserve backward compatibility with Twilio Existing API ([#1260](https://github.com/supabase/auth/issues/1260)) ([71fb156](https://github.com/supabase/auth/commit/71fb1569c9daff8ac99ae6b9626e098606b2934f))
* prevent user email side-channel leak on verify ([#1472](https://github.com/supabase/auth/issues/1472)) ([311cde8](https://github.com/supabase/auth/commit/311cde8d1e82f823ae26a341e068034d60273864))
* publish to ghcr.io/supabase/auth ([#1626](https://github.com/supabase/auth/issues/1626)) ([930aa3e](https://github.com/supabase/auth/commit/930aa3edb633823d4510c2aff675672df06f1211)), closes [#1625](https://github.com/supabase/auth/issues/1625)
* rate limits of 0 take precedence over MAILER_AUTO_CONFIRM ([#1837](https://github.com/supabase/auth/issues/1837)) ([cb7894e](https://github.com/supabase/auth/commit/cb7894e1119d27d527dedcca22d8b3d433beddac))
* redirect invalid state errors to site url ([#1722](https://github.com/supabase/auth/issues/1722)) ([b2b1123](https://github.com/supabase/auth/commit/b2b11239dc9f9bd3c85d76f6c23ee94beb3330bb))
* refactor email sending functions ([#1495](https://github.com/supabase/auth/issues/1495)) ([285c290](https://github.com/supabase/auth/commit/285c290adf231fea7ca1dff954491dc427cf18e2))
* refactor factor_test to centralize setup ([#1473](https://github.com/supabase/auth/issues/1473)) ([c86007e](https://github.com/supabase/auth/commit/c86007e59684334b5e8c2285c36094b6eec89442))
* refactor mfa and aal update methods ([#1503](https://github.com/supabase/auth/issues/1503)) ([31a5854](https://github.com/supabase/auth/commit/31a585429bf248aa919d94c82c7c9e0c1c695461))
* refactor mfa challenge and tests ([#1469](https://github.com/supabase/auth/issues/1469)) ([6c76f21](https://github.com/supabase/auth/commit/6c76f21cee5dbef0562c37df6a546939affb2f8d))
* refactor mfa models and add observability to loadFactor ([#1669](https://github.com/supabase/auth/issues/1669)) ([822fb93](https://github.com/supabase/auth/commit/822fb93faab325ba3d4bb628dff43381d68d0b5d))
* refactor mfa validation into functions ([#1780](https://github.com/supabase/auth/issues/1780)) ([410b8ac](https://github.com/supabase/auth/commit/410b8acdd659fc4c929fe57a9e9dba4c76da305d))
* refactor request params to use generics ([#1464](https://github.com/supabase/auth/issues/1464)) ([e1cdf5c](https://github.com/supabase/auth/commit/e1cdf5c4b5c1bf467094f4bdcaa2e42a5cc51c20))
* refactor TOTP MFA into separate methods ([#1698](https://github.com/supabase/auth/issues/1698)) ([250d92f](https://github.com/supabase/auth/commit/250d92f9a18d38089d1bf262ef9088022a446965))
* remove captcha on id_token grant ([#1175](https://github.com/supabase/auth/issues/1175)) ([910079c](https://github.com/supabase/auth/commit/910079c4e48f9fc0d82f7956f974bb25b4c3a154))
* remove check for content-length ([#1700](https://github.com/supabase/auth/issues/1700)) ([81b332d](https://github.com/supabase/auth/commit/81b332d2f48622008469d2c5a9b130465a65f2a3))
* remove deprecated LogoutAllRefreshTokens ([#1519](https://github.com/supabase/auth/issues/1519)) ([35533ea](https://github.com/supabase/auth/commit/35533ea100669559e1209ecc7b091db3657234d9))
* remove duplicated index on refresh_tokens table ([#1058](https://github.com/supabase/auth/issues/1058)) ([1aa8447](https://github.com/supabase/auth/commit/1aa84478eb8a4cdd30510de5467fd2f78a451c8e))
* remove FindFactorsByUser ([#1707](https://github.com/supabase/auth/issues/1707)) ([af8e2dd](https://github.com/supabase/auth/commit/af8e2dda15a1234a05e7d2d34d316eaa029e0912))
* remove organizations from fly provider ([#1267](https://github.com/supabase/auth/issues/1267)) ([c79fc6e](https://github.com/supabase/auth/commit/c79fc6e41988e2854e3e30c7c3f96b1374bdf983))
* remove redundant queries to get session ([#1204](https://github.com/supabase/auth/issues/1204)) ([669ce97](https://github.com/supabase/auth/commit/669ce9706656b157b4e0026ec143827cbe0692b4))
* remove server side cookie token methods ([#1742](https://github.com/supabase/auth/issues/1742)) ([c6efec4](https://github.com/supabase/auth/commit/c6efec4cbc950e01e1fd06d45ed821bd27c2ad08))
* remove TOTP field for phone enroll response ([#1717](https://github.com/supabase/auth/issues/1717)) ([4b04327](https://github.com/supabase/auth/commit/4b043275dd2d94600a8138d4ebf4638754ed926b))
* rename from CustomSMSProvider to SendSMS ([#1513](https://github.com/supabase/auth/issues/1513)) ([c0bc37b](https://github.com/supabase/auth/commit/c0bc37b44effaebb62ba85102f072db07fe57e48))
* resend email change ([#1151](https://github.com/supabase/auth/issues/1151)) ([ddad10f](https://github.com/supabase/auth/commit/ddad10fa69e41fb161469f07b3f24483b9c980cf))
* resend email change & phone change issues ([#1100](https://github.com/supabase/auth/issues/1100)) ([184fa38](https://github.com/supabase/auth/commit/184fa38f0f90b7a7c6d7c9c4c8a1a087f5e9b453))
* Resend SMS when duplicate SMS sign ups are made ([#1490](https://github.com/supabase/auth/issues/1490)) ([73240a0](https://github.com/supabase/auth/commit/73240a0b096977703e3c7d24a224b5641ce47c81))
* respect last_sign_in_at on secure password update ([#1164](https://github.com/supabase/auth/issues/1164)) ([963df37](https://github.com/supabase/auth/commit/963df37946445af7c762d12d57d95492d3952ec6))
* restrict autoconfirm email change to anonymous users ([#1679](https://github.com/supabase/auth/issues/1679)) ([b57e223](https://github.com/supabase/auth/commit/b57e2230102280ed873acf70be1aeb5a2f6f7a4f))
* restrict mfa enrollment to aal2 if verified factors are present ([#1439](https://github.com/supabase/auth/issues/1439)) ([7e10d45](https://github.com/supabase/auth/commit/7e10d45e54010d38677f4c3f2f224127688eb9a2))
* return correct sms otp error ([#1351](https://github.com/supabase/auth/issues/1351)) ([5b06680](https://github.com/supabase/auth/commit/5b06680601b4129f34e5fe571ab01dae435c853e))
* return error if session id does not exist ([#1538](https://github.com/supabase/auth/issues/1538)) ([91e9eca](https://github.com/supabase/auth/commit/91e9ecabe33a1c022f8e82a6050c22a7ca42de48))
* return error if user not found but identity exists ([#1200](https://github.com/supabase/auth/issues/1200)) ([1802ff3](https://github.com/supabase/auth/commit/1802ff39c90cf61dc48c0d6ecebc4e4ed707e70d))
* return oauth identity when user is created ([#1736](https://github.com/supabase/auth/issues/1736)) ([60cfb60](https://github.com/supabase/auth/commit/60cfb6063afa574dfe4993df6b0e087d4df71309))
* return proper error if sms rate limit is exceeded ([#1647](https://github.com/supabase/auth/issues/1647)) ([3c8d765](https://github.com/supabase/auth/commit/3c8d7656431ac4b2e80726b7c37adb8f0c778495))
* return the error code instead of status code ([#1855](https://github.com/supabase/auth/issues/1855)) ([834a380](https://github.com/supabase/auth/commit/834a380d803ae9ce59ce5ee233fa3a78a984fe68))
* return the latest flow state ([#1076](https://github.com/supabase/auth/issues/1076)) ([00c9a11](https://github.com/supabase/auth/commit/00c9a11bcbde4a3d3d8856e7aa797f0142995895))
* Revert "fix: remove organizations from fly provider" ([#1287](https://github.com/supabase/auth/issues/1287)) ([84e16ed](https://github.com/supabase/auth/commit/84e16ed362a38610deee94b9dbea48a855a1fbbe))
* Revert "fix: revert fallback on btree indexes when hash is unavailable" ([#1859](https://github.com/supabase/auth/issues/1859)) ([9fe5b1e](https://github.com/supabase/auth/commit/9fe5b1eebfafb385d6b5d10196aeb2a1964ab296))
* revert define search path in auth functions ([#1634](https://github.com/supabase/auth/issues/1634)) ([155e87e](https://github.com/supabase/auth/commit/155e87ef8129366d665968f64d1fc66676d07e16))
* revert fallback on btree indexes when hash is unavailable ([#1858](https://github.com/supabase/auth/issues/1858)) ([1c7202f](https://github.com/supabase/auth/commit/1c7202ff835856562ee66b33be131eca769acf1d))
* revert patch for linkedin_oidc provider error ([#1535](https://github.com/supabase/auth/issues/1535)) ([58ef4af](https://github.com/supabase/auth/commit/58ef4af0b4224b78cd9e59428788d16a8d31e562))
* revert refactor resource owner password grant ([#1466](https://github.com/supabase/auth/issues/1466)) ([fa21244](https://github.com/supabase/auth/commit/fa21244fa929709470c2e1fc4092a9ce947399e7))
* sanitizeUser leaks user role ([#1366](https://github.com/supabase/auth/issues/1366)) ([8ce9d3f](https://github.com/supabase/auth/commit/8ce9d3f7d93afb056b7ecd151545270a46002ae6))
* serialize jwt as string ([#1657](https://github.com/supabase/auth/issues/1657)) ([98d8324](https://github.com/supabase/auth/commit/98d83245e40d606438eb0afdbf474276179fd91d))
* set rate limit log level to warn ([#1652](https://github.com/supabase/auth/issues/1652)) ([10ca9c8](https://github.com/supabase/auth/commit/10ca9c806e4b67a371897f1b3f93c515764c4240))
* set the otp if it's not a test otp ([#1223](https://github.com/supabase/auth/issues/1223)) ([3afc8a9](https://github.com/supabase/auth/commit/3afc8a9a309d20a7f582f83f94a2776b1d3e13f7))
* show proper error message on textlocal ([#1338](https://github.com/supabase/auth/issues/1338)) ([44e2466](https://github.com/supabase/auth/commit/44e2466da22bc639e08bbaac1ce73bb169eca225))
* simplify WaitForCleanup ([#1747](https://github.com/supabase/auth/issues/1747)) ([0084625](https://github.com/supabase/auth/commit/0084625ad0790dd7c14b412d932425f4b84bb4c8))
* skip cleanup for non-2xx status ([#1877](https://github.com/supabase/auth/issues/1877)) ([f572ced](https://github.com/supabase/auth/commit/f572ced3699c7f920deccce1a3539299541ec94c))
* sms verify should update is_anonymous field ([#1580](https://github.com/supabase/auth/issues/1580)) ([e5f98cb](https://github.com/supabase/auth/commit/e5f98cb9e24ecebb0b7dc88c495fd456cc73fcba))
* support email verification type on token hash verification ([#1177](https://github.com/supabase/auth/issues/1177)) ([ffa5efa](https://github.com/supabase/auth/commit/ffa5efa4da8c19841e2ab2abe2709c249f427271))
* support message IDs for Twilio Whatsapp ([#1203](https://github.com/supabase/auth/issues/1203)) ([77e85c8](https://github.com/supabase/auth/commit/77e85c87f7f53245dd2792f3e885791063a1201f))
* take into account test otp for twilio verify ([#1255](https://github.com/supabase/auth/issues/1255)) ([18b4291](https://github.com/supabase/auth/commit/18b4291ea00eb0f95229f5dbe5d6474c1e563b4d))
* test otp with twilio verify ([#1259](https://github.com/supabase/auth/issues/1259)) ([ab2aba6](https://github.com/supabase/auth/commit/ab2aba69ae0261454eaef1dc9dacf8717f0bbe15))
* treat `GOTRUE_MFA_ENABLED` as meaning TOTP enabled on enroll and verify ([#1694](https://github.com/supabase/auth/issues/1694)) ([8015251](https://github.com/supabase/auth/commit/8015251400bd52cbdad3ea28afb83b1cdfe816dd))
* treat empty string as nil in `encrypted_password` ([#1663](https://github.com/supabase/auth/issues/1663)) ([f99286e](https://github.com/supabase/auth/commit/f99286eaed505daf3db6f381265ef6024e7e36d2))
* unlink identity bugs ([#1475](https://github.com/supabase/auth/issues/1475)) ([73e8d87](https://github.com/supabase/auth/commit/73e8d8742de3575b3165a707b5d2f486b2598d9d))
* unmarshal is_private_email correctly ([#1402](https://github.com/supabase/auth/issues/1402)) ([47df151](https://github.com/supabase/auth/commit/47df15113ce8d86666c0aba3854954c24fe39f7f))
* update aal requirements to update user ([#1766](https://github.com/supabase/auth/issues/1766)) ([25d9874](https://github.com/supabase/auth/commit/25d98743f6cc2cca2b490a087f468c8556ec5e44))
* update contributing to use v1.22 ([#1609](https://github.com/supabase/auth/issues/1609)) ([5894d9e](https://github.com/supabase/auth/commit/5894d9e41e7681512a9904ad47082a705e948c98))
* update dependencies (1/2) ([#1304](https://github.com/supabase/auth/issues/1304)) ([accccee](https://github.com/supabase/auth/commit/accccee91650880e530a7d9b2cd62bb5cc4a7266))
* update file name so migration to Drop IP Address is applied ([#1447](https://github.com/supabase/auth/issues/1447)) ([f29e89d](https://github.com/supabase/auth/commit/f29e89d7d2c48ee8fd5bf8279a7fa3db0ad4d842))
* update from oauth_pkce to pkce ([#1017](https://github.com/supabase/auth/issues/1017)) ([63bc007](https://github.com/supabase/auth/commit/63bc0077d38124d5846c093e0a2e02224eaba806))
* update ip mismatch error message ([#1849](https://github.com/supabase/auth/issues/1849)) ([49fbbf0](https://github.com/supabase/auth/commit/49fbbf03917a1085c58e9a1ff76c247ae6bb9ca7))
* update linkedin issuer url ([#1536](https://github.com/supabase/auth/issues/1536)) ([10d6d8b](https://github.com/supabase/auth/commit/10d6d8b1eafa504da2b2a351d1f64a3a832ab1b9))
* update MaxFrequency error message to reflect number of seconds ([#1540](https://github.com/supabase/auth/issues/1540)) ([e81c25d](https://github.com/supabase/auth/commit/e81c25d19551fdebfc5197d96bc220ddb0f8227b))
* update mfa admin methods ([#1774](https://github.com/supabase/auth/issues/1774)) ([567ea7e](https://github.com/supabase/auth/commit/567ea7ebd18eacc5e6daea8adc72e59e94459991))
* update mfa phone migration to be idempotent ([#1687](https://github.com/supabase/auth/issues/1687)) ([fdff1e7](https://github.com/supabase/auth/commit/fdff1e703bccf93217636266f1862bd0a9205edb))
* update openapi spec for MFA (Phone)  ([#1689](https://github.com/supabase/auth/issues/1689)) ([a3da4b8](https://github.com/supabase/auth/commit/a3da4b89820c37f03ea128889616aca598d99f68))
* update phone if autoconfirm is enabled ([#1431](https://github.com/supabase/auth/issues/1431)) ([95db770](https://github.com/supabase/auth/commit/95db770c5d2ecca4a1e960a8cb28ded37cccc100))
* update suggested Go version for contributors to 1.21 ([#1331](https://github.com/supabase/auth/issues/1331)) ([9feeec4](https://github.com/supabase/auth/commit/9feeec48ef85539ad5e818a45e53e262748479e5))
* upgrade ci Go version ([#1782](https://github.com/supabase/auth/issues/1782)) ([97a48f6](https://github.com/supabase/auth/commit/97a48f6daaa2edda5b568939cbb1007ccdf33cfc))
* upgrade golang-jwt to v5 ([#1639](https://github.com/supabase/auth/issues/1639)) ([2cb97f0](https://github.com/supabase/auth/commit/2cb97f080fa4695766985cc4792d09476534be68))
* upgrade pop version ([#1069](https://github.com/supabase/auth/issues/1069)) ([969691f](https://github.com/supabase/auth/commit/969691ffed3282cd09d954bf350c60d2d5d5f261))
* use `pattern` for semver docker image tags ([#1411](https://github.com/supabase/auth/issues/1411)) ([14a3aeb](https://github.com/supabase/auth/commit/14a3aeb6c3f46c8d38d98cc840112dfd0278eeda))
* use api_external_url domain as localname ([#1575](https://github.com/supabase/auth/issues/1575)) ([ed2b490](https://github.com/supabase/auth/commit/ed2b4907244281e4c54aaef74b1f4c8a8e3d97c9))
* use configured redirect URL for external providers ([#1114](https://github.com/supabase/auth/issues/1114)) ([42bb1e0](https://github.com/supabase/auth/commit/42bb1e0310cd4407a49913ac392e4da1be6f4ccd))
* use deep equal ([#1672](https://github.com/supabase/auth/issues/1672)) ([8efd57d](https://github.com/supabase/auth/commit/8efd57dab40346762a04bac61b314ce05d6fa69c))
* use email change email in identity ([#1429](https://github.com/supabase/auth/issues/1429)) ([4d3b9b8](https://github.com/supabase/auth/commit/4d3b9b8841b1a5fa8f3244825153cc81a73ba300))
* use linkedin oidc endpoint ([#1254](https://github.com/supabase/auth/issues/1254)) ([6d5c8eb](https://github.com/supabase/auth/commit/6d5c8ebb4c894d028e90493a35f43eae1d6c5e7d))
* use pointer for `user.EncryptedPassword` ([#1637](https://github.com/supabase/auth/issues/1637)) ([bbecbd6](https://github.com/supabase/auth/commit/bbecbd61a46b0c528b1191f48d51f166c06f4b16))
* use signing jwk to sign oauth state ([#1728](https://github.com/supabase/auth/issues/1728)) ([66fd0c8](https://github.com/supabase/auth/commit/66fd0c8434388bbff1e1bf02f40517aca0e9d339))
* use started transaction, not a new one ([#1196](https://github.com/supabase/auth/issues/1196)) ([0b5b656](https://github.com/supabase/auth/commit/0b5b656d1ed0870fcf9fc4b09273055d5a5b8edc))
* user sanitization should clean up email change info too ([#1759](https://github.com/supabase/auth/issues/1759)) ([9d419b4](https://github.com/supabase/auth/commit/9d419b400f0637b10e5c235b8fd5bac0d69352bd))
* validateEmail should normalise emails ([#1790](https://github.com/supabase/auth/issues/1790)) ([2e9b144](https://github.com/supabase/auth/commit/2e9b144a0cbf2d26d3c4c2eafbff1899a36aeb3b))


### Reverts

* "fix: only create or update the email / phone identity after i… ([#1407](https://github.com/supabase/auth/issues/1407)) ([ff86849](https://github.com/supabase/auth/commit/ff868493169a0d9ac18b66058a735197b1df5b9b))


### Miscellaneous Chores

* release as 2.165.2, switch to googleapis/release-please-action ([#1880](https://github.com/supabase/auth/issues/1880)) ([65961fb](https://github.com/supabase/auth/commit/65961fb6553152e735ab0f1588ede364f9df5464))

## [2.165.1](https://github.com/supabase/auth/compare/v2.165.0...v2.165.1) (2024-12-19)


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

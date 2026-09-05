# Configuration

Configure Auth using a configuration file named `.env`, environment variables, or both.

## Server

### General

```properties
GOTRUE_SITE_URL=https://example.netlify.com/
```

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_SITE_URL` | `string` | required | The base URL of your site. Auth uses it, combined with other settings, to construct URLs for emails. Auth also accepts a `redirect_to` value whose scheme, host, and port all match `GOTRUE_SITE_URL`. The port need not match for loopback addresses, per RFC 8252. To permit other destinations, add them to `GOTRUE_URI_ALLOW_LIST`. |
| `GOTRUE_URI_ALLOW_LIST` | `string` | optional (default `[]`) | A comma-separated list of URIs permitted as valid `redirect_to` destinations, for example `"https://foo.example.com,https://*.foo.example.com,https://bar.example.com"`.<br><br>Supports wildcard matching through globbing. `https://*.foo.example.com` allows `https://a.foo.example.com` and `https://b.foo.example.com`. Globbing also works on paths: `https://foo.example.com/*` allows `https://foo.example.com/page1` and `https://foo.example.com/page2`. For more glob patterns, see the [glob package documentation](https://pkg.go.dev/github.com/gobwas/glob#Compile). |
| `GOTRUE_OPERATOR_TOKEN` | `string` | optional, multi-instance mode only | The shared secret with an operator, usually Netlify, for this microservice. Auth uses it to verify that the operator proxied the request and that the payload values can be trusted. |

### API

```properties
GOTRUE_API_HOST=localhost
PORT=9999
API_EXTERNAL_URL=http://localhost:9999
```

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `API_EXTERNAL_URL` (no prefix) | `string` | required | The URL on which Auth is accessible. |
| `GOTRUE_API_HOST` | `string` | optional | Hostname to listen on. |
| `GOTRUE_API_PORT` / `PORT` (no prefix) | `number` | `8081` | Port number to listen on. |
| `GOTRUE_API_ENDPOINT` | `string` | optional, multi-instance mode only | Controls what endpoint Netlify can access this API on. |
| `GOTRUE_API_REQUEST_ID_HEADER` | `string` | optional | The name of the header Auth reads an inherited request ID from on the incoming request. |
| `GOTRUE_API_MAX_REQUEST_DURATION` | `duration` | `10s` | The maximum time a single API request may take before Auth cancels it. |

### Database

```properties
GOTRUE_DB_DRIVER=postgres
DATABASE_URL=root@localhost/auth
```

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_DB_DRIVER` | `string` | required | The database dialect. Must be `postgres`. |
| `GOTRUE_DB_DATABASE_URL` / `DATABASE_URL` (no prefix) | `string` | required | Connection string for the database. |
| `DB_NAMESPACE` (no prefix) | `string` | `auth` | A prefix added to all table names. |
| `GOTRUE_DB_MAX_POOL_SIZE` | `int` | `0` (unlimited connections) | The maximum number of open connections to the database. |
| `GOTRUE_DB_MAX_IDLE_POOL_SIZE` | `int` | optional | The maximum number of idle connections to keep in the pool. |
| `GOTRUE_DB_CONN_PERCENTAGE` | `int` | optional | The percentage (1-100) of available database connections Auth may use. Values outside the range are clamped. |
| `GOTRUE_DB_CONN_MAX_LIFETIME` | `duration` | optional | The maximum time a connection may be reused before it is closed. |
| `GOTRUE_DB_CONN_MAX_IDLE_TIME` | `duration` | optional | The maximum time a connection may sit idle before it is closed. |
| `GOTRUE_DB_HEALTH_CHECK_PERIOD` | `duration` | optional | How often the pool checks the health of idle connections. |
| `GOTRUE_DB_MIGRATIONS_PATH` | `string` | `./migrations` | The path to the migrations directory. |
| `GOTRUE_DB_CLEANUP_ENABLED` | `bool` | `false` | Whether Auth periodically cleans up expired rows, such as stale sessions and tokens. |
| `GOTRUE_DB_ADVISOR_ENABLED` | `bool` | `true` | Whether the database advisor, which samples query performance, is enabled. |
| `GOTRUE_DB_ADVISOR_SAMPLING_INTERVAL` | `duration` | `200ms` | How often the advisor samples query activity. |
| `GOTRUE_DB_ADVISOR_OBSERVATION_INTERVAL` | `duration` | `20s` | How often the advisor reports its observations. |

**Migrations**

Auth applies migrations automatically when you run `./auth`. You can also rerun the migrations directly:

- If built locally: `./auth migrate`
- Using Docker: `docker run --rm auth auth migrate`

### Logging

```properties
GOTRUE_LOG_LEVEL=debug
GOTRUE_LOG_FILE=/var/log/go/auth.log
```

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_LOG_LEVEL` | `string` | `info` | The log level Auth outputs. Choose from `panic`, `fatal`, `error`, `warn`, `info`, or `debug`. |
| `GOTRUE_LOG_FILE` | `string` | optional | A file path to write logs to. |
| `GOTRUE_LOG_SQL` | `string` | optional | The log level for SQL queries. |
| `GOTRUE_LOG_TSFORMAT` | `string` | optional | The timestamp format for log entries. |
| `GOTRUE_LOG_DISABLE_COLORS` | `bool` | `false` | Whether to disable ANSI colors in console log output. |
| `GOTRUE_LOG_QUOTE_EMPTY_FIELDS` | `bool` | `false` | Whether to quote empty fields in log output. |
| `GOTRUE_LOG_FIELDS` | `string` (JSON) | optional, advanced | Default fields added to every log entry, as a JSON object. |

### Audit log

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_AUDIT_LOG_DISABLE_POSTGRES` | `bool` | `false` | When `true`, Auth stops writing audit log entries to Postgres. |

### CORS

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_CORS_ALLOWED_HEADERS` | `string` | optional | A comma-separated list of extra request headers to allow, added to the built-in defaults. |

### Profiler

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_PROFILER_ENABLED` | `bool` | `false` | Whether the pprof profiling server is enabled. |
| `GOTRUE_PROFILER_HOST` | `string` | `localhost` | Host the profiling server binds to. |
| `GOTRUE_PROFILER_PORT` | `string` | `9998` | Port the profiling server binds to. |

### User search indexes

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_INDEX_WORKER_ENSURE_USER_SEARCH_INDEXES_EXIST` | `bool` | `false` | When `true`, Auth always creates the user-search indexes, ignoring the threshold. |
| `GOTRUE_INDEX_WORKER_MAX_USERS_THRESHOLD` | `int` | `0` | When greater than 0, Auth creates the indexes only if the user count is at or below this threshold. `0` disables the progressive rollout. Has no effect when the setting above is `true`. |

### Configuration reloading

These startup values control runtime configuration reloads. They take effect only when you provide the `--config-dir` flag, and they stay fixed across reloads.

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_RELOADING_NOTIFY_ENABLED` | `bool` | `true` | Whether Auth watches the config directory for changes using filesystem notifications. |
| `GOTRUE_RELOADING_POLLERENABLED` | `bool` | `false` | Whether Auth falls back to filesystem polling when notifications are unavailable. |
| `GOTRUE_RELOADING_POLLER_INTERVAL` | `duration` | `10s` | How often to poll the filesystem when polling is used. |
| `GOTRUE_RELOADING_SIGNAL_ENABLED` | `bool` | `false` | Whether Auth reloads the config when it receives the configured signal. |
| `GOTRUE_RELOADING_SIGNAL_NUMBER` | `int` | `10` | The signal number that triggers a reload. `10` is `SIGUSR1` on Linux. |
| `GOTRUE_RELOADING_GRACE_PERIOD_INTERVAL` | `duration` | `5s` | How much idle time must pass after a burst of changes before Auth reloads, so a burst triggers a single reload. |

## Observability

Auth has basic observability built in. It can export [OpenTelemetry](https://opentelemetry.io) metrics and traces to a collector.

### Tracing

To enable tracing, configure these variables.

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_TRACING_ENABLED` | `bool` | `false` | Whether tracing is enabled. |
| `GOTRUE_TRACING_EXPORTER` | `string` | `opentelemetry` | Only `opentelemetry` is supported. |
| `GOTRUE_TRACING_SERVICE_NAME` | `string` | `gotrue` | The service name reported in traces. |
| `GOTRUE_TRACING_HOST` | `string` | optional | The tracing collector host. |
| `GOTRUE_TRACING_PORT` | `string` | optional | The tracing collector port. |
| `GOTRUE_TRACING_TAGS` | `string` | optional | Comma-separated `key:value` tags added to traces. |
| `OTEL_EXPORTER_OTLP_PROTOCOL` (no prefix) | `string` | `http/protobuf` | The OTLP exporter protocol, for example `grpc`. |

You must also configure the [OpenTelemetry exporter](https://opentelemetry.io/docs/reference/specification/protocol/exporter/) for your collector or service.

For example, if you use [Honeycomb.io](https://docs.honeycomb.io/getting-data-in/opentelemetry/go-distro/#using-opentelemetry-without-the-honeycomb-distribution), set these standard OpenTelemetry OTLP variables:

```
OTEL_SERVICE_NAME=auth
OTEL_EXPORTER_OTLP_PROTOCOL=grpc
OTEL_EXPORTER_OTLP_ENDPOINT=https://api.honeycomb.io:443
OTEL_EXPORTER_OTLP_HEADERS="x-honeycomb-team=<API-KEY>,x-honeycomb-dataset=auth"
```

### Metrics

To enable metrics, configure these variables.

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_METRICS_ENABLED` | `bool` | `false` | Whether metrics are enabled. |
| `GOTRUE_METRICS_EXPORTER` | `string` | `opentelemetry` | Only `opentelemetry` and `prometheus` are supported. |
| `OTEL_EXPORTER_PROMETHEUS_HOST` (no prefix) | IP address | `0.0.0.0` | The server host to bind the `prometheus` exporter to. |
| `OTEL_EXPORTER_PROMETHEUS_PORT` (no prefix) | port number | `9100` | The server port to bind the `prometheus` exporter to. |

You must also configure the [OpenTelemetry exporter](https://opentelemetry.io/docs/reference/specification/protocol/exporter/) for your collector or service. If you use the `prometheus` exporter, Auth serves the metrics at the `/` path on the server.

If you use the `opentelemetry` exporter, Auth pushes the metrics to the collector.

### Custom resource attributes

When using the OpenTelemetry tracing or metrics exporter you can define custom resource attributes using the [standard `OTEL_RESOURCE_ATTRIBUTES` environment variable](https://opentelemetry.io/docs/reference/specification/resource/sdk/#specifying-resource-information-via-an-environment-variable).

Auth provides a default attribute, `auth.version`, containing the build version.

### Tracing HTTP routes

Auth traces all HTTP calls to its API. It records each route in parametrized form and records each parameter value as the `http.route.params.<route-key>` span attribute.

For example, the following request:

```
GET /admin/users/4acde936-82dc-4552-b851-831fb8ce0927/
```

is traced as:

```
http.method = GET
http.route = /admin/users/{user_id}
http.route.params.user_id = 4acde936-82dc-4552-b851-831fb8ce0927
```

### Go runtime and HTTP metrics

Auth exposes all Go runtime metrics. It also collects some HTTP metrics by default.

## Authentication

### Sign-up

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_DISABLE_SIGNUP` | `bool` | `false` | When `true`, invites become the only way to create new users. When `false`, all signups are enabled. |
| `GOTRUE_EXTERNAL_EMAIL_ENABLED` | `bool` | `true` | Set to `false` to disable email signups. Users can still use external OAuth providers to sign up or sign in. |
| `GOTRUE_EXTERNAL_EMAIL_MAGIC_LINK_ENABLED` | `bool` | `true` | Whether magic-link sign-in over email is enabled. |
| `GOTRUE_EXTERNAL_EMAIL_AUTHORIZED_ADDRESSES` | `string` | optional | A comma-separated allowlist of email addresses permitted to sign up. When unset, any address may sign up. |
| `GOTRUE_EXTERNAL_PHONE_ENABLED` | `bool` | `false` | Set to `true` to enable phone signups. Phone signups are disabled by default. |

### JSON Web Tokens (JWT)

```properties
GOTRUE_JWT_SECRET=supersecretvalue
GOTRUE_JWT_EXP=3600
GOTRUE_JWT_AUD=netlify
```

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_JWT_SECRET` | `string` | required | The secret used to sign JWT tokens with. |
| `GOTRUE_JWT_EXP` | `number` | `3600` (1 hour) | How long, in seconds, tokens remain valid. |
| `GOTRUE_JWT_AUD` | `string` | optional | The default JWT audience. Use audiences to group users. |
| `GOTRUE_JWT_ADMIN_GROUP_NAME` | `string` | `admin` | The name of the admin group, if enabled. |
| `GOTRUE_JWT_ADMIN_ROLES` | `string` | `service_role,supabase_admin` | A comma-separated list of roles treated as admin. |
| `GOTRUE_JWT_DEFAULT_GROUP_NAME` | `string` | optional | The default group for all new users. |
| `GOTRUE_JWT_ISSUER` | `string` | optional | The `iss` claim to set on issued tokens. |
| `GOTRUE_JWT_KEY_ID` | `string` | optional | The `kid` for the signing key derived from `GOTRUE_JWT_SECRET`. |
| `GOTRUE_JWT_KEYS` | `string` (JSON) | optional, advanced | A JSON array of JWKs used for signing and verification. When set, it takes the place of `GOTRUE_JWT_SECRET`. |
| `GOTRUE_JWT_VALID_METHODS` | `string` | optional, advanced | A comma-separated list of accepted signing algorithms. Derived from the configured keys when unset. |

### External authentication providers

Auth supports `apple`, `azure`, `bitbucket`, `discord`, `facebook`, `figma`, `fly`, `github`, `gitlab`, `google`, `kakao`, `keycloak`, `linkedin`, `linkedin_oidc`, `notion`, `slack`, `slack_oidc`, `snapchat`, `spotify`, `twitch`, `twitter`, `vercel_marketplace`, `workos`, `x`, and `zoom` for external authentication.

Use the provider name as the key underneath `external` to configure each one separately.

```properties
GOTRUE_EXTERNAL_GITHUB_ENABLED=true
GOTRUE_EXTERNAL_GITHUB_CLIENT_ID=myappclientid
GOTRUE_EXTERNAL_GITHUB_SECRET=clientsecretvaluessssh
GOTRUE_EXTERNAL_GITHUB_REDIRECT_URI=http://localhost:3000/callback
```

External providers are optional, but each one you enable needs its required values. Replace `X` in the variable names below with the uppercased provider name, for example `GOTRUE_EXTERNAL_GITHUB_ENABLED`.

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_EXTERNAL_X_ENABLED` | `bool` | optional | Whether this external provider is enabled. |
| `GOTRUE_EXTERNAL_X_CLIENT_ID` | `string` | required if enabled | The OAuth2 client ID registered with the external provider. Accepts a comma-separated list to allow more than one client ID. |
| `GOTRUE_EXTERNAL_X_SECRET` | `string` | required if enabled | The OAuth2 client secret the external provider issued when you registered. |
| `GOTRUE_EXTERNAL_X_REDIRECT_URI` | `string` | required if enabled | The URI an OAuth2 provider redirects to with the `code` and `state` values. |
| `GOTRUE_EXTERNAL_X_URL` | `string` | required for `keycloak` | The base URL used to construct the authorization and access token URLs. Used by `gitlab` and `keycloak`. For `gitlab` it is optional and defaults to `https://gitlab.com`. For `keycloak` it is required: set it to your instance, for example `https://keycloak.example.com/realms/myrealm`. |
| `GOTRUE_EXTERNAL_X_API_URL` | `string` | optional | Overrides the userinfo/API base URL for the provider, when it differs from the authorization URL. |
| `GOTRUE_EXTERNAL_X_EMAIL_OPTIONAL` | `bool` | optional | When `true`, Auth allows sign-in even if the provider returns no email address. |
| `GOTRUE_EXTERNAL_X_SKIP_NONCE_CHECK` | `bool` | optional | When `true`, Auth skips nonce verification during OIDC token validation. Nonce verification helps prevent replay attacks; only disable it when necessary. |

#### Shared provider settings

These apply across providers rather than to a single one.

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_EXTERNAL_REDIRECTURL` | `string` | optional | The default redirect URL used after an external sign-in. |
| `GOTRUE_EXTERNAL_IOS_BUNDLE_ID` | `string` | optional | The iOS bundle identifier accepted for native Apple sign-in. |
| `GOTRUE_EXTERNAL_ALLOWED_ID_TOKEN_ISSUERS` | `string` | `https://appleid.apple.com,https://accounts.google.com` | A comma-separated list of issuers accepted for ID-token sign-in. |
| `GOTRUE_EXTERNAL_FLOW_STATE_EXPIRY_DURATION` | `duration` | `300s` | How long a PKCE flow state remains valid. Values below `300s` are raised to `300s`. |
| `GOTRUE_EXTERNAL_OIDC_PROVIDER_CACHE_TTL` | `duration` | `1h` | How long Auth caches OIDC discovery documents. |

#### Network hardening

Configuring an external authentication provider causes Auth to make outbound HTTP requests to that provider's authorization, token, and userinfo endpoints. Configuring a provider, either through `GOTRUE_EXTERNAL_*` settings or an admin API, is an administrative action, and doing so implies trust in the hosts and URLs Auth will contact.

Harden the network Auth runs in so these outbound connections cannot reach internal-only resources you don't want exposed, such as `localhost`/loopback addresses or cloud metadata endpoints such as `169.254.169.254`. This matters most for providers with admin-configurable or discoverable endpoints, such as custom OAuth or OIDC providers, where a misconfigured or malicious URL could otherwise reach internal infrastructure.

#### Apple OAuth

To try external authentication with Apple locally, do the following:

1. Remap `localhost` to a custom hostname in your `/etc/hosts` config.
2. Serve your local Auth instance over HTTPS. Use a local tunnel such as [ngrok](https://ngrok.com) and point `API_EXTERNAL_URL` at the tunnel's HTTPS URL.
3. Generate the `GOTRUE_EXTERNAL_APPLE_SECRET` by following this [post](https://medium.com/identity-beyond-borders/how-to-configure-sign-in-with-apple-77c61e336003).

### Custom OAuth providers

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_CUSTOM_OAUTH_ENABLED` | `bool` | `true` | Whether custom OAuth and OIDC providers are enabled. |
| `GOTRUE_CUSTOM_OAUTH_MAX_PROVIDERS` | `int` | `0` (unlimited) | The maximum number of custom providers that can be configured. |
| `GOTRUE_CUSTOM_OAUTH_EXTERNAL_URL` | `string` | optional | Overrides the external URL advertised for custom provider callbacks. |

### OAuth server

Auth can act as an OAuth 2.0 authorization server.

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_OAUTH_SERVER_ENABLED` | `bool` | `false` | Whether the OAuth authorization server is enabled. |
| `GOTRUE_OAUTH_SERVER_ALLOW_DYNAMIC_REGISTRATION` | `bool` | optional | Whether dynamic client registration is allowed. |
| `GOTRUE_OAUTH_SERVER_AUTHORIZATION_PATH` | `string` | optional | The path served for the authorization endpoint. |
| `GOTRUE_OAUTH_SERVER_AUTHORIZATION_TTL` | `duration` | `10m` | How long an authorization code remains valid. |
| `GOTRUE_OAUTH_SERVER_DEFAULT_SCOPE` | `string` | `email` | The default scope granted when none is requested. |

### Web3 (wallet) sign-in

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_EXTERNAL_WEB3_SOLANA_ENABLED` | `bool` | optional | Whether Sign in with Solana is enabled. |
| `GOTRUE_EXTERNAL_WEB3_SOLANA_MAXIMUM_VALIDITY_DURATION` | `duration` | `10m` | How long a signed Solana message remains valid. |
| `GOTRUE_EXTERNAL_WEB3_ETHEREUM_ENABLED` | `bool` | optional | Whether Sign in with Ethereum is enabled. |
| `GOTRUE_EXTERNAL_WEB3_ETHEREUM_MAXIMUM_VALIDITY_DURATION` | `duration` | `10m` | How long a signed Ethereum message remains valid. |

### SAML single sign-on

```properties
GOTRUE_SAML_ENABLED=true
GOTRUE_SAML_PRIVATE_KEY=<base64-encoded PKCS#1 DER key>
```

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_SAML_ENABLED` | `bool` | `false` | Whether SAML SSO support is enabled. |
| `GOTRUE_SAML_PRIVATE_KEY` | `string` | required if enabled | The active signing and decryption key. PKCS#1 DER format, Base64-encoded. Must be RSA 2048 or larger with the 65537 public exponent. |
| `GOTRUE_SAML_PRIVATE_KEY_NEXT` | `string` | optional | An incoming key for zero-downtime key rotation. Advertised in SAML metadata alongside `GOTRUE_SAML_PRIVATE_KEY` and used as a decryption fallback. See the [SAML SP key rotation runbook](saml_key_rotation.md) for the full rotation procedure. |
| `GOTRUE_SAML_ALLOW_ENCRYPTED_ASSERTIONS` | `bool` | optional | Whether Auth accepts encrypted SAML assertions from the identity provider. |
| `GOTRUE_SAML_RELAY_STATE_VALIDITY_PERIOD` | `duration` | `2m` | How long a SAML `RelayState` value remains valid. |
| `GOTRUE_SAML_EXTERNAL_URL` | `string` | optional | Overrides the URL Auth advertises for the SAML SP entity ID and endpoints, if it differs from `API_EXTERNAL_URL`. |
| `GOTRUE_SAML_RATE_LIMIT_ASSERTION` | `float` | `15` | Maximum SAML assertions accepted per 5 minutes per client IP. |

### Phone auth

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_SMS_AUTOCONFIRM` | `bool` | `false` | Set to `true` if you do not require phone confirmation. |
| `GOTRUE_SMS_MAX_FREQUENCY` | `duration` | `1m` | The minimum time between one SMS OTP and the next, for example `1m` or `60s`. |
| `GOTRUE_SMS_OTP_EXP` | `number` | `60` | How long an SMS OTP remains valid, in seconds. |
| `GOTRUE_SMS_OTP_LENGTH` | `number` | `6` | The number of digits of the SMS OTP sent. |
| `GOTRUE_SMS_PROVIDER` | `string` | optional | Available options are `twilio`, `twilio_verify`, `messagebird`, `textlocal`, and `vonage`. |
| `GOTRUE_SMS_TEMPLATE` | `string` | optional | The message template for the OTP SMS. The `{{ .Code }}` variable is available. |
| `GOTRUE_SMS_TEST_OTP` | `string` | optional | A comma-separated list of `phone:code` pairs that bypass the provider and always verify, for testing. |
| `GOTRUE_SMS_TEST_OTP_VALID_UNTIL` | `time` | optional | The timestamp after which the test OTPs stop working. |
| `GOTRUE_SMS_TWILIO_ACCOUNT_SID` | `string` | required for Twilio | Your [Twilio account SID](https://www.twilio.com/docs/usage/requests-to-twilio#credentials). |
| `GOTRUE_SMS_TWILIO_AUTH_TOKEN` | `string` | required for Twilio | Your [Twilio auth token](https://www.twilio.com/docs/usage/requests-to-twilio#credentials). |
| `GOTRUE_SMS_TWILIO_MESSAGE_SERVICE_SID` | `string` | required for Twilio | Your Twilio message service SID. Can be set to your Twilio sender mobile number. |
| `GOTRUE_SMS_TWILIO_CONTENT_SID` | `string` | optional | The Twilio content template SID, when using content templates. |
| `GOTRUE_SMS_TWILIO_VERIFY_ACCOUNT_SID` | `string` | required for Twilio Verify | Your Twilio account SID for the Verify service. |
| `GOTRUE_SMS_TWILIO_VERIFY_AUTH_TOKEN` | `string` | required for Twilio Verify | Your Twilio auth token for the Verify service. |
| `GOTRUE_SMS_TWILIO_VERIFY_MESSAGE_SERVICE_SID` | `string` | required for Twilio Verify | Your Twilio Verify service SID. |
| `GOTRUE_SMS_MESSAGEBIRD_ACCESS_KEY` | `string` | required for Messagebird | Your Messagebird access key. Find it in the [Messagebird dashboard](https://dashboard.messagebird.com/en/developers/access). |
| `GOTRUE_SMS_MESSAGEBIRD_ORIGINATOR` | `string` | required for Messagebird | The SMS sender: your Messagebird phone number with `+`, or a company name. |
| `GOTRUE_SMS_TEXTLOCAL_API_KEY` | `string` | required for Textlocal | Your Textlocal API key. |
| `GOTRUE_SMS_TEXTLOCAL_SENDER` | `string` | required for Textlocal | Your Textlocal sender ID. |
| `GOTRUE_SMS_VONAGE_API_KEY` | `string` | required for Vonage | Your Vonage API key. |
| `GOTRUE_SMS_VONAGE_API_SECRET` | `string` | required for Vonage | Your Vonage API secret. |
| `GOTRUE_SMS_VONAGE_FROM` | `string` | required for Vonage | The Vonage sender phone number or name. |

### Multi-factor authentication (MFA)

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_MFA_CHALLENGE_EXPIRY_DURATION` | `float` | `300` | How long, in seconds, an MFA challenge remains valid. Values below `300` are raised to `300`. |
| `GOTRUE_MFA_FACTOR_EXPIRY_DURATION` | `duration` | `300s` | How long an unverified factor remains before expiry. Values below `300s` are raised to `300s`. |
| `GOTRUE_MFA_MAX_ENROLLED_FACTORS` | `float` | `10` | The maximum number of factors a user may enroll. |
| `GOTRUE_MFA_MAX_VERIFIED_FACTORS` | `int` | `10` | The maximum number of verified factors a user may have. |
| `GOTRUE_MFA_RATE_LIMIT_CHALLENGE_AND_VERIFY` | `float` | `15` | Maximum challenge and verify attempts per minute per client IP. |
| `GOTRUE_MFA_TOTP_ENROLL_ENABLED` | `bool` | `true` | Whether users may enroll a TOTP factor. |
| `GOTRUE_MFA_TOTP_VERIFY_ENABLED` | `bool` | `true` | Whether users may verify with a TOTP factor. |
| `GOTRUE_MFA_PHONE_ENROLL_ENABLED` | `bool` | `false` | Whether users may enroll a phone factor. |
| `GOTRUE_MFA_PHONE_VERIFY_ENABLED` | `bool` | `false` | Whether users may verify with a phone factor. |
| `GOTRUE_MFA_PHONE_OTP_LENGTH` | `int` | `6` | The number of digits in the phone MFA OTP. |
| `GOTRUE_MFA_PHONE_MAX_FREQUENCY` | `duration` | `1m` | The minimum time between one phone MFA message and the next. |
| `GOTRUE_MFA_PHONE_TEMPLATE` | `string` | optional | The message template for the phone MFA OTP. The `{{ .Code }}` variable is available. |
| `GOTRUE_MFA_WEB_AUTHN_ENROLL_ENABLED` | `bool` | `false` | Whether users may enroll a WebAuthn factor. |
| `GOTRUE_MFA_WEB_AUTHN_VERIFY_ENABLED` | `bool` | `false` | Whether users may verify with a WebAuthn factor. |
| `GOTRUE_MFA_RECOVERY_CODES_ENROLL_ENABLED` | `bool` | `false` | Whether recovery codes may be generated. |
| `GOTRUE_MFA_RECOVERY_CODES_VERIFY_ENABLED` | `bool` | `false` | Whether recovery codes may be used to verify. |
| `GOTRUE_MFA_RECOVERY_CODES_COUNT` | `int` | `10` | The number of recovery codes generated. Must be 4-16 when enabled. |
| `GOTRUE_MFA_RECOVERY_CODES_CODE_LENGTH` | `int` | `16` | The length of each recovery code. Must be 13-32 when enabled. |
| `GOTRUE_MFA_RECOVERY_CODES_MAX_VERIFY_ATTEMPTS` | `int` | `5` | The maximum failed verification attempts. Must be 3-15 when enabled. |
| `GOTRUE_MFA_RECOVERY_CODES_LOCKOUT_DURATION` | `duration` | `15m` | How long a user is locked out after too many failed attempts. Must be between `1m` and `24h` when enabled. |

### WebAuthn

Required when WebAuthn MFA or passkeys are enabled.

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_WEBAUTHN_RP_ID` | `string` | required if enabled | The relying party ID, usually your site's domain. |
| `GOTRUE_WEBAUTHN_RP_DISPLAY_NAME` | `string` | required if enabled | The relying party display name shown to users. |
| `GOTRUE_WEBAUTHN_RP_ORIGINS` | `string` | required if enabled | A comma-separated list of allowed origins. |
| `GOTRUE_WEBAUTHN_CHALLENGE_EXPIRY_DURATION` | `duration` | `5m` | How long a WebAuthn challenge remains valid. |

### Passkeys

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_PASSKEY_ENABLED` | `bool` | `false` | Whether passkey sign-in is enabled. Requires the WebAuthn settings above. |
| `GOTRUE_PASSKEY_MAX_PASSKEYS_PER_USER` | `int` | `10` | The maximum number of passkeys a user may register. |

### Sessions

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_SESSIONS_TIMEBOX` | `duration` | optional | The maximum lifetime of a session, after which it ends regardless of activity. Must be positive when set. |
| `GOTRUE_SESSIONS_INACTIVITY_TIMEOUT` | `duration` | optional | How long a session may be idle before it ends. Must be positive when set. |
| `GOTRUE_SESSIONS_ALLOW_LOW_AAL` | `duration` | optional | How long a session may keep a low assurance level before MFA is required. Must be positive when set. |
| `GOTRUE_SESSIONS_SINGLE_PER_USER` | `bool` | optional | When `true`, each user may have only one active session. |
| `GOTRUE_SESSIONS_TAGS` | `string` | optional | A comma-separated list of tags applied to sessions. |

### Auth hooks

Each hook points at a Postgres function (`pg-functions://...`) or an HTTPS endpoint. Replace `HOOK` below with one of `MFA_VERIFICATION_ATTEMPT`, `PASSWORD_VERIFICATION_ATTEMPT`, `CUSTOM_ACCESS_TOKEN`, `SEND_EMAIL`, `SEND_SMS`, `BEFORE_USER_CREATED`, or `AFTER_USER_CREATED`.

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_HOOK_HOOK_ENABLED` | `bool` | optional | Whether this hook is enabled. |
| `GOTRUE_HOOK_HOOK_URI` | `string` | required if enabled | The hook target. `pg-functions://<schema>/<function>` or an `https://` URL. `http://` is allowed only for localhost. |
| `GOTRUE_HOOK_HOOK_SECRETS` | `string` | required for HTTP hooks | Pipe-separated webhook signing secrets, for example `v1,whsec_...|v1a,whpk_...`. |

### Anonymous sign-ins

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_EXTERNAL_ANONYMOUS_USERS_ENABLED` | `bool` | `false` | Enable or disable anonymous sign-ins. |

### Experimental

These settings may change or be removed in a future release.

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_EXPERIMENTAL_SCIM_ENABLED` | `bool` | `false` | Gates the `/scim/v2` router. |
| `GOTRUE_EXPERIMENTAL_CURSOR_PAGINATION_ENABLED` | `bool` | `false` | Enables cursor-based pagination for the admin user list endpoint. |
| `GOTRUE_EXPERIMENTAL_CREATE_EMAIL_IDENTITY_ON_PASSWORD_SET_ENABLED` | `bool` | `false` | Creates a missing email identity when a password is added to an account that had none. |
| `GOTRUE_EXPERIMENTAL_PROVIDER_LINKING_DOMAINS` | `string` | optional | A comma-separated list of `provider=domain` pairs. Providers mapped to the same domain link to one another but stay isolated from the default email-linked pool, for example `custom:github=social,custom:google=social`. |
| `GOTRUE_EXPERIMENTAL_PROVIDERS_WITH_OWN_LINKING_DOMAIN` | `string` | deprecated | Use `GOTRUE_EXPERIMENTAL_PROVIDER_LINKING_DOMAINS` instead. A comma-separated list of providers that do not participate in email-similarity linking. |

## Email

Sending email is not required, but is highly recommended for password recovery. If you enable it, provide the values below.

```properties
GOTRUE_SMTP_HOST=smtp.mandrillapp.com
GOTRUE_SMTP_PORT=587
GOTRUE_SMTP_USER=smtp-delivery@example.com
GOTRUE_SMTP_PASS=correcthorsebatterystaple
GOTRUE_SMTP_ADMIN_EMAIL=support@example.com
GOTRUE_MAILER_SUBJECTS_CONFIRMATION="Please confirm"
```

### Delivery (SMTP)

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_SMTP_HOST` | `string` | optional | The mail server hostname to send emails through. When unset, Auth skips sending email. |
| `GOTRUE_SMTP_PORT` | `number` | `587` | The port number for connecting to the mail server. |
| `GOTRUE_SMTP_USER` | `string` | optional | If the mail server requires authentication, the username to use. |
| `GOTRUE_SMTP_PASS` | `string` | optional | If the mail server requires authentication, the password to use. |
| `GOTRUE_SMTP_ADMIN_EMAIL` | `string` | optional | The `From` email address for all emails sent. |
| `GOTRUE_SMTP_SENDER_NAME` | `string` | optional | The display name for the `From` address. When unset, the address has no display name. |
| `GOTRUE_SMTP_MAX_FREQUENCY` | `duration` | `1m` | The minimum time between a signup confirmation or password reset email and the next, for example `1m` or `60s`. |
| `GOTRUE_SMTP_HEADERS` | `string` (JSON) | optional | Extra headers to add to every email, as a JSON object of header name to list of values. Invalid JSON is ignored. |
| `GOTRUE_SMTP_LOGGING_ENABLED` | `bool` | `false` | Whether Auth logs SMTP activity. |

### Message behavior

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_MAILER_AUTOCONFIRM` | `bool` | `false` | Set to `true` if you do not require email confirmation. |
| `GOTRUE_MAILER_ALLOW_UNVERIFIED_EMAIL_SIGN_INS` | `bool` | `false` | When `true`, users may sign in before confirming their email. Cannot be combined with `GOTRUE_MAILER_AUTOCONFIRM`. |
| `GOTRUE_MAILER_SECURE_EMAIL_CHANGE_ENABLED` | `bool` | `true` | When `true`, changing an email requires confirmation from both the old and new address. |
| `GOTRUE_MAILER_OTP_EXP` | `number` | `86400` (1 day) | How long an email link or OTP remains valid. |
| `GOTRUE_MAILER_OTP_LENGTH` | `int` | `6` | The number of digits in an email OTP. |
| `GOTRUE_MAILER_URLPATHS_INVITE` | `string` | `/verify` | URL path to use in the user invite email. |
| `GOTRUE_MAILER_URLPATHS_CONFIRMATION` | `string` | `/verify` | URL path to use in the signup confirmation email. |
| `GOTRUE_MAILER_URLPATHS_RECOVERY` | `string` | `/verify` | URL path to use in the password reset email. |
| `GOTRUE_MAILER_URLPATHS_EMAIL_CHANGE` | `string` | `/verify` | URL path to use in the email change confirmation email. |
| `GOTRUE_MAILER_EXTERNAL_HOSTS` | `string` | optional | A comma-separated allowlist of hosts permitted in email redirect links. |
| `GOTRUE_MAILER_EMAIL_BACKGROUND_SENDING` | `bool` | `false` | When `true`, Auth sends email in the background rather than during the request. |
| `GOTRUE_MAILER_EMAIL_VALIDATION_EXTENDED` | `bool` | `false` | When `true`, Auth performs extended validation of recipient email addresses. |
| `GOTRUE_MAILER_EMAIL_VALIDATION_SERVICE_URL` | `string` | optional | The URL of an external email validation service. |
| `GOTRUE_MAILER_EMAIL_VALIDATION_SERVICE_HEADERS` | `string` (JSON) | optional | Headers for the validation service, as a JSON object of header name to list of values. |
| `GOTRUE_MAILER_EMAIL_VALIDATION_BLOCKED_MX` | `string` (JSON) | optional | A JSON array of MX hostnames whose domains are rejected. |
| `GOTRUE_MAILER_TEMPLATE_MAX_SIZE` | `int` | `1000000` | The maximum number of bytes read from a remote template endpoint. |
| `GOTRUE_MAILER_TEMPLATE_MAX_AGE` | `duration` | `10m` | How long a fetched template is used before it is considered stale. |
| `GOTRUE_MAILER_TEMPLATE_RETRY_INTERVAL` | `duration` | `10s` | The time between retries after a failed template reload. |
| `GOTRUE_MAILER_TEMPLATE_RELOADING_ENABLED` | `bool` | `false` | Whether templates reload in the background to avoid blocking requests. |
| `GOTRUE_MAILER_TEMPLATE_RELOADING_MAX_IDLE` | `duration` | `20m` | The maximum idle time before background template reloading stops. |

### Subjects

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_MAILER_SUBJECTS_INVITE` | `string` | `You've been invited` | Email subject to use for user invite. |
| `GOTRUE_MAILER_SUBJECTS_CONFIRMATION` | `string` | `Confirm your email address` | Email subject to use for signup confirmation. |
| `GOTRUE_MAILER_SUBJECTS_RECOVERY` | `string` | `Reset your password` | Email subject to use for password reset. |
| `GOTRUE_MAILER_SUBJECTS_MAGIC_LINK` | `string` | `Your sign-in link` | Email subject to use for magic link email. |
| `GOTRUE_MAILER_SUBJECTS_EMAIL_CHANGE` | `string` | `Confirm your new email address` | Email subject to use for email change confirmation. |
| `GOTRUE_MAILER_SUBJECTS_REAUTHENTICATION` | `string` | `{{ .Token }} is your verification code` | Email subject to use for reauthentication. |
| `GOTRUE_MAILER_SUBJECTS_PASSWORD_CHANGED_NOTIFICATION` | `string` | `Your password was changed` | Email subject to use for password changed notification. |
| `GOTRUE_MAILER_SUBJECTS_EMAIL_CHANGED_NOTIFICATION` | `string` | `Your email address was changed` | Email subject to use for email changed notification. |
| `GOTRUE_MAILER_SUBJECTS_PHONE_CHANGED_NOTIFICATION` | `string` | `Your phone number was changed` | Email subject to use for phone changed notification. |
| `GOTRUE_MAILER_SUBJECTS_IDENTITY_LINKED_NOTIFICATION` | `string` | `A new sign-in method was linked to your account` | Email subject to use for identity linked notification. |
| `GOTRUE_MAILER_SUBJECTS_IDENTITY_UNLINKED_NOTIFICATION` | `string` | `A sign-in method was removed from your account` | Email subject to use for identity unlinked notification. |
| `GOTRUE_MAILER_SUBJECTS_MFA_FACTOR_ENROLLED_NOTIFICATION` | `string` | `A new verification method was added to your account` | Email subject to use for verification method added notification. |
| `GOTRUE_MAILER_SUBJECTS_MFA_FACTOR_UNENROLLED_NOTIFICATION` | `string` | `A verification method was removed from your account` | Email subject to use for verification method removed notification. |

### Templates

Each value is a URL path to an email template. Default content, used when the template is unavailable, is shown under "Default template content".

| Variable | Type | Default/Required | Available variables |
| --- | --- | --- | --- |
| `GOTRUE_MAILER_TEMPLATES_INVITE` | `string` | optional | `SiteURL`, `Email`, `ConfirmationURL` |
| `GOTRUE_MAILER_TEMPLATES_CONFIRMATION` | `string` | optional | `SiteURL`, `Email`, `ConfirmationURL` |
| `GOTRUE_MAILER_TEMPLATES_RECOVERY` | `string` | optional | `SiteURL`, `Email`, `ConfirmationURL` |
| `GOTRUE_MAILER_TEMPLATES_MAGIC_LINK` | `string` | optional | `SiteURL`, `Email`, `ConfirmationURL` |
| `GOTRUE_MAILER_TEMPLATES_EMAIL_CHANGE` | `string` | optional | `SiteURL`, `Email`, `NewEmail`, `ConfirmationURL` |
| `GOTRUE_MAILER_TEMPLATES_REAUTHENTICATION` | `string` | optional | `Token` |
| `GOTRUE_MAILER_TEMPLATES_PASSWORD_CHANGED_NOTIFICATION` | `string` | optional | `Email` |
| `GOTRUE_MAILER_TEMPLATES_EMAIL_CHANGED_NOTIFICATION` | `string` | optional | `Email`, `OldEmail` |
| `GOTRUE_MAILER_TEMPLATES_PHONE_CHANGED_NOTIFICATION` | `string` | optional | `Email`, `Phone`, `OldPhone` |
| `GOTRUE_MAILER_TEMPLATES_IDENTITY_LINKED_NOTIFICATION` | `string` | optional | `Email`, `Provider` |
| `GOTRUE_MAILER_TEMPLATES_IDENTITY_UNLINKED_NOTIFICATION` | `string` | optional | `Email`, `Provider` |
| `GOTRUE_MAILER_TEMPLATES_MFA_FACTOR_ENROLLED_NOTIFICATION` | `string` | optional | `Email`, `FactorType` |
| `GOTRUE_MAILER_TEMPLATES_MFA_FACTOR_UNENROLLED_NOTIFICATION` | `string` | optional | `Email`, `FactorType` |

### Notifications

Account-change notification emails are off by default. Enable the ones you want.

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_MAILER_NOTIFICATIONS_PASSWORD_CHANGED_ENABLED` | `bool` | `false` | Whether to send a notification email when a user's password changes. |
| `GOTRUE_MAILER_NOTIFICATIONS_EMAIL_CHANGED_ENABLED` | `bool` | `false` | Whether to send a notification email when a user's email changes. |
| `GOTRUE_MAILER_NOTIFICATIONS_PHONE_CHANGED_ENABLED` | `bool` | `false` | Whether to send a notification email when a user's phone number changes. |
| `GOTRUE_MAILER_NOTIFICATIONS_IDENTITY_LINKED_ENABLED` | `bool` | `false` | Whether to send a notification email when a sign-in method is linked to a user's account. |
| `GOTRUE_MAILER_NOTIFICATIONS_IDENTITY_UNLINKED_ENABLED` | `bool` | `false` | Whether to send a notification email when a sign-in method is removed from a user's account. |
| `GOTRUE_MAILER_NOTIFICATIONS_MFA_FACTOR_ENROLLED_ENABLED` | `bool` | `false` | Whether to send a notification email when a new verification method is added to a user's account. |
| `GOTRUE_MAILER_NOTIFICATIONS_MFA_FACTOR_UNENROLLED_ENABLED` | `bool` | `false` | Whether to send a notification email when a verification method is removed from a user's account. |

### Default template content

Used when the corresponding `GOTRUE_MAILER_TEMPLATES_*` variable is unset.

`GOTRUE_MAILER_TEMPLATES_INVITE`

```html
<h2>You've been invited</h2>

<p>You've been invited to create an account. Follow the link below to accept.</p>
<p><a href="{{ .ConfirmationURL }}">Accept invitation</a></p>
```

`GOTRUE_MAILER_TEMPLATES_CONFIRMATION`

```html
<h2>Confirm your email address</h2>

<p>Follow the link below to confirm this email address and finish signing up.</p>
<p><a href="{{ .ConfirmationURL }}">Confirm email address</a></p>
```

`GOTRUE_MAILER_TEMPLATES_RECOVERY`

```html
<h2>Reset your password</h2>

<p>We received a request to reset your password. Follow the link below to choose a new one.</p>
<p><a href="{{ .ConfirmationURL }}">Reset password</a></p>
<p>If you didn't request this, you can safely ignore this email.</p>
```

`GOTRUE_MAILER_TEMPLATES_MAGIC_LINK`

```html
<h2>Your sign-in link</h2>

<p>Follow the link below to sign in. This link expires shortly and can only be used once.</p>
<p><a href="{{ .ConfirmationURL }}">Sign in</a></p>
```

`GOTRUE_MAILER_TEMPLATES_EMAIL_CHANGE`

```html
<h2>Confirm your new email address</h2>

<p>Follow the link below to confirm {{ .NewEmail }} as your new email address.</p>
<p><a href="{{ .ConfirmationURL }}">Confirm new email address</a></p>
<p>If you didn't request this change, you can safely ignore this email.</p>
```

`GOTRUE_MAILER_TEMPLATES_REAUTHENTICATION`

```html
<h2>Your verification code</h2>

<p>Use the code below to verify your identity. It expires shortly.</p>
<p>{{ .Token }}</p>
```

`GOTRUE_MAILER_TEMPLATES_PASSWORD_CHANGED_NOTIFICATION`

```html
<h2>Your password was changed</h2>

<p>The password for your account was recently changed.</p>
<p>If you didn't make this change, reset your password and contact support immediately.</p>
```

`GOTRUE_MAILER_TEMPLATES_EMAIL_CHANGED_NOTIFICATION`

```html
<h2>Your email address was changed</h2>

<p>The email address for your account was changed from {{ .OldEmail }} to {{ .Email }}.</p>
<p>If you didn't make this change, contact support immediately.</p>
```

`GOTRUE_MAILER_TEMPLATES_PHONE_CHANGED_NOTIFICATION`

```html
<h2>Your phone number was changed</h2>

<p>The phone number for your account was changed from {{ .OldPhone }} to {{ .Phone }}.</p>
<p>If you didn't make this change, contact support immediately.</p>
```

`GOTRUE_MAILER_TEMPLATES_IDENTITY_LINKED_NOTIFICATION`

```html
<h2>A new sign-in method was linked</h2>

<p>Your {{ .Provider }} account was linked as a new sign-in method for {{ .Email }}.</p>
<p>If you didn't make this change, contact support immediately.</p>
```

`GOTRUE_MAILER_TEMPLATES_IDENTITY_UNLINKED_NOTIFICATION`

```html
<h2>A sign-in method was removed</h2>

<p>Your {{ .Provider }} account was removed as a sign-in method for {{ .Email }}.</p>
<p>If you didn't make this change, contact support immediately.</p>
```

`GOTRUE_MAILER_TEMPLATES_MFA_FACTOR_ENROLLED_NOTIFICATION`

```html
<h2>A new verification method was added</h2>

<p>Sign-in verification method {{ .FactorType }} was added to your account.</p>
<p>If you didn't make this change, contact support immediately.</p>
```

`GOTRUE_MAILER_TEMPLATES_MFA_FACTOR_UNENROLLED_NOTIFICATION`

```html
<h2>A verification method was removed</h2>

<p>Sign-in verification method {{ .FactorType }} was removed from your account.</p>
<p>If you didn't make this change, contact support immediately.</p>
```

## Security

### Passwords

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_PASSWORD_MIN_LENGTH` | `int` | `6` | Minimum password length. Values below `6` are raised to `6`. |
| `GOTRUE_PASSWORD_REQUIRED_CHARACTERS` | `string` | optional | A string of character sets separated by `:`. A password must contain at least one character of each set to be accepted. To use the `:` character, escape it with `\`. |
| `GOTRUE_PASSWORD_HIBP_ENABLED` | `bool` | optional | Whether passwords are checked against the Have I Been Pwned database. |
| `GOTRUE_PASSWORD_HIBP_FAIL_CLOSED` | `bool` | optional | When `true`, Auth rejects the password if the HIBP check cannot complete. |
| `GOTRUE_PASSWORD_HIBP_USER_AGENT` | `string` | `https://github.com/supabase/gotrue` | The `User-Agent` sent to the HIBP API. |
| `GOTRUE_PASSWORD_HIBP_BLOOM_ENABLED` | `bool` | optional | Whether a local bloom filter caches pwned passwords. |
| `GOTRUE_PASSWORD_HIBP_BLOOM_ITEMS` | `uint` | `100000` | The expected number of items in the bloom filter. |
| `GOTRUE_PASSWORD_HIBP_BLOOM_FALSE_POSITIVES` | `float` | `0.0000099` | The target false-positive rate for the bloom filter. |

### Rate limiting

Rate limits are applied per client IP.

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_RATE_LIMIT_HEADER` | `string` | optional | Header on which to rate limit the `/token` endpoint. A trusted upstream proxy, such as Kong or Envoy, must set this header. Headers such as `x-forwarded-for` are spoofable. Do not trust them for rate limiting when a client supplies them directly. |
| `GOTRUE_RATE_LIMIT_EMAIL_SENT` | `Rate` | `30` (per hour) | Emails sent per hour on `/signup`, `/invite`, `/magiclink`, `/recover`, `/otp`, and `/user`. Accepts a plain number of events per hour, or a burst syntax of `events/duration`, for example `30/1h`. |
| `GOTRUE_RATE_LIMIT_SMS_SENT` | `Rate` | `30` (per hour) | SMS messages sent per hour. Accepts the same syntax as `GOTRUE_RATE_LIMIT_EMAIL_SENT`. |
| `GOTRUE_RATE_LIMIT_OTP` | `float` | `30` | OTP-related requests per 5 minutes (`/signup`, `/magiclink`, `/recover`, `/otp`, `/user`, resend). |
| `GOTRUE_RATE_LIMIT_VERIFY` | `float` | `30` | Verify requests per 5 minutes. |
| `GOTRUE_RATE_LIMIT_TOKEN_REFRESH` | `float` | `150` | Token refresh requests per 5 minutes. |
| `GOTRUE_RATE_LIMIT_SSO` | `float` | `30` | SSO requests per 5 minutes. |
| `GOTRUE_RATE_LIMIT_ANONYMOUS_USERS` | `float` | `30` | Anonymous sign-ins per hour. |
| `GOTRUE_RATE_LIMIT_WEB3` | `float` | `30` | Web3 sign-ins per 5 minutes. |
| `GOTRUE_RATE_LIMIT_PASSKEY` | `float` | `30` | Passkey authentications per 5 minutes. |
| `GOTRUE_RATE_LIMIT_O_AUTH_DYNAMIC_CLIENT_REGISTER` | `float` | `10` | Dynamic OAuth client registrations per 5 minutes. |

### Refresh tokens

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_SECURITY_REFRESH_TOKEN_ROTATION_ENABLED` | `bool` | `true` | When enabled, Auth detects attempts to reuse a revoked refresh token. When it detects a reuse attempt, Auth revokes all tokens descended from the offending token. |
| `GOTRUE_SECURITY_REFRESH_TOKEN_REUSE_INTERVAL` | `int` | optional | The interval length in seconds. Applies only when `GOTRUE_SECURITY_REFRESH_TOKEN_ROTATION_ENABLED` is enabled.<br><br>The reuse interval for a refresh token allows exchanging the refresh token multiple times during the interval, to support concurrency or offline use. During the reuse interval, Auth does not treat reuse of a revoked token as a reuse attempt, and returns the child refresh token instead.<br><br>Auth allows reuse of only the previous revoked token. Using an older refresh token triggers reuse detection. |
| `GOTRUE_SECURITY_REFRESH_TOKEN_ALLOW_REUSE` | `bool` | optional | When `true`, Auth does not treat refresh token reuse as an attack. |
| `GOTRUE_SECURITY_REFRESH_TOKEN_ALGORITHM_VERSION` | `int` | optional | The refresh token algorithm version. Must be 0, 1, or 2. |
| `GOTRUE_SECURITY_REFRESH_TOKEN_UPGRADE_PERCENTAGE` | `int` | optional | The percentage (0-100) of tokens upgraded to the newer algorithm during a rollout. |

### CAPTCHA

If enabled, Auth checks the request body for the `captcha_token` field and makes a verification request to the CAPTCHA provider.

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_SECURITY_CAPTCHA_ENABLED` | `bool` | `false` | Whether the CAPTCHA middleware is enabled. |
| `GOTRUE_SECURITY_CAPTCHA_PROVIDER` | `string` | `hcaptcha` | Auth currently supports only `hcaptcha` and `turnstile`. |
| `GOTRUE_SECURITY_CAPTCHA_SECRET` | `string` | required if enabled | Retrieve this from your hCaptcha or Turnstile account. |
| `GOTRUE_SECURITY_CAPTCHA_TIMEOUT` | `duration` | `10s` | The HTTP client timeout for the CAPTCHA verification request. |

### Reauthentication

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_SECURITY_UPDATE_PASSWORD_REQUIRE_REAUTHENTICATION` | `bool` | optional | Enforce reauthentication on password update. |
| `GOTRUE_SECURITY_UPDATE_PASSWORD_REQUIRE_CURRENT_PASSWORD` | `bool` | optional | Require the current password when updating the password. |

### Account linking

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_SECURITY_MANUAL_LINKING_ENABLED` | `bool` | `false` | Whether the manual identity linking API is enabled. |

### Database encryption

Once `GOTRUE_SECURITY_DB_ENCRYPTION_ENCRYPT` is `true`, Auth encrypts certain columns with the provided key. Setting it back to `false` stops further encryption, but the key must remain in the decryption keys so existing data stays readable.

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_SECURITY_DB_ENCRYPTION_ENCRYPT` | `bool` | optional | Whether column encryption is enabled. |
| `GOTRUE_SECURITY_DB_ENCRYPTION_ENCRYPTION_KEY_ID` | `string` | required if encrypting | The ID of the active encryption key. |
| `GOTRUE_SECURITY_DB_ENCRYPTION_ENCRYPTION_KEY` | `string` | required if encrypting | The active 256-bit key, Base64 raw-URL encoded. |
| `GOTRUE_SECURITY_DB_ENCRYPTION_DECRYPTION_KEYS` | `string` | required if encrypting | A comma-separated list of `key_id:key` pairs used to decrypt existing data. Must contain the active key. |

### IP address forwarding

| Variable | Type | Default/Required | Description |
| --- | --- | --- | --- |
| `GOTRUE_SECURITY_SB_FORWARDED_FOR_ENABLED` | `bool` | `false` | Enable IP address forwarding using the `Sb-Forwarded-For` HTTP request header. When enabled, Auth parses the first value of this header as an IP address and uses it for IP address tracking and rate limiting.<br><br>Before enabling this feature, make sure only trustworthy clients or proxies can set this header. |

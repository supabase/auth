# Auth: authentication and user management by Supabase

[![Coverage Status](https://coveralls.io/repos/github/supabase/auth/badge.svg?branch=master)](https://coveralls.io/github/supabase/auth?branch=master)

Auth is a user management and authentication server written in Go that powers [Supabase](https://supabase.com)'s features such as:

- Issuing JWTs
- Row Level Security with PostgREST
- User management
- Sign in with email, password, magic link, phone number
- Sign in with external providers (Google, Apple, Facebook, Discord, ...)

It was originally based on the [GoTrue codebase by Netlify](https://github.com/netlify/gotrue).
However, the two projects have since diverged significantly in features and capabilities.

To contribute to the project, see the [contributing guide](/CONTRIBUTING.md).

## Table of contents

- [Quick start](#quick-start)
- [Running in production](#running-in-production)
- [Configuration](#configuration)
- [API](#api)

## Quick start

To build, run, and test Auth locally, see [DEVELOPMENT.md](DEVELOPMENT.md).

## Running in production

Running an authentication server in production is hard. We recommend using [Supabase Auth](https://supabase.com/auth), which receives regular security updates.

Otherwise, set up a process to update promptly to the latest version.
Follow this repository, especially the [Releases](https://github.com/supabase/auth/releases) and [Security Advisories](https://github.com/supabase/auth/security/advisories) sections.

### Backward compatibility

Auth uses the [Semantic Versioning](https://semver.org) scheme. The following sections clarify its backward compatibility guarantees:

**Go API compatibility**

Auth is not meant for use as a Go library. Auth does not guarantee backward API compatibility for this use, regardless of which version number changes.

**Patch**

Changes to the patch version guarantee backward compatibility with:

- Database objects (tables, columns, indexes, functions).
- REST API
- JWT structure
- Configuration

Guaranteed examples:

- A column won't change its type.
- A table won't change its primary key.
- An index will not be removed.
- A uniqueness constraint will not be removed.
- A REST API will not be removed.
- Parameters to REST APIs will work equivalently as before. A bug fix might make them work better.
- Configuration will not change.

Not guaranteed examples:

- A table may add new columns.
- Columns in a table may be reordered.
- Non-unique constraints may be removed. Examples include database-level checks, null constraints, and default values.
- JWT may add new properties.

**Minor**

Changes to the minor version guarantee backward compatibility with:

- REST API
- JWT structure
- Configuration

We make exceptions to these guarantees only for serious security issues that have no other remedy.

Guaranteed examples:

- Existing APIs may be deprecated but continue working for the next few minor version releases.
- Configuration changes may become deprecated but continue working for the next few minor version releases.
- Already issued JWTs remain accepted. New JWTs may have a different structure, though usually similar to the old one.

Not guaranteed examples:

- Removal of JWT fields after a deprecation notice.
- Removal of certain APIs after a deprecation notice.
- Removal of sign-in with external providers after a deprecation notice.
- Deletion, truncation, significant schema changes to tables, indexes, views, functions.

We aim to provide a deprecation notice in execution logs for at least two major version releases or two weeks if multiple releases go out. We guarantee compatibility while the notice is live.

**Major**

Changes to the major version do not guarantee any backward compatibility with previous versions.

### Inherited features

Supabase does not support certain features inherited from the Netlify codebase and may remove them without prior notice. The following is a comprehensive list of those features:

1. Multi-tenancy via the `instances` table, that is the `GOTRUE_MULTI_INSTANCE_MODE` configuration parameter.
2. System user, identified by an all-zero UUID.
3. Super admin via the `is_super_admin` column.
4. Group information in JWTs via `GOTRUE_JWT_ADMIN_GROUP_NAME` and other configuration fields.
5. JWT signing. Supabase Auth supports asymmetric keys and uses RS256 by default. It also supports ECC and Ed25519 as optional algorithms. Auth still supports HS256 for compatibility, but migrating to asymmetric keys is recommended for easier validation and rotation. We announce future deprecations in the changelog. See the [JWT Signing Keys](https://supabase.com/docs/guides/auth/signing-keys) and [JWTs guide](https://supabase.com/docs/guides/auth/jwts) for details.

This list is not exhaustive and may change.

### Best practices when self-hosting

Follow these best practices when self-hosting Auth to preserve backward compatibility:

1. Do not modify the schema managed by Auth. See all migrations in the `migrations` directory.
2. Do not rely on the schema and the structure of data in the database. Always use Auth APIs and JWTs to infer information about users.
3. Always run Auth behind a TLS-capable proxy such as a load balancer, CDN, nginx, or similar software.

## Configuration

Configure Auth using a configuration file, environment variables, or a combination of both. See [configuration.md](docs/configuration.md) for the full list of settings, organized by area: top-level, API, database, logging, observability, JWT, external authentication providers, SAML single sign-on, email, phone auth, CAPTCHA, reauthentication, anonymous sign-ins, and IP address forwarding.

## API

Auth exposes a REST API. See [openapi.yaml](openapi.yaml) for the full, codegen-verified reference of every endpoint, and [docs/api.md](docs/api.md) for behavior notes that the spec alone doesn't cover, such as session delivery and token lifetime.

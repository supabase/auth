# CONTRIBUTING

We would love to have contributions from each and every one of you in the community be it big or small and you are the ones who motivate us to do better than what we do today

## Code Of Conduct

Please help us keep all our projects open and inclusive. Kindly follow our [Code of Conduct](<(CODE_OF_CONDUCT.md)>) to keep the ecosystem healthy and friendly for all.

## Setup and Tooling

GoTrue -- as the name implies -- is a user registration and authentication API developed in [Go](https://go.dev).

It connects to a [PostgreSQL](https://www.postgresql.org) database in ordder to store authentication data, [Soda CLI](https://gobuffalo.io/en/docs/db/toolbox) to manage database schema and migrations,
and runs inside a [Docker](https://www.docker.com/get-started) container.

Therefore, to contribute to GoTrue you will need to install those tools.

### Install Tools

- Install [Go](https://go.dev) 1.16

```terminal
# Via Homebrew on OSX
brew install go@1.16
```

- Install [Docker](https://www.docker.com/get-started)

```terminal
# Via Homebrew on OSX
brew install docker
```

Or, if you prefer, download [Docker Desktop](https://www.docker.com/get-started).

- Install [Soda CLI](https://gobuffalo.io/en/docs/db/toolbox)

```
go install github.com/gobuffalo/pop/soda@latest
```

- Clone the GoTrue repository

```
git clone https://github.com/supabase/gotrue
```

### Install GoTrue

- `cd gotrue`

To run the GoTrue PostgreSQL container locally, you'll need to:

- Install the PostgreSQL Docker image
- Create the DB Schema and Migrations
- Setup a local `.env` for environment variables
- Compile GoTrue
- Run the GoTrue binary executable

#### Installation Steps

- Make sure you are in the `gotrue`
- Start Docker
- To install the PostgreSQL Docker image, run:

```
./hack/postgresd.sh
```

You may see a message like:

> Unable to find image 'postgres:13' locally

And then

> Pulling from library/postgres

as Docker installs the image:

```
Unable to find image 'postgres:13' locally
13: Pulling from library/postgres
968621624b32: Pull complete
9ef9c0761899: Pull complete
effb6e89256d: Pull complete
e19a7fe239e0: Pull complete
7f97626b93ac: Pull complete
ecc35a9a2c7c: Pull complete
b749e660435b: Pull complete
457ea4f6253a: Pull complete
722af21d2ec3: Pull complete
899eee526623: Pull complete
746f304547aa: Pull complete
2d4dfc6819e6: Pull complete
c99864ddd548: Pull complete
Digest: sha256:3c6d1cef78fe0c84a79c76f0907aed29895dff661fecd45103f7afe2a055078e
Status: Downloaded newer image for postgres:13
f709b97d83fddc3b099e4f2ddc4cb2fbf68052e7a8093332bec57672f38cfa36
```

You should then see in Docker that `gotrue_postgresql` is running on `port: 5432`.

- Next compile the GoTrue binary:

```
make build
```

- Run `make migrate_test` to setup the database schema.

> Note: This uses Soda to create the database an run the migration scripts

You should see log messages that indicate that the GoTrue migrations were applied successfully:

```terminal
INFO[0000] GoTrue migrations applied successfully
DEBU[0000] after status
[POP] 2021/12/15 10:44:36 sql - SELECT EXISTS (SELECT schema_migrations.* FROM schema_migrations AS schema_migrations WHERE version = $1) | ["20210710035447"]
[POP] 2021/12/15 10:44:36 sql - SELECT EXISTS (SELECT schema_migrations.* FROM schema_migrations AS schema_migrations WHERE version = $1) | ["20210722035447"]
[POP] 2021/12/15 10:44:36 sql - SELECT EXISTS (SELECT schema_migrations.* FROM schema_migrations AS schema_migrations WHERE version = $1) | ["20210730183235"]
[POP] 2021/12/15 10:44:36 sql - SELECT EXISTS (SELECT schema_migrations.* FROM schema_migrations AS schema_migrations WHERE version = $1) | ["20210909172000"]
[POP] 2021/12/15 10:44:36 sql - SELECT EXISTS (SELECT schema_migrations.* FROM schema_migrations AS schema_migrations WHERE version = $1) | ["20211122151130"]
Version          Name                         Status
20210710035447   alter_users                  Applied
20210722035447   adds_confirmed_at            Applied
20210730183235   add_email_change_confirmed   Applied
20210909172000   create_identities_table      Applied
20211122151130   create_user_id_idx           Applied
```

That lists each migration that was applied. Note: there may be more migrations than those listed.

- Create a `.env` file in the root of the project and copy the following config in [example.env](example.env)
- In order to have GoTrue connect to your PostgreSQL database running in Docket, it is important to set a connection string like:

```
DATABASE_URL="postgres://supabase_auth_admin:root@localhost:5432/postgres"
```

> Important: GoTrue requires a set of SMTP credentials to run, you can generate your own SMTP credentials via an SMTP provider such as AWS SES, SendGrid, MailChimp, SendInBlue or any other SMTP providers.

### Starting GoTrue

Start GoTrue by running the executable:

```
./gotrue
```

This command will re-run migrations and then indicate that GoTrue has started:

```
INFO[0000] GoTrue API started on: localhost:9999
```

### How To Verify that GoTrue is Available

To test that your GoTrue is up and available, you can query the `health` endpoint at `http://localhost:9999/health`. You should see a response similar to:

```json
{
  "description": "GoTrue is a user registration and authentication API",
  "name": "GoTrue",
  "version": ""
}
```

To see the current settings, make a request to `http://localhost:9999/settings` and you should see a response similar to:

```json
{
  "external": {
    "apple": false,
    "azure": false,
    "bitbucket": false,
    "discord": false,
    "github": false,
    "gitlab": false,
    "google": false,
    "facebook": false,
    "spotify": false,
    "slack": false,
    "twitch": true,
    "twitter": false,
    "email": true,
    "phone": false,
    "saml": false
  },
  "external_labels": {
    "saml": "auth0"
  },
  "disable_signup": false,
  "mailer_autoconfirm": false,
  "phone_autoconfirm": false,
  "sms_provider": "twilio"
}
```

### Running Database Migrations

If you need to run new migrations:`

```
make migrate_test
```

## Testing

Currently, we don't use a separate test database, so the same database created when installing GoTrue to run locally is used.

The following commands should help in setting up a database and running the tests:

```sh
# Runs the database in a docker container
$ ./hack/postgresd.sh

# Applies the migrations to the database (requires soda cli)
$ make migrate_test

# Executes the tests
$ make testß
```

## Updating Package Dependencies

- `make deps`
- `go mod tidy` if necessary

## Submitting Pull Requests

We actively welcome your pull requests.

- Fork the repo and create your branch from `master`.
- If you've added code that should be tested, add tests.
- If you've changed APIs, update the documentation.
- Ensure the test suite passes.
- Make sure your code lints.

### Checklist for Submitting Pull Requests

- Is there a corresponding issue created for it? If so, please include it in the PR description so we can track / refer to it.
- Does your PR follow the [semantic-release commit guidelines](https://github.com/angular/angular.js/blob/master/DEVELOPERS.md#-git-commit-guidelines)?
- If the PR is a `feat`, an [RFC](https://github.com/supabase/rfcs) or a detailed description of the design implementation is required. The former (RFC) is prefered before starting on the PR.
- Are the existing tests passing?
- Have you written some tests for your PR?

## Guidelines for Implementing Additional oAuth Providers

Please ensure that an end-to-end test is done for the oAuth provider implemented.

An end-to-end test includes:

- Creating an application on the oauth provider site
- Generating your own client_id and secret
- Testing that `http://localhost:9999/authorize?provider=MY_COOL_NEW_PROVIDER` redirects you to the provider sign-in page
- The callback is handled properly
- Gotrue redirects to the `SITE_URL` or one of the URI's specified in the `URI_ALLOW_LIST` with the access_token, provider_token, expiry and refresh_token as query fragments

### Writing tests for the new oAuth provider implemented

Since implementing an additional oauth provider consists of making api calls to an external api, we set up a mock server to attempt to mock the responses expected from the oauth provider.

## License

By contributing to Gotrue, you agree that your contributions will be licensed
under its [MIT license](LICENSE).

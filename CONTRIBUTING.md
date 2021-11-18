# CONTRIBUTING

Contributions are always welcome, no matter how large or small. Before contributing,
please read the [code of conduct](CODE_OF_CONDUCT.md).

## Setup

- Install Go 1.16
- Install [Soda CLI](https://gobuffalo.io/en/docs/db/toolbox)
- Install Docker to run tests

GoTrue uses the Go Modules support built into Go 1.11 to build. The easiest is to clone GoTrue in a directory outside of GOPATH, as in the following example:

```sh
$ git clone https://github.com/supabase/gotrue
$ cd gotrue
$ make deps
```

> Important. If you happen to already have a local running instance of Postgres running on the port `5432`, perhaps if you have installed via [homebrew on OSX](https://formulae.brew.sh/formula/postgresql) then be certain to stop the process using:
>
> - `brew services stop postgresql`
>
> If you need to run the test environment on another port, you will need to modify several configuration files to use the custom port. See below [Customize Test Environment Postgres Port](#Customize_Test_Environment_Postgres_Port])

## Building

```sh
$ make build
```

## Running database migrations for supabase

- Create a `.env` file to store the custom gotrue environment variables. You can refer to an example of the `.env` file [here](hack/test.env)
- Start PostgreSQL inside a docker container running `hack/postgresd.sh`
- In your Docker dashboard, you should see `gotrue_postgresql` running on port 5432
- Build the gotrue binary `make build`
- Execute the binary `./gotrue`
  - gotrue runs any database migrations from `/migrations` on start

## Testing

- Currently, we don't use a test db. You can just create a new postgres container, make sure docker is running and do:

```sh
$ ./hack/postgresd.sh
$ make migrate_test
$ make test
```

### Customize Test Environment Postgres Port

If you want to run your test environment Postgres on a port other than the standard 5432, you will need to update the following configuration and settings files:

```
///file: postgresd.sh
docker run --name gotrue_postgresql \
	-p 7432:5432 \ 👈 set the first value to your external facing port
```

The port you customize here can them be used in the subsequent configuration:

```
// file: database.yaml
test:
  dialect: "postgres"
  database: "postgres"
  host: {{ envOr "POSTGRES_HOST" "127.0.0.1"  }}
  port: {{ envOr "POSTGRES_PORT" "7432"  }} 👈 set to your port
```

```
// file: test.env
DATABASE_URL="postgres://supabase_auth_admin:root@localhost:7432/postgres" 👈 set to your port
```

```
//file: migrate.sh
export GOTRUE_DB_DATABASE_URL="postgres://supabase_auth_admin:root@localhost:5432/$DB_ENV"
```

## Pull Requests

We actively welcome your pull requests.

1. Fork the repo and create your branch from `master`.
2. If you've added code that should be tested, add tests.
3. If you've changed APIs, update the documentation.
4. Ensure the test suite passes.
5. Make sure your code lints.

## License

By contributing to Gotrue, you agree that your contributions will be licensed
under its [MIT license](LICENSE).

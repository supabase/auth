# CONTRIBUTING

Contributions are always welcome, no matter how large or small. Before contributing,
please read the [code of conduct](CODE_OF_CONDUCT.md).

## Setup
* Install Go 1.16
* Install Docker 
* Install [Soda CLI](https://gobuffalo.io/en/docs/db/toolbox)
  * `go install github.com/gobuffalo/pop/soda@latest`
* Clone this repo: `git clone https://github.com/supabase/gotrue`
* `cd gotrue`
* To start the gotrue postgresql container running locally: `./hack/postgresd.sh` 
* To compile the gotrue binary for execution: `make build` 
* Before executing the binary (`./gotrue`), create a `.env` file in the root of the project and copy the following config in [example.env](example.env)
* Gotrue requires a set of smtp credentials to run, you can generate your own smtp credentials via an smtp provider such as AWS SES, SendGrid, MailChimp, SendInBlue or any other smtp providers.

## Running database migrations for supabase
- Create a `.env` file to store the custom gotrue environment variables. You can refer to an example of the `.env` file [here](hack/test.env)
- Start PostgreSQL inside a docker container running `./hack/postgresd.sh`
- Run `make migrate_test`

## Testing
- Currently, we don't use a test db. The following commands should help in setting up a test database and running the tests:
```sh
# Runs the database in a docker container 
$ ./hack/postgresd.sh

# Applies the migrations to the database (requires soda cli)
$ make migrate_test

# Executes the tests
$ make test
```

## Updating package dependencies
1. `make deps`
2. `go mod tidy` if necessary

## Pull Requests

We actively welcome your pull requests.

1. Fork the repo and create your branch from `master`.
2. If you've added code that should be tested, add tests.
3. If you've changed APIs, update the documentation.
4. Ensure the test suite passes.
5. Make sure your code lints.

### Guidelines for submitting PRs
1. Is there a corresponding issue created for it? If so, please include it in the PR description so we can track / refer to it.
2. Does your PR follow the [semantic-release commit guidelines](https://github.com/angular/angular.js/blob/master/DEVELOPERS.md#-git-commit-guidelines)?
3. If the PR is a `feat`, an [RFC](https://github.com/supabase/rfcs) or a detailed description of the design implementation is required. The former (RFC) is prefered before starting on the PR.
4. Are the existing tests passing?
5. Have you written some tests for your PR?

### Guidelines for implementing additional oauth providers
1. Please ensure that an end-to-end test is done for the oauth provider implemented. An end-to-end test includes:
  * Creating an application on the oauth provider site
  * Generating your own client_id and secret
  * Testing that `http://localhost:9999/authorize?provider=MY_COOL_NEW_PROVIDER` redirects you to the provider sign-in page
  * The callback is handled properly
  * Gotrue redirects to the `SITE_URL` or one of the URI's specified in the `URI_ALLOW_LIST` with the access_token, provider_token, expiry and refresh_token as query fragments

2. [Writing tests for the new oauth provider implemented] Since implementing an additional oauth provider consists of making api calls to an external api, we set up a mock server to attempt to mock the responses expected from the oauth provider. 

## License

By contributing to Gotrue, you agree that your contributions will be licensed
under its [MIT license](LICENSE).

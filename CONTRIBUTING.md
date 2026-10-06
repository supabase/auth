# CONTRIBUTING

We would love to have contributions from each and every one of you in the community be it big or small and you are the ones who motivate us to do better than what we do today.

## Code Of Conduct

Please help us keep all our projects open and inclusive. Kindly follow our [Code of Conduct](CODE_OF_CONDUCT.md) to keep the ecosystem healthy and friendly for all.

## Development

To build, run, and test Auth locally, see [DEVELOPMENT.md](DEVELOPMENT.md).

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
- If the PR is a `feat`, an [RFC](https://github.com/supabase/rfcs) or a detailed description of the design implementation is required. The former (RFC) is preferred before starting on the PR.
- Are the existing tests passing?
- Have you written some tests for your PR?

## Guidelines for Implementing Additional OAuth Providers

> ⚠️ We won't be accepting any additional oauth / sms provider contributions for now because we intend to support these through webhooks or a generic provider in the future.

Please ensure that an end-to-end test is done for the OAuth provider implemented.

An end-to-end test includes:

- Creating an application on the oauth provider site
- Generating your own client_id and secret
- Testing that `http://localhost:9999/authorize?provider=MY_COOL_NEW_PROVIDER` redirects you to the provider sign-in page
- The callback is handled properly
- Gotrue redirects to the `SITE_URL` or one of the URI's specified in the `URI_ALLOW_LIST` with the access_token, provider_token, expiry and refresh_token as query fragments

### Writing tests for the new OAuth provider implemented

Since implementing an additional OAuth provider consists of making api calls to an external api, we set up a mock server to attempt to mock the responses expected from the OAuth provider.

## License

By contributing to Auth, you agree that your contributions will be licensed
under its [MIT license](LICENSE).

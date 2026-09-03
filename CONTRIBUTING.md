# Contributing to Auth

Thanks for your interest in improving Auth. Contributions of every size are welcome. Please follow our [Code of Conduct](https://github.com/supabase/.github/blob/main/CODE_OF_CONDUCT.md).

## Before you start

For anything beyond a trivial fix, open a [Discussion](https://github.com/supabase/supabase/discussions) before you start writing code.
Auth sits at the center of Supabase, and coordinating up front lets the team weigh in on the approach and line the work up with the rest of the project before effort is spent.

Meaningful pull requests opened without a prior, agreed upon Discussion may be closed or left stale until the work has been coordinated. This is not about turning contributors away, it is about making sure your time is well spent.

You should understand your own changes and be able to explain what they do and how they interact with the rest of the system.

## Pull requests

- Fork the repo and create your branch from `master`.
- Keep it small: one logical change per pull request.
- Add tests with your change. CI must be green.
- Reference the accepted Discussion or issue in the pull request description.

### Commit messages

Pull request titles and commits must follow [Conventional Commits](https://www.conventionalcommits.org). For example:

* `feat: add support for OIDC sign-in`
* `fix: resolve race condition in token refresh`
* `docs: update OAuth configuration guide`
* `chore: upgrade dependencies`

## Review

The Auth team (`@supabase/auth`) reviews and merges pull requests. We aim to respond promptly, but there is no guaranteed response time for community contributions. Please address blocking review feedback before a change can be merged.

## Development

See [DEVELOPMENT.md](DEVELOPMENT.md) to build, run, and test Auth locally.

## License

By contributing to Auth, you agree that your contributions will be licensed under its [MIT license](LICENSE).

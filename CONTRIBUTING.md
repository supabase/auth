# Contributing to Auth

We would love to have contributions from each and every one of you in the community be it big or small and you are the ones who motivate us to do better than what we do today. Follow the [Supabase Code of Conduct](https://github.com/supabase/.github/blob/main/CODE_OF_CONDUCT.md).

Read this guide before you write code. It tells you which changes we accept, how to propose a change, and what a pull request must contain.

## Why we require a discussion first

Auth runs in many different places. A change that is safe for a small project can be a risk for a large one.

Some changes need work outside this repository. A new setting needs dashboard, configuration, and documentation changes before a customer can use it. A bug fix is much easier for us to accept. A product decision is not. This includes changes that require API changes and schema migrations.

For these reasons, we ask you to discuss and agree on the change with the team before you write code. It makes sure that everyone's time goes to changes that we can merge.

## Before you open a pull request

Start a [Discussion](https://github.com/supabase/auth/discussions). Wait for the team to agree on the approach. A maintainer then opens an issue with the `open-for-contribution` label. Then a pull request can be opened with a link to the issue.

Search open issues, discussions, and pull requests first. Many fixes already have a pull request. Add to that work instead of opening a duplicate.

We will close pull requests that skip these steps.

## Pull requests

- Fork the repository and create your branch from `master`.
- If you've added code that should be tested, add tests.
- If you've changed APIs, update the documentation.
- Link the issue with a closing keyword, for example `Closes #123`.
- Write the description yourself. Explain why, not just what, and what was tested.
- Tell us how you tested the change and how a reviewer can confirm it.
- If you used AI tools, follow the [AI policy](AI_POLICY.md).
- CI must pass.

### Commit messages

Pull request titles and commits must follow [Conventional Commits](https://www.conventionalcommits.org). CI checks the title. Examples:

- `feat: add support for OIDC sign-in`
- `fix: resolve race condition in token refresh`
- `docs: update OAuth configuration guide`
- `chore: upgrade dependencies`

Add `!` after the type for a breaking change, for example `feat!: change the token format`.

## Review

The Auth team reviews and merges pull requests. We try to respond quickly, but we do not guarantee a response time for community contributions. Address blocking review feedback before we can merge the change. We may close a pull request that has no activity for 60 days. You can reopen it when you are ready to continue.

## Security issues

Do not open a public issue or pull request for a security vulnerability. Report it through [GitHub Security Advisories](https://github.com/supabase/auth/security/advisories/new).

## Development

To build, run, and test Auth locally, see [DEVELOPMENT.md](DEVELOPMENT.md).

## License

By contributing to Auth, you agree that your contributions will be licensed under its [MIT license](LICENSE).

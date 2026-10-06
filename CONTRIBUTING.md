# Contributing to Auth

Thank you for your interest in Auth. We welcome contributions of every size. Follow the [Supabase Code of Conduct](https://github.com/supabase/.github/blob/main/CODE_OF_CONDUCT.md).

Read this guide before you write code. It tells you which changes we accept, how to propose a change, and what a pull request must contain.

## Why we ask you to talk to us first

Auth runs on every Supabase project and on many self-hosted installations. We cannot predict how a given database is configured or what a project has customized. A change that is safe for a small project can be a risk for a large one. For example, a query that filters users by email needs an index that a large table may not have.

Some changes also need work outside this repository. A new setting needs dashboard, configuration, and documentation changes before a customer can use it. A bug fix is easy to accept. A product decision is not.

For these reasons, we ask you to agree on the change with the team before you write code.

## Before you open a pull request

Find the row that matches your change.

| Change | What to do first |
| --- | --- |
| Typo, documentation, test-only change, or dependency update | Open the pull request. |
| Bug fix | Open an issue, or find the existing one. Wait for a maintainer to add the `open-for-contribution` label. Then open the pull request and link the issue. |
| New feature, behavior change, new setting, schema change, or new provider | Start a [Discussion](https://github.com/supabase/auth/discussions). Wait for the team to agree on the approach. A maintainer then opens an issue with the `open-for-contribution` label. Then open the pull request and link the issue. |

Search open issues, discussions, and pull requests first. Many fixes already have a pull request. Add to that work instead of opening a duplicate.

We can close pull requests that skip these steps. This is not a judgement on your work. It makes sure that your time and our review time go to changes that we can merge.

### Changes we do not accept

- New OAuth or SMS providers. We plan to support these through a generic provider and hooks instead.
- Changes that break [backward compatibility](README.md#backward-compatibility).

## Pull requests

- Fork the repository and create your branch from `master`.
- Keep the pull request small. Make one logical change per pull request.
- Add tests. CI must pass.
- Link the issue with a closing keyword, for example `Closes #123`.
- Write the description yourself. Explain why, not what. The diff shows what changed. Tell us the motivation, the impact, and the alternatives you considered.
- Tell us how you tested the change and how a reviewer can confirm it.
- If you used AI tools, follow the [AI policy](AI_POLICY.md).

### Schema changes and other risky changes

Schema changes and other risky changes get extra scrutiny.

- Prefer additive, backward compatible changes. A migration must run safely against an existing production database, not only against a fresh one.
- Do not assume the data shape, the data size, or the installed extensions. Avoid operations that take long locks or rewrite large tables.
- Include the `EXPLAIN` or `EXPLAIN ANALYZE` output for the affected queries so that reviewers can see the query plan.

### Commit messages

Pull request titles and commits must follow [Conventional Commits](https://www.conventionalcommits.org). CI checks the title. Examples:

- `feat: add support for OIDC sign-in`
- `fix: resolve race condition in token refresh`
- `docs: update OAuth configuration guide`
- `chore: upgrade dependencies`

Add `!` after the type for a breaking change, for example `feat!: change the token format`.

## Review

The Auth team reviews and merges pull requests. We try to respond quickly, but we do not guarantee a response time for community contributions. Address blocking review feedback before we can merge the change. We can close a pull request that has no activity for 60 days. You can reopen it when you are ready to continue.

## Security issues

Do not open a public issue or pull request for a security vulnerability. Report it through [GitHub Security Advisories](https://github.com/supabase/auth/security/advisories/new).

## Development

To build, run, and test Auth locally, see [DEVELOPMENT.md](DEVELOPMENT.md).

## License

By contributing to Auth, you agree that your contributions will be licensed under its [MIT license](LICENSE).

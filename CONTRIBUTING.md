# Contributing to Auth

Thanks for your interest in improving Auth. Contributions of every size are welcome. Follow our [Code of Conduct](https://github.com/supabase/.github/blob/main/CODE_OF_CONDUCT.md).

## Before you start

For anything beyond a trivial fix, open a [Discussion](https://github.com/supabase/supabase/discussions) before you start writing code.
Auth sits at the center of Supabase, and coordinating up front lets the team weigh in on the approach and line the work up with the rest of the project before effort is spent.

Auth ships to a large and growing number of self-hosted and managed deployments. You cannot predict how any given project's database is configured or what has been customized, so schema changes and other risky changes carry outsized impact. Coordinate them early.

Meaningful pull requests opened without a prior, agreed-upon Discussion may be closed or left stale until the work has been coordinated. This is not about turning contributors away, it is about making sure your time is well spent.

You should understand your own changes and be able to explain what they do and how they interact with the rest of the system.

## Pull requests

Follow these conventions when you open a pull request:

- Fork the repo and create your branch from `master`.
- Keep it small: one logical change per pull request.
- Add tests with your change. CI must be green.
- Reference the accepted Discussion or issue in the pull request description.

### Writing a good pull request

A clear description speeds up review:

- Explain why, not what. The diff shows what changed, the description should cover the motivation, the impact, and any tradeoffs or alternatives you weighed.
- Include verification steps: how you tested the change and how a reviewer can confirm it works.

### Schema and risky changes

For the reasons above, schema changes and other risky changes get extra scrutiny. See also the [backward compatibility](README.md#backward-compatibility) guarantees.

- Prefer backward compatible, additive changes. A migration must run safely against an existing production database, and not just a fresh one.
- Do not assume data shape, size, or installed extensions. Avoid operations that take long locks or rewrite large tables.
- Include the `EXPLAIN` (or `EXPLAIN ANALYZE`) output for the affected queries so reviewers can see the query plan.

### Commit messages

Pull request titles and commits must follow [Conventional Commits](https://www.conventionalcommits.org). For example:

- `feat: add support for OIDC sign-in`
- `fix: resolve race condition in token refresh`
- `docs: update OAuth configuration guide`
- `chore: upgrade dependencies`

## Review

The Auth team (`@supabase/auth`) reviews and merges pull requests. We aim to respond promptly, but there is no guaranteed response time for community contributions. Address blocking review feedback before a change can be merged.

## Development

See [DEVELOPMENT.md](DEVELOPMENT.md) to build, run, and test Auth locally.

## License

By contributing to Auth, you agree that your contributions will be licensed under its [MIT license](LICENSE).

# Development

How to build, run, and test Auth locally.

## Prerequisites

- [Go](https://go.dev) 1.27
- [Docker](https://www.docker.com/get-started)

## Quick start

Run Postgres in a container and Auth on your host. This matches CI, which pins Go 1.27 in `go.mod`.

```bash
# Create your local env file
cp example.env .env

# Start Postgres in the background
docker compose -f docker-compose-dev.yml up -d postgres

# Run Auth (applies migrations on startup)
go run .
```

Verify Auth is up:

```bash
curl http://localhost:9999/health
```

## Going further

Once Auth is running, these commands cover the rest of the workflow:

- `make help` lists every available command; see the `Makefile` for details.
- `example.env` holds the full set of environment variables.
- Postgres must be running to run the tests: `go test ./...`. Scope with `-run`, for example `go test ./internal/api/... -run SCIM`.

Optionally, install the git hooks so `gofmt` and the linters run before each commit. This requires [lefthook](https://github.com/evilmartians/lefthook):

```bash
brew install lefthook
make hooks
```

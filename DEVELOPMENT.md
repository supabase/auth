# Development

How to build, run, and test Auth locally.

## Prerequisites

- [Go](https://go.dev) 1.27
- [Docker](https://www.docker.com/get-started)

## Quick start

Run Postgres in a container and Auth on your host. This matches CI and needs Go 1.27 (from `go.mod`).

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

- `make help` lists every available command; see the `Makefile` for details.
- `example.env` holds the full set of environment variables.
- Run the tests with `go test ./...` (Postgres must be running). Scope with `-run`, e.g. `go test ./internal/api/... -run SCIM`.

Optionally, install the git hooks so `gofmt` and the linters run before each commit:

```bash
make hooks
```

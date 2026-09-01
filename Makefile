.PHONY: all build build-strip deps release release-test check-go-version
.PHONY: db-create db-migrate db-reset db-schema-dump format lint test
.PHONY: generate check-oapi-codegen dev down docker-test docker-build docker-clean hooks clean

ifdef RELEASE_VERSION
	VERSION=v$(RELEASE_VERSION)
else
	VERSION=$(shell git describe --tags)
endif

ifneq ($(shell docker compose version 2>/dev/null),)
	DOCKER_COMPOSE = docker compose
else
	DOCKER_COMPOSE = docker-compose
endif

DEV_DOCKER_COMPOSE = docker-compose-dev.yml

BUILD_VERSION_PKG = github.com/supabase/auth/internal/utilities
BUILD_LD_FLAGS = -X $(BUILD_VERSION_PKG).Version=$(VERSION)
BUILD_CMD = go build \
	-o $(1) \
	-buildvcs=false \
	-ldflags "$(BUILD_LD_FLAGS)$(2)"

RELEASE_TARGETS = x86 arm64 darwin-arm64 amd64-strip arm64-strip
RELEASE_ARCHIVES = \
	auth-$(VERSION)-x86.tar.gz \
	auth-$(VERSION)-arm64.tar.gz \
	auth-$(VERSION)-darwin-arm64.tar.gz \
	auth-$(VERSION)-amd64.tar.xz \
	auth-$(VERSION)-arm64.tar.xz

# Database configuration. Override on the command line, e.g. `APP_ENV=test make db-create`.
APP_ENV ?= development
POSTGRES_HOST ?= localhost
POSTGRES_PORT ?= 5432
POSTGRES_USER ?= postgres
POSTGRES_PASSWORD ?= root

DB_USER ?= supabase_auth_admin
DB_PASSWORD ?= root
DEV_DB_NAME ?= postgres
TEST_DB_NAME ?= postgres_test

ifeq ($(APP_ENV),test)
DB_NAME := $(TEST_DB_NAME)
MIGRATE_ENV_FILE := hack/test.env
else
DB_NAME := $(DEV_DB_NAME)
MIGRATE_ENV_FILE := hack/dev.env
endif

help: ## Show this help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {sub("\\\\n",sprintf("\n%22c"," "), $$2);printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

all: check-go-version lint test build ## Run the linters, tests, and build the binary.

build: auth auth-amd64 auth-arm64 auth-darwin-arm64 ## Build the binaries.

build-strip: auth-amd64-strip auth-arm64-strip ## Build a stripped binary, for which the version file needs to be rewritten.

auth: deps
	CGO_ENABLED=0 $(call BUILD_CMD,$(@),)

auth-x86: deps
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(call BUILD_CMD,$(@),)

auth-amd64: deps
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(call BUILD_CMD,$(@),)

auth-arm64: deps
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(call BUILD_CMD,$(@),)

auth-darwin-arm64: deps
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(call BUILD_CMD,$(@),)

auth-amd64-strip: deps
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(call BUILD_CMD,$(@), -s)

auth-arm64-strip: deps
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(call BUILD_CMD,$(@), -s)

deps: ## Install dependencies.
	@go mod download
	@go mod verify

release-test: lint test

release: $(RELEASE_ARCHIVES)

auth-$(VERSION)-%.tar.gz: \
		release-%/auth \
		release-%/gotrue | migrations
	tar -C $(<D) -czvf $(@) auth gotrue -C ../ migrations/

auth-$(VERSION)-amd64.tar.xz: \
		release-amd64-strip/auth \
		release-amd64-strip/gotrue | migrations
	tar -C $(<D) -cf - auth gotrue -C ../ migrations/ \
		| xz -T0 -9e -C crc64 > $(@)

auth-$(VERSION)-arm64.tar.xz: \
		release-arm64-strip/auth \
		release-arm64-strip/gotrue | migrations
	tar -C $(<D) -cf - auth gotrue -C ../ migrations/ \
		| xz -T0 -9e -C crc64 > $(@)

release-%/auth: auth-%
	mkdir -p $(@D)
	cp -a $(<) $(@)

release-%/gotrue: release-%/auth
	ln -sf $(<F) $(@)

check-go-version: ## Verify the pinned Go version matches across go.mod, Dockerfiles, and submodules.
	./hack/check-go-version.sh

db-create: ## Create the Postgres database (APP_ENV=test for the test database).
	@PGPASSWORD=$(POSTGRES_PASSWORD) psql -v ON_ERROR_STOP=1 -h $(POSTGRES_HOST) -p $(POSTGRES_PORT) -U $(POSTGRES_USER) -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname = '$(DB_NAME)'" | grep -qx 1 \
		|| PGPASSWORD=$(POSTGRES_PASSWORD) createdb -h $(POSTGRES_HOST) -p $(POSTGRES_PORT) -U $(POSTGRES_USER) $(DB_NAME)
	PGPASSWORD=$(POSTGRES_PASSWORD) psql -v ON_ERROR_STOP=1 -v dbname=$(DB_NAME) -h $(POSTGRES_HOST) -p $(POSTGRES_PORT) -U $(POSTGRES_USER) -d $(DB_NAME) -f hack/init_postgres.sql

db-migrate: ## Run new migrations (APP_ENV=test for the test database).
	go run . migrate -c $(MIGRATE_ENV_FILE)

db-reset: ## Drop, recreate, and migrate the database (APP_ENV=test for the test database).
	PGPASSWORD=$(POSTGRES_PASSWORD) psql -v ON_ERROR_STOP=1 -h $(POSTGRES_HOST) -p $(POSTGRES_PORT) -U $(POSTGRES_USER) -d postgres -c "DROP DATABASE IF EXISTS $(DB_NAME);"
	$(MAKE) db-create
	$(MAKE) db-migrate

db-schema-dump: ## Dump the development database schema to structure.sql.
	PGPASSWORD=$(DB_PASSWORD) pg_dump --schema-only --no-owner --no-privileges \
		-h $(POSTGRES_HOST) -p $(POSTGRES_PORT) -U $(DB_USER) -d $(DEV_DB_NAME) \
		-f structure.sql

format: ## Format the codebase.
	go run golang.org/x/tools/cmd/goimports@latest -w .
	go fmt ./...

lint: ## Run golangci-lint, govulncheck, and validate the OpenAPI spec.
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	golangci-lint run
	go run golang.org/x/vuln/cmd/govulncheck@latest ./... | go run ./hack/vulncheck-filter
	npx --yes @stoplight/spectral-cli@latest lint openapi.yaml --ruleset .spectral.yaml

test: ## Run the unit test suite with the race detector against the test database.
	# -p 1: packages share one test database, so they can't run concurrently.
	go test -race -p 1 ./...

generate: | check-oapi-codegen
	go generate ./...

check-oapi-codegen:
	@command -v oapi-codegen >/dev/null 2>&1 \
		|| go install github.com/deepmap/oapi-codegen/cmd/oapi-codegen@latest

dev: ## Run the development containers
	${DOCKER_COMPOSE} -f $(DEV_DOCKER_COMPOSE) up

down: ## Shutdown the development containers
	${DOCKER_COMPOSE} -f $(DEV_DOCKER_COMPOSE) down

docker-test: ## Run the tests using the development containers
	${DOCKER_COMPOSE} -f $(DEV_DOCKER_COMPOSE) up -d postgres
	${DOCKER_COMPOSE} -f $(DEV_DOCKER_COMPOSE) run auth sh -c "APP_ENV=test make db-create && APP_ENV=test make db-migrate && make test"
	${DOCKER_COMPOSE} -f $(DEV_DOCKER_COMPOSE) down -v

docker-build: ## Force a full rebuild of the development containers
	${DOCKER_COMPOSE} -f $(DEV_DOCKER_COMPOSE) build --no-cache
	${DOCKER_COMPOSE} -f $(DEV_DOCKER_COMPOSE) up -d postgres
	${DOCKER_COMPOSE} -f $(DEV_DOCKER_COMPOSE) run auth sh -c "make db-migrate"
	${DOCKER_COMPOSE} -f $(DEV_DOCKER_COMPOSE) down

docker-clean: ## Remove the development containers and volumes
	${DOCKER_COMPOSE} -f $(DEV_DOCKER_COMPOSE) rm -fsv

hooks: ## Install the git hooks defined in lefthook.yml (requires: brew install lefthook).
	lefthook install

clean:
	rm -rf \
		$(addprefix release-,$(RELEASE_TARGETS)) \
		$(addprefix auth-,$(RELEASE_TARGETS)) \
		$(RELEASE_ARCHIVES) \
		auth

.PHONY: all build deps image migrate test sec vulncheck format hooks lint unused release golangci-lint
.PHONY: check-gosec check-govulncheck check-oapi-codegen check-staticcheck check-go-version check-format
CHECK_FILES ?= ./...

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

TOOL_BIN_DIR = tools/bin
TOOL_TARGETS = \
	$(TOOL_BIN_DIR)/govulncheck \
	$(TOOL_BIN_DIR)/golangci-lint


help: ## Show this help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {sub("\\\\n",sprintf("\n%22c"," "), $$2);printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

all: check-go-version golangci-lint build ## Run the tests and build the binary.

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

lint: \
	check-go-version \
	golangci-lint \
	vulncheck

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

migrate_dev: ## Run database migrations for development.
	hack/migrate.sh postgres

migrate_test: ## Run database migrations for test.
	hack/migrate.sh postgres

test: auth ## Run tests.
	go test -failfast $(CHECK_FILES) -coverprofile=coverage.out -coverpkg ./... -p 1 -race -v -count=1
	./hack/coverage.sh

check-go-version: ## Verify the pinned Go version matches across go.mod, Dockerfiles, and submodules.
	./hack/check-go-version.sh

.NOTPARALLEL: $(TOOL_TARGETS)
$(TOOL_TARGETS):
	$(MAKE) -C tools

sec: | $(TOOL_BIN_DIR)/golangci-lint # Check for security issues (gosec)
	$(TOOL_BIN_DIR)/golangci-lint run --enable-only=gosec $(CHECK_FILES)

vulncheck: $(TOOL_BIN_DIR)/govulncheck # Check for known vulnerabilities
	$(TOOL_BIN_DIR)/govulncheck $(CHECK_FILES) | go run ./hack/vulncheck-filter

unused: | $(TOOL_BIN_DIR)/golangci-lint # Look for unused code
	$(TOOL_BIN_DIR)/golangci-lint run --enable-only=unused $(CHECK_FILES)

golangci-lint: | $(TOOL_BIN_DIR)/golangci-lint
	$(TOOL_BIN_DIR)/golangci-lint run $(CHECK_FILES)

generate: | check-oapi-codegen
	go generate ./...

check-oapi-codegen:
	@command -v oapi-codegen >/dev/null 2>&1 \
		|| go install github.com/deepmap/oapi-codegen/cmd/oapi-codegen@latest

dev: ## Run the development containers
	${DOCKER_COMPOSE} -f $(DEV_DOCKER_COMPOSE) up

down: ## Shutdown the development containers
	# Start postgres first and apply migrations
	${DOCKER_COMPOSE} -f $(DEV_DOCKER_COMPOSE) down

docker-test: ## Run the tests using the development containers
	${DOCKER_COMPOSE} -f $(DEV_DOCKER_COMPOSE) up -d postgres
	${DOCKER_COMPOSE} -f $(DEV_DOCKER_COMPOSE) run auth sh -c "make migrate_test"
	${DOCKER_COMPOSE} -f $(DEV_DOCKER_COMPOSE) run auth sh -c "make test"
	${DOCKER_COMPOSE} -f $(DEV_DOCKER_COMPOSE) down -v

docker-build: ## Force a full rebuild of the development containers
	${DOCKER_COMPOSE} -f $(DEV_DOCKER_COMPOSE) build --no-cache
	${DOCKER_COMPOSE} -f $(DEV_DOCKER_COMPOSE) up -d postgres
	${DOCKER_COMPOSE} -f $(DEV_DOCKER_COMPOSE) run auth sh -c "make migrate_dev"
	${DOCKER_COMPOSE} -f $(DEV_DOCKER_COMPOSE) down

docker-clean: ## Remove the development containers and volumes
	${DOCKER_COMPOSE} -f $(DEV_DOCKER_COMPOSE) rm -fsv

format:
	gofmt -s -w .

check-format: ## Verify gofmt formatting. Pass FILES="..." to scope the check.
	@files=$$(gofmt -s -l $(or $(FILES),.)); \
	if [ -n "$$files" ]; then \
		echo "The following files are not gofmt-formatted:"; \
		echo "$$files"; \
		echo 'Run "make format" and re-stage the changes.'; \
		exit 1; \
	fi

hooks: ## Install the git hooks defined in lefthook.yml (requires: brew install lefthook).
	lefthook install
	$(MAKE) -C tools

clean:
	$(MAKE) -C tools clean
	rm -rf \
		$(addprefix release-,$(RELEASE_TARGETS)) \
		$(addprefix auth-,$(RELEASE_TARGETS)) \
		$(RELEASE_ARCHIVES) \
		auth

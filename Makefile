.PHONY: all build deps image migrate test vet sec vulncheck format unused
.PHONY: check-gosec check-govulncheck check-oapi-codegen check-staticcheck
CHECK_FILES?=./...

ifdef RELEASE_VERSION
	VERSION=v$(RELEASE_VERSION)
else
	VERSION=$(shell git describe --tags)
endif

FLAGS=-ldflags "-X github.com/supabase/auth/internal/utilities.Version=$(VERSION)" -buildvcs=false

ifneq ($(shell docker compose version 2>/dev/null),)
  DOCKER_COMPOSE=docker compose
else
  DOCKER_COMPOSE=docker-compose
endif

DEV_DOCKER_COMPOSE:=docker-compose-dev.yml

help: ## Show this help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {sub("\\\\n",sprintf("\n%22c"," "), $$2);printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

all: vet sec static build ## Run the tests and build the binary.

build: deps ## Build the binary.
	CGO_ENABLED=0 go build $(FLAGS)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(FLAGS) -o auth-arm64

build-strip: deps ## Build a stripped binary, for which the version file needs to be rewritten.
	echo "package utilities" > internal/utilities/version.go
	echo "const Version = \"$(VERSION)\"" >> internal/utilities/version.go

	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build \
		$(FLAGS) -ldflags "-s -w" -o auth-arm64-strip

deps: ## Install dependencies.
	@go mod download
	@go mod verify

migrate_dev: ## Run database migrations for development.
	hack/migrate.sh postgres

migrate_test: ## Run database migrations for test.
	hack/migrate.sh postgres

test: build ## Run tests.
	go test $(CHECK_FILES) -coverprofile=coverage.out -coverpkg ./... -p 1 -race -v -count=1
	./hack/coverage.sh

vet: # Vet the code
	go vet $(CHECK_FILES)

sec: check-gosec # Check for security vulnerabilities
	gosec -quiet -exclude-generated -exclude=G117,G704 $(CHECK_FILES)
	gosec -quiet -tests -exclude-generated -exclude=G101,G104,G117,G704 $(CHECK_FILES)

check-gosec:
	@command -v gosec >/dev/null 2>&1 \
		|| go install github.com/securego/gosec/v2/cmd/gosec@latest

vulncheck: check-govulncheck # Check for known vulnerabilities
	govulncheck $(CHECK_FILES)

check-govulncheck:
	@command -v govulncheck >/dev/null 2>&1 \
		|| go install golang.org/x/vuln/cmd/govulncheck@latest

unused: | check-staticcheck # Look for unused code
	@echo "Unused code:"
	staticcheck -checks U1000 $(CHECK_FILES)
	@echo
	@echo "Code used only in _test.go (do move it in those files):"
	staticcheck -checks U1000 -tests=false $(CHECK_FILES)

static: | check-staticcheck
	staticcheck ./...

check-staticcheck:
	@command -v staticcheck >/dev/null 2>&1 \
		|| go install honnef.co/go/tools/cmd/staticcheck@latest

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

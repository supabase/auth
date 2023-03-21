.PHONY: all build deps dev-deps image migrate test vet sec format unused
CHECK_FILES?=./...
FLAGS?=-ldflags "-X github.com/supabase/gotrue/internal/utilities.Version=`git describe --tags`" -buildvcs=false
DEV_DOCKER_COMPOSE:=docker-compose-dev.yml

help: ## Show this help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {sub("\\\\n",sprintf("\n%22c"," "), $$2);printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

all: vet sec static build ## Run the tests and build the binary.

build: deps ## Build the binary.
	CGO_ENABLED=0 go build $(FLAGS)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(FLAGS) -o gotrue-arm64

dev-deps: ## Install developer dependencies
	@go install github.com/gobuffalo/pop/soda@latest
	@go install github.com/securego/gosec/v2/cmd/gosec@latest
	@go install honnef.co/go/tools/cmd/staticcheck@latest
	@go install github.com/deepmap/oapi-codegen/cmd/oapi-codegen@latest

deps: ## Install dependencies.
	@go mod download
	@go mod verify

migrate_dev: ## Run database migrations for development.
	hack/migrate.sh postgres

migrate_test: ## Run database migrations for test.
	hack/migrate.sh postgres

test: build ## Run tests.
	go test $(CHECK_FILES) -coverprofile=coverage.out -coverpkg ./... -p 1 -race -v -count=1

vet: # Vet the code
	go vet $(CHECK_FILES)

sec: dev-deps # Check for security vulnerabilities
	gosec -quiet -exclude-generated $(CHECK_FILES)
	gosec -quiet -tests -exclude-generated -exclude=G104 $(CHECK_FILES)

unused: dev-deps # Look for unused code
	@echo "Unused code:"
	staticcheck -checks U1000 $(CHECK_FILES)
	
	@echo
	
	@echo "Code used only in _test.go (do move it in those files):"
	staticcheck -checks U1000 -tests=false $(CHECK_FILES)

static: dev-deps
	staticcheck ./...

generate: dev-deps
	go generate ./...

dev: ## Run the development containers
	docker-compose -f $(DEV_DOCKER_COMPOSE) up

down: ## Shutdown the development containers
	# Start postgres first and apply migrations
	docker-compose -f $(DEV_DOCKER_COMPOSE) down

docker-test: ## Run the tests using the development containers
	docker-compose -f $(DEV_DOCKER_COMPOSE) up -d postgres
	docker-compose -f $(DEV_DOCKER_COMPOSE) run gotrue sh -c "make migrate_test"
	docker-compose -f $(DEV_DOCKER_COMPOSE) run gotrue sh -c "make test"
	docker-compose -f $(DEV_DOCKER_COMPOSE) down -v

docker-build: ## Force a full rebuild of the development containers
	docker-compose -f $(DEV_DOCKER_COMPOSE) build --no-cache
	docker-compose -f $(DEV_DOCKER_COMPOSE) up -d postgres
	docker-compose -f $(DEV_DOCKER_COMPOSE) run gotrue sh -c "make migrate_dev"
	docker-compose -f $(DEV_DOCKER_COMPOSE) down

docker-clean: ## Remove the development containers and volumes
	docker-compose -f $(DEV_DOCKER_COMPOSE) rm -fsv

format:
	gofmt -s -w .

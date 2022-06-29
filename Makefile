.PHONY: all build deps image lint migrate test vet
CHECK_FILES?=$$(go list ./... | grep -v /vendor/)
FLAGS?=-ldflags "-X github.com/netlify/gotrue/cmd.Version=`git describe --tags`"
DEV_DOCKER_COMPOSE:=docker-compose-dev.yml

help: ## Show this help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {sub("\\\\n",sprintf("\n%22c"," "), $$2);printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

all: lint vet build ## Run the tests and build the binary.

build: ## Build the binary.
	go build $(FLAGS)
	GOOS=linux GOARCH=arm64 go build $(FLAGS) -o gotrue-arm64

deps: ## Install dependencies.
	@go install github.com/gobuffalo/pop/soda@latest
	@go install golang.org/x/lint/golint@latest
	@go mod download

lint: ## Lint the code.
	golint $(CHECK_FILES)

migrate_dev: ## Run database migrations for development.
	hack/migrate.sh postgres

migrate_test: ## Run database migrations for test.
	hack/migrate.sh postgres

test: ## Run tests.
	go test -p 1 -v $(CHECK_FILES)

vet: # Vet the code
	go vet $(CHECK_FILES)

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

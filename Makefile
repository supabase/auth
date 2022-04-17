.PHONY: all build deps image lint migrate test vet
CHECK_FILES?=$$(go list ./... | grep -v /vendor/)
FLAGS?=-ldflags "-X github.com/netlify/gotrue/cmd.Version=`git describe --tags`"

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

image: ## Build the Docker image.
	docker build .

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


# Run the development containers
dev:
	docker-compose -f docker-compose-dev.yml up

# Run the tests using the development containers
docker-test:
	docker-compose -f docker-compose-dev.yml up -d postgres
	docker-compose -f docker-compose-dev.yml run gotrue sh -c "./hack/migrate.sh postgres"
	docker-compose -f docker-compose-dev.yml run gotrue sh -c "make test"
	docker-compose -f docker-compose-dev.yml down -v

# Remove the development containers and volumes
docker-build:
	docker-compose -f docker-compose-dev.yml build --no-cache

# Remove the development containers and volumes
docker-clean:
	docker-compose -f docker-compose-dev.yml rm -fsv

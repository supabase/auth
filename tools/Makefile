BIN_DIR := $(CURDIR)/bin
BIN_TARGETS := \
	$(BIN_DIR)/govulncheck \
	$(BIN_DIR)/golangci-lint

.PHONY: all
all: $(BIN_TARGETS)

$(BIN_DIR)/govulncheck: | $(BIN_DIR)
	GOBIN=$(BIN_DIR) go install golang.org/x/vuln/cmd/govulncheck

$(BIN_DIR)/golangci-lint: | $(BIN_DIR)
	GOBIN=$(BIN_DIR) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint

$(BIN_DIR):
	mkdir -p $(@)

.PHONY: clean
clean:
	rm -f $(BIN_TARGETS)
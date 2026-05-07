BIN_DIR := $(PWD)/bin

all: \
	$(BIN_DIR)/gosec \
	$(BIN_DIR)/staticcheck \
	$(BIN_DIR)/govulncheck

$(BIN_DIR)/gosec: | $(BIN_DIR)
	GOBIN=$(BIN_DIR) go install github.com/securego/gosec/v2/cmd/gosec

$(BIN_DIR)/staticcheck: | $(BIN_DIR)
	GOBIN=$(BIN_DIR) go install honnef.co/go/tools/cmd/staticcheck

$(BIN_DIR)/govulncheck: | $(BIN_DIR)
	GOBIN=$(BIN_DIR) go install golang.org/x/vuln/cmd/govulncheck

$(BIN_DIR):
	mkdir -p $(@)

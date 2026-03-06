## MetalWAF — build, test, lint, and packaging targets.
## Usage: make [target]

BINARY      := metalwaf
CMD         := ./cmd/metalwaf
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS     := -ldflags "-X main.version=$(VERSION) -s -w"

WEB_DIR     := internal/frontend/web
DIST_DIR    := $(WEB_DIR)/dist

# ── Colours ───────────────────────────────────────────────────────────────────
CYAN  := \033[0;36m
RESET := \033[0m

.PHONY: all build build-all test test-go test-ui lint clean dev ui-install \
        ui-build ui-dev docker help

## all: build the binary (default)
all: build

# ── Frontend ──────────────────────────────────────────────────────────────────

## ui-install: install npm dependencies
ui-install:
	@echo "$(CYAN)→ npm install$(RESET)"
	cd $(WEB_DIR) && npm install

## ui-build: compile the React SPA into web/dist
ui-build: ui-install
	@echo "$(CYAN)→ npm run build$(RESET)"
	cd $(WEB_DIR) && npm run build

## ui-dev: start the Vite dev server (with proxy to :9090)
ui-dev:
	@echo "$(CYAN)→ Vite dev server$(RESET)"
	cd $(WEB_DIR) && npm run dev

# ── Go ────────────────────────────────────────────────────────────────────────

## build: build the Go binary (requires ui-build to have run first)
build:
	@echo "$(CYAN)→ go build $(VERSION)$(RESET)"
	go build $(LDFLAGS) -o $(BINARY) $(CMD)

## build-ui-and-go: full production build (UI then Go)
build-ui-and-go: ui-build build

## build-all: cross-compile for common targets
build-all: ui-build
	@echo "$(CYAN)→ cross-compile$(RESET)"
	GOOS=linux   GOARCH=amd64  go build $(LDFLAGS) -o dist/$(BINARY)-linux-amd64   $(CMD)
	GOOS=linux   GOARCH=arm64  go build $(LDFLAGS) -o dist/$(BINARY)-linux-arm64   $(CMD)
	GOOS=darwin  GOARCH=amd64  go build $(LDFLAGS) -o dist/$(BINARY)-darwin-amd64  $(CMD)
	GOOS=darwin  GOARCH=arm64  go build $(LDFLAGS) -o dist/$(BINARY)-darwin-arm64  $(CMD)
	GOOS=windows GOARCH=amd64  go build $(LDFLAGS) -o dist/$(BINARY)-windows-amd64.exe $(CMD)

# ── Tests ─────────────────────────────────────────────────────────────────────

## test: run all Go tests
test: test-go

## test-go: run Go unit tests with race detector
test-go:
	@echo "$(CYAN)→ go test$(RESET)"
	go test -race -count=1 ./...

## test-ui: run frontend unit tests
test-ui:
	@echo "$(CYAN)→ npm test$(RESET)"
	cd $(WEB_DIR) && npm test -- --run

## test-all: run Go + frontend tests
test-all: test-go test-ui

# ── Lint ──────────────────────────────────────────────────────────────────────

## lint: run golangci-lint (must be installed)
lint:
	@echo "$(CYAN)→ golangci-lint$(RESET)"
	golangci-lint run ./...

# ── Dev helpers ───────────────────────────────────────────────────────────────

## dev: build and run the server locally
dev: build
	@echo "$(CYAN)→ running $(BINARY)$(RESET)"
	./$(BINARY) -config configs/metalwaf.yaml

## tidy: tidy and verify Go modules
tidy:
	go mod tidy
	go mod verify

# ── Docker ────────────────────────────────────────────────────────────────────

## docker: build a production Docker image
docker: ui-build
	@echo "$(CYAN)→ docker build$(RESET)"
	docker build -t metalwaf:$(VERSION) .

# ── Cleanup ───────────────────────────────────────────────────────────────────

## clean: remove build artifacts
clean:
	rm -f $(BINARY)
	rm -rf dist/
	rm -rf $(DIST_DIR)

# ── Help ──────────────────────────────────────────────────────────────────────

## help: list available targets
help:
	@grep -E '^##' Makefile | sed 's/## /  /'

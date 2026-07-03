VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
IMAGE    ?= acme-gateway
REGISTRY ?= ghcr.io/danieldonoghue
ACME_HOOKS_BIN_DIR ?=
BIND_E2E_DNS_SERVER ?= 127.0.0.1:1053
BIND_E2E_DNS_ZONE ?= pebble-test.local
STAGING_E2E_ENV ?= ACME_E2E_STAGING=1 ACME_E2E_COMPOSE_PROFILE=always-valid

LDFLAGS  := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.date=$(DATE)

.PHONY: build build-linux test test-e2e test-e2e-dns01 test-e2e-staging test-e2e-staging-lego vet lint security deb docker-dev docker clean help

help: ## Show this help message
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'

# ── Local build (native arch, for running on this machine) ───────────────────

build: ## Build for the local OS/arch
	go build -trimpath -ldflags "$(LDFLAGS)" -o dist/acme-gateway ./cmd/acme-gateway
	go build -trimpath -ldflags "$(LDFLAGS)" -o dist/acme-probe ./cmd/acme-probe

# ── Cross-compiled Linux binaries ────────────────────────────────────────────

build-linux: ## Cross-compile for linux/amd64 and linux/arm64
	@mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -trimpath -ldflags "$(LDFLAGS)" -o dist/acme-gateway_linux_amd64 ./cmd/acme-gateway
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
		go build -trimpath -ldflags "$(LDFLAGS)" -o dist/acme-gateway_linux_arm64 ./cmd/acme-gateway

# ── Test & quality ────────────────────────────────────────────────────────────

test: ## Run unit tests with race detector
	go test -race -count=1 ./...

test-e2e: ## Run end-to-end tests against Pebble (requires Docker)
	ACME_E2E_COMPOSE_PROFILE=always-valid go test -v -tags e2e -timeout 5m ./test/e2e/...

test-e2e-dns01: ## Run Pebble dns-01 test with BIND hook binaries (requires Docker; set ACME_HOOKS_BIN_DIR)
	@test -n "$(ACME_HOOKS_BIN_DIR)" || (echo "Error: ACME_HOOKS_BIN_DIR must be set to a directory containing bind-dns-deploy and bind-dns-cleanup" >&2; exit 1)
	@test -x "$(ACME_HOOKS_BIN_DIR)/bind-dns-deploy" || (echo "Error: missing executable $(ACME_HOOKS_BIN_DIR)/bind-dns-deploy" >&2; exit 1)
	@test -x "$(ACME_HOOKS_BIN_DIR)/bind-dns-cleanup" || (echo "Error: missing executable $(ACME_HOOKS_BIN_DIR)/bind-dns-cleanup" >&2; exit 1)
	go clean -testcache
	ACME_E2E_PEBBLE_DNS=1 ACME_E2E_COMPOSE_PROFILE=dns-challenge ACME_E2E_PEBBLE_DNS_PRESENT_CMD='BIND_DNS_SERVER=$(BIND_E2E_DNS_SERVER) BIND_DNS_ZONE=$(BIND_E2E_DNS_ZONE) $(ACME_HOOKS_BIN_DIR)/bind-dns-deploy' ACME_E2E_PEBBLE_DNS_CLEANUP_CMD='BIND_DNS_SERVER=$(BIND_E2E_DNS_SERVER) BIND_DNS_ZONE=$(BIND_E2E_DNS_ZONE) $(ACME_HOOKS_BIN_DIR)/bind-dns-cleanup' go test -v -tags e2e -run TestPebbleDNS01 -timeout 5m ./test/e2e/...

test-e2e-staging: ## Run LE staging E2E via dns-01 hook commands (set ACME_E2E_DOMAIN ACME_E2E_EMAIL ACME_E2E_DNS_PRESENT_CMD; optional ACME_E2E_DNS_CLEANUP_CMD; ACME_DNS_CHALLENGE_ZONE for CNAME delegation; any backend-specific env is the hook's own concern)
	@test -n "$(ACME_E2E_DOMAIN)" || (echo "Error: ACME_E2E_DOMAIN must be set" >&2; exit 1)
	@test -n "$(ACME_E2E_EMAIL)" || (echo "Error: ACME_E2E_EMAIL must be set" >&2; exit 1)
	@test -n "$(ACME_E2E_DNS_PRESENT_CMD)" || (echo "Error: ACME_E2E_DNS_PRESENT_CMD must be set" >&2; exit 1)
	go clean -testcache
	$(STAGING_E2E_ENV) go test -v -tags e2e -run '^TestStagingLE$$' -timeout 10m ./test/e2e/...

test-e2e-staging-lego: ## Run LE staging E2E using lego as external client against acme-gateway (set ACME_E2E_DOMAIN ACME_E2E_EMAIL ACME_E2E_DNS_PRESENT_CMD; optional ACME_E2E_DNS_CLEANUP_CMD; ACME_DNS_CHALLENGE_ZONE for CNAME delegation; any backend-specific env is the hook's own concern)
	@test -n "$(ACME_E2E_DOMAIN)" || (echo "Error: ACME_E2E_DOMAIN must be set" >&2; exit 1)
	@test -n "$(ACME_E2E_EMAIL)" || (echo "Error: ACME_E2E_EMAIL must be set" >&2; exit 1)
	@test -n "$(ACME_E2E_DNS_PRESENT_CMD)" || (echo "Error: ACME_E2E_DNS_PRESENT_CMD must be set" >&2; exit 1)
	go clean -testcache
	$(STAGING_E2E_ENV) go test -v -tags e2e -run '^TestStagingLELegoViaGateway$$' -timeout 10m ./test/e2e/...

vet: ## Run go vet
	go vet ./...

lint: ## Run golangci-lint (requires golangci-lint in PATH)
	golangci-lint run

security: ## Run govulncheck + gosec (requires both in PATH)
	govulncheck ./...
	gosec -severity medium -exclude G304 ./...

# ── Debian packages ───────────────────────────────────────────────────────────
# Requires docker (uses a Debian container for dpkg-deb).

deb: build-linux ## Build .deb packages for Debian 12/13 × amd64/arm64 (uses Docker)
	@chmod +x packaging/build-deb.sh
	@if [[ ! -d "packaging/hooks.d/examples" ]] || [[ -z "$$(ls -A packaging/hooks.d/examples/*.sh 2>/dev/null)" ]]; then \
		echo "Error: example DNS hooks not found in packaging/hooks.d/examples/" >&2; \
		exit 1; \
	fi
	@DEB_VERSION="$(subst v,,$(VERSION))"; \
	docker run --rm \
		-v "$(PWD):/workspace" \
		-w /workspace \
		debian:12-slim \
		bash -c "apt-get update -qq && apt-get install -qq -y dpkg && \
		for arch in amd64 arm64; do \
			for dver in 12 13; do \
				packaging/build-deb.sh $${DEB_VERSION} $${arch} $${dver}; \
			done; \
		done"
	@echo "Packages written to dist/"

# ── Docker ────────────────────────────────────────────────────────────────────

docker-dev: ## Build a local dev Docker image (from source, Alpine)
	docker build -t $(IMAGE):dev .

docker: build-linux ## Build multi-arch release Docker image (distroless, pre-built binary)
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		--file Dockerfile.release \
		--tag $(REGISTRY)/$(IMAGE):$(VERSION) \
		--tag $(REGISTRY)/$(IMAGE):latest \
		--push \
		.

# ── Housekeeping ──────────────────────────────────────────────────────────────

clean: ## Remove build artifacts
	rm -rf dist/

VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
IMAGE    ?= acme-gateway
REGISTRY ?= ghcr.io/danieldonoghue

LDFLAGS  := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.date=$(DATE)

.PHONY: build build-linux test test-e2e test-e2e-dns01 test-e2e-staging vet lint security deb docker-dev docker clean help

help: ## Show this help message
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'

# ── Local build (native arch, for running on this machine) ───────────────────

build: ## Build for the local OS/arch
	go build -trimpath -ldflags "$(LDFLAGS)" -o dist/acme-gateway ./cmd/acme-gateway

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
	go test -v -tags e2e -timeout 5m ./test/e2e/...

test-e2e-dns01: ## Run Pebble dns-01 test with real DNS validation via BIND (requires Docker + nsupdate)
	ACME_E2E_PEBBLE_DNS=1 PEBBLE_VA_ALWAYS_VALID=0 ACME_E2E_PEBBLE_DNS_PRESENT_CMD='sh $(PWD)/test/e2e/examples/dns_present_pebble.sh' ACME_E2E_PEBBLE_DNS_CLEANUP_CMD='sh $(PWD)/test/e2e/examples/dns_cleanup_pebble.sh' go test -v -tags e2e -run TestPebbleDNS01 -timeout 5m ./test/e2e/...

test-e2e-staging: ## Run LE staging E2E via dns-01 hooks (set ACME_E2E_DOMAIN ACME_E2E_EMAIL ACME_E2E_DNS_PRESENT_CMD; optional ACME_E2E_DNS_CLEANUP_CMD)
	ACME_E2E_STAGING=1 go test -v -tags e2e -run TestStagingLE -timeout 10m ./test/e2e/...

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

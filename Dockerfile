# ── Build stage ───────────────────────────────────────────────────────────────
# This Dockerfile builds from source — useful for local development and quick
# testing.  For production / CI releases use Dockerfile.release which copies a
# pre-compiled binary into a distroless image.
FROM golang:1.25-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /acme-gateway ./cmd/acme-gateway

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata

# Non-root user for the process.
RUN addgroup -S acme && adduser -S -G acme acme

# Runtime directories.
RUN mkdir -p /etc/acme-gateway /var/lib/acme-gateway && \
    chown acme:acme /etc/acme-gateway /var/lib/acme-gateway

COPY --from=builder /acme-gateway /usr/local/bin/acme-gateway

USER acme

# Config file and hook scripts are expected to be bind-mounted at runtime.
VOLUME ["/etc/acme-gateway", "/var/lib/acme-gateway"]

EXPOSE 443

ENTRYPOINT ["acme-gateway"]
CMD ["-config", "/etc/acme-gateway/config.yaml"]

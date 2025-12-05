# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Enable auto toolchain to download required Go version if needed
ENV GOTOOLCHAIN=auto
RUN go mod download

# Copy source code
COPY . .

# Build the demo binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /zkdpop-demo ./cmd/demo

# Runtime stage
FROM alpine:3.19

WORKDIR /app

# Install ca-certificates for HTTPS
RUN apk add --no-cache ca-certificates

# Copy binary from builder
COPY --from=builder /zkdpop-demo /app/zkdpop-demo

# Copy keys for demo (these are TEST keys only - do not use in production!)
COPY keys/ /app/keys/

# Expose demo port
EXPOSE 8081

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8081/api/info || exit 1

# Run the demo
ENTRYPOINT ["/app/zkdpop-demo"]

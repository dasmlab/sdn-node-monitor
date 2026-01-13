FROM golang:1.21-alpine AS builder

WORKDIR /build

# Install vtysh (FRR tools)
RUN apk add --no-cache frr frr-pythontools

# Copy go mod files
COPY go.mod go.sum* ./

# Download dependencies
RUN go mod download

# Copy source code
COPY main.go ./

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o sdn-node-monitor .

# Final stage
FROM alpine:latest

# Install runtime dependencies including podman client
# Note: We need podman client in the container to execute 'podman exec frr' commands
# The podman socket will be mounted from the host at runtime
RUN apk --no-cache add ca-certificates tini podman

WORKDIR /app

# Create directory for podman config (needed when running as non-root)
RUN mkdir -p /app/.config/containers && chmod 755 /app/.config /app/.config/containers

# Copy binary from builder
COPY --from=builder /build/sdn-node-monitor .

# Use tini for proper signal handling
ENTRYPOINT ["/sbin/tini", "--"]

# Run the monitor
CMD ["./sdn-node-monitor"]

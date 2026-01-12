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

# Install runtime dependencies
# Note: With hostNetwork: true, we can access host's podman, but we need the binary
# Option 1: Install podman in container (if available in Alpine repos)
# Option 2: Mount podman binary from host (see deployment.yaml)
RUN apk --no-cache add ca-certificates tini

# If podman is available in Alpine repos, uncomment:
# RUN apk --no-cache add podman

# Alternative: Copy podman from host if mounted (see deployment volumeMounts)

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/sdn-node-monitor .

# Use tini for proper signal handling
ENTRYPOINT ["/sbin/tini", "--"]

# Run the monitor
CMD ["./sdn-node-monitor"]

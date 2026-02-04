FROM golang:1.24-alpine AS builder

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
# Pass git commit hash as build arg if available
ARG GIT_COMMIT=unknown
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo \
	-ldflags "-X main.gitCommit=${GIT_COMMIT}" \
	-o sdn-node-monitor .

# Final stage
FROM alpine:latest

# Install runtime dependencies including podman client and nsenter (util-linux)
# Note: We need podman client in the container to execute 'podman exec frr' commands
# The podman socket will be mounted from the host at runtime
# Works on both Ubuntu and RHEL host systems
RUN apk --no-cache add ca-certificates tini podman util-linux

WORKDIR /app

# Create directory for podman config (needed when running as non-root)
RUN mkdir -p /app/.config/containers && chmod 755 /app/.config /app/.config/containers

# Copy binary from builder
COPY --from=builder /build/sdn-node-monitor .

# Use tini for proper signal handling
ENTRYPOINT ["/sbin/tini", "--"]

# Run the monitor
CMD ["./sdn-node-monitor"]

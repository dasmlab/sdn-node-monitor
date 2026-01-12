.PHONY: build test clean run docker-build podman-build docker-run podman-run fmt lint

# Build the Go binary
build:
	cd container && go mod download
	cd container && go build -o sdn-node-monitor main.go

# Run tests
test:
	cd container && go test -v ./...

# Clean build artifacts
clean:
	rm -f container/sdn-node-monitor
	cd container && go clean

# Run locally
run: build
	./container/sdn-node-monitor

# Build Docker image
docker-build:
	cd container && docker build -t sdn-node-monitor:local .

# Build Podman image
podman-build:
	cd container && podman build -t sdn-node-monitor:local .

# Run Docker container
docker-run:
	cd container && ./runme-local.sh

# Run Podman container (using docker syntax, adjust if needed)
podman-run:
	cd container && podman run -d \
		--name sdn-node-monitor-local-instance \
		--hostname $$(hostname) \
		-e NODE_NAME=$$(hostname) \
		-e LOG_LEVEL=info \
		-e CHECK_INTERVAL=30s \
		-e METRICS_PORT=8080 \
		-p 8080:8080 \
		--network host \
		-v /var/run/frr:/var/run/frr \
		--restart always \
		sdn-node-monitor:local

# Format code
fmt:
	cd container && go fmt ./...

# Lint code
lint:
	cd container && golangci-lint run

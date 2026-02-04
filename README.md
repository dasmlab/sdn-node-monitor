# SDN Node Monitor

A monitoring and remediation system for SDN nodes running FRR and BGP. This project consists of three main components:

1. **Container (Golang)**: Monitors BGP daemon status and exposes Prometheus metrics (SDN and non-SDN modes)
2. **AlertRule CR**: Prometheus alerting rules that trigger remediation
3. **Remediation Playbook**: Ansible playbook that restarts FRR and OVN BGP agent

## Architecture

```
┌─────────────────┐
│  SDN Node       │
│  ┌───────────┐  │
│  │ Monitor   │──┼──> HTTP /metrics endpoint
│  │ Container │  │    (Prometheus scrapes)
│  └───────────┘  │    (sdn_bgp_daemon_down only when down)
│       │         │
│       v         │
│  podman exec    │
│  frr vtysh      │
│  show daemons   │
└─────────────────┘
       │
       v
┌─────────────────┐
│  Prometheus     │
│  Scrapes /metrics│
│  + AlertRule    │──┼──> Alertmanager
│  (checks metric │
│   existence)    │
└─────────────────┘
       │
       v
┌─────────────────┐
│  Alertmanager   │──┼──> EDA/AAP Webhook
└─────────────────┘
       │
       v
┌─────────────────┐
│  EDA/AAP        │──┼──> Remediation Playbook
└─────────────────┘
       │
       v
┌─────────────────┐
│  Ansible        │
│  Playbook       │──┼──> Restart FRR + OVN BGP Agent
└─────────────────┘
```

### Metric Pattern (SDN mode, following frr_exporter)

The monitor follows the **frr_exporter pattern** for efficient metric cardinality:

- **When all required FRR daemons are UP**: Metric is **deleted** (not exposed) → No metric in Prometheus
- **When any required FRR daemon is DOWN**: Metric is **exposed with value 1** → Prometheus sees the metric

Required daemons checked: `zebra`, `bgpd`, `watchfrr`, `staticd`, `bfdd`

This means:
- **No metric = Healthy** (All required FRR daemons are running)
- **Metric exists = Problem** (One or more required FRR daemons are missing)

The AlertRule checks for metric **existence** (`sdn_bgp_daemon_down > 0`), not a specific value. This reduces cardinality significantly since we only create time series when there's an actual problem.

## Components

### 1. Monitor Container

A lightweight Golang container that:
- Runs as a background daemon
- Periodically checks FRR container daemons via `podman exec frr vtysh -c "show daemons"` (SDN mode)
- In non-SDN mode, monitors `bgpd` via `systemctl` and restarts on a schedule and on failures
- Optionally gossips events on port **9393** to peer nodes
- Optionally emits OpenTelemetry spans for event correlation
- Verifies all required daemons are present: `zebra`, `bgpd`, `watchfrr`, `staticd`, `bfdd`
- Exposes Prometheus metrics at `/metrics`
- Uses logrus for structured logging (debug, info, warn, critical)
- Resilient error handling (no fatal/panics that cause container exit)

**Configuration via environment variables:**
- `NODE_NAME`: Node identifier (defaults to hostname)
- `NODE_MODE`: `sdn` or `non-sdn` (default: `sdn`)
- `LOG_LEVEL`: Logging level - debug, info, warn, error (default: info)
- `CHECK_INTERVAL`: How often to check BGP status (default: 30s)
- `METRICS_PORT`: Port for metrics endpoint (default: 8080)
- `RESTART_INTERVAL`: Non-SDN periodic restart interval (default: 5m)
- `BGPD_SERVICE`: Non-SDN systemd service name (default: bgpd)
- `GOSSIP_ENABLED`: Enable gossip server and chatter (default: false)
- `GOSSIP_PORT`: Gossip listener port (default: 9393)
- `GOSSIP_PEERS`: Comma-separated peer list (`host:port` or URL)
- `GOSSIP_HELLO_INTERVAL`: Periodic hello interval (default: 2m)
- `OTEL_ENABLED`: Enable OpenTelemetry spans (default: false)
- `OTEL_EXPORTER_OTLP_ENDPOINT`: OTLP endpoint (e.g. `http://otel-collector:4318`)
- `OTEL_SERVICE_NAME`: Service name for traces (default: sdn-node-monitor)
- `TEST_MODE`: off | on | flip (default: off)
- `TEST_FLIP_INTERVAL`: How often to flip when TEST_MODE=flip (default: 4 checks)
- `BUFFER_WINDOW`: Rolling window for pre-failure state capture (default: 30s)

**Prometheus Metrics:**
- `sdn_bgp_daemon_down{node}`: Gauge (1 = down, metric only exists when BGP is down)
  - **Cardinality Reduction**: This metric is only exposed when BGP is down
  - When BGP is running, the metric is deleted and not exposed at all
  - This follows the frr_exporter pattern for efficient metric cardinality
- `sdn_simple_bgpd_restart_total{node,reason}`: Counter (non-SDN mode only)
  - Increments on bgpd restarts
  - `reason`: interval | inactive | test_mode

### 2. Prometheus ScrapeConfig

The `kubernetes/scrapeconfig.yaml` file contains the Prometheus scrape configuration for the SDN node monitor.

**Important Notes:**
- The container runs on port **8080** internally
- The container is mapped to host port **8989** (configured in `runme-local.sh`)
- Scrape targets should use the **host IP and port 8989**

**Configuration:**
- Update the `targets` list in `scrapeconfig.yaml` with your SDN node IPs
- Default target: `192.168.1.2:8989`
- Add more nodes as needed

**Deployment:**
- If using standard Prometheus: Apply the ConfigMap version
- If using Prometheus Operator: Use the ScrapeConfig CRD version (commented in the file)

### 3. Prometheus AlertRule

Defines alerting rules that:
- Monitor `sdn_bgp_daemon_down > 0` for 1 minute
- Trigger alerts with node information
- Route to EDA/AAP webhook receiver via Alertmanager

### 3. Remediation Playbook

Ansible playbook that:
- Accepts EDA event with node name
- Restarts FRR service
- Restarts OVN BGP Agent service
- Verifies BGP daemon is running via vtysh
- Provides detailed logging and error handling

## Project Structure

```
sdn-node-monitor/
├── container/              # Container code and build scripts
│   ├── main.go            # Main monitoring application
│   ├── Dockerfile         # Container build definition
│   ├── go.mod             # Go dependencies
│   ├── buildme.sh         # Build script
│   ├── pushme.sh          # Push to registry script
│   └── runme-local.sh     # Run locally script
├── kubernetes/            # Kubernetes manifests
│   ├── deployment.yaml    # DaemonSet, Service, ServiceMonitor
│   ├── scrapeconfig.yaml  # Prometheus scrape configuration
│   ├── alertrule.yaml     # PrometheusRule for alerts
│   └── alertmanager-config.yaml  # Alertmanager config example
├── ansible/               # Remediation playbooks
│   ├── restart-frr-bgp-agent.yml  # Main remediation playbook
│   ├── deploy-sdn-node-monitor.yml # Deploy container (SDN/non-SDN)
│   └── eda-event-example.json    # Example EDA event
├── Makefile               # Make targets for common tasks
└── README.md              # This file
```

## Building

### Build the Container

```bash
# Using the build script
cd container
./buildme.sh

# Or using Make
make podman-build

# Or using Podman directly
cd container
podman build -t sdn-node-monitor:local .
```

### Save Container Image for Transfer

To save the built container image to a tar file for transfer to a secured environment:

```bash
cd container
./saveme.sh
```

This creates `sdn-node-monitor-local.tar` which you can then transfer via SCP:

```bash
scp sdn-node-monitor-local.tar user@remote-host:/path/to/destination/
```

On the remote system, load the image:

```bash
podman load -i sdn-node-monitor-local.tar
```

### Build Go Binary Locally

```bash
# Using Make
make build

# Or manually
cd container
go mod download
go build -o sdn-node-monitor main.go
```

## Deployment

### Using Kubernetes/Podman

1. **Deploy the DaemonSet:**
   ```bash
   kubectl apply -f kubernetes/deployment.yaml
   ```

2. **Deploy the AlertRule:**
   ```bash
   kubectl apply -f kubernetes/alertrule.yaml
   ```

3. **Configure Alertmanager (RHOBS):**
   - Apply `kubernetes/alertmanager-config.yaml`
   - Update the EDA webhook URL in that file
   - Expose the Rulebook Activation service with an edge route:
     ```bash
     oc create route edge sdn-mon-webhook -n aap-instance \
       --service=sdn-mon-service \
       --port=5000 \
       --insecure-policy=Redirect
     ```
   - Use the route in `alertmanager-config.yaml`:
     `https://sdn-mon-webhook-aap-instance.apps.<domain>/webhook/sdn-bgp-daemon`

### Run Locally

```bash
# Using the run script (SDN mode default)
cd container
./runme-local.sh

# Non-SDN mode example
NODE_MODE=non-sdn BGPD_SERVICE=bgpd RESTART_INTERVAL=5m ./runme-local.sh

# Gossip + OTEL example
GOSSIP_ENABLED=true GOSSIP_PEERS="10.0.0.10:9393,10.0.0.11:9393" \
OTEL_ENABLED=true OTEL_EXPORTER_OTLP_ENDPOINT="http://otel-collector:4318" \
./runme-local.sh

# Or using Make
make docker-run

# Or manually with Podman (SDN mode example)
cd container
podman run -d \
  --name sdn-node-monitor-local-instance \
  --hostname $(hostname) \
  -e NODE_NAME=$(hostname) \
  -e NODE_MODE=sdn \
  -e LOG_LEVEL=info \
  -e CHECK_INTERVAL=30s \
  -e METRICS_PORT=8080 \
  -p 8989:8080 \
  --network host \
  -v /run/podman:/run/podman:rw \
  --privileged \
  --restart always \
  sdn-node-monitor:local
```

## Testing

### Test the Monitor Locally

```bash
# Build and run locally (requires vtysh to be available)
cd container
export NODE_NAME=test-node
export LOG_LEVEL=debug
go run main.go

# Or using Make
make build
make run
```

### Test Prometheus Metrics

```bash
curl http://localhost:8080/metrics
```

### Test Health Endpoint

```bash
curl http://localhost:8080/health
```

### Test Remediation Playbook

```bash
# Using the example event
ansible-playbook ansible/restart-frr-bgp-agent.yml \
  -e @ansible/eda-event-example.json \
  -i "localhost," -c local
```

## EDA/AAP Integration

The Alertmanager should be configured to send webhooks to your EDA/AAP endpoint when the `SDNBGPDaemonDown` alert fires. The webhook payload should include:

```json
{
  "extra_vars": {
    "node_name": "sdn-node-01",
    "alert_name": "SDNBGPDaemonDown",
    "severity": "critical"
  }
}
```

The EDA/AAP job template should then call the remediation playbook with this event data.

## Logging

The container uses logrus with the following log levels:
- **DEBUG**: Detailed diagnostic information
- **INFO**: General informational messages
- **WARN**: Warning messages (e.g., BGP not found)
- **ERROR**: Critical issues requiring immediate attention (BGP down) - logged with "level: critical" field

All logs include structured fields:
- `node`: Node identifier
- `error`: Error details when applicable
- `output`: Command output when relevant

## Troubleshooting

### Container can't access FRR container

- Ensure the container has access to podman binary and socket
- With `hostNetwork: true`, container shares host network namespace
- Verify podman socket is mounted: `/run/podman/podman.sock`
- If podman binary is not in container, mount it from host (see deployment.yaml comments)
- Ensure the FRR container is named `frr` (or update the command in code)
- Container needs `SYS_ADMIN` capability to exec into other containers
- Verify podman is available: `which podman` or mount from host

### Metrics not appearing in Prometheus

- Check ServiceMonitor is configured correctly
- Verify Prometheus is scraping the correct namespace
- Check pod labels match ServiceMonitor selector

### Alerts not firing

- Verify PrometheusRule is applied and recognized
- Check Alertmanager is configured to receive alerts
- Verify the metric `sdn_bgp_daemon_down` is being collected when BGP is down (SDN mode)
- For non-SDN mode, verify `sdn_simple_bgpd_restart_total` increments on restarts
- Remember: the metric only exists when BGP is down, so you won't see it when healthy

### Remediation playbook fails

- Ensure SSH access to target node
- Verify service names match your environment (frr, ovn-bgp-agent)
- Check Ansible can execute systemd commands on target node

## License

[Add your license here]

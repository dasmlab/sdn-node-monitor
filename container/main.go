package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
)

var (
	// Prometheus metrics
	// Only expose this metric when FRR daemons are DOWN (cardinality reduction)
	// When all required daemons (zebra, bgpd, watchfrr, staticd, bfdd) are up, the metric is deleted
	bgpDaemonDown = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sdn_bgp_daemon_down",
			Help: "FRR daemons are down on this node (1 = down, metric only exists when required daemons are missing)",
		},
		[]string{"node"},
	)
	bgpRestartTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sdn_simple_bgpd_restart_total",
			Help: "Total number of bgpd restarts performed by sdn-node-monitor (non-SDN mode)",
		},
		[]string{"node", "reason"},
	)

	// Configuration
	checkInterval       time.Duration = 30 * time.Second
	restartInterval     time.Duration = 5 * time.Minute
	nodeName            string
	nodeMode            string = "sdn"
	bgpdService         string = "edpm_ovn_bgp_agent.service"
	gossipEnabled       bool   = false
	gossipPort          string = "9393"
	gossipPeers         []string
	gossipHelloInterval time.Duration = 2 * time.Minute
	otelEnabled         bool          = false
	otelEndpoint        string        = ""
	otelServiceName     string        = "sdn-node-monitor"
	logLevel            string        = "info"
	gitCommit           string        = "unknown"
	testMode            string        = "off"
	testFlipInterval    int           = 4
	bufferWindow        time.Duration = 30 * time.Second
	maxBufferSize       int           = 10

	// State buffer for capturing logs before condition fires
	stateBuffer struct {
		sync.RWMutex
		snapshots []StateSnapshot
	}

	// Test mode state
	testModeState struct {
		sync.RWMutex
		flipState bool
		flipCount int
	}

	// Gossip state
	gossipState struct {
		sync.RWMutex
		lastTrace trace.SpanContext
	}

	httpClient = &http.Client{
		Timeout: 5 * time.Second,
	}

	tracer = otel.Tracer("sdn-node-monitor")
)

// StateSnapshot captures system state at a point in time
type StateSnapshot struct {
	Timestamp      time.Time
	FRRLogs        string
	OVNBGPStatus   string
	OVNBGPLogs     string
	FRRDaemonCheck string
	BGPDStatus     string
	BGPDLogs       string
	SystemState    string
}

type GossipMessage struct {
	Node      string `json:"node"`
	Mode      string `json:"mode"`
	Event     string `json:"event"`
	Reason    string `json:"reason,omitempty"`
	TraceID   string `json:"trace_id,omitempty"`
	SpanID    string `json:"span_id,omitempty"`
	Timestamp string `json:"timestamp"`
}

func init() {
	// Register Prometheus metrics
	prometheus.MustRegister(bgpDaemonDown)
	prometheus.MustRegister(bgpRestartTotal)

	// Get node name from environment or hostname
	nodeName = os.Getenv("NODE_NAME")
	if nodeName == "" {
		hostname, err := os.Hostname()
		if err != nil {
			logrus.WithError(err).Warn("Failed to get hostname, using 'unknown'")
			nodeName = "unknown"
		} else {
			nodeName = hostname
		}
	}

	// Get log level from environment
	if envLogLevel := os.Getenv("LOG_LEVEL"); envLogLevel != "" {
		logLevel = envLogLevel
	}

	// Get node mode from environment (sdn or non-sdn)
	if envMode := os.Getenv("NODE_MODE"); envMode != "" {
		mode := strings.ToLower(strings.TrimSpace(envMode))
		switch mode {
		case "sdn":
			nodeMode = "sdn"
		case "non-sdn", "nonsdn", "non_sdn":
			nodeMode = "non-sdn"
		default:
			logrus.WithField("node_mode", envMode).Warn("Invalid NODE_MODE, must be 'sdn' or 'non-sdn'. Defaulting to 'sdn'")
		}
	}

	// Gossip configuration
	if envGossip := os.Getenv("GOSSIP_ENABLED"); envGossip != "" {
		if parsed, ok := parseBool(envGossip); ok {
			gossipEnabled = parsed
		} else {
			logrus.WithField("gossip_enabled", envGossip).Warn("Invalid GOSSIP_ENABLED, must be true/false")
		}
	}
	if envPort := os.Getenv("GOSSIP_PORT"); envPort != "" {
		gossipPort = envPort
	}
	if envPeers := os.Getenv("GOSSIP_PEERS"); envPeers != "" {
		parts := strings.Split(envPeers, ",")
		for _, part := range parts {
			peer := strings.TrimSpace(part)
			if peer != "" {
				gossipPeers = append(gossipPeers, peer)
			}
		}
	}
	if envHello := os.Getenv("GOSSIP_HELLO_INTERVAL"); envHello != "" {
		if parsed, err := time.ParseDuration(envHello); err == nil {
			gossipHelloInterval = parsed
		} else {
			logrus.WithError(err).Warnf("Invalid GOSSIP_HELLO_INTERVAL '%s', using default 2m", envHello)
		}
	}

	// OpenTelemetry configuration
	if envService := os.Getenv("OTEL_SERVICE_NAME"); envService != "" {
		otelServiceName = envService
	}
	if envEndpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"); envEndpoint != "" {
		otelEndpoint = envEndpoint
		otelEnabled = true
	}
	if envOTEL := os.Getenv("OTEL_ENABLED"); envOTEL != "" {
		if parsed, ok := parseBool(envOTEL); ok {
			otelEnabled = parsed
		} else {
			logrus.WithField("otel_enabled", envOTEL).Warn("Invalid OTEL_ENABLED, must be true/false")
		}
	}

	// Get bgpd service name from environment (non-SDN mode)
	if envService := os.Getenv("BGPD_SERVICE"); envService != "" {
		bgpdService = envService
	}

	// Set logrus level
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		logrus.WithError(err).Warn("Invalid log level, defaulting to info")
		level = logrus.InfoLevel
	}
	logrus.SetLevel(level)
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
		ForceColors:   false,
	})

	// Get check interval from environment
	if envInterval := os.Getenv("CHECK_INTERVAL"); envInterval != "" {
		if parsed, err := time.ParseDuration(envInterval); err == nil {
			checkInterval = parsed
		} else {
			logrus.WithError(err).Warnf("Invalid CHECK_INTERVAL '%s', using default 30s", envInterval)
		}
	}

	// Get restart interval from environment (non-SDN mode)
	if envRestart := os.Getenv("RESTART_INTERVAL"); envRestart != "" {
		if parsed, err := time.ParseDuration(envRestart); err == nil {
			restartInterval = parsed
		} else {
			logrus.WithError(err).Warnf("Invalid RESTART_INTERVAL '%s', using default 5m", envRestart)
		}
	}

	// Get test mode from environment
	if envTestMode := os.Getenv("TEST_MODE"); envTestMode != "" {
		testMode = strings.ToLower(envTestMode)
		if testMode != "off" && testMode != "on" && testMode != "flip" {
			logrus.WithField("test_mode", testMode).Warn("Invalid TEST_MODE, must be 'off', 'on', or 'flip'. Defaulting to 'off'")
			testMode = "off"
		}
	}

	// Get test flip interval from environment
	if envFlipInterval := os.Getenv("TEST_FLIP_INTERVAL"); envFlipInterval != "" {
		if parsed, err := time.ParseDuration(envFlipInterval); err == nil {
			// Convert duration to number of check intervals
			testFlipInterval = int(parsed / checkInterval)
			if testFlipInterval < 1 {
				testFlipInterval = 1
			}
		}
	}

	// Get buffer window from environment
	if envBufferWindow := os.Getenv("BUFFER_WINDOW"); envBufferWindow != "" {
		if parsed, err := time.ParseDuration(envBufferWindow); err == nil {
			bufferWindow = parsed
		} else {
			logrus.WithError(err).Warnf("Invalid BUFFER_WINDOW '%s', using default 30s", envBufferWindow)
		}
	}

	// Initialize state buffer
	stateBuffer.snapshots = make([]StateSnapshot, 0, maxBufferSize)
}

func parseBool(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "yes", "on":
		return true, true
	case "false", "0", "no", "off":
		return false, true
	default:
		return false, false
	}
}

// runHostCommand executes a command on the host using nsenter when available.
func runHostCommand(ctx context.Context, args ...string) ([]byte, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("runHostCommand requires at least one argument")
	}
	hostRoot := os.Getenv("HOST_ROOT")
	if hostRoot == "" {
		if _, err := os.Stat("/host"); err == nil {
			hostRoot = "/host"
		}
	}
	command := args[0]
	if command == "systemctl" {
		command = "/usr/bin/systemctl"
	}
	if _, err := exec.LookPath("nsenter"); err == nil {
		nsenterArgs := []string{"--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid", "--cgroup"}
		if hostRoot != "" {
			nsenterArgs = append(nsenterArgs, "--root", hostRoot)
		}
		nsenterArgs = append(nsenterArgs, "--", command)
		nsenterArgs = append(nsenterArgs, args[1:]...)
		cmd := exec.CommandContext(ctx, "nsenter", nsenterArgs...)
		return cmd.CombinedOutput()
	}
	if hostRoot != "" {
		hostCommand := command
		if hostRoot != "" {
			hostCommand = filepath.Join(hostRoot, strings.TrimPrefix(command, "/"))
		}
		cmd := exec.CommandContext(ctx, "chroot", append([]string{hostRoot, hostCommand}, args[1:]...)...)
		return cmd.CombinedOutput()
	}
	cmd := exec.CommandContext(ctx, command, args[1:]...)
	return cmd.CombinedOutput()
}

func initTracing(ctx context.Context) (func(context.Context) error, error) {
	if !otelEnabled || otelEndpoint == "" {
		return nil, nil
	}

	endpoint := otelEndpoint
	var opts []otlptracehttp.Option
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		parsed, err := url.Parse(endpoint)
		if err != nil {
			return nil, fmt.Errorf("invalid OTEL_EXPORTER_OTLP_ENDPOINT: %w", err)
		}
		if parsed.Host == "" {
			return nil, fmt.Errorf("invalid OTEL_EXPORTER_OTLP_ENDPOINT host: %s", endpoint)
		}
		opts = append(opts, otlptracehttp.WithEndpoint(parsed.Host))
		if parsed.Path != "" && parsed.Path != "/" {
			opts = append(opts, otlptracehttp.WithURLPath(parsed.Path))
		}
		if parsed.Scheme == "http" {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
	} else {
		opts = append(opts, otlptracehttp.WithEndpoint(endpoint))
		opts = append(opts, otlptracehttp.WithInsecure())
	}

	exporter, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(otelServiceName),
			attribute.String("node", nodeName),
			attribute.String("node_mode", nodeMode),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	tracer = otel.Tracer(otelServiceName)

	return tp.Shutdown, nil
}

func normalizePeer(peer string) (string, error) {
	peer = strings.TrimSpace(peer)
	if peer == "" {
		return "", fmt.Errorf("empty peer")
	}
	if !strings.Contains(peer, "://") {
		peer = "http://" + peer
	}
	parsed, err := url.Parse(peer)
	if err != nil {
		return "", err
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("invalid peer host: %s", peer)
	}
	if !strings.Contains(parsed.Host, ":") {
		parsed.Host = net.JoinHostPort(parsed.Host, gossipPort)
	}
	if parsed.Path == "" || parsed.Path == "/" {
		parsed.Path = "/gossip"
	}
	return parsed.String(), nil
}

func storeGossipLink(sc trace.SpanContext) {
	if !sc.IsValid() {
		return
	}
	gossipState.Lock()
	defer gossipState.Unlock()
	gossipState.lastTrace = sc
}

func getGossipLink() (trace.SpanContext, bool) {
	gossipState.RLock()
	defer gossipState.RUnlock()
	if gossipState.lastTrace.IsValid() {
		return gossipState.lastTrace, true
	}
	return trace.SpanContext{}, false
}

func startEventSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	opts := []trace.SpanStartOption{trace.WithAttributes(attrs...)}
	if link, ok := getGossipLink(); ok {
		opts = append(opts, trace.WithLinks(trace.Link{SpanContext: link}))
	}
	return tracer.Start(ctx, name, opts...)
}

func sendGossip(ctx context.Context, eventName, reason string) {
	if !gossipEnabled || len(gossipPeers) == 0 {
		return
	}

	sc := trace.SpanContextFromContext(ctx)
	msg := GossipMessage{
		Node:      nodeName,
		Mode:      nodeMode,
		Event:     eventName,
		Reason:    reason,
		TraceID:   sc.TraceID().String(),
		SpanID:    sc.SpanID().String(),
		Timestamp: time.Now().Format(time.RFC3339),
	}

	payload, err := json.Marshal(msg)
	if err != nil {
		logrus.WithError(err).Warn("Failed to marshal gossip message")
		return
	}

	for _, peer := range gossipPeers {
		endpoint, err := normalizePeer(peer)
		if err != nil {
			logrus.WithError(err).WithField("peer", peer).Warn("Invalid gossip peer")
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
		if err != nil {
			logrus.WithError(err).WithField("peer", peer).Warn("Failed to create gossip request")
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := httpClient.Do(req)
		if err != nil {
			logrus.WithError(err).WithField("peer", peer).Warn("Failed to send gossip message")
			continue
		}
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			logrus.WithField("peer", peer).WithField("status", resp.StatusCode).Warn("Gossip peer returned non-2xx")
		}
	}
}

func startGossipServer(ctx context.Context) {
	if !gossipEnabled {
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/gossip", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var msg GossipMessage
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			logrus.WithError(err).Warn("Failed to decode gossip message")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var link trace.SpanContext
		if msg.TraceID != "" && msg.SpanID != "" {
			if tid, err := trace.TraceIDFromHex(msg.TraceID); err == nil {
				if sid, err := trace.SpanIDFromHex(msg.SpanID); err == nil {
					link = trace.NewSpanContext(trace.SpanContextConfig{
						TraceID:    tid,
						SpanID:     sid,
						TraceFlags: trace.FlagsSampled,
						Remote:     true,
					})
					storeGossipLink(link)
				}
			}
		}

		var span trace.Span
		if link.IsValid() {
			_, span = tracer.Start(ctx, "gossip.receive",
				trace.WithLinks(trace.Link{SpanContext: link}),
				trace.WithAttributes(
					attribute.String("event", msg.Event),
					attribute.String("reason", msg.Reason),
					attribute.String("from_node", msg.Node),
				),
			)
		} else {
			_, span = tracer.Start(ctx, "gossip.receive",
				trace.WithAttributes(
					attribute.String("event", msg.Event),
					attribute.String("reason", msg.Reason),
					attribute.String("from_node", msg.Node),
				),
			)
		}
		span.End()

		logrus.WithFields(logrus.Fields{
			"event":  msg.Event,
			"reason": msg.Reason,
			"node":   msg.Node,
		}).Info("Gossip message received")

		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	server := &http.Server{
		Addr:    ":" + gossipPort,
		Handler: mux,
	}

	go func() {
		logrus.WithField("port", gossipPort).Info("Starting gossip server")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logrus.WithError(err).Error("Gossip server failed")
		}
	}()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logrus.WithError(err).Warn("Failed to shut down gossip server")
		}
	}()
}

func startGossipHelloLoop(ctx context.Context) {
	if !gossipEnabled {
		return
	}
	sendHello := func() {
		spanCtx, span := startEventSpan(ctx, "gossip.hello",
			attribute.String("node", nodeName),
			attribute.String("mode", nodeMode),
		)
		sendGossip(spanCtx, "gossip_hello", "")
		span.End()
	}
	sendHello()
	if gossipHelloInterval <= 0 {
		return
	}
	ticker := time.NewTicker(gossipHelloInterval)
	go func() {
		for {
			select {
			case <-ctx.Done():
				ticker.Stop()
				return
			case <-ticker.C:
				sendHello()
			}
		}
	}()
}

// captureStateSnapshot captures current system state
func captureStateSnapshot(ctx context.Context) StateSnapshot {
	snapshot := StateSnapshot{
		Timestamp: time.Now(),
	}

	// Capture FRR container logs (last 100 lines, last 30 seconds)
	cmd := exec.CommandContext(ctx, "podman", "logs", "frr", "--tail", "100", "--since", "30s")
	if output, err := cmd.CombinedOutput(); err == nil {
		snapshot.FRRLogs = string(output)
	} else {
		snapshot.FRRLogs = fmt.Sprintf("Error capturing FRR logs: %v", err)
	}

	// Capture OVN BGP agent service status
	cmd = exec.CommandContext(ctx, "systemctl", "status", "edpm_ovn_bgp_agent", "--no-pager", "-l")
	if output, err := cmd.CombinedOutput(); err == nil {
		snapshot.OVNBGPStatus = string(output)
	} else {
		snapshot.OVNBGPStatus = fmt.Sprintf("Error capturing OVN BGP agent status: %v", err)
	}

	// Capture OVN BGP agent recent logs
	cmd = exec.CommandContext(ctx, "journalctl", "-u", "edpm_ovn_bgp_agent", "--since", "30s", "--no-pager", "-n", "50")
	if output, err := cmd.CombinedOutput(); err == nil {
		snapshot.OVNBGPLogs = string(output)
	} else {
		snapshot.OVNBGPLogs = fmt.Sprintf("Error capturing OVN BGP agent logs: %v", err)
	}

	// System state (dmesg tail - last 30 seconds)
	cmd = exec.CommandContext(ctx, "dmesg", "-T", "--since", "30s")
	if output, err := cmd.CombinedOutput(); err == nil {
		// Limit to last 50 lines to avoid too much data
		lines := strings.Split(string(output), "\n")
		if len(lines) > 50 {
			lines = lines[len(lines)-50:]
		}
		snapshot.SystemState = strings.Join(lines, "\n")
	} else {
		snapshot.SystemState = fmt.Sprintf("Error capturing system logs: %v", err)
	}

	return snapshot
}

// captureNonSDNSnapshot captures system state for non-SDN mode
func captureNonSDNSnapshot(ctx context.Context) StateSnapshot {
	snapshot := StateSnapshot{
		Timestamp: time.Now(),
	}

	// Capture bgpd service status
	if output, err := runHostCommand(ctx, "systemctl", "status", bgpdService, "--no-pager", "-l"); err == nil {
		snapshot.BGPDStatus = string(output)
	} else {
		snapshot.BGPDStatus = fmt.Sprintf("Error capturing bgpd status: %v", err)
	}

	// Capture bgpd recent logs
	if output, err := runHostCommand(ctx, "journalctl", "-u", bgpdService, "--since", "30s", "--no-pager", "-n", "50"); err == nil {
		snapshot.BGPDLogs = string(output)
	} else {
		snapshot.BGPDLogs = fmt.Sprintf("Error capturing bgpd logs: %v", err)
	}

	// System state (dmesg tail - last 30 seconds)
	if output, err := runHostCommand(ctx, "dmesg", "-T", "--since", "30s"); err == nil {
		lines := strings.Split(string(output), "\n")
		if len(lines) > 50 {
			lines = lines[len(lines)-50:]
		}
		snapshot.SystemState = strings.Join(lines, "\n")
	} else {
		snapshot.SystemState = fmt.Sprintf("Error capturing system logs: %v", err)
	}

	return snapshot
}

// addToBuffer adds a snapshot to the rolling buffer
func addToBuffer(snapshot StateSnapshot) {
	stateBuffer.Lock()
	defer stateBuffer.Unlock()

	// Add new snapshot
	stateBuffer.snapshots = append(stateBuffer.snapshots, snapshot)

	// Remove old snapshots outside buffer window
	cutoffTime := time.Now().Add(-bufferWindow)
	validSnapshots := make([]StateSnapshot, 0, maxBufferSize)
	for _, snap := range stateBuffer.snapshots {
		if snap.Timestamp.After(cutoffTime) {
			validSnapshots = append(validSnapshots, snap)
		}
	}

	// Limit buffer size
	if len(validSnapshots) > maxBufferSize {
		validSnapshots = validSnapshots[len(validSnapshots)-maxBufferSize:]
	}

	stateBuffer.snapshots = validSnapshots
}

// dumpBuffer dumps the buffer contents to logs and optionally to file
func dumpBuffer() {
	stateBuffer.RLock()
	defer stateBuffer.RUnlock()

	if len(stateBuffer.snapshots) == 0 {
		logrus.Warn("State buffer is empty - no state captured before condition fired")
		return
	}

	// Build buffer dump
	var buffer strings.Builder
	buffer.WriteString("\n=== State Buffer Dump (last 30s before condition fired) ===\n")
	buffer.WriteString(fmt.Sprintf("Captured %d snapshots\n\n", len(stateBuffer.snapshots)))

	for i, snap := range stateBuffer.snapshots {
		buffer.WriteString(fmt.Sprintf("--- Snapshot %d [%s] ---\n", i+1, snap.Timestamp.Format(time.RFC3339)))
		buffer.WriteString(fmt.Sprintf("FRR Daemon Check:\n%s\n", snap.FRRDaemonCheck))
		buffer.WriteString(fmt.Sprintf("FRR Logs:\n%s\n", snap.FRRLogs))
		buffer.WriteString(fmt.Sprintf("OVN BGP Agent Status:\n%s\n", snap.OVNBGPStatus))
		buffer.WriteString(fmt.Sprintf("OVN BGP Agent Logs:\n%s\n", snap.OVNBGPLogs))
		if snap.BGPDStatus != "" {
			buffer.WriteString(fmt.Sprintf("BGPD Status:\n%s\n", snap.BGPDStatus))
		}
		if snap.BGPDLogs != "" {
			buffer.WriteString(fmt.Sprintf("BGPD Logs:\n%s\n", snap.BGPDLogs))
		}
		if snap.SystemState != "" {
			buffer.WriteString(fmt.Sprintf("System Logs:\n%s\n", snap.SystemState))
		}
		buffer.WriteString("\n")
	}
	buffer.WriteString("=== End State Buffer ===\n")

	// Log the buffer dump
	logrus.WithFields(logrus.Fields{
		"node":        nodeName,
		"level":       "critical",
		"buffer_dump": buffer.String(),
	}).Error("FRR daemons condition fired - state buffer dump")

	// Optionally write to file
	timestamp := time.Now().Format("20060102-150405")
	filename := fmt.Sprintf("/tmp/sdn-monitor-capture-%s.log", timestamp)
	if err := os.WriteFile(filename, []byte(buffer.String()), 0644); err == nil {
		logrus.WithField("file", filename).Info("State buffer written to file")
	} else {
		logrus.WithError(err).Warn("Failed to write state buffer to file")
	}
}

// shouldForceTestCondition determines if test mode should force condition
func shouldForceTestCondition() bool {
	switch testMode {
	case "on":
		return true
	case "flip":
		// Toggle every testFlipInterval checks
		testModeState.Lock()
		testModeState.flipCount++
		if testModeState.flipCount >= testFlipInterval {
			testModeState.flipState = !testModeState.flipState
			testModeState.flipCount = 0
		}
		state := testModeState.flipState
		testModeState.Unlock()
		return state
	default:
		return false
	}
}

func checkBGPDaemon(ctx context.Context) (bool, error) {
	logrus.WithFields(logrus.Fields{
		"node": nodeName,
	}).Debug("Checking FRR daemons status")

	// Track previous state to detect transition
	wasDown := false
	if _, err := bgpDaemonDown.GetMetricWithLabelValues(nodeName); err == nil {
		wasDown = true
	}

	// Check if test mode should force condition
	forceCondition := shouldForceTestCondition()
	if forceCondition {
		logrus.WithFields(logrus.Fields{
			"node":      nodeName,
			"test_mode": testMode,
		}).Warn("TEST MODE: Forcing condition ON (FRR daemons down)")
		bgpDaemonDown.WithLabelValues(nodeName).Set(1)
		if !wasDown {
			spanCtx, span := startEventSpan(ctx, "frr.daemon_down",
				attribute.String("reason", "test_mode"),
				attribute.String("node", nodeName),
				attribute.String("mode", nodeMode),
			)
			sendGossip(spanCtx, "frr_daemon_down", "test_mode")
			span.End()
		}
		return false, fmt.Errorf("test mode forcing condition")
	}

	// Capture state snapshot before check
	snapshot := captureStateSnapshot(ctx)

	// Required daemons that must be present
	requiredDaemons := []string{"zebra", "bgpd", "watchfrr", "staticd", "bfdd"}

	// Execute podman exec to get into FRR container and run show daemons
	// Using -c flag to run command non-interactively (no -it needed)
	cmd := exec.CommandContext(ctx, "podman", "exec", "frr", "vtysh", "-c", "show daemons")
	output, err := cmd.CombinedOutput()

	// Store FRR daemon check output in snapshot
	snapshot.FRRDaemonCheck = string(output)
	if err != nil {
		snapshot.FRRDaemonCheck = fmt.Sprintf("ERROR: %v\nOUTPUT: %s", err, string(output))
	}

	if err != nil {
		logrus.WithFields(logrus.Fields{
			"node":   nodeName,
			"error":  err.Error(),
			"output": string(output),
		}).Error("Failed to execute podman exec frr vtysh command")

		// Add snapshot to buffer
		addToBuffer(snapshot)

		// If transitioning from OK to DOWN, dump buffer
		if !wasDown {
			dumpBuffer()
			spanCtx, span := startEventSpan(ctx, "frr.daemon_down",
				attribute.String("reason", "exec_error"),
				attribute.String("node", nodeName),
				attribute.String("mode", nodeMode),
			)
			sendGossip(spanCtx, "frr_daemon_down", "exec_error")
			span.End()
		}

		// On error, assume daemons are down and expose metric
		bgpDaemonDown.WithLabelValues(nodeName).Set(1)
		return false, fmt.Errorf("podman exec frr vtysh command failed: %w", err)
	}

	// Check output for all required daemons
	outputStr := strings.ToLower(string(output))
	missingDaemons := []string{}

	for _, daemon := range requiredDaemons {
		if !strings.Contains(outputStr, strings.ToLower(daemon)) {
			missingDaemons = append(missingDaemons, daemon)
		}
	}

	if len(missingDaemons) == 0 {
		// All required daemons are present - DELETE the metric (cardinality reduction)
		// This way the metric only exists when there's a problem
		bgpDaemonDown.DeleteLabelValues(nodeName)
		logrus.WithFields(logrus.Fields{
			"node": nodeName,
		}).Debug("All required FRR daemons are running - metric removed")
		return true, nil
	} else {
		// One or more daemons are missing - EXPOSE the metric with value 1

		// Add snapshot to buffer
		addToBuffer(snapshot)

		// If transitioning from OK to DOWN, dump buffer
		if !wasDown {
			dumpBuffer()
			spanCtx, span := startEventSpan(ctx, "frr.daemon_down",
				attribute.String("reason", "missing_daemons"),
				attribute.String("node", nodeName),
				attribute.String("mode", nodeMode),
			)
			sendGossip(spanCtx, "frr_daemon_down", "missing_daemons")
			span.End()
		}

		bgpDaemonDown.WithLabelValues(nodeName).Set(1)
		logrus.WithFields(logrus.Fields{
			"node":            nodeName,
			"missing_daemons": missingDaemons,
			"output":          string(output),
		}).Warn("Required FRR daemons missing - metric exposed")
		return false, fmt.Errorf("missing required daemons: %v", missingDaemons)
	}
}

func runMonitor(ctx context.Context) {
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	logFields := logrus.Fields{
		"node":           nodeName,
		"check_interval": checkInterval,
		"node_mode":      nodeMode,
	}
	if testMode != "off" {
		logFields["test_mode"] = testMode
		if testMode == "flip" {
			logFields["test_flip_interval"] = testFlipInterval
		}
	}
	logrus.WithFields(logFields).Info("Starting FRR daemons monitor")

	// Initial check
	_, err := checkBGPDaemon(ctx)
	if err != nil {
		logrus.WithError(err).Error("Initial FRR daemons check failed")
	}

	for {
		select {
		case <-ctx.Done():
			logrus.Info("Monitor context cancelled, shutting down")
			return
		case <-ticker.C:
			bgpRunning, err := checkBGPDaemon(ctx)
			if err != nil {
				logrus.WithError(err).Error("FRR daemons check failed, will retry on next interval")
				continue
			}

			if !bgpRunning {
				logFields := logrus.Fields{
					"node":  nodeName,
					"level": "critical",
				}
				if testMode != "off" {
					logFields["test_mode"] = testMode
				}
				logrus.WithFields(logFields).Error("FRR daemons are not running properly - alert should be triggered")
			} else {
				logFields := logrus.Fields{
					"node": nodeName,
				}
				if testMode != "off" {
					logFields["test_mode"] = testMode
				}
				logrus.WithFields(logFields).Info("All required FRR daemons are running normally")
			}
		}
	}
}

// checkBGPDService returns true when bgpd is active
func checkBGPDService(ctx context.Context) (bool, string) {
	if _, err := runHostCommand(ctx, "systemctl", "is-active", "--quiet", bgpdService); err != nil {
		return false, fmt.Sprintf("bgpd service '%s' is not active: %v", bgpdService, err)
	}
	return true, ""
}

// restartBGPD restarts bgpd and increments the restart metric
func restartBGPD(ctx context.Context, reason string) bool {
	spanCtx, span := startEventSpan(ctx, "bgpd.restart",
		attribute.String("node", nodeName),
		attribute.String("reason", reason),
		attribute.String("service", bgpdService),
	)
	defer span.End()

	logrus.WithFields(logrus.Fields{
		"node":   nodeName,
		"reason": reason,
	}).Warn("Restarting bgpd service")

	_, stopErr := runHostCommand(ctx, "systemctl", "stop", bgpdService)
	if stopErr != nil {
		logrus.WithError(stopErr).Warn("Failed to stop bgpd, will attempt restart")
	}

	_, startErr := runHostCommand(ctx, "systemctl", "start", bgpdService)
	if startErr != nil {
		logrus.WithError(startErr).Warn("Failed to start bgpd, attempting systemctl restart")
		_, _ = runHostCommand(ctx, "systemctl", "restart", bgpdService)
	}

	success := false
	for i := 0; i < 3; i++ {
		if active, _ := checkBGPDService(ctx); active {
			success = true
			break
		}
		time.Sleep(2 * time.Second)
	}

	if !success {
		statusOut, err := runHostCommand(ctx, "systemctl", "status", bgpdService, "--no-pager", "-l")
		if err != nil {
			logrus.WithError(err).Error("bgpd restart verification failed")
		} else {
			logrus.WithField("status", string(statusOut)).Error("bgpd restart verification failed")
		}
	} else {
		logrus.WithField("service", bgpdService).Info("bgpd restart verified as active")
	}

	span.SetAttributes(attribute.Bool("restart_success", success))
	bgpRestartTotal.WithLabelValues(nodeName, reason).Inc()
	sendGossip(spanCtx, "bgpd_restart", reason)

	return success
}

// runNonSDNMonitor monitors bgpd on non-SDN nodes (systemctl)
func runNonSDNMonitor(ctx context.Context) {
	checkTicker := time.NewTicker(checkInterval)
	restartTicker := time.NewTicker(restartInterval)
	defer checkTicker.Stop()
	defer restartTicker.Stop()

	logFields := logrus.Fields{
		"node":             nodeName,
		"check_interval":   checkInterval,
		"restart_interval": restartInterval,
		"node_mode":        nodeMode,
		"bgpd_service":     bgpdService,
	}
	logrus.WithFields(logFields).Info("Starting bgpd monitor (non-SDN mode)")

	for {
		select {
		case <-ctx.Done():
			logrus.Info("Monitor context cancelled, shutting down")
			return
		case <-restartTicker.C:
			if ok := restartBGPD(ctx, "interval"); !ok {
				logrus.WithField("service", bgpdService).Error("bgpd restart failed on interval")
			}
		case <-checkTicker.C:
			// Force test mode condition if enabled
			if shouldForceTestCondition() {
				addToBuffer(captureNonSDNSnapshot(ctx))
				dumpBuffer()
				if ok := restartBGPD(ctx, "test_mode"); !ok {
					logrus.WithField("service", bgpdService).Error("bgpd restart failed in test mode")
				}
				continue
			}

			active, message := checkBGPDService(ctx)
			if !active {
				logrus.WithFields(logrus.Fields{
					"node":    nodeName,
					"service": bgpdService,
				}).Error(message)
				addToBuffer(captureNonSDNSnapshot(ctx))
				dumpBuffer()
				if ok := restartBGPD(ctx, "inactive"); !ok {
					logrus.WithField("service", bgpdService).Error("bgpd restart failed after inactive state")
				}
				continue
			}

			logrus.WithFields(logrus.Fields{
				"node":    nodeName,
				"service": bgpdService,
			}).Debug("bgpd service is active")
		}
	}
}

func main() {
	logrus.WithFields(logrus.Fields{
		"git_commit": gitCommit,
	}).Info("SDN Node Monitor starting up")

	configFields := logrus.Fields{
		"node":           nodeName,
		"check_interval": checkInterval,
		"log_level":      logLevel,
		"git_commit":     gitCommit,
		"node_mode":      nodeMode,
	}
	if gossipEnabled {
		configFields["gossip_enabled"] = gossipEnabled
		configFields["gossip_port"] = gossipPort
		configFields["gossip_peers"] = len(gossipPeers)
	}
	if otelEnabled {
		configFields["otel_enabled"] = otelEnabled
		configFields["otel_endpoint"] = otelEndpoint
		configFields["otel_service"] = otelServiceName
	}
	if nodeMode == "non-sdn" {
		configFields["restart_interval"] = restartInterval
		configFields["bgpd_service"] = bgpdService
	}
	if testMode != "off" {
		configFields["test_mode"] = testMode
		if testMode == "flip" {
			configFields["test_flip_interval"] = testFlipInterval
		}
	}
	if bufferWindow > 0 {
		configFields["buffer_window"] = bufferWindow
	}
	logrus.WithFields(configFields).Info("Configuration loaded")

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize OpenTelemetry (optional)
	if shutdown, err := initTracing(ctx); err != nil {
		logrus.WithError(err).Warn("Failed to initialize OpenTelemetry")
	} else if shutdown != nil {
		defer func() {
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			if err := shutdown(shutdownCtx); err != nil {
				logrus.WithError(err).Warn("Failed to shutdown OpenTelemetry")
			}
		}()
	}

	// Start gossip server (optional)
	startGossipServer(ctx)
	startGossipHelloLoop(ctx)

	// Start HTTP server for Prometheus metrics
	metricsHandler := promhttp.Handler()
	http.Handle("/metrics", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logrus.WithFields(logrus.Fields{
			"method": r.Method,
			"path":   r.URL.Path,
			"remote": r.RemoteAddr,
			"node":   nodeName,
			"ua":     r.UserAgent(),
		}).Info("Metrics scrape request received")
		metricsHandler.ServeHTTP(w, r)
	}))
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	metricsPort := os.Getenv("METRICS_PORT")
	if metricsPort == "" {
		metricsPort = "8080"
	}

	server := &http.Server{
		Addr:    ":" + metricsPort,
		Handler: nil,
	}

	go func() {
		logrus.WithField("port", metricsPort).Info("Starting metrics HTTP server")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logrus.WithError(err).Error("Metrics server failed")
			// Don't exit, continue monitoring
		}
	}()

	// Start monitoring loop
	if nodeMode == "non-sdn" {
		go runNonSDNMonitor(ctx)
	} else {
		go runMonitor(ctx)
	}

	// Wait for interrupt signal for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	logrus.Info("SDN Node Monitor is running. Press Ctrl+C to stop.")

	// Wait for signal
	sig := <-sigChan
	logrus.WithField("signal", sig.String()).Info("Received shutdown signal, shutting down gracefully")

	// Cancel context to stop monitoring
	cancel()

	// Shutdown HTTP server gracefully
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logrus.WithError(err).Error("Error shutting down HTTP server")
	} else {
		logrus.Info("HTTP server shut down successfully")
	}

	logrus.Info("SDN Node Monitor stopped")
}

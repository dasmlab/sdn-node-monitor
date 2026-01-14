package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
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

	// Configuration
	checkInterval   time.Duration = 30 * time.Second
	nodeName        string
	logLevel        string = "info"
	gitCommit       string = "unknown"
	testMode        string = "off"
	testFlipInterval int  = 4
	bufferWindow    time.Duration = 30 * time.Second
	maxBufferSize   int          = 10

	// State buffer for capturing logs before condition fires
	stateBuffer struct {
		sync.RWMutex
		snapshots []StateSnapshot
	}

	// Test mode state
	testModeState struct {
		sync.RWMutex
		flipState bool
		flipCount  int
	}
)

// StateSnapshot captures system state at a point in time
type StateSnapshot struct {
	Timestamp      time.Time
	FRRLogs        string
	OVNBGPStatus   string
	OVNBGPLogs     string
	FRRDaemonCheck string
	SystemState    string
}

func init() {
	// Register Prometheus metrics
	prometheus.MustRegister(bgpDaemonDown)

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
		if snap.SystemState != "" {
			buffer.WriteString(fmt.Sprintf("System Logs:\n%s\n", snap.SystemState))
		}
		buffer.WriteString("\n")
	}
	buffer.WriteString("=== End State Buffer ===\n")

	// Log the buffer dump
	logrus.WithFields(logrus.Fields{
		"node":         nodeName,
		"level":        "critical",
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

	// Check if test mode should force condition
	forceCondition := shouldForceTestCondition()
	if forceCondition {
		logrus.WithFields(logrus.Fields{
			"node":      nodeName,
			"test_mode": testMode,
		}).Warn("TEST MODE: Forcing condition ON (FRR daemons down)")
		bgpDaemonDown.WithLabelValues(nodeName).Set(1)
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

	// Track previous state to detect transition
	wasDown := false
	if _, err := bgpDaemonDown.GetMetricWithLabelValues(nodeName); err == nil {
		wasDown = true
	}

	if err != nil {
		logrus.WithFields(logrus.Fields{
			"node":    nodeName,
			"error":   err.Error(),
			"output":  string(output),
		}).Error("Failed to execute podman exec frr vtysh command")
		
		// Add snapshot to buffer
		addToBuffer(snapshot)
		
		// If transitioning from OK to DOWN, dump buffer
		if !wasDown {
			dumpBuffer()
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

func main() {
	logrus.WithFields(logrus.Fields{
		"git_commit": gitCommit,
	}).Info("SDN Node Monitor starting up")
	
	configFields := logrus.Fields{
		"node":           nodeName,
		"check_interval": checkInterval,
		"log_level":      logLevel,
		"git_commit":     gitCommit,
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

	// Start HTTP server for Prometheus metrics
	http.Handle("/metrics", promhttp.Handler())
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
	go runMonitor(ctx)

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

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
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
	checkInterval time.Duration = 30 * time.Second
	nodeName      string
	logLevel      string = "info"
	gitCommit     string = "unknown"
)

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
}

func checkBGPDaemon(ctx context.Context) (bool, error) {
	logrus.WithFields(logrus.Fields{
		"node": nodeName,
	}).Debug("Checking FRR daemons status")

	// Required daemons that must be present
	requiredDaemons := []string{"zebra", "bgpd", "watchfrr", "staticd", "bfdd"}

	// Execute podman exec to get into FRR container and run show daemons
	// Using -c flag to run command non-interactively (no -it needed)
	cmd := exec.CommandContext(ctx, "podman", "exec", "frr", "vtysh", "-c", "show daemons")
	output, err := cmd.CombinedOutput()
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"node":    nodeName,
			"error":   err.Error(),
			"output":  string(output),
		}).Error("Failed to execute podman exec frr vtysh command")
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

	logrus.WithFields(logrus.Fields{
		"node":           nodeName,
		"check_interval": checkInterval,
	}).Info("Starting FRR daemons monitor")

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
				logrus.WithFields(logrus.Fields{
					"node": nodeName,
					"level": "critical",
				}).Error("FRR daemons are not running properly - alert should be triggered")
			} else {
				logrus.WithFields(logrus.Fields{
					"node": nodeName,
				}).Info("All required FRR daemons are running normally")
			}
		}
	}
}

func main() {
	logrus.WithFields(logrus.Fields{
		"git_commit": gitCommit,
	}).Info("SDN Node Monitor starting up")
	logrus.WithFields(logrus.Fields{
		"node":           nodeName,
		"check_interval": checkInterval,
		"log_level":      logLevel,
		"git_commit":     gitCommit,
	}).Info("Configuration loaded")

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

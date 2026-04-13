package metrics

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	klog "k8s.io/klog/v2"
)

var (
	FirewallSyncTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "wigglenet",
			Name:      "firewall_sync_total",
			Help:      "Total number of firewall rule sync attempts.",
		},
		[]string{"backend", "status"},
	)

	FirewallSyncDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "wigglenet",
			Name:      "firewall_sync_duration_seconds",
			Help:      "Duration of firewall rule sync operations.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"backend"},
	)

	PodCIDRsTotal = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "wigglenet",
			Name:      "pod_cidrs_total",
			Help:      "Current number of pod CIDRs tracked across all nodes.",
		},
	)

	PeersTotal = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "wigglenet",
			Name:      "peers_total",
			Help:      "Current number of WireGuard peers configured.",
		},
	)

	NetworkPolicyRulesTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "wigglenet",
			Name:      "network_policy_rules_total",
			Help:      "Current number of generated NetworkPolicy firewall rules.",
		},
		[]string{"direction"},
	)
)

func init() {
	prometheus.MustRegister(
		FirewallSyncTotal,
		FirewallSyncDuration,
		PodCIDRsTotal,
		PeersTotal,
		NetworkPolicyRulesTotal,
	)
}

// RecordFirewallSync records a firewall sync attempt with its duration and outcome.
func RecordFirewallSync(backend string, duration time.Duration, err error) {
	status := "success"
	if err != nil {
		status = "error"
	}
	FirewallSyncTotal.WithLabelValues(backend, status).Inc()
	FirewallSyncDuration.WithLabelValues(backend).Observe(duration.Seconds())
}

// Run starts the Prometheus metrics HTTP server. It blocks until the context
// is cancelled or the server encounters a fatal error.
func Run(ctx context.Context, addr string) {
	logger := klog.FromContext(ctx)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	server := &http.Server{
		Addr:        addr,
		Handler:     mux,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdownCtx)
	}()

	logger.Info("starting metrics server", "addr", addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error(err, "metrics server failed")
	}
}

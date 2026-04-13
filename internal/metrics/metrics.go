package metrics

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	klog "k8s.io/klog/v2"
)

var (
	BuildInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "wigglenet",
			Name:      "build_info",
			Help:      "Build information. Always 1.",
		},
		[]string{"version", "firewall_backend"},
	)

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
		BuildInfo,
		FirewallSyncTotal,
		FirewallSyncDuration,
		PodCIDRsTotal,
		PeersTotal,
		NetworkPolicyRulesTotal,
	)
}

// SetBuildInfo sets the build_info metric with version and backend labels.
func SetBuildInfo(version, firewallBackend string) {
	BuildInfo.WithLabelValues(version, firewallBackend).Set(1)
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

// TLSConfig holds optional TLS configuration for the metrics server.
type TLSConfig struct {
	CertFile     string // Server certificate
	KeyFile      string // Server private key
	ClientCAFile string // If set, require and verify client certificates against this CA
}

// Run starts the Prometheus metrics HTTP(S) server. It blocks until the context
// is cancelled or the server encounters a fatal error.
func Run(ctx context.Context, addr string, tlsCfg *TLSConfig) {
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

	if tlsCfg != nil && tlsCfg.CertFile != "" && tlsCfg.KeyFile != "" {
		// Use k8s dynamic certificate infrastructure for automatic
		// reload on file change (e.g. Secret-mounted certs rotated by
		// kubelet or cert-manager).
		servingCert, err := dynamiccertificates.NewDynamicServingContentFromFiles("wigglenet-metrics", tlsCfg.CertFile, tlsCfg.KeyFile)
		if err != nil {
			logger.Error(err, "failed to load serving certificate")
			return
		}
		go servingCert.Run(ctx, 1)

		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				certPEM, keyPEM := servingCert.CurrentCertKeyContent()
				cert, err := tls.X509KeyPair(certPEM, keyPEM)
				if err != nil {
					return nil, err
				}
				return &cert, nil
			},
		}

		if tlsCfg.ClientCAFile != "" {
			clientCA, err := dynamiccertificates.NewDynamicCAContentFromFile("wigglenet-metrics-client-ca", tlsCfg.ClientCAFile)
			if err != nil {
				logger.Error(err, "failed to load client CA")
				return
			}
			go clientCA.Run(ctx, 1)

			tlsConfig.ClientAuth = tls.RequireAnyClientCert
			tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				verifyOpts, ok := clientCA.VerifyOptions()
				if !ok {
					return fmt.Errorf("client CA not yet loaded")
				}
				for _, rawCert := range rawCerts {
					cert, err := x509.ParseCertificate(rawCert)
					if err != nil {
						return fmt.Errorf("failed to parse client certificate: %w", err)
					}
					if _, err := cert.Verify(verifyOpts); err != nil {
						return fmt.Errorf("client certificate verification failed: %w", err)
					}
				}
				return nil
			}
			logger.Info("starting metrics server with mTLS", "addr", addr)
		} else {
			logger.Info("starting metrics server with TLS", "addr", addr)
		}

		server.TLSConfig = tlsConfig
		listener, err := tls.Listen("tcp", addr, tlsConfig)
		if err != nil {
			logger.Error(err, "failed to create TLS listener")
			return
		}
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			logger.Error(err, "metrics server failed")
		}
	} else {
		logger.Info("starting metrics server", "addr", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error(err, "metrics server failed")
		}
	}
}

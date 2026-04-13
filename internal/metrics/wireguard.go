package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/tibordp/wigglenet/internal/wireguard"
)

var (
	peerLastHandshakeDesc = prometheus.NewDesc(
		"wigglenet_peer_last_handshake_seconds",
		"Seconds since last successful WireGuard handshake with this peer.",
		[]string{"public_key", "endpoint"}, nil,
	)
	peerReceiveBytesDesc = prometheus.NewDesc(
		"wigglenet_peer_receive_bytes_total",
		"Total bytes received from this WireGuard peer.",
		[]string{"public_key", "endpoint"}, nil,
	)
	peerTransmitBytesDesc = prometheus.NewDesc(
		"wigglenet_peer_transmit_bytes_total",
		"Total bytes transmitted to this WireGuard peer.",
		[]string{"public_key", "endpoint"}, nil,
	)
)

// WireGuardCollector implements prometheus.Collector and reads peer stats
// from the WireGuard device on each scrape.
type WireGuardCollector struct {
	manager wireguard.Manager
}

// NewWireGuardCollector creates a collector that reads WireGuard peer
// statistics on each Prometheus scrape.
func NewWireGuardCollector(manager wireguard.Manager) *WireGuardCollector {
	return &WireGuardCollector{manager: manager}
}

// RegisterWireGuardCollector creates and registers a WireGuard collector.
func RegisterWireGuardCollector(manager wireguard.Manager) {
	prometheus.MustRegister(NewWireGuardCollector(manager))
}

func (c *WireGuardCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- peerLastHandshakeDesc
	ch <- peerReceiveBytesDesc
	ch <- peerTransmitBytesDesc
}

func (c *WireGuardCollector) Collect(ch chan<- prometheus.Metric) {
	peers, err := c.manager.PeerStats()
	if err != nil {
		return
	}

	now := time.Now()
	for _, p := range peers {
		if !p.LastHandshakeTime.IsZero() {
			ch <- prometheus.MustNewConstMetric(
				peerLastHandshakeDesc,
				prometheus.GaugeValue,
				now.Sub(p.LastHandshakeTime).Seconds(),
				p.PublicKey, p.Endpoint,
			)
		}
		ch <- prometheus.MustNewConstMetric(
			peerReceiveBytesDesc,
			prometheus.CounterValue,
			float64(p.ReceiveBytes),
			p.PublicKey, p.Endpoint,
		)
		ch <- prometheus.MustNewConstMetric(
			peerTransmitBytesDesc,
			prometheus.CounterValue,
			float64(p.TransmitBytes),
			p.PublicKey, p.Endpoint,
		)
	}
}

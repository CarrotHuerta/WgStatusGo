package wireguard

import (
	"time"
)

const (
	DefaultOnlineThreshold = 180 * time.Second
)

// Peer represents all telemetry and metadata for a single WireGuard peer.
type Peer struct {
	IP                    string    `json:"ip"`
	Name                  string    `json:"name"`
	ConfName              string    `json:"conf_name"`
	CustomAlias           string    `json:"custom_alias"`
	IsCustomAlias         bool      `json:"is_custom_alias"`
	EndpointIP            string    `json:"endpoint_ip"`
	ISP                   string    `json:"isp"`
	OnlineStatus          bool      `json:"online_status"`
	PingMS                *float64  `json:"ping_ms"`
	PingHuman             string    `json:"ping_human"`
	PingSamples           []float64 `json:"ping_samples"`
	DataUsage             string    `json:"data_usage"`
	Interface             string    `json:"interface"`
	PublicKey             string    `json:"public_key"`
	PublicKeyShort        string    `json:"public_key_short"`
	AllowedIPs           []string  `json:"allowed_ips"`
	RxBytes               int64     `json:"rx_bytes"`
	TxBytes               int64     `json:"tx_bytes"`
	RxHuman               string    `json:"rx_human"`
	TxHuman               string    `json:"tx_human"`
	RxRateBps             float64   `json:"rx_rate_bps"`
	TxRateBps             float64   `json:"tx_rate_bps"`
	RxRateHuman           string    `json:"rx_rate_human"`
	TxRateHuman           string    `json:"tx_rate_human"`
	LatestHandshake       int64     `json:"latest_handshake"`
	LatestHandshakeHuman  string    `json:"latest_handshake_human"`
	MonthlyUsage          string    `json:"monthly_usage"`
	MonthlyBytes          int64     `json:"monthly_bytes"`
	ConnectedSinceRestart bool      `json:"connected_since_restart"`
}

// IsOnline checks whether the peer's last handshake is within the threshold.
func (p *Peer) IsOnline(now time.Time, threshold time.Duration) bool {
	if p.LatestHandshake <= 0 {
		return false
	}
	diff := now.Unix() - p.LatestHandshake
	return diff >= 0 && diff <= int64(threshold.Seconds())
}

// ToMap converts Peer to map[string]interface{} for dynamic exports and backward compatibility.
func (p *Peer) ToMap() map[string]interface{} {
	pingMSVal := interface{}(nil)
	if p.PingMS != nil {
		pingMSVal = *p.PingMS
	}

	samples := p.PingSamples
	if samples == nil {
		samples = []float64{}
	}

	allowed := p.AllowedIPs
	if allowed == nil {
		allowed = []string{}
	}

	return map[string]interface{}{
		"ip":                      p.IP,
		"name":                    p.Name,
		"conf_name":               p.ConfName,
		"custom_alias":            p.CustomAlias,
		"is_custom_alias":         p.IsCustomAlias,
		"endpoint_ip":             p.EndpointIP,
		"isp":                     p.ISP,
		"online_status":           p.OnlineStatus,
		"ping_ms":                 pingMSVal,
		"ping_human":              p.PingHuman,
		"ping_samples":            samples,
		"data_usage":              p.DataUsage,
		"interface":               p.Interface,
		"public_key":              p.PublicKey,
		"public_key_short":        p.PublicKeyShort,
		"allowed_ips":             allowed,
		"rx_bytes":                p.RxBytes,
		"tx_bytes":                p.TxBytes,
		"rx_human":                p.RxHuman,
		"tx_human":                p.TxHuman,
		"rx_rate_bps":             p.RxRateBps,
		"tx_rate_bps":             p.TxRateBps,
		"rx_rate_human":           p.RxRateHuman,
		"tx_rate_human":           p.TxRateHuman,
		"latest_handshake":        p.LatestHandshake,
		"latest_handshake_human":  p.LatestHandshakeHuman,
		"monthly_usage":           p.MonthlyUsage,
		"monthly_bytes":           p.MonthlyBytes,
		"connected_since_restart": p.ConnectedSinceRestart,
	}
}

// Summary stores aggregate server status and bandwidth counters.
type Summary struct {
	TotalPeers             int     `json:"total_peers"`
	OnlinePeers            int     `json:"online_peers"`
	ConnectedSinceRestart  int     `json:"connected_since_restart"`
	OfflinePeers           int     `json:"offline_peers"`
	TotalRxBytes           int64   `json:"total_rx_bytes"`
	TotalTxBytes           int64   `json:"total_tx_bytes"`
	TotalUsageHuman        string  `json:"total_usage_human"`
	TotalRxRateBps         float64 `json:"total_rx_rate_bps"`
	TotalTxRateBps         float64 `json:"total_tx_rate_bps"`
	TotalRxRateHuman       string  `json:"total_rx_rate_human"`
	TotalTxRateHuman       string  `json:"total_tx_rate_human"`
	CurrentMonth           string  `json:"current_month"`
	MockMode               bool    `json:"mock_mode"`
	UpdatedAt              string  `json:"updated_at"`
}

// ToMap converts Summary to map[string]interface{}.
func (s *Summary) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"total_peers":             s.TotalPeers,
		"online_peers":            s.OnlinePeers,
		"connected_since_restart": s.ConnectedSinceRestart,
		"offline_peers":           s.OfflinePeers,
		"total_rx_bytes":          s.TotalRxBytes,
		"total_tx_bytes":          s.TotalTxBytes,
		"total_usage_human":       s.TotalUsageHuman,
		"total_rx_rate_bps":       s.TotalRxRateBps,
		"total_tx_rate_bps":       s.TotalTxRateBps,
		"total_rx_rate_human":     s.TotalRxRateHuman,
		"total_tx_rate_human":     s.TotalTxRateHuman,
		"current_month":           s.CurrentMonth,
		"mock_mode":               s.MockMode,
		"updated_at":              s.UpdatedAt,
	}
}

// LivePayload models the unified /api/live endpoint payload.
type LivePayload struct {
	Peers   []*Peer  `json:"peers"`
	Summary *Summary `json:"summary"`
}

// BandwidthHistoryPoint models a point in time bandwidth telemetry.
type BandwidthHistoryPoint struct {
	Timestamp int64   `json:"timestamp"`
	RxMbps    float64 `json:"rx_mbps"`
	TxMbps    float64 `json:"tx_mbps"`
}

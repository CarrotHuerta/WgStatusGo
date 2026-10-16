package history

import (
	"fmt"
	"time"

	"wgstatus/internal/wireguard"
)

// ConnectionSession represents an individual device connection window.
type ConnectionSession struct {
	ID          string    `json:"id"`
	PeerIP      string    `json:"peer_ip"`
	EndpointIP  string    `json:"endpoint_ip"`
	ISP         string    `json:"isp"`
	StartedAt   int64     `json:"started_at"`
	LastActive  int64     `json:"last_active"`
	RxBytes     int64     `json:"rx_bytes"`
	TxBytes     int64     `json:"tx_bytes"`
	PingMS      *float64  `json:"ping_ms"`
	PingSamples []float64 `json:"ping_samples"`
}

// ToDict converts the session into a map matching Python's serialization format.
func (s *ConnectionSession) ToDict() map[string]interface{} {
	pingHuman := "-"
	if s.PingMS != nil {
		pingHuman = fmt.Sprintf("%.1f ms", *s.PingMS)
	}

	samples := s.PingSamples
	if samples == nil {
		samples = []float64{}
	}

	return map[string]interface{}{
		"id":           s.ID,
		"peer_ip":      s.PeerIP,
		"endpoint_ip":  s.EndpointIP,
		"isp":          s.ISP,
		"started_at":   s.StartedAt,
		"last_active":  s.LastActive,
		"rx_bytes":     s.RxBytes,
		"tx_bytes":     s.TxBytes,
		"ping_ms":      s.PingMS,
		"ping_human":   pingHuman,
		"ping_samples": samples,
	}
}

// MonthlyUsage stores cumulative transfer and metadata for a peer across the calendar month.
type MonthlyUsage struct {
	MonthlyRx       int64     `json:"monthly_rx"`
	MonthlyTx       int64     `json:"monthly_tx"`
	FirstSeen       int64     `json:"first_seen"`
	LastSeen        int64     `json:"last_seen"`
	LastEndpoint    string    `json:"last_endpoint"`
	LastISP         string    `json:"last_isp"`
	LastPingMS      *float64  `json:"last_ping_ms,omitempty"`
	LastPingSamples []float64 `json:"last_ping_samples,omitempty"`
	LastPingTime    int64     `json:"last_ping_time,omitempty"`
}

// PingRecord records a single latency probe sample.
type PingRecord struct {
	Timestamp   int64     `json:"timestamp"`
	TimeHuman   string    `json:"time_human"`
	HandshakeTS int64     `json:"handshake_ts"`
	PingMS      *float64  `json:"ping_ms"`
	PingSamples []float64 `json:"ping_samples"`
}

// StatePayload represents the structure written to data/history_state.json.
type StatePayload struct {
	CurrentMonth string                          `json:"current_month"`
	LastSavedAt  int64                           `json:"last_saved_at"`
	MonthlyUsage map[string]*MonthlyUsage        `json:"monthly_usage"`
	Sessions     map[string][]ConnectionSession `json:"sessions"`
	Aliases      map[string]string               `json:"aliases"`
	PingHistory  map[string][]PingRecord         `json:"ping_history"`
}

// HumanDuration formats a second duration into human readable text matching Python.
func HumanDuration(seconds int64) string {
	if seconds < 0 {
		seconds = 0
	}
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	}
	if seconds < 3600 {
		return fmt.Sprintf("%dm %ds", seconds/60, seconds%60)
	}
	return fmt.Sprintf("%dh %dm", seconds/3600, (seconds%3600)/60)
}

// HumanizeSession adds computed display fields in-place.
func HumanizeSession(s map[string]interface{}) {
	rx, _ := s["rx_bytes"].(int64)
	tx, _ := s["tx_bytes"].(int64)
	s["rx_human"] = wireguard.HumanBytes(rx)
	s["tx_human"] = wireguard.HumanBytes(tx)
	s["total_human"] = wireguard.HumanBytes(rx + tx)

	tStart, _ := s["started_at"].(int64)
	tEnd, _ := s["last_active"].(int64)

	if tStart > 0 {
		s["started_at_human"] = time.Unix(tStart, 0).Format("2006-01-02 15:04:05")
	} else {
		s["started_at_human"] = "-"
	}

	if tEnd > 0 {
		s["last_active_human"] = time.Unix(tEnd, 0).Format("2006-01-02 15:04:05")
	} else {
		s["last_active_human"] = "-"
	}

	dur := tEnd - tStart
	s["duration_human"] = HumanDuration(dur)
}

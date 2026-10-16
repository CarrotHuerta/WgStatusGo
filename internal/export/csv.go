package export

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strconv"
	"strings"
	"time"

	"wgstatus/internal/analytics"
)

var formulaPrefixes = []string{"=", "+", "@", "\t", "\r"}

// SanitizeCell prefixes formula injection characters with ' so spreadsheet programs never evaluate them.
func SanitizeCell(val interface{}) string {
	if val == nil {
		return ""
	}
	s := fmt.Sprintf("%v", val)
	if s == "" {
		return ""
	}

	for _, prefix := range formulaPrefixes {
		if strings.HasPrefix(s, prefix) {
			return "'" + s
		}
	}

	if strings.HasPrefix(s, "-") && len(s) > 1 {
		// Valid negative numbers are fine
		if _, err := strconv.ParseFloat(s, 64); err != nil {
			return "'" + s
		}
	}

	return s
}

type safeCSVWriter struct {
	w *csv.Writer
}

func newSafeCSVWriter(buf *bytes.Buffer) *safeCSVWriter {
	return &safeCSVWriter{w: csv.NewWriter(buf)}
}

func (sw *safeCSVWriter) Write(row []string) error {
	sanitized := make([]string, len(row))
	for i, v := range row {
		sanitized[i] = SanitizeCell(v)
	}
	return sw.w.Write(sanitized)
}

func (sw *safeCSVWriter) Flush() {
	sw.w.Flush()
}

// GeneratePeersCSV produces a sanitized CSV with UTF-8 BOM of the peers and monthly stats.
func GeneratePeersCSV(peers []map[string]interface{}, summary map[string]interface{}) []byte {
	var buf bytes.Buffer
	// UTF-8 BOM
	buf.WriteString("\xef\xbb\xbf")

	w := newSafeCSVWriter(&buf)
	exportTime := time.Now().Format("2006-01-02 15:04:05")

	_ = w.Write([]string{"# WireGuard Status - Peers Telemetry Report"})
	_ = w.Write([]string{"# Generated At", exportTime})

	month, _ := summary["current_month"].(string)
	if month != "" {
		_ = w.Write([]string{"# Month", month})
	}
	if summary != nil {
		totPeers := fmt.Sprintf("%v", summary["total_peers"])
		onlinePeers := fmt.Sprintf("%v", summary["online_peers"])
		totUsage := fmt.Sprintf("%v", summary["total_usage_human"])
		_ = w.Write([]string{"# Total Peers", totPeers, "Online", onlinePeers, "Total Usage", totUsage})
	}
	_ = w.Write([]string{})

	headers := []string{
		"Device Name",
		"IP Address",
		"Status",
		"Latency (ms)",
		"Latest Handshake",
		"Endpoint",
		"ISP / Network",
		"Monthly Download",
		"Monthly Upload",
		"Monthly Total",
		"Monthly Total (Bytes)",
		"Session Usage",
		"Current Down Rate",
		"Current Up Rate",
		"Connected Since Boot",
		"Public Key",
	}
	_ = w.Write(headers)

	for _, p := range peers {
		name, _ := p["name"].(string)
		if name == "" {
			name, _ = p["conf_name"].(string)
		}
		if name == "" {
			name = "Unnamed"
		}

		status := "Offline"
		if online, ok := p["online_status"].(bool); ok && online {
			status = "Online"
		}

		pingVal := "-"
		if pMS, ok := p["ping_ms"].(float64); ok {
			pingVal = fmt.Sprintf("%.1f", pMS)
		}

		sinceBoot := "No"
		if boot, ok := p["connected_since_restart"].(bool); ok && boot {
			sinceBoot = "Yes"
		}

		row := []string{
			name,
			fmt.Sprintf("%v", p["ip"]),
			status,
			pingVal,
			fmt.Sprintf("%v", p["latest_handshake_human"]),
			fmt.Sprintf("%v", p["endpoint_ip"]),
			fmt.Sprintf("%v", p["isp"]),
			fmt.Sprintf("%v", p["monthly_rx_human"]),
			fmt.Sprintf("%v", p["monthly_tx_human"]),
			fmt.Sprintf("%v", p["monthly_usage"]),
			fmt.Sprintf("%v", p["monthly_bytes"]),
			fmt.Sprintf("%v", p["data_usage"]),
			fmt.Sprintf("%v", p["rx_rate_human"]),
			fmt.Sprintf("%v", p["tx_rate_human"]),
			sinceBoot,
			fmt.Sprintf("%v", p["public_key"]),
		}
		_ = w.Write(row)
	}

	w.Flush()
	return buf.Bytes()
}

// GenerateSessionsCSV produces a CSV of recorded connection sessions.
func GenerateSessionsCSV(sessions []map[string]interface{}, peerIP, deviceName string) []byte {
	var buf bytes.Buffer
	buf.WriteString("\xef\xbb\xbf")
	w := newSafeCSVWriter(&buf)

	exportTime := time.Now().Format("2006-01-02 15:04:05")
	_ = w.Write([]string{"# WireGuard Status - Connection Sessions History"})
	_ = w.Write([]string{"# Generated At", exportTime})
	if peerIP != "" {
		if deviceName == "" {
			deviceName = "Unnamed"
		}
		_ = w.Write([]string{"# Device IP", peerIP, "Name", deviceName})
	}
	_ = w.Write([]string{})

	headers := []string{
		"Peer IP",
		"Session Started",
		"Last Active",
		"Duration",
		"Endpoint IP",
		"ISP / Network",
		"Ping (ms)",
		"Ping Samples",
		"Downloaded",
		"Uploaded",
		"Total Transferred",
		"Total Bytes",
	}
	_ = w.Write(headers)

	for _, s := range sessions {
		sIP, _ := s["peer_ip"].(string)
		if sIP == "" {
			sIP = peerIP
		}

		pingVal := "-"
		if pMS, ok := s["ping_ms"].(float64); ok {
			pingVal = fmt.Sprintf("%.1f", pMS)
		}

		samplesStr := "-"
		if samples, ok := s["ping_samples"].([]interface{}); ok && len(samples) > 0 {
			var parts []string
			for _, sm := range samples {
				parts = append(parts, fmt.Sprintf("%vms", sm))
			}
			samplesStr = strings.Join(parts, " -> ")
		}

		rx, _ := s["rx_bytes"].(int64)
		tx, _ := s["tx_bytes"].(int64)

		row := []string{
			sIP,
			fmt.Sprintf("%v", s["started_at_human"]),
			fmt.Sprintf("%v", s["last_active_human"]),
			fmt.Sprintf("%v", s["duration_human"]),
			fmt.Sprintf("%v", s["endpoint_ip"]),
			fmt.Sprintf("%v", s["isp"]),
			pingVal,
			samplesStr,
			fmt.Sprintf("%v", s["rx_human"]),
			fmt.Sprintf("%v", s["tx_human"]),
			fmt.Sprintf("%v", s["total_human"]),
			strconv.FormatInt(rx+tx, 10),
		}
		_ = w.Write(row)
	}

	w.Flush()
	return buf.Bytes()
}

func mb(val int64) string {
	return fmt.Sprintf("%.2f", float64(val)/1_000_000.0)
}

func hourRange(hour *int) string {
	if hour == nil {
		return "-"
	}
	return fmt.Sprintf("%02d:00-%02d:00", *hour, (*hour+1)%24)
}

// GenerateAnalyticsCSV produces a multi-section stacked CSV of traffic metrics.
func GenerateAnalyticsCSV(report *analytics.Report) []byte {
	var buf bytes.Buffer
	buf.WriteString("\xef\xbb\xbf")
	w := newSafeCSVWriter(&buf)

	_ = w.Write([]string{"# WireGuard Status - Traffic Analytics"})
	_ = w.Write([]string{"# Generated At", time.Now().Format("2006-01-02 15:04:05")})
	_ = w.Write([]string{"# Range", report.Range})
	_ = w.Write([]string{
		"# Total Traffic", report.Totals.TotalHuman,
		"Download", report.Totals.RxHuman,
		"Upload", report.Totals.TxHuman,
	})
	if report.PeakHour != nil {
		_ = w.Write([]string{"# Busiest hour of day", report.PeakHour.Label, "avg per day", report.PeakHour.AvgHuman})
	}
	_ = w.Write([]string{})

	// 1. ISP Ranking
	_ = w.Write([]string{"# ISP / Network ranking"})
	_ = w.Write([]string{"#", "ISP / Network", "Download (MB)", "Upload (MB)", "Total (MB)", "Share (%)", "Sessions", "Devices", "Connected time", "Peak hour"})
	for i, r := range report.TopISPs {
		_ = w.Write([]string{
			strconv.Itoa(i + 1),
			r.ISP,
			mb(r.Rx),
			mb(r.Tx),
			mb(r.Total),
			fmt.Sprintf("%.1f", r.SharePct),
			strconv.Itoa(r.Sessions),
			strconv.Itoa(r.Devices),
			r.ActiveHuman,
			hourRange(r.PeakHour),
		})
	}
	_ = w.Write([]string{})

	// 2. Traffic Series
	timeCol := "Hour"
	if report.Granularity == "day" {
		timeCol = "Day"
	}
	_ = w.Write([]string{"# Traffic over time"})
	_ = w.Write([]string{timeCol, "Download (MB)", "Upload (MB)", "Total (MB)", "Peak rate (Mbps)", "Avg online peers"})
	for _, pt := range report.Series {
		_ = w.Write([]string{
			pt.Key,
			mb(pt.Rx),
			mb(pt.Tx),
			mb(pt.Total),
			fmt.Sprintf("%.2f", pt.PeakBps/1_000_000.0),
			fmt.Sprintf("%.2f", pt.AvgOnline),
		})
	}
	_ = w.Write([]string{})

	// 3. Hour of Day
	_ = w.Write([]string{"# Traffic by hour of day"})
	_ = w.Write([]string{"Hour of day", "Avg download / day (MB)", "Avg upload / day (MB)", "Avg total / day (MB)"})
	for _, h := range report.HourOfDay {
		hr := h.Hour
		_ = w.Write([]string{
			hourRange(&hr),
			mb(h.AvgRx),
			mb(h.AvgTx),
			mb(h.AvgTotal),
		})
	}

	w.Flush()
	return buf.Bytes()
}

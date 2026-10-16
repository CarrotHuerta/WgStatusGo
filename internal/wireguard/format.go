package wireguard

import (
	"bytes"
	"fmt"
	"net"
	"sort"
	"strings"
)

// HumanBytes matches Python's human_bytes(b) formatting with KiB, MiB, GiB, TiB.
func HumanBytes(b int64) string {
	if b < 1024 {
		return fmt.Sprintf("%d B", b)
	}
	fb := float64(b)
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	for _, unit := range units {
		fb /= 1024.0
		if fb < 1024.0 {
			return fmt.Sprintf("%.2f %s", fb, unit)
		}
	}
	return fmt.Sprintf("%.2f PiB", fb)
}

// FormatRate formats bits per second to human-readable string matching Python.
func FormatRate(bps float64) string {
	if bps < 1000 {
		return fmt.Sprintf("%.0f bps", bps)
	}
	if bps < 1_000_000 {
		return fmt.Sprintf("%.1f Kbps", bps/1000.0)
	}
	if bps < 1_000_000_000 {
		return fmt.Sprintf("%.2f Mbps", bps/1_000_000.0)
	}
	return fmt.Sprintf("%.2f Gbps", bps/1_000_000_000.0)
}

// FormatHandshakeAge formats the seconds since last handshake matching Python.
func FormatHandshakeAge(ageSeconds int64) string {
	if ageSeconds <= 0 {
		return "just now"
	}
	if ageSeconds < 60 {
		return fmt.Sprintf("%ds ago", ageSeconds)
	}
	if ageSeconds < 3600 {
		return fmt.Sprintf("%dm %ds ago", ageSeconds/60, ageSeconds%60)
	}
	return fmt.Sprintf("%dh %dm ago", ageSeconds/3600, (ageSeconds%3600)/60)
}

// ExtractFirstIP returns the first IPv4/IPv6 address from an AllowedIPs CIDR string.
func ExtractFirstIP(allowedIPs string) string {
	parts := strings.Split(allowedIPs, ",")
	if len(parts) > 0 {
		first := strings.TrimSpace(parts[0])
		if idx := strings.Index(first, "/"); idx != -1 {
			return first[:idx]
		}
		return first
	}
	return ""
}

// IPSortKey returns a comparable byte slice for sorting IPs numerically.
func IPSortKey(ipStr string) []byte {
	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		return []byte(ipStr)
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4
	}
	return parsed.To16()
}

// SortPeersByIP sorts peer slice in ascending numerical IP order.
func SortPeersByIP(peers []*Peer) {
	sort.Slice(peers, func(i, j int) bool {
		keyA := IPSortKey(peers[i].IP)
		keyB := IPSortKey(peers[j].IP)
		return bytes.Compare(keyA, keyB) < 0
	})
}

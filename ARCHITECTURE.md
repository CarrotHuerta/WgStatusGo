# WgStatusGo: Technical Specification & Go Architecture

This document details the architecture, code structure, and engineering design used to port **WgStatus v2.5** from Python/Flask to **Go (Golang)** as a high-performance, self-contained single static binary.

---

## 1. Architecture & Migration Goals

1. **Single Self-Contained Binary**:
   - Native static compilation (`CGO_ENABLED=0`).
   - Web assets (HTML, CSS, JS, and vendored Chart.js) embedded directly into the binary using `//go:embed`.
   - Zero external runtime dependencies on the Linux host (no Python interpreter, no virtualenvs, no `pip`, no `gunicorn`).
2. **Extreme Resource Efficiency**:
   - Memory footprint reduced from ~55 MB (Python + Gunicorn workers) to **< 8 MB RAM**.
   - Startup time reduced to **< 5 milliseconds**.
   - Direct WireGuard kernel integration via Generic Netlink (`wgctrl`), eliminating periodic shell subprocess forks (`wg show all dump`).
3. **Native Concurrency & Stability**:
   - Lightweight goroutines and buffered channels for non-blocking ICMP ping workers and asynchronous ISP lookups.
   - Thread-safe state synchronization via `sync.RWMutex` and pre-serialized JSON/Gzip snapshots for O(1) sub-millisecond HTTP responses with zero lock contention.
   - SSD wear protection: periodic background flush ticker with atomic file replacements (`os.Rename`).
4. **Full v2.5 Security Parity**:
   - Subnet CIDR filtering (`net.IPNet`) and trusted reverse proxy hop parsing (`X-Forwarded-For`).
   - Strict Content Security Policy (CSP) without third-party origins or `'unsafe-inline'` scripts.
   - Per-IP sliding-window rate limiting across `global`, `heavy`, and `write` buckets.
   - Exponential `LoginThrottle` per IP + distributed global failure ceiling.
   - In-memory bearer sessions using cryptographically random tokens (`crypto/rand`) stored as SHA-256 digests.
   - Spreadsheet formula injection sanitization (`=`, `+`, `-`, `@`, `\t`, `\r`) for CSV and Excel exports.

---

## 2. Go Ecosystem Libraries

| Python Module | Go Equivalent | Technical Rationale |
|---|---|---|
| `wg show all dump` (subprocess fork) | `golang.zx2c4.com/wireguard/wgctrl` | **Official WireGuard library** (authored by Jason A. Donenfeld). Communicates directly with the Linux kernel via Generic Netlink without spawning child processes. |
| Flask + Gunicorn | `net/http` + `github.com/go-chi/chi/v5` | Ultra-lightweight, 100% `http.Handler`-compatible idiomatic Go router with zero unnecessary heap allocations. |
| `flask-sock` / WebSockets | `github.com/coder/websocket` | Modern, context-aware, high-performance WebSocket implementation for Go. |
| `openpyxl` | `github.com/xuri/excelize/v2` | Industry-standard pure-Go library for generating styled multi-sheet Microsoft Excel (`.xlsx`) workbooks. |
| Low-latency ICMP pings | `internal/ping` (ICMP / system ping) | Concurrent two-sample latency probes triggered exclusively on fresh WireGuard handshakes (`<= 5s`). |
| Jinja templates & static files | `embed` (`//go:embed`) | Bundles `web/templates` and `web/static` directly into the compiled executable binary. |

---

## 3. Go Project Structure

```text
WgStatusGo/
├── cmd/
│   └── wgstatus/
│       └── main.go                 # Entrypoint, CLI flags, HTTP server & OS signal handling (SIGTERM/SIGINT)
├── internal/
│   ├── config/
│   │   └── config.go               # Environment variables & defaults (PORT, HOST, SERVER_PASSWORD, etc.)
│   ├── wireguard/
│   │   ├── client.go               # wgctrl Netlink reader + MockReader fallback for dev/non-Linux
│   │   ├── conf_parser.go          # Read-only wg0.conf parser for peer comment nicknames
│   │   ├── format.go               # Binary byte formatting (KiB/MiB/GiB/TiB), rates & IPv4/IPv6 sorting
│   │   └── models.go               # Peer, Summary, and bandwidth snapshot structs
│   ├── server/
│   │   ├── monitor.go              # 1 Hz background telemetry loop, SSE/WebSocket broadcaster & Gzip cache
│   │   ├── handlers.go             # REST, SSE, WebSocket, Auth & Export HTTP handlers
│   │   └── router.go               # Chi router wiring & middleware stack
│   ├── security/
│   │   ├── middleware.go           # HTTP security middleware (CSP, Host, Origin, CIDR allowlist)
│   │   ├── limiter.go              # Per-IP sliding-window rate limiter
│   │   ├── throttle.go             # Exponential LoginThrottle + global brute-force ceiling
│   │   ├── session.go              # In-memory SessionStore (SHA-256 bearer token digests)
│   │   └── stream.go               # StreamGuard concurrency caps for WebSocket & SSE streams
│   ├── analytics/
│   │   ├── manager.go              # 32-day hourly bucket retention, 24h heatmaps & ISP aggregation
│   │   └── models.go               # HourlyBucket, IspTotal, and analytics payload structs
│   ├── history/
│   │   ├── manager.go              # Persistent monthly peer accounting, session logs & custom aliases
│   │   └── models.go               # ConnectionSession and MonthlyUsage structs
│   ├── isp/
│   │   ├── cache.go                # Thread-safe ISP cache, CSV persistence & async ipinfo.io worker
│   │   └── normalizer.go           # ASN prefix stripping & canonical ISP name normalization
│   ├── ping/
│   │   └── pinger.go               # Battery-safe 2-sample latency measurement on fresh handshakes
│   └── export/
│       ├── csv.go                  # UTF-8 BOM CSV generator with formula injection sanitization
│       └── excel.go                # Styled multi-sheet XLSX audit report generator via excelize
├── web/
│   ├── embed.go                    # //go:embed static/* templates/*
│   ├── templates/                  # index.html
│   └── static/                     # CSS, JS, and vendor/chart.umd.js
├── go.mod
└── go.sum
```

---

## 4. Core Component Design

### 4.1. WireGuard Kernel Telemetry (`internal/wireguard` & `internal/server`)

```go
type DeviceReader interface {
    ReadPeers() ([]RawPeer, error)
    IsMock() bool
    Close() error
}
```
On Linux, `WgctrlReader` opens a Netlink socket via `wgctrl.New()` and queries the WireGuard kernel interface every second (`1 Hz`), computing instantaneous RX/TX bitrates, tracking session boundaries, and pre-compressing the JSON state into RAM so HTTP/SSE/WebSocket consumers read immutable byte slices without locking the collector.

### 4.2. ISP Normalization & Asynchronous Resolution (`internal/isp`)

```go
func CleanISPName(raw string) string {
    val := strings.TrimSpace(raw)
    if val == "" || val == "-" || val == "Unknown" {
        return "Unknown ISP"
    }
    // Strip leading ASN prefix (e.g. "AS7418 TELEFONICA CHILE S.A." -> "TELEFONICA CHILE S.A.")
    parts := strings.SplitN(val, " ", 2)
    if len(parts) == 2 && strings.HasPrefix(strings.ToUpper(parts[0]), "AS") {
        if isDigits(parts[0][2:]) {
            val = strings.TrimSpace(parts[1])
        }
    }
    return val
}
```

### 4.3. Traffic Analytics Engine (`internal/analytics`)

```go
type HourlyBucket struct {
    RX         int64                 `json:"rx"`
    TX         int64                 `json:"tx"`
    PeakRxBps  float64               `json:"peak_rx_bps"`
    PeakTxBps  float64               `json:"peak_tx_bps"`
    Samples    int                   `json:"samples"`
    OnlineSum  int                   `json:"online_sum"`
    OnlinePeak int                   `json:"online_peak"`
    ISPs       map[string]*IspBucket `json:"isps"`
}
```
Maintains up to 768 hourly buckets (32 rolling days) in memory and flushes atomically to `data/analytics_state.json` every 10 minutes or upon receiving `SIGINT`/`SIGTERM`.

### 4.4. Spreadsheet Formula Injection Defense (`internal/export`)

```go
func SanitizeCell(val string) string {
    if val == "" {
        return val
    }
    for _, p := range []string{"=", "+", "@", "\t", "\r"} {
        if strings.HasPrefix(val, p) {
            return "'" + val
        }
    }
    if strings.HasPrefix(val, "-") && len(val) > 1 {
        if _, err := strconv.ParseFloat(val, 64); err != nil {
            return "'" + val
        }
    }
    return val
}
```

---

## 5. Build & Deployment Strategy

### Cross-Compilation (from Windows, macOS, or Linux CI to Linux amd64/arm64)
```bash
# Static binary for Linux x86_64 (zero dynamic C dependencies)
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o wgstatus ./cmd/wgstatus

# Static binary for Raspberry Pi / ARM64 gateways
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -o wgstatus-arm64 ./cmd/wgstatus
```
The resulting ~12 MB executable contains the complete application, HTTP/WebSocket server, WireGuard Netlink collector, Excel report generator, and all embedded HTML/JS/CSS assets.

### Simplified `systemd` Service Unit
```ini
[Unit]
Description=WgStatusGo - WireGuard Status Dashboard (Go)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/wgstatus
ExecStart=/opt/wgstatus/wgstatus
Restart=on-failure
RestartSec=3
EnvironmentFile=-/etc/default/wgstatus

[Install]
WantedBy=multi-user.target
```

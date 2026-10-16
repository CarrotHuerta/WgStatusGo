package analytics

const (
	HourlyRetentionDays = 32
	MaxISPs             = 500
	UnknownISP          = "Unknown ISP"
)

// Ranges maps query range parameter to hours count.
var Ranges = map[string]int{
	"24h": 24,
	"7d":  24 * 7,
	"30d": 24 * 30,
	"all": 24 * 30,
}

// PeerSample represents an instantaneous telemetry measurement of a peer.
type PeerSample struct {
	IP       string
	Rx       int64
	Tx       int64
	ISP      string
	Online   bool
	Endpoint string
}

// IspBucket tracks traffic and connection duration for a specific ISP within an hour.
type IspBucket struct {
	Rx       int64    `json:"rx"`
	Tx       int64    `json:"tx"`
	ActiveS  float64  `json:"active_s"`
	Sessions int      `json:"sessions"`
	Peers    []string `json:"peers"`
}

// HourlyBucket stores 1-hour aggregated traffic metrics.
type HourlyBucket struct {
	Rx         int64                 `json:"rx"`
	Tx         int64                 `json:"tx"`
	PeakRxBps  float64               `json:"peak_rx_bps"`
	PeakTxBps  float64               `json:"peak_tx_bps"`
	Samples    int                   `json:"samples"`
	OnlineSum  int                   `json:"online_sum"`
	OnlinePeak int                   `json:"online_peak"`
	ISPs       map[string]*IspBucket `json:"isps"`
}

// IspTotal tracks all-time cumulative usage for an ISP.
type IspTotal struct {
	Rx        int64    `json:"rx"`
	Tx        int64    `json:"tx"`
	ActiveS   float64  `json:"active_s"`
	Sessions  int      `json:"sessions"`
	Peers     []string `json:"peers"`
	FirstSeen int64    `json:"first_seen"`
	LastSeen  int64    `json:"last_seen"`
}

// AnalyticsState is the on-disk JSON document structure.
type AnalyticsState struct {
	Version   int                      `json:"version"`
	SavedAt   int64                    `json:"saved_at"`
	FirstTS   int64                    `json:"first_ts"`
	Demo      bool                     `json:"demo"`
	Hourly    map[string]*HourlyBucket `json:"hourly"`
	IspTotals map[string]*IspTotal     `json:"isp_totals"`
}

// Report holds the aggregated dashboard report.
type Report struct {
	Range          string               `json:"range"`
	Granularity    string               `json:"granularity"`
	GeneratedAt    int64                `json:"generated_at"`
	Demo           bool                 `json:"demo"`
	DataSince      int64                `json:"data_since"`
	DaysWithData   int                  `json:"days_with_data"`
	Totals         Totals               `json:"totals"`
	PeakHour       *HourLabel           `json:"peak_hour"`
	QuietHour      *HourLabel           `json:"quiet_hour"`
	BusiestHour    *BusiestHour         `json:"busiest_hour"`
	Series         []SeriesPoint        `json:"series"`
	HourOfDay      []HourOfDayPoint     `json:"hour_of_day"`
	HourOfDayByISP []HourOfDayIspSeries `json:"hour_of_day_by_isp"`
	TopISPs        []IspRow             `json:"top_isps"`
}

// Totals contains grand-total metrics for the requested time window.
type Totals struct {
	Rx         int64   `json:"rx"`
	Tx         int64   `json:"tx"`
	Total      int64   `json:"total"`
	RxHuman    string  `json:"rx_human"`
	TxHuman    string  `json:"tx_human"`
	TotalHuman string  `json:"total_human"`
	PeakRxBps  float64 `json:"peak_rx_bps"`
	PeakTxBps  float64 `json:"peak_tx_bps"`
	AvgOnline  float64 `json:"avg_online"`
	PeakOnline int     `json:"peak_online"`
	Networks   int     `json:"networks"`
}

// HourLabel describes a 1-hour interval and its daily average volume.
type HourLabel struct {
	Hour     int    `json:"hour"`
	Label    string `json:"label"`
	AvgHuman string `json:"avg_human"`
}

// BusiestHour describes the single highest volume bucket in the window.
type BusiestHour struct {
	Key        string  `json:"key"`
	TotalHuman string  `json:"total_human"`
	PeakBps    float64 `json:"peak_bps"`
}

// SeriesPoint is a timeline datapoint (per-hour or per-day).
type SeriesPoint struct {
	Key       string  `json:"key"`
	Rx        int64   `json:"rx"`
	Tx        int64   `json:"tx"`
	Total     int64   `json:"total"`
	PeakBps   float64 `json:"peak_bps"`
	AvgOnline float64 `json:"avg_online,omitempty"`
}

// HourOfDayPoint aggregates typical diurnal usage for hour 0..23.
type HourOfDayPoint struct {
	Hour     int   `json:"hour"`
	AvgTotal int64 `json:"avg_total"`
	AvgRx    int64 `json:"avg_rx"`
	AvgTx    int64 `json:"avg_tx"`
}

// HourOfDayIspSeries tracks diurnal profile for a specific top ISP.
type HourOfDayIspSeries struct {
	ISP   string  `json:"isp"`
	Bytes []int64 `json:"bytes"`
}

// IspRow summarizes an ISP's ranking, total volume and market share.
type IspRow struct {
	ISP           string  `json:"isp"`
	Rx            int64   `json:"rx"`
	Tx            int64   `json:"tx"`
	Total         int64   `json:"total"`
	TotalHuman    string  `json:"total_human"`
	RxHuman       string  `json:"rx_human"`
	TxHuman       string  `json:"tx_human"`
	SharePct      float64 `json:"share_pct"`
	Sessions      int     `json:"sessions"`
	Devices       int     `json:"devices"`
	ActiveSeconds int64   `json:"active_seconds"`
	ActiveHuman   string  `json:"active_human"`
	PeakHour      *int    `json:"peak_hour"`
}

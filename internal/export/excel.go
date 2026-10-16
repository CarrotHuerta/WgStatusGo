package export

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/xuri/excelize/v2"

	"wgstatus/internal/analytics"
)

func round1(val float64) float64 {
	return math.Round(val*10) / 10
}

func round2(val float64) float64 {
	return math.Round(val*100) / 100
}

func applyExcelStyling(f *excelize.File, sheet string, headerRow, maxCol, maxRow int) {
	headerStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{
			Family: "Segoe UI",
			Size:   10,
			Bold:   true,
			Color:  "FFFFFF",
		},
		Fill: excelize.Fill{
			Type:    "pattern",
			Color:   []string{"1E293B"},
			Pattern: 1,
		},
		Alignment: &excelize.Alignment{
			Horizontal: "center",
			Vertical:   "center",
			WrapText:   true,
		},
	})

	thinBorder := []excelize.Border{
		{Type: "left", Color: "E2E8F0", Style: 1},
		{Type: "right", Color: "E2E8F0", Style: 1},
		{Type: "top", Color: "E2E8F0", Style: 1},
		{Type: "bottom", Color: "E2E8F0", Style: 1},
	}

	regStyle, _ := f.NewStyle(&excelize.Style{
		Font:   &excelize.Font{Family: "Segoe UI", Size: 9},
		Border: thinBorder,
	})

	zebraStyle, _ := f.NewStyle(&excelize.Style{
		Font:   &excelize.Font{Family: "Segoe UI", Size: 9},
		Border: thinBorder,
		Fill: excelize.Fill{
			Type:    "pattern",
			Color:   []string{"F8FAFC"},
			Pattern: 1,
		},
	})

	onlineStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{
			Family: "Segoe UI",
			Size:   9,
			Bold:   true,
			Color:  "166534",
		},
		Border: thinBorder,
		Fill: excelize.Fill{
			Type:    "pattern",
			Color:   []string{"DCFCE7"},
			Pattern: 1,
		},
		Alignment: &excelize.Alignment{Horizontal: "center"},
	})

	offlineStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{
			Family: "Segoe UI",
			Size:   9,
			Color:  "64748B",
		},
		Border: thinBorder,
		Fill: excelize.Fill{
			Type:    "pattern",
			Color:   []string{"F1F5F9"},
			Pattern: 1,
		},
		Alignment: &excelize.Alignment{Horizontal: "center"},
	})

	// Header row styling
	_ = f.SetRowHeight(sheet, headerRow, 24)
	for col := 1; col <= maxCol; col++ {
		cell, _ := excelize.CoordinatesToCellName(col, headerRow)
		_ = f.SetCellStyle(sheet, cell, cell, headerStyle)
	}

	// Data rows styling
	for row := headerRow + 1; row <= maxRow; row++ {
		_ = f.SetRowHeight(sheet, row, 20)
		isEven := (row % 2 == 0)

		for col := 1; col <= maxCol; col++ {
			cell, _ := excelize.CoordinatesToCellName(col, row)
			val, _ := f.GetCellValue(sheet, cell)

			// Sanitize cell content if formula injection
			if sanitized := SanitizeCell(val); sanitized != val {
				_ = f.SetCellValue(sheet, cell, sanitized)
			}

			if val == "Online" {
				_ = f.SetCellStyle(sheet, cell, cell, onlineStyle)
			} else if val == "Offline" {
				_ = f.SetCellStyle(sheet, cell, cell, offlineStyle)
			} else if isEven {
				_ = f.SetCellStyle(sheet, cell, cell, zebraStyle)
			} else {
				_ = f.SetCellStyle(sheet, cell, cell, regStyle)
			}
		}
	}

	// Auto-fit column widths
	for col := 1; col <= maxCol; col++ {
		maxLen := 0
		colName, _ := excelize.ColumnNumberToName(col)
		for row := headerRow; row <= maxRow; row++ {
			cell, _ := excelize.CoordinatesToCellName(col, row)
			val, _ := f.GetCellValue(sheet, cell)
			if len(val) > maxLen {
				maxLen = len(val)
			}
		}
		w := math.Min(40, math.Max(float64(maxLen+4), 11))
		_ = f.SetColWidth(sheet, colName, colName, w)
	}
}

// GeneratePeersXLSX creates a styled Excel workbook of current peers.
func GeneratePeersXLSX(peers []map[string]interface{}, summary map[string]interface{}) ([]byte, error) {
	f := excelize.NewFile()
	sheet := "WireGuard Peers"
	_ = f.SetSheetName("Sheet1", sheet)

	headers := []interface{}{
		"Device Name",
		"IP Address",
		"Status",
		"Latency (ms)",
		"Latest Handshake",
		"Endpoint",
		"ISP / Network",
		"Monthly Total",
		"Monthly Download",
		"Monthly Upload",
		"Session Usage",
		"Down Rate",
		"Up Rate",
		"Connected Since Boot",
		"Public Key",
	}

	for col, h := range headers {
		cell, _ := excelize.CoordinatesToCellName(col+1, 1)
		_ = f.SetCellValue(sheet, cell, h)
	}

	rowIdx := 2
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

		pingVal := interface{}("-")
		if pMS, ok := p["ping_ms"].(float64); ok {
			pingVal = round1(pMS)
		}

		sinceBoot := "No"
		if boot, ok := p["connected_since_restart"].(bool); ok && boot {
			sinceBoot = "Yes"
		}

		vals := []interface{}{
			name,
			p["ip"],
			status,
			pingVal,
			p["latest_handshake_human"],
			p["endpoint_ip"],
			p["isp"],
			p["monthly_usage"],
			p["monthly_rx_human"],
			p["monthly_tx_human"],
			p["data_usage"],
			p["rx_rate_human"],
			p["tx_rate_human"],
			sinceBoot,
			p["public_key"],
		}

		for col, v := range vals {
			cell, _ := excelize.CoordinatesToCellName(col+1, rowIdx)
			_ = f.SetCellValue(sheet, cell, v)
		}
		rowIdx++
	}

	applyExcelStyling(f, sheet, 1, len(headers), rowIdx-1)

	buf, err := f.WriteToBuffer()
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// GenerateSessionsXLSX creates an Excel workbook of connection sessions.
func GenerateSessionsXLSX(sessions []map[string]interface{}, peerIP, deviceName string) ([]byte, error) {
	f := excelize.NewFile()
	sheet := "Sessions"
	_ = f.SetSheetName("Sheet1", sheet)

	headers := []interface{}{
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
	}

	for col, h := range headers {
		cell, _ := excelize.CoordinatesToCellName(col+1, 1)
		_ = f.SetCellValue(sheet, cell, h)
	}

	rowIdx := 2
	for _, s := range sessions {
		sIP, _ := s["peer_ip"].(string)
		if sIP == "" {
			sIP = peerIP
		}

		pingVal := interface{}("-")
		if pMS, ok := s["ping_ms"].(float64); ok {
			pingVal = round1(pMS)
		}

		samplesStr := "-"
		if samples, ok := s["ping_samples"].([]interface{}); ok && len(samples) > 0 {
			var parts []string
			for _, sm := range samples {
				parts = append(parts, fmt.Sprintf("%vms", sm))
			}
			samplesStr = strings.Join(parts, " -> ")
		}

		vals := []interface{}{
			sIP,
			s["started_at_human"],
			s["last_active_human"],
			s["duration_human"],
			s["endpoint_ip"],
			s["isp"],
			pingVal,
			samplesStr,
			s["rx_human"],
			s["tx_human"],
			s["total_human"],
		}

		for col, v := range vals {
			cell, _ := excelize.CoordinatesToCellName(col+1, rowIdx)
			_ = f.SetCellValue(sheet, cell, v)
		}
		rowIdx++
	}

	applyExcelStyling(f, sheet, 1, len(headers), rowIdx-1)

	buf, err := f.WriteToBuffer()
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// GenerateFullReportXLSX generates a multi-sheet audit report.
func GenerateFullReportXLSX(
	peers []map[string]interface{},
	summary map[string]interface{},
	allSessions []map[string]interface{},
	analyticsReports []*analytics.Report,
) ([]byte, error) {
	f := excelize.NewFile()

	// Sheet 1: Peers Overview
	sheetPeers := "Peers Overview"
	_ = f.SetSheetName("Sheet1", sheetPeers)

	headersPeers := []interface{}{
		"Device Name", "IP Address", "Status", "Latency (ms)", "Latest Handshake",
		"Endpoint", "ISP / Network", "Monthly Total", "Monthly Download", "Monthly Upload",
		"Session Usage", "Down Rate", "Up Rate", "Connected Since Boot", "Public Key",
	}
	for col, h := range headersPeers {
		cell, _ := excelize.CoordinatesToCellName(col+1, 1)
		_ = f.SetCellValue(sheetPeers, cell, h)
	}

	rowIdx := 2
	for _, p := range peers {
		name, _ := p["name"].(string)
		if name == "" {
			name, _ = p["conf_name"].(string)
		}
		status := "Offline"
		if online, ok := p["online_status"].(bool); ok && online {
			status = "Online"
		}
		pingVal := interface{}("-")
		if pMS, ok := p["ping_ms"].(float64); ok {
			pingVal = round1(pMS)
		}
		sinceBoot := "No"
		if boot, ok := p["connected_since_restart"].(bool); ok && boot {
			sinceBoot = "Yes"
		}

		vals := []interface{}{
			name, p["ip"], status, pingVal, p["latest_handshake_human"],
			p["endpoint_ip"], p["isp"], p["monthly_usage"], p["monthly_rx_human"],
			p["monthly_tx_human"], p["data_usage"], p["rx_rate_human"], p["tx_rate_human"],
			sinceBoot, p["public_key"],
		}
		for col, v := range vals {
			cell, _ := excelize.CoordinatesToCellName(col+1, rowIdx)
			_ = f.SetCellValue(sheetPeers, cell, v)
		}
		rowIdx++
	}
	applyExcelStyling(f, sheetPeers, 1, len(headersPeers), rowIdx-1)

	// Sheet 2: Connection Sessions
	sheetSess := "Connection Sessions"
	_, _ = f.NewSheet(sheetSess)
	headersSess := []interface{}{
		"Peer IP", "Session Started", "Last Active", "Duration", "Endpoint IP",
		"ISP / Network", "Ping (ms)", "Ping Samples", "Downloaded", "Uploaded", "Total Transferred",
	}
	for col, h := range headersSess {
		cell, _ := excelize.CoordinatesToCellName(col+1, 1)
		_ = f.SetCellValue(sheetSess, cell, h)
	}
	rowIdx = 2
	for _, s := range allSessions {
		pingVal := interface{}("-")
		if pMS, ok := s["ping_ms"].(float64); ok {
			pingVal = round1(pMS)
		}
		samplesStr := "-"
		if samples, ok := s["ping_samples"].([]interface{}); ok && len(samples) > 0 {
			var parts []string
			for _, sm := range samples {
				parts = append(parts, fmt.Sprintf("%vms", sm))
			}
			samplesStr = strings.Join(parts, " -> ")
		}
		vals := []interface{}{
			s["peer_ip"], s["started_at_human"], s["last_active_human"], s["duration_human"],
			s["endpoint_ip"], s["isp"], pingVal, samplesStr, s["rx_human"], s["tx_human"], s["total_human"],
		}
		for col, v := range vals {
			cell, _ := excelize.CoordinatesToCellName(col+1, rowIdx)
			_ = f.SetCellValue(sheetSess, cell, v)
		}
		rowIdx++
	}
	applyExcelStyling(f, sheetSess, 1, len(headersSess), rowIdx-1)

	// Sheet 3: Server Summary & Audit
	sheetSum := "Audit & Summary"
	_, _ = f.NewSheet(sheetSum)
	_ = f.SetCellValue(sheetSum, "A1", "Metric")
	_ = f.SetCellValue(sheetSum, "B1", "Value")

	metrics := [][]interface{}{
		{"Report Generated At", time.Now().Format("2006-01-02 15:04:05")},
		{"Month Period", summary["current_month"]},
		{"Total Configured Peers", summary["total_peers"]},
		{"Online Peers", summary["online_peers"]},
		{"Offline Peers", summary["offline_peers"]},
		{"Connected Since Server Boot", summary["connected_since_restart"]},
		{"Total Transferred This Month", summary["total_usage_human"]},
		{"Current Aggregate Down Rate", summary["total_rx_rate_human"]},
		{"Current Aggregate Up Rate", summary["total_tx_rate_human"]},
	}
	for i, m := range metrics {
		cellA, _ := excelize.CoordinatesToCellName(1, i+2)
		cellB, _ := excelize.CoordinatesToCellName(2, i+2)
		_ = f.SetCellValue(sheetSum, cellA, m[0])
		_ = f.SetCellValue(sheetSum, cellB, m[1])
	}
	applyExcelStyling(f, sheetSum, 1, 2, len(metrics)+1)

	// Analytics sheets
	for _, report := range analyticsReports {
		if report != nil {
			addAnalyticsSheets(f, report, report.Range != "all")
		}
	}

	buf, err := f.WriteToBuffer()
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func addAnalyticsSheets(f *excelize.File, report *analytics.Report, includeTraffic bool) {
	tag := report.Range
	if tag == "all" {
		tag = "all-time"
	}

	// 1. ISP Ranking sheet
	titleISP := fmt.Sprintf("ISP Ranking (%s)", tag)
	if len(titleISP) > 31 {
		titleISP = titleISP[:31]
	}
	_, _ = f.NewSheet(titleISP)

	headersISP := []interface{}{"#", "ISP / Network", "Download (MB)", "Upload (MB)", "Total (MB)", "Share (%)", "Sessions", "Devices", "Connected time", "Peak hour"}
	for col, h := range headersISP {
		cell, _ := excelize.CoordinatesToCellName(col+1, 1)
		_ = f.SetCellValue(titleISP, cell, h)
	}
	for i, r := range report.TopISPs {
		row := i + 2
		vals := []interface{}{
			i + 1, r.ISP, round2(float64(r.Rx) / 1_000_000.0), round2(float64(r.Tx) / 1_000_000.0),
			round2(float64(r.Total) / 1_000_000.0), r.SharePct, r.Sessions, r.Devices,
			r.ActiveHuman, hourRange(r.PeakHour),
		}
		for col, v := range vals {
			cell, _ := excelize.CoordinatesToCellName(col+1, row)
			_ = f.SetCellValue(titleISP, cell, v)
		}
	}
	applyExcelStyling(f, titleISP, 1, len(headersISP), len(report.TopISPs)+1)

	if includeTraffic {
		// 2. Traffic series sheet
		timeCol := "Hour"
		titleTraffic := fmt.Sprintf("Hourly Traffic (%s)", tag)
		if report.Granularity == "day" {
			timeCol = "Day"
			titleTraffic = fmt.Sprintf("Daily Traffic (%s)", tag)
		}
		if len(titleTraffic) > 31 {
			titleTraffic = titleTraffic[:31]
		}
		_, _ = f.NewSheet(titleTraffic)

		headersTraffic := []interface{}{timeCol, "Download (MB)", "Upload (MB)", "Total (MB)", "Peak rate (Mbps)", "Avg online peers"}
		for col, h := range headersTraffic {
			cell, _ := excelize.CoordinatesToCellName(col+1, 1)
			_ = f.SetCellValue(titleTraffic, cell, h)
		}
		for i, pt := range report.Series {
			row := i + 2
			vals := []interface{}{
				pt.Key, round2(float64(pt.Rx) / 1_000_000.0), round2(float64(pt.Tx) / 1_000_000.0),
				round2(float64(pt.Total) / 1_000_000.0), round2(pt.PeakBps / 1_000_000.0), pt.AvgOnline,
			}
			for col, v := range vals {
				cell, _ := excelize.CoordinatesToCellName(col+1, row)
				_ = f.SetCellValue(titleTraffic, cell, v)
			}
		}
		applyExcelStyling(f, titleTraffic, 1, len(headersTraffic), len(report.Series)+1)

		// 3. Hour of Day sheet
		titleHOD := fmt.Sprintf("Hour of Day (%s)", tag)
		if len(titleHOD) > 31 {
			titleHOD = titleHOD[:31]
		}
		_, _ = f.NewSheet(titleHOD)

		headersHOD := []interface{}{"Hour of day", "Avg download / day (MB)", "Avg upload / day (MB)", "Avg total / day (MB)"}
		for col, h := range headersHOD {
			cell, _ := excelize.CoordinatesToCellName(col+1, 1)
			_ = f.SetCellValue(titleHOD, cell, h)
		}
		for i, h := range report.HourOfDay {
			row := i + 2
			hr := h.Hour
			vals := []interface{}{
				hourRange(&hr), round2(float64(h.AvgRx) / 1_000_000.0),
				round2(float64(h.AvgTx) / 1_000_000.0), round2(float64(h.AvgTotal) / 1_000_000.0),
			}
			for col, v := range vals {
				cell, _ := excelize.CoordinatesToCellName(col+1, row)
				_ = f.SetCellValue(titleHOD, cell, v)
			}
		}
		applyExcelStyling(f, titleHOD, 1, len(headersHOD), len(report.HourOfDay)+1)
	}
}

// GenerateAnalyticsXLSX creates an Excel workbook specifically for analytics.
func GenerateAnalyticsXLSX(report *analytics.Report) ([]byte, error) {
	f := excelize.NewFile()
	addAnalyticsSheets(f, report, true)
	_ = f.DeleteSheet("Sheet1")

	buf, err := f.WriteToBuffer()
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

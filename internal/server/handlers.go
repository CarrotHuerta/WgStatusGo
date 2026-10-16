package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"

	"wgstatus/internal/analytics"
	"wgstatus/internal/export"
	"wgstatus/internal/history"
	"wgstatus/internal/security"
	"wgstatus/internal/wireguard"
	"wgstatus/web"
)

var controlCharsRegex = regexp.MustCompile(`[\x00-\x1f\x7f-\x9f\x{200b}-\x{200f}\x{202a}-\x{202e}\x{2066}-\x{2069}]`)

func parsePeerIP(raw string) string {
	text := strings.TrimSpace(raw)
	if text == "" || len(text) > 45 {
		return ""
	}
	parsed := net.ParseIP(text)
	if parsed == nil {
		return ""
	}
	return parsed.String()
}

func sanitizeAlias(raw string) string {
	cleaned := controlCharsRegex.ReplaceAllString(raw, "")
	fields := strings.Fields(cleaned)
	joined := strings.Join(fields, " ")
	if len(joined) > 48 {
		return joined[:48]
	}
	return joined
}

func fastResponse(w http.ResponseWriter, r *http.Request, rawJSON, rawGz []byte, fallback interface{}) {
	if rawJSON != nil {
		accept := strings.ToLower(r.Header.Get("Accept-Encoding"))
		if strings.Contains(accept, "gzip") && rawGz != nil {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Length", strconv.Itoa(len(rawGz)))
			w.Header().Set("Cache-Control", "no-cache, must-revalidate")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(rawGz)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache, must-revalidate")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(rawJSON)
		return
	}
	security.WriteJSON(w, http.StatusOK, fallback)
}

type Server struct {
	monitor      *WireGuardMonitor
	historyMgr   *history.HistoryManager
	analyticsMgr *analytics.AnalyticsManager
	sec          *security.Security
}

func NewServer(
	monitor *WireGuardMonitor,
	historyMgr *history.HistoryManager,
	analyticsMgr *analytics.AnalyticsManager,
	sec *security.Security,
) *Server {
	return &Server{
		monitor:      monitor,
		historyMgr:   historyMgr,
		analyticsMgr: analyticsMgr,
		sec:          sec,
	}
}

func (s *Server) HandleIndex(w http.ResponseWriter, r *http.Request) {
	htmlBytes, err := web.ReadIndexHTML()
	if err != nil {
		http.Error(w, "Failed to load index template", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(htmlBytes)
}

func (s *Server) HandleStatus(w http.ResponseWriter, r *http.Request) {
	rawJSON, rawGz, fallback := s.monitor.GetStatus()
	fastResponse(w, r, rawJSON, rawGz, fallback)
}

func (s *Server) HandleSummary(w http.ResponseWriter, r *http.Request) {
	rawJSON, rawGz, fallback := s.monitor.GetSummary()
	fastResponse(w, r, rawJSON, rawGz, fallback)
}

func (s *Server) HandleLive(w http.ResponseWriter, r *http.Request) {
	rawJSON, rawGz, fallback := s.monitor.GetLive()
	fastResponse(w, r, rawJSON, rawGz, fallback)
}

func (s *Server) HandleBandwidth(w http.ResponseWriter, r *http.Request) {
	security.WriteJSON(w, http.StatusOK, s.monitor.GetBandwidthSnapshot())
}

func (s *Server) HandleBandwidthTotal(w http.ResponseWriter, r *http.Request) {
	security.WriteJSON(w, http.StatusOK, s.monitor.GetTotalBandwidthHistory())
}

func (s *Server) HandleBandwidthHistory(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimSpace(r.URL.Query().Get("ip"))
	if raw == "" || strings.EqualFold(raw, "total") || strings.EqualFold(raw, "__total__") {
		security.WriteJSON(w, http.StatusOK, s.monitor.GetTotalBandwidthHistory())
		return
	}
	ip := parsePeerIP(raw)
	if ip == "" {
		security.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid IP parameter"})
		return
	}
	security.WriteJSON(w, http.StatusOK, s.monitor.GetPeerHistory(ip))
}

func (s *Server) HandlePeerHistory(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimSpace(r.URL.Query().Get("ip"))
	if raw == "" {
		security.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "Missing IP parameter"})
		return
	}
	ip := parsePeerIP(raw)
	if ip == "" {
		security.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid IP parameter"})
		return
	}

	payload := s.historyMgr.GetPeerHistoryPayload(ip)
	mRx, _ := payload["monthly_rx"].(int64)
	mTx, _ := payload["monthly_tx"].(int64)
	tot := mRx + mTx
	payload["monthly_total_bytes"] = tot
	payload["monthly_total_human"] = wireguard.HumanBytes(tot)
	payload["monthly_rx_human"] = wireguard.HumanBytes(mRx)
	payload["monthly_tx_human"] = wireguard.HumanBytes(mTx)

	security.WriteJSON(w, http.StatusOK, payload)
}

func (s *Server) HandleAlias(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP    string `json:"ip"`
		Alias string `json:"alias"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		security.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON body"})
		return
	}

	ip := parsePeerIP(body.IP)
	if ip == "" {
		security.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid IP parameter"})
		return
	}

	if !s.monitor.HasPeer(ip) {
		security.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "Unknown peer"})
		return
	}

	cleanAlias := sanitizeAlias(body.Alias)
	savedAlias := s.historyMgr.SetAlias(ip, cleanAlias)
	s.monitor.UpdatePeerAliasInCache(ip, savedAlias)

	security.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"status": "ok",
		"ip":     ip,
		"alias":  savedAlias,
	})
}

func (s *Server) HandleFlush(w http.ResponseWriter, r *http.Request) {
	s.historyMgr.Flush(true)
	s.analyticsMgr.Flush(true)
	security.WriteJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"message": "State flushed to SSD",
	})
}

func (s *Server) HandleAnalytics(w http.ResponseWriter, r *http.Request) {
	rangeKey := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("range")))
	if rangeKey == "" {
		rangeKey = "7d"
	}
	if _, ok := analytics.Ranges[rangeKey]; !ok {
		security.WriteJSON(w, http.StatusBadRequest, map[string]string{
			"error": "Invalid range. Use one of: 24h, 7d, 30d, all",
		})
		return
	}
	security.WriteJSON(w, http.StatusOK, s.analyticsMgr.GetReport(rangeKey))
}

func (s *Server) HandleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	clientIP := s.sec.ClientIP(r)
	token, status, errorMsg := s.sec.Login(clientIP, strings.TrimSpace(body.Password))
	if token == "" {
		if status == http.StatusTooManyRequests {
			retry := s.sec.LoginThrottle.Check(clientIP)
			if retry <= 0 {
				retry = 60
			}
			w.Header().Set("Retry-After", strconv.Itoa(retry))
		}
		security.WriteJSON(w, status, map[string]string{"error": errorMsg})
		return
	}

	s.sec.SetSessionCookie(w, r, token)
	security.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"status":     "ok",
		"expires_in": int(s.sec.Sessions.TTL().Seconds()),
	})
}

func (s *Server) HandleAuthStatus(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(security.SessionCookie)
	authenticated := err == nil && cookie != nil && s.sec.Sessions.Validate(cookie.Value)

	security.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"authenticated":  authenticated,
		"protect_writes": s.sec.Cfg.ProtectWrites,
	})
}

func (s *Server) HandleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(security.SessionCookie)
	if err == nil && cookie != nil {
		s.sec.Sessions.Revoke(cookie.Value)
	}
	s.sec.ClearSessionCookie(w)
	security.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) HandleExportPeers(w http.ResponseWriter, r *http.Request) {
	fmtChoice := strings.ToLower(r.URL.Query().Get("format"))
	_, _, peers := s.monitor.GetStatus()
	_, _, summary := s.monitor.GetSummary()

	var peerMaps []map[string]interface{}
	for _, p := range peers {
		peerMaps = append(peerMaps, p.ToMap())
	}
	sumMap := summary.ToMap()
	tsStr := time.Now().Format("20060102_150405")

	if fmtChoice == "xlsx" || fmtChoice == "excel" {
		xlsxBytes, err := export.GeneratePeersXLSX(peerMaps, sumMap)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		filename := fmt.Sprintf("wireguard_peers_%s.xlsx", tsStr)
		w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
		_, _ = w.Write(xlsxBytes)
		return
	}

	csvBytes := export.GeneratePeersCSV(peerMaps, sumMap)
	filename := fmt.Sprintf("wireguard_peers_%s.csv", tsStr)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	_, _ = w.Write(csvBytes)
}

func (s *Server) HandleExportSessions(w http.ResponseWriter, r *http.Request) {
	fmtChoice := strings.ToLower(r.URL.Query().Get("format"))
	rawIP := strings.TrimSpace(r.URL.Query().Get("ip"))
	ip := ""
	if rawIP != "" {
		ip = parsePeerIP(rawIP)
		if ip == "" {
			security.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid IP parameter"})
			return
		}
	}

	tsStr := time.Now().Format("20060102_150405")
	var sessions []map[string]interface{}
	deviceName := "All Devices"

	if ip != "" {
		payload := s.historyMgr.GetPeerHistoryPayload(ip)
		if rawSess, ok := payload["sessions"].([]map[string]interface{}); ok {
			sessions = rawSess
		}
		if alias, ok := payload["alias"].(string); ok && alias != "" {
			deviceName = alias
		} else {
			deviceName = ip
		}
	} else {
		sessions = s.historyMgr.GetAllSessions()
	}

	ipTag := ip
	if ipTag == "" {
		ipTag = "all"
	}

	if fmtChoice == "xlsx" || fmtChoice == "excel" {
		xlsxBytes, err := export.GenerateSessionsXLSX(sessions, ip, deviceName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		filename := fmt.Sprintf("wireguard_sessions_%s_%s.xlsx", ipTag, tsStr)
		w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
		_, _ = w.Write(xlsxBytes)
		return
	}

	csvBytes := export.GenerateSessionsCSV(sessions, ip, deviceName)
	filename := fmt.Sprintf("wireguard_sessions_%s_%s.csv", ipTag, tsStr)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	_, _ = w.Write(csvBytes)
}

func (s *Server) HandleExportReport(w http.ResponseWriter, r *http.Request) {
	fmtChoice := strings.ToLower(r.URL.Query().Get("format"))
	_, _, peers := s.monitor.GetStatus()
	_, _, summary := s.monitor.GetSummary()

	var peerMaps []map[string]interface{}
	for _, p := range peers {
		peerMaps = append(peerMaps, p.ToMap())
	}
	sumMap := summary.ToMap()
	allSessions := s.historyMgr.GetAllSessions()
	tsStr := time.Now().Format("20060102_150405")

	if fmtChoice != "csv" {
		analyticsReports := []*analytics.Report{
			s.analyticsMgr.GetReport("7d"),
			s.analyticsMgr.GetReport("all"),
		}
		xlsxBytes, err := export.GenerateFullReportXLSX(peerMaps, sumMap, allSessions, analyticsReports)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		filename := fmt.Sprintf("wireguard_full_report_%s.xlsx", tsStr)
		w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
		_, _ = w.Write(xlsxBytes)
		return
	}

	csvBytes := export.GeneratePeersCSV(peerMaps, sumMap)
	filename := fmt.Sprintf("wireguard_full_report_%s.csv", tsStr)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	_, _ = w.Write(csvBytes)
}

func (s *Server) HandleExportAnalytics(w http.ResponseWriter, r *http.Request) {
	rangeKey := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("range")))
	if rangeKey == "" {
		rangeKey = "7d"
	}
	if _, ok := analytics.Ranges[rangeKey]; !ok {
		security.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid range"})
		return
	}

	fmtChoice := strings.ToLower(r.URL.Query().Get("format"))
	report := s.analyticsMgr.GetReport(rangeKey)
	tsStr := time.Now().Format("20060102_150405")

	if fmtChoice == "xlsx" || fmtChoice == "excel" {
		xlsxBytes, err := export.GenerateAnalyticsXLSX(report)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		filename := fmt.Sprintf("wireguard_analytics_%s_%s.xlsx", rangeKey, tsStr)
		w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
		_, _ = w.Write(xlsxBytes)
		return
	}

	csvBytes := export.GenerateAnalyticsCSV(report)
	filename := fmt.Sprintf("wireguard_analytics_%s_%s.csv", rangeKey, tsStr)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	_, _ = w.Write(csvBytes)
}

func (s *Server) HandleHealth(w http.ResponseWriter, r *http.Request) {
	security.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"status": "ok",
		"time":   float64(time.Now().UnixNano()) / 1e9,
	})
}

// HandleSSE manages Server-Sent Events push stream.
func (s *Server) HandleSSE(w http.ResponseWriter, r *http.Request) {
	clientIP := s.sec.ClientIP(r)
	if !s.sec.Streams.Acquire(clientIP) {
		security.TooMany(w, 5, "Too many concurrent streams")
		return
	}
	defer s.sec.Streams.Release(clientIP)

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")

	// Send initial state immediately
	if initJSON := s.monitor.GetCachedLiveJSON(); len(initJSON) > 0 {
		_, _ = fmt.Fprintf(w, "data: %s\n\n", initJSON)
		flusher.Flush()
	}

	ch := s.monitor.SubscribeSSE()
	defer s.monitor.UnsubscribeSSE(ch)

	keepAliveTicker := time.NewTicker(25 * time.Second)
	defer keepAliveTicker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case data := <-ch:
			_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-keepAliveTicker.C:
			_, _ = fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

// HandleWebSocket manages real-time bidirectional WebSocket connection.
func (s *Server) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	clientIP := s.sec.ClientIP(r)
	if !s.sec.Streams.Acquire(clientIP) {
		http.Error(w, "Too many concurrent streams", http.StatusTooManyRequests)
		return
	}
	defer s.sec.Streams.Release(clientIP)

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // Origin is checked by Security middleware
	})
	if err != nil {
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	s.monitor.RegisterWS(conn)
	defer s.monitor.UnregisterWS(conn)

	// Send initial live payload
	if initJSON := s.monitor.GetCachedLiveJSON(); len(initJSON) > 0 {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		_ = conn.Write(ctx, websocket.MessageText, initJSON)
		cancel()
	}

	for {
		msgType, msg, err := conn.Read(r.Context())
		if err != nil {
			break
		}
		if msgType == websocket.MessageText && string(msg) == "ping" {
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			_ = conn.Write(ctx, websocket.MessageText, []byte("pong"))
			cancel()
		}
	}
}

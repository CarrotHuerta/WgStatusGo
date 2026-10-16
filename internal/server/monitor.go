package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/coder/websocket"

	"wgstatus/internal/analytics"
	"wgstatus/internal/history"
	"wgstatus/internal/isp"
	"wgstatus/internal/ping"
	"wgstatus/internal/wireguard"
)

type peerRate struct {
	rxBytes   int64
	txBytes   int64
	timestamp time.Time
	rxRateBps float64
	txRateBps float64
}

type bandwidthPoint struct {
	label     string
	rxRateBps float64
	txRateBps float64
}

// WireGuardMonitor polls WireGuard stats, computes bandwidth rates, updates analytics/history, and broadcasts live.
type WireGuardMonitor struct {
	reader        wireguard.DeviceReader
	ispCache      *isp.IspCache
	historyMgr    *history.HistoryManager
	analyticsMgr  *analytics.AnalyticsManager
	pinger        *ping.Pinger
	pollInterval  time.Duration
	historyPoints int
	mockMode      bool
	confFilePath  string

	mu                    sync.RWMutex
	confNamesPub          map[string]string
	confNamesIP           map[string]string
	lastConfReload        time.Time
	previousCounters      map[string]peerRate
	historyMap            map[string][]bandwidthPoint
	totalHistory          []bandwidthPoint
	lastPeers             []*wireguard.Peer
	lastSummary           *wireguard.Summary
	lastBandwidthSnapshot map[string]map[string]interface{}

	cachedStatusJSON []byte
	cachedStatusGzip []byte
	cachedSummaryJSON []byte
	cachedSummaryGzip []byte
	cachedLiveJSON   []byte
	cachedLiveGzip   []byte

	lastPingedHandshake map[string]int64
	lastPingDispatched  map[string]float64
	lastKnownEndpoint   map[string]string
	lastKnownISP        map[string]string

	sseMu       sync.Mutex
	sseChannels map[chan []byte]bool

	wsMu      sync.Mutex
	wsClients map[*websocket.Conn]bool
}

// NewWireGuardMonitor creates an initialized WireGuardMonitor.
func NewWireGuardMonitor(
	reader wireguard.DeviceReader,
	ispCache *isp.IspCache,
	historyMgr *history.HistoryManager,
	analyticsMgr *analytics.AnalyticsManager,
	pinger *ping.Pinger,
	pollInterval time.Duration,
	historyPoints int,
	confFilePath string,
) *WireGuardMonitor {
	if historyPoints <= 0 {
		historyPoints = 120
	}

	pubMap, ipMap := wireguard.ParseWgConfPeerNames(confFilePath)

	return &WireGuardMonitor{
		reader:                reader,
		ispCache:              ispCache,
		historyMgr:            historyMgr,
		analyticsMgr:          analyticsMgr,
		pinger:                pinger,
		pollInterval:          pollInterval,
		historyPoints:         historyPoints,
		mockMode:              reader.IsMock(),
		confFilePath:          confFilePath,
		confNamesPub:          pubMap,
		confNamesIP:           ipMap,
		lastConfReload:        time.Now(),
		previousCounters:      make(map[string]peerRate),
		historyMap:            make(map[string][]bandwidthPoint),
		lastBandwidthSnapshot: make(map[string]map[string]interface{}),
		lastPingedHandshake:   make(map[string]int64),
		lastPingDispatched:    make(map[string]float64),
		lastKnownEndpoint:     make(map[string]string),
		lastKnownISP:          make(map[string]string),
		sseChannels:           make(map[chan []byte]bool),
		wsClients:             make(map[*websocket.Conn]bool),
	}
}

// Start launches the monitor background loop.
func (m *WireGuardMonitor) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(m.pollInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				if time.Since(m.lastConfReload) > 60*time.Second {
					pubMap, ipMap := wireguard.ParseWgConfPeerNames(m.confFilePath)
					if len(pubMap) > 0 || len(ipMap) > 0 {
						m.mu.Lock()
						m.confNamesPub = pubMap
						m.confNamesIP = ipMap
						m.mu.Unlock()
					}
					m.lastConfReload = time.Now()
				}

				rawPeers, err := m.reader.ReadPeers()
				if err != nil {
					log.Printf("[WireGuardMonitor] Read error: %v", err)
					continue
				}
				m.processPeers(rawPeers, now)
			}
		}
	}()
}

func (m *WireGuardMonitor) processPeers(rawList []wireguard.RawPeer, now time.Time) {
	nowUnix := now.Unix()
	timeLabel := now.Format("15:04:05")

	var peers []*wireguard.Peer
	for _, raw := range rawList {
		ip := wireguard.ExtractFirstIP(raw.AllowedIPs)
		if ip == "" {
			continue
		}

		epIP := raw.Endpoint
		if idx := epIP; idx != "" && idx != "(none)" {
			if colonIdx := bytes.IndexByte([]byte(epIP), ':'); colonIdx != -1 {
				epIP = epIP[:colonIdx]
			}
		} else {
			epIP = "-"
		}

		pubShort := raw.PublicKey
		if len(pubShort) > 10 {
			pubShort = fmt.Sprintf("%s...%s", pubShort[:6], pubShort[len(pubShort)-4:])
		}

		confName := m.confNamesPub[raw.PublicKey]
		if confName == "" {
			confName = m.confNamesIP[ip]
		}
		if confName == "" && m.mockMode {
			confName = mockDeviceName(ip)
		}

		peers = append(peers, &wireguard.Peer{
			IP:              ip,
			Interface:       "wg0",
			PublicKey:       raw.PublicKey,
			PublicKeyShort:  pubShort,
			EndpointIP:      epIP,
			AllowedIPs:      []string{raw.AllowedIPs},
			LatestHandshake: raw.LatestHandshake.Unix(),
			RxBytes:         raw.ReceiveBytes,
			TxBytes:         raw.TransmitBytes,
			ConfName:        confName,
		})
	}

	wireguard.SortPeersByIP(peers)

	// Feed persistent monthly accounting in RAM
	m.historyMgr.UpdatePeers(peers, now)

	var processed []*wireguard.Peer
	bwSnapshot := make(map[string]map[string]interface{})
	var totalRx, totalTx int64
	var totalRxRate, totalTxRate float64
	var onlineCount, sinceRestartCount int
	var analyticsSamples []analytics.PeerSample

	m.mu.Lock()

	for _, p := range peers {
		peerIP := p.IP
		isOnline := p.IsOnline(now, wireguard.DefaultOnlineThreshold)
		if isOnline {
			onlineCount++
		}

		endpoint := p.EndpointIP
		ispName := m.ispCache.Get(endpoint)
		if ispName != "-" && ispName != "Resolving..." && ispName != "Unknown ISP" {
			m.historyMgr.UpdateSessionISP(peerIP, endpoint, ispName)
		}

		analyticsSamples = append(analyticsSamples, analytics.PeerSample{
			IP:       peerIP,
			Rx:       p.RxBytes,
			Tx:       p.TxBytes,
			ISP:      ispName,
			Online:   isOnline,
			Endpoint: endpoint,
		})

		// Battery-safe Ping Trigger: Handshake renewal, Endpoint IP change, ISP change, or initial connection baseline
		if peerIP != "" && isOnline {
			hsAge := float64(nowUnix - p.LatestHandshake)
			if p.LatestHandshake <= 0 {
				hsAge = 999999
			}
			lastHSPinged := m.lastPingedHandshake[peerIP]
			freshHS := (p.LatestHandshake > lastHSPinged) && (hsAge <= 5.0)

			prevEP := m.lastKnownEndpoint[peerIP]
			epChanged := endpoint != "-" && endpoint != "(none)" && prevEP != "" && prevEP != "-" && prevEP != "(none)" && endpoint != prevEP

			prevISP := m.lastKnownISP[peerIP]
			validISP := ispName != "-" && ispName != "Resolving..." && ispName != "Unknown ISP"
			ispChanged := validISP && prevISP != "" && prevISP != "-" && prevISP != "Resolving..." && prevISP != "Unknown ISP" && ispName != prevISP

			shouldPing := false
			reason := ""
			if freshHS {
				shouldPing = true
				reason = fmt.Sprintf("Fresh handshake (%.0fs ago)", hsAge)
			} else if epChanged {
				shouldPing = true
				reason = fmt.Sprintf("Endpoint IP changed (%s -> %s)", prevEP, endpoint)
			} else if ispChanged {
				shouldPing = true
				reason = fmt.Sprintf("ISP changed (%s -> %s)", prevISP, ispName)
			} else if (prevEP == "" || prevEP == "-") && endpoint != "-" && endpoint != "(none)" && m.lastPingedHandshake[peerIP] == 0 {
				shouldPing = true
				reason = fmt.Sprintf("Initial connection baseline (%s)", endpoint)
			}

			if shouldPing {
				nowFloat := float64(now.UnixNano()) / 1e9
				lastDisp := m.lastPingDispatched[peerIP]
				if (nowFloat - lastDisp) >= 2.0 {
					m.lastPingDispatched[peerIP] = nowFloat
					m.lastPingedHandshake[peerIP] = p.LatestHandshake
					m.pinger.TriggerPing(peerIP, p.LatestHandshake, reason, func(ip string, res *ping.LatencyResult, handshakeTS int64) {
						if res != nil {
							m.historyMgr.RecordPeerPing(ip, &res.BestMs, handshakeTS, res.Samples, time.Now())
						}
					})
				}
			}

			if endpoint != "-" && endpoint != "(none)" {
				m.lastKnownEndpoint[peerIP] = endpoint
			}
			if validISP {
				m.lastKnownISP[peerIP] = ispName
			}
		}

		totalRx += p.RxBytes
		totalTx += p.TxBytes

		// Delta throughput rate
		prev, hasPrev := m.previousCounters[peerIP]
		var rxRateBps, txRateBps float64
		if hasPrev {
			dt := now.Sub(prev.timestamp).Seconds()
			if dt > 0.05 {
				dRx := p.RxBytes - prev.rxBytes
				if dRx < 0 {
					dRx = 0
				}
				dTx := p.TxBytes - prev.txBytes
				if dTx < 0 {
					dTx = 0
				}
				rxRateBps = (float64(dRx) * 8.0) / dt
				txRateBps = (float64(dTx) * 8.0) / dt
			}
		}
		m.previousCounters[peerIP] = peerRate{
			rxBytes:   p.RxBytes,
			txBytes:   p.TxBytes,
			timestamp: now,
			rxRateBps: rxRateBps,
			txRateBps: txRateBps,
		}

		totalRxRate += rxRateBps
		totalTxRate += txRateBps

		// Record peer history slice
		hSlice := m.historyMap[peerIP]
		hSlice = append(hSlice, bandwidthPoint{label: timeLabel, rxRateBps: rxRateBps, txRateBps: txRateBps})
		if len(hSlice) > m.historyPoints {
			hSlice = hSlice[len(hSlice)-m.historyPoints:]
		}
		m.historyMap[peerIP] = hSlice

		// Monthly accounting
		mRx, mTx := m.historyMgr.GetPeerMonthlyUsage(peerIP)
		monthlyBytes := mRx + mTx
		monthlyHuman := wireguard.HumanBytes(monthlyBytes)

		connectedSinceRestart := m.historyMgr.IsConnectedSinceRestart(peerIP)
		if connectedSinceRestart {
			sinceRestartCount++
		}

		// Handshake age
		hsHuman := "Never"
		if p.LatestHandshake > 0 {
			age := nowUnix - p.LatestHandshake
			if age < 0 {
				age = 0
			}
			hsHuman = wireguard.FormatHandshakeAge(age)
		}

		customAlias := m.historyMgr.GetAlias(peerIP)
		displayName := customAlias
		if displayName == "" {
			displayName = p.ConfName
		}

		pingHuman := "-"
		var pingMsVal *float64
		var pingSamples []float64
		if isOnline {
			if res := m.pinger.GetLatencyResult(peerIP); res != nil {
				pingHuman = res.Human
				pingMsVal = &res.BestMs
				pingSamples = res.Samples
			} else if lastPing := m.historyMgr.GetLastPing(peerIP); lastPing != nil {
				pingHuman = fmt.Sprintf("%.1f ms", *lastPing)
				pingMsVal = lastPing
			}
		}

		p.Name = displayName
		p.CustomAlias = customAlias
		p.IsCustomAlias = customAlias != ""
		p.ISP = ispName
		p.OnlineStatus = isOnline
		p.PingMS = pingMsVal
		p.PingHuman = pingHuman
		p.PingSamples = pingSamples
		p.DataUsage = wireguard.HumanBytes(p.RxBytes + p.TxBytes)
		p.RxHuman = wireguard.HumanBytes(p.RxBytes)
		p.TxHuman = wireguard.HumanBytes(p.TxBytes)
		p.RxRateBps = rxRateBps
		p.TxRateBps = txRateBps
		p.RxRateHuman = wireguard.FormatRate(rxRateBps)
		p.TxRateHuman = wireguard.FormatRate(txRateBps)
		p.LatestHandshakeHuman = hsHuman
		p.MonthlyUsage = monthlyHuman
		p.MonthlyBytes = monthlyBytes
		p.ConnectedSinceRestart = connectedSinceRestart

		processed = append(processed, p)

		bwSnapshot[peerIP] = map[string]interface{}{
			"received": p.RxBytes,
			"sent":     p.TxBytes,
			"rx_rate":  rxRateBps,
			"tx_rate":  txRateBps,
		}
	}

	bwSnapshot["total"] = map[string]interface{}{
		"received": totalRx,
		"sent":     totalTx,
		"rx_rate":  totalRxRate,
		"tx_rate":  totalTxRate,
	}

	m.totalHistory = append(m.totalHistory, bandwidthPoint{label: timeLabel, rxRateBps: totalRxRate, txRateBps: totalTxRate})
	if len(m.totalHistory) > m.historyPoints {
		m.totalHistory = m.totalHistory[len(m.totalHistory)-m.historyPoints:]
	}

	m.mu.Unlock()

	// Ingest analytics
	m.analyticsMgr.Record(analyticsSamples, now, totalRxRate, totalTxRate)

	summary := &wireguard.Summary{
		TotalPeers:            len(processed),
		OnlinePeers:           onlineCount,
		ConnectedSinceRestart: sinceRestartCount,
		OfflinePeers:          len(processed) - onlineCount,
		TotalRxBytes:          totalRx,
		TotalTxBytes:          totalTx,
		TotalUsageHuman:       wireguard.HumanBytes(totalRx + totalTx),
		TotalRxRateBps:        totalRxRate,
		TotalTxRateBps:        totalTxRate,
		TotalRxRateHuman:      wireguard.FormatRate(totalRxRate),
		TotalTxRateHuman:      wireguard.FormatRate(totalTxRate),
		CurrentMonth:          m.historyMgr.CurrentMonth(),
		MockMode:              m.mockMode,
		UpdatedAt:             timeLabel,
	}

	// Pre-serialize and pre-compress (gzip level 6) for sub-millisecond HTTP delivery
	statusJSON, _ := json.Marshal(processed)
	summaryJSON, _ := json.Marshal(summary)
	livePayload := wireguard.LivePayload{Peers: processed, Summary: summary}
	liveJSON, _ := json.Marshal(livePayload)

	statusGz := gzipBytes(statusJSON)
	summaryGz := gzipBytes(summaryJSON)
	liveGz := gzipBytes(liveJSON)

	m.mu.Lock()
	m.lastPeers = processed
	m.lastSummary = summary
	m.lastBandwidthSnapshot = bwSnapshot
	m.cachedStatusJSON = statusJSON
	m.cachedStatusGzip = statusGz
	m.cachedSummaryJSON = summaryJSON
	m.cachedSummaryGzip = summaryGz
	m.cachedLiveJSON = liveJSON
	m.cachedLiveGzip = liveGz
	m.mu.Unlock()

	// Real-time broadcast
	m.BroadcastRealtime(liveJSON)
}

func gzipBytes(data []byte) []byte {
	var buf bytes.Buffer
	gw, err := gzip.NewWriterLevel(&buf, 6)
	if err != nil {
		return nil
	}
	_, _ = gw.Write(data)
	_ = gw.Close()
	return buf.Bytes()
}

// HasPeer returns whether an IP is in the current peer table.
func (m *WireGuardMonitor) HasPeer(ip string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, p := range m.lastPeers {
		if p.IP == ip {
			return true
		}
	}
	return false
}

// UpdatePeerAliasInCache updates the in-RAM name of a peer.
func (m *WireGuardMonitor) UpdatePeerAliasInCache(ip, alias string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.lastPeers {
		if p.IP == ip {
			p.CustomAlias = alias
			p.IsCustomAlias = alias != ""
			if alias != "" {
				p.Name = alias
			} else {
				p.Name = p.ConfName
			}
		}
	}

	statusJSON, _ := json.Marshal(m.lastPeers)
	m.cachedStatusJSON = statusJSON
	m.cachedStatusGzip = gzipBytes(statusJSON)
	if m.lastSummary != nil {
		livePayload := wireguard.LivePayload{Peers: m.lastPeers, Summary: m.lastSummary}
		liveJSON, _ := json.Marshal(livePayload)
		m.cachedLiveJSON = liveJSON
		m.cachedLiveGzip = gzipBytes(liveJSON)
		go m.BroadcastRealtime(liveJSON)
	}
}

// GetStatus returns the cached status payload.
func (m *WireGuardMonitor) GetStatus() ([]byte, []byte, []*wireguard.Peer) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cachedStatusJSON, m.cachedStatusGzip, m.lastPeers
}

// GetSummary returns the cached summary payload.
func (m *WireGuardMonitor) GetSummary() ([]byte, []byte, *wireguard.Summary) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cachedSummaryJSON, m.cachedSummaryGzip, m.lastSummary
}

// GetLive returns the cached live payload.
func (m *WireGuardMonitor) GetLive() ([]byte, []byte, *wireguard.LivePayload) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cachedLiveJSON, m.cachedLiveGzip, &wireguard.LivePayload{Peers: m.lastPeers, Summary: m.lastSummary}
}

// GetCachedLiveJSON returns raw live JSON string.
func (m *WireGuardMonitor) GetCachedLiveJSON() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cachedLiveJSON
}

// GetBandwidthSnapshot returns current bandwidth counters.
func (m *WireGuardMonitor) GetBandwidthSnapshot() map[string]map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]map[string]interface{}, len(m.lastBandwidthSnapshot))
	for k, v := range m.lastBandwidthSnapshot {
		out[k] = v
	}
	return out
}

// GetTotalBandwidthHistory returns total Mbps timeline points.
func (m *WireGuardMonitor) GetTotalBandwidthHistory() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	labels := make([]string, len(m.totalHistory))
	rx := make([]float64, len(m.totalHistory))
	tx := make([]float64, len(m.totalHistory))
	var curRx, curTx float64

	for i, pt := range m.totalHistory {
		labels[i] = pt.label
		rx[i] = float64(int(pt.rxRateBps/1_000.0+0.5)) / 1000.0 // Mbps
		tx[i] = float64(int(pt.txRateBps/1_000.0+0.5)) / 1000.0
	}
	if len(m.totalHistory) > 0 {
		curRx = m.totalHistory[len(m.totalHistory)-1].rxRateBps
		curTx = m.totalHistory[len(m.totalHistory)-1].txRateBps
	}

	return map[string]interface{}{
		"ip":            "total",
		"labels":        labels,
		"rx":            rx,
		"tx":            tx,
		"rx_rate_bps":   curRx,
		"tx_rate_bps":   curTx,
		"rx_rate_human": wireguard.FormatRate(curRx),
		"tx_rate_human": wireguard.FormatRate(curTx),
	}
}

// GetPeerHistory returns Mbps timeline points for a specific peer.
func (m *WireGuardMonitor) GetPeerHistory(ip string) map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	historySlice := m.historyMap[ip]
	labels := make([]string, len(historySlice))
	rx := make([]float64, len(historySlice))
	tx := make([]float64, len(historySlice))

	for i, pt := range historySlice {
		labels[i] = pt.label
		rx[i] = float64(int(pt.rxRateBps/1_000.0+0.5)) / 1000.0
		tx[i] = float64(int(pt.txRateBps/1_000.0+0.5)) / 1000.0
	}

	return map[string]interface{}{
		"ip":     ip,
		"labels": labels,
		"rx":     rx,
		"tx":     tx,
	}
}

// Real-time SSE / WS broadcasting ----------------------------------------

func (m *WireGuardMonitor) SubscribeSSE() chan []byte {
	ch := make(chan []byte, 10)
	m.sseMu.Lock()
	m.sseChannels[ch] = true
	m.sseMu.Unlock()
	return ch
}

func (m *WireGuardMonitor) UnsubscribeSSE(ch chan []byte) {
	m.sseMu.Lock()
	delete(m.sseChannels, ch)
	m.sseMu.Unlock()
}

func (m *WireGuardMonitor) RegisterWS(conn *websocket.Conn) {
	m.wsMu.Lock()
	m.wsClients[conn] = true
	m.wsMu.Unlock()
}

func (m *WireGuardMonitor) UnregisterWS(conn *websocket.Conn) {
	m.wsMu.Lock()
	delete(m.wsClients, conn)
	m.wsMu.Unlock()
}

// BroadcastRealtime pushes new JSON to all active WebSockets and SSE queues.
func (m *WireGuardMonitor) BroadcastRealtime(data []byte) {
	// Push to SSE
	m.sseMu.Lock()
	for ch := range m.sseChannels {
		select {
		case ch <- data:
		default:
			// Buffer full, drop oldest
			select {
			case <-ch:
			default:
			}
			select {
			case ch <- data:
			default:
			}
		}
	}
	m.sseMu.Unlock()

	// Push to WebSockets
	m.wsMu.Lock()
	var dead []*websocket.Conn
	for ws := range m.wsClients {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err := ws.Write(ctx, websocket.MessageText, data)
		cancel()
		if err != nil {
			dead = append(dead, ws)
		}
	}
	for _, ws := range dead {
		delete(m.wsClients, ws)
		_ = ws.Close(websocket.StatusAbnormalClosure, "write error")
	}
	m.wsMu.Unlock()
}

func mockDeviceName(ip string) string {
	switch ip {
	case "10.20.0.2":
		return "MacBook-Pro-M3-Max"
	case "10.20.0.3":
		return "Edge-Gateway-Santiago"
	case "10.20.0.4":
		return "Remote-Dev-ThinkPad"
	case "10.20.0.5":
		return "Mobile-iOS-Roaming"
	case "10.20.0.6":
		return "Branch-Office-Valparaiso"
	default:
		return ""
	}
}

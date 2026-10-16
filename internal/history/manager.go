package history

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"wgstatus/internal/wireguard"
)

// HistoryManager manages monthly accounting, connection sessions, and latency logs in RAM.
type HistoryManager struct {
	baseDir               string
	dataDir               string
	archiveDir            string
	stateFile             string
	flushInterval         time.Duration
	maxSessionsPerPeer    int
	serviceStartTime      int64

	mu                     sync.RWMutex
	currentMonth           string
	monthlyUsage           map[string]*MonthlyUsage
	sessions               map[string][]*ConnectionSession
	rawBaseline            map[string][2]int64
	activeSessions         map[string]*ConnectionSession
	connectedSinceRestart  map[string]bool
	aliases                map[string]string
	pingHistory            map[string][]*PingRecord

	dirty                  bool
	lastFlushTime          time.Time
}

// NewHistoryManager creates and initializes a HistoryManager.
func NewHistoryManager(baseDir string, flushIntervalSeconds float64, maxSessionsPerPeer int) *HistoryManager {
	absBase, _ := filepath.Abs(baseDir)
	dataDir := filepath.Join(absBase, "data")
	archiveDir := filepath.Join(absBase, "archives")
	stateFile := filepath.Join(dataDir, "history_state.json")

	if maxSessionsPerPeer <= 0 {
		maxSessionsPerPeer = 60
	}

	hm := &HistoryManager{
		baseDir:               absBase,
		dataDir:               dataDir,
		archiveDir:            archiveDir,
		stateFile:             stateFile,
		flushInterval:         time.Duration(flushIntervalSeconds * float64(time.Second)),
		maxSessionsPerPeer:    maxSessionsPerPeer,
		serviceStartTime:      time.Now().Unix(),
		currentMonth:          time.Now().Format("2006-01"),
		monthlyUsage:          make(map[string]*MonthlyUsage),
		sessions:              make(map[string][]*ConnectionSession),
		rawBaseline:           make(map[string][2]int64),
		activeSessions:        make(map[string]*ConnectionSession),
		connectedSinceRestart: make(map[string]bool),
		aliases:               make(map[string]string),
		pingHistory:           make(map[string][]*PingRecord),
		lastFlushTime:         time.Now(),
	}

	_ = os.MkdirAll(dataDir, 0755)
	_ = os.MkdirAll(archiveDir, 0755)

	hm.loadState()
	return hm
}

// loadState loads existing state from history_state.json.
func (hm *HistoryManager) loadState() {
	if _, err := os.Stat(hm.stateFile); os.IsNotExist(err) {
		return
	}

	data, err := os.ReadFile(hm.stateFile)
	if err != nil {
		log.Printf("[HistoryManager] Failed to read state file: %v", err)
		return
	}

	var payload StatePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		log.Printf("[HistoryManager] Failed to unmarshal state: %v", err)
		return
	}

	nowMonth := time.Now().Format("2006-01")
	if payload.CurrentMonth != "" && payload.CurrentMonth != nowMonth {
		log.Printf("[HistoryManager] Month rollover detected during startup: %s -> %s", payload.CurrentMonth, nowMonth)
		hm.archiveMonth(payload.CurrentMonth, data)
		hm.currentMonth = nowMonth
		hm.dirty = true
		hm.Flush(true)
		return
	}

	if payload.CurrentMonth != "" {
		hm.currentMonth = payload.CurrentMonth
	}
	if payload.MonthlyUsage != nil {
		hm.monthlyUsage = payload.MonthlyUsage
	}
	if payload.Aliases != nil {
		hm.aliases = payload.Aliases
	}

	if payload.Sessions != nil {
		for ip, sessList := range payload.Sessions {
			slice := make([]*ConnectionSession, 0, len(sessList))
			for i := range sessList {
				sCopy := sessList[i]
				slice = append(slice, &sCopy)
			}
			if len(slice) > hm.maxSessionsPerPeer {
				slice = slice[len(slice)-hm.maxSessionsPerPeer:]
			}
			hm.sessions[ip] = slice
		}
	}

	if payload.PingHistory != nil {
		for ip, pList := range payload.PingHistory {
			slice := make([]*PingRecord, 0, len(pList))
			for i := range pList {
				pCopy := pList[i]
				slice = append(slice, &pCopy)
			}
			if len(slice) > 60 {
				slice = slice[len(slice)-60:]
			}
			hm.pingHistory[ip] = slice
		}
	}

	log.Printf("[HistoryManager] Loaded history state for month %s (%d peers tracked)", hm.currentMonth, len(hm.monthlyUsage))
}

// CheckMonthRollover checks whether the calendar month has rolled over and archives the previous month.
func (hm *HistoryManager) checkMonthRollover(now time.Time) {
	nowMonth := now.Format("2006-01")
	if hm.currentMonth != nowMonth {
		log.Printf("[HistoryManager] New calendar month detected: %s (archiving %s)", nowMonth, hm.currentMonth)
		oldMonth := hm.currentMonth
		payload := hm.buildExportPayload()
		data, _ := json.MarshalIndent(payload, "", "  ")

		hm.archiveMonth(oldMonth, data)

		hm.currentMonth = nowMonth
		hm.monthlyUsage = make(map[string]*MonthlyUsage)
		hm.dirty = true
		hm.flushLocked()
	}
}

func (hm *HistoryManager) archiveMonth(monthStr string, data []byte) {
	archivePath := filepath.Join(hm.archiveDir, fmt.Sprintf("wg_history_%s.json.gz", monthStr))
	var buf bytes.Buffer
	gw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		log.Printf("[HistoryManager] Failed to init gzip writer: %v", err)
		return
	}
	if _, err := gw.Write(data); err != nil {
		log.Printf("[HistoryManager] Failed to compress archive: %v", err)
		_ = gw.Close()
		return
	}
	if err := gw.Close(); err != nil {
		log.Printf("[HistoryManager] Failed to close gzip: %v", err)
		return
	}

	if err := os.WriteFile(archivePath, buf.Bytes(), 0644); err != nil {
		log.Printf("[HistoryManager] Failed to write archive file %s: %v", archivePath, err)
		return
	}
	log.Printf("[HistoryManager] Successfully archived month %s to %s (%.1f KB compressed)",
		monthStr, archivePath, float64(buf.Len())/1024.0)
}

// CurrentMonth returns the current active month string (YYYY-MM).
func (hm *HistoryManager) CurrentMonth() string {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	return hm.currentMonth
}

// UpdatePeers ingests WireGuard metrics, calculating deltas and tracking login sessions.
func (hm *HistoryManager) UpdatePeers(peers []*wireguard.Peer, now time.Time) {
	nowUnix := now.Unix()

	hm.mu.Lock()
	defer hm.mu.Unlock()

	hm.checkMonthRollover(now)

	for _, p := range peers {
		ip := p.IP
		if ip == "" {
			continue
		}
		rx := p.RxBytes
		tx := p.TxBytes
		endpoint := p.EndpointIP
		if endpoint == "" {
			endpoint = "-"
		}
		handshake := p.LatestHandshake
		isOnline := p.IsOnline(now, wireguard.DefaultOnlineThreshold)

		// 1. Delta Accounting
		var deltaRx, deltaTx int64
		prevBaseline, exists := hm.rawBaseline[ip]
		if !exists {
			deltaRx = 0
			deltaTx = 0
			hm.rawBaseline[ip] = [2]int64{rx, tx}
		} else {
			prevRx, prevTx := prevBaseline[0], prevBaseline[1]
			if rx >= prevRx {
				deltaRx = rx - prevRx
			} else {
				deltaRx = rx // counter reset / restarted
			}
			if tx >= prevTx {
				deltaTx = tx - prevTx
			} else {
				deltaTx = tx
			}
			hm.rawBaseline[ip] = [2]int64{rx, tx}
		}

		// Monthly bucket
		entry, found := hm.monthlyUsage[ip]
		if !found {
			lastSeen := handshake
			if lastSeen <= 0 {
				lastSeen = nowUnix
			}
			entry = &MonthlyUsage{
				MonthlyRx:    0,
				MonthlyTx:    0,
				FirstSeen:    nowUnix,
				LastSeen:     lastSeen,
				LastEndpoint: endpoint,
				LastISP:      "-",
			}
			hm.monthlyUsage[ip] = entry
		}

		if deltaRx > 0 || deltaTx > 0 {
			entry.MonthlyRx += deltaRx
			entry.MonthlyTx += deltaTx
			hm.dirty = true
		}

		if handshake > entry.LastSeen {
			entry.LastSeen = handshake
			hm.dirty = true
		}

		if endpoint != "-" && endpoint != entry.LastEndpoint {
			entry.LastEndpoint = endpoint
			hm.dirty = true
		}

		// 2. Connected Since Restart
		if isOnline || (handshake >= hm.serviceStartTime) {
			hm.connectedSinceRestart[ip] = true
		}

		// 3. Connection / Login Session Event Tracking
		activeSess := hm.activeSessions[ip]
		if isOnline {
			if activeSess == nil || (endpoint != "-" && activeSess.EndpointIP != "-" && endpoint != activeSess.EndpointIP) {
				sessionID := fmt.Sprintf("%s_%d", ip, nowUnix)
				startAt := nowUnix
				if handshake > 0 && handshake >= (hm.serviceStartTime-300) {
					startAt = handshake
				}

				newSess := &ConnectionSession{
					ID:         sessionID,
					PeerIP:     ip,
					EndpointIP: endpoint,
					ISP:        "-",
					StartedAt:  startAt,
					LastActive: nowUnix,
					RxBytes:    deltaRx,
					TxBytes:    deltaTx,
				}
				hm.activeSessions[ip] = newSess

				slice := hm.sessions[ip]
				slice = append(slice, newSess)
				if len(slice) > hm.maxSessionsPerPeer {
					slice = slice[len(slice)-hm.maxSessionsPerPeer:]
				}
				hm.sessions[ip] = slice
				hm.dirty = true
			} else {
				activeSess.LastActive = nowUnix
				activeSess.RxBytes += deltaRx
				activeSess.TxBytes += deltaTx
				if endpoint != "-" && activeSess.EndpointIP == "-" {
					activeSess.EndpointIP = endpoint
				}
				if deltaRx > 0 || deltaTx > 0 {
					hm.dirty = true
				}
			}
		} else {
			if activeSess != nil {
				if handshake > 0 {
					activeSess.LastActive = handshake
				} else {
					activeSess.LastActive = nowUnix
				}
				delete(hm.activeSessions, ip)
				hm.dirty = true
			}
		}
	}

	// 4. Periodic Flush Check
	if hm.dirty && now.Sub(hm.lastFlushTime) >= hm.flushInterval {
		hm.flushLocked()
	}
}

// UpdateSessionISP updates the ISP for active and recent sessions once resolved.
func (hm *HistoryManager) UpdateSessionISP(ip, endpoint, isp string) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	if entry, ok := hm.monthlyUsage[ip]; ok {
		entry.LastISP = isp
	}

	if sess, ok := hm.activeSessions[ip]; ok && sess.EndpointIP == endpoint {
		sess.ISP = isp
	}

	if list, ok := hm.sessions[ip]; ok {
		for _, s := range list {
			if s.EndpointIP == endpoint && (s.ISP == "-" || s.ISP == "Resolving..." || s.ISP == "Unknown ISP") {
				s.ISP = isp
			}
		}
	}
}

// GetPeerMonthlyUsage returns (monthlyRx, monthlyTx) for the given peer IP.
func (hm *HistoryManager) GetPeerMonthlyUsage(ip string) (int64, int64) {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	entry, ok := hm.monthlyUsage[ip]
	if !ok {
		return 0, 0
	}
	return entry.MonthlyRx, entry.MonthlyTx
}

// IsConnectedSinceRestart returns true if the peer connected during this process run.
func (hm *HistoryManager) IsConnectedSinceRestart(ip string) bool {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	return hm.connectedSinceRestart[ip]
}

// RecordPeerPing records a measured ping for a peer.
func (hm *HistoryManager) RecordPeerPing(peerIP string, pingMS *float64, handshakeTS int64, samples []float64, now time.Time) {
	nowUnix := now.Unix()
	var roundedSamples []float64
	if samples != nil {
		for _, s := range samples {
			roundedSamples = append(roundedSamples, round1(s))
		}
	} else if pingMS != nil {
		roundedSamples = []float64{round1(*pingMS)}
	} else {
		roundedSamples = []float64{}
	}

	hm.mu.Lock()
	defer hm.mu.Unlock()

	entry, found := hm.monthlyUsage[peerIP]
	if !found {
		entry = &MonthlyUsage{
			FirstSeen:    nowUnix,
			LastSeen:     nowUnix,
			LastEndpoint: "-",
			LastISP:      "-",
		}
		hm.monthlyUsage[peerIP] = entry
	}
	entry.LastPingMS = pingMS
	entry.LastPingSamples = roundedSamples
	entry.LastPingTime = nowUnix

	if activeSess := hm.activeSessions[peerIP]; activeSess != nil {
		activeSess.PingMS = pingMS
		activeSess.PingSamples = roundedSamples
	}

	if list := hm.sessions[peerIP]; len(list) > 0 {
		latest := list[len(list)-1]
		if latest.PingMS == nil || hm.activeSessions[peerIP] == latest {
			latest.PingMS = pingMS
			latest.PingSamples = roundedSamples
		}
	}

	pList := hm.pingHistory[peerIP]
	rec := &PingRecord{
		Timestamp:   nowUnix,
		TimeHuman:   now.Format("2006-01-02 15:04:05"),
		HandshakeTS: handshakeTS,
		PingMS:      pingMS,
		PingSamples: roundedSamples,
	}
	pList = append(pList, rec)
	if len(pList) > 60 {
		pList = pList[len(pList)-60:]
	}
	hm.pingHistory[peerIP] = pList
	hm.dirty = true
}

func round1(val float64) float64 {
	return float64(int(val*10+0.5)) / 10
}

// GetLastPing returns the last measured latency in milliseconds, or nil.
func (hm *HistoryManager) GetLastPing(peerIP string) *float64 {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	entry := hm.monthlyUsage[peerIP]
	if entry != nil {
		return entry.LastPingMS
	}
	return nil
}

// SetAlias assigns a friendly name to a peer IP.
func (hm *HistoryManager) SetAlias(ip, alias string) string {
	clean := strings.TrimSpace(alias)
	hm.mu.Lock()
	defer hm.mu.Unlock()

	if clean == "" {
		delete(hm.aliases, ip)
	} else {
		hm.aliases[ip] = clean
	}
	hm.dirty = true
	return clean
}

// GetAlias retrieves the friendly alias for a peer IP.
func (hm *HistoryManager) GetAlias(ip string) string {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	return hm.aliases[ip]
}

// GetAllAliases returns a copy of all configured aliases.
func (hm *HistoryManager) GetAllAliases() map[string]string {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	out := make(map[string]string, len(hm.aliases))
	for k, v := range hm.aliases {
		out[k] = v
	}
	return out
}

// GetPeerHistoryPayload formats historical telemetry for a single peer.
func (hm *HistoryManager) GetPeerHistoryPayload(ip string) map[string]interface{} {
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	entry := hm.monthlyUsage[ip]
	var mRx, mTx, lastSeen, lastPingTime int64
	var lastEP, lastISP string
	var lastPing *float64
	var lastPingSamples []float64

	if entry != nil {
		mRx = entry.MonthlyRx
		mTx = entry.MonthlyTx
		lastSeen = entry.LastSeen
		lastEP = entry.LastEndpoint
		lastISP = entry.LastISP
		lastPing = entry.LastPingMS
		lastPingSamples = entry.LastPingSamples
		lastPingTime = entry.LastPingTime
	} else {
		lastEP = "-"
		lastISP = "-"
	}

	lastPingHuman := "-"
	if lastPing != nil {
		lastPingHuman = fmt.Sprintf("%.1f ms", *lastPing)
	}
	if lastPingSamples == nil {
		lastPingSamples = []float64{}
	}

	sessList := hm.sessions[ip]
	sessDicts := make([]map[string]interface{}, 0, len(sessList))
	for i := len(sessList) - 1; i >= 0; i-- {
		sDict := sessList[i].ToDict()
		HumanizeSession(sDict)
		sessDicts = append(sessDicts, sDict)
	}

	pList := hm.pingHistory[ip]
	pingExport := make([]PingRecord, 0, len(pList))
	for _, p := range pList {
		pingExport = append(pingExport, *p)
	}

	return map[string]interface{}{
		"ip":                       ip,
		"alias":                    hm.aliases[ip],
		"current_month":            hm.currentMonth,
		"monthly_rx":               mRx,
		"monthly_tx":               mTx,
		"last_endpoint":            lastEP,
		"last_isp":                 lastISP,
		"last_seen":                lastSeen,
		"last_ping_ms":             lastPing,
		"last_ping_samples":        lastPingSamples,
		"last_ping_human":          lastPingHuman,
		"last_ping_time":           lastPingTime,
		"connected_since_restart":  hm.connectedSinceRestart[ip],
		"sessions":                 sessDicts,
		"ping_history":             pingExport,
	}
}

// GetAllSessions returns all logged sessions across all peers, sorted newest first.
func (hm *HistoryManager) GetAllSessions() []map[string]interface{} {
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	var allSess []map[string]interface{}
	for ip, list := range hm.sessions {
		alias := hm.aliases[ip]
		for _, s := range list {
			d := s.ToDict()
			d["peer_ip"] = ip
			d["alias"] = alias
			HumanizeSession(d)
			allSess = append(allSess, d)
		}
	}

	sort.Slice(allSess, func(i, j int) bool {
		si, _ := allSess[i]["started_at"].(int64)
		sj, _ := allSess[j]["started_at"].(int64)
		return si > sj
	})

	return allSess
}

func (hm *HistoryManager) buildExportPayload() StatePayload {
	sessionsExport := make(map[string][]ConnectionSession, len(hm.sessions))
	for ip, list := range hm.sessions {
		slice := make([]ConnectionSession, 0, len(list))
		for _, s := range list {
			slice = append(slice, *s)
		}
		sessionsExport[ip] = slice
	}

	pingExport := make(map[string][]PingRecord, len(hm.pingHistory))
	for ip, list := range hm.pingHistory {
		slice := make([]PingRecord, 0, len(list))
		for _, p := range list {
			slice = append(slice, *p)
		}
		pingExport[ip] = slice
	}

	aliasesExport := make(map[string]string, len(hm.aliases))
	for k, v := range hm.aliases {
		aliasesExport[k] = v
	}

	monthlyExport := make(map[string]*MonthlyUsage, len(hm.monthlyUsage))
	for k, v := range hm.monthlyUsage {
		vCopy := *v
		monthlyExport[k] = &vCopy
	}

	return StatePayload{
		CurrentMonth: hm.currentMonth,
		LastSavedAt:  time.Now().Unix(),
		MonthlyUsage: monthlyExport,
		Sessions:     sessionsExport,
		Aliases:      aliasesExport,
		PingHistory:  pingExport,
	}
}

// Flush writes buffered RAM telemetry to disk atomically.
func (hm *HistoryManager) Flush(force bool) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	if !hm.dirty && !force {
		return
	}
	hm.flushLocked()
}

func (hm *HistoryManager) flushLocked() {
	payload := hm.buildExportPayload()
	tempFile := hm.stateFile + ".tmp"

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		log.Printf("[HistoryManager] Failed to marshal state: %v", err)
		return
	}

	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		log.Printf("[HistoryManager] Failed to write temp state: %v", err)
		_ = os.Remove(tempFile)
		return
	}

	if err := os.Rename(tempFile, hm.stateFile); err != nil {
		log.Printf("[HistoryManager] Failed to replace state file: %v", err)
		_ = os.Remove(tempFile)
		return
	}

	hm.dirty = false
	hm.lastFlushTime = time.Now()
}

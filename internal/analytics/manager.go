package analytics

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"wgstatus/internal/isp"
	"wgstatus/internal/wireguard"
)

type peerState struct {
	wasOnline   bool
	wasEndpoint string
}

type cachedReport struct {
	cachedAt time.Time
	report   *Report
}

// AnalyticsManager aggregates traffic volume and ISP rankings in RAM and periodically flushes to disk.
type AnalyticsManager struct {
	dataDir       string
	flushInterval time.Duration
	stateFile     string

	mu           sync.RWMutex
	hourly       map[string]*HourlyBucket
	ispTotals    map[string]*IspTotal
	firstTS      int64
	demo         bool
	baseline     map[string][2]int64
	peerISP      map[string]string
	peerStateMap map[string]peerState
	lastRecord   time.Time
	lastPruneKey string

	dirty        bool
	lastFlush    time.Time
	reportCache  map[string]cachedReport
	started      bool
}

// NewAnalyticsManager creates a new AnalyticsManager.
func NewAnalyticsManager(baseDir string, flushIntervalSeconds float64) *AnalyticsManager {
	absBase, _ := filepath.Abs(baseDir)
	dataDir := filepath.Join(absBase, "data")
	stateFile := filepath.Join(dataDir, "analytics_state.json")

	return &AnalyticsManager{
		dataDir:       dataDir,
		flushInterval: time.Duration(flushIntervalSeconds * float64(time.Second)),
		stateFile:     stateFile,
		hourly:        make(map[string]*HourlyBucket),
		ispTotals:     make(map[string]*IspTotal),
		baseline:      make(map[string][2]int64),
		peerISP:       make(map[string]string),
		peerStateMap:  make(map[string]peerState),
		reportCache:   make(map[string]cachedReport),
		lastFlush:     time.Now(),
	}
}

// Start loads state and seeds demo data if in mock mode.
func (am *AnalyticsManager) Start(mock bool) {
	am.mu.Lock()
	defer am.mu.Unlock()

	if am.started {
		return
	}
	am.started = true

	if mock {
		am.stateFile = filepath.Join(am.dataDir, "analytics_state.demo.json")
	}
	_ = os.MkdirAll(am.dataDir, 0755)

	am.loadLocked()

	if mock && len(am.hourly) == 0 {
		am.seedDemoLocked()
	}
}

func (am *AnalyticsManager) loadLocked() {
	if _, err := os.Stat(am.stateFile); os.IsNotExist(err) {
		return
	}

	data, err := os.ReadFile(am.stateFile)
	if err != nil {
		log.Printf("[Analytics] Failed to read state: %v", err)
		return
	}

	var state AnalyticsState
	if err := json.Unmarshal(data, &state); err != nil {
		log.Printf("[Analytics] Failed to unmarshal state: %v", err)
		return
	}

	am.hourly = make(map[string]*HourlyBucket)
	for hkey, b := range state.Hourly {
		mb := &HourlyBucket{
			Rx:         b.Rx,
			Tx:         b.Tx,
			PeakRxBps:  b.PeakRxBps,
			PeakTxBps:  b.PeakTxBps,
			Samples:    b.Samples,
			OnlineSum:  b.OnlineSum,
			OnlinePeak: b.OnlinePeak,
			ISPs:       make(map[string]*IspBucket),
		}
		for ispRaw, ib := range b.ISPs {
			canon := isp.CleanISPName(ispRaw)
			mib := mb.ISPs[canon]
			if mib == nil {
				mib = &IspBucket{Peers: []string{}}
				mb.ISPs[canon] = mib
			}
			mib.Rx += ib.Rx
			mib.Tx += ib.Tx
			mib.ActiveS = round2(mib.ActiveS + ib.ActiveS)
			mib.Sessions += ib.Sessions
			for _, p := range ib.Peers {
				if !containsString(mib.Peers, p) {
					mib.Peers = append(mib.Peers, p)
				}
			}
		}
		am.hourly[hkey] = mb
	}

	am.ispTotals = make(map[string]*IspTotal)
	for ispRaw, tot := range state.IspTotals {
		canon := isp.CleanISPName(ispRaw)
		mtot := am.ispTotals[canon]
		if mtot == nil {
			mtot = &IspTotal{Peers: []string{}, FirstSeen: tot.FirstSeen, LastSeen: tot.LastSeen}
			am.ispTotals[canon] = mtot
		}
		mtot.Rx += tot.Rx
		mtot.Tx += tot.Tx
		mtot.ActiveS = round2(mtot.ActiveS + tot.ActiveS)
		mtot.Sessions += tot.Sessions
		for _, p := range tot.Peers {
			if !containsString(mtot.Peers, p) {
				mtot.Peers = append(mtot.Peers, p)
			}
		}
		if tot.FirstSeen > 0 {
			if mtot.FirstSeen == 0 || tot.FirstSeen < mtot.FirstSeen {
				mtot.FirstSeen = tot.FirstSeen
			}
		}
		if tot.LastSeen > mtot.LastSeen {
			mtot.LastSeen = tot.LastSeen
		}
	}

	am.firstTS = state.FirstTS
	am.demo = state.Demo
	log.Printf("[Analytics] Loaded analytics: %d hourly buckets, %d networks", len(am.hourly), len(am.ispTotals))
}

func (am *AnalyticsManager) normalizeISP(ip, raw string) string {
	canon := isp.CleanISPName(raw)
	if canon == UnknownISP {
		if prev, ok := am.peerISP[ip]; ok {
			return prev
		}
		return UnknownISP
	}
	am.peerISP[ip] = canon
	return canon
}

func hourKey(t time.Time) string {
	return t.Format("2006-01-02 15")
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}

func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func (am *AnalyticsManager) bucket(key string) *HourlyBucket {
	b, ok := am.hourly[key]
	if !ok {
		b = &HourlyBucket{
			ISPs: make(map[string]*IspBucket),
		}
		am.hourly[key] = b
	}
	return b
}

// Record ingests a slice of peer samples from the monitor loop.
func (am *AnalyticsManager) Record(samples []PeerSample, now time.Time, totalRxBps, totalTxBps float64) {
	am.mu.Lock()
	defer am.mu.Unlock()

	key := hourKey(now)
	dt := 0.0
	if !am.lastRecord.IsZero() {
		diff := now.Sub(am.lastRecord).Seconds()
		if diff < 0 {
			diff = 0
		} else if diff > 5.0 {
			diff = 5.0
		}
		dt = diff
	}
	am.lastRecord = now
	if am.firstTS == 0 {
		am.firstTS = now.Unix()
	}

	b := am.bucket(key)
	b.Samples++
	if totalRxBps > b.PeakRxBps {
		b.PeakRxBps = totalRxBps
	}
	if totalTxBps > b.PeakTxBps {
		b.PeakTxBps = totalTxBps
	}

	onlineCount := 0
	for _, s := range samples {
		canonISP := am.normalizeISP(s.IP, s.ISP)

		prev, hasPrev := am.baseline[s.IP]
		var dRx, dTx int64
		if !hasPrev {
			dRx = 0
			dTx = 0
		} else {
			if s.Rx >= prev[0] {
				dRx = s.Rx - prev[0]
			} else {
				dRx = s.Rx
			}
			if s.Tx >= prev[1] {
				dTx = s.Tx - prev[1]
			} else {
				dTx = s.Tx
			}
		}
		am.baseline[s.IP] = [2]int64{s.Rx, s.Tx}

		newSession := false
		st, hasSt := am.peerStateMap[s.IP]
		if s.Online && hasSt {
			endpointValid := s.Endpoint != "-" && s.Endpoint != ""
			wasValid := st.wasEndpoint != "-" && st.wasEndpoint != ""
			newSession = (!st.wasOnline) || (endpointValid && wasValid && s.Endpoint != st.wasEndpoint)
		}
		epStore := s.Endpoint
		if epStore == "-" || epStore == "" {
			if hasSt {
				epStore = st.wasEndpoint
			} else {
				epStore = "-"
			}
		}
		am.peerStateMap[s.IP] = peerState{wasOnline: s.Online, wasEndpoint: epStore}

		if s.Online {
			onlineCount++
		}

		if dRx == 0 && dTx == 0 && !s.Online && !newSession {
			continue
		}

		b.Rx += dRx
		b.Tx += dTx

		ib := b.ISPs[canonISP]
		if ib == nil {
			ib = &IspBucket{Peers: []string{}}
			b.ISPs[canonISP] = ib
		}
		ib.Rx += dRx
		ib.Tx += dTx
		if s.Online {
			ib.ActiveS = round2(ib.ActiveS + dt)
		}
		if newSession {
			ib.Sessions++
		}
		if !containsString(ib.Peers, s.IP) {
			ib.Peers = append(ib.Peers, s.IP)
		}

		tot := am.ispTotals[canonISP]
		if tot == nil {
			if len(am.ispTotals) >= MaxISPs {
				var weakestKey string
				var weakestVol int64 = -1
				for k, v := range am.ispTotals {
					vol := v.Rx + v.Tx
					if weakestVol == -1 || vol < weakestVol {
						weakestVol = vol
						weakestKey = k
					}
				}
				delete(am.ispTotals, weakestKey)
			}
			tot = &IspTotal{
				Peers:     []string{},
				FirstSeen: now.Unix(),
				LastSeen:  now.Unix(),
			}
			am.ispTotals[canonISP] = tot
		}
		tot.Rx += dRx
		tot.Tx += dTx
		if s.Online {
			tot.ActiveS = round2(tot.ActiveS + dt)
			tot.LastSeen = now.Unix()
		}
		if newSession {
			tot.Sessions++
		}
		if len(tot.Peers) < 2000 && !containsString(tot.Peers, s.IP) {
			tot.Peers = append(tot.Peers, s.IP)
		}
	}

	b.OnlineSum += onlineCount
	if onlineCount > b.OnlinePeak {
		b.OnlinePeak = onlineCount
	}
	am.dirty = true

	if key != am.lastPruneKey {
		am.lastPruneKey = key
		am.pruneLocked(now)
	}

	if am.dirty && now.Sub(am.lastFlush) >= am.flushInterval {
		am.flushLocked()
	}
}

func (am *AnalyticsManager) pruneLocked(now time.Time) {
	cutoff := hourKey(now.Add(-time.Duration(HourlyRetentionDays*24) * time.Hour))
	for k := range am.hourly {
		if k < cutoff {
			delete(am.hourly, k)
		}
	}
	am.reportCache = make(map[string]cachedReport)
}

// GetReport compiles the analytics report for the requested range (24h, 7d, 30d, all).
func (am *AnalyticsManager) GetReport(rangeKey string) *Report {
	if _, ok := Ranges[rangeKey]; !ok {
		rangeKey = "7d"
	}

	now := time.Now()

	am.mu.RLock()
	cached, found := am.reportCache[rangeKey]
	if found && now.Sub(cached.cachedAt) < 5*time.Second {
		rpt := cached.report
		am.mu.RUnlock()
		return rpt
	}
	am.mu.RUnlock()

	am.mu.Lock()
	defer am.mu.Unlock()

	// Double check cache
	if c2, f2 := am.reportCache[rangeKey]; f2 && now.Sub(c2.cachedAt) < 5*time.Second {
		return c2.report
	}

	report := am.buildReportLocked(rangeKey, now)
	am.reportCache[rangeKey] = cachedReport{cachedAt: now, report: report}
	return report
}

func (am *AnalyticsManager) windowKeys(hours int, now time.Time) []string {
	base := now.Truncate(time.Hour)
	keys := make([]string, hours)
	for i := 0; i < hours; i++ {
		offset := hours - 1 - i
		t := base.Add(-time.Duration(offset) * time.Hour)
		keys[i] = hourKey(t)
	}
	return keys
}

func humanDuration(seconds float64) string {
	s := int64(math.Max(0, seconds))
	if s < 60 {
		return fmt.Sprintf("%ds", s)
	}
	if s < 3600 {
		return fmt.Sprintf("%dm", s/60)
	}
	if s < 86400 {
		return fmt.Sprintf("%dh %dm", s/3600, (s%3600)/60)
	}
	return fmt.Sprintf("%dd %dh", s/86400, (s%86400)/3600)
}

func (am *AnalyticsManager) buildReportLocked(rangeKey string, now time.Time) *Report {
	hours := Ranges[rangeKey]
	keys := am.windowKeys(hours, now)

	var seriesHourly []SeriesPoint
	var hodTotal [24]int64
	var hodRx [24]int64
	var hodTx [24]int64
	hodISP := make(map[string]*[24]int64)
	daysWithData := make(map[string]bool)

	type windowIspAgg struct {
		rx       int64
		tx       int64
		activeS  float64
		sessions int
		peers    map[string]bool
	}
	ispWindow := make(map[string]*windowIspAgg)

	var totRx, totTx int64
	var peakRx, peakTx float64
	var onlineSum, samplesSum, onlinePeak int

	for _, k := range keys {
		b := am.hourly[k]
		var hr int
		fmt.Sscanf(k[len(k)-2:], "%d", &hr)

		var rx, tx int64
		var peakBps, avgOnline float64

		if b != nil {
			rx = b.Rx
			tx = b.Tx
			if b.PeakRxBps > b.PeakTxBps {
				peakBps = b.PeakRxBps
			} else {
				peakBps = b.PeakTxBps
			}
			if b.Samples > 0 {
				avgOnline = round2(float64(b.OnlineSum) / float64(b.Samples))
			}

			daysWithData[k[:10]] = true
			totRx += rx
			totTx += tx
			hodTotal[hr] += rx + tx
			hodRx[hr] += rx
			hodTx[hr] += tx
			if b.PeakRxBps > peakRx {
				peakRx = b.PeakRxBps
			}
			if b.PeakTxBps > peakTx {
				peakTx = b.PeakTxBps
			}
			onlineSum += b.OnlineSum
			samplesSum += b.Samples
			if b.OnlinePeak > onlinePeak {
				onlinePeak = b.OnlinePeak
			}

			for ispName, ib := range b.ISPs {
				agg := ispWindow[ispName]
				if agg == nil {
					agg = &windowIspAgg{peers: make(map[string]bool)}
					ispWindow[ispName] = agg
				}
				agg.rx += ib.Rx
				agg.tx += ib.Tx
				agg.activeS += ib.ActiveS
				agg.sessions += ib.Sessions
				for _, p := range ib.Peers {
					agg.peers[p] = true
				}

				hArr := hodISP[ispName]
				if hArr == nil {
					hArr = &[24]int64{}
					hodISP[ispName] = hArr
				}
				hArr[hr] += ib.Rx + ib.Tx
			}
		}

		seriesHourly = append(seriesHourly, SeriesPoint{
			Key:       k,
			Rx:        rx,
			Tx:        tx,
			Total:     rx + tx,
			PeakBps:   peakBps,
			AvgOnline: avgOnline,
		})
	}

	nDays := len(daysWithData)
	if nDays < 1 {
		nDays = 1
	}

	// Daily series aggregation
	dailyMap := make(map[string]*SeriesPoint)
	var dailyKeys []string
	for _, pt := range seriesHourly {
		dayKey := pt.Key[:10]
		d := dailyMap[dayKey]
		if d == nil {
			d = &SeriesPoint{Key: dayKey}
			dailyMap[dayKey] = d
			dailyKeys = append(dailyKeys, dayKey)
		}
		d.Rx += pt.Rx
		d.Tx += pt.Tx
		d.Total += pt.Total
		if pt.PeakBps > d.PeakBps {
			d.PeakBps = pt.PeakBps
		}
	}

	granularity := "hour"
	var series []SeriesPoint
	if rangeKey == "24h" || rangeKey == "7d" {
		series = seriesHourly
	} else {
		granularity = "day"
		for _, dk := range dailyKeys {
			series = append(series, *dailyMap[dk])
		}
	}

	// Source for ISP rankings
	type ispSourceRow struct {
		rx       int64
		tx       int64
		activeS  float64
		sessions int
		peersLen int
	}
	source := make(map[string]ispSourceRow)
	if rangeKey == "all" {
		for ispName, t := range am.ispTotals {
			source[ispName] = ispSourceRow{
				rx:       t.Rx,
				tx:       t.Tx,
				activeS:  t.ActiveS,
				sessions: t.Sessions,
				peersLen: len(t.Peers),
			}
		}
	} else {
		for ispName, agg := range ispWindow {
			source[ispName] = ispSourceRow{
				rx:       agg.rx,
				tx:       agg.tx,
				activeS:  agg.activeS,
				sessions: agg.sessions,
				peersLen: len(agg.peers),
			}
		}
	}

	var grandTotal int64
	for _, v := range source {
		grandTotal += v.rx + v.tx
	}
	if grandTotal == 0 {
		grandTotal = 1
	}

	var ispRows []IspRow
	for ispName, v := range source {
		total := v.rx + v.tx
		var peakHr *int
		hArr := hodISP[ispName]
		if hArr != nil {
			maxVol := int64(-1)
			bestH := 0
			hasAny := false
			for h := 0; h < 24; h++ {
				if hArr[h] > 0 {
					hasAny = true
				}
				if hArr[h] > maxVol {
					maxVol = hArr[h]
					bestH = h
				}
			}
			if hasAny {
				peakHr = &bestH
			}
		}

		ispRows = append(ispRows, IspRow{
			ISP:           ispName,
			Rx:            v.rx,
			Tx:            v.tx,
			Total:         total,
			TotalHuman:    wireguard.HumanBytes(total),
			RxHuman:       wireguard.HumanBytes(v.rx),
			TxHuman:       wireguard.HumanBytes(v.tx),
			SharePct:      round1Val(100.0 * float64(total) / float64(grandTotal)),
			Sessions:      v.sessions,
			Devices:       v.peersLen,
			ActiveSeconds: int64(v.activeS),
			ActiveHuman:   humanDuration(v.activeS),
			PeakHour:      peakHr,
		})
	}

	sort.Slice(ispRows, func(i, j int) bool {
		return ispRows[i].Total > ispRows[j].Total
	})

	if len(ispRows) > 25 {
		ispRows = ispRows[:25]
	}

	// Diurnal hour of day by ISP series
	var topNames []string
	for i := 0; i < len(ispRows) && i < 5; i++ {
		topNames = append(topNames, ispRows[i].ISP)
	}

	divisor := float64(nDays)
	var hodSeries []HourOfDayIspSeries
	for _, name := range topNames {
		hArr := hodISP[name]
		bytesArr := make([]int64, 24)
		if hArr != nil {
			for h := 0; h < 24; h++ {
				bytesArr[h] = int64(math.Round(float64(hArr[h]) / divisor))
			}
		}
		hodSeries = append(hodSeries, HourOfDayIspSeries{ISP: name, Bytes: bytesArr})
	}

	var othersArr [24]int64
	hasOthers := false
	for ispName, hArr := range hodISP {
		if !containsString(topNames, ispName) && hArr != nil {
			for h := 0; h < 24; h++ {
				othersArr[h] += hArr[h]
				if hArr[h] > 0 {
					hasOthers = true
				}
			}
		}
	}
	if hasOthers {
		bytesArr := make([]int64, 24)
		for h := 0; h < 24; h++ {
			bytesArr[h] = int64(math.Round(float64(othersArr[h]) / divisor))
		}
		hodSeries = append(hodSeries, HourOfDayIspSeries{ISP: "Others", Bytes: bytesArr})
	}

	hourOfDay := make([]HourOfDayPoint, 24)
	for h := 0; h < 24; h++ {
		hourOfDay[h] = HourOfDayPoint{
			Hour:     h,
			AvgTotal: int64(math.Round(float64(hodTotal[h]) / divisor)),
			AvgRx:    int64(math.Round(float64(hodRx[h]) / divisor)),
			AvgTx:    int64(math.Round(float64(hodTx[h]) / divisor)),
		}
	}

	var peakHour, quietHour *HourLabel
	hasAnyVol := false
	for h := 0; h < 24; h++ {
		if hodTotal[h] > 0 {
			hasAnyVol = true
			break
		}
	}

	if hasAnyVol {
		ph := 0
		qh := 0
		maxH := hodTotal[0]
		minH := hodTotal[0]
		for h := 1; h < 24; h++ {
			if hodTotal[h] > maxH {
				maxH = hodTotal[h]
				ph = h
			}
			if hodTotal[h] < minH {
				minH = hodTotal[h]
				qh = h
			}
		}
		peakHour = &HourLabel{
			Hour:     ph,
			Label:    fmt.Sprintf("%02d:00-%02d:00", ph, (ph+1)%24),
			AvgHuman: wireguard.HumanBytes(int64(math.Round(float64(hodTotal[ph]) / divisor))),
		}
		quietHour = &HourLabel{
			Hour:     qh,
			Label:    fmt.Sprintf("%02d:00-%02d:00", qh, (qh+1)%24),
			AvgHuman: wireguard.HumanBytes(int64(math.Round(float64(hodTotal[qh]) / divisor))),
		}
	}

	var busiestHour *BusiestHour
	var maxTotal int64 = 0
	var maxPt *SeriesPoint
	for i := range seriesHourly {
		if seriesHourly[i].Total > maxTotal {
			maxTotal = seriesHourly[i].Total
			maxPt = &seriesHourly[i]
		}
	}
	if maxPt != nil && maxPt.Total > 0 {
		busiestHour = &BusiestHour{
			Key:        maxPt.Key,
			TotalHuman: wireguard.HumanBytes(maxPt.Total),
			PeakBps:    maxPt.PeakBps,
		}
	}

	var avgOnline float64
	if samplesSum > 0 {
		avgOnline = round2(float64(onlineSum) / float64(samplesSum))
	}

	return &Report{
		Range:        rangeKey,
		Granularity:  granularity,
		GeneratedAt:  now.Unix(),
		Demo:         am.demo,
		DataSince:    am.firstTS,
		DaysWithData: len(daysWithData),
		Totals: Totals{
			Rx:         totRx,
			Tx:         totTx,
			Total:      totRx + totTx,
			RxHuman:    wireguard.HumanBytes(totRx),
			TxHuman:    wireguard.HumanBytes(totTx),
			TotalHuman: wireguard.HumanBytes(totRx + totTx),
			PeakRxBps:  peakRx,
			PeakTxBps:  peakTx,
			AvgOnline:  avgOnline,
			PeakOnline: onlinePeak,
			Networks:   len(source),
		},
		PeakHour:       peakHour,
		QuietHour:      quietHour,
		BusiestHour:    busiestHour,
		Series:         series,
		HourOfDay:      hourOfDay,
		HourOfDayByISP: hodSeries,
		TopISPs:        ispRows,
	}
}

func round1Val(v float64) float64 {
	return math.Round(v*10) / 10
}

func (am *AnalyticsManager) seedDemoLocked() {
	r := rand.New(rand.NewSource(42))
	networks := []struct {
		isp   string
		share float64
		ip    string
	}{
		{"Starlink", 0.34, "10.20.0.2"},
		{"Entel PCS Telecomunicaciones", 0.27, "10.20.0.3"},
		{"Claro Chile", 0.16, "10.20.0.10"},
		{"GTD Telsur", 0.14, "10.20.0.4"},
		{"INTERNAL", 0.09, "10.20.0.5"},
	}

	now := time.Now()
	base := now.Truncate(time.Hour)

	for i := 24 * 14; i > 0; i-- {
		ts := base.Add(-time.Duration(i) * time.Hour)
		hr := ts.Hour()
		weekday := ts.Weekday()

		curve := 0.15 + 0.85*math.Exp(-math.Pow(float64(hr-21), 2)/18.0) + 0.35*math.Exp(-math.Pow(float64(hr-13), 2)/10.0)
		if weekday == time.Saturday || weekday == time.Sunday {
			curve *= 1.25
		}

		total := int64(r.Float64()*0.6+0.7) * int64(curve*1_400_000_000)
		b := am.bucket(hourKey(ts))
		b.Samples = 3600
		b.OnlineSum = int(3600.0 * (1.5 + 3.0*curve*(0.8+r.Float64()*0.3)))
		b.OnlinePeak = int(math.Min(5, float64(1+int(4*curve))))
		b.PeakRxBps = float64(total) * 8.0 / 3600.0 * (2.5 + r.Float64()*3.5)
		b.PeakTxBps = b.PeakRxBps * 0.35

		for _, nw := range networks {
			part := int64(float64(total) * nw.share * (0.6 + r.Float64()*0.8))
			rx := int64(float64(part) * 0.78)
			tx := part - rx

			ib := b.ISPs[nw.isp]
			if ib == nil {
				ib = &IspBucket{Peers: []string{nw.ip}}
				b.ISPs[nw.isp] = ib
			}
			ib.Rx = rx
			ib.Tx = tx
			ib.ActiveS = round2(3600.0 * math.Min(1.0, nw.share*2.2*curve))
			if r.Float64() < 0.25 {
				ib.Sessions = 1
			}

			b.Rx += rx
			b.Tx += tx

			tot := am.ispTotals[nw.isp]
			if tot == nil {
				tot = &IspTotal{
					Peers:     []string{nw.ip},
					FirstSeen: ts.Unix(),
					LastSeen:  ts.Unix(),
				}
				am.ispTotals[nw.isp] = tot
			}
			tot.Rx += rx
			tot.Tx += tx
			tot.ActiveS = round2(tot.ActiveS + ib.ActiveS)
			tot.Sessions += ib.Sessions
			tot.LastSeen = ts.Unix()
		}
	}

	am.firstTS = base.Add(-time.Duration(24*14) * time.Hour).Unix()
	am.demo = true
	am.dirty = true
	log.Printf("[Analytics] Seeded demo analytics dataset (%d hourly buckets)", len(am.hourly))
}

// Flush writes the in-memory analytics to disk atomically.
func (am *AnalyticsManager) Flush(force bool) {
	am.mu.Lock()
	defer am.mu.Unlock()

	if !am.dirty && !force {
		return
	}
	am.flushLocked()
}

func (am *AnalyticsManager) flushLocked() {
	state := AnalyticsState{
		Version:   1,
		SavedAt:   time.Now().Unix(),
		FirstTS:   am.firstTS,
		Demo:      am.demo,
		Hourly:    am.hourly,
		IspTotals: am.ispTotals,
	}

	data, err := json.Marshal(state)
	if err != nil {
		log.Printf("[Analytics] Failed to marshal analytics state: %v", err)
		return
	}

	tempFile := am.stateFile + ".tmp"
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		log.Printf("[Analytics] Failed to write temp analytics: %v", err)
		_ = os.Remove(tempFile)
		return
	}

	if err := os.Rename(tempFile, am.stateFile); err != nil {
		log.Printf("[Analytics] Failed to rename analytics state: %v", err)
		_ = os.Remove(tempFile)
		return
	}

	am.dirty = false
	am.lastFlush = time.Now()
}

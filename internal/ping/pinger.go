package ping

import (
	"fmt"
	"log"
	"math/rand"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	packetTimeRegex = regexp.MustCompile(`(?i)(?:time|tiempo)[=<]\s*([0-9.]+)\s*ms`)
	summaryRttRegex = regexp.MustCompile(`(?i)rtt min/avg/max/mdev =\s*([0-9.]+)/`)
)

type LatencyResult struct {
	BestMs  float64
	Human   string
	Samples []float64
}

type Pinger struct {
	mu           sync.Mutex
	cache        map[string]*LatencyResult
	inFlight     map[string]bool
	isMock       bool
	timeout      time.Duration
	maxAgeSec    float64
	lastPingTime map[string]time.Time
}

func NewPinger(isMock bool, timeout time.Duration, maxAgeSec float64) *Pinger {
	return &Pinger{
		cache:        make(map[string]*LatencyResult),
		inFlight:     make(map[string]bool),
		isMock:       isMock,
		timeout:      timeout,
		maxAgeSec:    maxAgeSec,
		lastPingTime: make(map[string]time.Time),
	}
}

func (p *Pinger) GetLatency(ip string) (string, *float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	res, ok := p.cache[ip]
	if !ok || res == nil {
		return "-", nil
	}
	return res.Human, &res.BestMs
}

func (p *Pinger) GetLatencyResult(ip string) *LatencyResult {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cache[ip]
}

// TriggerPing executes a latency measurement if the peer is not already being pinged.
// It respects a 2-second per-peer debounce rate limit and executes async.
func (p *Pinger) TriggerPing(ip string, handshakeTS int64, reason string, onComplete func(ip string, res *LatencyResult, handshakeTS int64)) {
	if ip == "" || ip == "-" {
		return
	}

	p.mu.Lock()
	if p.inFlight[ip] {
		p.mu.Unlock()
		return
	}
	// Avoid flooding: minimum 2.0s between ping dispatches per peer
	if last, ok := p.lastPingTime[ip]; ok && time.Since(last) < 2*time.Second {
		p.mu.Unlock()
		return
	}
	p.inFlight[ip] = true
	p.lastPingTime[ip] = time.Now()
	p.mu.Unlock()

	if reason != "" {
		log.Printf("[INFO] wgstatus: Ping queued for %s: %s", ip, reason)
	}

	go func() {
		defer func() {
			p.mu.Lock()
			delete(p.inFlight, ip)
			p.mu.Unlock()
		}()

		var res *LatencyResult
		if p.isMock {
			res = p.simulatePing(ip)
		} else {
			res = p.executePing(ip)
		}

		if res != nil {
			p.mu.Lock()
			p.cache[ip] = res
			p.mu.Unlock()

			if onComplete != nil {
				onComplete(ip, res, handshakeTS)
			}
		}
	}()
}

// MaybeTriggerPingWithCallback is provided for backwards compatibility.
func (p *Pinger) MaybeTriggerPingWithCallback(ip string, handshakeAgeSec float64, handshakeTS int64, onComplete func(ip string, res *LatencyResult, handshakeTS int64)) {
	p.TriggerPing(ip, handshakeTS, "", onComplete)
}

func (p *Pinger) simulatePing(ip string) *LatencyResult {
	time.Sleep(50 * time.Millisecond)
	p1 := 15.0 + rand.Float64()*120.0
	p2 := 8.0 + rand.Float64()*40.0
	best := min(p1, p2)
	log.Printf("[INFO] wgstatus: Simulated mock latency for %s: 2 pings %.1f -> %.1f ms (best: %.1f ms)", ip, p1, p2, best)
	return &LatencyResult{
		BestMs:  best,
		Human:   fmt.Sprintf("%.1f ms", best),
		Samples: []float64{round1(p1), round1(p2)},
	}
}

func (p *Pinger) executePing(ip string) *LatencyResult {
	timeoutSec := int(p.timeout.Seconds())
	if timeoutSec < 1 {
		timeoutSec = 1
	}

	isIPv6 := strings.Contains(ip, ":")
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		flag := "-4"
		if isIPv6 {
			flag = "-6"
		}
		cmd = exec.Command("ping", flag, "-n", "2", "-w", strconv.Itoa(timeoutSec*1000), ip)
	} else {
		flag := "-4"
		if isIPv6 {
			flag = "-6"
		}
		cmd = exec.Command("ping", flag, "-c", "2", "-i", "0.2", "-W", strconv.Itoa(timeoutSec), "-n", ip)
	}

	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return nil
	}

	output := string(out)
	var samples []float64

	matches := packetTimeRegex.FindAllStringSubmatch(output, -1)
	for _, m := range matches {
		if len(m) > 1 {
			if v, e := strconv.ParseFloat(m[1], 64); e == nil {
				samples = append(samples, round1(v))
			}
		}
	}

	// Fallback to summary line if per-packet line wasn't parsed
	if len(samples) == 0 {
		if m := summaryRttRegex.FindStringSubmatch(output); len(m) > 1 {
			if v, e := strconv.ParseFloat(m[1], 64); e == nil {
				samples = append(samples, round1(v))
			}
		}
	}

	if len(samples) == 0 {
		return nil
	}

	best := samples[0]
	for _, v := range samples[1:] {
		if v < best {
			best = v
		}
	}

	var sampleStrs []string
	for _, s := range samples {
		sampleStrs = append(sampleStrs, fmt.Sprintf("%.1fms", s))
	}
	log.Printf("[INFO] wgstatus: Measured latency for %s (2 pings: %s; best: %.1f ms)", ip, strings.Join(sampleStrs, " -> "), best)

	return &LatencyResult{
		BestMs:  best,
		Human:   fmt.Sprintf("%.1f ms", best),
		Samples: samples,
	}
}

func round1(val float64) float64 {
	return float64(int(val*10+0.5)) / 10.0
}

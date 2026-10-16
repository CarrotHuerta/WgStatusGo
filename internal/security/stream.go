package security

import "sync"

// StreamGuard limits concurrent SSE and WebSocket connections per client IP and globally.
type StreamGuard struct {
	mu     sync.Mutex
	perIP  int
	total  int
	counts map[string]int
	sum    int
}

// NewStreamGuard creates a new StreamGuard.
func NewStreamGuard(perIP, total int) *StreamGuard {
	if perIP <= 0 {
		perIP = 6
	}
	if total <= 0 {
		total = 150
	}
	return &StreamGuard{
		perIP:  perIP,
		total:  total,
		counts: make(map[string]int),
	}
}

// Acquire attempts to claim a stream slot for an IP.
func (sg *StreamGuard) Acquire(ip string) bool {
	sg.mu.Lock()
	defer sg.mu.Unlock()

	if sg.sum >= sg.total || sg.counts[ip] >= sg.perIP {
		return false
	}
	sg.counts[ip]++
	sg.sum++
	return true
}

// Release frees a claimed stream slot.
func (sg *StreamGuard) Release(ip string) {
	sg.mu.Lock()
	defer sg.mu.Unlock()

	n := sg.counts[ip]
	if n <= 1 {
		delete(sg.counts, ip)
	} else {
		sg.counts[ip] = n - 1
	}
	if sg.sum > 0 {
		sg.sum--
	}
}

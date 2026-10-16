package security

import (
	"math"
	"sync"
	"time"
)

// SlidingWindowLimiter implements a thread-safe sliding-window counter keyed by an arbitrary string.
type SlidingWindowLimiter struct {
	mu      sync.Mutex
	hits    map[string][]time.Time
	maxKeys int
	lastGC  time.Time
}

// NewSlidingWindowLimiter creates a new limiter.
func NewSlidingWindowLimiter(maxKeys int) *SlidingWindowLimiter {
	if maxKeys <= 0 {
		maxKeys = 20000
	}
	return &SlidingWindowLimiter{
		hits:    make(map[string][]time.Time),
		maxKeys: maxKeys,
		lastGC:  time.Now(),
	}
}

// Hit registers a request for key and returns whether allowed and retry-after in seconds.
func (l *SlidingWindowLimiter) Hit(key string, limit int, window time.Duration) (bool, int) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	if now.Sub(l.lastGC) > time.Minute || len(l.hits) > l.maxKeys {
		l.gcLocked(now)
	}

	timestamps := l.hits[key]
	cutoff := now.Add(-window)

	// Filter out expired hits
	validIdx := 0
	for validIdx < len(timestamps) && timestamps[validIdx].Before(cutoff) {
		validIdx++
	}
	if validIdx > 0 {
		timestamps = timestamps[validIdx:]
	}

	if len(timestamps) >= limit {
		retry := int(math.Max(1, math.Ceil(window.Seconds()-now.Sub(timestamps[0]).Seconds())))
		l.hits[key] = timestamps
		return false, retry
	}

	timestamps = append(timestamps, now)
	l.hits[key] = timestamps
	return true, 0
}

func (l *SlidingWindowLimiter) gcLocked(now time.Time) {
	l.lastGC = now
	for k, ts := range l.hits {
		if len(ts) == 0 || now.Sub(ts[len(ts)-1]) > time.Hour {
			delete(l.hits, k)
		}
	}

	if len(l.hits) > l.maxKeys {
		// Drop arbitrary keys to avoid memory bloat under attack
		count := 0
		for k := range l.hits {
			delete(l.hits, k)
			count++
			if len(l.hits) <= l.maxKeys {
				break
			}
		}
	}
}

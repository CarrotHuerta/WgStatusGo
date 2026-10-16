package security

import (
	"log"
	"math"
	"sync"
	"time"
)

// LoginThrottle enforces exponential backoff lockout per IP and a global ceiling against distributed attacks.
type LoginThrottle struct {
	maxAttempts int
	window      time.Duration
	baseLock    time.Duration
	maxLock     time.Duration
	globalMax   int
	globalLock  time.Duration

	mu              sync.Mutex
	fails           map[string][]time.Time
	strikes         map[string]int
	lockUntil       map[string]time.Time
	globalFails     []time.Time
	globalLockUntil time.Time
}

// NewLoginThrottle creates a LoginThrottle instance.
func NewLoginThrottle(maxAttempts int, windowSec, baseLockSec, maxLockSec float64, globalMax int, globalLockSec float64) *LoginThrottle {
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	if windowSec <= 0 {
		windowSec = 600.0
	}
	if baseLockSec <= 0 {
		baseLockSec = 60.0
	}
	if maxLockSec <= 0 {
		maxLockSec = 3600.0
	}
	if globalMax <= 0 {
		globalMax = 40
	}
	if globalLockSec <= 0 {
		globalLockSec = 60.0
	}

	return &LoginThrottle{
		maxAttempts: maxAttempts,
		window:      time.Duration(windowSec * float64(time.Second)),
		baseLock:    time.Duration(baseLockSec * float64(time.Second)),
		maxLock:     time.Duration(maxLockSec * float64(time.Second)),
		globalMax:   globalMax,
		globalLock:  time.Duration(globalLockSec * float64(time.Second)),
		fails:       make(map[string][]time.Time),
		strikes:     make(map[string]int),
		lockUntil:   make(map[string]time.Time),
	}
}

// Check returns remaining lockout seconds for an IP (0 = allowed).
func (lt *LoginThrottle) Check(ip string) int {
	now := time.Now()
	lt.mu.Lock()
	defer lt.mu.Unlock()

	until := lt.lockUntil[ip]
	if lt.globalLockUntil.After(until) {
		until = lt.globalLockUntil
	}

	if until.After(now) {
		return int(math.Ceil(until.Sub(now).Seconds()))
	}
	return 0
}

// Failure records a login failure and returns newly imposed lockout seconds (0 = none).
func (lt *LoginThrottle) Failure(ip string) int {
	now := time.Now()
	lt.mu.Lock()
	defer lt.mu.Unlock()

	lt.gcLocked(now)

	cutoff := now.Add(-lt.window)
	dq := lt.fails[ip]
	validIdx := 0
	for validIdx < len(dq) && dq[validIdx].Before(cutoff) {
		validIdx++
	}
	if validIdx > 0 {
		dq = dq[validIdx:]
	}
	dq = append(dq, now)
	lt.fails[ip] = dq

	// Track global failures
	gValid := 0
	for gValid < len(lt.globalFails) && lt.globalFails[gValid].Before(cutoff) {
		gValid++
	}
	if gValid > 0 {
		lt.globalFails = lt.globalFails[gValid:]
	}
	lt.globalFails = append(lt.globalFails, now)

	if len(lt.globalFails) >= lt.globalMax {
		lt.globalLockUntil = now.Add(lt.globalLock)
		lt.globalFails = nil
		log.Printf("[Security] Global password-failure ceiling hit: pausing all logins for %v", lt.globalLock)
	}

	if len(dq) >= lt.maxAttempts {
		strikes := lt.strikes[ip] + 1
		lt.strikes[ip] = strikes

		multiplier := math.Pow(2, float64(strikes-1))
		lockSec := math.Min(lt.baseLock.Seconds()*multiplier, lt.maxLock.Seconds())
		lockDuration := time.Duration(lockSec * float64(time.Second))

		lt.lockUntil[ip] = now.Add(lockDuration)
		delete(lt.fails, ip)
		log.Printf("[Security] Login lockout for %s: %ds (strike %d)", ip, int(lockSec), strikes)
		return int(lockSec)
	}

	return 0
}

// Success resets failed counters and strikes for an IP upon successful authentication.
func (lt *LoginThrottle) Success(ip string) {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	delete(lt.fails, ip)
	delete(lt.strikes, ip)
	delete(lt.lockUntil, ip)
}

// ResetIP is an alias for Success.
func (lt *LoginThrottle) ResetIP(ip string) {
	lt.Success(ip)
}

func (lt *LoginThrottle) gcLocked(now time.Time) {
	if len(lt.fails) > 5000 {
		for ip, dq := range lt.fails {
			if len(dq) == 0 || now.Sub(dq[len(dq)-1]) > lt.window {
				delete(lt.fails, ip)
			}
		}
	}
	if len(lt.lockUntil) > 5000 {
		for ip, t := range lt.lockUntil {
			if t.Before(now) {
				delete(lt.lockUntil, ip)
				delete(lt.strikes, ip)
			}
		}
	}
}

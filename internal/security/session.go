package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"sync"
	"time"
)

// SessionStore maintains ephemeral random bearer tokens in RAM hashed with SHA-256.
type SessionStore struct {
	mu          sync.Mutex
	ttl         time.Duration
	maxSessions int
	sessions    map[string]time.Time
}

// NewSessionStore creates a new SessionStore.
func NewSessionStore(ttlHours float64, maxSessions int) *SessionStore {
	if ttlHours <= 0 {
		ttlHours = 12.0
	}
	if maxSessions <= 0 {
		maxSessions = 200
	}
	return &SessionStore{
		ttl:         time.Duration(ttlHours * float64(time.Hour)),
		maxSessions: maxSessions,
		sessions:    make(map[string]time.Time),
	}
}

// TTL returns session TTL duration.
func (ss *SessionStore) TTL() time.Duration {
	return ss.ttl
}

func (ss *SessionStore) digest(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// Create generates a secure URL-safe 32-byte token and records its hash until expiration.
func (ss *SessionStore) Create() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	token := base64.RawURLEncoding.EncodeToString(b)

	now := time.Now()
	exp := now.Add(ss.ttl)
	hashKey := ss.digest(token)

	ss.mu.Lock()
	defer ss.mu.Unlock()

	// Clean expired
	for k, v := range ss.sessions {
		if v.Before(now) {
			delete(ss.sessions, k)
		}
	}

	// Evict oldest if full
	for len(ss.sessions) >= ss.maxSessions {
		var oldestKey string
		var oldestTime time.Time
		for k, v := range ss.sessions {
			if oldestKey == "" || v.Before(oldestTime) {
				oldestKey = k
				oldestTime = v
			}
		}
		delete(ss.sessions, oldestKey)
	}

	ss.sessions[hashKey] = exp
	return token
}

// Validate verifies whether token exists and has not expired.
func (ss *SessionStore) Validate(token string) bool {
	if token == "" || len(token) > 128 {
		return false
	}
	hashKey := ss.digest(token)

	now := time.Now()
	ss.mu.Lock()
	defer ss.mu.Unlock()

	exp, ok := ss.sessions[hashKey]
	if !ok {
		return false
	}
	if exp.Before(now) {
		delete(ss.sessions, hashKey)
		return false
	}
	return true
}

// Revoke immediately removes a token from memory.
func (ss *SessionStore) Revoke(token string) {
	if token == "" {
		return
	}
	hashKey := ss.digest(token)
	ss.mu.Lock()
	defer ss.mu.Unlock()
	delete(ss.sessions, hashKey)
}

package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"wgstatus/internal/config"
)

const SessionCookie = "wgstatus_session"

var hostRegex = regexp.MustCompile(`^[A-Za-z0-9.\-]+(:\d{1,5})?$|^\[[0-9A-Fa-f:.]+\](:\d{1,5})?$`)

// Security wires together all rate limits, throttles, session stores, and HTTP middlewares.
type Security struct {
	Cfg           *config.Config
	Limiter       *SlidingWindowLimiter
	LoginThrottle *LoginThrottle
	Sessions      *SessionStore
	Streams       *StreamGuard
}

// NewSecurity instantiates the security suite based on the supplied configuration.
func NewSecurity(cfg *config.Config) *Security {
	return &Security{
		Cfg:     cfg,
		Limiter: NewSlidingWindowLimiter(20000),
		LoginThrottle: NewLoginThrottle(
			cfg.LoginMaxAttempts,
			600.0,
			cfg.LoginLockout.Seconds(),
			cfg.LoginMaxLockout.Seconds(),
			cfg.LoginGlobalMax,
			60.0,
		),
		Sessions: NewSessionStore(12.0, 200),
		Streams:  NewStreamGuard(cfg.MaxStreamsPerIP, cfg.MaxStreamsTotal),
	}
}

// ClientIP resolves the remote IP address, taking trusted reverse proxies into account.
func (s *Security) ClientIP(r *http.Request) string {
	remote := r.RemoteAddr
	host, _, err := net.SplitHostPort(remote)
	if err == nil {
		remote = host
	}

	remoteIP := net.ParseIP(remote)
	if remoteIP == nil {
		return "0.0.0.0"
	}

	if len(s.Cfg.TrustedProxies) > 0 && ipInNets(remoteIP, s.Cfg.TrustedProxies) {
		xff := r.Header.Get("X-Forwarded-For")
		if xff != "" {
			parts := strings.Split(xff, ",")
			for i := len(parts) - 1; i >= 0; i-- {
				hop := strings.TrimSpace(parts[i])
				hopIP := net.ParseIP(hop)
				if hopIP == nil {
					break
				}
				if !ipInNets(hopIP, s.Cfg.TrustedProxies) {
					return hop
				}
			}
		}
	}

	return remote
}

func ipInNets(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// IsIPAllowed checks if an IP is admitted by the WG_ALLOWED_NETWORKS CIDR list.
func (s *Security) IsIPAllowed(ipStr string) bool {
	if len(s.Cfg.AllowedNetworks) == 0 {
		return true
	}
	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		return false
	}
	return ipInNets(parsed, s.Cfg.AllowedNetworks)
}

// IsHTTPS returns true if the incoming request was made over TLS.
func (s *Security) IsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	remote := r.RemoteAddr
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	remoteIP := net.ParseIP(remote)
	if remoteIP != nil && len(s.Cfg.TrustedProxies) > 0 && ipInNets(remoteIP, s.Cfg.TrustedProxies) {
		return strings.ToLower(r.Header.Get("X-Forwarded-Proto")) == "https"
	}
	return false
}

// OriginOK verifies same-origin or configured cross-origin rules for mutating requests and WebSockets.
func (s *Security) OriginOK(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin != "" {
		originNorm := strings.ToLower(strings.TrimRight(origin, "/"))
		if s.Cfg.AllowedOrigins[originNorm] {
			return true
		}
		u, err := url.Parse(origin)
		if err != nil {
			return false
		}
		host := strings.ToLower(r.Host)
		return u.Host != "" && strings.ToLower(u.Host) == host
	}

	secFetchSite := r.Header.Get("Sec-Fetch-Site")
	if secFetchSite != "" {
		return secFetchSite == "same-origin" || secFetchSite == "none"
	}

	return true // Non-browser clients (curl, scripts)
}

// PasswordsMatch compares candidate password with configured password in constant time.
func (s *Security) PasswordsMatch(candidate string) bool {
	candHash := sha256.Sum256([]byte(candidate))
	passHash := sha256.Sum256([]byte(s.Cfg.Password))
	return hmac.Equal(candHash[:], passHash[:])
}

// IsAuthorized verifies whether a request holds a valid session cookie or X-Server-Password header.
func (s *Security) IsAuthorized(r *http.Request) bool {
	if s.Cfg.PasswordIsDefault && !s.Cfg.AllowDefaultPassword {
		return false
	}

	cookie, err := r.Cookie(SessionCookie)
	if err == nil && cookie != nil && s.Sessions.Validate(cookie.Value) {
		return true
	}

	hdr := r.Header.Get("X-Server-Password")
	if hdr != "" {
		ip := s.ClientIP(r)
		if s.LoginThrottle.Check(ip) > 0 {
			return false
		}
		if s.PasswordsMatch(hdr) {
			s.LoginThrottle.Success(ip)
			return true
		}
		s.LoginThrottle.Failure(ip)
		log.Printf("[Security] Bad X-Server-Password header from %s", ip)
	}

	return false
}

// Login attempts password authentication.
func (s *Security) Login(ip, candidate string) (string, int, string) {
	if s.Cfg.PasswordIsDefault && !s.Cfg.AllowDefaultPassword {
		return "", http.StatusServiceUnavailable, "Login disabled: set SERVER_PASSWORD (default password is not allowed)"
	}

	wait := s.LoginThrottle.Check(ip)
	if wait > 0 {
		return "", http.StatusTooManyRequests, fmt.Sprintf("Demasiados intentos fallidos. Intenta de nuevo en %ds", wait)
	}

	if s.PasswordsMatch(candidate) {
		s.LoginThrottle.Success(ip)
		log.Printf("[Security] Successful login from %s", ip)
		return s.Sessions.Create(), http.StatusOK, ""
	}

	lock := s.LoginThrottle.Failure(ip)
	log.Printf("[Security] Failed login attempt from %s", ip)
	if lock > 0 {
		return "", http.StatusTooManyRequests, fmt.Sprintf("Demasiados intentos fallidos. Bloqueado por %ds", lock)
	}
	return "", http.StatusUnauthorized, "Contraseña de servidor incorrecta"
}

// SetSessionCookie sets HttpOnly Strict cookie.
func (s *Security) SetSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    token,
		Path:     "/",
		MaxAge:   int(s.Sessions.TTL().Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   s.IsHTTPS(r),
	})
}

// ClearSessionCookie invalidates the browser session cookie.
func (s *Security) ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
}

// WriteJSON sends a JSON response with status code.
func WriteJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// TooMany sends a standardized 429 response.
func TooMany(w http.ResponseWriter, retryAfter int, msg string) {
	if msg == "" {
		msg = "Too many requests"
	}
	w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	WriteJSON(w, http.StatusTooManyRequests, map[string]interface{}{
		"error":       msg,
		"retry_after": retryAfter,
	})
}

// Middlewares -------------------------------------------------------------

// SecurityHeaders applies strict HTTP response headers.
func (s *Security) SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		connect := "'self'"
		if hostRegex.MatchString(host) {
			connect += fmt.Sprintf(" ws://%s wss://%s", host, host)
		}

		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; "+
				"connect-src "+connect+"; "+
				"font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=(), usb=(), interest-cohort=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("X-Permitted-Cross-Domain-Policies", "none")

		if s.IsHTTPS(r) {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		if !strings.HasPrefix(r.URL.Path, "/static") && h.Get("Cache-Control") == "" {
			h.Set("Cache-Control", "no-store")
		}

		next.ServeHTTP(w, r)
	})
}

// IPAndOriginGuard validates source network, Host header, CSRF, and global rate limits.
func (s *Security) IPAndOriginGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := s.ClientIP(r)

		// 1. IP allowlist
		if !s.IsIPAllowed(ip) {
			log.Printf("[Security] Blocked request from %s (not in WG_ALLOWED_NETWORKS)", ip)
			WriteJSON(w, http.StatusForbidden, map[string]string{"error": "Forbidden"})
			return
		}

		// 2. Host allowlist
		if len(s.Cfg.AllowedHosts) > 0 {
			host := strings.ToLower(r.Host)
			hostname := host
			if h, _, err := net.SplitHostPort(host); err == nil {
				hostname = h
			}
			if !s.Cfg.AllowedHosts[host] && !s.Cfg.AllowedHosts[hostname] {
				WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid Host header"})
				return
			}
		}

		// 3. Same-origin on mutating requests or WebSocket endpoint
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if !s.OriginOK(r) {
				log.Printf("[Security] Cross-origin %s %s rejected from %s", r.Method, r.URL.Path, ip)
				WriteJSON(w, http.StatusForbidden, map[string]string{"error": "Cross-origin request rejected"})
				return
			}
		}
		if r.URL.Path == "/ws" && !s.OriginOK(r) {
			log.Printf("[Security] Cross-origin WebSocket rejected from %s", ip)
			WriteJSON(w, http.StatusForbidden, map[string]string{"error": "Cross-origin request rejected"})
			return
		}

		// 4. Global sliding-window rate limit (skip /health)
		if r.URL.Path != "/health" {
			ok, retry := s.Limiter.Hit("global:"+ip, s.Cfg.RateGlobal, time.Minute)
			if !ok {
				TooMany(w, retry, "Too many requests")
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// RequireAuth enforces valid session cookie or X-Server-Password header.
func (s *Security) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.IsAuthorized(r) {
			WriteJSON(w, http.StatusUnauthorized, map[string]interface{}{
				"error":         "Unauthorized: se requiere la contraseña del servidor",
				"auth_required": true,
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireAuthForWrites enforces auth only if ProtectWrites is enabled.
func (s *Security) RequireAuthForWrites(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.Cfg.ProtectWrites && !s.IsAuthorized(r) {
			WriteJSON(w, http.StatusUnauthorized, map[string]interface{}{
				"error":         "Unauthorized: se requiere la contraseña del servidor",
				"auth_required": true,
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RateLimit creates an endpoint-specific sliding-window rate limit middleware.
func (s *Security) RateLimit(bucket string, limit int, window time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := s.ClientIP(r)
			ok, retry := s.Limiter.Hit(bucket+":"+ip, limit, window)
			if !ok {
				TooMany(w, retry, "Too many requests")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

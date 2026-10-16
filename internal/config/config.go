package config

import (
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultPort           = 5010 // Production port
	DefaultHost           = "0.0.0.0"
	DefaultDevice         = "wg0"
	DefaultPollInterval   = 1 * time.Second
	DefaultFlushInterval  = 600 * time.Second
	LegacyDefaultPassword = "changeme-admin-password"
)

type Config struct {
	Port                   int
	Host                   string
	Device                 string
	Password               string
	PasswordIsDefault      bool
	AllowDefaultPassword   bool
	ProtectWrites          bool
	PollInterval           time.Duration
	FlushInterval          time.Duration
	DataDir                string
	IspCacheFile           string
	AllowedNetworks        []*net.IPNet
	TrustedProxies         []*net.IPNet
	AllowedHosts           map[string]bool
	AllowedOrigins         map[string]bool
	RateGlobal             int
	RateHeavy              int
	RateWrite              int
	LoginMaxAttempts       int
	LoginLockout           time.Duration
	LoginMaxLockout        time.Duration
	LoginGlobalMax         int
	MaxStreamsPerIP        int
	MaxStreamsTotal        int
	PingEnabled            bool
	PingMaxHandshakeAgeSec float64
	PingTimeout            time.Duration
	ConfFile               string
	MockMode               bool
}

func Load() *Config {
	cfg := &Config{
		Port:                   getEnvInt("PORT", DefaultPort),
		Host:                   getEnv("HOST", DefaultHost),
		Device:                 getEnv("WG_DEVICE", DefaultDevice),
		ConfFile:               getEnv("WG_CONF_FILE", ""),
		ProtectWrites:          getEnvBool("WG_PROTECT_WRITES", true),
		PollInterval:           getEnvDurationSec("WG_POLL_INTERVAL", DefaultPollInterval),
		FlushInterval:          getEnvDurationSec("WG_FLUSH_INTERVAL", DefaultFlushInterval),
		DataDir:                getEnv("WG_DATA_DIR", "data"),
		IspCacheFile:           getEnv("WG_ISP_CACHE_FILE", "isp_data.csv"),
		RateGlobal:             getEnvInt("WG_RATE_LIMIT_GLOBAL", 600),
		RateHeavy:              getEnvInt("WG_RATE_LIMIT_HEAVY", 20),
		RateWrite:              getEnvInt("WG_RATE_LIMIT_WRITE", 30),
		LoginMaxAttempts:       getEnvInt("WG_LOGIN_MAX_ATTEMPTS", 5),
		LoginLockout:           getEnvDurationSec("WG_LOGIN_LOCKOUT", 60*time.Second),
		LoginMaxLockout:        getEnvDurationSec("WG_LOGIN_MAX_LOCKOUT", 3600*time.Second),
		LoginGlobalMax:         getEnvInt("WG_LOGIN_GLOBAL_MAX", 40),
		MaxStreamsPerIP:        getEnvInt("WG_MAX_STREAMS_PER_IP", 6),
		MaxStreamsTotal:        getEnvInt("WG_MAX_STREAMS_TOTAL", 150),
		PingEnabled:            getEnvBool("WG_PING_ENABLED", true),
		PingMaxHandshakeAgeSec: getEnvFloat("WG_PING_MAX_HANDSHAKE_AGE", 5.0),
		PingTimeout:            getEnvDurationSec("WG_PING_TIMEOUT", 2*time.Second),
		MockMode:               getEnvBool("WG_MOCK", false),
	}

	cfg.Password, cfg.PasswordIsDefault = resolvePassword()
	cfg.AllowDefaultPassword = getEnvBool("WG_ALLOW_DEFAULT_PASSWORD", true)

	cfg.AllowedNetworks = parseCIDRList(getEnv("WG_ALLOWED_NETWORKS", ""))
	cfg.TrustedProxies = parseCIDRList(getEnv("WG_TRUSTED_PROXIES", ""))
	cfg.AllowedHosts = parseStringSet(getEnv("WG_ALLOWED_HOSTS", ""))
	cfg.AllowedOrigins = parseStringSet(getEnv("WG_ALLOWED_ORIGINS", ""))

	if cfg.PasswordIsDefault {
		log.Println("[WARNING] SECURITY: using the built-in default server password. Set SERVER_PASSWORD (or SERVER_PASSWORD_FILE) before exposing this dashboard to other subnets.")
	}

	return cfg
}

func resolvePassword() (string, bool) {
	if val := os.Getenv("SERVER_PASSWORD"); val != "" {
		return val, false
	}
	if val := os.Getenv("WGSTATUS_EXPORT_PASSWORD"); val != "" {
		return val, false
	}
	if path := os.Getenv("SERVER_PASSWORD_FILE"); path != "" {
		if content, err := os.ReadFile(path); err == nil {
			trimmed := strings.TrimSpace(string(content))
			if trimmed != "" {
				return trimmed, false
			}
		}
	}
	return LegacyDefaultPassword, true
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultVal
}

func getEnvFloat(key string, defaultVal float64) float64 {
	if val := os.Getenv(key); val != "" {
		if f, err := strconv.ParseFloat(val, 64); err == nil {
			return f
		}
	}
	return defaultVal
}

func getEnvBool(key string, defaultVal bool) bool {
	if val := os.Getenv(key); val != "" {
		val = strings.ToLower(strings.TrimSpace(val))
		return val == "1" || val == "true" || val == "yes" || val == "on"
	}
	return defaultVal
}

func getEnvDurationSec(key string, defaultVal time.Duration) time.Duration {
	if val := os.Getenv(key); val != "" {
		if f, err := strconv.ParseFloat(val, 64); err == nil {
			return time.Duration(f * float64(time.Second))
		}
	}
	return defaultVal
}

func parseCIDRList(raw string) []*net.IPNet {
	var list []*net.IPNet
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ';' }) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			if strings.Contains(part, ":") {
				part += "/128"
			} else {
				part += "/32"
			}
		}
		_, ipNet, err := net.ParseCIDR(part)
		if err == nil {
			list = append(list, ipNet)
		} else {
			log.Printf("[WARNING] Ignoring invalid CIDR %q: %v", part, err)
		}
	}
	return list
}

func parseStringSet(raw string) map[string]bool {
	set := make(map[string]bool)
	for _, part := range strings.Split(raw, ",") {
		part = strings.ToLower(strings.TrimSpace(part))
		if part != "" {
			set[part] = true
		}
	}
	return set
}

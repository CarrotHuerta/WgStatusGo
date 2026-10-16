package wireguard

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// FindWgConfFile locates wg0.conf safely in standard locations without modifying anything.
func FindWgConfFile(overridePath string) string {
	if overridePath != "" {
		if _, err := os.Stat(overridePath); err == nil {
			return overridePath
		}
	}

	envConf := os.Getenv("WG_CONF_FILE")
	if envConf != "" {
		if _, err := os.Stat(envConf); err == nil {
			return envConf
		}
	}

	candidates := []string{
		"/etc/wireguard/wg0.conf",
		"/etc/wireguard/wg.conf",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}

	// Search upward in current working directory hierarchy (for dev/testing)
	cwd, err := os.Getwd()
	if err == nil {
		curr := cwd
		for i := 0; i < 5; i++ {
			cand := filepath.Join(curr, "wg0.conf")
			if _, err := os.Stat(cand); err == nil {
				return cand
			}
			parent := filepath.Dir(curr)
			if parent == curr {
				break
			}
			curr = parent
		}
	}

	return ""
}

// ParseWgConfPeerNames parses peer names from comments in wg0.conf.
// It returns (namesByPublicKey, namesByTunnelIP).
//
// Expected structure in wg0.conf:
//
// ### Client Laptop
// [Peer]
// # PublicKey = DemoPublicKeyBase64Placeholder0000000000000=
// AllowedIPs = 10.20.0.2/32,fd42:42:42::2/128
func ParseWgConfPeerNames(confPath string) (map[string]string, map[string]string) {
	path := confPath
	if path == "" {
		path = FindWgConfFile("")
	}
	if path == "" {
		return make(map[string]string), make(map[string]string)
	}

	f, err := os.Open(path)
	if err != nil {
		return make(map[string]string), make(map[string]string)
	}
	defer f.Close()

	namesByPub := make(map[string]string)
	namesByIP := make(map[string]string)

	var currentName string
	inPeer := false

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineStr := strings.TrimSpace(scanner.Text())
		if lineStr == "" {
			continue
		}

		if strings.HasPrefix(lineStr, "#") {
			// Extract comment text, strip leading hashtags and "Client " prefix if present
			commentClean := strings.TrimSpace(strings.TrimLeft(lineStr, "#"))
			if strings.HasPrefix(strings.ToLower(commentClean), "client ") {
				commentClean = strings.TrimSpace(commentClean[7:])
			}
			if commentClean != "" {
				currentName = commentClean
			}
			continue
		}

		if strings.EqualFold(lineStr, "[peer]") {
			inPeer = true
			continue
		}

		if strings.HasPrefix(lineStr, "[") {
			inPeer = false
			currentName = ""
			continue
		}

		if inPeer && strings.Contains(lineStr, "=") {
			parts := strings.SplitN(lineStr, "=", 2)
			key := strings.ToLower(strings.TrimSpace(parts[0]))
			val := strings.TrimSpace(parts[1])

			switch key {
			case "publickey":
				if currentName != "" && val != "" {
					namesByPub[val] = currentName
				}
			case "allowedips":
				for _, part := range strings.Split(val, ",") {
					cleanPart := strings.TrimSpace(part)
					cleanIP := cleanPart
					if idx := strings.Index(cleanIP, "/"); idx != -1 {
						cleanIP = cleanIP[:idx]
					}
					if currentName != "" && cleanIP != "" {
						namesByIP[cleanIP] = currentName
					}
				}
			}
		}
	}

	return namesByPub, namesByIP
}

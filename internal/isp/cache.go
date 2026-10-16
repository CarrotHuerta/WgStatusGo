package isp

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func IsPrivateOrInternalIP(ipStr string) bool {
	if ipStr == "" || ipStr == "(none)" || ipStr == "-" {
		return true
	}
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

type Cache struct {
	csvPath    string
	apiTimeout time.Duration
	mu         sync.RWMutex
	cache      map[string]string
	pending    map[string]bool
	queue      chan string
	httpClient *http.Client
}

type IspCache = Cache

func NewIspCache(csvPath string) *IspCache {
	return NewCache(csvPath, 5*time.Second)
}

func NewCache(csvPath string, apiTimeout time.Duration) *Cache {
	c := &Cache{
		csvPath:    csvPath,
		apiTimeout: apiTimeout,
		cache:      make(map[string]string),
		pending:    make(map[string]bool),
		queue:      make(chan string, 1000),
		httpClient: &http.Client{Timeout: apiTimeout},
	}
	c.loadCSV()
	go c.worker()
	return c
}

func (c *Cache) loadCSV() {
	c.mu.Lock()
	defer c.mu.Unlock()

	dir := filepath.Dir(c.csvPath)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}

	f, err := os.Open(c.csvPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Create new CSV with header
			if nf, cerr := os.Create(c.csvPath); cerr == nil {
				w := csv.NewWriter(nf)
				_ = w.Write([]string{"ip", "isp"})
				w.Flush()
				nf.Close()
			}
		}
		return
	}
	defer f.Close()

	reader := csv.NewReader(f)
	isFirst := true
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		if isFirst {
			isFirst = false
			continue
		}
		if len(record) >= 2 {
			ip := strings.TrimSpace(record[0])
			isp := CleanISPName(record[1])
			if ip != "" && isp != "" {
				c.cache[ip] = isp
			}
		}
	}
}

func (c *Cache) Get(ipStr string) string {
	clean := strings.TrimSpace(ipStr)
	if clean == "" || clean == "(none)" || clean == "-" {
		return "-"
	}
	if IsPrivateOrInternalIP(clean) {
		return "INTERNAL"
	}

	c.mu.RLock()
	if val, ok := c.cache[clean]; ok {
		c.mu.RUnlock()
		return val
	}
	c.mu.RUnlock()

	c.mu.Lock()
	if !c.pending[clean] {
		c.pending[clean] = true
		select {
		case c.queue <- clean:
		default:
		}
	}
	c.mu.Unlock()

	return "Resolving..."
}

func (c *Cache) worker() {
	for ip := range c.queue {
		resolved := c.resolveFromAPI(ip)
		c.mu.Lock()
		cleanName := CleanISPName(resolved)
		c.cache[ip] = cleanName
		delete(c.pending, ip)
		c.appendCSV(ip, cleanName)
		c.mu.Unlock()
	}
}

type ipinfoResponse struct {
	Org     string `json:"org"`
	Company struct {
		Name string `json:"name"`
	} `json:"company"`
}

func (c *Cache) resolveFromAPI(ip string) string {
	url := fmt.Sprintf("https://ipinfo.io/%s/json", ip)
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return "Unknown ISP"
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		log.Println("[WARNING] ipinfo.io rate limit reached")
		return "Rate Limited"
	}
	if resp.StatusCode != http.StatusOK {
		return "Unknown ISP"
	}

	var data ipinfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "Unknown ISP"
	}

	org := data.Org
	if org == "" {
		org = data.Company.Name
	}
	if org != "" {
		return CleanISPName(org)
	}
	return "Unknown ISP"
}

func (c *Cache) appendCSV(ip, ispName string) {
	f, err := os.OpenFile(c.csvPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	w := csv.NewWriter(f)
	_ = w.Write([]string{ip, ispName})
	w.Flush()
}

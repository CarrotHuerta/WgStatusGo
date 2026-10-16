package wireguard

import (
	"fmt"
	"math/rand"
	"runtime"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
)

type RawPeer struct {
	PublicKey           string
	Endpoint            string
	AllowedIPs          string
	LatestHandshake     time.Time
	ReceiveBytes        int64
	TransmitBytes       int64
	PersistentKeepalive int
}

type DeviceReader interface {
	ReadPeers() ([]RawPeer, error)
	IsMock() bool
	Close() error
}

type WgctrlReader struct {
	client     *wgctrl.Client
	deviceName string
}

func NewWgctrlReader(deviceName string) (*WgctrlReader, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	// Verify device exists
	_, err = c.Device(deviceName)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("device %s not accessible via wgctrl: %w", deviceName, err)
	}
	return &WgctrlReader{client: c, deviceName: deviceName}, nil
}

func (r *WgctrlReader) ReadPeers() ([]RawPeer, error) {
	dev, err := r.client.Device(r.deviceName)
	if err != nil {
		return nil, err
	}
	raw := make([]RawPeer, 0, len(dev.Peers))
	for _, p := range dev.Peers {
		ep := ""
		if p.Endpoint != nil {
			ep = p.Endpoint.String()
		}
		var ips []string
		for _, ipnet := range p.AllowedIPs {
			ips = append(ips, ipnet.String())
		}
		raw = append(raw, RawPeer{
			PublicKey:           p.PublicKey.String(),
			Endpoint:            ep,
			AllowedIPs:          strings.Join(ips, ", "),
			LatestHandshake:     p.LastHandshakeTime,
			ReceiveBytes:        p.ReceiveBytes,
			TransmitBytes:       p.TransmitBytes,
			PersistentKeepalive: int(p.PersistentKeepaliveInterval.Seconds()),
		})
	}
	return raw, nil
}

func (r *WgctrlReader) IsMock() bool {
	return false
}

func (r *WgctrlReader) Close() error {
	if r.client != nil {
		return r.client.Close()
	}
	return nil
}

// ---------------------------------------------------------------------------
// Mock Reader (for Windows dev or when WireGuard is not installed)
// ---------------------------------------------------------------------------
type MockReader struct {
	peers []RawPeer
}

func NewMockReader() *MockReader {
	now := time.Now()
	basePeers := []RawPeer{
		{
			PublicKey:       "K2A9a3bK81xQeXN0h2DemoKeyMacBookProM3Max001=",
			Endpoint:        "198.51.100.24:54321",
			AllowedIPs:      "10.20.0.2/32",
			LatestHandshake: now.Add(-12 * time.Second),
			ReceiveBytes:    26771456,
			TransmitBytes:   26738688,
		},
		{
			PublicKey:       "L9bZc1mP44dTyWO1k5DemoKeyEdgeGatewayScl0002=",
			Endpoint:        "203.0.113.88:49152",
			AllowedIPs:      "10.20.0.3/32",
			LatestHandshake: now.Add(-32 * time.Second),
			ReceiveBytes:    267675648,
			TransmitBytes:   1911361536,
		},
		{
			PublicKey:       "P7eNm8qW92zRtUV2m9DemoKeyRemoteDevThinkPad3=",
			Endpoint:        "192.0.2.45:51820",
			AllowedIPs:      "10.20.0.4/32",
			LatestHandshake: now.Add(-55 * time.Second),
			ReceiveBytes:    200065024,
			TransmitBytes:   8407482368,
		},
		{
			PublicKey:       "R3tUk4vX15bXyZA3n2DemoKeyMobileIosRoaming04=",
			Endpoint:        "198.51.100.99:60112",
			AllowedIPs:      "10.20.0.5/32",
			LatestHandshake: now.Add(-75 * time.Second),
			ReceiveBytes:    2340823040,
			TransmitBytes:   15730376704,
		},
		{
			PublicKey:       "W6vPn2yQ67cVuTS4r8DemoKeyBranchValparaiso05=",
			Endpoint:        "203.0.113.15:55110",
			AllowedIPs:      "10.20.0.6/32",
			LatestHandshake: now.Add(-185 * time.Second),
			ReceiveBytes:    316817408,
			TransmitBytes:   30697963520,
		},
	}
	return &MockReader{peers: basePeers}
}

func (m *MockReader) ReadPeers() ([]RawPeer, error) {
	now := time.Now()
	for i := range m.peers {
		if i < 3 {
			// Simulate fresh traffic
			rxAdd := int64(rand.Intn(150000) + 10000)
			txAdd := int64(rand.Intn(400000) + 20000)
			m.peers[i].ReceiveBytes += rxAdd
			m.peers[i].TransmitBytes += txAdd
			if rand.Float64() < 0.25 {
				m.peers[i].LatestHandshake = now.Add(-time.Duration(rand.Intn(4)) * time.Second)
			}
		}
	}
	return m.peers, nil
}

func (m *MockReader) IsMock() bool {
	return true
}

func (m *MockReader) Close() error {
	return nil
}

func CreateDeviceReader(deviceName string, forceMock bool) DeviceReader {
	if forceMock || runtime.GOOS != "linux" {
		return NewMockReader()
	}
	reader, err := NewWgctrlReader(deviceName)
	if err != nil {
		return NewMockReader()
	}
	return reader
}

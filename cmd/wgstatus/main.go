package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"wgstatus/internal/analytics"
	"wgstatus/internal/config"
	"wgstatus/internal/history"
	"wgstatus/internal/isp"
	"wgstatus/internal/ping"
	"wgstatus/internal/security"
	"wgstatus/internal/server"
	"wgstatus/internal/wireguard"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Println("=================================================================")
	log.Println("  WgStatus (Go Edition) - High Performance WireGuard Dashboard   ")
	log.Println("=================================================================")

	cfg := config.Load()
	log.Printf("[Config] Host: %s, Port: %d (Testing Port)", cfg.Host, cfg.Port)
	log.Printf("[Config] WireGuard Device: %s, Mock: %v", cfg.Device, cfg.MockMode)
	log.Printf("[Config] Poll Interval: %v, Flush Interval: %v", cfg.PollInterval, cfg.FlushInterval)

	// Context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. Initialize components
	ispCache := isp.NewIspCache(cfg.IspCacheFile)
	historyMgr := history.NewHistoryManager(".", cfg.FlushInterval.Seconds(), 60)
	analyticsMgr := analytics.NewAnalyticsManager(".", cfg.FlushInterval.Seconds())
	deviceReader := wireguard.CreateDeviceReader(cfg.Device, cfg.MockMode)

	analyticsMgr.Start(deviceReader.IsMock())

	pinger := ping.NewPinger(deviceReader.IsMock(), cfg.PingTimeout, cfg.PingMaxHandshakeAgeSec)
	monitor := server.NewWireGuardMonitor(deviceReader, ispCache, historyMgr, analyticsMgr, pinger, cfg.PollInterval, 120, cfg.ConfFile)
	sec := security.NewSecurity(cfg)

	srv := server.NewServer(monitor, historyMgr, analyticsMgr, sec)
	router := srv.SetupRouter()

	// 2. Start WireGuard monitor background loop
	monitor.Start(ctx)

	// 3. HTTP Server configuration
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// 4. Handle OS signals for graceful shutdown & SSD flush
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		sig := <-sigChan
		log.Printf("[Shutdown] Received signal: %v. Initiating clean exit...", sig)
		cancel()

		// Shutdown HTTP server
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("[Shutdown] HTTP server error: %v", err)
		}

		// Flush in-memory state to disk
		log.Println("[Shutdown] Flushing history and analytics to SSD...")
		historyMgr.Flush(true)
		analyticsMgr.Flush(true)
		_ = deviceReader.Close()

		log.Println("[Shutdown] Clean exit complete.")
		os.Exit(0)
	}()

	log.Printf("[HTTP] Server listening on http://%s (Port %d)", addr, cfg.Port)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("[HTTP] Fatal server error: %v", err)
	}
}

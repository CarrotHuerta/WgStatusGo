package server

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"wgstatus/web"
)

// SetupRouter creates the Chi HTTP router with security middlewares and route bindings.
func (s *Server) SetupRouter() http.Handler {
	r := chi.NewRouter()

	// Base middlewares
	r.Use(middleware.Recoverer)
	r.Use(s.sec.SecurityHeaders)
	r.Use(s.sec.IPAndOriginGuard)

	// Static assets
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(web.StaticFS())))

	// Frontend root
	r.Get("/", s.HandleIndex)

	// Real-time telemetry endpoints
	r.Get("/status", s.HandleStatus)
	r.Get("/summary", s.HandleSummary)
	r.Get("/api/summary", s.HandleSummary)
	r.Get("/api/live", s.HandleLive)

	// Bandwidth endpoints
	r.Get("/bandwidth", s.HandleBandwidth)
	r.Get("/bandwidth/total", s.HandleBandwidthTotal)
	r.Get("/bandwidth/history", s.HandleBandwidthHistory)

	// Historical sessions and peer details
	r.Get("/api/history", s.HandlePeerHistory)

	// Traffic analytics
	r.With(s.sec.RateLimit("analytics", 60, time.Minute)).Get("/api/analytics", s.HandleAnalytics)

	// Health check
	r.Get("/health", s.HandleHealth)

	// Streaming push
	r.Get("/ws", s.HandleWebSocket)
	r.Get("/api/stream", s.HandleSSE)

	// Authentication
	r.Post("/api/auth/login", s.HandleLogin)
	r.Post("/api/export/verify-password", s.HandleLogin)
	r.Get("/api/auth/status", s.HandleAuthStatus)
	r.Post("/api/auth/logout", s.HandleLogout)

	// Mutating operations (guarded by write rate limit + write auth)
	writeGuard := []func(http.Handler) http.Handler{
		s.sec.RateLimit("write", s.sec.Cfg.RateWrite, time.Minute),
		s.sec.RequireAuthForWrites,
	}
	r.With(writeGuard...).Post("/api/alias", s.HandleAlias)
	r.With(writeGuard...).Post("/api/flush", s.HandleFlush)

	// Export endpoints (guarded by heavy rate limit + strict auth)
	heavyExportGuard := []func(http.Handler) http.Handler{
		s.sec.RateLimit("heavy", s.sec.Cfg.RateHeavy, time.Minute),
		s.sec.RequireAuth,
	}
	r.With(heavyExportGuard...).Get("/api/export/peers", s.HandleExportPeers)
	r.With(heavyExportGuard...).Get("/api/export/sessions", s.HandleExportSessions)
	r.With(heavyExportGuard...).Get("/api/export/report", s.HandleExportReport)
	r.With(heavyExportGuard...).Get("/api/export/analytics", s.HandleExportAnalytics)

	return r
}

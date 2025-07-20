package cmd

import (
	"context"
	"crypto/tls"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/heyayush09/glyph-proxy/internal/auth"
	"github.com/heyayush09/glyph-proxy/internal/config"
	"github.com/heyayush09/glyph-proxy/internal/logging"
	"github.com/heyayush09/glyph-proxy/internal/middleware"
	"github.com/heyayush09/glyph-proxy/internal/policy"
	"github.com/heyayush09/glyph-proxy/internal/proxy"
	"github.com/heyayush09/glyph-proxy/internal/session"
	"github.com/spf13/cobra"
)

var (
	configFile string
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the glyph reverse proxy server",
	Long:  `Start the glyph reverse proxy server with OIDC authentication and fine-grained access control.`,
	Run:   runServe,
}

func init() {
	serveCmd.Flags().StringVarP(&configFile, "config", "c", "config.yaml", "Path to configuration file")
	rootCmd.AddCommand(serveCmd)
}

func runServe(cmd *cobra.Command, args []string) {
	logging.Log.Info("🚀 Starting glyph-proxy server...")

	// Load configuration
	atomicCfg, err := config.LoadConfig(configFile)
	if err != nil {
		logging.Log.Fatalf("Failed to load config: %v", err)
	}
	logging.Log.Info("Configuration loaded successfully")

	cfg := atomicCfg.Load()

	// Initialize session store
	if err := session.InitSessionStore(); err != nil {
		logging.Log.Fatalf("Failed to initialize session store: %v", err)
	}
	logging.Log.Info("Session store initialized")

	// Initialize OIDC manager
	ctx := context.Background()
	oidcManager, err := auth.NewOIDCManager(ctx, &cfg.OIDC)
	if err != nil {
		logging.Log.Fatalf("Failed to initialize OIDC: %v", err)
	}
	logging.Log.Info("OIDC manager initialized")

	// Initialize proxy engine
	proxyEngine := proxy.New(atomicCfg)

	// Set up routes
	mux := http.NewServeMux()
	
	// Auth routes (public, no auth required)
	mux.HandleFunc("/auth/login", oidcManager.LoginHandler)
	mux.HandleFunc("/auth/callback", oidcManager.CallbackHandler)
	mux.HandleFunc("/auth/logout", oidcManager.LogoutHandler)
	
	// Health check (public)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	
	// Metrics endpoint (public for now, could be protected later)
	mux.Handle("/metrics", middleware.MetricsHandler())
	
	// Main proxy handler with middleware chain and policy enforcement
	protectedHandler := session.Middleware(
		middleware.Logging(
			oidcManager.RequireAuth(
				createPolicyEnforcer(atomicCfg, proxyEngine.Handler()),
			),
		),
	)
	mux.Handle("/", protectedHandler)

	// Create server
	server := &http.Server{
		Addr:    cfg.Listen,
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server
	go func() {
		logging.Log.Infof("🌐 Server listening on %s", cfg.Listen)

		if cfg.TLS.Mode == "auto" || cfg.TLS.Mode == "manual" {
			if cfg.TLS.Mode == "auto" {
				logging.Log.Info("🔒 TLS: Auto mode (development certificates)")
			} else {
				logging.Log.Infof("🔒 TLS: Manual mode (cert: %s, key: %s)", cfg.TLS.CertFile, cfg.TLS.KeyFile)
			}

			if err := server.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile); err != nil && err != http.ErrServerClosed {
				logging.Log.Fatalf("HTTPS server failed: %v", err)
			}
		} else {
			logging.Log.Warn("⚠️  TLS: Disabled (not recommended for production)")
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logging.Log.Fatalf("HTTP server failed: %v", err)
			}
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logging.Log.Info("\n🛑 Shutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logging.Log.Errorf("Server forced to shutdown: %v", err)
	}

	logging.Log.Info("✅ Server exited")
}

// createPolicyEnforcer wraps the proxy handler with policy enforcement
func createPolicyEnforcer(atomicCfg *config.AtomicConfig, proxyHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := atomicCfg.Load()
		
		// Find the route policy for this request
		host := r.Host
		route, exists := cfg.Routes[host]
		if !exists {
			http.Error(w, "Route not found", http.StatusNotFound)
			return
		}
		
		// Create policy for this route
		routePolicy := policy.RoutePolicy{
			AllowedUsers:  route.AllowedUsers,
			AllowedGroups: route.AllowedGroups,
		}
		
		// Apply policy middleware and then proxy
		policyMiddleware := policy.Middleware(routePolicy, proxyHandler)
		policyMiddleware.ServeHTTP(w, r)
	})
}

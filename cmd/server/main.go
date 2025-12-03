package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/nexus-cloaker/cloaker/internal/api"
	"github.com/nexus-cloaker/cloaker/internal/config"
	"github.com/nexus-cloaker/cloaker/internal/database"
	"github.com/nexus-cloaker/cloaker/internal/detection"
	"github.com/nexus-cloaker/cloaker/internal/proxy"
)

func main() {
	// Parse flags
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	port := flag.Int("port", 8080, "Server port")
	adminPort := flag.Int("admin-port", 8081, "Admin dashboard port")
	flag.Parse()

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Printf("Warning: Could not load config file, using defaults: %v", err)
		cfg = config.Default()
	}

	// Check for PORT environment variable (App Platform uses this)
	if envPort := os.Getenv("PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil {
			cfg.Server.Port = p
			cfg.Server.AdminPort = p // Use same port for both in App Platform
			log.Printf("Using PORT from environment: %d", p)
		}
	}

	// Override with flags if provided
	if *port != 8080 {
		cfg.Server.Port = *port
	}
	if *adminPort != 8081 {
		cfg.Server.AdminPort = *adminPort
	}

	// Initialize database
	db, err := database.New(cfg.Database)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Run migrations
	if err := db.Migrate(); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	// Initialize detection engine
	detector, err := detection.NewEngine(cfg.Detection)
	if err != nil {
		log.Fatalf("Failed to initialize detection engine: %v", err)
	}

	// Initialize proxy
	proxyServer := proxy.New(cfg.Proxy, detector, db)

	// Initialize API server
	apiServer := api.New(cfg, db, detector)

	// Start servers
	errChan := make(chan error, 2)

	// Check if running in App Platform mode (single port)
	isAppPlatform := os.Getenv("PORT") != ""

	if isAppPlatform {
		// App Platform mode: run API server only (which includes dashboard and health)
		go func() {
			addr := fmt.Sprintf(":%d", cfg.Server.AdminPort)
			log.Printf("🚀 NEXUS Cloaker starting on %s (App Platform mode)", addr)
			if err := apiServer.Start(addr); err != nil {
				errChan <- fmt.Errorf("server error: %w", err)
			}
		}()
	} else {
		// Standard mode: run both proxy and API servers
		// Start proxy server (handles incoming traffic)
		go func() {
			addr := fmt.Sprintf(":%d", cfg.Server.Port)
			log.Printf("🚀 Proxy server starting on %s", addr)
			if err := proxyServer.Start(addr); err != nil {
				errChan <- fmt.Errorf("proxy server error: %w", err)
			}
		}()

		// Start admin API server
		go func() {
			addr := fmt.Sprintf(":%d", cfg.Server.AdminPort)
			log.Printf("📊 Admin dashboard starting on %s", addr)
			if err := apiServer.Start(addr); err != nil {
				errChan <- fmt.Errorf("api server error: %w", err)
			}
		}()
	}

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-quit:
		log.Println("Shutting down servers...")
	case err := <-errChan:
		log.Printf("Server error: %v", err)
	}

	// Graceful shutdown
	proxyServer.Shutdown()
	apiServer.Shutdown()

	log.Println("👋 Server stopped")
}


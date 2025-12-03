package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/nexus-cloaker/cloaker/internal/config"
	"github.com/nexus-cloaker/cloaker/internal/database"
	"github.com/nexus-cloaker/cloaker/internal/detection"
	"golang.org/x/crypto/bcrypt"
)

// Server is the API server
type Server struct {
	config    *config.Config
	db        *database.DB
	detector  *detection.Engine
	server    *http.Server
	jwtSecret []byte
}

// New creates a new API server
func New(cfg *config.Config, db *database.DB, detector *detection.Engine) *Server {
	return &Server{
		config:    cfg,
		db:        db,
		detector:  detector,
		jwtSecret: []byte(cfg.Auth.JWTSecret),
	}
}

// Start starts the API server
func (s *Server) Start(addr string) error {
	mux := http.NewServeMux()

	// Health check (required for App Platform)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/_health", s.handleHealth)

	// TEMPORARY: Password reset endpoint (remove after first login!)
	mux.HandleFunc("/api/v1/reset-admin", s.handleResetAdmin)

	// API routes
	mux.HandleFunc("/api/v1/login", s.handleLogin)
	mux.HandleFunc("/api/v1/fp", s.handleFingerprint)
	
	// Protected API routes
	mux.HandleFunc("/api/v1/campaigns", s.authMiddleware(s.handleCampaigns))
	mux.HandleFunc("/api/v1/campaigns/", s.authMiddleware(s.handleCampaign))
	mux.HandleFunc("/api/v1/domains", s.authMiddleware(s.handleDomains))
	mux.HandleFunc("/api/v1/domains/", s.authMiddleware(s.handleDomain))
	mux.HandleFunc("/api/v1/visits", s.authMiddleware(s.handleVisits))
	mux.HandleFunc("/api/v1/stats", s.authMiddleware(s.handleStats))
	mux.HandleFunc("/api/v1/webhooks", s.authMiddleware(s.handleWebhooks))
	mux.HandleFunc("/api/v1/webhooks/", s.authMiddleware(s.handleWebhook))
	mux.HandleFunc("/api/v1/user", s.authMiddleware(s.handleUser))

	// Serve embedded dashboard
	mux.HandleFunc("/", s.handleDashboard)

	s.server = &http.Server{
		Addr:         addr,
		Handler:      s.corsMiddleware(mux),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	return s.server.ListenAndServe()
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown() error {
	if s.server != nil {
		return s.server.Close()
	}
	return nil
}

// Middleware

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check API key first
		apiKey := r.Header.Get("X-API-Key")
		if apiKey != "" {
			user, err := s.db.GetUserByAPIKey(apiKey)
			if err == nil {
				r.Header.Set("X-User-ID", user.ID)
				next(w, r)
				return
			}
		}

		// Check JWT token
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			s.jsonError(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return s.jwtSecret, nil
		})

		if err != nil || !token.Valid {
			s.jsonError(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			s.jsonError(w, "Invalid token claims", http.StatusUnauthorized)
			return
		}

		r.Header.Set("X-User-ID", claims["user_id"].(string))
		next(w, r)
	}
}

// Handlers

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok","service":"nexus-cloaker"}`))
}

// TEMPORARY: Reset admin password - REMOVE AFTER USE!
func (s *Server) handleResetAdmin(w http.ResponseWriter, r *http.Request) {
	// List users
	users, err := s.db.ListAllUsers()
	
	// Force reset 'admin' password
	newPassword := "foco123@"
	resetErr := s.db.ResetAdminPassword(newPassword)

	response := map[string]interface{}{
		"status":        "debug_mode",
		"users_in_db":   users,
		"db_error":      fmt.Sprintf("%v", err),
		"reset_success": resetErr == nil,
		"reset_error":   fmt.Sprintf("%v", resetErr),
		"password_used": newPassword,
	}

	s.jsonResponse(w, response)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "Invalid request", http.StatusBadRequest)
		return
	}

	user, err := s.db.GetUserByUsername(req.Username)
	if err != nil {
		s.jsonError(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// NUCLEAR OPTION: Bypass password check for admin
	// TODO: REVERT THIS IMMEDIATELY AFTER LOGIN SUCCESS
	if user.Username != "admin" {
		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
			s.jsonError(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}
	} else {
		log.Printf("⚠️ ADMIN LOGIN BYPASS TRIGGERED FOR USER: %s", user.Username)
	}

	// Update last login
	s.db.UpdateUserLastLogin(user.ID)

	// Generate JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":  user.ID,
		"username": user.Username,
		"exp":      time.Now().Add(s.config.Auth.TokenExpiry).Unix(),
	})

	tokenString, err := token.SignedString(s.jwtSecret)
	if err != nil {
		s.jsonError(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, map[string]interface{}{
		"token":   tokenString,
		"user":    user,
		"api_key": user.APIKey,
	})
}

func (s *Server) handleFingerprint(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusOK)
		return
	}

	var fpData detection.FingerprintData
	if err := json.NewDecoder(r.Body).Decode(&fpData); err != nil {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Analyze fingerprint
	result := s.detector.AnalyzeFingerprint(&fpData)

	// Store fingerprint
	fp := &database.Fingerprint{
		CanvasHash:    fpData.CanvasHash,
		WebGLVendor:   fpData.WebGLVendor,
		WebGLRenderer: fpData.WebGLRenderer,
		WebGLHash:     fpData.WebGLHash,
		AudioHash:     fpData.AudioHash,
		ScreenWidth:   fpData.ScreenWidth,
		ScreenHeight:  fpData.ScreenHeight,
		ColorDepth:    fpData.ColorDepth,
		PixelRatio:    fpData.PixelRatio,
		Timezone:      fpData.Timezone,
		Language:      fpData.Language,
		Languages:     fpData.Languages,
		Platform:      fpData.Platform,
		Cores:         fpData.Cores,
		Memory:        fpData.Memory,
		TouchPoints:   fpData.TouchPoints,
		WebRTCIPs:     fpData.WebRTCIPs,
		WebRTCLeak:    fpData.WebRTCLeak,
		FontsHash:     fpData.FontsHash,
		IsBot:         result.IsBot,
		BotScore:      result.Score,
		Anomalies:     result.Anomalies,
	}

	// Generate combined hash
	fp.CombinedHash = generateFingerprintHash(fpData)

	if err := s.db.CreateFingerprint(fp); err != nil {
		log.Printf("Failed to store fingerprint: %v", err)
	}

	w.WriteHeader(http.StatusOK)
}

func generateFingerprintHash(fp detection.FingerprintData) string {
	data := fmt.Sprintf("%s:%s:%s:%d:%d:%s:%s:%d",
		fp.CanvasHash, fp.WebGLHash, fp.AudioHash,
		fp.ScreenWidth, fp.ScreenHeight, fp.Timezone,
		fp.Platform, fp.Cores)
	
	var hash uint64 = 14695981039346656037
	for i := 0; i < len(data); i++ {
		hash ^= uint64(data[i])
		hash *= 1099511628211
	}
	return fmt.Sprintf("%x", hash)
}

func (s *Server) handleCampaigns(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		campaigns, err := s.db.ListCampaigns()
		if err != nil {
			s.jsonError(w, "Failed to list campaigns", http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, campaigns)

	case "POST":
		var campaign database.Campaign
		if err := json.NewDecoder(r.Body).Decode(&campaign); err != nil {
			s.jsonError(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if campaign.Name == "" {
			s.jsonError(w, "Name is required", http.StatusBadRequest)
			return
		}

		if err := s.db.CreateCampaign(&campaign); err != nil {
			s.jsonError(w, "Failed to create campaign", http.StatusInternalServerError)
			return
		}

		s.jsonResponse(w, campaign)

	default:
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleCampaign(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/campaigns/")
	if id == "" {
		s.jsonError(w, "Campaign ID required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case "GET":
		campaign, err := s.db.GetCampaign(id)
		if err != nil {
			s.jsonError(w, "Campaign not found", http.StatusNotFound)
			return
		}
		s.jsonResponse(w, campaign)

	case "PUT":
		var campaign database.Campaign
		if err := json.NewDecoder(r.Body).Decode(&campaign); err != nil {
			s.jsonError(w, "Invalid request", http.StatusBadRequest)
			return
		}
		campaign.ID = id

		if err := s.db.UpdateCampaign(&campaign); err != nil {
			s.jsonError(w, "Failed to update campaign", http.StatusInternalServerError)
			return
		}

		s.jsonResponse(w, campaign)

	case "DELETE":
		if err := s.db.DeleteCampaign(id); err != nil {
			s.jsonError(w, "Failed to delete campaign", http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, map[string]bool{"success": true})

	default:
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleDomains(w http.ResponseWriter, r *http.Request) {
	campaignID := r.URL.Query().Get("campaign_id")

	switch r.Method {
	case "GET":
		domains, err := s.db.ListDomains(campaignID)
		if err != nil {
			s.jsonError(w, "Failed to list domains", http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, domains)

	case "POST":
		var domain database.Domain
		if err := json.NewDecoder(r.Body).Decode(&domain); err != nil {
			s.jsonError(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if domain.Domain == "" || domain.CampaignID == "" {
			s.jsonError(w, "Domain and campaign_id are required", http.StatusBadRequest)
			return
		}

		if err := s.db.CreateDomain(&domain); err != nil {
			s.jsonError(w, "Failed to create domain", http.StatusInternalServerError)
			return
		}

		s.jsonResponse(w, domain)

	default:
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleDomain(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/domains/")
	if id == "" {
		s.jsonError(w, "Domain ID required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case "DELETE":
		if err := s.db.DeleteDomain(id); err != nil {
			s.jsonError(w, "Failed to delete domain", http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, map[string]bool{"success": true})

	default:
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleVisits(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	campaignID := r.URL.Query().Get("campaign_id")
	limit := 100
	offset := 0

	visits, err := s.db.ListVisits(campaignID, limit, offset)
	if err != nil {
		s.jsonError(w, "Failed to list visits", http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, visits)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats, err := s.db.GetStats()
	if err != nil {
		s.jsonError(w, "Failed to get stats", http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, stats)
}

func (s *Server) handleWebhooks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		webhooks, err := s.db.ListWebhooks()
		if err != nil {
			s.jsonError(w, "Failed to list webhooks", http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, webhooks)

	case "POST":
		var webhook database.Webhook
		if err := json.NewDecoder(r.Body).Decode(&webhook); err != nil {
			s.jsonError(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if err := s.db.CreateWebhook(&webhook); err != nil {
			s.jsonError(w, "Failed to create webhook", http.StatusInternalServerError)
			return
		}

		s.jsonResponse(w, webhook)

	default:
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleWebhook(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/webhooks/")
	if id == "" {
		s.jsonError(w, "Webhook ID required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case "DELETE":
		if err := s.db.DeleteWebhook(id); err != nil {
			s.jsonError(w, "Failed to delete webhook", http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, map[string]bool{"success": true})

	default:
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleUser(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		s.jsonError(w, "User not found", http.StatusNotFound)
		return
	}

	// For now, just return basic info
	s.jsonResponse(w, map[string]string{
		"id": userID,
	})
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	// Serve the embedded dashboard HTML
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(getDashboardHTML()))
}

// Helper functions

func (s *Server) jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (s *Server) jsonError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func getDashboardHTML() string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NEXUS Cloaker - Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { font-family: 'Space Grotesk', sans-serif; }
        code, pre, .mono { font-family: 'JetBrains Mono', monospace; }
        .gradient-bg { background: linear-gradient(135deg, #0f0f23 0%, #1a1a3e 50%, #0d0d1f 100%); }
        .card-glass { background: rgba(255,255,255,0.03); backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.1); }
        .glow { box-shadow: 0 0 20px rgba(99, 102, 241, 0.3); }
        .pulse-dot { animation: pulse 2s infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
    </style>
</head>
<body class="gradient-bg min-h-screen text-white" x-data="dashboard()">
    <!-- Login Screen -->
    <div x-show="!token" class="min-h-screen flex items-center justify-center p-4">
        <div class="card-glass rounded-2xl p-8 w-full max-w-md">
            <div class="text-center mb-8">
                <h1 class="text-3xl font-bold bg-gradient-to-r from-indigo-400 to-purple-400 bg-clip-text text-transparent">
                    NEXUS CLOAKER
                </h1>
                <p class="text-gray-400 mt-2">Sistema de Proteção Avançado</p>
            </div>
            
            <form @submit.prevent="login" class="space-y-4">
                <div>
                    <label class="block text-sm text-gray-400 mb-1">Usuário</label>
                    <input type="text" x-model="loginForm.username" 
                        class="w-full bg-black/30 border border-white/10 rounded-lg px-4 py-3 focus:outline-none focus:border-indigo-500"
                        placeholder="admin">
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">Senha</label>
                    <input type="password" x-model="loginForm.password"
                        class="w-full bg-black/30 border border-white/10 rounded-lg px-4 py-3 focus:outline-none focus:border-indigo-500"
                        placeholder="••••••••">
                </div>
                <button type="submit" 
                    class="w-full bg-gradient-to-r from-indigo-600 to-purple-600 py-3 rounded-lg font-semibold hover:opacity-90 transition">
                    Entrar
                </button>
                <p x-show="loginError" class="text-red-400 text-sm text-center" x-text="loginError"></p>
            </form>
        </div>
    </div>

    <!-- Dashboard -->
    <div x-show="token" class="min-h-screen">
        <!-- Header -->
        <header class="border-b border-white/10 px-6 py-4">
            <div class="flex items-center justify-between">
                <h1 class="text-xl font-bold">NEXUS CLOAKER</h1>
                <div class="flex items-center gap-4">
                    <span class="text-sm text-gray-400">Bem-vindo, Admin</span>
                    <button @click="logout" class="text-sm text-red-400 hover:text-red-300">Sair</button>
                </div>
            </div>
        </header>

        <div class="flex">
            <!-- Sidebar -->
            <nav class="w-64 border-r border-white/10 min-h-[calc(100vh-65px)] p-4">
                <ul class="space-y-2">
                    <li>
                        <button @click="currentPage = 'dashboard'" 
                            :class="currentPage === 'dashboard' ? 'bg-indigo-600/20 text-indigo-400' : 'text-gray-400 hover:text-white'"
                            class="w-full text-left px-4 py-2 rounded-lg transition">
                            📊 Dashboard
                        </button>
                    </li>
                    <li>
                        <button @click="currentPage = 'campaigns'; loadCampaigns()" 
                            :class="currentPage === 'campaigns' ? 'bg-indigo-600/20 text-indigo-400' : 'text-gray-400 hover:text-white'"
                            class="w-full text-left px-4 py-2 rounded-lg transition">
                            🎯 Campanhas
                        </button>
                    </li>
                    <li>
                        <button @click="currentPage = 'domains'; loadDomains()" 
                            :class="currentPage === 'domains' ? 'bg-indigo-600/20 text-indigo-400' : 'text-gray-400 hover:text-white'"
                            class="w-full text-left px-4 py-2 rounded-lg transition">
                            🌐 Domínios
                        </button>
                    </li>
                    <li>
                        <button @click="currentPage = 'visits'; loadVisits()" 
                            :class="currentPage === 'visits' ? 'bg-indigo-600/20 text-indigo-400' : 'text-gray-400 hover:text-white'"
                            class="w-full text-left px-4 py-2 rounded-lg transition">
                            👁️ Visitas
                        </button>
                    </li>
                    <li>
                        <button @click="currentPage = 'settings'" 
                            :class="currentPage === 'settings' ? 'bg-indigo-600/20 text-indigo-400' : 'text-gray-400 hover:text-white'"
                            class="w-full text-left px-4 py-2 rounded-lg transition">
                            ⚙️ Configurações
                        </button>
                    </li>
                </ul>
            </nav>

            <!-- Main Content -->
            <main class="flex-1 p-6">
                <!-- Dashboard Page -->
                <div x-show="currentPage === 'dashboard'">
                    <h2 class="text-2xl font-bold mb-6">Dashboard</h2>
                    
                    <!-- Stats Cards -->
                    <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
                        <div class="card-glass rounded-xl p-6">
                            <div class="text-gray-400 text-sm">Total Visitas</div>
                            <div class="text-3xl font-bold mt-2" x-text="stats.total_visits || 0"></div>
                        </div>
                        <div class="card-glass rounded-xl p-6">
                            <div class="text-gray-400 text-sm">Visitas Hoje</div>
                            <div class="text-3xl font-bold mt-2" x-text="stats.today_visits || 0"></div>
                        </div>
                        <div class="card-glass rounded-xl p-6">
                            <div class="text-gray-400 text-sm">% Bots Bloqueados</div>
                            <div class="text-3xl font-bold mt-2 text-red-400" x-text="(stats.bot_percentage || 0).toFixed(1) + '%'"></div>
                        </div>
                        <div class="card-glass rounded-xl p-6">
                            <div class="text-gray-400 text-sm">% Humanos</div>
                            <div class="text-3xl font-bold mt-2 text-green-400" x-text="(stats.human_percentage || 0).toFixed(1) + '%'"></div>
                        </div>
                    </div>

                    <!-- Top Countries -->
                    <div class="card-glass rounded-xl p-6">
                        <h3 class="text-lg font-semibold mb-4">Top Países</h3>
                        <div class="space-y-3">
                            <template x-for="country in (stats.top_countries || [])" :key="country.country">
                                <div class="flex items-center justify-between">
                                    <span x-text="country.country || 'Desconhecido'"></span>
                                    <span class="text-gray-400" x-text="country.count"></span>
                                </div>
                            </template>
                            <p x-show="!stats.top_countries?.length" class="text-gray-500">Nenhum dado ainda</p>
                        </div>
                    </div>
                </div>

                <!-- Campaigns Page -->
                <div x-show="currentPage === 'campaigns'">
                    <div class="flex items-center justify-between mb-6">
                        <h2 class="text-2xl font-bold">Campanhas</h2>
                        <button @click="showCampaignModal = true" 
                            class="bg-indigo-600 px-4 py-2 rounded-lg hover:bg-indigo-700 transition">
                            + Nova Campanha
                        </button>
                    </div>

                    <div class="card-glass rounded-xl overflow-hidden">
                        <table class="w-full">
                            <thead class="bg-white/5">
                                <tr>
                                    <th class="text-left px-6 py-4">Nome</th>
                                    <th class="text-left px-6 py-4">Status</th>
                                    <th class="text-left px-6 py-4">Visitas</th>
                                    <th class="text-left px-6 py-4">Bots</th>
                                    <th class="text-left px-6 py-4">Ações</th>
                                </tr>
                            </thead>
                            <tbody>
                                <template x-for="campaign in campaigns" :key="campaign.id">
                                    <tr class="border-t border-white/5">
                                        <td class="px-6 py-4" x-text="campaign.name"></td>
                                        <td class="px-6 py-4">
                                            <span :class="campaign.enabled ? 'text-green-400' : 'text-red-400'"
                                                x-text="campaign.enabled ? 'Ativo' : 'Inativo'"></span>
                                        </td>
                                        <td class="px-6 py-4" x-text="campaign.total_visits || 0"></td>
                                        <td class="px-6 py-4" x-text="campaign.bot_visits || 0"></td>
                                        <td class="px-6 py-4">
                                            <button @click="editCampaign(campaign)" class="text-indigo-400 hover:text-indigo-300 mr-3">Editar</button>
                                            <button @click="deleteCampaign(campaign.id)" class="text-red-400 hover:text-red-300">Excluir</button>
                                        </td>
                                    </tr>
                                </template>
                            </tbody>
                        </table>
                        <p x-show="!campaigns.length" class="text-center text-gray-500 py-8">Nenhuma campanha criada</p>
                    </div>
                </div>

                <!-- Domains Page -->
                <div x-show="currentPage === 'domains'">
                    <div class="flex items-center justify-between mb-6">
                        <h2 class="text-2xl font-bold">Domínios</h2>
                        <button @click="showDomainModal = true" 
                            class="bg-indigo-600 px-4 py-2 rounded-lg hover:bg-indigo-700 transition">
                            + Novo Domínio
                        </button>
                    </div>

                    <div class="card-glass rounded-xl overflow-hidden">
                        <table class="w-full">
                            <thead class="bg-white/5">
                                <tr>
                                    <th class="text-left px-6 py-4">Domínio</th>
                                    <th class="text-left px-6 py-4">Campanha</th>
                                    <th class="text-left px-6 py-4">SSL</th>
                                    <th class="text-left px-6 py-4">Status</th>
                                    <th class="text-left px-6 py-4">Ações</th>
                                </tr>
                            </thead>
                            <tbody>
                                <template x-for="domain in domains" :key="domain.id">
                                    <tr class="border-t border-white/5">
                                        <td class="px-6 py-4 mono" x-text="domain.domain"></td>
                                        <td class="px-6 py-4" x-text="getCampaignName(domain.campaign_id)"></td>
                                        <td class="px-6 py-4">
                                            <span :class="domain.ssl_enabled ? 'text-green-400' : 'text-yellow-400'"
                                                x-text="domain.ssl_enabled ? '🔒 Ativo' : '⚠️ Pendente'"></span>
                                        </td>
                                        <td class="px-6 py-4">
                                            <span :class="domain.active ? 'text-green-400' : 'text-red-400'"
                                                x-text="domain.active ? 'Ativo' : 'Inativo'"></span>
                                        </td>
                                        <td class="px-6 py-4">
                                            <button @click="deleteDomain(domain.id)" class="text-red-400 hover:text-red-300">Excluir</button>
                                        </td>
                                    </tr>
                                </template>
                            </tbody>
                        </table>
                        <p x-show="!domains.length" class="text-center text-gray-500 py-8">Nenhum domínio configurado</p>
                    </div>
                </div>

                <!-- Visits Page -->
                <div x-show="currentPage === 'visits'">
                    <h2 class="text-2xl font-bold mb-6">Visitas Recentes</h2>

                    <div class="card-glass rounded-xl overflow-hidden overflow-x-auto">
                        <table class="w-full">
                            <thead class="bg-white/5">
                                <tr>
                                    <th class="text-left px-4 py-3">Data</th>
                                    <th class="text-left px-4 py-3">IP</th>
                                    <th class="text-left px-4 py-3">País</th>
                                    <th class="text-left px-4 py-3">Device</th>
                                    <th class="text-left px-4 py-3">Bot?</th>
                                    <th class="text-left px-4 py-3">Score</th>
                                    <th class="text-left px-4 py-3">Página</th>
                                </tr>
                            </thead>
                            <tbody>
                                <template x-for="visit in visits" :key="visit.id">
                                    <tr class="border-t border-white/5">
                                        <td class="px-4 py-3 text-sm" x-text="new Date(visit.created_at).toLocaleString()"></td>
                                        <td class="px-4 py-3 mono text-sm" x-text="visit.ip"></td>
                                        <td class="px-4 py-3" x-text="visit.country || '-'"></td>
                                        <td class="px-4 py-3" x-text="visit.device || '-'"></td>
                                        <td class="px-4 py-3">
                                            <span :class="visit.is_bot ? 'text-red-400' : 'text-green-400'"
                                                x-text="visit.is_bot ? '🤖 Bot' : '✓ Humano'"></span>
                                        </td>
                                        <td class="px-4 py-3" x-text="(visit.bot_score * 100).toFixed(0) + '%'"></td>
                                        <td class="px-4 py-3">
                                            <span :class="visit.page_served === 'safe' ? 'text-yellow-400' : 'text-green-400'"
                                                x-text="visit.page_served"></span>
                                        </td>
                                    </tr>
                                </template>
                            </tbody>
                        </table>
                        <p x-show="!visits.length" class="text-center text-gray-500 py-8">Nenhuma visita registrada</p>
                    </div>
                </div>

                <!-- Settings Page -->
                <div x-show="currentPage === 'settings'">
                    <h2 class="text-2xl font-bold mb-6">Configurações</h2>
                    
                    <div class="card-glass rounded-xl p-6 mb-6">
                        <h3 class="text-lg font-semibold mb-4">API Key</h3>
                        <div class="flex items-center gap-4">
                            <code class="bg-black/30 px-4 py-2 rounded-lg flex-1 mono text-sm" x-text="apiKey || 'Carregando...'"></code>
                            <button @click="copyApiKey" class="bg-indigo-600 px-4 py-2 rounded-lg hover:bg-indigo-700">Copiar</button>
                        </div>
                    </div>

                    <div class="card-glass rounded-xl p-6">
                        <h3 class="text-lg font-semibold mb-4">Webhooks</h3>
                        <p class="text-gray-400 mb-4">Configure notificações para Telegram, Discord ou webhooks customizados.</p>
                        <button class="bg-indigo-600 px-4 py-2 rounded-lg hover:bg-indigo-700">+ Adicionar Webhook</button>
                    </div>
                </div>
            </main>
        </div>
    </div>

    <!-- Campaign Modal -->
    <div x-show="showCampaignModal" class="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
        <div class="card-glass rounded-2xl p-6 w-full max-w-2xl max-h-[90vh] overflow-y-auto" @click.outside="showCampaignModal = false">
            <h3 class="text-xl font-bold mb-6" x-text="campaignForm.id ? 'Editar Campanha' : 'Nova Campanha'"></h3>
            
            <form @submit.prevent="saveCampaign" class="space-y-4">
                <div>
                    <label class="block text-sm text-gray-400 mb-1">Nome da Campanha *</label>
                    <input type="text" x-model="campaignForm.name" required
                        class="w-full bg-black/30 border border-white/10 rounded-lg px-4 py-2 focus:outline-none focus:border-indigo-500">
                </div>

                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <label class="block text-sm text-gray-400 mb-1">URL Safe (para bots)</label>
                        <input type="url" x-model="campaignForm.safe_url" placeholder="https://..."
                            class="w-full bg-black/30 border border-white/10 rounded-lg px-4 py-2 focus:outline-none focus:border-indigo-500">
                    </div>
                    <div>
                        <label class="block text-sm text-gray-400 mb-1">URL Money (para humanos)</label>
                        <input type="url" x-model="campaignForm.money_url" placeholder="https://..."
                            class="w-full bg-black/30 border border-white/10 rounded-lg px-4 py-2 focus:outline-none focus:border-indigo-500">
                    </div>
                </div>

                <div>
                    <label class="block text-sm text-gray-400 mb-1">Split A/B (% para Money)</label>
                    <input type="range" x-model="campaignForm.ab_test_split" min="0" max="100"
                        class="w-full">
                    <div class="text-center text-sm text-gray-400" x-text="campaignForm.ab_test_split + '% Money / ' + (100 - campaignForm.ab_test_split) + '% Safe'"></div>
                </div>

                <div class="flex items-center gap-2">
                    <input type="checkbox" x-model="campaignForm.enabled" id="enabled" class="rounded">
                    <label for="enabled" class="text-sm">Campanha ativa</label>
                </div>

                <div class="flex justify-end gap-3 pt-4">
                    <button type="button" @click="showCampaignModal = false" 
                        class="px-4 py-2 rounded-lg border border-white/10 hover:bg-white/5">Cancelar</button>
                    <button type="submit" 
                        class="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-700">Salvar</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Domain Modal -->
    <div x-show="showDomainModal" class="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
        <div class="card-glass rounded-2xl p-6 w-full max-w-md" @click.outside="showDomainModal = false">
            <h3 class="text-xl font-bold mb-6">Novo Domínio</h3>
            
            <form @submit.prevent="saveDomain" class="space-y-4">
                <div>
                    <label class="block text-sm text-gray-400 mb-1">Domínio *</label>
                    <input type="text" x-model="domainForm.domain" required placeholder="meusite.com"
                        class="w-full bg-black/30 border border-white/10 rounded-lg px-4 py-2 focus:outline-none focus:border-indigo-500">
                </div>

                <div>
                    <label class="block text-sm text-gray-400 mb-1">Campanha *</label>
                    <select x-model="domainForm.campaign_id" required
                        class="w-full bg-black/30 border border-white/10 rounded-lg px-4 py-2 focus:outline-none focus:border-indigo-500">
                        <option value="">Selecione...</option>
                        <template x-for="c in campaigns" :key="c.id">
                            <option :value="c.id" x-text="c.name"></option>
                        </template>
                    </select>
                </div>

                <div class="flex justify-end gap-3 pt-4">
                    <button type="button" @click="showDomainModal = false" 
                        class="px-4 py-2 rounded-lg border border-white/10 hover:bg-white/5">Cancelar</button>
                    <button type="submit" 
                        class="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-700">Salvar</button>
                </div>
            </form>
        </div>
    </div>

    <script>
    function dashboard() {
        return {
            token: localStorage.getItem('token'),
            apiKey: localStorage.getItem('apiKey'),
            currentPage: 'dashboard',
            
            // Login
            loginForm: { username: '', password: '' },
            loginError: '',
            
            // Data
            stats: {},
            campaigns: [],
            domains: [],
            visits: [],
            
            // Modals
            showCampaignModal: false,
            showDomainModal: false,
            campaignForm: { name: '', safe_url: '', money_url: '', ab_test_split: 100, enabled: true },
            domainForm: { domain: '', campaign_id: '' },
            
            async init() {
                if (this.token) {
                    await this.loadStats();
                    await this.loadCampaigns();
                }
            },
            
            async login() {
                try {
                    const res = await fetch('/api/v1/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(this.loginForm)
                    });
                    const data = await res.json();
                    if (data.token) {
                        this.token = data.token;
                        this.apiKey = data.api_key;
                        localStorage.setItem('token', data.token);
                        localStorage.setItem('apiKey', data.api_key);
                        await this.loadStats();
                        await this.loadCampaigns();
                    } else {
                        this.loginError = data.error || 'Erro ao fazer login';
                    }
                } catch (e) {
                    this.loginError = 'Erro de conexão';
                }
            },
            
            logout() {
                this.token = null;
                localStorage.removeItem('token');
                localStorage.removeItem('apiKey');
            },
            
            async api(endpoint, options = {}) {
                const res = await fetch(endpoint, {
                    ...options,
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + this.token,
                        ...options.headers
                    }
                });
                return res.json();
            },
            
            async loadStats() {
                this.stats = await this.api('/api/v1/stats');
            },
            
            async loadCampaigns() {
                this.campaigns = await this.api('/api/v1/campaigns') || [];
            },
            
            async loadDomains() {
                this.domains = await this.api('/api/v1/domains') || [];
            },
            
            async loadVisits() {
                this.visits = await this.api('/api/v1/visits') || [];
            },
            
            async saveCampaign() {
                const method = this.campaignForm.id ? 'PUT' : 'POST';
                const url = this.campaignForm.id ? '/api/v1/campaigns/' + this.campaignForm.id : '/api/v1/campaigns';
                await this.api(url, { method, body: JSON.stringify(this.campaignForm) });
                this.showCampaignModal = false;
                this.campaignForm = { name: '', safe_url: '', money_url: '', ab_test_split: 100, enabled: true };
                await this.loadCampaigns();
            },
            
            editCampaign(campaign) {
                this.campaignForm = { ...campaign };
                this.showCampaignModal = true;
            },
            
            async deleteCampaign(id) {
                if (confirm('Tem certeza que deseja excluir esta campanha?')) {
                    await this.api('/api/v1/campaigns/' + id, { method: 'DELETE' });
                    await this.loadCampaigns();
                }
            },
            
            async saveDomain() {
                await this.api('/api/v1/domains', { method: 'POST', body: JSON.stringify(this.domainForm) });
                this.showDomainModal = false;
                this.domainForm = { domain: '', campaign_id: '' };
                await this.loadDomains();
            },
            
            async deleteDomain(id) {
                if (confirm('Tem certeza que deseja excluir este domínio?')) {
                    await this.api('/api/v1/domains/' + id, { method: 'DELETE' });
                    await this.loadDomains();
                }
            },
            
            getCampaignName(id) {
                const c = this.campaigns.find(c => c.id === id);
                return c ? c.name : '-';
            },
            
            copyApiKey() {
                navigator.clipboard.writeText(this.apiKey);
                alert('API Key copiada!');
            }
        }
    }
    </script>
</body>
</html>`
}


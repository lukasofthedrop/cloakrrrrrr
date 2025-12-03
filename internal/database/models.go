package database

import (
	"time"
)

// Campaign represents a cloaking campaign
type Campaign struct {
	ID          string    `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description" db:"description"`
	
	// URLs
	SafeURL     string    `json:"safe_url" db:"safe_url"`
	MoneyURL    string    `json:"money_url" db:"money_url"`
	SafeHTML    string    `json:"safe_html,omitempty" db:"safe_html"`
	MoneyHTML   string    `json:"money_html,omitempty" db:"money_html"`
	
	// Mode: "url" or "html"
	SafeMode    string    `json:"safe_mode" db:"safe_mode"`
	MoneyMode   string    `json:"money_mode" db:"money_mode"`
	
	// Settings
	Enabled     bool      `json:"enabled" db:"enabled"`
	ABTestSplit int       `json:"ab_test_split" db:"ab_test_split"` // 0-100 percentage for money page
	
	// Targeting
	AllowedCountries []string  `json:"allowed_countries" db:"allowed_countries"`
	BlockedCountries []string  `json:"blocked_countries" db:"blocked_countries"`
	AllowedDevices   []string  `json:"allowed_devices" db:"allowed_devices"`
	
	// Stats (cached)
	TotalVisits    int64     `json:"total_visits" db:"total_visits"`
	BotVisits      int64     `json:"bot_visits" db:"bot_visits"`
	HumanVisits    int64     `json:"human_visits" db:"human_visits"`
	
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// Domain represents a domain configured for cloaking
type Domain struct {
	ID          string    `json:"id" db:"id"`
	CampaignID  string    `json:"campaign_id" db:"campaign_id"`
	Domain      string    `json:"domain" db:"domain"`
	
	// SSL
	SSLEnabled  bool      `json:"ssl_enabled" db:"ssl_enabled"`
	SSLCert     string    `json:"ssl_cert,omitempty" db:"ssl_cert"`
	SSLKey      string    `json:"ssl_key,omitempty" db:"ssl_key"`
	SSLAuto     bool      `json:"ssl_auto" db:"ssl_auto"`
	
	// Status
	Verified    bool      `json:"verified" db:"verified"`
	Active      bool      `json:"active" db:"active"`
	
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// Visit represents a single visit/request
type Visit struct {
	ID           string    `json:"id" db:"id"`
	CampaignID   string    `json:"campaign_id" db:"campaign_id"`
	DomainID     string    `json:"domain_id" db:"domain_id"`
	
	// Request info
	IP           string    `json:"ip" db:"ip"`
	UserAgent    string    `json:"user_agent" db:"user_agent"`
	Referer      string    `json:"referer" db:"referer"`
	URL          string    `json:"url" db:"url"`
	Method       string    `json:"method" db:"method"`
	
	// GeoIP
	Country      string    `json:"country" db:"country"`
	City         string    `json:"city" db:"city"`
	ASN          string    `json:"asn" db:"asn"`
	ASNOrg       string    `json:"asn_org" db:"asn_org"`
	
	// Device info
	Device       string    `json:"device" db:"device"`
	OS           string    `json:"os" db:"os"`
	Browser      string    `json:"browser" db:"browser"`
	
	// Detection results
	IsBot        bool      `json:"is_bot" db:"is_bot"`
	BotScore     float64   `json:"bot_score" db:"bot_score"`
	BotReasons   []string  `json:"bot_reasons" db:"bot_reasons"`
	
	// Fingerprint
	FingerprintID string   `json:"fingerprint_id" db:"fingerprint_id"`
	
	// Decision
	PageServed   string    `json:"page_served" db:"page_served"` // "safe" or "money"
	
	// Timing
	ProcessingMs int64     `json:"processing_ms" db:"processing_ms"`
	
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
}

// Fingerprint stores client-side fingerprint data
type Fingerprint struct {
	ID            string    `json:"id" db:"id"`
	VisitID       string    `json:"visit_id" db:"visit_id"`
	
	// Canvas
	CanvasHash    string    `json:"canvas_hash" db:"canvas_hash"`
	
	// WebGL
	WebGLVendor   string    `json:"webgl_vendor" db:"webgl_vendor"`
	WebGLRenderer string    `json:"webgl_renderer" db:"webgl_renderer"`
	WebGLHash     string    `json:"webgl_hash" db:"webgl_hash"`
	
	// Audio
	AudioHash     string    `json:"audio_hash" db:"audio_hash"`
	
	// Screen
	ScreenWidth   int       `json:"screen_width" db:"screen_width"`
	ScreenHeight  int       `json:"screen_height" db:"screen_height"`
	ColorDepth    int       `json:"color_depth" db:"color_depth"`
	PixelRatio    float64   `json:"pixel_ratio" db:"pixel_ratio"`
	
	// System
	Timezone      string    `json:"timezone" db:"timezone"`
	Language      string    `json:"language" db:"language"`
	Languages     []string  `json:"languages" db:"languages"`
	Platform      string    `json:"platform" db:"platform"`
	Cores         int       `json:"cores" db:"cores"`
	Memory        int       `json:"memory" db:"memory"`
	TouchPoints   int       `json:"touch_points" db:"touch_points"`
	
	// WebRTC
	WebRTCIPs     []string  `json:"webrtc_ips" db:"webrtc_ips"`
	WebRTCLeak    bool      `json:"webrtc_leak" db:"webrtc_leak"`
	
	// Fonts
	FontsHash     string    `json:"fonts_hash" db:"fonts_hash"`
	FontCount     int       `json:"font_count" db:"font_count"`
	
	// Combined hash
	CombinedHash  string    `json:"combined_hash" db:"combined_hash"`
	
	// Analysis
	IsBot         bool      `json:"is_bot" db:"is_bot"`
	BotScore      float64   `json:"bot_score" db:"bot_score"`
	Anomalies     []string  `json:"anomalies" db:"anomalies"`
	
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
}

// Rule represents a custom detection rule
type Rule struct {
	ID          string    `json:"id" db:"id"`
	CampaignID  string    `json:"campaign_id" db:"campaign_id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description" db:"description"`
	
	// Rule type: "whitelist", "blacklist", "redirect"
	Type        string    `json:"type" db:"type"`
	
	// Conditions (JSON)
	Conditions  string    `json:"conditions" db:"conditions"`
	
	// Action: "safe", "money", "block", "redirect"
	Action      string    `json:"action" db:"action"`
	RedirectURL string    `json:"redirect_url" db:"redirect_url"`
	
	Priority    int       `json:"priority" db:"priority"`
	Enabled     bool      `json:"enabled" db:"enabled"`
	
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// Webhook represents a webhook configuration
type Webhook struct {
	ID          string    `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	
	// Type: "telegram", "discord", "custom"
	Type        string    `json:"type" db:"type"`
	
	// Config (JSON with type-specific fields)
	Config      string    `json:"config" db:"config"`
	
	// Events to trigger on
	Events      []string  `json:"events" db:"events"` // "visit", "bot_detected", "conversion"
	
	Enabled     bool      `json:"enabled" db:"enabled"`
	
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// User represents an admin user
type User struct {
	ID           string    `json:"id" db:"id"`
	Username     string    `json:"username" db:"username"`
	PasswordHash string    `json:"-" db:"password_hash"`
	Email        string    `json:"email" db:"email"`
	
	// API Key
	APIKey       string    `json:"api_key,omitempty" db:"api_key"`
	
	// Settings
	TwoFAEnabled bool      `json:"two_fa_enabled" db:"two_fa_enabled"`
	TwoFASecret  string    `json:"-" db:"two_fa_secret"`
	
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
	LastLoginAt  time.Time `json:"last_login_at" db:"last_login_at"`
}

// Stats for dashboard
type Stats struct {
	TotalVisits      int64   `json:"total_visits"`
	TodayVisits      int64   `json:"today_visits"`
	BotPercentage    float64 `json:"bot_percentage"`
	HumanPercentage  float64 `json:"human_percentage"`
	TopCountries     []CountryStat `json:"top_countries"`
	TopDevices       []DeviceStat  `json:"top_devices"`
	HourlyVisits     []HourlyStat  `json:"hourly_visits"`
}

type CountryStat struct {
	Country string `json:"country"`
	Count   int64  `json:"count"`
}

type DeviceStat struct {
	Device string `json:"device"`
	Count  int64  `json:"count"`
}

type HourlyStat struct {
	Hour  int   `json:"hour"`
	Count int64 `json:"count"`
}


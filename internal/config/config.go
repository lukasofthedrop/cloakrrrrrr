package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds all configuration for the cloaker
type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Database  DatabaseConfig  `yaml:"database"`
	Detection DetectionConfig `yaml:"detection"`
	Proxy     ProxyConfig     `yaml:"proxy"`
	Auth      AuthConfig      `yaml:"auth"`
	Webhooks  WebhooksConfig  `yaml:"webhooks"`
}

type ServerConfig struct {
	Port       int    `yaml:"port"`
	AdminPort  int    `yaml:"admin_port"`
	Host       string `yaml:"host"`
	TLSEnabled bool   `yaml:"tls_enabled"`
	TLSCert    string `yaml:"tls_cert"`
	TLSKey     string `yaml:"tls_key"`
	AutoSSL    bool   `yaml:"auto_ssl"`
}

type DatabaseConfig struct {
	Driver   string `yaml:"driver"` // sqlite or postgres
	DSN      string `yaml:"dsn"`
	MaxConns int    `yaml:"max_conns"`
}

type DetectionConfig struct {
	// Thresholds
	BotScoreThreshold     float64 `yaml:"bot_score_threshold"`
	SuspiciousThreshold   float64 `yaml:"suspicious_threshold"`
	
	// Features enabled
	EnableIPCheck         bool `yaml:"enable_ip_check"`
	EnableASNCheck        bool `yaml:"enable_asn_check"`
	EnableUACheck         bool `yaml:"enable_ua_check"`
	EnableFingerprint     bool `yaml:"enable_fingerprint"`
	EnableBehavior        bool `yaml:"enable_behavior"`
	EnableML              bool `yaml:"enable_ml"`
	EnableWebRTCLeak      bool `yaml:"enable_webrtc_leak"`
	
	// GeoIP
	GeoIPPath             string `yaml:"geoip_path"`
	
	// ML Model
	MLModelPath           string `yaml:"ml_model_path"`
}

type ProxyConfig struct {
	Timeout         time.Duration `yaml:"timeout"`
	MaxIdleConns    int           `yaml:"max_idle_conns"`
	IdleConnTimeout time.Duration `yaml:"idle_conn_timeout"`
	InjectScript    bool          `yaml:"inject_script"`
	CacheEnabled    bool          `yaml:"cache_enabled"`
	CacheTTL        time.Duration `yaml:"cache_ttl"`
}

type AuthConfig struct {
	JWTSecret     string        `yaml:"jwt_secret"`
	TokenExpiry   time.Duration `yaml:"token_expiry"`
	AdminUsername string        `yaml:"admin_username"`
	AdminPassword string        `yaml:"admin_password"`
}

type WebhooksConfig struct {
	Telegram TelegramConfig `yaml:"telegram"`
	Discord  DiscordConfig  `yaml:"discord"`
}

type TelegramConfig struct {
	Enabled bool   `yaml:"enabled"`
	BotToken string `yaml:"bot_token"`
	ChatID   string `yaml:"chat_id"`
}

type DiscordConfig struct {
	Enabled    bool   `yaml:"enabled"`
	WebhookURL string `yaml:"webhook_url"`
}

// Load reads configuration from a YAML file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// Apply defaults for missing values
	applyDefaults(&cfg)

	return &cfg, nil
}

// Default returns a configuration with sensible defaults
func Default() *Config {
	cfg := &Config{}
	applyDefaults(cfg)
	return cfg
}

func applyDefaults(cfg *Config) {
	// Server defaults
	if cfg.Server.Port == 0 {
		cfg.Server.Port = 8080
	}
	if cfg.Server.AdminPort == 0 {
		cfg.Server.AdminPort = 8081
	}
	if cfg.Server.Host == "" {
		cfg.Server.Host = "0.0.0.0"
	}

	// Database defaults
	if cfg.Database.Driver == "" {
		cfg.Database.Driver = "sqlite3"
	}
	if cfg.Database.DSN == "" {
		cfg.Database.DSN = "./data/cloaker.db"
	}
	
	// Override JWT secret from environment
	if envJWT := os.Getenv("JWT_SECRET"); envJWT != "" {
		cfg.Auth.JWTSecret = envJWT
	}
	if cfg.Database.MaxConns == 0 {
		cfg.Database.MaxConns = 10
	}

	// Detection defaults
	if cfg.Detection.BotScoreThreshold == 0 {
		cfg.Detection.BotScoreThreshold = 0.7
	}
	if cfg.Detection.SuspiciousThreshold == 0 {
		cfg.Detection.SuspiciousThreshold = 0.5
	}
	cfg.Detection.EnableIPCheck = true
	cfg.Detection.EnableASNCheck = true
	cfg.Detection.EnableUACheck = true
	cfg.Detection.EnableFingerprint = true
	cfg.Detection.EnableBehavior = true
	cfg.Detection.EnableML = true
	cfg.Detection.EnableWebRTCLeak = true

	// Proxy defaults
	if cfg.Proxy.Timeout == 0 {
		cfg.Proxy.Timeout = 30 * time.Second
	}
	if cfg.Proxy.MaxIdleConns == 0 {
		cfg.Proxy.MaxIdleConns = 100
	}
	if cfg.Proxy.IdleConnTimeout == 0 {
		cfg.Proxy.IdleConnTimeout = 90 * time.Second
	}
	cfg.Proxy.InjectScript = true
	cfg.Proxy.CacheEnabled = true
	if cfg.Proxy.CacheTTL == 0 {
		cfg.Proxy.CacheTTL = 5 * time.Minute
	}

	// Auth defaults
	if cfg.Auth.JWTSecret == "" {
		cfg.Auth.JWTSecret = "change-this-secret-in-production"
	}
	if cfg.Auth.TokenExpiry == 0 {
		cfg.Auth.TokenExpiry = 24 * time.Hour
	}
	if cfg.Auth.AdminUsername == "" {
		cfg.Auth.AdminUsername = "admin"
	}
	if cfg.Auth.AdminPassword == "" {
		cfg.Auth.AdminPassword = "foco123@"
	}
}

// Save writes configuration to a YAML file
func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}


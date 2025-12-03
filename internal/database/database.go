package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/nexus-cloaker/cloaker/internal/config"
	"golang.org/x/crypto/bcrypt"
)

// DB wraps the database connection
type DB struct {
	conn   *sql.DB
	config config.DatabaseConfig
}

// New creates a new database connection
func New(cfg config.DatabaseConfig) (*DB, error) {
	// Ensure directory exists for SQLite
	if cfg.Driver == "sqlite3" || cfg.Driver == "sqlite" {
		dir := filepath.Dir(cfg.DSN)
		if dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return nil, fmt.Errorf("failed to create database directory: %w", err)
			}
		}
	}

	conn, err := sql.Open(cfg.Driver, cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	conn.SetMaxOpenConns(cfg.MaxConns)
	conn.SetMaxIdleConns(cfg.MaxConns / 2)
	conn.SetConnMaxLifetime(time.Hour)

	// Test connection
	if err := conn.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &DB{conn: conn, config: cfg}, nil
}

// Close closes the database connection
func (db *DB) Close() error {
	return db.conn.Close()
}

// Migrate runs database migrations
func (db *DB) Migrate() error {
	migrations := []string{
		// Users table
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			email TEXT,
			api_key TEXT UNIQUE,
			two_fa_enabled INTEGER DEFAULT 0,
			two_fa_secret TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_login_at DATETIME
		)`,

		// Campaigns table
		`CREATE TABLE IF NOT EXISTS campaigns (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT,
			safe_url TEXT,
			money_url TEXT,
			safe_html TEXT,
			money_html TEXT,
			safe_mode TEXT DEFAULT 'url',
			money_mode TEXT DEFAULT 'url',
			enabled INTEGER DEFAULT 1,
			ab_test_split INTEGER DEFAULT 100,
			allowed_countries TEXT,
			blocked_countries TEXT,
			allowed_devices TEXT,
			total_visits INTEGER DEFAULT 0,
			bot_visits INTEGER DEFAULT 0,
			human_visits INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// Domains table
		`CREATE TABLE IF NOT EXISTS domains (
			id TEXT PRIMARY KEY,
			campaign_id TEXT NOT NULL,
			domain TEXT UNIQUE NOT NULL,
			ssl_enabled INTEGER DEFAULT 0,
			ssl_cert TEXT,
			ssl_key TEXT,
			ssl_auto INTEGER DEFAULT 1,
			verified INTEGER DEFAULT 0,
			active INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE
		)`,

		// Visits table
		`CREATE TABLE IF NOT EXISTS visits (
			id TEXT PRIMARY KEY,
			campaign_id TEXT,
			domain_id TEXT,
			ip TEXT,
			user_agent TEXT,
			referer TEXT,
			url TEXT,
			method TEXT,
			country TEXT,
			city TEXT,
			asn TEXT,
			asn_org TEXT,
			device TEXT,
			os TEXT,
			browser TEXT,
			is_bot INTEGER DEFAULT 0,
			bot_score REAL DEFAULT 0,
			bot_reasons TEXT,
			fingerprint_id TEXT,
			page_served TEXT,
			processing_ms INTEGER,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE SET NULL,
			FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE SET NULL
		)`,

		// Fingerprints table
		`CREATE TABLE IF NOT EXISTS fingerprints (
			id TEXT PRIMARY KEY,
			visit_id TEXT,
			canvas_hash TEXT,
			webgl_vendor TEXT,
			webgl_renderer TEXT,
			webgl_hash TEXT,
			audio_hash TEXT,
			screen_width INTEGER,
			screen_height INTEGER,
			color_depth INTEGER,
			pixel_ratio REAL,
			timezone TEXT,
			language TEXT,
			languages TEXT,
			platform TEXT,
			cores INTEGER,
			memory INTEGER,
			touch_points INTEGER,
			webrtc_ips TEXT,
			webrtc_leak INTEGER DEFAULT 0,
			fonts_hash TEXT,
			font_count INTEGER,
			combined_hash TEXT,
			is_bot INTEGER DEFAULT 0,
			bot_score REAL DEFAULT 0,
			anomalies TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (visit_id) REFERENCES visits(id) ON DELETE CASCADE
		)`,

		// Rules table
		`CREATE TABLE IF NOT EXISTS rules (
			id TEXT PRIMARY KEY,
			campaign_id TEXT,
			name TEXT NOT NULL,
			description TEXT,
			type TEXT NOT NULL,
			conditions TEXT,
			action TEXT NOT NULL,
			redirect_url TEXT,
			priority INTEGER DEFAULT 0,
			enabled INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE
		)`,

		// Webhooks table
		`CREATE TABLE IF NOT EXISTS webhooks (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			type TEXT NOT NULL,
			config TEXT,
			events TEXT,
			enabled INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// Indexes
		`CREATE INDEX IF NOT EXISTS idx_visits_campaign ON visits(campaign_id)`,
		`CREATE INDEX IF NOT EXISTS idx_visits_created ON visits(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_visits_ip ON visits(ip)`,
		`CREATE INDEX IF NOT EXISTS idx_domains_domain ON domains(domain)`,
		`CREATE INDEX IF NOT EXISTS idx_fingerprints_hash ON fingerprints(combined_hash)`,
	}

	for _, migration := range migrations {
		if _, err := db.conn.Exec(migration); err != nil {
			return fmt.Errorf("migration failed: %w", err)
		}
	}

	// Create default admin user if not exists
	if err := db.createDefaultAdmin(); err != nil {
		return fmt.Errorf("failed to create default admin: %w", err)
	}

	return nil
}

func (db *DB) createDefaultAdmin() error {
	var count int
	err := db.conn.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil {
		return err
	}

	if count == 0 {
		hash, err := bcrypt.GenerateFromPassword([]byte("foco123@"), bcrypt.DefaultCost)
		if err != nil {
			return err
		}

		apiKey := uuid.New().String()
		_, err = db.conn.Exec(
			`INSERT INTO users (id, username, password_hash, api_key, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
			uuid.New().String(), "admin", string(hash), apiKey, time.Now(), time.Now(),
		)
		if err != nil {
			return err
		}
	}

	return nil
}

// =====================
// Campaign Operations
// =====================

func (db *DB) CreateCampaign(c *Campaign) error {
	c.ID = uuid.New().String()
	c.CreatedAt = time.Now()
	c.UpdatedAt = time.Now()

	allowedCountries, _ := json.Marshal(c.AllowedCountries)
	blockedCountries, _ := json.Marshal(c.BlockedCountries)
	allowedDevices, _ := json.Marshal(c.AllowedDevices)

	_, err := db.conn.Exec(
		`INSERT INTO campaigns (id, name, description, safe_url, money_url, safe_html, money_html, 
		safe_mode, money_mode, enabled, ab_test_split, allowed_countries, blocked_countries, 
		allowed_devices, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.Name, c.Description, c.SafeURL, c.MoneyURL, c.SafeHTML, c.MoneyHTML,
		c.SafeMode, c.MoneyMode, c.Enabled, c.ABTestSplit, string(allowedCountries),
		string(blockedCountries), string(allowedDevices), c.CreatedAt, c.UpdatedAt,
	)
	return err
}

func (db *DB) GetCampaign(id string) (*Campaign, error) {
	var c Campaign
	var allowedCountries, blockedCountries, allowedDevices string

	err := db.conn.QueryRow(
		`SELECT id, name, description, safe_url, money_url, safe_html, money_html,
		safe_mode, money_mode, enabled, ab_test_split, allowed_countries, blocked_countries,
		allowed_devices, total_visits, bot_visits, human_visits, created_at, updated_at
		FROM campaigns WHERE id = ?`, id,
	).Scan(
		&c.ID, &c.Name, &c.Description, &c.SafeURL, &c.MoneyURL, &c.SafeHTML, &c.MoneyHTML,
		&c.SafeMode, &c.MoneyMode, &c.Enabled, &c.ABTestSplit, &allowedCountries,
		&blockedCountries, &allowedDevices, &c.TotalVisits, &c.BotVisits, &c.HumanVisits,
		&c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	json.Unmarshal([]byte(allowedCountries), &c.AllowedCountries)
	json.Unmarshal([]byte(blockedCountries), &c.BlockedCountries)
	json.Unmarshal([]byte(allowedDevices), &c.AllowedDevices)

	return &c, nil
}

func (db *DB) ListCampaigns() ([]Campaign, error) {
	rows, err := db.conn.Query(
		`SELECT id, name, description, safe_url, money_url, safe_mode, money_mode, 
		enabled, ab_test_split, total_visits, bot_visits, human_visits, created_at, updated_at
		FROM campaigns ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var campaigns []Campaign
	for rows.Next() {
		var c Campaign
		err := rows.Scan(
			&c.ID, &c.Name, &c.Description, &c.SafeURL, &c.MoneyURL, &c.SafeMode, &c.MoneyMode,
			&c.Enabled, &c.ABTestSplit, &c.TotalVisits, &c.BotVisits, &c.HumanVisits,
			&c.CreatedAt, &c.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		campaigns = append(campaigns, c)
	}

	return campaigns, nil
}

func (db *DB) UpdateCampaign(c *Campaign) error {
	c.UpdatedAt = time.Now()

	allowedCountries, _ := json.Marshal(c.AllowedCountries)
	blockedCountries, _ := json.Marshal(c.BlockedCountries)
	allowedDevices, _ := json.Marshal(c.AllowedDevices)

	_, err := db.conn.Exec(
		`UPDATE campaigns SET name=?, description=?, safe_url=?, money_url=?, safe_html=?, money_html=?,
		safe_mode=?, money_mode=?, enabled=?, ab_test_split=?, allowed_countries=?, blocked_countries=?,
		allowed_devices=?, updated_at=? WHERE id=?`,
		c.Name, c.Description, c.SafeURL, c.MoneyURL, c.SafeHTML, c.MoneyHTML,
		c.SafeMode, c.MoneyMode, c.Enabled, c.ABTestSplit, string(allowedCountries),
		string(blockedCountries), string(allowedDevices), c.UpdatedAt, c.ID,
	)
	return err
}

func (db *DB) DeleteCampaign(id string) error {
	_, err := db.conn.Exec("DELETE FROM campaigns WHERE id = ?", id)
	return err
}

// =====================
// Domain Operations
// =====================

func (db *DB) CreateDomain(d *Domain) error {
	d.ID = uuid.New().String()
	d.CreatedAt = time.Now()
	d.UpdatedAt = time.Now()

	_, err := db.conn.Exec(
		`INSERT INTO domains (id, campaign_id, domain, ssl_enabled, ssl_auto, verified, active, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.ID, d.CampaignID, d.Domain, d.SSLEnabled, d.SSLAuto, d.Verified, d.Active, d.CreatedAt, d.UpdatedAt,
	)
	return err
}

func (db *DB) GetDomainByHost(host string) (*Domain, error) {
	var d Domain
	err := db.conn.QueryRow(
		`SELECT id, campaign_id, domain, ssl_enabled, ssl_cert, ssl_key, ssl_auto, verified, active, created_at, updated_at
		FROM domains WHERE domain = ? AND active = 1`, host,
	).Scan(
		&d.ID, &d.CampaignID, &d.Domain, &d.SSLEnabled, &d.SSLCert, &d.SSLKey, &d.SSLAuto, &d.Verified, &d.Active, &d.CreatedAt, &d.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func (db *DB) ListDomains(campaignID string) ([]Domain, error) {
	query := `SELECT id, campaign_id, domain, ssl_enabled, ssl_auto, verified, active, created_at, updated_at FROM domains`
	args := []interface{}{}

	if campaignID != "" {
		query += " WHERE campaign_id = ?"
		args = append(args, campaignID)
	}
	query += " ORDER BY created_at DESC"

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domains []Domain
	for rows.Next() {
		var d Domain
		err := rows.Scan(&d.ID, &d.CampaignID, &d.Domain, &d.SSLEnabled, &d.SSLAuto, &d.Verified, &d.Active, &d.CreatedAt, &d.UpdatedAt)
		if err != nil {
			return nil, err
		}
		domains = append(domains, d)
	}

	return domains, nil
}

func (db *DB) DeleteDomain(id string) error {
	_, err := db.conn.Exec("DELETE FROM domains WHERE id = ?", id)
	return err
}

// =====================
// Visit Operations
// =====================

func (db *DB) CreateVisit(v *Visit) error {
	v.ID = uuid.New().String()
	v.CreatedAt = time.Now()

	botReasons, _ := json.Marshal(v.BotReasons)

	_, err := db.conn.Exec(
		`INSERT INTO visits (id, campaign_id, domain_id, ip, user_agent, referer, url, method,
		country, city, asn, asn_org, device, os, browser, is_bot, bot_score, bot_reasons,
		fingerprint_id, page_served, processing_ms, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		v.ID, v.CampaignID, v.DomainID, v.IP, v.UserAgent, v.Referer, v.URL, v.Method,
		v.Country, v.City, v.ASN, v.ASNOrg, v.Device, v.OS, v.Browser, v.IsBot, v.BotScore,
		string(botReasons), v.FingerprintID, v.PageServed, v.ProcessingMs, v.CreatedAt,
	)

	// Update campaign stats
	if v.CampaignID != "" {
		if v.IsBot {
			db.conn.Exec("UPDATE campaigns SET total_visits = total_visits + 1, bot_visits = bot_visits + 1 WHERE id = ?", v.CampaignID)
		} else {
			db.conn.Exec("UPDATE campaigns SET total_visits = total_visits + 1, human_visits = human_visits + 1 WHERE id = ?", v.CampaignID)
		}
	}

	return err
}

func (db *DB) ListVisits(campaignID string, limit, offset int) ([]Visit, error) {
	query := `SELECT id, campaign_id, domain_id, ip, user_agent, referer, url, method,
		country, city, asn, asn_org, device, os, browser, is_bot, bot_score, bot_reasons,
		fingerprint_id, page_served, processing_ms, created_at FROM visits`
	args := []interface{}{}

	if campaignID != "" {
		query += " WHERE campaign_id = ?"
		args = append(args, campaignID)
	}
	query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var visits []Visit
	for rows.Next() {
		var v Visit
		var botReasons string
		err := rows.Scan(
			&v.ID, &v.CampaignID, &v.DomainID, &v.IP, &v.UserAgent, &v.Referer, &v.URL, &v.Method,
			&v.Country, &v.City, &v.ASN, &v.ASNOrg, &v.Device, &v.OS, &v.Browser, &v.IsBot, &v.BotScore,
			&botReasons, &v.FingerprintID, &v.PageServed, &v.ProcessingMs, &v.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(botReasons), &v.BotReasons)
		visits = append(visits, v)
	}

	return visits, nil
}

// =====================
// Fingerprint Operations
// =====================

func (db *DB) CreateFingerprint(f *Fingerprint) error {
	f.ID = uuid.New().String()
	f.CreatedAt = time.Now()

	languages, _ := json.Marshal(f.Languages)
	webrtcIPs, _ := json.Marshal(f.WebRTCIPs)
	anomalies, _ := json.Marshal(f.Anomalies)

	_, err := db.conn.Exec(
		`INSERT INTO fingerprints (id, visit_id, canvas_hash, webgl_vendor, webgl_renderer, webgl_hash,
		audio_hash, screen_width, screen_height, color_depth, pixel_ratio, timezone, language, languages,
		platform, cores, memory, touch_points, webrtc_ips, webrtc_leak, fonts_hash, font_count,
		combined_hash, is_bot, bot_score, anomalies, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, f.VisitID, f.CanvasHash, f.WebGLVendor, f.WebGLRenderer, f.WebGLHash,
		f.AudioHash, f.ScreenWidth, f.ScreenHeight, f.ColorDepth, f.PixelRatio, f.Timezone,
		f.Language, string(languages), f.Platform, f.Cores, f.Memory, f.TouchPoints,
		string(webrtcIPs), f.WebRTCLeak, f.FontsHash, f.FontCount, f.CombinedHash, f.IsBot,
		f.BotScore, string(anomalies), f.CreatedAt,
	)
	return err
}

func (db *DB) GetFingerprintByHash(hash string) (*Fingerprint, error) {
	var f Fingerprint
	var languages, webrtcIPs, anomalies string

	err := db.conn.QueryRow(
		`SELECT id, visit_id, canvas_hash, webgl_vendor, webgl_renderer, webgl_hash,
		audio_hash, screen_width, screen_height, color_depth, pixel_ratio, timezone, language, languages,
		platform, cores, memory, touch_points, webrtc_ips, webrtc_leak, fonts_hash, font_count,
		combined_hash, is_bot, bot_score, anomalies, created_at FROM fingerprints WHERE combined_hash = ?
		ORDER BY created_at DESC LIMIT 1`, hash,
	).Scan(
		&f.ID, &f.VisitID, &f.CanvasHash, &f.WebGLVendor, &f.WebGLRenderer, &f.WebGLHash,
		&f.AudioHash, &f.ScreenWidth, &f.ScreenHeight, &f.ColorDepth, &f.PixelRatio, &f.Timezone,
		&f.Language, &languages, &f.Platform, &f.Cores, &f.Memory, &f.TouchPoints,
		&webrtcIPs, &f.WebRTCLeak, &f.FontsHash, &f.FontCount, &f.CombinedHash, &f.IsBot,
		&f.BotScore, &anomalies, &f.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	json.Unmarshal([]byte(languages), &f.Languages)
	json.Unmarshal([]byte(webrtcIPs), &f.WebRTCIPs)
	json.Unmarshal([]byte(anomalies), &f.Anomalies)

	return &f, nil
}

// =====================
// User Operations
// =====================

func (db *DB) GetUserByUsername(username string) (*User, error) {
	var u User
	err := db.conn.QueryRow(
		`SELECT id, username, password_hash, email, api_key, two_fa_enabled, two_fa_secret,
		created_at, updated_at, last_login_at FROM users WHERE username = ?`, username,
	).Scan(
		&u.ID, &u.Username, &u.PasswordHash, &u.Email, &u.APIKey, &u.TwoFAEnabled,
		&u.TwoFASecret, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt,
	)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (db *DB) GetUserByAPIKey(apiKey string) (*User, error) {
	var u User
	err := db.conn.QueryRow(
		`SELECT id, username, password_hash, email, api_key, two_fa_enabled, created_at, updated_at
		FROM users WHERE api_key = ?`, apiKey,
	).Scan(
		&u.ID, &u.Username, &u.PasswordHash, &u.Email, &u.APIKey, &u.TwoFAEnabled, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (db *DB) UpdateUserLastLogin(id string) error {
	_, err := db.conn.Exec("UPDATE users SET last_login_at = ? WHERE id = ?", time.Now(), id)
	return err
}

// =====================
// Stats Operations
// =====================

func (db *DB) GetStats() (*Stats, error) {
	stats := &Stats{}

	// Total visits
	db.conn.QueryRow("SELECT COUNT(*) FROM visits").Scan(&stats.TotalVisits)

	// Today visits
	today := time.Now().Format("2006-01-02")
	db.conn.QueryRow("SELECT COUNT(*) FROM visits WHERE DATE(created_at) = ?", today).Scan(&stats.TodayVisits)

	// Bot percentage
	var botCount int64
	db.conn.QueryRow("SELECT COUNT(*) FROM visits WHERE is_bot = 1").Scan(&botCount)
	if stats.TotalVisits > 0 {
		stats.BotPercentage = float64(botCount) / float64(stats.TotalVisits) * 100
		stats.HumanPercentage = 100 - stats.BotPercentage
	}

	// Top countries
	rows, _ := db.conn.Query(`SELECT country, COUNT(*) as cnt FROM visits WHERE country != '' 
		GROUP BY country ORDER BY cnt DESC LIMIT 10`)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var cs CountryStat
			rows.Scan(&cs.Country, &cs.Count)
			stats.TopCountries = append(stats.TopCountries, cs)
		}
	}

	// Top devices
	rows2, _ := db.conn.Query(`SELECT device, COUNT(*) as cnt FROM visits WHERE device != '' 
		GROUP BY device ORDER BY cnt DESC LIMIT 5`)
	if rows2 != nil {
		defer rows2.Close()
		for rows2.Next() {
			var ds DeviceStat
			rows2.Scan(&ds.Device, &ds.Count)
			stats.TopDevices = append(stats.TopDevices, ds)
		}
	}

	return stats, nil
}

// =====================
// Webhook Operations
// =====================

func (db *DB) CreateWebhook(w *Webhook) error {
	w.ID = uuid.New().String()
	w.CreatedAt = time.Now()
	w.UpdatedAt = time.Now()

	events, _ := json.Marshal(w.Events)

	_, err := db.conn.Exec(
		`INSERT INTO webhooks (id, name, type, config, events, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		w.ID, w.Name, w.Type, w.Config, string(events), w.Enabled, w.CreatedAt, w.UpdatedAt,
	)
	return err
}

func (db *DB) ListWebhooks() ([]Webhook, error) {
	rows, err := db.conn.Query(
		`SELECT id, name, type, config, events, enabled, created_at, updated_at FROM webhooks ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var webhooks []Webhook
	for rows.Next() {
		var w Webhook
		var events string
		err := rows.Scan(&w.ID, &w.Name, &w.Type, &w.Config, &events, &w.Enabled, &w.CreatedAt, &w.UpdatedAt)
		if err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(events), &w.Events)
		webhooks = append(webhooks, w)
	}

	return webhooks, nil
}

func (db *DB) DeleteWebhook(id string) error {
	_, err := db.conn.Exec("DELETE FROM webhooks WHERE id = ?", id)
	return err
}


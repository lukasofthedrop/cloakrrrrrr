package detection

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nexus-cloaker/cloaker/internal/config"
)

// Result contains the detection analysis results
type Result struct {
	IsBot       bool      `json:"is_bot"`
	Score       float64   `json:"score"` // 0.0 (human) to 1.0 (bot)
	Reasons     []string  `json:"reasons"`
	Confidence  float64   `json:"confidence"`
	ProcessedAt time.Time `json:"processed_at"`
	
	// Detailed checks
	IPCheck       CheckResult `json:"ip_check"`
	ASNCheck      CheckResult `json:"asn_check"`
	UACheck       CheckResult `json:"ua_check"`
	TLSCheck      CheckResult `json:"tls_check"`
	BehaviorCheck CheckResult `json:"behavior_check"`
}

type CheckResult struct {
	Passed  bool    `json:"passed"`
	Score   float64 `json:"score"`
	Reason  string  `json:"reason,omitempty"`
	Details string  `json:"details,omitempty"`
}

// RequestInfo contains information about the incoming request
type RequestInfo struct {
	IP          string
	UserAgent   string
	Referer     string
	URL         string
	Method      string
	Headers     http.Header
	TLSVersion  uint16
	TLSCipher   uint16
	Cookies     []*http.Cookie
}

// Engine is the main detection engine
type Engine struct {
	config     config.DetectionConfig
	
	// IP data
	botIPs         map[string]bool
	datacenterCIDRs []*net.IPNet
	vpnCIDRs       []*net.IPNet
	
	// ASN data
	datacenterASNs map[string]bool
	vpnASNs        map[string]bool
	
	// User-Agent data
	botUAPatterns  []string
	crawlerUAs     map[string]bool
	
	// Fingerprint cache
	fingerprintCache sync.Map
	
	mu sync.RWMutex
}

// NewEngine creates a new detection engine
func NewEngine(cfg config.DetectionConfig) (*Engine, error) {
	e := &Engine{
		config:         cfg,
		botIPs:         make(map[string]bool),
		datacenterASNs: make(map[string]bool),
		vpnASNs:        make(map[string]bool),
		crawlerUAs:     make(map[string]bool),
	}

	// Load data from filesystem
	if err := e.loadData(); err != nil {
		log.Printf("Warning: Could not load some detection data: %v", err)
	}

	return e, nil
}

func (e *Engine) loadData() error {
	// Load bot IPs
	if data, err := os.ReadFile("data/ip_ranges.json"); err == nil {
		var ips struct {
			Meta       []string `json:"meta"`
			TikTok     []string `json:"tiktok"`
			Google     []string `json:"google"`
			Datacenters []string `json:"datacenters"`
		}
		if err := json.Unmarshal(data, &ips); err == nil {
			for _, ip := range ips.Meta {
				e.botIPs[ip] = true
				if _, cidr, err := net.ParseCIDR(ip); err == nil {
					e.datacenterCIDRs = append(e.datacenterCIDRs, cidr)
				}
			}
			for _, ip := range ips.TikTok {
				e.botIPs[ip] = true
				if _, cidr, err := net.ParseCIDR(ip); err == nil {
					e.datacenterCIDRs = append(e.datacenterCIDRs, cidr)
				}
			}
			for _, ip := range ips.Google {
				e.botIPs[ip] = true
			}
			for _, ip := range ips.Datacenters {
				if _, cidr, err := net.ParseCIDR(ip); err == nil {
					e.datacenterCIDRs = append(e.datacenterCIDRs, cidr)
				}
			}
		}
	}

	// Load bot signatures
	if data, err := os.ReadFile("data/bot_signatures.json"); err == nil {
		var sigs struct {
			UserAgents []string `json:"user_agents"`
			ASNs       []string `json:"datacenter_asns"`
			VPNASNs    []string `json:"vpn_asns"`
		}
		if err := json.Unmarshal(data, &sigs); err == nil {
			e.botUAPatterns = sigs.UserAgents
			for _, ua := range sigs.UserAgents {
				e.crawlerUAs[strings.ToLower(ua)] = true
			}
			for _, asn := range sigs.ASNs {
				e.datacenterASNs[asn] = true
			}
			for _, asn := range sigs.VPNASNs {
				e.vpnASNs[asn] = true
			}
		}
	}

	log.Printf("Detection engine loaded: %d bot IPs, %d CIDRs, %d UA patterns, %d datacenter ASNs",
		len(e.botIPs), len(e.datacenterCIDRs), len(e.botUAPatterns), len(e.datacenterASNs))

	return nil
}

// Analyze performs detection analysis on a request
func (e *Engine) Analyze(req *RequestInfo) *Result {
	result := &Result{
		ProcessedAt: time.Now(),
		Reasons:     []string{},
	}

	var totalScore float64
	var checksPerformed int

	// 1. IP Check
	if e.config.EnableIPCheck {
		result.IPCheck = e.checkIP(req.IP)
		totalScore += result.IPCheck.Score
		checksPerformed++
		if !result.IPCheck.Passed {
			result.Reasons = append(result.Reasons, result.IPCheck.Reason)
		}
	}

	// 2. ASN Check
	if e.config.EnableASNCheck {
		result.ASNCheck = e.checkASN(req.IP)
		totalScore += result.ASNCheck.Score
		checksPerformed++
		if !result.ASNCheck.Passed {
			result.Reasons = append(result.Reasons, result.ASNCheck.Reason)
		}
	}

	// 3. User-Agent Check
	if e.config.EnableUACheck {
		result.UACheck = e.checkUserAgent(req.UserAgent)
		totalScore += result.UACheck.Score
		checksPerformed++
		if !result.UACheck.Passed {
			result.Reasons = append(result.Reasons, result.UACheck.Reason)
		}
	}

	// 4. TLS Check (JA3-like)
	result.TLSCheck = e.checkTLS(req.TLSVersion, req.TLSCipher)
	totalScore += result.TLSCheck.Score
	checksPerformed++
	if !result.TLSCheck.Passed {
		result.Reasons = append(result.Reasons, result.TLSCheck.Reason)
	}

	// Calculate final score
	if checksPerformed > 0 {
		result.Score = totalScore / float64(checksPerformed)
	}

	// Determine if bot based on threshold
	result.IsBot = result.Score >= e.config.BotScoreThreshold
	result.Confidence = calculateConfidence(result)

	return result
}

func (e *Engine) checkIP(ip string) CheckResult {
	result := CheckResult{Passed: true, Score: 0}

	// Direct IP match
	if e.botIPs[ip] {
		result.Passed = false
		result.Score = 1.0
		result.Reason = "IP known bot/crawler"
		result.Details = ip
		return result
	}

	// CIDR match
	parsedIP := net.ParseIP(ip)
	if parsedIP != nil {
		for _, cidr := range e.datacenterCIDRs {
			if cidr.Contains(parsedIP) {
				result.Passed = false
				result.Score = 0.9
				result.Reason = "IP in datacenter range"
				result.Details = cidr.String()
				return result
			}
		}
	}

	return result
}

func (e *Engine) checkASN(ip string) CheckResult {
	result := CheckResult{Passed: true, Score: 0}
	
	// TODO: Implement GeoIP ASN lookup
	// For now, return passed
	
	return result
}

func (e *Engine) checkUserAgent(ua string) CheckResult {
	result := CheckResult{Passed: true, Score: 0}

	if ua == "" {
		result.Passed = false
		result.Score = 0.8
		result.Reason = "Empty User-Agent"
		return result
	}

	uaLower := strings.ToLower(ua)

	// Check known bot patterns
	botKeywords := []string{
		"bot", "crawler", "spider", "scraper", "curl", "wget", "python",
		"java", "go-http", "httpie", "postman", "insomnia", "axios",
		"node-fetch", "php", "ruby", "perl", "libwww", "apache-httpclient",
		"okhttp", "headless", "phantom", "selenium", "puppeteer", "playwright",
		"facebookexternalhit", "facebot", "bytespider", "bytedance",
		"googlebot", "bingbot", "yandex", "baidu", "duckduck",
		"slurp", "ia_archiver", "mediapartners", "adsbot",
	}

	for _, keyword := range botKeywords {
		if strings.Contains(uaLower, keyword) {
			result.Passed = false
			result.Score = 0.95
			result.Reason = "Bot User-Agent detected"
			result.Details = keyword
			return result
		}
	}

	// Check for suspicious patterns
	if len(ua) < 20 {
		result.Score = 0.3
		result.Reason = "Suspiciously short User-Agent"
	}

	// Check for common browser signatures
	hasBrowserSignature := strings.Contains(uaLower, "mozilla") ||
		strings.Contains(uaLower, "chrome") ||
		strings.Contains(uaLower, "safari") ||
		strings.Contains(uaLower, "firefox") ||
		strings.Contains(uaLower, "edge")

	if !hasBrowserSignature {
		result.Score = 0.5
		result.Reason = "Non-browser User-Agent"
	}

	return result
}

func (e *Engine) checkTLS(version uint16, cipher uint16) CheckResult {
	result := CheckResult{Passed: true, Score: 0}

	// Check TLS version (older versions are suspicious)
	// TLS 1.0 = 0x0301, TLS 1.1 = 0x0302, TLS 1.2 = 0x0303, TLS 1.3 = 0x0304
	if version < 0x0303 { // Less than TLS 1.2
		result.Score = 0.3
		result.Reason = "Old TLS version"
	}

	return result
}

func calculateConfidence(result *Result) float64 {
	// Higher confidence when multiple signals agree
	reasons := len(result.Reasons)
	if reasons == 0 {
		return 0.9 // High confidence it's human
	}
	if reasons >= 3 {
		return 0.95 // Very confident it's a bot
	}
	return 0.7 + (float64(reasons) * 0.1)
}

// AnalyzeFingerprint analyzes client-side fingerprint data
func (e *Engine) AnalyzeFingerprint(fp *FingerprintData) *FingerprintResult {
	result := &FingerprintResult{
		Anomalies: []string{},
	}

	var score float64
	var checks int

	// Check for headless browser indicators
	if fp.WebGLVendor == "Brian Paul" || fp.WebGLRenderer == "Mesa OffScreen" {
		score += 1.0
		result.Anomalies = append(result.Anomalies, "Headless browser WebGL")
	}
	checks++

	// Check for automation indicators
	if fp.Cores == 0 || fp.Memory == 0 {
		score += 0.5
		result.Anomalies = append(result.Anomalies, "Missing hardware info")
	}
	checks++

	// Check screen dimensions
	if fp.ScreenWidth == 0 || fp.ScreenHeight == 0 {
		score += 0.7
		result.Anomalies = append(result.Anomalies, "Invalid screen dimensions")
	} else if fp.ScreenWidth == 800 && fp.ScreenHeight == 600 {
		score += 0.4
		result.Anomalies = append(result.Anomalies, "Default VM screen size")
	}
	checks++

	// Check for timezone mismatch (would need IP geolocation)
	if fp.Timezone == "" {
		score += 0.3
		result.Anomalies = append(result.Anomalies, "Missing timezone")
	}
	checks++

	// Check for WebRTC leak (VPN detection)
	if fp.WebRTCLeak {
		score += 0.6
		result.Anomalies = append(result.Anomalies, "WebRTC IP leak detected")
	}
	checks++

	// Check canvas fingerprint
	if fp.CanvasHash == "" || fp.CanvasHash == "0" {
		score += 0.5
		result.Anomalies = append(result.Anomalies, "Canvas fingerprint blocked/missing")
	}
	checks++

	// Check touch support vs device type
	if fp.TouchPoints > 0 && fp.Platform != "" && 
		!strings.Contains(strings.ToLower(fp.Platform), "android") &&
		!strings.Contains(strings.ToLower(fp.Platform), "iphone") &&
		!strings.Contains(strings.ToLower(fp.Platform), "ipad") {
		// Desktop claiming touch support - might be emulation
		score += 0.2
	}
	checks++

	// Calculate final score
	if checks > 0 {
		result.Score = score / float64(checks)
	}

	result.IsBot = result.Score >= e.config.BotScoreThreshold

	return result
}

// FingerprintData represents client-side fingerprint
type FingerprintData struct {
	CanvasHash    string   `json:"canvas"`
	WebGLVendor   string   `json:"webgl_vendor"`
	WebGLRenderer string   `json:"webgl_renderer"`
	WebGLHash     string   `json:"webgl"`
	AudioHash     string   `json:"audio"`
	ScreenWidth   int      `json:"screen_width"`
	ScreenHeight  int      `json:"screen_height"`
	ColorDepth    int      `json:"color_depth"`
	PixelRatio    float64  `json:"pixel_ratio"`
	Timezone      string   `json:"timezone"`
	Language      string   `json:"language"`
	Languages     []string `json:"languages"`
	Platform      string   `json:"platform"`
	Cores         int      `json:"cores"`
	Memory        int      `json:"memory"`
	TouchPoints   int      `json:"touch_points"`
	WebRTCIPs     []string `json:"webrtc_ips"`
	WebRTCLeak    bool     `json:"webrtc_leak"`
	FontsHash     string   `json:"fonts"`
	FontCount     int      `json:"font_count"`
}

type FingerprintResult struct {
	IsBot     bool     `json:"is_bot"`
	Score     float64  `json:"score"`
	Anomalies []string `json:"anomalies"`
}

// QuickCheck performs a fast initial check (for first-pass filtering)
func (e *Engine) QuickCheck(ip, userAgent string) bool {
	// Direct IP check
	if e.botIPs[ip] {
		return true
	}

	// Quick UA check
	uaLower := strings.ToLower(userAgent)
	quickBots := []string{"bot", "crawler", "spider", "facebookexternalhit", "bytespider"}
	for _, bot := range quickBots {
		if strings.Contains(uaLower, bot) {
			return true
		}
	}

	return false
}


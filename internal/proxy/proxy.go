package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/allegro/bigcache/v3"
	"github.com/nexus-cloaker/cloaker/internal/config"
	"github.com/nexus-cloaker/cloaker/internal/database"
	"github.com/nexus-cloaker/cloaker/internal/detection"
)

// Server is the proxy server
type Server struct {
	config   config.ProxyConfig
	detector *detection.Engine
	db       *database.DB
	cache    *bigcache.BigCache
	server   *http.Server

	// Fingerprint script to inject
	fingerprintScript string

	mu sync.RWMutex
}

// New creates a new proxy server
func New(cfg config.ProxyConfig, detector *detection.Engine, db *database.DB) *Server {
	// Initialize cache with minimal memory footprint for App Platform
	cacheConfig := bigcache.DefaultConfig(cfg.CacheTTL)
	cacheConfig.MaxEntrySize = 1024 * 1024     // 1MB max per entry (reduced)
	cacheConfig.HardMaxCacheSize = 50          // Max 50MB total cache
	cacheConfig.Shards = 256                   // Fewer shards for less memory
	cache, _ := bigcache.New(context.Background(), cacheConfig)

	return &Server{
		config:            cfg,
		detector:          detector,
		db:                db,
		cache:             cache,
		fingerprintScript: getFingerprintScript(),
	}
}

// Start starts the proxy server
func (s *Server) Start(addr string) error {
	s.server = &http.Server{
		Addr:         addr,
		Handler:      s,
		ReadTimeout:  s.config.Timeout,
		WriteTimeout: s.config.Timeout,
		IdleTimeout:  s.config.IdleConnTimeout,
	}

	return s.server.ListenAndServe()
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown() error {
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return s.server.Shutdown(ctx)
	}
	return nil
}

// ServeHTTP handles incoming requests
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Get client IP
	clientIP := getClientIP(r)

	// Get the domain from host header
	host := r.Host
	if colonIdx := strings.Index(host, ":"); colonIdx != -1 {
		host = host[:colonIdx]
	}

	// Look up domain configuration
	domain, err := s.db.GetDomainByHost(host)
	if err != nil {
		log.Printf("Unknown domain: %s", host)
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// Get campaign
	campaign, err := s.db.GetCampaign(domain.CampaignID)
	if err != nil || !campaign.Enabled {
		log.Printf("Campaign not found or disabled for domain: %s", host)
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// Perform detection
	reqInfo := &detection.RequestInfo{
		IP:        clientIP,
		UserAgent: r.UserAgent(),
		Referer:   r.Referer(),
		URL:       r.URL.String(),
		Method:    r.Method,
		Headers:   r.Header,
	}

	// Get TLS info if available
	if r.TLS != nil {
		reqInfo.TLSVersion = r.TLS.Version
		reqInfo.TLSCipher = r.TLS.CipherSuite
	}

	// Quick check first (fast path for obvious bots)
	isBot := s.detector.QuickCheck(clientIP, r.UserAgent())

	// Full analysis if not obviously a bot
	var result *detection.Result
	if !isBot {
		result = s.detector.Analyze(reqInfo)
		isBot = result.IsBot
	} else {
		result = &detection.Result{
			IsBot:   true,
			Score:   1.0,
			Reasons: []string{"Quick check match"},
		}
	}

	// Determine which page to serve
	pageToServe := "money"
	if isBot {
		pageToServe = "safe"
	} else {
		// A/B test split (only for non-bots)
		if campaign.ABTestSplit < 100 {
			// Simple random split based on IP hash
			ipHash := hashIP(clientIP)
			if int(ipHash%100) >= campaign.ABTestSplit {
				pageToServe = "safe"
			}
		}
	}

	// Log the visit
	go func() {
		visit := &database.Visit{
			CampaignID:   campaign.ID,
			DomainID:     domain.ID,
			IP:           clientIP,
			UserAgent:    r.UserAgent(),
			Referer:      r.Referer(),
			URL:          r.URL.String(),
			Method:       r.Method,
			IsBot:        isBot,
			BotScore:     result.Score,
			BotReasons:   result.Reasons,
			PageServed:   pageToServe,
			ProcessingMs: time.Since(startTime).Milliseconds(),
		}
		// Parse device info from UA
		visit.Device, visit.OS, visit.Browser = parseUserAgent(r.UserAgent())

		if err := s.db.CreateVisit(visit); err != nil {
			log.Printf("Failed to log visit: %v", err)
		}
	}()

	// Serve the appropriate page
	var targetURL string
	var htmlContent string

	if pageToServe == "safe" {
		if campaign.SafeMode == "html" {
			htmlContent = campaign.SafeHTML
		} else {
			targetURL = campaign.SafeURL
		}
	} else {
		if campaign.MoneyMode == "html" {
			htmlContent = campaign.MoneyHTML
		} else {
			targetURL = campaign.MoneyURL
		}
	}

	// Serve HTML directly or proxy to URL
	if htmlContent != "" {
		s.serveHTML(w, r, htmlContent, !isBot)
	} else if targetURL != "" {
		s.proxyRequest(w, r, targetURL, !isBot)
	} else {
		http.Error(w, "Configuration Error", http.StatusInternalServerError)
	}
}

func (s *Server) serveHTML(w http.ResponseWriter, r *http.Request, html string, injectScript bool) {
	// Inject fingerprint script if needed
	if injectScript && s.config.InjectScript {
		html = injectFingerprintScript(html, s.fingerprintScript)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func (s *Server) proxyRequest(w http.ResponseWriter, r *http.Request, targetURL string, injectScript bool) {
	target, err := url.Parse(targetURL)
	if err != nil {
		http.Error(w, "Invalid target URL", http.StatusInternalServerError)
		return
	}

	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Custom transport for following redirects
	proxy.Transport = &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:          s.config.MaxIdleConns,
		IdleConnTimeout:       s.config.IdleConnTimeout,
		ResponseHeaderTimeout: s.config.Timeout,
	}

	// Modify the request
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = target.Host
		req.URL.Host = target.Host
		req.URL.Scheme = target.Scheme
		
		// Preserve original path if target doesn't specify one
		if target.Path == "" || target.Path == "/" {
			req.URL.Path = r.URL.Path
		}
		
		// Forward relevant headers
		req.Header.Set("X-Forwarded-Host", r.Host)
	}

	// Modify the response to inject script
	if injectScript && s.config.InjectScript {
		proxy.ModifyResponse = func(resp *http.Response) error {
			// Only inject into HTML responses
			contentType := resp.Header.Get("Content-Type")
			if !strings.Contains(contentType, "text/html") {
				return nil
			}

			// Read the body
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return err
			}

			// Decompress if gzipped
			if resp.Header.Get("Content-Encoding") == "gzip" {
				reader, err := gzip.NewReader(bytes.NewReader(body))
				if err == nil {
					body, _ = io.ReadAll(reader)
					reader.Close()
					resp.Header.Del("Content-Encoding")
				}
			}

			// Inject the script
			modifiedBody := injectFingerprintScript(string(body), s.fingerprintScript)

			// Update the response
			resp.Body = io.NopCloser(strings.NewReader(modifiedBody))
			resp.ContentLength = int64(len(modifiedBody))
			resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(modifiedBody)))

			return nil
		}
	}

	proxy.ServeHTTP(w, r)
}

func injectFingerprintScript(html, script string) string {
	// Try to inject before </body>
	bodyClose := strings.LastIndex(strings.ToLower(html), "</body>")
	if bodyClose != -1 {
		return html[:bodyClose] + script + html[bodyClose:]
	}

	// Try to inject before </html>
	htmlClose := strings.LastIndex(strings.ToLower(html), "</html>")
	if htmlClose != -1 {
		return html[:htmlClose] + script + html[htmlClose:]
	}

	// Just append at the end
	return html + script
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}

	// Check CF-Connecting-IP (Cloudflare)
	cfIP := r.Header.Get("CF-Connecting-IP")
	if cfIP != "" {
		return cfIP
	}

	// Fall back to RemoteAddr
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

func hashIP(ip string) uint32 {
	var hash uint32 = 2166136261
	for i := 0; i < len(ip); i++ {
		hash ^= uint32(ip[i])
		hash *= 16777619
	}
	return hash
}

func parseUserAgent(ua string) (device, os, browser string) {
	uaLower := strings.ToLower(ua)

	// Detect device
	if strings.Contains(uaLower, "mobile") || strings.Contains(uaLower, "android") {
		device = "Mobile"
	} else if strings.Contains(uaLower, "tablet") || strings.Contains(uaLower, "ipad") {
		device = "Tablet"
	} else {
		device = "Desktop"
	}

	// Detect OS
	switch {
	case strings.Contains(uaLower, "windows"):
		os = "Windows"
	case strings.Contains(uaLower, "mac os") || strings.Contains(uaLower, "macos"):
		os = "macOS"
	case strings.Contains(uaLower, "linux"):
		os = "Linux"
	case strings.Contains(uaLower, "android"):
		os = "Android"
	case strings.Contains(uaLower, "iphone") || strings.Contains(uaLower, "ipad"):
		os = "iOS"
	default:
		os = "Unknown"
	}

	// Detect browser
	switch {
	case strings.Contains(uaLower, "edg"):
		browser = "Edge"
	case strings.Contains(uaLower, "chrome") && !strings.Contains(uaLower, "edg"):
		browser = "Chrome"
	case strings.Contains(uaLower, "firefox"):
		browser = "Firefox"
	case strings.Contains(uaLower, "safari") && !strings.Contains(uaLower, "chrome"):
		browser = "Safari"
	case strings.Contains(uaLower, "opera") || strings.Contains(uaLower, "opr"):
		browser = "Opera"
	default:
		browser = "Unknown"
	}

	return
}

func getFingerprintScript() string {
	return `<script>
(function(){
  'use strict';
  
  // Fingerprint collection script
  const fp = {};
  
  // Canvas fingerprint
  async function getCanvasFingerprint() {
    try {
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      canvas.width = 200;
      canvas.height = 50;
      
      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.fillStyle = '#f60';
      ctx.fillRect(0, 0, 100, 50);
      ctx.fillStyle = '#069';
      ctx.fillText('Cwm fjord veg balks', 2, 15);
      ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
      ctx.fillText('xyz', 4, 17);
      
      return canvas.toDataURL().slice(-50);
    } catch (e) {
      return '';
    }
  }
  
  // WebGL fingerprint
  function getWebGLFingerprint() {
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) return { vendor: '', renderer: '', hash: '' };
      
      const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
      return {
        vendor: debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : '',
        renderer: debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : '',
        hash: gl.getParameter(gl.VERSION) + gl.getParameter(gl.SHADING_LANGUAGE_VERSION)
      };
    } catch (e) {
      return { vendor: '', renderer: '', hash: '' };
    }
  }
  
  // Audio fingerprint
  async function getAudioFingerprint() {
    try {
      const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      const oscillator = audioCtx.createOscillator();
      const analyser = audioCtx.createAnalyser();
      const gain = audioCtx.createGain();
      const processor = audioCtx.createScriptProcessor(4096, 1, 1);
      
      gain.gain.value = 0;
      oscillator.type = 'triangle';
      oscillator.connect(analyser);
      analyser.connect(processor);
      processor.connect(gain);
      gain.connect(audioCtx.destination);
      oscillator.start(0);
      
      return new Promise(resolve => {
        processor.onaudioprocess = function(e) {
          const data = new Float32Array(analyser.frequencyBinCount);
          analyser.getFloatFrequencyData(data);
          let hash = 0;
          for (let i = 0; i < data.length; i++) {
            hash += Math.abs(data[i]);
          }
          oscillator.stop();
          audioCtx.close();
          resolve(hash.toString(36).slice(0, 10));
        };
      });
    } catch (e) {
      return '';
    }
  }
  
  // WebRTC IP detection
  async function getWebRTCIPs() {
    return new Promise(resolve => {
      const ips = [];
      try {
        const pc = new RTCPeerConnection({ iceServers: [] });
        pc.createDataChannel('');
        pc.createOffer().then(offer => pc.setLocalDescription(offer));
        
        pc.onicecandidate = (e) => {
          if (!e.candidate) {
            pc.close();
            resolve(ips);
            return;
          }
          const parts = e.candidate.candidate.split(' ');
          const ip = parts[4];
          if (ip && !ips.includes(ip) && !ip.includes(':')) {
            ips.push(ip);
          }
        };
        
        setTimeout(() => {
          pc.close();
          resolve(ips);
        }, 1000);
      } catch (e) {
        resolve(ips);
      }
    });
  }
  
  // Collect all fingerprints
  async function collect() {
    const webgl = getWebGLFingerprint();
    
    fp.canvas = await getCanvasFingerprint();
    fp.webgl_vendor = webgl.vendor;
    fp.webgl_renderer = webgl.renderer;
    fp.webgl = webgl.hash;
    fp.audio = await getAudioFingerprint();
    fp.screen_width = screen.width;
    fp.screen_height = screen.height;
    fp.color_depth = screen.colorDepth;
    fp.pixel_ratio = window.devicePixelRatio || 1;
    fp.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    fp.language = navigator.language;
    fp.languages = navigator.languages ? Array.from(navigator.languages) : [];
    fp.platform = navigator.platform;
    fp.cores = navigator.hardwareConcurrency || 0;
    fp.memory = navigator.deviceMemory || 0;
    fp.touch_points = navigator.maxTouchPoints || 0;
    fp.webrtc_ips = await getWebRTCIPs();
    
    // Check for WebRTC leak (multiple IPs might indicate VPN)
    fp.webrtc_leak = fp.webrtc_ips.length > 1;
    
    // Send to server
    try {
      navigator.sendBeacon('/api/v1/fp', JSON.stringify(fp));
    } catch (e) {
      fetch('/api/v1/fp', {
        method: 'POST',
        body: JSON.stringify(fp),
        headers: { 'Content-Type': 'application/json' },
        keepalive: true
      }).catch(() => {});
    }
  }
  
  // Run after page load
  if (document.readyState === 'complete') {
    setTimeout(collect, 100);
  } else {
    window.addEventListener('load', () => setTimeout(collect, 100));
  }
})();
</script>`
}


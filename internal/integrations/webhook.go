package integrations

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/nexus-cloaker/cloaker/internal/database"
)

// Event types
const (
	EventVisit       = "visit"
	EventBotDetected = "bot_detected"
	EventConversion  = "conversion"
	EventError       = "error"
)

// WebhookManager manages all webhook integrations
type WebhookManager struct {
	db     *database.DB
	client *http.Client
}

// NewWebhookManager creates a new webhook manager
func NewWebhookManager(db *database.DB) *WebhookManager {
	return &WebhookManager{
		db: db,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Event represents a webhook event
type Event struct {
	Type      string      `json:"type"`
	Timestamp time.Time   `json:"timestamp"`
	Data      interface{} `json:"data"`
}

// VisitData contains data for visit events
type VisitData struct {
	IP          string  `json:"ip"`
	Country     string  `json:"country"`
	Device      string  `json:"device"`
	Browser     string  `json:"browser"`
	IsBot       bool    `json:"is_bot"`
	BotScore    float64 `json:"bot_score"`
	BotReasons  []string `json:"bot_reasons,omitempty"`
	PageServed  string  `json:"page_served"`
	CampaignID  string  `json:"campaign_id"`
	URL         string  `json:"url"`
}

// Trigger sends an event to all configured webhooks
func (m *WebhookManager) Trigger(eventType string, data interface{}) {
	webhooks, err := m.db.ListWebhooks()
	if err != nil {
		return
	}

	event := Event{
		Type:      eventType,
		Timestamp: time.Now(),
		Data:      data,
	}

	for _, webhook := range webhooks {
		if !webhook.Enabled {
			continue
		}

		// Check if webhook is subscribed to this event type
		subscribed := false
		for _, e := range webhook.Events {
			if e == eventType {
				subscribed = true
				break
			}
		}
		if !subscribed {
			continue
		}

		go m.send(webhook, event)
	}
}

func (m *WebhookManager) send(webhook database.Webhook, event Event) {
	var err error

	switch webhook.Type {
	case "telegram":
		err = m.sendTelegram(webhook, event)
	case "discord":
		err = m.sendDiscord(webhook, event)
	case "custom":
		err = m.sendCustom(webhook, event)
	}

	if err != nil {
		fmt.Printf("Webhook error (%s): %v\n", webhook.Name, err)
	}
}

// Telegram integration

type TelegramConfig struct {
	BotToken string `json:"bot_token"`
	ChatID   string `json:"chat_id"`
}

func (m *WebhookManager) sendTelegram(webhook database.Webhook, event Event) error {
	var config TelegramConfig
	if err := json.Unmarshal([]byte(webhook.Config), &config); err != nil {
		return err
	}

	// Format message based on event type
	message := formatTelegramMessage(event)

	// Send to Telegram
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", config.BotToken)
	payload := map[string]interface{}{
		"chat_id":    config.ChatID,
		"text":       message,
		"parse_mode": "HTML",
	}

	body, _ := json.Marshal(payload)
	resp, err := m.client.Post(url, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram API returned status %d", resp.StatusCode)
	}

	return nil
}

func formatTelegramMessage(event Event) string {
	switch event.Type {
	case EventBotDetected:
		if data, ok := event.Data.(VisitData); ok {
			return fmt.Sprintf(
				"🤖 <b>Bot Detectado!</b>\n\n"+
					"🌐 IP: <code>%s</code>\n"+
					"📍 País: %s\n"+
					"📱 Device: %s\n"+
					"🎯 Score: %.0f%%\n"+
					"📋 Motivos: %v\n"+
					"⏰ %s",
				data.IP, data.Country, data.Device,
				data.BotScore*100, data.BotReasons,
				event.Timestamp.Format("15:04:05"),
			)
		}
	case EventVisit:
		if data, ok := event.Data.(VisitData); ok {
			emoji := "✅"
			if data.IsBot {
				emoji = "🤖"
			}
			return fmt.Sprintf(
				"%s <b>Nova Visita</b>\n\n"+
					"🌐 IP: <code>%s</code>\n"+
					"📍 País: %s\n"+
					"📱 Device: %s | %s\n"+
					"📄 Página: %s\n"+
					"⏰ %s",
				emoji, data.IP, data.Country, data.Device, data.Browser,
				data.PageServed, event.Timestamp.Format("15:04:05"),
			)
		}
	}

	return fmt.Sprintf("📢 Evento: %s\n⏰ %s", event.Type, event.Timestamp.Format("15:04:05"))
}

// Discord integration

type DiscordConfig struct {
	WebhookURL string `json:"webhook_url"`
}

func (m *WebhookManager) sendDiscord(webhook database.Webhook, event Event) error {
	var config DiscordConfig
	if err := json.Unmarshal([]byte(webhook.Config), &config); err != nil {
		return err
	}

	embed := formatDiscordEmbed(event)

	payload := map[string]interface{}{
		"embeds": []interface{}{embed},
	}

	body, _ := json.Marshal(payload)
	resp, err := m.client.Post(config.WebhookURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("discord webhook returned status %d", resp.StatusCode)
	}

	return nil
}

func formatDiscordEmbed(event Event) map[string]interface{} {
	embed := map[string]interface{}{
		"timestamp": event.Timestamp.Format(time.RFC3339),
	}

	switch event.Type {
	case EventBotDetected:
		if data, ok := event.Data.(VisitData); ok {
			embed["title"] = "🤖 Bot Detectado"
			embed["color"] = 15158332 // Red
			embed["fields"] = []map[string]interface{}{
				{"name": "IP", "value": data.IP, "inline": true},
				{"name": "País", "value": data.Country, "inline": true},
				{"name": "Device", "value": data.Device, "inline": true},
				{"name": "Score", "value": fmt.Sprintf("%.0f%%", data.BotScore*100), "inline": true},
				{"name": "Motivos", "value": fmt.Sprintf("%v", data.BotReasons), "inline": false},
			}
		}
	case EventVisit:
		if data, ok := event.Data.(VisitData); ok {
			if data.IsBot {
				embed["title"] = "🤖 Visita (Bot)"
				embed["color"] = 15158332 // Red
			} else {
				embed["title"] = "✅ Visita (Humano)"
				embed["color"] = 3066993 // Green
			}
			embed["fields"] = []map[string]interface{}{
				{"name": "IP", "value": data.IP, "inline": true},
				{"name": "País", "value": data.Country, "inline": true},
				{"name": "Device", "value": data.Device, "inline": true},
				{"name": "Página", "value": data.PageServed, "inline": true},
			}
		}
	default:
		embed["title"] = fmt.Sprintf("📢 %s", event.Type)
		embed["color"] = 3447003 // Blue
	}

	return embed
}

// Custom webhook

type CustomConfig struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Method  string            `json:"method,omitempty"`
}

func (m *WebhookManager) sendCustom(webhook database.Webhook, event Event) error {
	var config CustomConfig
	if err := json.Unmarshal([]byte(webhook.Config), &config); err != nil {
		return err
	}

	method := config.Method
	if method == "" {
		method = "POST"
	}

	body, _ := json.Marshal(event)
	req, err := http.NewRequest(method, config.URL, bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	for key, value := range config.Headers {
		req.Header.Set(key, value)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("custom webhook returned status %d", resp.StatusCode)
	}

	return nil
}


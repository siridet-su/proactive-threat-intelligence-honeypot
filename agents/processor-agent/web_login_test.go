package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func syntheticWebLoginPayload() map[string]any {
	return map[string]any{
		"schema_version": float64(1),
		"event":          "web_login_attempt",
		"request_id":     "0123456789abcdef0123456789abcdef",
		"timestamp":      "2026-09-24T12:00:00.000Z",
		"source_ip":      "198.51.100.20",
		"http": map[string]any{
			"scheme": "http", "method": "POST", "path": "/web/login", "query": "",
			"host": "decoy.invalid", "user_agent": "synthetic-test-agent",
		},
		"odoo_login": map[string]any{
			"database": "synthetic-db", "login": "synthetic-user",
			"password": "synthetic-test-value", "redirect": "/web", "remember": "1",
		},
		"sqli_indicators":  map[string]any{"login": []any{"sql_keyword"}},
		"truncated_fields": []any{},
		"result":           "rejected",
	}
}

func TestNormalizeHTTPSLoginPreservesTransportAndPort(t *testing.T) {
	payload := syntheticWebLoginPayload()
	payload["http"].(map[string]any)["scheme"] = "https"
	values := map[string]any{
		"source": "web-corp", "log_type": "web_login",
		"dedup_id": "0123456789abcdef0123456789abcdef",
		"src_ip":   "198.51.100.20", "dst_ip": "10.58.33.42", "dst_port": "443",
		"sensor_ip": "10.58.33.42", "sensor_name": "test-sensor",
		"ingested_at": "2026-09-24T12:00:01Z",
	}
	event := normalizeEvent("raw:web-login", "1-0", values, payload)

	if event["network"].(map[string]any)["dst_port"] != 443 {
		t.Fatalf("HTTPS destination port was not preserved: %#v", event["network"])
	}
	if event["network"].(map[string]any)["service"] != "https" {
		t.Fatalf("HTTPS service was not identified: %#v", event["network"])
	}
	if event["http"].(map[string]any)["scheme"] != "https" {
		t.Fatalf("HTTPS scheme was not preserved: %#v", event["http"])
	}
}

func TestNormalizeWebLoginEventPreservesAdminDataWithoutCommandLeak(t *testing.T) {
	payload := syntheticWebLoginPayload()
	values := map[string]any{
		"source": "web-corp", "log_type": "web_login",
		"dedup_id": "0123456789abcdef0123456789abcdef",
		"src_ip":   "198.51.100.20", "dst_ip": "10.58.33.42", "dst_port": "80",
		"sensor_ip": "10.58.33.42", "sensor_name": "test-sensor",
		"ingested_at": "2026-09-24T12:00:01Z",
	}
	event := normalizeEvent("raw:web-login", "1-0", values, payload)

	if event["event_id"] != payload["request_id"] || event["event_type"] != "web_login_attempt" {
		t.Fatalf("event identity mismatch: %#v", event)
	}
	if event["source"] != "web-corp" || event["log_type"] != "web_login" {
		t.Fatalf("event source mismatch: %#v", event)
	}
	login := event["web_login"].(map[string]any)
	if login["password"] != "synthetic-test-value" || login["username"] != "synthetic-user" {
		t.Fatalf("credential-bearing login object missing expected values: %#v", login)
	}
	if _, exists := event["activity"]; exists {
		t.Fatalf("web login must not create a generic command activity: %#v", event["activity"])
	}
	if identity, exists := event["identity"].(map[string]any); exists {
		if _, hasPassword := identity["password"]; hasPassword {
			t.Fatalf("web password was copied into generic identity: %#v", identity)
		}
	}
	raw := event["raw"].(map[string]any)["payload"].(map[string]any)
	rawLogin := raw["odoo_login"].(map[string]any)
	if _, exists := rawLogin["password"]; exists {
		t.Fatalf("web password was duplicated in raw payload: %#v", rawLogin)
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(encoded), "synthetic-test-value") != 1 {
		t.Fatalf("password must occur exactly once in the canonical Mongo event: %s", encoded)
	}
	if getNestedString(event, "network.src_ip") != "198.51.100.20" {
		t.Fatalf("source IP was not normalized: %#v", event["network"])
	}
}

func TestWebLoginCanonicalProjectionOmitsPassword(t *testing.T) {
	event := map[string]any{
		"event_id": "0123456789abcdef0123456789abcdef",
		"web_login": map[string]any{
			"username": "synthetic-user", "password": "synthetic-test-value",
		},
	}
	projection := canonicalEventProjection(event, "web-corp")
	encoded, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "synthetic-test-value") || strings.Contains(string(encoded), "password") {
		t.Fatalf("canonical Redis projection leaked password field: %s", encoded)
	}
	if event["web_login"].(map[string]any)["password"] != "synthetic-test-value" {
		t.Fatal("building the projection mutated the MongoDB event")
	}
}

func TestInferWebLoginEventType(t *testing.T) {
	if got := inferEventType("web-corp", "web_login", map[string]any{"event": "web_login_attempt"}); got != "web_login_attempt" {
		t.Fatalf("event type = %q", got)
	}
}

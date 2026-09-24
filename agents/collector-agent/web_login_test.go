package main

import (
	"strings"
	"testing"
)

func validWebLoginPayload() map[string]any {
	return map[string]any{
		"schema_version": float64(1),
		"event":          "web_login_attempt",
		"request_id":     "0123456789abcdef0123456789abcdef",
		"timestamp":      "2026-09-24T12:00:00.000Z",
		"source_ip":      "198.51.100.20",
		"http":           map[string]any{"scheme": "http", "method": "POST", "path": "/web/login"},
		"odoo_login": map[string]any{
			"database": "synthetic-db", "login": "test-user", "password": "synthetic-test-value",
			"redirect": "/web", "remember": "1",
		},
		"result": "rejected",
	}
}

func TestValidateWebLoginPayload(t *testing.T) {
	requestID, sourceIP, err := validateWebLoginPayload(validWebLoginPayload())
	if err != nil {
		t.Fatalf("valid web login rejected: %v", err)
	}
	if requestID != "0123456789abcdef0123456789abcdef" || sourceIP != "198.51.100.20" {
		t.Fatalf("unexpected validated metadata: request_id=%q source_ip=%q", requestID, sourceIP)
	}
}

func TestValidateWebLoginPayloadUsesCharacterLimits(t *testing.T) {
	payload := validWebLoginPayload()
	login := payload["odoo_login"].(map[string]any)
	login["password"] = strings.Repeat("界", 256)
	if _, _, err := validateWebLoginPayload(payload); err != nil {
		t.Fatalf("256 Unicode characters should be accepted: %v", err)
	}

	login["password"] = strings.Repeat("界", 257)
	if _, _, err := validateWebLoginPayload(payload); err == nil {
		t.Fatal("257 Unicode characters should be rejected")
	}
}

func TestValidateWebLoginPayloadRejectsInvalidMetadata(t *testing.T) {
	tests := []struct {
		name   string
		change func(map[string]any)
	}{
		{name: "wrong event", change: func(p map[string]any) { p["event"] = "web_scan" }},
		{name: "unsupported schema", change: func(p map[string]any) { p["schema_version"] = float64(2) }},
		{name: "invalid id", change: func(p map[string]any) { p["request_id"] = "../bad" }},
		{name: "invalid timestamp", change: func(p map[string]any) { p["timestamp"] = "yesterday" }},
		{name: "invalid source ip", change: func(p map[string]any) { p["source_ip"] = "not-an-ip" }},
		{name: "invalid HTTP scheme", change: func(p map[string]any) { p["http"].(map[string]any)["scheme"] = "ftp" }},
		{name: "accepted result", change: func(p map[string]any) { p["result"] = "accepted" }},
		{name: "missing login object", change: func(p map[string]any) { delete(p, "odoo_login") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := validWebLoginPayload()
			test.change(payload)
			if _, _, err := validateWebLoginPayload(payload); err == nil {
				t.Fatal("invalid event unexpectedly accepted")
			}
		})
	}
}

func TestWebLoginDestinationPortFollowsScheme(t *testing.T) {
	for _, test := range []struct {
		name   string
		scheme string
		want   string
	}{
		{name: "legacy event defaults to HTTP", want: "80"},
		{name: "HTTP", scheme: "http", want: "80"},
		{name: "HTTPS", scheme: "https", want: "443"},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := validWebLoginPayload()
			if test.scheme != "" {
				payload["http"].(map[string]any)["scheme"] = test.scheme
			}
			if got := webLoginDestinationPort(payload); got != test.want {
				t.Fatalf("destination port = %q, want %q", got, test.want)
			}
		})
	}
}

func TestValidateWebHTTPPayloadAndSessionBoundary(t *testing.T) {
	payload := validWebLoginPayload()
	payload["event"] = "web_http_request"
	payload["web_session_id"] = "abcdef0123456789abcdef0123456789"
	payload["http"] = map[string]any{"method": "GET", "path": "/login.html", "status_code": float64(200)}
	delete(payload, "odoo_login")
	delete(payload, "result")
	if _, _, err := validateWebLoginPayload(payload); err != nil {
		t.Fatalf("safe web HTTP event rejected: %v", err)
	}
	payload["http"].(map[string]any)["query"] = "q=%3Cscript%3E"
	payload["http"].(map[string]any)["raw_path"] = "/login.html"
	if _, _, err := validateWebLoginPayload(payload); err != nil {
		t.Fatalf("bounded literal URL should be accepted: %v", err)
	}
	payload["http"].(map[string]any)["query"] = strings.Repeat("x", 513)
	if _, _, err := validateWebLoginPayload(payload); err == nil {
		t.Fatal("oversized query must be rejected")
	}
	payload["http"].(map[string]any)["query"] = "q=test"
	payload["http"].(map[string]any)["raw_path"] = 42
	if _, _, err := validateWebLoginPayload(payload); err == nil {
		t.Fatal("non-string raw path must be rejected")
	}
	delete(payload["http"].(map[string]any), "raw_path")
	payload["odoo_login"] = map[string]any{"password": "synthetic-secret"}
	if _, _, err := validateWebLoginPayload(payload); err == nil {
		t.Fatal("HTTP page event must not contain login credentials")
	}
	delete(payload, "odoo_login")
	payload["web_session_id"] = "invalid"
	if _, _, err := validateWebLoginPayload(payload); err == nil {
		t.Fatal("invalid web session ID must be rejected")
	}
}

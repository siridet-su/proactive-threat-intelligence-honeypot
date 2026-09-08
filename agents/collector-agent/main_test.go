package main

import "testing"

func TestAddCowrieEnvelopeMapsAuthoritativeCommandCwd(t *testing.T) {
	values := map[string]any{}
	addCowrieEnvelope(values, map[string]any{
		"eventid":    "cowrie.command.input",
		"session":    "session-1",
		"cwd":        "/home/operator",
		"cwd_status": "confirmed",
	})

	if values["cwd_before"] != "/home/operator" {
		t.Fatalf("command cwd must be mirrored as cwd_before: %#v", values)
	}
	if values["cwd_after"] != "/home/operator" {
		t.Fatalf("direct cwd must remain available in the envelope: %#v", values)
	}
	if values["cwd_status"] != "confirmed" {
		t.Fatalf("confidence must be preserved: %#v", values)
	}
}

func TestAddCowrieEnvelopePreservesTransitionEndpoints(t *testing.T) {
	values := map[string]any{}
	addCowrieEnvelope(values, map[string]any{
		"eventid":    "cowrie.session.cwd",
		"session":    "session-1",
		"cwd_before": "/home/operator",
		"cwd_after":  "/var/tmp",
		"cwd":        "/ignored-fallback",
		"cwd_action": "changed",
		"cwd_status": "confirmed",
	})

	if values["cwd_before"] != "/home/operator" || values["cwd_after"] != "/var/tmp" {
		t.Fatalf("transition endpoints changed: %#v", values)
	}
}

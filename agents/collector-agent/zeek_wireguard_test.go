package main

import "testing"

func TestZeekWireGuardDestination(t *testing.T) {
	cfg := AppConfig{
		LanIP:          "192.0.2.2",
		LanInterface:   "wlan0",
		WireGuardIP:    "198.51.100.2",
		WireGuardIface: "wg0",
		AllowedPorts:   map[int]bool{22: true, 80: true},
	}

	web := map[string]any{
		"id.orig_h": "203.0.113.7",
		"id.resp_h": cfg.WireGuardIP,
		"id.resp_p": float64(80),
	}
	keep, meta := shouldKeepZeek(cfg, web)
	if !keep || meta.Interface != "wg0" || meta.SensorIP != cfg.WireGuardIP {
		t.Fatalf("WireGuard decoy connection was not attributed to wg0: keep=%v meta=%+v", keep, meta)
	}

	web["id.resp_p"] = float64(2222)
	if keep, _ := shouldKeepZeek(cfg, web); keep {
		t.Fatal("management port passed the collector gate")
	}

	web["id.resp_p"] = float64(80)
	web["id.resp_h"] = "198.51.100.3"
	if keep, _ := shouldKeepZeek(cfg, web); keep {
		t.Fatal("unconfigured destination passed the collector gate")
	}
}

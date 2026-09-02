package main

import (
	"testing"

	"github.com/shirou/gopsutil/v3/mem"
	psnet "github.com/shirou/gopsutil/v3/net"
)

func TestCSVValuesTrimsDeduplicatesAndPreservesOrder(t *testing.T) {
	got := csvValues(" wlan0, tailscale0,wlan0,,lo ")
	want := []string{"wlan0", "tailscale0", "lo"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestAddMemoryMetricsPreservesLegacyAndDefinesPressureSemantics(t *testing.T) {
	values := map[string]interface{}{}
	memory := &mem.VirtualMemoryStat{
		Total:       1000,
		Available:   700,
		Used:        200,
		UsedPercent: 20,
	}

	addMemoryMetrics(values, memory)

	if values["mem_used_bytes"] != uint64(200) || values["mem_percent"] != "20.00" {
		t.Fatalf("legacy metrics changed: %#v", values)
	}
	if values["mem_pressure_used_bytes"] != uint64(300) {
		t.Fatalf("pressure used mismatch: %#v", values)
	}
	if values["mem_pressure_percent"] != "30.00" {
		t.Fatalf("pressure percent mismatch: %#v", values)
	}
	if values["mem_pressure_semantics"] != "total_minus_available" {
		t.Fatalf("pressure semantics missing: %#v", values)
	}
}

func TestAddInterfaceMetricsIncludesDocumentedCountersAndRates(t *testing.T) {
	previous := psnet.IOCountersStat{
		BytesRecv:   1000,
		BytesSent:   2000,
		PacketsRecv: 10,
		PacketsSent: 20,
	}
	current := psnet.IOCountersStat{
		BytesRecv:   1300,
		BytesSent:   2600,
		PacketsRecv: 16,
		PacketsSent: 28,
		Errin:       1,
		Errout:      2,
		Dropin:      3,
		Dropout:     4,
	}
	values := map[string]interface{}{}

	addInterfaceMetrics(values, "net_wlan0_", current, &previous, 2)

	want := map[string]interface{}{
		"net_wlan0_rx_bytes_total":        uint64(1300),
		"net_wlan0_tx_bytes_total":        uint64(2600),
		"net_wlan0_rx_packets_total":      uint64(16),
		"net_wlan0_tx_packets_total":      uint64(28),
		"net_wlan0_rx_errors_total":       uint64(1),
		"net_wlan0_tx_errors_total":       uint64(2),
		"net_wlan0_rx_dropped_total":      uint64(3),
		"net_wlan0_tx_dropped_total":      uint64(4),
		"net_wlan0_rx_bytes_per_second":   "150.000",
		"net_wlan0_tx_bytes_per_second":   "300.000",
		"net_wlan0_rx_packets_per_second": "3.000",
		"net_wlan0_tx_packets_per_second": "4.000",
		"net_wlan0_rx_mbps":               "0.001200",
		"net_wlan0_tx_mbps":               "0.002400",
	}
	for key, expected := range want {
		if observed, exists := values[key]; !exists || observed != expected {
			t.Errorf("%s: got %#v, want %#v", key, observed, expected)
		}
	}
}

func TestAddInterfaceMetricsSkipsOnlyResetRateFamily(t *testing.T) {
	previous := psnet.IOCountersStat{
		BytesRecv:   1000,
		BytesSent:   2000,
		PacketsRecv: 10,
		PacketsSent: 20,
	}
	current := psnet.IOCountersStat{
		BytesRecv:   900,
		BytesSent:   1900,
		PacketsRecv: 12,
		PacketsSent: 24,
	}
	values := map[string]interface{}{}

	addInterfaceMetrics(values, "net_wlan0_", current, &previous, 2)

	if _, exists := values["net_wlan0_rx_bytes_per_second"]; exists {
		t.Fatal("byte rate must be omitted after a byte counter reset")
	}
	if values["net_wlan0_rx_packets_per_second"] != "1.000" {
		t.Fatalf("packet rate should remain available, got %#v", values)
	}
}

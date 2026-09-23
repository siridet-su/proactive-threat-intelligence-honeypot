package main

import (
	"testing"

	"github.com/shirou/gopsutil/v3/disk"
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

func TestPositiveIntEnvUsesFallbackAndConfiguredValue(t *testing.T) {
	t.Setenv("HARDWARE_TEST_POSITIVE_INT", "")
	if got := positiveIntEnv("HARDWARE_TEST_POSITIVE_INT", 900); got != 900 {
		t.Fatalf("fallback = %d, want 900", got)
	}
	t.Setenv("HARDWARE_TEST_POSITIVE_INT", "1200")
	if got := positiveIntEnv("HARDWARE_TEST_POSITIVE_INT", 900); got != 1200 {
		t.Fatalf("configured value = %d, want 1200", got)
	}
}

func TestHardwareSensorIDPrefersConfiguredValue(t *testing.T) {
	t.Setenv("HARDWARE_SENSOR_ID", " pi-dev-01 ")
	if got := hardwareSensorID(); got != "pi-dev-01" {
		t.Fatalf("sensor id = %q, want pi-dev-01", got)
	}
}

func TestParseTemperatureOmitsInvalidSensorValues(t *testing.T) {
	if got, ok := parseTemperature([]byte("42000\n")); !ok || got != 42 {
		t.Fatalf("temperature = %v, ok=%v; want 42, true", got, ok)
	}
	for _, input := range [][]byte{nil, []byte(""), []byte("not-a-temperature")} {
		if got, ok := parseTemperature(input); ok {
			t.Fatalf("invalid temperature %q returned %v, want missing", input, got)
		}
	}
}

func TestAddMemoryMetricsUsesCanonicalPressureSemantics(t *testing.T) {
	values := map[string]interface{}{}
	memory := &mem.VirtualMemoryStat{
		Total:       1000,
		Available:   700,
		Used:        200,
		UsedPercent: 20,
	}

	addMemoryMetrics(values, memory)

	if values["mem_total_bytes"] != uint64(1000) || values["mem_available_bytes"] != uint64(700) {
		t.Fatalf("capacity metrics changed: %#v", values)
	}
	if values["mem_pressure_percent"] != "30.00" {
		t.Fatalf("pressure percent mismatch: %#v", values)
	}
	for _, key := range []string{"mem_used_bytes", "mem_percent", "mem_used_semantics", "mem_pressure_used_bytes", "mem_pressure_semantics"} {
		if _, exists := values[key]; exists {
			t.Fatalf("legacy/semantic field %q should not be emitted: %#v", key, values)
		}
	}
}

func TestAddCPUMetricsIncludesCurrentPerCoreBreakdown(t *testing.T) {
	values := map[string]interface{}{}

	addCPUMetrics(values, []float64{12.5}, []float64{10, 15})

	if values["cpu_percent"] != "12.50" {
		t.Fatalf("cpu percent = %#v", values["cpu_percent"])
	}
	if values["cpu_core_percent"] != "[10,15]" {
		t.Fatalf("per-core CPU payload = %#v", values["cpu_core_percent"])
	}
}

func TestAddDiskMetricsIncludesCapacityAndFreeSpace(t *testing.T) {
	values := map[string]interface{}{}

	addDiskMetrics(values, &disk.UsageStat{Total: 1_000, Free: 600, Used: 400, UsedPercent: 40})

	if values["disk_total_bytes"] != uint64(1_000) || values["disk_free_bytes"] != uint64(600) || values["disk_percent"] != "40.00" {
		t.Fatalf("disk metrics = %#v", values)
	}
	if _, exists := values["disk_used_bytes"]; exists {
		t.Fatal("disk_used_bytes is derived and should not be emitted")
	}
}

func TestAddInterfaceMetricsIncludesCanonicalRates(t *testing.T) {
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
	for _, key := range []string{
		"net_wlan0_rx_bytes_total",
		"net_wlan0_tx_bytes_total",
		"net_wlan0_rx_packets_total",
		"net_wlan0_tx_packets_total",
		"net_wlan0_rx_errors_total",
		"net_wlan0_tx_errors_total",
		"net_wlan0_rx_dropped_total",
		"net_wlan0_tx_dropped_total",
		"net_wlan0_rx_bytes_per_second",
		"net_wlan0_tx_bytes_per_second",
	} {
		if _, exists := values[key]; exists {
			t.Fatalf("redundant network field %q should not be emitted: %#v", key, values)
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

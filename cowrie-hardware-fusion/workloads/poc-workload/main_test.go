package main

import (
	"context"
	"errors"
	"syscall"
	"testing"
	"time"
)

func TestConfigurationRejectsUnsafeBounds(t *testing.T) {
	unsafeArguments := [][]string{
		{"--mode=unknown"},
		{"--mode=compute", "--duration=181s"},
		{"--mode=compute", "--workers=5"},
		{"--mode=compute", "--duty-percent=0"},
		{"--mode=service", "--requests-per-second=201"},
		{"--mode=service", "--work-iterations=20001"},
		{"--mode=service", "--workers=9"},
		{"--mode=service", "--connection-mode=external"},
		{"--mode=service", "--service-capacity=9"},
		{"--mode=service", "--handler-delay=251ms"},
		{"--mode=compute", "unexpected-position"},
	}
	for _, arguments := range unsafeArguments {
		if _, err := parseConfiguration(arguments); err == nil {
			t.Fatalf("expected unsafe arguments to fail: %v", arguments)
		}
	}
}

func TestComputeStopsAtContextDeadline(t *testing.T) {
	config, err := parseConfiguration([]string{
		"--mode=compute",
		"--duration=1s",
		"--workers=1",
		"--duty-percent=25",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	operations, failures := runCompute(ctx, config)
	if operations == 0 {
		t.Fatal("expected bounded compute operations")
	}
	if failures != 0 {
		t.Fatalf("unexpected failures: %d", failures)
	}
}

func TestServiceUsesLoopbackOnlyAndStops(t *testing.T) {
	config, err := parseConfiguration([]string{
		"--mode=service",
		"--duration=1s",
		"--workers=2",
		"--requests-per-second=50",
		"--work-iterations=100",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	operations, failures, attempts, rejected, latencyP95MS, err := runService(ctx, config)
	if err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skip("loopback sockets are disabled by the test sandbox; run the container integration test")
		}
		t.Fatal(err)
	}
	if operations == 0 {
		t.Fatal("expected loopback service operations")
	}
	if attempts < operations || failures > 1 || rejected != 0 || latencyP95MS <= 0 {
		t.Fatalf("unexpected healthy service evidence: operations=%d failures=%d attempts=%d rejected=%d latency=%f", operations, failures, attempts, rejected, latencyP95MS)
	}
}

func TestServicePressureProducesBoundedRejections(t *testing.T) {
	config, err := parseConfiguration([]string{
		"--mode=service",
		"--duration=1s",
		"--workers=8",
		"--requests-per-second=200",
		"--work-iterations=10",
		"--connection-mode=close",
		"--service-capacity=1",
		"--handler-delay=50ms",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	operations, failures, attempts, rejected, latencyP95MS, err := runService(ctx, config)
	if err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skip("loopback sockets are disabled by the test sandbox; run the container integration test")
		}
		t.Fatal(err)
	}
	if attempts == 0 || operations == 0 || failures == 0 || rejected == 0 {
		t.Fatalf("expected bounded pressure evidence: operations=%d failures=%d attempts=%d rejected=%d", operations, failures, attempts, rejected)
	}
	if failures > attempts || rejected > failures || latencyP95MS <= 0 {
		t.Fatalf("invalid pressure evidence: failures=%d attempts=%d rejected=%d latency=%f", failures, attempts, rejected, latencyP95MS)
	}
}

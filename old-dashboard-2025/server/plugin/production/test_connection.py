#!/usr/bin/env python3
"""
Test script to verify connection to GCP ingest_api and honeypot-forwarder configuration.

Usage:
    python3 test_connection.py [--config CONFIG_FILE]

Environment variables used (same as sensor_forwarder):
    - SENSOR_ID
    - INGEST_URL
    - HONEYPOT_API_TOKEN
    - COWRIE_LOG_PATH
    - FORWARDER_SPOOL_PATH
    - FORWARDER_TIMEOUT_SECONDS (optional)
    - FORWARDER_BATCH_SIZE (optional)
    - FORWARDER_POLL_SECONDS (optional)
"""

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

from .config import ProductionConfig
from .serialization import utc_now


def test_config_loading(config_file=None):
    """Test that configuration loads correctly."""
    print("[1/5] Testing configuration loading...")
    try:
        config = ProductionConfig.from_env(config_file)
        print(f"  ✓ Config loaded successfully")
        print(f"    Sensor ID: {config.sensor_id}")
        print(f"    Ingest URL: {config.ingest_url}")
        print(f"    Cowrie log path: {config.cowrie_log_path}")
        print(f"    Spool path: {config.spool_path}")
        print(f"    Poll interval: {config.forwarder_poll_seconds}s")
        print(f"    Batch size: {config.forwarder_batch_size}")
        return config
    except ValueError as e:
        print(f"  ✗ Config error: {e}")
        return None


def test_cowrie_log_readable(config):
    """Test that cowrie.json exists and is readable."""
    print("\n[2/5] Testing Cowrie log accessibility...")
    log_path = Path(config.cowrie_log_path)
    if not log_path.exists():
        print(f"  ✗ Cowrie log not found: {config.cowrie_log_path}")
        return False
    if not log_path.is_file():
        print(f"  ✗ Cowrie log is not a file: {config.cowrie_log_path}")
        return False
    try:
        with open(log_path, "r") as f:
            first_line = f.readline()
        print(f"  ✓ Cowrie log readable: {config.cowrie_log_path}")
        if first_line:
            print(f"    First event: {first_line[:80]}...")
        else:
            print(f"    (Log file is empty)")
        return True
    except Exception as e:
        print(f"  ✗ Cannot read Cowrie log: {e}")
        return False


def test_spool_directory(config):
    """Test that spool directory can be created and written to."""
    print("\n[3/5] Testing spool directory setup...")
    spool_path = Path(config.spool_path)
    try:
        spool_path.parent.mkdir(parents=True, exist_ok=True)
        # Try to write a test file
        test_file = spool_path.parent / ".write_test"
        test_file.write_text("test")
        test_file.unlink()
        print(f"  ✓ Spool directory writable: {spool_path.parent}")
        if spool_path.exists():
            count = sum(1 for line in spool_path.read_text().splitlines() if line.strip())
            print(f"    Existing spool items: {count}")
        else:
            print(f"    Spool file not yet created")
        return True
    except Exception as e:
        print(f"  ✗ Spool directory error: {e}")
        return False


def test_network_connectivity(config):
    """Test network connection to ingest_api endpoint."""
    print("\n[4/5] Testing network connectivity to GCP ingest_api...")
    
    # First, try health check endpoint (if available)
    health_url = config.ingest_url.rsplit("/", 1)[0] + "/health"
    try:
        request = urllib.request.Request(health_url, method="GET")
        with urllib.request.urlopen(request, timeout=config.forwarder_timeout_seconds) as response:
            if response.status == 200:
                print(f"  ✓ GCP ingest_api health check: OK (HTTP 200)")
            else:
                print(f"  ! Health check returned HTTP {response.status}")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print(f"  ! Health endpoint not available (HTTP 404)")
        else:
            print(f"  ! Health check failed (HTTP {e.code})")
    except Exception as e:
        print(f"  ! Health check unavailable: {e}")
    
    # Now test actual event posting (required)
    print(f"  Testing event submission to {config.ingest_url}...")
    try:
        test_events = [
            {
                "eventid": "test.connection",
                "timestamp": utc_now(),
                "sensor_id": config.sensor_id,
            }
        ]
        payload = {"sensor_id": config.sensor_id, "events": test_events}
        request = urllib.request.Request(
            config.ingest_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {config.api_token}",
                "Content-Type": "application/json",
                "X-Sensor-ID": config.sensor_id,
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=config.forwarder_timeout_seconds) as response:
            status = response.status
            result = json.loads(response.read().decode("utf-8"))
            if status == 202:
                print(f"  ✓ Connection successful (HTTP {status} Accepted)")
                print(f"    Response: {result}")
                return True
            else:
                print(f"  ! Unexpected status code: HTTP {status}")
                print(f"    Response: {result}")
                return True  # Still OK, just informational
    except urllib.error.HTTPError as e:
        print(f"  ✗ HTTP Error {e.code}: {e.reason}")
        try:
            body = e.read().decode("utf-8")
            print(f"    Response body: {body}")
        except Exception:
            pass
        return False
    except urllib.error.URLError as e:
        print(f"  ✗ Connection failed: {e.reason}")
        return False
    except TimeoutError:
        print(f"  ✗ Connection timeout (>{config.forwarder_timeout_seconds}s)")
        return False
    except Exception as e:
        print(f"  ✗ Unexpected error: {e}")
        return False


def test_token_validation(config):
    """Test that API token is not a placeholder."""
    print("\n[5/5] Testing API token configuration...")
    if config.api_token == "test-token-change-me":
        print(f"  ⚠ WARNING: Using test token (unsafe for production)")
        print(f"    Token: {config.api_token}")
        return True  # Not a failure, just a warning
    elif "test" in config.api_token.lower() or "xxx" in config.api_token.lower():
        print(f"  ⚠ WARNING: Token looks like a placeholder")
        print(f"    Token: {config.api_token[:20]}...")
        return True
    else:
        print(f"  ✓ Token configured (length: {len(config.api_token)} chars)")
        return True


def main(argv=None):
    parser = argparse.ArgumentParser(description="Test sensor_forwarder configuration and connectivity")
    parser.add_argument("--config", help="Path to JSON config file")
    args = parser.parse_args(argv)

    print("=" * 60)
    print("Honeypot Sensor Forwarder - Connection Test")
    print("=" * 60)

    config = test_config_loading(args.config)
    if not config:
        print("\n✗ Configuration failed - cannot continue")
        return 1

    tests = [
        ("Cowrie log", test_cowrie_log_readable),
        ("Spool dir", test_spool_directory),
        ("Network", test_network_connectivity),
        ("Token", test_token_validation),
    ]

    passed = 0
    for name, test_func in tests:
        try:
            if test_func(config):
                passed += 1
        except Exception as e:
            print(f"  ✗ Test error: {e}")

    print("\n" + "=" * 60)
    print(f"Results: {passed}/{len(tests)} checks passed")
    print("=" * 60)

    if passed == len(tests):
        print("\n✓ All checks passed! Ready for deployment.")
        return 0
    else:
        print(f"\n✗ {len(tests) - passed} check(s) failed - review errors above")
        return 1


if __name__ == "__main__":
    sys.exit(main())

# Existing Pi Zeek capture

The tracked `node.cfg` is the reviewed capture scope for the existing Pi:
one `wlan0` worker and one ZeroTier worker in the local Zeek cluster. There is
no Tailscale worker. The fresh-install Ansible Zeek playbook uses its own
versioned template and has a separate validation boundary.

Zeek's `logs/current` path points to the active logger; the Go collector reads
that path. Verify both Zeek and the collector after any capture change:

```sh
sudo /usr/local/zeek/bin/zeekctl check
sudo /usr/local/zeek/bin/zeekctl status
readlink -f /usr/local/zeek/logs/current
systemctl is-active zeek.service honeypot-collector.service honeypot-processor.service
```

To change the Pi's node list, save its current `node.cfg` in a root-only host
backup, stop `zeek.service` while the old configuration is still installed,
install the reviewed new configuration, run `zeekctl check`, then start the
service and run the checks above. Stopping first lets ZeekControl stop every
old worker, including any worker removed from the new configuration. If the
new check or start fails, restore the protected backup and start the old
configuration. Never copy a protected backup into this repository.

This capture choice is recorded in
[ADR-0012](../docs/adr/ADR-0012-zeek-primary-uplink-capture.md).

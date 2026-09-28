# Existing Pi Zeek capture

The tracked `node.cfg` is the reviewed capture scope for the existing Pi:
`wlan0`, ZeroTier, and `wg0` workers in the local Zeek cluster. There is
no Tailscale worker. The fresh-install Ansible Zeek playbook uses its own
versioned template and has a separate validation boundary.

The active Pi also loads `pti-decoy-capture.zeek` from its site policy. The
tracked [renderer](render_decoy_capture.py) generates that host-specific file
from the current `wlan0`, ZeroTier, and `wg0` IPv4 addresses before each Zeek start.
The [systemd drop-in](../systemd-services/zeek-decoy-capture.conf) invokes the
renderer on start and reload. Zeek captures Cowrie TCP 22/23 on both interfaces
and Web-corp TCP 80 on ZeroTier and `wg0`, in both directions. Admin SSH 2222 and stopped decoy
ports are outside this filter. The generated file contains private interface
addresses and stays on the host; it is never committed.

For the existing Pi, keep a root-only backup of its current `local.zeek` and
any capture drop-in before changing either file. Install the renderer at
`/usr/local/libexec/pti-zeek-render-decoy-capture` with mode `0755` and the
drop-in at `/etc/systemd/system/zeek.service.d/decoy-capture.conf` with mode
`0644`. Replace the old broad `capture_filters` block in `local.zeek` with
`@load ./pti-decoy-capture`; leave other site policy intact. Run the renderer
once, `systemctl daemon-reload`, `zeekctl check`, then restart Zeek and perform
the bounded capture check below. If checking or startup fails, restore the
protected site policy/drop-in, remove the generated policy, reload systemd,
and restart the old Zeek configuration.

Zeek's `logs/current` path points to the active logger; the Go collector reads
that path. Verify both Zeek and the collector after any capture change:

```sh
sudo /usr/local/zeek/bin/zeekctl check
sudo /usr/local/zeek/bin/zeekctl status
readlink -f /usr/local/zeek/logs/current
systemctl is-active zeek.service honeypot-collector.service honeypot-processor.service
```

After restart, verify a bounded Cowrie/Web-corp test flow in `conn.log` and
confirm a management-port connection is absent. Inspect `packet_filter.log`
if this Zeek version emits it. A listener check alone does not prove Zeek
capture. If an interface address changes while Zeek is running, restart or
reload `zeek.service` to regenerate the filter. Before enabling a new decoy
port, update the reviewed renderer, collector allowance, and this runbook
together.

To change the Pi's node list, save its current `node.cfg` in a root-only host
backup, stop `zeek.service` while the old configuration is still installed,
install the reviewed new configuration, run `zeekctl check`, then start the
service and run the checks above. Stopping first lets ZeekControl stop every
old worker, including any worker removed from the new configuration. If the
new check or start fails, restore the protected backup and start the old
configuration. Never copy a protected backup into this repository.

The interface and endpoint choices are recorded in
[ADR-0012](../docs/adr/ADR-0012-zeek-primary-uplink-capture.md) and
[ADR-0013](../docs/adr/ADR-0013-zeek-decoy-endpoint-filter.md), extended for
the public Web-corp path by
[ADR-0014](../docs/adr/ADR-0014-public-web-corp-ip-https-edge.md).

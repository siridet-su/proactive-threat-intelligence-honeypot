# Tailscale response-control identity

> **Retired on 2026-09-25.** The Dashboard-to-Pi session response channel has
> been removed. This page is historical and its grant/deployment instructions
> must not be applied. The Pi response agent is stopped and removed, and port
> 8788 has no listener. Tailscale stays enabled for administration. The actual
> tailnet ACL was not changed from this host; remove any old TCP 8788 grant in
> the Tailscale Admin Console.

## Former design (historical)

The retired control channel used a one-way grant from a tagged Dashboard host
to a tagged Pi on TCP 8788. Its grant example, Dashboard service credential
example, and agent install procedure have been removed from the repository.
They are not current Tailscale or host configuration instructions.

## Current administration path

Tailscale remains enabled on the Pi for SSH/host administration. This host's
local CLI cannot inspect or edit the tailnet Admin Console ACL. Remove any old
Dashboard-to-Pi TCP 8788 grant in the Admin Console; the response agent itself
is stopped, removed, and no longer listening.

No MongoDB action history was deleted.

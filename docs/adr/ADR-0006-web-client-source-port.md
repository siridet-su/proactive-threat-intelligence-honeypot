---
title: ADR-0006 — Preserve the observed Web-corp client source port
status: accepted
date: 2026-09-25
---

# ADR-0006 — Preserve the observed Web-corp client source port

## Context

Web-corp login events record the source IP, but the sensor payload and collector
envelope omit the TCP source port. The processor currently derives
`network.src_port` from Zeek's `id.orig_p`, which Web-corp events do not have.
Consequently, new Web-corp records have no usable source port even though the
dashboard read model already supports `network.src_port`.

## Decision

- Add an optional integer `source_port` (1–65535) to Web-corp sensor events.
- For a direct connection, capture the ASGI peer port. If the immediate peer is
  in `WEB_TRUSTED_PROXY_CIDRS`, use `X-Forwarded-Client-Port` only when present
  and valid; the trusted proxy must overwrite this header with the original
  client's remote port. If the trusted proxy does not supply a valid value,
  leave the port absent rather than recording the proxy's upstream socket
  port as the client port.
- When Uvicorn's `ProxyHeadersMiddleware` has rewritten a trusted forwarded
  client to port `0`, accept `X-Forwarded-Client-Port` only when
  `X-Forwarded-For` is also present and `WEB_TRUSTED_PROXY_CIDRS` is configured.
  Configure Uvicorn's `--forwarded-allow-ips` with exactly the same proxy peers;
  never use `*` for this deployment.
- Validate and propagate the value as Redis `src_port`, then normalize it into
  MongoDB `network.src_port`. Keep the field optional for old producers and
  proxy paths that cannot preserve it. This additive field does not require a
  MongoDB migration or a schema-version bump.
- Treat the port as transient connection metadata, not an identity or stable
  cross-session key. Never trust a forwarding header from an untrusted peer.

## Consequences

New direct Web-corp login events can show the observed peer source port in
MongoDB and the existing dashboard projection. Events that passed through a
proxy show the original client port only if the trusted proxy explicitly
forwards it. Existing records cannot be backfilled because this information was
not captured at ingestion time. Source-port NAT and short-lived TCP ports limit
its correlation value.

## Alternatives considered

- Infer the source port from the source IP or HTTP headers: rejected; neither
  contains a trustworthy transport-port value.
- Always store `request.client.port`: rejected for trusted-proxy deployments,
  because it would report the proxy's connection port as the client port.
- Make the field mandatory: rejected because legacy payloads and proxy paths
  may not have a trustworthy client port.

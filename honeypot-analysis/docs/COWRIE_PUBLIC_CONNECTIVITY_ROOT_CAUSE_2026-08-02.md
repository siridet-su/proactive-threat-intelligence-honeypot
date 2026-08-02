# Cowrie public connectivity root cause and correction

Date: 2026-08-02 (UTC evidence recorded 2026-08-01)

## Decision

`PUBLIC_COWRIE_CONNECTIVITY_RESTORED`

The timeout was caused by the existing GCP VPC rule `allow-cowrie-relay-2222`
being disabled. The rule already had the intended scope: ingress TCP/2222,
source `0.0.0.0/0`, priority 1000, target tag `honeypot-test`. The instance
had that tag and public address `34.124.181.196`. No new rule or port was
created.

## Evidence

Before correction, a bounded metadata-only capture on GCP recorded zero TCP
packets while the authorized client timed out. The GCP public listener was
present, HAProxy configuration was valid, and the Pi backend was reachable
through Tailscale at `100.118.43.30:2224`.

The rule was enabled in place without changing source ranges, port, priority,
network, or target tag. The before-rule receipt SHA-256 is
`0aa2ad1e6b0ad627fbcf4f9d7935c6b6cd3879a5218261b0a33681391e33355f`; the
after-rule receipt SHA-256 is
`d99832d058cb77d3cffc928b2407cbf4dfa96f6a4480dd888eb203c9957e557c`.
Owner-only receipts are retained beside the activation backup.

After correction, a bounded capture recorded SYN/SYN-ACK/ACK and application
traffic on TCP/2222. HAProxy counters increased and the configured backend
remained `UP`. A real public Cowrie session created durable `session.connect`,
`login.success`, command, and `session.closed` records. All observed events
were processed successfully.

## Boundaries

No Pi software or configuration was changed. The accepted Pi release remains
`5bb3b97fbe3b9034c70fc6ca2aba0ad9d159bb02`. No application semantics,
prediction behavior, firewall exposure beyond the pre-existing intended rule,
historical records, or model artifacts were changed.

Rollback of the infrastructure correction is the reversible command:

```text
gcloud compute firewall-rules update allow-cowrie-relay-2222 --disabled
```

The application rollback remains the guarded pointer rollback to
`19afabd0bb7ed82ac93767301bb0cb1024d0b92e` using the retained activation
receipt.

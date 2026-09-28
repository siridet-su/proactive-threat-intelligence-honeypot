# Fresh Pi activation check on disposable ARM64 VM

Date: 2026-09-28. Scope: Ubuntu 24.04 ARM64 Azure test VM only. The existing
Pi, public Droplet, and Dashboard host were not changed.

## What ran

- Prepared source, packages, and blank env files were already staged on the
  test VM. The fresh installer filled missing non-secret values. A same-release
  retry made no preparation changes and paused before activation because the
  operator-managed MongoDB URI was absent.
- The Cowrie activation playbook installed the fresh sanitizer contract and
  non-login service account, then started SSH/Telnet on loopback TCP 2223/2323.
  Administrator SSH remained on TCP 22. A synthetic SSH connection yielded
  sanitized event output. The second activation run reported no changes.
- Zeek ran on loopback with a generated BPF policy. Its effective packet
  filter admitted test traffic for TCP 2223/2323 and excluded synthetic TCP
  22/80 traffic. The control status showed the worker running. An initial
  policy load order error produced a broad effective filter; the activation
  playbook was corrected to render, check, and install the policy before
  starting the service, then the packet test was repeated successfully.
- The decoy playbook built and started PostgreSQL, Deception Core, and
  Web-corp. Web-corp returned HTTP 200 on loopback. Docker published only
  loopback TCP 80/9000/5432. After the non-secret Zeek log path was filled,
  a same-release retry reconciled Compose and the Core container mounted
  `/opt/zeek/logs/current`; a further retry reported no changes.
- Local targeted Python tests, Go collector tests, Python syntax, shell
  syntax, and Ansible syntax checks passed. The fresh Cowrie and legacy
  sanitizer contracts were both covered by targeted tests.

## Final VM state

The test Compose project and its disposable volumes were removed. Cowrie,
Zeek, Docker, the Docker socket, and containerd were stopped and disabled.
The synthetic PostgreSQL password was cleared from the private test env. The
provisional Cowrie activation marker, config, unit, and sanitizer symlinks were
removed because that package used an earlier Git revision and was only a test
artifact. The prepared source and package installation remain staged for
inspection. The final listener check showed only administrator SSH on TCP 22
and local DNS stub ports; no decoy listener remained.

## Limits

The VM test used loopback and alternate Cowrie ports. It does not prove Wi-Fi
DHCP rebinding, public exposure, real Atlas or B2 credentials, Go event
delivery, Dashboard authentication, backup execution, or restore. The full
one-command installer was observed through its private-env pause and retry,
not through a completed all-service activation. The final sanitizer release
must be rebuilt from the committed source before a real Pi install.

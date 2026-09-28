# Admin SSH cutover bounded validation — 2026-09-28

Status: historical test record. The automatic SSH migration was removed from
the installer later on 2026-09-28 at the operator's request. This record does
not describe the current installation procedure.

- Target: the existing disposable Ubuntu 24.04 ARM64 Azure VM used for installer validation. This is not the active Pi.
- Starting state: `ssh.socket` was active and real SSH listened on TCP 22 only.
- Applied to the VM: copied the target helper, ran its dual-port `prepare` for TCP 2222, tested SSH from the controller on 2222, then ran `rollback` over 22. Repeated that blocked-port test through the new controller `migrate` function. Both new-port attempts timed out at the Azure network boundary and rolled back. A final root probe returned `fresh`, port 22, listeners 22 and 53. No `cutover`, Cowrie activation, firewall update, or Pi change was performed.
- Repository checks: the installer suite passed with `PYTHONPATH=.` (42 tests and five subtests). Focused cases cover occupied-port suggestion, rollback before cutover when the new route fails, the required prepare → cutover → confirm order, and a same-release retry after Cowrie occupies 22. Python compilation and whitespace checks passed. A first `pytest` invocation without the repository on `PYTHONPATH` failed collection for three existing imports; the corrected invocation passed.
- Not tested: successful externally reachable cutover, automatic 150-second timer expiry, post-cutover SSH reconnect, real Wi-Fi Pi, and full installation. These require a controlled network route and console recovery.

## 2026-09-28 addendum

The controller and target migration code and tests were removed before commit.
The disposable VM's copied target helper was removed. Its managed SSH drop-in
and marker were absent, and `ssh.socket` was active with effective port 22.
The local test receipt was removed. No Cowrie port or Pi service was changed.

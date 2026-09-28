# Fresh Pi high-port default validation — 2026-09-28

- Scope: repository-only change for future fresh Ubuntu 24.04 ARM64 Pi installations. The existing Pi and disposable VM were not changed.
- `PYTHONPATH=. pytest -q tests/installer`: 39 tests and five subtests passed. The focused fresh-install tests checked the 2222/2223 example pair, exact Cowrie/Zeek port agreement, artifact digest validation, and a reviewed 22/23 override before first installation.
- `ansible-playbook -i localhost, --syntax-check deploy/ansible/activate-cowrie.yml deploy/ansible/activate-zeek.yml deploy/ansible/fill-fresh-nonsecret-env.yml`: syntax passed for all three playbooks. The temporary localhost inventory did not contain `pi_sensors`, so Ansible reported a host-pattern warning; no tasks ran.
- `python3 -m py_compile scripts/install_fresh_pi.py`, `python3 -m json.tool deploy/ansible/full-install-vars.example.json`, and `git diff --check`: passed.
- A local `lo` render of `zeek/render_fresh_capture.py` with `--ports 2222,2223` produced a TCP filter with both source and destination directions for 2222 and 2223. The temporary output was removed after the check; no Zeek process was started.
- Not tested: actual Cowrie listeners, Zeek BPF capture on `wlan0`, a full fresh installation, and a later move to 22/23. Historical VM activation evidence used separate loopback test ports and does not establish the new Wi-Fi default's live behavior.

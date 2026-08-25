# CyberLab external adapter v2

The v1 adapter normalized every event before applying the label-blind
`sensor == "ubuntu_basic_pool"` boundary.  A malformed command event in a
session whose sensor was `prod-ubuntu-ssh-k8s-local-3` therefore stopped the
member even though the session was provably ineligible.

v2 performs a structural session check and a sensor-only preflight first.  A
wrong-sensor, mixed-sensor, or missing-sensor session is excluded with a stable
reason and event counters; no timestamp, protocol, command, or ATT&CK semantic
validation is performed for that excluded session.  An exact
`ubuntu_basic_pool` session is passed through the unchanged v1 normalizer.  A
malformed event in an eligible session still fails closed.  A metadata-only
exclusion record cannot enter the classifier or safe-session boundary.

The private session shape remains `cyberlab_private_session.v1` so the reviewed
multi-member and privacy contracts remain byte-compatible.  The adapter
implementation, policy, and receipt are independently versioned as v2.  The
old v1 receipt and failed-development evidence are immutable historical
records; they are not restamped or replaced.

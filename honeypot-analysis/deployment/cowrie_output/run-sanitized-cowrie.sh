#!/bin/sh
set -eu

bundle_root=${HONEYPOT_COWRIE_OUTPUT_ROOT:-/opt/honeypot-cowrie-output/current}
cowrie_root=${HONEYPOT_COWRIE_ROOT:-/home/cowrie/cowrie}

export HONEYPOT_COWRIE_OUTPUT_ROOT="${bundle_root}"
export HONEYPOT_COWRIE_CONFIG="${HONEYPOT_COWRIE_CONFIG:-${cowrie_root}/etc/cowrie.cfg}"
export PYTHONPATH="${bundle_root}:${cowrie_root}/src"

exec "${cowrie_root}/cowrie-env/bin/twistd" \
  --umask=0077 \
  --pidfile=var/run/cowrie.pid \
  --logger production.cowrie_output.twisted_logger.logger \
  -n cowrie

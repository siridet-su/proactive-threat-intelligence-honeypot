#!/bin/sh
set -eu

bundle_root=${HONEYPOT_COWRIE_OUTPUT_ROOT:-/opt/honeypot-cowrie-output/current}
cowrie_root=${HONEYPOT_COWRIE_ROOT:-/home/cowrie/cowrie}
python=${cowrie_root}/cowrie-env/bin/python

case "${MAINPID:-}" in
  ''|*[!0-9]*) exit 2 ;;
esac

attempt=0
while [ "${attempt}" -lt 50 ]; do
  if env \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH="${bundle_root}:${cowrie_root}/src" \
    HONEYPOT_COWRIE_OUTPUT_ROOT="${bundle_root}" \
    HONEYPOT_COWRIE_CONFIG="${HONEYPOT_COWRIE_CONFIG:-${cowrie_root}/etc/cowrie.cfg}" \
    HONEYPOT_COWRIE_ROOT="${cowrie_root}" \
    "${python}" -m production.tools.cowrie_output_integration live-readiness \
      --config "${HONEYPOT_COWRIE_CONFIG:-${cowrie_root}/etc/cowrie.cfg}" \
      --bundle-root "${bundle_root}" \
      --expected-pid "${MAINPID}" >/dev/null
  then
    exit 0
  fi
  attempt=$((attempt + 1))
  sleep 0.1
done

exit 2

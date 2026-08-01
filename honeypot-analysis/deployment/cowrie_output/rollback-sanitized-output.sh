#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "must run as root" >&2
  exit 2
fi
if [ "$#" -ne 1 ] || { [ ! -f "$1/managed-paths.jsonl" ] && [ ! -f "$1/managed-paths.tsv" ]; }; then
  echo "usage: $0 VERIFIED_RECEIPT_DIRECTORY" >&2
  exit 2
fi

receipt=$1
cowrie_root=${HONEYPOT_COWRIE_ROOT:-/home/cowrie/cowrie}
current=${HONEYPOT_COWRIE_CURRENT:-/opt/honeypot-cowrie-output/current}
users_file=${HONEYPOT_COWRIE_USERS_FILE:-/home/cowrie/users.txt}
dropin=${HONEYPOT_COWRIE_DROPIN:-/etc/systemd/system/cowrie.service.d/20-sanitized-output.conf}
logrotate=${HONEYPOT_COWRIE_LOGROTATE:-/etc/logrotate.d/cowrie}
python="${cowrie_root}/cowrie-env/bin/python"
source_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

# Parse, normalize, and verify every record and saved-file digest before the
# service or any managed path is touched.
env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="${source_root}" \
  "${python}" -m production.tools.cowrie_rollback_receipt verify \
  --receipt "${receipt}" --cowrie-root "${cowrie_root}" \
  --users-file "${users_file}" --current "${current}" \
  --drop-in "${dropin}" --logrotate "${logrotate}" \
  >"${receipt}/receipt-verification.before-rollback.json"
chmod 0600 "${receipt}/receipt-verification.before-rollback.json"

systemctl stop cowrie.service
env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="${source_root}" \
  "${python}" -m production.tools.cowrie_rollback_receipt apply \
  --receipt "${receipt}" --cowrie-root "${cowrie_root}" \
  --users-file "${users_file}" --current "${current}" \
  --drop-in "${dropin}" --logrotate "${logrotate}" \
  >"${receipt}/receipt-application.json"
chmod 0600 "${receipt}/receipt-application.json"

systemctl daemon-reload
systemctl start cowrie.service
systemctl is-active --quiet cowrie.service

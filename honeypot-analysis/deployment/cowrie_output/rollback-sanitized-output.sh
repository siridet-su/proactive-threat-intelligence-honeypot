#!/bin/sh
set -eu
umask 077

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
active_text_log="${cowrie_root}/var/log/cowrie/cowrie.log"
python="${cowrie_root}/cowrie-env/bin/python"
source_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
forwarder=honeypot-sensor-forwarder.service
receipt_tool() {
  status_file=$1
  shift
  env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="${source_root}" \
    "${python}" -m production.tools.cowrie_rollback_receipt \
    --quiet --status-file "${status_file}" "$@"
}
test "$(systemctl is-active "${forwarder}")" = active
forwarder_pid=$(systemctl show "${forwarder}" -p MainPID --value)
test -n "${forwarder_pid}"
test "${forwarder_pid}" != 0

# Parse, normalize, and verify every record and saved-file digest before the
# service or any managed path is touched.
receipt_tool "${receipt}/receipt-verification.before-rollback.json" verify \
  --receipt "${receipt}" --cowrie-root "${cowrie_root}" \
  --users-file "${users_file}" --current "${current}" \
  --drop-in "${dropin}" --logrotate "${logrotate}"

timeout 30 systemctl stop cowrie.service
remaining=30
while [ "${remaining}" -gt 0 ]; do
  state=$(systemctl show cowrie.service -p ActiveState --value)
  main_pid=$(systemctl show cowrie.service -p MainPID --value)
  if [ "${state}" = inactive ] && [ "${main_pid}" = 0 ]; then
    control_group=$(systemctl show cowrie.service -p ControlGroup --value)
    process_file="/sys/fs/cgroup${control_group}/cgroup.procs"
    if [ -z "${control_group}" ] || [ ! -e "${process_file}" ]; then
      break
    fi
    if [ -r "${process_file}" ] && [ -z "$(cat "${process_file}")" ]; then
      break
    fi
  fi
  sleep 1
  remaining=$((remaining - 1))
done
test "${remaining}" -gt 0
if [ -e "${active_text_log}" ] || [ -L "${active_text_log}" ]; then
  receipt_tool "${receipt}/failed-log-stopped-preflight.json" assert-stopped \
    --active-log "${active_text_log}"
fi
receipt_tool "${receipt}/receipt-application.json" apply \
  --receipt "${receipt}" --cowrie-root "${cowrie_root}" \
  --users-file "${users_file}" --current "${current}" \
  --drop-in "${dropin}" --logrotate "${logrotate}"

for temporary_link in "${current}.new" "${cowrie_root}/src/cowrie/output/sanitizedjson.py.new"; do
  if [ -L "${temporary_link}" ]; then
    rm -f "${temporary_link}"
  else
    test ! -e "${temporary_link}"
  fi
done

systemctl daemon-reload
timeout 30 systemctl start cowrie.service
systemctl is-active --quiet cowrie.service
test "$(systemctl is-active "${forwarder}")" = active
test "$(systemctl show "${forwarder}" -p MainPID --value)" = "${forwarder_pid}"

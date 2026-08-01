#!/bin/sh
set -eu
umask 077

if [ "$(id -u)" -ne 0 ]; then
  echo "must run as root" >&2
  exit 2
fi
if [ "$#" -ne 3 ]; then
  echo "usage: $0 BUNDLE_TAR FULL_GIT_REVISION RECEIPT_DIRECTORY" >&2
  exit 2
fi

package=$1
revision=$2
receipt=$3
releases_root=/opt/honeypot-cowrie-output/releases
staging_root=/opt/honeypot-cowrie-output/staging
release="${releases_root}/${revision}"
staging="${staging_root}/.${revision}.$$.staging"
current=/opt/honeypot-cowrie-output/current
cowrie_root=/home/cowrie/cowrie
config="${cowrie_root}/etc/cowrie.cfg"
plugin="${cowrie_root}/src/cowrie/output/sanitizedjson.py"
active_text_log="${cowrie_root}/var/log/cowrie/cowrie.log"
dropin=/etc/systemd/system/cowrie.service.d/20-sanitized-output.conf
logrotate=/etc/logrotate.d/cowrie
users_file=/home/cowrie/users.txt
python="${cowrie_root}/cowrie-env/bin/python"
source_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
forwarder=honeypot-sensor-forwarder.service
receipt_ready=0
release_created=0
staging_created=0
completed=0
forwarder_pid=

receipt_tool() {
  status_file=$1
  shift
  env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="${source_root}" \
    "${python}" -m production.tools.cowrie_rollback_receipt \
    --quiet --status-file "${status_file}" "$@"
}

record_step() {
  if [ -d "${receipt}" ]; then
    { printf '%s\n' "$1" >>"${receipt}/transaction-steps.log" \
      && chmod 0600 "${receipt}/transaction-steps.log"; } 2>/dev/null || :
  fi
}

wait_cowrie_inactive() {
  remaining=30
  while [ "${remaining}" -gt 0 ]; do
    state=$(systemctl show cowrie.service -p ActiveState --value)
    main_pid=$(systemctl show cowrie.service -p MainPID --value)
    if [ "${state}" = inactive ] && [ "${main_pid}" = 0 ]; then
      control_group=$(systemctl show cowrie.service -p ControlGroup --value)
      process_file="/sys/fs/cgroup${control_group}/cgroup.procs"
      if [ -z "${control_group}" ] || [ ! -e "${process_file}" ]; then
        return 0
      fi
      if [ -r "${process_file}" ] && [ -z "$(cat "${process_file}")" ]; then
        return 0
      fi
    fi
    sleep 1
    remaining=$((remaining - 1))
  done
  return 1
}

start_cowrie_bounded() {
  timeout 30 systemctl start cowrie.service
  remaining=30
  while [ "${remaining}" -gt 0 ]; do
    if [ "$(systemctl show cowrie.service -p ActiveState --value)" = active ]; then
      return 0
    fi
    sleep 1
    remaining=$((remaining - 1))
  done
  return 1
}

rollback_on_failure() {
  status=$?
  if [ "${status}" -eq 0 ]; then
    status=1
  fi
  if [ "${completed}" -eq 1 ]; then
    return
  fi
  trap - 0 HUP INT TERM
  set +e
  managed_recovery_status=0
  if [ -d "${receipt}" ]; then
    find "${receipt}" -type d -exec chmod 0700 {} +
    find "${receipt}" -type f -exec chmod 0600 {} +
  fi
  if [ "${staging_created}" -eq 1 ] && [ -d "${staging}" ]; then
    rm -rf "${staging}" || managed_recovery_status=1
  fi
  if [ "${receipt_ready}" -eq 1 ]; then
    timeout 30 systemctl stop cowrie.service >/dev/null 2>&1
    wait_cowrie_inactive >/dev/null 2>&1
    stopped_status=$?
    if [ -e "${active_text_log}" ] || [ -L "${active_text_log}" ]; then
      receipt_tool "${receipt}/failed-log-stopped-preflight.json" \
        assert-stopped --active-log "${active_text_log}"
      held_status=$?
    else
      held_status=0
    fi
    if [ "${stopped_status}" -ne 0 ] || [ "${held_status}" -ne 0 ]; then
      apply_status=1
    else
      receipt_tool "${receipt}/receipt-application.after-failure.json" apply \
        --receipt "${receipt}" --cowrie-root "${cowrie_root}" \
        --users-file "${users_file}" --current "${current}" \
        --drop-in "${dropin}" --logrotate "${logrotate}"
      apply_status=$?
    fi
    if [ "${managed_recovery_status}" -ne 0 ]; then
      apply_status=1
    fi
    if [ "${apply_status}" -eq 0 ]; then
      cleanup_status=0
      for temporary_link in "${current}.new" "${plugin}.new"; do
        if [ -L "${temporary_link}" ]; then
          rm -f "${temporary_link}" || cleanup_status=1
        elif [ -e "${temporary_link}" ]; then
          cleanup_status=1
        fi
      done
      if [ "${cleanup_status}" -eq 0 ]; then
        systemctl daemon-reload || apply_status=1
        if [ "${release_created}" -eq 1 ] && [ -d "${release}" ]; then
          rm -rf "${release}" || apply_status=1
          if [ -e "${release}" ]; then
            apply_status=1
          fi
        fi
      else
        apply_status=1
      fi
    fi
    managed_recovery_status=${apply_status}
  fi
  if [ "${managed_recovery_status}" -eq 0 ]; then
    start_cowrie_bounded >/dev/null 2>&1
    recovery_status=$?
  else
    recovery_status=1
  fi
  current_revision=$(basename "$(readlink -f "${current}" 2>/dev/null)" 2>/dev/null)
  observed_forwarder_pid=$(systemctl show "${forwarder}" -p MainPID --value 2>/dev/null)
  if [ "${managed_recovery_status}" -ne 0 ] \
    || [ "${recovery_status}" -ne 0 ] \
    || [ "${current_revision}" = "${revision}" ] \
    || [ "$(systemctl is-active "${forwarder}" 2>/dev/null)" != active ] \
    || [ "${observed_forwarder_pid}" != "${forwarder_pid}" ]; then
    echo "Cowrie installation failed and automatic recovery is incomplete" >&2
    exit 70
  fi
  echo "Cowrie installation failed; the prior component was restored" >&2
  exit "${status}"
}
trap rollback_on_failure 0 HUP INT TERM

case "${revision}" in
  *[!0-9a-f]*|'') echo "revision is invalid" >&2; exit 2 ;;
esac
[ "${#revision}" -eq 40 ] || { echo "revision is invalid" >&2; exit 2; }
test -f "${package}"
test ! -e "${release}"
test ! -e "${receipt}"
test ! -e "${current}.new"
test ! -L "${current}.new"
test ! -e "${plugin}.new"
test ! -L "${plugin}.new"
test ! -e "${staging}"
test "$(systemctl is-active cowrie.service)" = active
test "$(systemctl is-active "${forwarder}")" = active
forwarder_pid=$(systemctl show "${forwarder}" -p MainPID --value)
test -n "${forwarder_pid}"
test "${forwarder_pid}" != 0
env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="${source_root}" \
  "${python}" -m production.tools.cowrie_output_integration verify-start \
  --current "${current}"

# The package is safely extracted and fully verified while the baseline is
# still active. No archive member is installed directly into the release.
install -d -o root -g root -m 0700 "${staging_root}"
env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="${source_root}" \
  "${python}" -m production.tools.cowrie_output_integration extract-package \
  --package "${package}" --staging-root "${staging}" \
  --expected-revision "${revision}"
staging_created=1
test -z "$(find "${staging}" \( -type d -name __pycache__ -o -type f -name '*.pyc' \) -print -quit)"

install -d -o root -g root -m 0700 "${receipt}"
record_step receipt_directory_created
systemctl show cowrie.service \
  -p ActiveState -p SubState -p MainPID -p ControlGroup -p NRestarts \
  >"${receipt}/cowrie.service.before"
chmod 0600 "${receipt}/cowrie.service.before"
sha256sum "${package}" >"${receipt}/bundle-package.sha256"
chmod 0600 "${receipt}/bundle-package.sha256"
sha256sum "${config}" "${dropin}" "${logrotate}" \
  >"${receipt}/managed-hashes.pre-stop.sha256"
chmod 0600 "${receipt}/managed-hashes.pre-stop.sha256"
git -c "safe.directory=${cowrie_root}" -C "${cowrie_root}" \
  status --porcelain=v1 -uno 2>&1 | sha256sum \
  >"${receipt}/cowrie-dirty-status.before.sha256"
chmod 0600 "${receipt}/cowrie-dirty-status.before.sha256"
record_step immutable_records_captured

record_step cowrie_stop_requested
timeout 30 systemctl stop cowrie.service
wait_cowrie_inactive
record_step cowrie_stopped
receipt_tool "${receipt}/stopped-log-preflight.json" assert-stopped \
  --active-log "${active_text_log}"

receipt_tool "${receipt}/receipt-capture.json" capture-stopped \
  --receipt "${receipt}" --cowrie-root "${cowrie_root}" \
  --users-file "${users_file}" --current "${current}" \
  --config "${config}" --plugin "${plugin}" --drop-in "${dropin}" \
  --logrotate "${logrotate}"
# capture-stopped returns only after sealing and self-verifying the v2 receipt.
# Set recovery authority before any diagnostic write can fail.
receipt_ready=1
record_step log_quarantined
record_step quarantine_hash_recorded
record_step receipt_sealed
receipt_tool "${receipt}/receipt-verification.before-install.json" verify-stopped \
  --receipt "${receipt}" --cowrie-root "${cowrie_root}" \
  --users-file "${users_file}" --current "${current}" \
  --drop-in "${dropin}" --logrotate "${logrotate}"
record_step receipt_verified

find "${cowrie_root}/var/log/cowrie" -xdev -type f \
  ! -path "${cowrie_root}/var/log/cowrie/cowrie_custom.json" \
  ! -path "${cowrie_root}/var/log/cowrie/cowrie.json" \
  ! -path "${cowrie_root}/var/log/cowrie/cowrie.log" \
  -exec sha256sum {} + >"${receipt}/historical-log-hashes.before.sha256"
chmod 0600 "${receipt}/historical-log-hashes.before.sha256"

install -d -o cowrie -g cowrie -m 0700 "${releases_root}"
release_created=1
env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="${source_root}" \
  "${python}" -m production.tools.cowrie_output_integration install-bundle \
  --staging-root "${staging}" --release-root "${release}" \
  --expected-revision "${revision}" \
  >"${receipt}/package-installation.before-activation.json"
chmod 0600 "${receipt}/package-installation.before-activation.json"
test -z "$(find "${release}" \( -type d -name __pycache__ -o -type f -name '*.pyc' \) -print -quit)"
record_step release_extracted

sudo -u cowrie env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="${release}" \
  "${python}" -m production.tools.cowrie_output_integration verify-bundle \
  --bundle-root "${release}" --expected-revision "${revision}" \
  >"${receipt}/package-verification.before-activation.json"
chmod 0600 "${receipt}/package-verification.before-activation.json"
test -z "$(find "${release}" \( -type d -name __pycache__ -o -type f -name '*.pyc' \) -print -quit)"
record_step release_manifest_verified
rm -rf "${staging}"
staging_created=0

ln -sfn "${release}" "${current}.new"
chown -h cowrie:cowrie "${current}.new"
mv -Tf "${current}.new" "${current}"
record_step active_link_changed

temporary_config=$(mktemp "${receipt}/cowrie.cfg.rendered.XXXXXX")
rm -f "${temporary_config}"
env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="${current}" \
  "${python}" -m production.tools.cowrie_output_integration render-config \
  --source "${config}" --destination "${temporary_config}" --bundle-root "${current}"
install -o cowrie -g cowrie -m 0600 "${temporary_config}" "${config}"
rm -f "${temporary_config}"
install -d -o cowrie -g cowrie -m 0700 \
  "${cowrie_root}/var/lib/cowrie"
record_step configuration_installed

ln -sfn "${current}/production/cowrie_output/sanitized_jsonlog.py" "${plugin}.new"
chown -h cowrie:cowrie "${plugin}.new"
mv -Tf "${plugin}.new" "${plugin}"
install -d -o root -g root -m 0755 "$(dirname "${dropin}")"
install -o root -g root -m 0644 \
  "${current}/deployment/cowrie_output/20-sanitized-output.conf" "${dropin}"
record_step systemd_dropin_installed
install -o root -g root -m 0644 \
  "${current}/deployment/cowrie_output/cowrie.logrotate" "${logrotate}"
record_step rotation_policy_installed

for sensitive_file in \
  "${users_file}" \
  "${cowrie_root}/var/log/cowrie/cowrie_custom.json"
do
  if [ -f "${sensitive_file}" ]; then
    chown cowrie:cowrie "${sensitive_file}"
    chmod 0600 "${sensitive_file}"
  fi
done
if [ -f "${cowrie_root}/var/log/cowrie/cowrie.json" ]; then
  chown cowrie:cowrie "${cowrie_root}/var/log/cowrie/cowrie.json"
  chmod 0640 "${cowrie_root}/var/log/cowrie/cowrie.json"
fi
find "${cowrie_root}/var/log/cowrie" -xdev -type f \
  ! -path "${cowrie_root}/var/log/cowrie/cowrie.json" \
  -exec chown cowrie:cowrie {} + \
  -exec chmod 0600 {} +

sudo -u cowrie env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="${current}" \
  HONEYPOT_COWRIE_OUTPUT_ROOT="${current}" \
  HONEYPOT_COWRIE_CONFIG="${config}" \
  "${python}" -m production.tools.cowrie_output_integration validate \
  --config "${config}" --bundle-root "${current}" --plugin-link "${plugin}" \
  --drop-in "${dropin}" --logrotate "${logrotate}" --live-permissions
sudo -u cowrie env PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH="${current}:${cowrie_root}/src" \
  HONEYPOT_COWRIE_OUTPUT_ROOT="${current}" \
  HONEYPOT_COWRIE_CONFIG="${config}" \
  HONEYPOT_COWRIE_ROOT="${cowrie_root}" \
  "${python}" -m production.tools.cowrie_output_integration plugin-readiness \
  --config "${config}" --bundle-root "${current}" --plugin-link "${plugin}" \
  --write-state >"${receipt}/plugin-readiness.before-start.json"
chmod 0600 "${receipt}/plugin-readiness.before-start.json"

systemctl daemon-reload
record_step cowrie_restart_requested
start_cowrie_bounded
test "$(systemctl is-active "${forwarder}")" = active
test "$(systemctl show "${forwarder}" -p MainPID --value)" = "${forwarder_pid}"
test -z "$(find "${release}" \( -type d -name __pycache__ -o -type f -name '*.pyc' \) -print -quit)"
main_pid=$(systemctl show cowrie.service -p MainPID --value)
sudo -u cowrie env PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH="${current}:${cowrie_root}/src" \
  HONEYPOT_COWRIE_OUTPUT_ROOT="${current}" \
  HONEYPOT_COWRIE_CONFIG="${config}" \
  HONEYPOT_COWRIE_ROOT="${cowrie_root}" \
  "${python}" -m production.tools.cowrie_output_integration live-readiness \
  --config "${config}" --bundle-root "${current}" \
  --expected-pid "${main_pid}" >"${receipt}/live-readiness.after-start.json"
chmod 0600 "${receipt}/live-readiness.after-start.json"
sudo -u cowrie env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="${current}" \
  HONEYPOT_COWRIE_OUTPUT_ROOT="${current}" \
  HONEYPOT_COWRIE_CONFIG="${config}" \
  "${python}" -m production.tools.cowrie_output_integration validate \
  --config "${config}" --bundle-root "${current}" --plugin-link "${plugin}" \
  --drop-in "${dropin}" --logrotate "${logrotate}" --live-permissions \
  >"${receipt}/validation.after.json"
chmod 0600 "${receipt}/validation.after.json"
record_step cowrie_healthy
test ! -e "${current}.new"
test ! -L "${current}.new"
test ! -e "${plugin}.new"
test ! -L "${plugin}.new"

sha256sum "${config}" "${dropin}" "${logrotate}" \
  "${release}/COWRIE_OUTPUT_MANIFEST.json" \
  >"${receipt}/managed-hashes.after.sha256"
systemctl show cowrie.service \
  -p ActiveState -p SubState -p MainPID -p ExecMainStartTimestamp \
  >"${receipt}/cowrie.service.after"
find "${receipt}" -type d -exec chmod 0700 {} +
find "${receipt}" -type f -exec chmod 0600 {} +
completed=1
trap - 0 HUP INT TERM

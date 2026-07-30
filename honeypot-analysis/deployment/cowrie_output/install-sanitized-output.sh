#!/bin/sh
set -eu

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
release="/opt/honeypot-cowrie-output/releases/${revision}"
current=/opt/honeypot-cowrie-output/current
cowrie_root=/home/cowrie/cowrie
config="${cowrie_root}/etc/cowrie.cfg"
plugin="${cowrie_root}/src/cowrie/output/sanitizedjson.py"
dropin=/etc/systemd/system/cowrie.service.d/20-sanitized-output.conf
python="${cowrie_root}/cowrie-env/bin/python"

test -f "${package}"
test ! -e "${release}"
test ! -e "${receipt}"
install -d -o root -g root -m 0700 "${receipt}"

record_path() {
  target=$1
  name=$2
  if [ -L "${target}" ]; then
    printf 'symlink\t%s\t%s\n' "${target}" "$(readlink "${target}")" >>"${receipt}/managed-paths.tsv"
  elif [ -f "${target}" ]; then
    cp -a "${target}" "${receipt}/${name}"
    printf 'file\t%s\t%s\t%s\t%s\t%s\n' \
      "${target}" "${name}" "$(stat -c %a "${target}")" \
      "$(stat -c %u "${target}")" "$(stat -c %g "${target}")" \
      >>"${receipt}/managed-paths.tsv"
  else
    printf 'absent\t%s\n' "${target}" >>"${receipt}/managed-paths.tsv"
  fi
}

record_metadata() {
  target=$1
  if [ -f "${target}" ]; then
    printf 'metadata\t%s\t-\t%s\t%s\t%s\n' \
      "${target}" "$(stat -c %a "${target}")" \
      "$(stat -c %u "${target}")" "$(stat -c %g "${target}")" \
      >>"${receipt}/managed-paths.tsv"
  else
    printf 'absent-metadata\t%s\n' "${target}" >>"${receipt}/managed-paths.tsv"
  fi
}

: >"${receipt}/managed-paths.tsv"
chmod 0600 "${receipt}/managed-paths.tsv"
record_path "${config}" cowrie.cfg.before
record_path "${plugin}" sanitizedjson.py.before
record_path "${dropin}" 20-sanitized-output.conf.before
record_path "${current}" current.before
record_metadata /home/cowrie/users.txt
record_metadata "${cowrie_root}/var/log/cowrie/cowrie_custom.json"
record_metadata "${cowrie_root}/var/log/cowrie/cowrie.json"
record_metadata "${cowrie_root}/var/log/cowrie/cowrie.log"
systemctl is-active cowrie.service >"${receipt}/cowrie.service.before" || true
git -C "${cowrie_root}" status --porcelain=v1 -uno 2>&1 \
  | sha256sum >"${receipt}/cowrie-dirty-status.before.sha256"
sha256sum "${package}" >"${receipt}/bundle-package.sha256"

install -d -o cowrie -g cowrie -m 0700 /opt/honeypot-cowrie-output/releases
install -d -o cowrie -g cowrie -m 0700 "${release}"
tar -xf "${package}" -C "${release}"
chown -R cowrie:cowrie "${release}"
find "${release}" -type d -exec chmod 0700 {} +
find "${release}" -type f -exec chmod 0600 {} +
chmod 0700 "${release}/deployment/cowrie_output/run-sanitized-cowrie.sh"

ln -sfn "${release}" "${current}.new"
chown -h cowrie:cowrie "${current}.new"
mv -Tf "${current}.new" "${current}"

temporary_config=$(mktemp "${receipt}/cowrie.cfg.rendered.XXXXXX")
rm -f "${temporary_config}"
env PYTHONPATH="${current}" \
  "${python}" -m production.tools.cowrie_output_integration render-config \
  --source "${config}" --destination "${temporary_config}" --bundle-root "${current}"
install -o cowrie -g cowrie -m 0600 "${temporary_config}" "${config}"
rm -f "${temporary_config}"

ln -sfn "${current}/production/cowrie_output/sanitized_jsonlog.py" "${plugin}.new"
chown -h cowrie:cowrie "${plugin}.new"
mv -Tf "${plugin}.new" "${plugin}"
install -d -o root -g root -m 0755 "$(dirname "${dropin}")"
install -o root -g root -m 0644 \
  "${current}/deployment/cowrie_output/20-sanitized-output.conf" "${dropin}"

for sensitive_file in \
  /home/cowrie/users.txt \
  "${cowrie_root}/var/log/cowrie/cowrie_custom.json" \
  "${cowrie_root}/var/log/cowrie/cowrie.json" \
  "${cowrie_root}/var/log/cowrie/cowrie.log"
do
  if [ -f "${sensitive_file}" ]; then
    chown cowrie:cowrie "${sensitive_file}"
    chmod 0600 "${sensitive_file}"
  fi
done

sudo -u cowrie env PYTHONPATH="${current}" \
  HONEYPOT_COWRIE_OUTPUT_ROOT="${current}" \
  HONEYPOT_COWRIE_CONFIG="${config}" \
  "${python}" -m production.tools.cowrie_output_integration validate \
  --config "${config}" --bundle-root "${current}" --plugin-link "${plugin}" \
  --drop-in "${dropin}" --live-permissions

systemctl daemon-reload
systemctl restart cowrie.service
systemctl is-active --quiet cowrie.service
sudo -u cowrie env PYTHONPATH="${current}" \
  HONEYPOT_COWRIE_OUTPUT_ROOT="${current}" \
  HONEYPOT_COWRIE_CONFIG="${config}" \
  "${python}" -m production.tools.cowrie_output_integration validate \
  --config "${config}" --bundle-root "${current}" --plugin-link "${plugin}" \
  --drop-in "${dropin}" --live-permissions \
  >"${receipt}/validation.after.json"

sha256sum "${config}" "${dropin}" "${release}/COWRIE_OUTPUT_MANIFEST.json" \
  >"${receipt}/managed-hashes.after.sha256"
systemctl show cowrie.service \
  -p ActiveState -p SubState -p MainPID -p ExecMainStartTimestamp \
  >"${receipt}/cowrie.service.after"
chmod 0600 "${receipt}"/*

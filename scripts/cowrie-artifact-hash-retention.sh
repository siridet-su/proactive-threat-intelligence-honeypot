#!/usr/bin/env bash
set -euo pipefail

artifact_dir=${COWRIE_ARTIFACT_DIR:-/home/cowrie/cowrie/var/lib/cowrie/downloads}
ledger=${COWRIE_ARTIFACT_HASH_LEDGER:-/var/lib/honeypot-artifact-retention/sha256.txt}
lock_file=${COWRIE_ARTIFACT_LOCK_FILE:-/run/lock/cowrie-artifact-hash-retention.lock}
payload_age_minutes=${COWRIE_PAYLOAD_MIN_AGE_MINUTES:-5}
decoy_age_minutes=${COWRIE_DECOY_MIN_AGE_MINUTES:-1440}
force_all=${COWRIE_RETENTION_FORCE_ALL:-false}

case "${payload_age_minutes}:${decoy_age_minutes}" in
    *[!0-9:]*) echo "invalid retention age" >&2; exit 2 ;;
esac

mkdir -p -- "$(dirname -- "${ledger}")" "$(dirname -- "${lock_file}")"
touch -- "${ledger}" "${lock_file}"
chmod 0600 "${ledger}" "${lock_file}"

exec 9>"${lock_file}"
flock -n 9 || exit 0

processed=0
failed=0

process_file() {
    local file=$1
    local actual_hash

    if ! actual_hash=$(sha256sum -- "${file}" 2>/dev/null | awk '{print $1}'); then
        failed=$((failed + 1))
        return
    fi
    if [[ ! "${actual_hash}" =~ ^[0-9a-f]{64}$ ]]; then
        failed=$((failed + 1))
        return
    fi

    # Make the retained hash durable before removing bytes. A crash can cause
    # a retry, but cannot leave a deleted artifact without its retained hash.
    if ! grep -Fqx -- "${actual_hash}" "${ledger}"; then
        printf '%s\n' "${actual_hash}" >>"${ledger}"
        chmod 0600 "${ledger}"
        sync -d "${ledger}"
    fi

    if rm -f -- "${file}"; then
        processed=$((processed + 1))
    else
        failed=$((failed + 1))
    fi
}

if [[ "${force_all}" == true ]]; then
    while IFS= read -r -d '' file; do
        process_file "${file}"
    done < <(find "${artifact_dir}" -xdev -maxdepth 1 -type f -print0)
else
    while IFS= read -r -d '' file; do
        process_file "${file}"
    done < <(find "${artifact_dir}" -xdev -maxdepth 1 -type f \
        -regextype posix-extended -regex '.*/[0-9a-fA-F]{64}' \
        -mmin "+${payload_age_minutes}" -print0)
    while IFS= read -r -d '' file; do
        process_file "${file}"
    done < <(find "${artifact_dir}" -xdev -maxdepth 1 -regextype posix-extended \
        -type f ! -regex '.*/[0-9a-fA-F]{64}' \
        -mmin "+${decoy_age_minutes}" -print0)
fi

printf 'artifact_hash_retention processed=%d failed=%d ledger_hashes=%d\n' \
    "${processed}" "${failed}" "$(sort -u "${ledger}" | wc -l)"
[[ "${failed}" -eq 0 ]]

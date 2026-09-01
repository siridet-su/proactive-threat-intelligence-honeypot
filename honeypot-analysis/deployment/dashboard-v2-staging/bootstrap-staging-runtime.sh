#!/usr/bin/env bash
set -euo pipefail

# Run this script as the existing authorized VM administrator. It provisions
# only the dashboard-v2 staging namespace and never edits the production unit,
# production release pointer, backend services, firewall, or Mongo.

SERVICE="honeypot-dashboard-v2-staging.service"
RELEASE_ROOT="/opt/honeypot-dashboard-v2-staging"
INCOMING="$RELEASE_ROOT/incoming"
ENV_DIR="/etc/honeypot/services"
ENV_FILE="$ENV_DIR/dashboard-v2-staging.env"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
NODE_PATH="/opt/honeypot-dashboard-v2/node-v24.18.0/bin/node"

if (( EUID != 0 )); then
  printf '%s\n' 'bootstrap-staging-runtime.sh must run as root' >&2
  exit 1
fi

for required in /usr/bin/openssl /usr/bin/install /usr/bin/systemctl; do
  if [[ ! -x "$required" ]]; then
    printf 'missing required executable: %s\n' "$required" >&2
    exit 1
  fi
done

getent passwd honeypot >/dev/null || {
  printf '%s\n' 'required non-root runtime user honeypot is absent' >&2
  exit 1
}
[[ -x "$NODE_PATH" ]] || {
  printf 'verified portable Node runtime is absent: %s\n' "$NODE_PATH" >&2
  exit 1
}

install -d -o root -g root -m 0755 "$RELEASE_ROOT" "$RELEASE_ROOT/releases" "$RELEASE_ROOT/incoming" "$RELEASE_ROOT/bin" "$RELEASE_ROOT/shared"
install -o root -g root -m 0755 "$SCRIPT_DIR/deploy-staging" "$RELEASE_ROOT/bin/deploy-staging"
install -o root -g root -m 0644 "$SCRIPT_DIR/honeypot-dashboard-v2-staging.service" \
  "/etc/systemd/system/$SERVICE"

if [[ -e "$ENV_FILE" ]]; then
  owner_mode="$(stat -c '%U:%G %a' "$ENV_FILE")"
  if [[ "$owner_mode" != "root:root 600" ]]; then
    printf 'existing staging environment has unsafe ownership/mode: %s\n' "$owner_mode" >&2
    exit 1
  fi
else
  umask 077
  temporary_env="$(mktemp "$ENV_DIR/.dashboard-v2-staging.env.XXXXXX")"
  trap 'rm -f -- "$temporary_env"' EXIT
  {
    printf '%s\n' 'DASHBOARD_API_ORIGIN=http://127.0.0.1:8090'
    printf '%s\n' 'DASHBOARD_V2_OPERATOR_ID=staging-operator'
    printf 'DASHBOARD_V2_ACCESS_KEY=%s\n' "$(/usr/bin/openssl rand -hex 32)"
    printf 'DASHBOARD_V2_SESSION_SECRET=%s\n' "$(/usr/bin/openssl rand -hex 32)"
    printf '%s\n' 'NODE_ENV=production'
    printf '%s\n' 'PORT=3001'
    printf '%s\n' 'HOSTNAME=127.0.0.1'
    printf '%s\n' 'NEXT_TELEMETRY_DISABLED=1'
  } > "$temporary_env"
  chown root:root "$temporary_env"
  chmod 600 "$temporary_env"
  mv -f -- "$temporary_env" "$ENV_FILE"
  trap - EXIT
fi

systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null

printf '%s\n' "staging_unit_installed=$SERVICE"
printf '%s\n' "staging_release_root=$RELEASE_ROOT"
printf '%s\n' "staging_incoming=$INCOMING"
printf '%s\n' "staging_environment_file=$ENV_FILE"
printf '%s\n' 'staging_credentials_generated_or_preserved=true'
printf '%s\n' 'production_service_touched=false'
printf '%s\n' 'backend_or_mongo_touched=false'
printf '%s\n' 'cloudflare_touched=false'

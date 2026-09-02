#!/usr/bin/env bash
set -euo pipefail

# Optional one-time root setup. It installs a dedicated non-root SSH user and
# an exact sudo allowlist for the root-owned staging deployment wrapper. The
# private key remains with the GitHub Environment administrator; this script
# accepts only its public key.

SERVICE_USER="dashboard-staging-deploy"
RELEASE_ROOT="/opt/honeypot-dashboard-v2-staging"
INCOMING="$RELEASE_ROOT/incoming"
SUDOERS_FILE="/etc/sudoers.d/$SERVICE_USER"

if (( EUID != 0 )); then
  printf '%s\n' 'setup-deploy-identity.sh must run as root' >&2
  exit 1
fi
if (( $# != 1 )); then
  printf 'usage: %s /path/to/public-key.pub\n' "$0" >&2
  exit 2
fi
PUBLIC_KEY="$1"
[[ -f "$PUBLIC_KEY" && ! -L "$PUBLIC_KEY" ]] || {
  printf '%s\n' 'public key path must be a regular file' >&2
  exit 1
}
mapfile -t key_lines < <(grep -v '^[[:space:]]*$' "$PUBLIC_KEY")
(( ${#key_lines[@]} == 1 )) || {
  printf '%s\n' 'public key file must contain exactly one non-empty key line' >&2
  exit 1
}
public_key_line="${key_lines[0]}"
[[ "$public_key_line" =~ ^(ssh-ed25519|ecdsa-sha2-nistp256|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)[[:space:]]+[A-Za-z0-9+/=]+([[:space:]][^[:cntrl:]]*)?$ ]] || {
  printf '%s\n' 'public key must be an approved SSH public-key format' >&2
  exit 1
}

if ! getent group "$SERVICE_USER" >/dev/null; then
  groupadd --system "$SERVICE_USER"
fi
if ! getent passwd "$SERVICE_USER" >/dev/null; then
  useradd --system --create-home --home-dir "/var/lib/$SERVICE_USER" --gid "$SERVICE_USER" --shell /bin/bash "$SERVICE_USER"
fi
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0700 "/var/lib/$SERVICE_USER/.ssh"
authorized_keys_tmp="$(mktemp "/var/lib/$SERVICE_USER/.ssh/.authorized_keys.XXXXXX")"
trap 'rm -f -- "$authorized_keys_tmp"' EXIT
printf 'restrict %s\n' "$public_key_line" > "$authorized_keys_tmp"
chown "$SERVICE_USER:$SERVICE_USER" "$authorized_keys_tmp"
chmod 0600 "$authorized_keys_tmp"
mv -f -- "$authorized_keys_tmp" "/var/lib/$SERVICE_USER/.ssh/authorized_keys"
trap - EXIT

install -d -o root -g root -m 0755 "$RELEASE_ROOT" "$RELEASE_ROOT/releases" "$RELEASE_ROOT/bin" "$RELEASE_ROOT/shared"
install -d -o root -g "$SERVICE_USER" -m 0730 "$INCOMING"
cat > "$SUDOERS_FILE" <<EOF
Cmnd_Alias DASHBOARD_STAGING_DEPLOY = $RELEASE_ROOT/bin/deploy-staging *
$SERVICE_USER ALL=(root) NOPASSWD: DASHBOARD_STAGING_DEPLOY
EOF
chown root:root "$SUDOERS_FILE"
chmod 440 "$SUDOERS_FILE"
visudo -cf "$SUDOERS_FILE" >/dev/null

printf '%s\n' "deploy_user=$SERVICE_USER"
printf '%s\n' "authorized_key=$PUBLIC_KEY"
printf '%s\n' "sudo_rule=$SUDOERS_FILE"
printf '%s\n' 'sudo_scope=only root-owned staging deployment wrapper'
printf '%s\n' 'production_restart_permission=false'
printf '%s\n' 'backend_restart_permission=false'
printf '%s\n' 'mongo_permission=false'

#!/usr/bin/env bash
set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
dashboard_dir="${repo_root}/dashboard-v2"

if [[ ! -f "${dashboard_dir}/.env.local" ]]; then
  install -m 0600 "${dashboard_dir}/env.local.template" "${dashboard_dir}/.env.local"
  printf '%s\n' 'PAUSED: fill dashboard-v2/.env.local with developer-only values, then rerun this script.' >&2
  exit 2
fi

python3 - "${dashboard_dir}/.env.local" <<'PY'
import os
import stat
import sys
from pathlib import Path

path = Path(sys.argv[1])
metadata = path.lstat()
if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
    raise SystemExit("Dashboard env needs a regular file owned by this user with mode 0600")
values = {}
for line in path.read_text(encoding="utf-8").splitlines():
    if line and not line.lstrip().startswith("#"):
        key, separator, value = line.partition("=")
        if not separator or key in values:
            raise SystemExit("Dashboard env has an invalid or duplicate assignment")
        values[key] = value.strip().strip("\"'")
required = ("MONGODB_URI", "PTI_ADMIN_PASSWORD", "AUTH_SESSION_SECRET")
missing = [key for key in required if not values.get(key)]
if missing:
    raise SystemExit("PAUSED: Dashboard env needs " + ", ".join(missing))
if len(values["AUTH_SESSION_SECRET"]) < 32 or len(values["PTI_ADMIN_PASSWORD"]) < 12:
    raise SystemExit("Dashboard auth values do not meet minimum lengths")
if not values["MONGODB_URI"].startswith(("mongodb://", "mongodb+srv://")):
    raise SystemExit("Dashboard MongoDB URI has an invalid scheme")
PY

cd "${dashboard_dir}"
if [[ ! -d node_modules ]]; then
  npm ci --legacy-peer-deps --ignore-scripts
fi
exec npm run dev -- --hostname 127.0.0.1

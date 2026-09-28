#!/usr/bin/env bash
# Prepare a Linux build host online, then produce an offline-built ARM64 bundle.
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
go_version=1.26.3
release_id=
output_root=${XDG_DATA_HOME:-"$HOME/.local/share"}/pti-build/releases
check_only=false

usage() {
  cat <<'EOF'
Usage: bash scripts/bootstrap_sensor_build.sh --release-id ID [--output-root DIR]
       bash scripts/bootstrap_sensor_build.sh --check

Linux amd64/arm64 build host. On Ubuntu 24.04, missing base tools are installed
with apt and sudo. Go is installed under your user data directory. This script
downloads Go modules, then uses the existing offline ARM64 release builder.
--check only reports what would be needed; it does not install or download.
EOF
}

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

while (($#)); do
  case "$1" in
    --release-id|--output-root)
      (($# >= 2)) || die "$1 requires a value"
      if [[ $1 == --release-id ]]; then release_id=$2; else output_root=$2; fi
      shift 2 ;;
    --check) check_only=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ $check_only == true || -n $release_id ]] || { usage >&2; die '--release-id is required'; }
[[ $(uname -s) == Linux ]] || die 'only Linux build hosts are supported'
case $(uname -m) in
  x86_64) go_arch=amd64; go_sha=2b2cfc7148493da5e73981bffbf3353af381d5f93e789c82c79aff64962eb556 ;;
  aarch64) go_arch=arm64; go_sha=9d89a3ea57d141c2b22d70083f2c8459ba3890f2d9e818e7e933b75614936565 ;;
  *) die 'only Linux x86_64 and aarch64 build hosts are supported' ;;
esac

# This pin is deliberately tied to the module directives. Update it and both
# checksums together when the repository moves to another Go release.
modules=(
  agents/collector-agent
  agents/processor-agent
  agents/ti-worker
  agents/hardware-agent
  agents/hardware-backup
)
for module in "${modules[@]}"; do
  [[ -f $repo_root/$module/go.mod ]] || die "missing $module/go.mod"
  required=$(awk '$1 == "go" { print $2; exit }' "$repo_root/$module/go.mod")
  [[ $required == "$go_version" ]] || die "$module requires Go $required; bootstrap is pinned to $go_version"
done

packages=()
for entry in git:git python3:python3 curl:curl tar:tar sha256sum:coreutils; do
  command_name=${entry%%:*}
  package_name=${entry#*:}
  command -v "$command_name" >/dev/null 2>&1 || packages+=("$package_name")
done
if command -v dpkg-query >/dev/null 2>&1 && ! dpkg-query -W -f='${Status}' ca-certificates 2>/dev/null | grep -qx 'install ok installed'; then
  packages+=(ca-certificates)
fi

toolchain_root=${XDG_DATA_HOME:-"$HOME/.local/share"}/pti-build/toolchains
toolchain_dir=$toolchain_root/go$go_version
go_bin=
if command -v go >/dev/null 2>&1 && [[ $(GOTOOLCHAIN=local go version 2>/dev/null || true) == *"go$go_version "* ]]; then
  go_bin=$(command -v go)
elif [[ -x $toolchain_dir/bin/go ]] && [[ $("$toolchain_dir/bin/go" version 2>/dev/null || true) == *"go$go_version "* ]]; then
  go_bin=$toolchain_dir/bin/go
fi

printf 'Build host: Linux %s\n' "$go_arch"
printf 'Base packages needed: %s\n' "${packages[*]:-none}"
printf 'Go %s: %s\n' "$go_version" "${go_bin:-download from go.dev/dl and verify SHA-256}"
printf 'Release output root: %s\n' "$output_root"
if [[ $check_only == true ]]; then
  printf 'Check only: no packages, toolchain, modules, or release were changed.\n'
  exit 0
fi

if ((${#packages[@]})); then
  # Only Ubuntu 24.04 gets automatic apt changes. Other Linux distributions
  # can use this script after their base tools are installed separately.
  [[ -r /etc/os-release ]] || die 'cannot identify OS for package installation'
  # shellcheck source=/dev/null
  source /etc/os-release
  [[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 24.04 ]] || die "install ${packages[*]} with your OS package manager, then rerun"
  command -v apt-get >/dev/null 2>&1 || die 'apt-get is missing'
  if ((EUID == 0)); then apt=(apt-get); else
    command -v sudo >/dev/null 2>&1 || die 'sudo is required for missing Ubuntu packages'
    apt=(sudo apt-get)
  fi
  "${apt[@]}" update
  "${apt[@]}" install --no-install-recommends "${packages[@]}"
fi

for command_name in git python3 curl tar sha256sum; do
  command -v "$command_name" >/dev/null 2>&1 || die "$command_name is still unavailable"
done
git -C "$repo_root" rev-parse --verify 'HEAD^{commit}' >/dev/null || die 'checkout has no commit'

if [[ -z $go_bin ]]; then
  mkdir -p -- "$toolchain_root"
  [[ ! -e $toolchain_dir && ! -L $toolchain_dir ]] || die "invalid existing toolchain path: $toolchain_dir"
  stage=$(mktemp -d "$toolchain_root/.go$go_version.XXXXXXXX")
  trap 'rm -rf -- "$stage"' EXIT
  archive=$stage/go.tar.gz
  url=https://go.dev/dl/go$go_version.linux-$go_arch.tar.gz
  printf 'Downloading %s\n' "$url"
  curl --fail --location --silent --show-error --proto '=https' --proto-redir '=https' --tlsv1.2 --output "$archive" "$url"
  printf '%s  %s\n' "$go_sha" "$archive" | sha256sum --check --status || die 'Go archive SHA-256 does not match the official pin'
  tar -C "$stage" -xzf "$archive"
  [[ -x $stage/go/bin/go ]] || die 'verified Go archive did not contain bin/go'
  [[ $("$stage/go/bin/go" version) == *"go$go_version "* ]] || die 'extracted Go version is unexpected'
  mv -- "$stage/go" "$toolchain_dir"
  go_bin=$toolchain_dir/bin/go
  trap - EXIT
  rm -rf -- "$stage"
fi

export PATH="$(dirname -- "$go_bin"):$PATH"
printf 'Using %s\n' "$(go version)"

# The release builder uses a deliberately sanitized environment and the
# default user module cache. Prefetch with the same HOME, GOPATH and flags.
for module in "${modules[@]}"; do
  printf '[download] %s\n' "$module"
  (cd "$repo_root/$module" && env -i HOME="$HOME" PATH="$PATH" GOTOOLCHAIN=local \
    GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GOFLAGS=-mod=readonly \
    go mod download)
  (cd "$repo_root/$module" && env -i HOME="$HOME" PATH="$PATH" GOTOOLCHAIN=local \
    GOPROXY=off GOSUMDB=off GOFLAGS=-mod=readonly go mod verify)
done

python3 "$repo_root/scripts/build_sensor_release.py" \
  --release-id "$release_id" --output-root "$output_root"

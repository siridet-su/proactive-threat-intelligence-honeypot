#!/bin/sh
set -eu

usage() {
    echo "usage: $0 archive|restore-files ARCHIVE_DIRECTORY" >&2
    exit 2
}

[ "$#" -eq 2 ] || usage
mode=$1
archive_dir=$2
unit_dir=/etc/systemd/system
service=honeypot-prediction-backtest.service
timer=honeypot-prediction-backtest.timer

[ "$(id -u)" -eq 0 ] || {
    echo "must run as root" >&2
    exit 2
}

umask 077

case "$mode" in
    archive)
        [ ! -e "$archive_dir" ] || {
            echo "archive directory already exists" >&2
            exit 2
        }
        install -d -o root -g root -m 0700 "$archive_dir"
        systemctl show "$service" "$timer" \
            -p Id -p LoadState -p ActiveState -p UnitFileState -p FragmentPath \
            -p NextElapseUSecRealtime --no-pager > "$archive_dir/before.properties"
        for unit in "$service" "$timer"; do
            source_path="$unit_dir/$unit"
            if [ -f "$source_path" ] && [ ! -L "$source_path" ]; then
                install -o root -g root -m 0600 "$source_path" "$archive_dir/$unit"
            fi
        done
        sha256sum "$archive_dir"/*.service "$archive_dir"/*.timer \
            > "$archive_dir/SHA256SUMS"
        systemctl disable --now "$timer"
        systemctl stop "$service"
        rm -f "$unit_dir/$service" "$unit_dir/$timer"
        systemctl daemon-reload
        systemctl reset-failed "$service" "$timer" || true
        systemctl show "$service" "$timer" \
            -p Id -p LoadState -p ActiveState -p UnitFileState -p FragmentPath \
            --no-pager > "$archive_dir/after.properties"
        ;;
    restore-files)
        [ -d "$archive_dir" ] || {
            echo "archive directory is unavailable" >&2
            exit 2
        }
        (
            cd "$archive_dir"
            sha256sum -c SHA256SUMS
        )
        for unit in "$service" "$timer"; do
            install -o root -g root -m 0644 "$archive_dir/$unit" "$unit_dir/$unit"
        done
        systemctl daemon-reload
        echo "files restored but obsolete timer intentionally remains disabled"
        ;;
    *)
        usage
        ;;
esac

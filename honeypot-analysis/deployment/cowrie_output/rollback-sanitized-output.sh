#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "must run as root" >&2
  exit 2
fi
if [ "$#" -ne 1 ] || [ ! -f "$1/managed-paths.tsv" ]; then
  echo "usage: $0 VERIFIED_RECEIPT_DIRECTORY" >&2
  exit 2
fi

receipt=$1
while IFS="$(printf '\t')" read -r kind target saved mode uid gid
do
  case "${kind}" in
    absent)
      if [ -e "${target}" ] || [ -L "${target}" ]; then
        rm -f -- "${target}"
      fi
      ;;
    symlink)
      ln -sfn "${saved}" "${target}.rollback"
      mv -Tf "${target}.rollback" "${target}"
      ;;
    file)
      install -o "${uid}" -g "${gid}" -m "${mode}" "${receipt}/${saved}" "${target}"
      ;;
    metadata)
      chown "${uid}:${gid}" "${target}"
      chmod "${mode}" "${target}"
      ;;
    absent-metadata)
      ;;
    *)
      echo "invalid rollback receipt entry" >&2
      exit 2
      ;;
  esac
done <"${receipt}/managed-paths.tsv"

systemctl daemon-reload
systemctl restart cowrie.service
systemctl is-active --quiet cowrie.service

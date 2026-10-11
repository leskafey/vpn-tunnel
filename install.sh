#!/usr/bin/env bash
# Shell entry point for the verified clean-server installer.
set -euo pipefail

usage() {
  cat <<'HELP'
vpn-tunnel: установка на чистый Ubuntu 24.04 x86_64

  sudo ./install.sh --server-ip PUBLIC_IPV4
  sudo ./install.sh --server-ip PUBLIC_IPV4 --resume
  sudo ./install.sh audit

--resume продолжает только прерванную установку этого проекта.
Правила: <проект>/config/. Профили: <проект>/profiles/. Управление: vpnctl.
HELP
}

fail() { printf '%s\n' "$*" >&2; exit 2; }

action=install
if [[ ${1:-} == audit || ${1:-} == install ]]; then
  action=$1
  shift
fi
server_ip=
resume=false
while (( $# )); do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --server-ip)
      (( $# >= 2 )) || fail 'После --server-ip нужен публичный IPv4.'
      [[ -n $2 && $2 != -* ]] || fail 'После --server-ip нужен публичный IPv4.'
      [[ -z $server_ip ]] || fail '--server-ip указан дважды.'
      server_ip=$2; shift 2 ;;
    --server-ip=*)
      [[ -z $server_ip ]] || fail '--server-ip указан дважды.'
      server_ip=${1#*=}; [[ -n $server_ip ]] || fail 'Пустой --server-ip.'; shift ;;
    --resume) resume=true; shift ;;
    *) fail "Неизвестный аргумент: $1. Используйте --help." ;;
  esac
done
if [[ $action == audit ]]; then
  [[ -z $server_ip && $resume == false ]] || fail 'audit не принимает --server-ip или --resume.'
else
  [[ -n $server_ip ]] || fail 'Укажите --server-ip PUBLIC_IPV4. Используйте --help.'
fi
[[ $(id -u) == 0 ]] || fail 'Запустите от root или через sudo.'
command -v python3 >/dev/null || fail 'Установите python3 и ca-certificates.'
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
[[ -f $root/install-vpn.py ]] || fail 'Не найден install-vpn.py рядом с install.sh.'
if [[ $action == audit ]]; then
  exec python3 "$root/install-vpn.py" audit
fi
command -v systemd-run >/dev/null || fail 'Нужен сервер с systemd.'
arguments=(install --server-ip "$server_ip")
[[ $resume == false ]] || arguments+=(--resume)
exec systemd-run --wait --pipe --collect --unit=vpn-stack-install \
  -p MemoryMax=768M -p MemorySwapMax=0 \
  -p TasksMax=64 -p RuntimeMaxSec=1800 -p UMask=0077 \
  "$(command -v python3)" "$root/install-vpn.py" "${arguments[@]}"

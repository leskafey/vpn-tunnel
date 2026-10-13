#!/usr/bin/env bash
set -euo pipefail
if [[ ${1:-} == --help || ${1:-} == -h ]]; then
  cat <<'HELP'
Управление установленным vpn-tunnel (запускайте от root):

  vpnctl device add laptop-macos
  vpnctl device add android-phone
  vpnctl device list
  vpnctl device export laptop-macos
  vpnctl device revoke laptop-macos
  vpnctl rule add proxy example.org
  vpnctl rule add proxy-ip 8.8.8.8
  vpnctl rule add direct example.org
  vpnctl rule add ads ads.example.org
  vpnctl rule add ads-exceptions ads.example.org
  vpnctl rule remove proxy example.org
  vpnctl status
  vpnctl cleanup

Эти команды также доступны через ./vpnctl.sh из клонированного проекта.
Имена устройств не определяют платформу. device list выводит только имена.
Профили: <проект>/profiles/. Личные правила: <проект>/config/.
Новые SMART/FULL-профили универсальны: Windows, macOS, iOS и Android.
Указывать --platform не требуется; прежние шаблоны ОС сохранены.
export выводит пути на VPS и восстанавливает отсутствующие JSON с прежним UUID.
Изменённый вручную JSON при export не перезаписывается (ошибка).
revoke локально проверяет отзыв UUID; внешние DNS/HTTPS/STUN не используются.
Неизменённые JSON удаляются, изменённые сохраняются с сообщением об отзыве UUID.
add/revoke кратко перезапускают Xray; незавершённая операция откатывается.
status: службы Xray/DNS/HTTP, обновления, последняя политика и неприменённые правки.
Ненулевой код — локальная неисправность; внешний доступ с устройства не проверяется.
cleanup удаляет остатки обновлений и работает при полном диске; активные данные,
незавершённая транзакция и необходимые поколения отката сохраняются.
Правки правил применяются после 3 с покоя; повтор при занятости через 15 с.
Клиентский DIRECT обновляется раз в 5 мин (выход из туннеля только в SMART), IP — раз в час.
HELP
  exit 0
fi
if [[ ! -x /usr/local/sbin/vpnctl ]]; then
  printf '%s\n' 'vpn-tunnel ещё не установлен. Начните с ./install.sh --help.' >&2
  exit 1
fi
exec /usr/local/sbin/vpnctl "$@"

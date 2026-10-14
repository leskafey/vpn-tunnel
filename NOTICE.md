# Компоненты и источники

В репозитории находятся код установки, управления и проверок. Ключи создаются
на целевом сервере при установке, пользовательские профили — при добавлении
устройств.

Бинарники скачиваются отдельно с проверкой закреплённых SHA-256:

- [Xray-core 26.3.27](https://github.com/XTLS/Xray-core/releases/tag/v26.3.27).
- [sing-box 1.14.2](https://github.com/SagerNet/sing-box/releases/tag/v1.14.2).
- [Mihomo 1.19.31](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.31).

Каждый компонент распространяется по своей upstream-лицензии. Лицензия
кода этого проекта не заменяет условия лицензирования этих компонентов.

Источники списков: [AntiZapret-VPN](https://github.com/GubernievS/AntiZapret-VPN),
[rulist](https://github.com/bol-van/rulist),
[antifilter](https://antifilter.download/), [oisd](https://github.com/sjhgvr/oisd),
[AdGuard DNS Filter](https://github.com/AdguardTeam/AdGuardSDNSFilter),
[официальные диапазоны Telegram](https://core.telegram.org/resources/cidr.txt).
rulist, antifilter, OISD и AdGuard скачиваются при сборке политики.
Доменные и рекламные дополнения хранятся в `lists/baseline/` и входят
в автономный установщик; происхождение записано в
[PROVENANCE.json](lists/baseline/PROVENANCE.json).
IP Telegram, Discord, WhatsApp и Cloudflare пока скачиваются из AntiZapret-VPN;
для Telegram также используется официальный источник.

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

Загружаемые источники списков: [rulist](https://github.com/bol-van/rulist),
[antifilter](https://antifilter.download/), [oisd](https://github.com/sjhgvr/oisd),
[AdGuard DNS Filter](https://github.com/AdguardTeam/AdGuardSDNSFilter),
[официальные диапазоны Telegram](https://core.telegram.org/resources/cidr.txt),
[официальные IPv4 Cloudflare](https://www.cloudflare.com/ips-v4/).
rulist, antifilter, OISD и AdGuard скачиваются при сборке политики.
Доменные, рекламные и IP-дополнения хранятся в `lists/baseline/` и входят
в автономный установщик; происхождение записано в
[PROVENANCE.json](lists/baseline/PROVENANCE.json).
Telegram и Cloudflare объединяются с собственными `*-extra-ips.txt`;
Discord и WhatsApp читаются из локальных `discord-ips.txt`/`whatsapp-ips.txt`.
Исходные данные дополнений получены из
[AntiZapret-VPN](https://github.com/GubernievS/AntiZapret-VPN); сетевых обращений
к этому репозиторию в действующем коде нет. Изменения базовых списков
доставляются через `upgrade`, отдельно от личных правил.

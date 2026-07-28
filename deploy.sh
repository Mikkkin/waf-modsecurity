#!/usr/bin/env bash
# Разворачивает WAF на текущей машине: nginx + ModSecurity + OWASP CRS,
# после чего раскладывает конфигурацию из этого репозитория.
#
# Запускать на узле waf от root:
#   sudo ./deploy.sh
#
# Этим же скриптом пользуется CI, поэтому если он ломается - сборка краснеет,
# и расхождение между "как написано в README" и "как есть на самом деле"
# обнаруживается сразу, а не через месяц.

set -euo pipefail

CRS_VERSION="${CRS_VERSION:-4.28.0}"
CRS_DIR="${CRS_DIR:-/etc/crs4}"
MODSEC_DIR="${MODSEC_DIR:-/etc/nginx/modsec}"
LOG_DIR="${LOG_DIR:-/var/log/modsec}"
ORIGIN="${ORIGIN:-192.168.130.20:3000}"
MODE="${MODE:-On}"
SKIP_PACKAGES=0

usage() {
    cat <<EOF
Использование: sudo ./deploy.sh [ключи]

  --origin HOST:PORT   адрес защищаемого приложения (сейчас: $ORIGIN)
  --mode On|DetectionOnly
                       режим движка (сейчас: $MODE)
  --skip-packages      не ставить пакеты и CRS, только разложить конфигурацию
  -h, --help           эта справка
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --origin) ORIGIN="$2"; shift 2 ;;
        --mode)   MODE="$2";   shift 2 ;;
        --skip-packages) SKIP_PACKAGES=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "неизвестный ключ: $1" >&2; usage; exit 1 ;;
    esac
done

[ "$(id -u)" -eq 0 ] || { echo "нужен root" >&2; exit 1; }

cd "$(dirname "$0")"
REPO="$PWD"

say() { printf '\n== %s ==\n' "$1"; }

if [ "$SKIP_PACKAGES" -eq 0 ]; then
    say "Пакеты"
    apt-get update -qq
    apt-get install -y --no-install-recommends \
        nginx libnginx-mod-http-modsecurity libmodsecurity3t64 curl gnupg jq
    # Дистрибутивный modsecurity-crs - это ветка 3.3.x. У нее другая структура
    # переменных, и конфигурация из этого репозитория к ней неприменима.
    apt-get purge -y modsecurity-crs >/dev/null 2>&1 || true
    dpkg-query -W -f='${Package} ${Version}\n' \
        nginx libnginx-mod-http-modsecurity libmodsecurity3t64

    say "OWASP CRS $CRS_VERSION"
    tmp="$(mktemp -d)"
    curl -fsSL -o "$tmp/crs.tar.gz" \
        "https://github.com/coreruleset/coreruleset/archive/refs/tags/v${CRS_VERSION}.tar.gz"
    curl -fsSL -o "$tmp/crs.tar.gz.asc" \
        "https://github.com/coreruleset/coreruleset/releases/download/v${CRS_VERSION}/coreruleset-${CRS_VERSION}.tar.gz.asc"
    curl -fsSL https://coreruleset.org/security.asc | gpg --batch --quiet --import
    gpg --batch --verify "$tmp/crs.tar.gz.asc" "$tmp/crs.tar.gz"
    mkdir -p "$CRS_DIR"
    tar xzf "$tmp/crs.tar.gz" -C "$CRS_DIR" --strip-components=1
    cp -n "$CRS_DIR/crs-setup.conf.example" "$CRS_DIR/crs-setup.conf"
    rm -rf "$tmp"

    # В 4.28.0 правила 901181 быть не должно. Если появилось - значит скачалась
    # не та версия, и дальше будут сюрпризы с лексером собственных правил.
    if grep -q 901181 "$CRS_DIR/rules/REQUEST-901-INITIALIZATION.conf"; then
        echo "в наборе есть правило 901181, версия не та" >&2
        exit 1
    fi
fi

say "Конфигурация из репозитория"
install -d "$MODSEC_DIR" "$LOG_DIR"
chown www-data:adm "$LOG_DIR"
install -m 0644 "$REPO/waf/modsecurity.conf"   "$MODSEC_DIR/modsecurity.conf"
install -m 0644 "$REPO/waf/crs-setup-lab.conf" "$MODSEC_DIR/crs-setup-lab.conf"
install -m 0644 "$REPO/waf/modsec-main.conf"   "$MODSEC_DIR/main.conf"
install -m 0644 "$REPO"/waf/rules/*.conf       "$CRS_DIR/rules/"
sed -i "s/^SecRuleEngine .*/SecRuleEngine $MODE/" "$MODSEC_DIR/modsecurity.conf"

install -d /etc/nginx/sites-available /etc/nginx/sites-enabled
install -m 0644 "$REPO/waf/nginx/waf.conf" /etc/nginx/sites-available/waf.conf
# Адрес приложения подставляется сюда, чтобы один и тот же конфиг годился
# и для стенда, и для сборки, где вместо Juice Shop стоит заглушка.
sed -i -E "s|^(\s*server\s+)[^;]+;|\1${ORIGIN};|" /etc/nginx/sites-available/waf.conf
ln -sf /etc/nginx/sites-available/waf.conf /etc/nginx/sites-enabled/waf.conf
rm -f /etc/nginx/sites-enabled/default

say "Проверка"
/usr/lib/x86_64-linux-gnu/libexec/modsec-rules-check "$MODSEC_DIR/main.conf"
nginx -t

say "Запуск"
# Именно restart: на чистой машине nginx уже поднят со старым конфигом,
# и reload не подхватит появившийся модуль.
systemctl restart nginx
systemctl --no-pager --lines=0 status nginx | head -3

printf '\nГотово. Режим: %s, приложение: %s\n' "$MODE" "$ORIGIN"

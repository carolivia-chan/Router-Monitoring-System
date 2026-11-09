#!/usr/bin/env bash
# Install NetMon on an Ubuntu/Debian machine: sudo ./install.sh
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo"; exit 1; }
SRC=$(cd "$(dirname "$0")" && pwd); D=/opt/netmon

# Check that every file is present BEFORE touching the system: stop right away if one is missing, instead of leaving
# a half-finished install (set -e would stop at the first failing cp, after packages / code / venv are already set up)
need=(main.py requirements.txt monitor/schema.sql monitor/jobs.py scripts/setup_subif.sh scripts/90-netmon-dispatcher
      systemd/netmon.service systemd/netmon-subif@.service systemd/netmon-job@.service etc/netmon.conf etc/targets.csv)
miss=(); for f in "${need[@]}"; do [[ -e "$SRC/$f" ]] || miss+=("$f"); done
(( ${#miss[@]} == 0 )) || { echo "Missing files in $SRC: ${miss[*]}"; exit 1; }

# PostgreSQL: port + password come from the docker compose .env file (the same values docker-compose.yml uses),
# so NETMON_PG_DSN always matches the port the container exposes on the host (default 5433, not 5432)
envval(){ sed -n "s/^$1=//p" "$SRC/.env" 2>/dev/null | tail -n 1 | tr -d "\"'"; }
PG_PORT=$(envval PG_PORT); PG_PORT=${PG_PORT:-5433}
PG_PASSWORD=$(envval PG_PASSWORD); PG_PASSWORD=${PG_PASSWORD:-netmon_pw}

apt-get update -y
apt-get install -y fping mtr-tiny traceroute iproute2 iptables iputils-arping python3 python3-venv python3-pip

mkdir -p "$D/results" /etc/netmon
cp -r "$SRC/main.py" "$SRC/monitor" "$SRC/scripts" "$SRC/requirements.txt" "$D/"
chmod +x "$D"/scripts/*.sh "$D/main.py"
python3 -m venv "$D/venv"
"$D/venv/bin/pip" install -q -r "$D/requirements.txt"

# never overwrite an existing configuration
[[ -f /etc/netmon/netmon.conf  ]] || cp "$SRC/etc/netmon.conf"  /etc/netmon/
[[ -f /etc/netmon/targets.csv  ]] || cp "$SRC/etc/targets.csv"  /etc/netmon/
# netmon.env holds secrets: created with mode 600 from the start, content generated here (no template file needed)
if [[ ! -f /etc/netmon/netmon.env ]]; then
  install -m 600 /dev/null /etc/netmon/netmon.env
  cat > /etc/netmon/netmon.env <<ENV
# NetMon secrets (chmod 600). systemd loads this file via EnvironmentFile=; main.py loads it itself when run by hand.
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
# PostgreSQL in docker compose: port ${PG_PORT} on the host -> 5432 in the container (see docker-compose.yml).
# Leave empty if PostgreSQL is not used yet.
NETMON_PG_DSN=postgresql://netmon:${PG_PASSWORD}@127.0.0.1:${PG_PORT}/netmon
# (optional) Globalping token (dash.globalping.io) -> 500 tests/hour instead of 250
GP_TOKEN=
ENV
else
  cur=$(sed -n 's|^NETMON_PG_DSN=.*@[^:/]*:\([0-9]*\)/.*|\1|p' /etc/netmon/netmon.env | tail -n 1)
  if [[ -n "$cur" && "$cur" != "$PG_PORT" ]]; then
    echo "WARNING: /etc/netmon/netmon.env uses PostgreSQL port $cur but docker compose exposes $PG_PORT -> fix NETMON_PG_DSN"
  fi
fi

# MaxMind: copy ./data/*.mmdb -> /opt/netmon/data (default path in netmon.conf)
mkdir -p "$D/data"
if ls "$SRC"/data/*.mmdb >/dev/null 2>&1; then
  cp "$SRC"/data/*.mmdb "$D/data/"
  echo "Copied MaxMind: $(cd "$D/data" && ls *.mmdb | tr '\n' ' ')"
else
  echo "WARNING: data/*.mmdb not found -> hops will show Unknown"
fi

cp "$SRC"/systemd/*.service "$SRC"/systemd/*.timer /etc/systemd/system/
ln -sf "$D/scripts/setup_subif.sh" /usr/local/bin/subif
[[ -d /etc/NetworkManager/dispatcher.d ]] && install -m 755 "$SRC/scripts/90-netmon-dispatcher" /etc/NetworkManager/dispatcher.d/90-netmon
# NetworkManager must not manage mon*
if [[ -d /etc/NetworkManager/conf.d ]]; then
  printf '[keyfile]\nunmanaged-devices=interface-name:mon*\n' > /etc/NetworkManager/conf.d/99-netmon-unmanaged.conf
  systemctl reload NetworkManager 2>/dev/null || true
fi
systemctl daemon-reload
# Automation: hourly aggregation, expired-data cleanup, backup, data freshness check, daily report (monitor/jobs.py)
TIMERS=(netmon-rollup.timer netmon-retention.timer netmon-backup.timer netmon-freshness.timer netmon-report.timer)
systemctl enable --now "${TIMERS[@]}"

cat <<MSG
Installation finished. Next steps:
  1. Check MaxMind: ls /opt/netmon/data
  2. sudo nano /etc/netmon/netmon.env        (Telegram token/chat id; DSN already points to 127.0.0.1:${PG_PORT})
  3. sudo nano /etc/netmon/netmon.conf       (PARENT, IP_OFFSET...) and /etc/netmon/targets.csv
  4. sudo subif create                       (create the sub-interfaces)
  5. sudo /opt/netmon/venv/bin/python /opt/netmon/main.py --once     (one test measurement)
  6. sudo systemctl enable --now netmon && systemctl status netmon
  7. sudo docker compose up -d               (Grafana: http://localhost:3001)
  8. systemctl list-timers 'netmon-*'        (automation jobs; logs: journalctl -u 'netmon-job@*')
MSG

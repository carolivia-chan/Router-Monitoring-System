#!/usr/bin/env bash
# setup_subif.sh -- create / delete / control ipvlan sub-interfaces on the parent (wlp1s0).
# Every setting lives in /etc/netmon/netmon.conf; there is NO need to edit this script.
#
#   subif create [N]        create sub-ifs 1..N      (enable --now netmon-subif@i)
#   subif add <i>           add sub-if number i
#   subif delete <i|all>    delete                   (disable --now netmon-subif@i)
#   subif start|stop|restart|enable|disable|status <i|all>   -> systemctl
#   subif list              list
#   subif up|down <i>       (called by systemd) configure / remove the kernel objects
#
# Several ISPs on 1 machine: UPLINKS="1-5:wlp1s0 6-10:usb0" -> mon1..5 are created on wlp1s0,
# mon6..10 on usb0 (phone USB tethering / USB 4G modem). Empty = every monN is created on PARENT.
#
# DRY_RUN=1 only prints the commands without running them.
set -euo pipefail

CONF=${NETMON_CONF:-/etc/netmon/netmon.conf}
# shellcheck disable=SC1090
[[ -r $CONF ]] && source "$CONF"
PARENT=${PARENT:-}; COUNT=${COUNT:-10}; PREFIX=${NAME_PREFIX:-mon}
TBASE=${TABLE_BASE:-100}; OFF=${IP_OFFSET:-200}
PARENT_CIDR=${PARENT_CIDR:-}; GATEWAY=${GATEWAY:-}; UPLINKS=${UPLINKS:-}

run()  { if [[ ${DRY_RUN:-0} == 1 ]]; then echo "+ $*"; else "$@"; fi; }
need_root() { [[ ${DRY_RUN:-0} == 1 || $EUID -eq 0 ]] || { echo "Must be run with sudo" >&2; exit 1; }; }
unit() { echo "netmon-subif@$1.service"; }

default_parent() {
  if [[ -n $PARENT ]]; then echo "$PARENT"
  else ip -4 route show default | awk '{print $5; exit}'; fi
}

# parent of monN: from UPLINKS if N falls in one of its ranges, otherwise the default parent
parent_if() {
  local i=$1 spec rng a b
  for spec in $UPLINKS; do
    rng=${spec%%:*}; a=${rng%-*}; b=${rng#*-}
    if [[ $a =~ ^[0-9]+$ && $b =~ ^[0-9]+$ ]] && (( i >= a && i <= b )); then
      echo "$spec" | cut -d: -f2; return
    fi
  done
  default_parent
}

# indexes of the sub-ifs systemd knows about (loaded or enabled)
instances() {
  { systemctl list-units --all --plain --no-legend 'netmon-subif@*.service' 2>/dev/null || true
    ls /etc/systemd/system/multi-user.target.wants 2>/dev/null || true; } \
    | grep -oE 'netmon-subif@[0-9]+' | sed 's/.*@//' | sort -un
}

up() {
  local i=$1 par name cidr gw ip plen net tbl
  [[ $i =~ ^[1-9][0-9]*$ ]] || { echo "The IPvlan index must be a positive integer" >&2; exit 1; }
  par=$(parent_if "$i"); name=$PREFIX$i; tbl=$((TBASE+i))
  ip link show "$par" &>/dev/null || { echo "interface '$par' not found (USB plugged in / tethering on?)" >&2; exit 1; }
  if [[ $par == "$(default_parent)" ]]; then      # PARENT_CIDR / GATEWAY only apply to the default parent
    cidr=${PARENT_CIDR:-}; gw=${GATEWAY:-}
  else
    cidr=; gw=
  fi
  cidr=${cidr:-$(ip -4 -o addr show dev "$par" scope global | awk '{print $4; exit}')}
  gw=${gw:-$(ip -4 route show default dev "$par" | awk '{print $3; exit}')}
  [[ -n $cidr && -n $gw ]] || { echo "parent '$par' has no IP/gateway yet (is it connected?)" >&2; exit 1; }

  read -r ip plen net < <(python3 -c '
import ipaddress, sys
parent = ipaddress.ip_interface(sys.argv[1])
n = parent.network
candidate = n.network_address + int(sys.argv[2]) + int(sys.argv[3])
if candidate not in n or candidate in (n.network_address, n.broadcast_address, parent.ip):
    raise SystemExit(f"IPvlan address {candidate} is invalid in {n} / same as the parent")
print(candidate, n.prefixlen, n)
' "$cidr" "$OFF" "$i")

  # avoid IP conflicts in the LAN
  # only the iputils arping (package iputils-arping) is used: -D = Duplicate Address Detection
  if [[ ${DRY_RUN:-0} != 1 ]]; then
    if ! command -v arping >/dev/null || ! arping -V 2>&1 | grep -qi iputils; then
      echo "iputils-arping is missing: an IPvlan is never created without a duplicate-IP check" >&2; exit 1
    fi
    arping -D -q -c 2 -w 3 -I "$par" "$ip" || { echo "IP $ip is already used by another device. Change IP_OFFSET." >&2; exit 1; }
  fi

  if [[ ${DRY_RUN:-0} != 1 ]] && ip link show "$name" &>/dev/null; then down "$i" >/dev/null; fi

  # ipvlan L2: shares the parent's MAC -> the Wi-Fi AP accepts it (the AP would reject macvlan)
  run ip link add link "$par" name "$name" type ipvlan mode l2
  # Do not put the IPvlan connected route in the main table: the Wi-Fi parent keeps the LAN route.
  run ip -4 addr add "$ip/$plen" dev "$name" noprefixroute
  run ip link set "$name" up
  run sysctl -qw "net.ipv4.conf.$name.rp_filter=2"
  # policy routing: packets sourced from monN leave through monN
  run ip route replace "$net" dev "$name" src "$ip" table "$tbl"
  run ip route replace default via "$gw" dev "$name" src "$ip" table "$tbl"
  run ip rule add from "$ip/32" lookup "$tbl" pref $((1000+i))
  run ip rule add oif "$name" lookup "$tbl" pref $((2000+i))
  # mtr sends through a raw socket and builds the IP header itself -> the kernel ignores the 2 rules above and even
  # 'mtr -I', so packets leave through the default-route interface (wlp1s0) instead of monN. Fix: mark (fwmark) every
  # packet with monN's source IP; once iptables marks it, the kernel re-routes it by the fwmark rule -> right monN.
  if command -v iptables >/dev/null; then
    iptables -t mangle -C OUTPUT -s "$ip/32" -j MARK --set-mark "$tbl" 2>/dev/null || \
      run iptables -t mangle -A OUTPUT -s "$ip/32" -j MARK --set-mark "$tbl"
    run ip rule add fwmark "$tbl" lookup "$tbl" pref $((1500+i))
  else
    echo "WARNING: iptables is not installed -> mtr packets will leave through $par instead of $name (sudo apt install iptables)" >&2
  fi
  echo "$name up: $ip/$plen via $gw (table $tbl, parent $par)"
}

down() {
  local i=$1 name=$PREFIX$1 tbl=$((TBASE+$1))
  if [[ ${DRY_RUN:-0} == 1 ]]; then
    echo "+ ip rule del pref $((1000+i)); ip rule del pref $((1500+i)); ip rule del pref $((2000+i))"
    echo "+ iptables -t mangle -D OUTPUT ... --set-mark $tbl"
    echo "+ ip route flush table $tbl"; echo "+ ip link del $name"
  else
    # Only remove the exact MARK rule of the source IP assigned to monN; no eval on iptables output.
    local src_ip=""
    if ip link show "$name" &>/dev/null; then
      if ! ip -d link show "$name" | grep -q 'ipvlan.*mode l2'; then
        echo "Refusing to delete '$name': it is not a NetMon IPvlan L2" >&2
        return 1
      fi
      src_ip=$(ip -4 -o addr show dev "$name" | awk '$3 == "inet" {split($4, a, "/"); print a[1]; exit}')
    fi
    if [[ -n $src_ip ]] && command -v iptables >/dev/null; then
      while iptables -t mangle -C OUTPUT -s "$src_ip/32" -j MARK --set-mark "$tbl" 2>/dev/null; do
        iptables -t mangle -D OUTPUT -s "$src_ip/32" -j MARK --set-mark "$tbl"
      done
    fi
    while ip rule del pref $((1000+i)) 2>/dev/null; do :; done
    while ip rule del pref $((1500+i)) 2>/dev/null; do :; done
    while ip rule del pref $((2000+i)) 2>/dev/null; do :; done
    ip route flush table "$tbl" 2>/dev/null || true
    ip link del "$name" 2>/dev/null || true
  fi
  echo "$name down"
}

for_targets() {   # for_targets <action> <i|all>
  local act=$1 t=$2
  if [[ $t == all ]]; then
    for i in $(instances); do run systemctl "$act" "$(unit "$i")" || true; done
  else
    run systemctl "$act" "$(unit "$t")"
  fi
}

cmd=${1:-}; arg=${2:-}
case "$cmd" in
  up)      need_root; up "$arg" ;;
  down)    need_root; down "$arg" ;;
  create)  need_root; for i in $(seq 1 "${arg:-$COUNT}"); do run systemctl enable --now "$(unit "$i")"; done ;;
  add)     need_root; [[ $arg =~ ^[0-9]+$ ]] || { echo "usage: $0 add <i>"; exit 1; }
           run systemctl enable --now "$(unit "$arg")" ;;
  delete)  need_root; [[ -n $arg ]] || { echo "usage: $0 delete <i|all>"; exit 1; }
           if [[ $arg == all ]]; then for i in $(instances); do run systemctl disable --now "$(unit "$i")" || true; done
           else run systemctl disable --now "$(unit "$arg")"; fi ;;
  start|stop|restart|enable|disable)
           need_root; [[ -n $arg ]] || { echo "usage: $0 $cmd <i|all>"; exit 1; }; for_targets "$cmd" "$arg" ;;
  status)  [[ -n $arg && $arg != all ]] && run systemctl status "$(unit "$arg")" --no-pager \
             || { systemctl list-units --all --no-legend 'netmon-subif@*.service' || true; } ;;
  list)    systemctl list-units --all --no-legend 'netmon-subif@*.service' || true
           echo; ip -4 -br addr show type ipvlan 2>/dev/null || true ;;
  *) sed -n '2,15p' "$0" | sed 's/^# \?//'; exit 1 ;;
esac


"""Shared helpers: read the configuration, find sub-interface IPs/names, read the target list, measurement source names."""
import csv
import json
import os
import re
import socket
import subprocess

DEFAULTS = {
    "PARENT": "wlp1s0", "NAME_PREFIX": "mon", "COUNT": "10",
    "INTERVAL": "60", "TRACE_EVERY": "5", "PING_COUNT": "20", "TRACE_CYCLES": "5",
    "PING_PERIOD": "1000", "PING_TIMEOUT": "1000", "PROBE_PPS": "50", "TRACE_TOOL": "mtr", "TRACE_WORKERS": "2",
    "LOSS_HOP_WARN": "10", "TRACE_ON_LOSS": "1", "TRACE_ON_ANOMALY": "1", "TRACE_ROTATE": "1",
    "FRESHNESS_MAX": "180", "BACKUP_DIR": "/var/backups/netmon", "BACKUP_KEEP_DAYS": "7",
    "PG_CONTAINER": "netmon-postgres-1", "REPORT_DIR": "/opt/netmon/results/reports",
    "RESULTS_DIR": "/opt/netmon/results", "STATE_DIR": "/var/lib/netmon",
    "TARGETS": "/etc/netmon/targets.csv",
    "GEOIP_CITY": "/opt/netmon/data/GeoLite2-City.mmdb",
    "GEOIP_ASN": "/opt/netmon/data/GeoLite2-ASN.mmdb",
    "EXPORTER_PORT": "9108", "PG_RETENTION_DAYS": "30",
    "LOSS_WARN": "20", "LATENCY_WARN": "600", "JITTER_WARN": "20", "ALERT_COOLDOWN": "1800", "ALERT_HOLD": "1200",
    "LATENCY_RISE_MS": "80", "LATENCY_RISE_PCT": "40", "JITTER_FACTOR": "2",
    "BASELINE_SAMPLES": "30", "BASELINE_MIN": "5", "BASELINE_RELEARN": "21600",
    "LOSS_UNSTABLE": "5", "DOWN_HOLD": "300", "ALERT_ESCALATE": "3600", "CLEAR_SAMPLES": "3",
    "INSTABILITY_RATIO": "0.5", "ALERT_GAP": "300",
    "PATH_MIN_TARGETS": "3", "PATH_RATIO": "0.3", "GW_JITTER_WARN": "10", "GW_LOSS_WARN": "5", "GATEWAY": "",
    "SOURCE_NAME": "", "UPLINKS": "",
    "GP_ENABLE": "0", "GP_LOCATIONS": "JP SG KR IN DE GB US BR ZA AU", "GP_TARGETS": "",
    "GP_TYPE": "mtr", "GP_PACKETS": "10", "GP_INTERVAL": "3600",
}


def load_conf(path=None):
    """Read KEY=VALUE lines (ignoring '#' comments) and merge them with DEFAULTS."""
    path = path or os.environ.get("NETMON_CONF", "/etc/netmon/netmon.conf")
    conf = dict(DEFAULTS)
    with open(path) as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if re.match(r"^[A-Z_]+=", line):
                k, v = line.split("=", 1)
                v = v.strip()
                if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":   # UPLINKS="a b" -> a b (like bash)
                    v = v[1:-1]
                conf[k] = v
    return conf


def load_env(path=None):
    """Load /etc/netmon/netmon.env (TELEGRAM_*, NETMON_PG_DSN) into os.environ.

    systemd loads this file itself via EnvironmentFile=; this function makes manual runs
    (sudo .../main.py --once / --test-alert) get Telegram and PostgreSQL too.
    Variables already present in the environment are kept (not overwritten).
    """
    path = path or os.environ.get("NETMON_ENV", "/etc/netmon/netmon.env")
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                if k.startswith("export "):
                    k = k[7:].strip()
                os.environ.setdefault(k, v.strip().strip('"').strip("'"))
    except OSError:
        pass                                 # no file / not enough permissions: ignore


def uplinks(conf):
    """UPLINKS="1-5:wlp1s0 6-10:usb0" -> [(1, 5, 'wlp1s0'), (6, 10, 'usb0')]: which monN is created on which parent.

    Each entry: <monN range>:<parent>. A range may be a single number ("3"). The ISP name is NOT written here: NetMon
    detects it with MaxMind (see isp_label); the ':<label>' part of the old format (1-5:wlp1s0:viettel) is ignored.
    """
    out = []
    for spec in conf.get("UPLINKS", "").split():
        parts = spec.split(":")
        try:
            a, _, b = parts[0].partition("-")
            out.append((int(a), int(b or a), parts[1]))
        except (ValueError, IndexError):
            raise ValueError(f"UPLINKS has an invalid entry '{spec}' (expected: 1-5:wlp1s0)") from None
    return out


def _isp_word(org):
    """Representative word of an organization name: the abbreviation in parentheses if any, else the first word."""
    org = (org or "").strip()
    m = re.search(r"\(([^)]*\w[^)]*)\)", org)
    return m.group(1) if m else (org.split() or [""])[0]


def isp_label(asn, org):
    """Short (lowercase) ISP label from MaxMind GeoLite2-ASN data, used in the source KEY (laptop/vnpt).

    Organization name with an abbreviation in parentheses -> the abbreviation; otherwise the first word:
      'VNPT Corp' -> 'vnpt', 'Viettel Group' -> 'viettel', 'FPT Telecom Company' -> 'fpt',
      'Vietnam Posts and Telecommunications (VNPT)' -> 'vnpt'.   No organization name -> 'as45899'.
    """
    word = re.sub(r"[^a-z0-9-]", "", _isp_word(org).lower())
    return word or (asn or "").lower()


def isp_name(asn, org):
    """ISP name for DISPLAY, keeping the letter case used by MaxMind:
    'VNPT Corp' -> 'VNPT', 'Viettel Group' -> 'Viettel', 'FPT Telecom Company' -> 'FPT'. No name -> 'AS45899'."""
    word = re.sub(r"[^A-Za-z0-9-]", "", _isp_word(org))
    return word or (asn or "").upper()


def source_name(conf):
    """Name of the measurement machine: SOURCE_NAME in netmon.conf, or the hostname when empty."""
    return conf.get("SOURCE_NAME") or socket.gethostname()


def source_label(conf, isp=None):
    """Measurement source KEY (source column in PostgreSQL, source label in Prometheus): short, no spaces.

    'laptop/vnpt' -> machine 'laptop', monN reaches the Internet through the ISP labeled 'vnpt' (isp, from MaxMind)
    'laptop'      -> ISP not identified yet (no trace yet, or every hop is '*' / a private IP)
    'gp/JP/Tokyo' -> Globalping probe, see gp_source()
    The human-readable name (Grafana, Telegram, reports) is display_name(), not this key.
    """
    return f"{source_name(conf)}/{isp}" if isp else source_name(conf)


# ------------------------------------------------------------------ measurement source: independent fields
#   source_type      Local | Globalping                      (kind of measurement source)
#   source_key       laptop/vnpt | gp/JP/Tokyo               (key stored in the DB / Prometheus)
#   source_location  - | Tokyo, Japan                        (Globalping only: where the probe is)
#   source_asn       AS45899 | AS2516                        (ASN of the network the measurement point sits in, per measurement)
#   display_name     Laptop · VNPT · mon1 | Tokyo, Japan     (human-readable name; the source type is shown separately)
# For Globalping the location is the main information; the probe country is NOT an ISP, and the ASN is NOT an iface.
SEP = " · "
_COUNTRIES = {}


def country_name(cc):
    """ISO 3166 country code -> English name, read from Ubuntu's iso-codes package ('JP' -> 'Japan', 'KR' -> 'South Korea').
    Without the iso-codes package the code itself is returned."""
    if not _COUNTRIES:
        try:
            with open("/usr/share/iso-codes/json/iso_3166-1.json") as f:
                for e in json.load(f)["3166-1"]:
                    _COUNTRIES[e["alpha_2"]] = e.get("common_name") or e["name"]
        except (OSError, ValueError, KeyError):
            _COUNTRIES["?"] = "?"                    # mark as tried, so the file is not read again each time
    return _COUNTRIES.get((cc or "").upper(), cc or "?")


def machine_display(name):
    """'laptop' -> 'Laptop' (first letter uppercased, the rest unchanged)."""
    return name[:1].upper() + name[1:]


def source_display(conf, isp=None):
    """Display name of the measurement machine + ISP (without sub-interface): 'Laptop · VNPT'; unknown ISP -> 'Laptop'."""
    m = machine_display(source_name(conf))
    return f"{m}{SEP}{isp}" if isp else m


def source_type(src):
    """Kind of measurement source from the source key: 'Globalping' (gp/...) or 'Local' (our own machine)."""
    return "Globalping" if (src or "").startswith("gp/") else "Local"


def gp_source(cc, city=None):
    """Source key of 1 Globalping probe: 'gp/JP/Tokyo' (country + city of the probe)."""
    return f"gp/{cc or '??'}/{city.replace('/', '-')}" if city else f"gp/{cc or '??'}"


def gp_location(cc, city=None):
    """Location of a Globalping probe: 'Tokyo, Japan'; a city named like its country (Singapore) or unknown -> 'Singapore'.
    This is also the probe's display_name: the word 'Globalping' is the source_type, shown in its own field."""
    country = country_name(cc)
    return f"{city}, {country}" if city and city != country else country


def display_name(src, src_display, iface):
    """Full display name of 1 measurement point: 'Laptop · VNPT · mon1' (Local) or 'Tokyo, Japan' (Globalping)."""
    if (src or "").startswith("gp/"):
        return src_display
    return f"{src_display}{SEP}{iface}" if iface else src_display


def display_for_key(name, isp_names=None):
    """Rebuild the display name (without sub-interface) from a source key, for older data in PostgreSQL.
    isp_names: {'vnpt': 'VNPT', ...} taken from the asn table (MaxMind organization names)."""
    parts = (name or "").split("/")
    if parts[0] == "gp":
        return gp_location(parts[1] if len(parts) > 1 else None, parts[2] if len(parts) > 2 else None)
    m = machine_display(parts[0])
    if len(parts) > 1 and parts[1]:
        return f"{m}{SEP}{(isp_names or {}).get(parts[1], parts[1])}"
    return m


def read_targets(path):
    with open(path, newline="") as f:
        return [{k: (v or "").strip() for k, v in row.items()} for row in csv.DictReader(f)]


def _ip_cmd(*args):
    return subprocess.run(["ip", *args], capture_output=True, text=True).stdout


def iface_ip(name):
    """IPv4 address of the interface, or None if it has none."""
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", _ip_cmd("-4", "-o", "addr", "show", "dev", name))
    return m.group(1) if m else None


def gateway_of(src_ip, conf=None):
    """Gateway (Wi-Fi router) that packets from src_ip (the IP of monN) go through: read from monN's routing table
    ('ip route get 1.1.1.1 from <ip>' -> '... via 192.168.0.1 dev mon1 table 101'). GATEWAY in the conf takes priority."""
    if conf and conf.get("GATEWAY"):
        return conf["GATEWAY"]
    m = re.search(r"\bvia (\d+\.\d+\.\d+\.\d+)", _ip_cmd("-4", "route", "get", "1.1.1.1", "from", src_ip)) \
        if src_ip else None
    return m.group(1) if m else None


def list_subifs(prefix):
    """Sub-interfaces currently present in the kernel, e.g. ['mon1', 'mon2']."""
    names = re.findall(r"^\d+:\s+(%s\d+)@" % re.escape(prefix), _ip_cmd("-o", "link", "show"), re.M)
    return sorted(names, key=lambda n: int(n[len(prefix):]))

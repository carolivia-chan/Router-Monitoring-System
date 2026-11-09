"""TRACE IP: route tracing with mtr (default) or traceroute, bound to a sub-interface (-I) + source IP;
computes per-hop latency (median/avg/best/worst/loss) and enriches each hop with MaxMind GeoLite2."""
import ipaddress
import re
import statistics
import subprocess
import sys


class Geo:
    """Look up the country (GeoLite2-City) and ASN/org (GeoLite2-ASN). Works without the .mmdb files, showing Unknown."""

    def __init__(self, city_path, asn_path):
        self.city = self._open(city_path)
        self.asn = self._open(asn_path)

    @staticmethod
    def _open(path):
        try:
            import geoip2.database
            return geoip2.database.Reader(path)
        except Exception as e:
            print(f"[geo] cannot open {path}: {e}", file=sys.stderr)
            return None

    def lookup(self, ip):
        if not ip:
            return {}
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return {}
        if not addr.is_global:                 # 10.x, 192.168.x, 100.64/10 ...: not looked up
            return {"public": False}
        out = {"public": True, "country": None, "asn": None, "org": None}
        if self.city:
            try:
                out["country"] = self.city.city(ip).country.name
            except Exception:
                pass
        if self.asn:
            try:
                r = self.asn.asn(ip)
                out["asn"] = f"AS{r.autonomous_system_number}"
                out["org"] = r.autonomous_system_organization
            except Exception:
                pass
        return out


# ------------------------------------------------------------------ statistics of 1 hop
def hop_stats(hop, ip, rtts, sent, dup=0):
    """rtts: list of RTTs (ms) received (duplicates removed); sent: number of probes sent to this hop;
    dup: number of duplicate replies (not counted in recv)."""
    sent = max(sent, len(rtts), 1)
    return {
        "hop": hop, "ip": ip, "sent": sent, "recv": len(rtts), "dup": dup,
        "loss_pct": round(100.0 * (sent - len(rtts)) / sent, 1),
        "median_ms": round(statistics.median(rtts), 1) if rtts else None,
        "avg_ms": round(statistics.mean(rtts), 1) if rtts else None,
        "best_ms": round(min(rtts), 1) if rtts else None,
        "worst_ms": round(max(rtts), 1) if rtts else None,
    }


def _truncate(hops, target_ip):
    """Clean up the hop list:
    - Destination reached: cut the hops after the destination (mtr also probes TTLs beyond the destination).
    - Destination not reached: the last router usually answers 'host unreachable' for every larger TTL, so its IP
      repeats over many hops with very large latency (~3000 ms, waiting for ARP). Cut at the first repeated IP.
    - Drop empty ('*') hops at the end."""
    for i, h in enumerate(hops):
        if h["ip"] == target_ip:
            return hops[: i + 1]
    seen = set()
    for i, h in enumerate(hops):
        if h["ip"] and h["ip"] in seen:
            hops = hops[:i]
            break
        if h["ip"]:
            seen.add(h["ip"])
    while hops and hops[-1]["ip"] is None:
        hops = hops[:-1]
    return hops


# ------------------------------------------------------------------ mtr (raw)
def parse_mtr_raw(text, target_ip, cycles):
    """`mtr --raw` prints one event per line:
        x <pos> <seq>          1 probe sent to hop pos (pos starts at 0)
        h <pos> <ip>           IP of hop pos
        p <pos> <usec> <seq>   reply received after <usec> microseconds
    Raw output is used (instead of -j/-r) because every RTT is needed to compute the MEDIAN (mtr reports have none).
    A probe (same pos + seq) receiving several 'p' lines -> DUPLICATE replies: only the first one is kept, the rest
    are counted in 'dup'. Otherwise duplicates would make up for really lost packets and hide the loss.
    """
    ips, rtts, sent, dups, seen = {}, {}, {}, {}, set()
    saw_x = False
    for line in text.splitlines():
        f = line.split()
        if len(f) < 3:
            continue
        try:
            pos = int(f[1])
        except ValueError:
            continue
        if f[0] == "x":
            saw_x = True
            sent[pos] = sent.get(pos, 0) + 1
        elif f[0] == "h":
            ips.setdefault(pos, f[2])           # ECMP: keep the first IP
        elif f[0] == "p":
            key = (pos, f[3] if len(f) > 3 else None)        # (hop, probe sequence number)
            if key[1] is not None and key in seen:
                dups[pos] = dups.get(pos, 0) + 1             # duplicate reply to the same probe
                continue
            seen.add(key)
            rtts.setdefault(pos, []).append(int(f[2]) / 1000.0)
    if not (ips or sent):
        return []
    last = max(list(ips) + list(sent) + list(rtts))
    hops = [hop_stats(pos + 1, ips.get(pos), rtts.get(pos, []),
                      sent.get(pos, 0) if saw_x else cycles, dups.get(pos, 0))
            for pos in range(last + 1)]
    return _truncate(hops, target_ip)


def trace_mtr(iface, src_ip, target_ip, cycles=5):
    cmd = ["mtr", "-n", "--raw", "-c", str(cycles), "-I", iface, "-a", src_ip, target_ip]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=cycles * 30 + 60)
    if r.returncode != 0 and not r.stdout.strip():
        raise RuntimeError(r.stderr.strip() or f"mtr exit {r.returncode}")
    return parse_mtr_raw(r.stdout, target_ip, cycles)


# ------------------------------------------------------------------ traceroute
_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_NUMF = re.compile(r"^\d+(?:\.\d+)?$")


def parse_traceroute(text, target_ip, queries):
    """traceroute -n prints one line per hop, e.g.:
         3  116.97.90.97  3.512 ms  3.401 ms  116.97.90.98  4.1 ms
         5  * * *
         9  129.250.2.254  210.1 ms !H  *  209.8 ms
    """
    hops = []
    for line in text.splitlines():
        f = line.split()
        if not f or not f[0].isdigit():
            continue                              # skip the "traceroute to ..." header line
        hop, ip, rtts = int(f[0]), None, []
        for i, tok in enumerate(f[1:], 1):
            if _IP.match(tok):
                ip = ip or tok                    # several IPs (ECMP): keep the first one
            elif _NUMF.match(tok) and i + 1 < len(f) and f[i + 1] == "ms":
                rtts.append(float(tok))
        hops.append(hop_stats(hop, ip, rtts, queries))
    return _truncate(hops, target_ip)


def trace_traceroute(iface, src_ip, target_ip, queries=3):
    # -I: use ICMP like mtr (needs root); -i: interface; -s: source IP; -N 4: at most 4 probes in flight
    cmd = ["traceroute", "-n", "-I", "-q", str(queries), "-w", "2", "-N", "4",
           "-i", iface, "-s", src_ip, target_ip]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30 * queries * 2 + 60)
    if r.returncode != 0 and not r.stdout.strip():
        raise RuntimeError(r.stderr.strip() or f"traceroute exit {r.returncode}")
    return parse_traceroute(r.stdout, target_ip, queries)


# ------------------------------------------------------------------ common entry point
def trace(iface, src_ip, target_ip, geo, cycles=5, tool="mtr"):
    if tool == "traceroute":
        hops = trace_traceroute(iface, src_ip, target_ip, queries=cycles)
    else:
        hops = trace_mtr(iface, src_ip, target_ip, cycles)
    for h in hops:
        h.update(geo.lookup(h["ip"]))
        h["tool"] = tool
    return hops

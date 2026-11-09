"""GLOBALPING: measure from Globalping probes located in many countries (https://globalping.io), no extra machine.

Each round: for each target server, send 1 measurement (mtr or ping) to the API, choosing 1 probe for each entry in
GP_LOCATIONS (Globalping "magic" strings: country code "JP", city "Tokyo", ASN "AS45899", "VN+VNPT"...).
Results are converted to the same format as probe.py / trace.py, so analyze, report, PostgreSQL, Prometheus and
Grafana reuse them unchanged:
    source_type = Globalping         source_key = "gp/<country code>/<city>"   (e.g. gp/JP/Tokyo)
    display_name = source_location = "Tokyo, Japan"      source_asn = ASN of the network hosting the probe (e.g. AS2516)
    A Globalping probe has no sub-interface (iface is empty); the probe ASN is NOT an iface and the probe country is
    NOT an ISP. The ASN is stored per measurement because Globalping may pick another probe in the same city next time.

Globalping free limits: 250 tests/hour (anonymous, per IP), 500 tests/hour (with a token, set GP_TOKEN in
netmon.env). 1 test = 1 probe measuring 1 server -> 1 round = servers x locations.
"""
import json
import math
import statistics
import sys
import time
import urllib.error
import urllib.request

from monitor.common import gp_location, gp_source
from monitor.trace import _truncate, hop_stats

API = "https://api.globalping.io/v1/measurements"


def _req(method, url, body=None, token=None, timeout=20):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json", "User-Agent": "netmon/1.0"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def _probe_result(rtts, sent, jitter=None):
    """Result in the same shape as probe.parse_fping, from the list of received RTTs and the number of packets sent."""
    sent = max(sent, len(rtts), 1)
    if jitter is None:                              # mean |difference| between 2 adjacent packets
        diffs = [abs(a - b) for a, b in zip(rtts, rtts[1:])]
        jitter = statistics.mean(diffs) if diffs else 0.0
    lost = sent - len(rtts)
    return {
        "avg_ms": round(statistics.mean(rtts), 1) if rtts else None,
        "median_ms": round(statistics.median(rtts), 1) if rtts else None,
        "min_ms": round(min(rtts), 1) if rtts else None,
        "max_ms": round(max(rtts), 1) if rtts else None,
        "jitter_ms": round(float(jitter), 1),
        "loss_pct": round(100.0 * lost / sent, 1),
        "lost_seq": [], "loss_burst": 0, "dup_count": 0,   # Globalping does not say which packets were lost
        "samples": rtts + [None] * lost,
        "status": "UP" if rtts else "DOWN",
    }


def parse_ping(result, packets):
    """result of a type=ping measurement -> probe dict."""
    rtts = [t["rtt"] for t in result.get("timings") or [] if t.get("rtt") is not None]
    sent = (result.get("stats") or {}).get("total") or packets
    return _probe_result(rtts, sent)


def parse_mtr(result, target_ip, packets):
    """result of a type=mtr measurement -> (probe to the destination, hop list in the trace.py format)."""
    hops = []
    for i, h in enumerate(result.get("hops") or []):
        rtts = [t["rtt"] for t in h.get("timings") or [] if t.get("rtt") is not None]
        sent = (h.get("stats") or {}).get("total") or packets
        hops.append(hop_stats(i + 1, h.get("resolvedAddress") or None, rtts, sent))
    hops = _truncate(hops, target_ip)
    raw = result.get("hops") or []
    if hops and hops[-1]["ip"] == target_ip:        # destination reached: the last hop is the probe result
        last = raw[len(hops) - 1]
        rtts = [t["rtt"] for t in last.get("timings") or [] if t.get("rtt") is not None]
        p = _probe_result(rtts, (last.get("stats") or {}).get("total") or packets,
                          (last.get("stats") or {}).get("jAvg"))
    else:
        p = _probe_result([], packets)
    return p, hops


class Globalping:
    def __init__(self, conf, geo, token=None):
        self.locations = conf["GP_LOCATIONS"].split()
        self.only = [x.strip() for x in conf["GP_TARGETS"].split(",") if x.strip()]
        self.mtype = conf["GP_TYPE"] if conf["GP_TYPE"] in ("mtr", "ping") else "mtr"
        self.packets = min(16, max(1, int(conf["GP_PACKETS"])))
        self.base_interval = int(conf["GP_INTERVAL"])
        self.geo, self.token = geo, token
        self.limit = 500 if token else 250           # free tests/hour

    def pick(self, targets):
        """Which servers are measured from Globalping (GP_TARGETS: names or IPs, comma separated; empty = all)."""
        return [t for t in targets if not self.only or t["ip"] in self.only or t["name"] in self.only]

    def interval(self, n_targets):
        """Stretch the period to fit the free limit (with a 10% margin)."""
        tests = n_targets * len(self.locations)
        return max(self.base_interval, math.ceil(tests * 3600 / (self.limit * 0.9)))

    def _create(self, ip, locations):
        body = {"type": self.mtype, "target": ip, "locations": [{"magic": loc, "limit": 1} for loc in locations],
                "measurementOptions": {"packets": self.packets}}
        return _req("POST", API, body, self.token)["id"]

    def _wait(self, mid, timeout=120):
        t0 = time.time()
        while True:
            m = _req("GET", f"{API}/{mid}", token=self.token)
            if m.get("status") != "in-progress" or time.time() - t0 > timeout:
                return m
            time.sleep(1)                             # the API allows at most 2 GETs/second/measurement

    def run(self, targets):
        """1 measurement round. Returns [(source_key, source_asn, display_name, target, probe, hops), ...]."""
        jobs = []                                     # (target, measurement id)
        for t in targets:
            try:
                jobs.append((t, self._create(t["ip"], self.locations)))
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    print("[gp] Globalping free quota used up (HTTP 429), stopping this round", file=sys.stderr)
                    break
                if e.code == 422:                     # some location has no probe: try each location separately
                    for loc in self.locations:
                        try:
                            jobs.append((t, self._create(t["ip"], [loc])))
                        except urllib.error.HTTPError as e2:
                            if e2.code == 429:
                                break
                            print(f"[gp] no probe for '{loc}' (HTTP {e2.code}), skipped", file=sys.stderr)
                else:
                    print(f"[gp] {t['ip']}: HTTP error {e.code}", file=sys.stderr)
            except Exception as e:
                print(f"[gp] {t['ip']}: cannot reach the Globalping API: {e}", file=sys.stderr)
                break
        out = []
        for t, mid in jobs:
            try:
                m = self._wait(mid)
            except Exception as e:
                print(f"[gp] {t['ip']}: failed to fetch result {mid}: {e}", file=sys.stderr)
                continue
            for item in m.get("results") or []:
                pr, r = item.get("probe") or {}, item.get("result") or {}
                if r.get("status") != "finished":     # probe offline / failed
                    continue
                cc, city = pr.get("country"), pr.get("city")
                src, asn, display = gp_source(cc, city), f"AS{pr['asn']}" if pr.get("asn") else None, gp_location(cc, city)
                if self.mtype == "mtr":
                    p, hops = parse_mtr(r, t["ip"], self.packets)
                    for h in hops:
                        h.update(self.geo.lookup(h["ip"]))
                        h["tool"] = "globalping"
                else:
                    p, hops = parse_ping(r, self.packets), None
                out.append((src, asn, display, t, p, hops))
        return out

"""Prometheus exporter (http://host:9108/metrics).

Labels of every metric (same as the measurement source fields in PostgreSQL, see monitor/common.py):
  source       measurement source key (laptop/vnpt, gp/JP/Tokyo)  -> 1 Prometheus can collect many measurement machines
  source_type  Local | Globalping
  iface        sub-interface (mon1); Globalping probes have none -> ""
  source_asn   ASN of the network the measurement point sits in (AS45899, AS2516); not the asn label of per-hop metrics
  display      display name ('Laptop · VNPT · mon1', 'Tokyo, Japan') used as the Grafana legend
netmon_up: result of the LATEST probe round (1 replied / 0 no reply);
netmon_status_5probe: Connection Status by majority over the last 5 probe rounds (1 UP / 0 DOWN / -1 UNKNOWN), with
  netmon_availability_5probe (share of UP rounds, 0..1) and netmon_valid_probes_5probe (valid rounds) - health.window_status;
netmon_health: 0 HEALTHY, 1 DEGRADED, 2 UNSTABLE, 3 DOWN, -1 UNKNOWN (see monitor/health.py), with the baselines;
netmon_gateway_*: the gateway of each monN measured in the same round (Wi-Fi / local network vs ISP side).
Series of Local pairs that are no longer measured (monN stopped) are removed after a gap (prune), so Grafana does not
keep showing an old state. If the collector stops, Prometheus can no longer scrape it; if it hangs, Grafana relies on
netmon_last_cycle_timestamp (unchanged for more than 180 s -> statuses hidden).
"""
import time

from prometheus_client import REGISTRY, Gauge, start_http_server

NAN = float("nan")
BASE = ["source", "source_type", "iface", "source_asn", "target", "name", "country", "display"]
HOP = ["source", "source_type", "iface", "target", "hop", "ip", "country", "asn"]
GW = ["source", "iface", "gateway"]


def _v(x):
    """None (no data) -> NaN."""
    return NAN if x is None else x


class Exporter:
    def __init__(self, port, registry=REGISTRY):
        self.port = port
        g = lambda n, d, l=BASE: Gauge(n, d, l, registry=registry)   # noqa: E731
        self.up = g("netmon_up", "1 if the probe got replies, 0 if DOWN")
        self.latency = g("netmon_latency_ms", "Mean latency (ms)")
        self.median = g("netmon_latency_median_ms", "Median latency (ms)")
        self.jitter = g("netmon_jitter_ms", "Jitter (ms)")
        self.loss = g("netmon_loss_pct", "Packet loss (%)")
        self.hops = g("netmon_hop_count", "Number of hops in the latest trace")
        self.reached = g("netmon_reached", "1 if the trace reached the destination")
        self.score = g("netmon_route_score", "Route quality score (lower = better)")
        self.bottleneck = g("netmon_bottleneck_ms", "Latency increase at the bottleneck hop (ms)")
        self.loss_start = g("netmon_loss_start_hop", "Hop where real packet loss starts (0 = no loss)")
        self.dest_loss = g("netmon_dest_loss_pct", "Loss at the destination (max of trace and probe, %)")
        self.hop_lat = g("netmon_hop_latency_ms", "Median latency of each hop (ms)", HOP)
        self.hop_loss = g("netmon_hop_loss_pct", "Loss of each hop (%)", HOP)
        self.health = g("netmon_health", "Network Health: 0 HEALTHY, 1 DEGRADED, 2 UNSTABLE, 3 DOWN, -1 UNKNOWN")
        self.base_median = g("netmon_baseline_median_ms", "Normal (baseline) median latency of the route (ms)")
        self.base_jitter = g("netmon_baseline_jitter_ms", "Normal (baseline) jitter of the route (ms)")
        self.gw_median = g("netmon_gateway_median_ms", "Median latency to the gateway (ms)", GW)
        self.gw_jitter = g("netmon_gateway_jitter_ms", "Jitter to the gateway (ms)", GW)
        self.gw_loss = g("netmon_gateway_loss_pct", "Packet loss to the gateway (%)", GW)
        self.status5 = g("netmon_status_5probe", "Connection Status by majority over the last 5 probe rounds: 1 UP "
                                                 "(>= 3 UP), 0 DOWN (>= 3 DOWN), -1 UNKNOWN (not enough valid rounds)")
        self.avail5 = g("netmon_availability_5probe", "Share of UP rounds among the valid rounds of the last 5 (0..1), "
                                                      "measurement errors not counted")
        self.valid5 = g("netmon_valid_probes_5probe", "Number of valid probe rounds (UP or DOWN) among the last 5")
        self.heartbeat = Gauge("netmon_last_cycle_timestamp", "Unix time of the latest measurement round", registry=registry)
        self._hop_keys = {}
        # per-round probe series of the local measurement machine -> time of last update (prune). Main thread only.
        self._probe_gauges = (self.up, self.latency, self.median, self.jitter, self.loss, self.score, self.health,
                              self.base_median, self.base_jitter, self.status5, self.avail5, self.valid5)
        self._seen = {}

    @staticmethod
    def _drop(g, lv):
        try:
            g.remove(*lv)
        except KeyError:
            pass

    def start(self):
        start_http_server(self.port)

    def probe(self, src, iface, t, p, sc, display="", stype="", asn="", h=None, w=None):
        """h: Network Health of this round; w: 5-round Connection Status (health.window_status). Both exist only for
        the local measurement machine (Globalping runs once an hour; 5 rounds = 5 hours, not a "current state")."""
        lv = (src, stype, iface or "", asn or "", t["ip"], t["name"], t["country"], display or iface or src)
        if p["status"] == "ERROR":
            # fping failed: there is NO data -> remove the series (Prometheus treats it as missing), do not write 0 = DOWN.
            # No NaN either: a time average in Grafana would become NaN over the whole window.
            for g in (self.up, self.latency, self.median, self.jitter, self.loss, self.score):
                self._drop(g, lv)
        else:
            self.up.labels(*lv).set(1 if p["status"] == "UP" else 0)
            self.latency.labels(*lv).set(_v(p.get("avg_ms")))
            self.median.labels(*lv).set(_v(p.get("median_ms")))
            self.jitter.labels(*lv).set(_v(p.get("jitter_ms")))
            self.loss.labels(*lv).set(_v(p.get("loss_pct")))
            self.score.labels(*lv).set(sc if sc != float("inf") else NAN)
        if h is not None:                                 # Network Health (local measurement machine only)
            self.health.labels(*lv).set(h["level"] if h["level"] is not None else -1)
            self.base_median.labels(*lv).set(h["base_lat"] if h["base_lat"] is not None else NAN)
            self.base_jitter.labels(*lv).set(h["base_jit"] if h["base_jit"] is not None else NAN)
        if w is not None:                                 # Connection Status: majority over the last 5 rounds
            self.status5.labels(*lv).set(w["level"])
            self.valid5.labels(*lv).set(w["valid"])
            if w["availability"] is None:                 # all of the last 5 rounds failed to measure: no ratio (no NaN)
                self._drop(self.avail5, lv)
            else:
                self.avail5.labels(*lv).set(w["availability"])
        if stype == "Local":
            self._seen[lv] = time.time()
        self.heartbeat.set(time.time())

    def prune(self, max_age, now=None):
        """Remove the probe series of Local pairs not updated for more than max_age seconds: monN stopped (mon3), or a
        label changed (ISP identified: laptop -> laptop/vnpt). Otherwise Grafana would keep showing the last value
        (e.g. UP). Trace series (hop_count...) are not removed here: each pair is traced only every ~25 min (TRACE_ROTATE)."""
        now = time.time() if now is None else now
        for lv, ts in list(self._seen.items()):
            if now - ts > max_age:
                for g in self._probe_gauges:
                    self._drop(g, lv)
                del self._seen[lv]

    def gateway(self, src, iface, gw, gp):
        if not gw or not gp:
            return
        lv = (src, iface, gw)
        up = gp.get("status") == "UP"
        self.gw_median.labels(*lv).set(_v(gp.get("median_ms")) if up else NAN)
        self.gw_jitter.labels(*lv).set(_v(gp.get("jitter_ms")) if up else NAN)
        self.gw_loss.labels(*lv).set(_v(gp.get("loss_pct")))

    def trace(self, src, iface, t, hops, a, display="", stype="", asn=""):
        lv = (src, stype, iface or "", asn or "", t["ip"], t["name"], t["country"], display or iface or src)
        self.hops.labels(*lv).set(a["hop_count"])
        self.reached.labels(*lv).set(1 if a["reached"] else 0)
        self.bottleneck.labels(*lv).set(a["bottleneck"]["delta_ms"] if a["bottleneck"] else 0)
        L = a.get("loss") or {}
        self.loss_start.labels(*lv).set((L.get("start") or {}).get("hop") or 0 if L.get("real") else 0)
        self.dest_loss.labels(*lv).set(L.get("dest_loss_pct", 0))
        key = (src, iface or "", t["ip"])
        for old in self._hop_keys.get(key, []):          # remove the series of the old route
            self.hop_lat.remove(*old)
            self.hop_loss.remove(*old)
        new = []
        for h in hops:
            if not h["ip"]:
                continue
            hv = (src, stype, iface or "", t["ip"], str(h["hop"]), h["ip"], h.get("country") or "", h.get("asn") or "")
            lat = h.get("median_ms") if h.get("median_ms") is not None else h.get("avg_ms")
            self.hop_lat.labels(*hv).set(lat if lat is not None else NAN)
            self.hop_loss.labels(*hv).set(h["loss_pct"])
            new.append(hv)
        self._hop_keys[key] = new

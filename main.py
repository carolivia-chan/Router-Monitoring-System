#!/usr/bin/env python3
"""NetMon main: from 1 measurement machine (source) -> many target servers, through N ipvlan sub-interfaces.
Several machines (or several ISPs on 1 machine, see UPLINKS) report to the same PostgreSQL / Prometheus / Grafana;
every measurement carries independent measurement source fields (see monitor/common.py):
  source_type  Local                          Globalping
  source_key   laptop/vnpt                    gp/JP/Tokyo
  source_asn   AS45899 (MaxMind, ISP)         AS2516 (network hosting the probe)
  display_name Laptop · VNPT · mon1           Tokyo, Japan

  python3 main.py --once        measure once, print the results to the screen, then exit
  python3 main.py               run the loop (used by netmon.service): probe every INTERVAL, traces in the background
  python3 main.py --test-alert  send 1 test Telegram message
  python3 main.py --once --tool traceroute          trace with traceroute instead of mtr
  python3 main.py --once --target 8.8.8.8 --iface mon1   measure only 1 server / 1 sub-interface
  python3 main.py --globalping  run 1 round from Globalping probes in many countries (GP_LOCATIONS), then exit
  python3 main.py --job rollup  run 1 automation job (rollup | retention | backup | freshness | report), see
                                monitor/jobs.py; the systemd timers netmon-*.timer run this command on schedule
"""
import argparse
import collections
import csv
import itertools
import json
import math
import os
import queue
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from monitor import alert, health, jobs                      # noqa: E402
from monitor.analyze import analyze, loss_analysis, pick_isp, score   # noqa: E402
from monitor.common import (display_name, gateway_of, iface_ip, isp_label, isp_name, list_subifs,   # noqa: E402
                            load_conf, load_env, machine_display, read_targets, source_display, source_label,
                            source_name, uplinks)
from monitor.exporter import Exporter                        # noqa: E402
from monitor.globalping import Globalping                    # noqa: E402
from monitor.probe import error_result, probe_many           # noqa: E402
from monitor.report import format_block, set_thresholds, use_color   # noqa: E402
from monitor.storage import Storage                          # noqa: E402
from monitor.trace import Geo, trace                         # noqa: E402

CSV_HEADER = ["ts", "source", "iface", "target_name", "target_ip", "avg_ms", "median_ms", "jitter_ms", "loss_pct",
              "status", "lost_seq", "source_asn"]


def open_csv(path):
    """Open a CSV file for appending; an old file with a different header (earlier version) is renamed .old-<time>."""
    if os.path.exists(path):
        with open(path) as f:
            if f.readline().strip() != ",".join(CSV_HEADER):
                os.rename(path, path + f".old-{int(time.time())}")
    new_file = not os.path.exists(path)
    f = open(path, "a", newline="")
    w = csv.writer(f)
    if new_file:
        w.writerow(CSV_HEADER)
    return f, w


class Monitor:
    def __init__(self, conf):
        self.c = conf
        self.cooldown = int(conf["ALERT_COOLDOWN"])
        self.out = conf["RESULTS_DIR"]
        os.makedirs(self.out, exist_ok=True)
        self.geo = Geo(conf["GEOIP_CITY"], conf["GEOIP_ASN"])
        port = int(conf["EXPORTER_PORT"])
        self.exporter = Exporter(port) if port else None
        dsn = os.environ.get("NETMON_PG_DSN")
        self.db = Storage(dsn) if dsn else None
        self.tool = conf["TRACE_TOOL"]
        self.only_target = self.only_iface = None
        self.isp = {}                            # monN -> {"asn", "org", "label", "name"}: ISP (MaxMind)
        self.gw, self.gw_probe = {}, {}          # monN -> gateway IP / gateway fping result of this round
        self.loss_where = {}                     # (monN|server) -> packet loss location of the latest trace
        self._probe_err = {}                     # monN -> latest fping error reason (logged only when it changes)
        # TRACES run in the background (see schedule_traces / trace_worker): the probe loop never waits for mtr /
        # traceroute. TRACE_WORKERS threads = at most that many mtr at once (too many -> routers rate-limit ICMP ->
        # '*' hops and fake probe loss, because traces and probes share 1 public IP)
        self.trace_db = Storage(dsn) if dsn else None   # separate DB connection for the trace threads
        self.trace_lock = threading.Lock()       # trace result handling: file / DB / Prometheus / ISP / route changes
        self.q_lock = threading.Lock()
        self.trace_q = queue.PriorityQueue()     # (priority, order, monN, monN IP, server): loss first, periodic later
        self.trace_seq = itertools.count()
        self.trace_pending = set()               # (monN, server IP) waiting / running: never queued twice
        self.trace_at = {}                       # (monN, server IP) -> time the latest trace finished
        self.last_trace = {}                     # (monN, server IP) -> latest (hops, analysis, loss), for the report
        self.last_probe = {}                     # (monN, server IP) -> latest probe, for the trace loss analysis
        self.win = {}                            # (monN, server IP) -> last 5 rounds (time, status): Connection Status
        self.isp_traces = {}                     # monN -> recent traces, ISP majority vote
        self.isp_tried = {}                      # monN -> last attempt to identify the ISP
        self.sweep_no, self.next_sweep = 0, 0.0  # periodic trace sweep (monN rotation)
        self.color = False                       # colors only when printing to a terminal (--once)
        set_thresholds(conf["LATENCY_WARN"], conf["JITTER_WARN"])
        # baselines + cooldowns are kept between runs (restart, --once)
        alert.load_state(os.path.join(conf["STATE_DIR"], "state.json"), conf["BASELINE_SAMPLES"])
        self.base_min = int(conf["BASELINE_MIN"])
        self.hold = int(conf["ALERT_HOLD"])      # a problem must last >= ALERT_HOLD seconds before Telegram is sent
        # Globalping: measure from probes in many countries; runs in its own thread, so it uses its own DB connection
        self.gp = Globalping(conf, self.geo, os.environ.get("GP_TOKEN")) if conf["GP_ENABLE"] == "1" else None
        self.gp_db = Storage(dsn) if dsn and self.gp else None
        if self.db:
            alert.listeners.append(self.record_alert)   # every Telegram message -> 1 alert_event row

    def src(self, iface):
        """Source KEY of measurements through monN: 'laptop/vnpt' (SOURCE_NAME/ISP), stored in PostgreSQL/Prometheus."""
        return source_label(self.c, self.isp.get(iface, {}).get("label"))

    def src_display(self, iface):
        """Display name of the measurement source (machine + ISP): 'Laptop · VNPT'; unknown ISP -> 'Laptop'."""
        return source_display(self.c, self.isp.get(iface, {}).get("name"))

    def tag(self, iface):
        """Full display name of monN, used in Telegram and reports: 'Laptop · VNPT · mon1'."""
        return display_name(self.src(iface), self.src_display(iface), iface)

    def src_asn(self, iface):
        """source_asn of monN: ISP ASN identified with MaxMind (AS45899); unknown -> None."""
        return self.isp.get(iface, {}).get("asn")

    def vote_isp(self, iface, hops, target_ip):
        """Identify the ISP of monN: ASN + organization name (MaxMind GeoLite2-ASN) of the first public hop, by majority
        vote over the last 10 traces of that monN (analyze.pick_isp). No public hop at all (network down...) -> keep the old label."""
        tr = self.isp_traces.setdefault(iface, collections.deque(maxlen=10))
        tr.append((hops, target_ip))
        found = pick_isp(list(tr))
        if not found:
            return
        asn, org = found
        if self.isp.get(iface, {}).get("asn") != asn:
            self.isp[iface] = {"asn": asn, "org": org, "label": isp_label(asn, org), "name": isp_name(asn, org)}
            print(f"[isp] {iface}: {asn} {org or ''} (MaxMind) -> '{self.tag(iface)}', source '{self.src(iface)}'",
                  file=sys.stderr)

    # ---------- measurement ----------
    def active_ifaces(self):
        res = []
        for name in list_subifs(self.c["NAME_PREFIX"]):
            ip = iface_ip(name)
            if ip and (not self.only_iface or name == self.only_iface):
                res.append((name, ip))
        return res

    def targets(self):
        ts = read_targets(self.c["TARGETS"])
        if self.only_target:
            ts = [t for t in ts if self.only_target in (t["ip"], t["name"])] or \
                 [{"name": self.only_target, "ip": self.only_target, "country": "?"}]
        return ts

    def pacing(self, n_ifaces, n_per_iface):
        """fping packet pacing so that the TOTAL ICMP packets per second of all monN stays within PROBE_PPS.

        All monN reach the Internet through 1 public IP (NAT router). By default fping sends packets 10 ms apart:
        5 monN x 25 targets = ~125 packets packed into 0.25 s every second -> the router / ISP rate-limits ICMP and drops
        packets -> FAKE loss, worst for the servers at the end of the list (sent last) and the monN started last.
        Returns (period_ms, interval_ms): each target gets 1 packet / period_ms (stretched above PROBE_PPS), and the
        packets of 1 monN are spaced evenly by interval_ms within each period."""
        period, pps = int(self.c["PING_PERIOD"]), float(self.c["PROBE_PPS"])
        if pps > 0:
            period = max(period, math.ceil(n_ifaces * n_per_iface * 1000 / pps / 100) * 100)   # rounded up to 100 ms
        interval = max(1, period // max(n_per_iface, 1))
        if (period, interval) != getattr(self, "_pace", None):
            self._pace = (period, interval)
            limit = f"at most {pps:g} packets/s" if pps > 0 else "no packets/s limit"
            print(f"[probe] {n_ifaces} monN x {n_per_iface} targets, {limit} -> 1 packet / {period} ms per target, "
                  f"{interval} ms between consecutive packets, ~{round(int(self.c['PING_COUNT']) * period / 1000)} s per probe round",
                  file=sys.stderr)
        return period, interval

    def probe_iface(self, ifc, targets, period=None, interval=None, delay_ms=0):
        """PROBE: 1 fping command for the gateway + ALL servers through 1 sub-interface. Returns {server ip: result};
        the gateway result (to tell Wi-Fi / local network from ISP problems) is kept separately in self.gw_probe.
        The gateway comes first in the list: its packets do not queue behind the server packets (fake jitter).
        delay_ms: phase offset between monN so the packets of mon1..mon5 interleave instead of going out together."""
        iface, ip = ifc
        ips = [t["ip"] for t in targets]
        gw = self.gw.get(iface)
        extra = [gw] if gw and gw not in ips else []
        if delay_ms:
            time.sleep(delay_ms / 1000)
        try:
            res = probe_many(iface, extra + ips, int(self.c["PING_COUNT"]), src_ip=ip,
                             period_ms=period or int(self.c["PING_PERIOD"]), timeout_ms=int(self.c["PING_TIMEOUT"]),
                             interval_ms=interval)
        except Exception as e:                   # no fping, timeout...: not measured, NOT DOWN
            res = {x: error_result(int(self.c["PING_COUNT"]), f"{type(e).__name__}: {e}") for x in ips + extra}
        self.gw_probe[iface] = res.get(gw) if gw else None
        if extra:
            res.pop(gw, None)
        return res

    # ---------- trace (background) ----------
    def run_trace(self, iface, src_ip, t):
        """TRACE 1 (monN, server) pair with mtr / traceroute, then process the result. Returns the hop list (None on error)."""
        try:
            hops = trace(iface, src_ip, t["ip"], self.geo, int(self.c["TRACE_CYCLES"]), self.tool)
        except Exception as e:
            print(f"[trace] {iface} -> {t['ip']} error: {e}", file=sys.stderr)
            return None
        if hops:
            self.record_trace(iface, t, hops)
        return hops

    def record_trace(self, iface, t, hops):
        """Analyze 1 trace, then write trace.jsonl / PostgreSQL / Prometheus, update the ISP, the loss location and the
        route change tracking. Several trace threads run at once: the writing part holds trace_lock (1 writer at a time)."""
        key, ts = (iface, t["ip"]), datetime.now(timezone.utc)
        a = analyze(hops, t["ip"])
        a["loss"] = L = loss_analysis(hops, t["ip"], self.last_probe.get(key), float(self.c["LOSS_HOP_WARN"]))
        with self.trace_lock:
            self.vote_isp(iface, hops, t["ip"])
            src, sd, disp, asn = self.src(iface), self.src_display(iface), self.tag(iface), self.src_asn(iface)
            with open(os.path.join(self.out, "trace.jsonl"), "a") as fj:
                fj.write(json.dumps({"ts": ts.isoformat(timespec="seconds"), "source_type": "Local",
                                     "source": src, "source_asn": asn, "display": disp, "iface": iface,
                                     "target": t["ip"], "hops": hops, "analysis": a}, ensure_ascii=False) + "\n")
            if self.trace_db:
                self.trace_db.save_trace(ts, src, iface, t, hops, a, sd, asn)
            if self.exporter:
                self.exporter.trace(src, iface, t, hops, a, disp, "Local", asn)
            self.last_trace[key], self.trace_at[key] = (hops, a, L), time.time()
            real = L["real"] and L["where"] != "unknown"
            self.loss_where[f"{iface}|{t['ip']}"] = L["where_text"] if real else None
            self.check_route(iface, t, a)

    def enqueue_trace(self, iface, src_ip, t, urgent=False):
        key = (iface, t["ip"])
        with self.q_lock:
            if key in self.trace_pending:
                return False
            self.trace_pending.add(key)
        self.trace_q.put((0 if urgent else 1, next(self.trace_seq), iface, src_ip, t))
        return True

    def trace_worker(self):
        """1 background trace thread: take jobs from the queue (loss traces first, periodic traces later), run 1 mtr."""
        while True:
            _pri, _n, iface, src_ip, t = self.trace_q.get()
            try:
                self.run_trace(iface, src_ip, t)
            except Exception as e:                       # a result-processing error must not kill the thread
                print(f"[trace] {iface} -> {t['ip']} result processing error: {e}", file=sys.stderr)
            finally:
                with self.q_lock:
                    self.trace_pending.discard((iface, t["ip"]))

    def schedule_traces(self, ifaces, targets, probes, checks=None):
        """Queue traces to run in the background; the probe loop does NOT wait for them.
          - Periodically every TRACE_EVERY x INTERVAL seconds: every server. TRACE_ROTATE=1: in each sweep every server
            is traced through only 1 monN, rotating mon1 -> mon2 -> ... (all monN share the Wi-Fi, ISP and public IP, so
            the route is the same): 24 traces per sweep instead of 5 x 24 = 120; each (monN, server) pair is still traced
            every 5 sweeps.
          - Trace immediately (higher priority) a pair that just had a problem, at most once per sweep per pair: probe
            loss >= LOSS_HOP_WARN (TRACE_ON_LOSS=1) or Network Health not HEALTHY (TRACE_ON_ANOMALY=1, checks = assess
            results). That trace is the evidence for the incident analysis in the alert (health.incident_lines)."""
        c, now = self.c, time.time()
        level = {(i, t["ip"]): h["level"] for i, t, _p, h in (checks or [])}
        period = int(c["TRACE_EVERY"]) * int(c["INTERVAL"])
        if now >= self.next_sweep:
            left = self.trace_q.qsize()
            if left:
                print(f"[trace] {left} traces of the previous sweep have not run yet (traces slower than schedule, see TRACE_WORKERS)",
                      file=sys.stderr)
            self.next_sweep, self.sweep_no = now + period, self.sweep_no + 1
            for k, t in enumerate(targets):
                chosen = [ifaces[(self.sweep_no + k) % len(ifaces)]] if c["TRACE_ROTATE"] == "1" else ifaces
                for i, ip in chosen:
                    self.enqueue_trace(i, ip, t)
        for i, ip in ifaces:
            for t in targets:
                p = probes[(i, ip)][t["ip"]]
                lossy = c["TRACE_ON_LOSS"] == "1" and p["status"] != "ERROR" \
                    and p["loss_pct"] >= float(c["LOSS_HOP_WARN"])
                odd = c["TRACE_ON_ANOMALY"] == "1" and bool(level.get((i, t["ip"])))
                if (lossy or odd) and now - self.trace_at.get((i, t["ip"]), 0) >= period:
                    self.enqueue_trace(i, ip, t, urgent=True)

    def ensure_isp(self, ifaces, targets):
        """monN with an unknown ISP (just started / just added): trace 1 server NOW and wait for it before writing probes,
        so probes are not stored under a source key without the ISP ('laptop' instead of 'laptop/viettel')."""
        now, retry = time.time(), int(self.c["TRACE_EVERY"]) * int(self.c["INTERVAL"])
        todo = [(i, ip) for i, ip in ifaces if i not in self.isp and now - self.isp_tried.get(i, 0) >= retry]
        if not todo or not targets:
            return
        for i, _ip in todo:
            self.isp_tried[i] = now
        with ThreadPoolExecutor(max_workers=min(len(todo), int(self.c["TRACE_WORKERS"]))) as ex:
            list(ex.map(lambda f: self.run_trace(f[0], f[1], targets[0]), todo))

    # ---------- alerts ----------
    def record_alert(self, key, state, text, meta=None):
        """Record an alert message in alert_event. key: 'mon1|<IP>|health', 'mon1|<IP>|route', 'mon1|path',
        'mon1|probe-error', 'no-subif'.
        meta: status (DEGRADED / UNSTABLE / DOWN / PATH / HEALTHY) and severity (WARNING / CRITICAL)."""
        meta, parts = meta or {}, key.split("|")
        if len(parts) == 3:
            iface, ip, kind = parts
        elif len(parts) == 2:
            (iface, kind), ip = parts, None
        else:
            iface, ip, kind = None, None, key
        src, sd = (self.src(iface), self.src_display(iface)) if iface else (source_name(self.c), source_display(self.c))
        # messages sent from a trace thread (route change) go through the trace thread connection (holding trace_lock)
        db = self.db if threading.current_thread() is threading.main_thread() else (self.trace_db or self.db)
        db.save_alert(src, iface, ip, kind, state, text, sd, meta.get("status"), meta.get("severity"))

    # ---------- Network Health (xem monitor/health.py) ----------
    def _gap(self):
        """Missing data for longer than this (ALERT_GAP, plus the duration of the current round: the first round includes
        the ISP identification trace) counts as a gap: incident episodes and the Connection Status window start over."""
        return max(int(self.c["ALERT_GAP"]), 3 * int(self.c["INTERVAL"])) + getattr(self, "cycle_secs", 0)

    def _track(self, key, level, down_hold=None):
        c = self.c
        return alert.track(key, level, self.hold, int(c["DOWN_HOLD"]) if down_hold is None else down_hold,
                           int(c["CLEAR_SAMPLES"]), float(c["INSTABILITY_RATIO"]), self._gap())

    def window(self, iface, t, p, now=None):
        """Connection Status of a (monN, server) pair: add this round to the window of the last 5 rounds, then decide by
        majority (health.window_status: >= 3/5 UP -> UP). Counts actual PROBE ROUNDS, not Prometheus scrape samples
        (scrape every 15 s, probe every ~60 s: avg_over_time(netmon_up[5m]) averages ~20 samples, not 5 rounds).
        A gap longer than _gap() (NetMon stopped, monN switched off and on) restarts the window: results from before
        the gap do not represent the present."""
        now = time.time() if now is None else now
        key = (iface, t["ip"])
        w = self.win.get(key)
        if w is None or (w and now - w[-1][0] > self._gap()):
            w = self.win[key] = collections.deque(maxlen=health.STATUS_WINDOW)
        w.append((now, p["status"]))
        return health.window_status([s for _ts, s in w])

    def assess(self, iface, t, p):
        """State of 1 (monN, server) pair in this round, compared with that pair's own baseline.
        Distant servers (Cairo, Johannesburg 300-400 ms) are not considered bad just because their RTT is large."""
        k = f"{iface}|{t['ip']}"
        return health.assess(p, alert.baseline(k + "|lat", None, "min", self.base_min),
                             alert.baseline(k + "|jit", None, "median", self.base_min), self.c)

    def check(self, iface, t, p, a=None, suppress=False, peers=None):
        """Track the incident episode of 1 pair and send 1 COMBINED Telegram message (latency + jitter + loss) when the
        episode is confirmed (lasting >= ALERT_HOLD; DOWN >= DOWN_HOLD), escalates, is reminded after ALERT_COOLDOWN, or
        recovers. suppress=True: the measurement point has a shared-path incident (PATH ISSUE already sent) -> track
        only, no separate message. peers: names of other servers on the same monN also abnormal in this round."""
        a = a or self.assess(iface, t, p)
        k, c = f"{iface}|{t['ip']}", self.c
        confirmed, dur = self._track(k + "|health", a["level"])
        if a["level"] is not None:
            # baselines only learn from normal rounds; an incident lasting longer than BASELINE_RELEARN becomes the new level
            relearn = dur >= float(c["BASELINE_RELEARN"])
            if not a["flags"].get("lat") or relearn:
                alert.learn(k + "|lat", p.get("median_ms"))
            if not a["flags"].get("jit") or relearn:
                alert.learn(k + "|jit", p.get("jitter_ms"))
        if confirmed is None or suppress:
            return a
        status = health.STATUS[confirmed] if confirmed else a["status"]
        sev = health.severity(status, a, dur, c)
        act = alert.decide(k + "|health", confirmed, sev, self.cooldown)
        who, dest = self.tag(iface), f"{t['name']} {t['ip']} ({t['country']})"
        if act in ("alert", "remind"):
            tr = self.last_trace.get((iface, t["ip"]))
            incident = health.incident_lines((*tr, self.trace_at.get((iface, t["ip"]), time.time())) if tr else None,
                                             self.route_stable(k))
            text = health.alert_text(act, status, sev, who, dest, p, a, dur, c, self.loss_where.get(k), peers,
                                     incident)
            alert.notify(k + "|health", "alert", text, {"status": status, "severity": sev})
        elif act == "recover":
            worst, wsev, total = alert.recovered(k + "|health")
            text = health.recover_text(who, dest, p, f"{health.STATUS[worst]} · {wsev}", total)
            alert.notify(k + "|health", "recover", text, {"status": health.HEALTHY, "severity": wsev})
        return a

    def check_path(self, iface, items):
        """Many servers abnormal on 1 measurement point -> 1 PATH ISSUE message (with the gateway measurement) instead
        of N separate ones. Returns True once the shared-path incident is confirmed (the separate messages of this
        measurement point are held back)."""
        c, key = self.c, f"{iface}|path"
        pa = health.path_assess(items, c)
        confirmed, dur = self._track(key, 1 if pa["bad"] else 0, down_hold=self.hold)
        ratio = len(pa["affected"]) / max(pa["known"], 1)
        sev = health.CRITICAL if ratio >= 0.6 or dur >= float(c["ALERT_ESCALATE"]) else health.WARNING
        act = alert.decide(key, confirmed, sev, self.cooldown)
        who = self.tag(iface)
        if act in ("alert", "remind"):
            kind, desc = health.gateway_verdict(self.gw.get(iface), self.gw_probe.get(iface), c)
            alert.notify(key, "alert", health.path_text(act, sev, who, pa, kind, desc, dur),
                         {"status": "PATH", "severity": sev})
        elif act == "recover":
            _, wsev, total = alert.recovered(key)
            alert.notify(key, "recover", f"🟢 NetMon · PATH OK\nSource: {who}\n"
                                         f"Many servers are no longer abnormal at once, after {health.minutes(total)}",
                         {"status": health.HEALTHY, "severity": wsev})
        return bool(confirmed)

    def check_probe(self, iface, res):
        """fping failed on monN (every target ERROR): the targets count as UNKNOWN, not DOWN, but the operator still
        needs to know NetMon is not measuring -> log when the reason changes, Telegram if it lasts >= DOWN_HOLD."""
        broken = bool(res) and all(r["status"] == "ERROR" for r in res.values())
        why = next(iter(res.values())).get("error") if broken else None
        if why != self._probe_err.get(iface):
            self._probe_err[iface] = why
            print(f"[probe] {iface}: " + (f"fping failed, not measuring: {why}" if why else "fping is working again"),
                  file=sys.stderr)
        who = self.tag(iface)
        alert.evaluate(f"{iface}|probe-error", broken,
                       f"⚠️ NetMon · PROBE ERROR\nSource: {who}\nfping failed, cannot measure through {iface}: {why}\n"
                       f"The servers are NOT counted as DOWN; check the sub-interface / permissions / fping.",
                       f"🟢 NetMon · PROBE OK\nSource: {who}\nfping measures normally again through {iface}",
                       self.cooldown, int(self.c["DOWN_HOLD"]))

    @staticmethod
    def route_stable(key):
        """Usual route (stable for >= ALERT_HOLD) of 1 (monN, server) pair, kept in the alert state
        (alert.route_changed): {"sig", "asn", "cc", "hops"} or None if not known yet."""
        with alert._lock:
            r = alert._state["route"].get(key)
            return dict(r["stable"]) if r and r.get("stable") else None

    def check_route(self, iface, t, a):
        key = f"{iface}|{t['ip']}"
        info = {"sig": a["signature"], "asn": a["asn_path"], "cc": a["country_path"], "hops": a["hop_count"]}
        changed = alert.route_changed(key, info, self.hold)      # the new route must stay stable >= ALERT_HOLD
        if changed:
            old, new = changed
            stable = f" (stable for {round(self.hold / 60)} min)" if self.hold else ""
            alert.event(key + "|route",
                        f"🔀 {self.tag(iface)} -> {t['name']} {t['ip']}: route changed{stable}\n"
                        f"Before: {' > '.join(old['asn'])} | {' > '.join(old['cc'])} ({old['hops']} hops)\n"
                        f"After:  {' > '.join(new['asn'])} | {' > '.join(new['cc'])} ({new['hops']} hops)",
                        self.cooldown)

    # ---------- 1 measurement round ----------
    def cycle(self, sync=False):
        """1 round: PROBE every (monN, server) pair -> store, assess Network Health, alert. Traces run in the background
        (schedule_traces); the report uses the latest trace of each pair.
        sync=True (--once): trace every pair within this round before printing the report, as before."""
        ts = datetime.now(timezone.utc)
        ifaces = self.active_ifaces()
        me = source_display(self.c)
        no_if = f"No active {self.c['NAME_PREFIX']}N sub-interface (parent {self.c['PARENT']})"
        alert.evaluate("no-subif", not ifaces, f"🔴 {me}: {no_if}", f"🟢 {me}: sub-interfaces are active again",
                       self.cooldown, self.hold)
        if not ifaces:
            return f"[warn] {no_if}\n"

        targets = self.targets()
        self.gw = {i: gateway_of(ip, self.c) for i, ip in ifaces}     # gateway of each monN (measured by the same fping)
        self.gw_probe = {}
        if not sync:
            self.ensure_isp(ifaces, targets)
        # 1) PROBE: 1 fping command per monN for the whole server list; the monN run in parallel, phase-shifted,
        #    total packets/s within PROBE_PPS (see pacing)
        n = len(ifaces)
        period, gap = self.pacing(n, len(targets) + (1 if any(self.gw.values()) else 0))
        with ThreadPoolExecutor(max_workers=n) as ex:
            probes = dict(zip(ifaces, ex.map(lambda k: self.probe_iface(ifaces[k], targets, period, gap, k * gap / n),
                                             range(n))))
        for i, ip in ifaces:
            self.check_probe(i, probes[(i, ip)])
            for t in targets:
                self.last_probe[(i, t["ip"])] = probes[(i, ip)][t["ip"]]
        # 2) TRACE: --once traces every pair right away (at most TRACE_WORKERS at once); the service queues them in
        #    the background (after the assessment below, so pairs that just became abnormal are traced too)
        if sync:
            pairs = [(i, ip, t) for i, ip in ifaces for t in targets]
            with ThreadPoolExecutor(max_workers=min(len(pairs), int(self.c["TRACE_WORKERS"]))) as ex:
                list(ex.map(lambda j: self.run_trace(*j), pairs))

        items, best, checks = [], {}, []
        fc, w = open_csv(os.path.join(self.out, "probe.csv"))
        with fc:
            for iface, _ip in ifaces:
                src, sd, disp, asn = self.src(iface), self.src_display(iface), self.tag(iface), self.src_asn(iface)
                for t in targets:
                    p = probes[(iface, _ip)][t["ip"]]
                    hops, a, L = self.last_trace.get((iface, t["ip"]), (None, None, None))
                    sc = score(p, a["hop_count"] if a else 0)
                    w.writerow([ts.isoformat(timespec="seconds"), src, iface, t["name"], t["ip"],
                                p["avg_ms"], p.get("median_ms"), p["jitter_ms"], p["loss_pct"], p["status"],
                                " ".join(map(str, p.get("lost_seq") or [])), asn or ""])
                    h = self.assess(iface, t, p)              # Network Health of this round (nothing sent yet)
                    ws = self.window(iface, t, p)             # Connection Status: majority over the last 5 rounds
                    checks.append((iface, t, p, h))
                    if self.db:
                        self.db.save_probe(ts, src, iface, t, p, sd, asn, health=h["status"],
                                           base_median=h["base_lat"], base_jitter=h["base_jit"])
                    if self.exporter:
                        self.exporter.probe(src, iface, t, p, sc, disp, "Local", asn, h, ws)
                    items.append((disp, t, p, hops, a, L))
                    if sc != float("inf") and (t["ip"] not in best or sc < best[t["ip"]][0]):
                        best[t["ip"]] = (sc, disp, t["name"])
        if self.exporter:                                     # stopped monN: do not keep showing an old state
            self.exporter.prune(self._gap())
        if not sync:
            self.schedule_traces(ifaces, targets, probes, checks)

        # 3) ALERTS: first per measurement point (many servers bad at once -> 1 PATH ISSUE message), then per pair
        self.cycle_secs = (datetime.now(timezone.utc) - ts).total_seconds()
        path_active = {}
        for i, _ip in ifaces:
            pairs = [(t, h) for iface, t, _p, h in checks if iface == i]
            path_active[i] = self.check_path(i, pairs)
            if self.exporter:
                self.exporter.gateway(self.src(i), i, self.gw.get(i), self.gw_probe.get(i))
        for iface, t, p, h in checks:
            peers = [f"{t2['name']} ({h2['status']})" for i2, t2, _p, h2 in checks
                     if i2 == iface and t2["ip"] != t["ip"] and h2["level"]]
            self.check(iface, t, p, h, suppress=path_active.get(iface, False), peers=peers)

        footer = ["", "=== best source per target (score = median latency + 10*loss% + 2*hops) ==="]
        footer += [f"{name} ({ip}): {iface} (score {sc})" for ip, (sc, iface, name) in best.items()]

        def render(color):
            blocks = [format_block(*it, color=color) for it in items]
            return "\n\n".join(blocks) + "\n" + "\n".join(footer) + "\n"

        alert.save_state()                               # save baselines + cooldowns
        with open(os.path.join(self.out, "latest.txt"), "w") as f:
            f.write(render(False))                       # file: plain text, no color codes
        return render(self.color)

    # ---------- Globalping: measurement sources in many countries ----------
    def gp_cycle(self):
        """1 Globalping round: write CSV/DB/Prometheus like monN, return the report.
        Globalping probes have no sub-interface: iface = None, the ASN of the probe network goes into source_asn."""
        ts = datetime.now(timezone.utc)
        targets = self.targets() if self.only_target else self.gp.pick(self.targets())
        items = []
        fc, w = open_csv(os.path.join(self.out, "globalping.csv"))
        with fc, open(os.path.join(self.out, "globalping.jsonl"), "a") as fj:
            for src, asn, disp, t, p, hops in self.gp.run(targets):
                a = analyze(hops, t["ip"]) if hops else None
                L = loss_analysis(hops, t["ip"], p, float(self.c["LOSS_HOP_WARN"])) if hops else None
                if a:
                    a["loss"] = L
                sc = score(p, a["hop_count"] if a else 0)
                w.writerow([ts.isoformat(timespec="seconds"), src, "", t["name"], t["ip"],
                            p["avg_ms"], p.get("median_ms"), p["jitter_ms"], p["loss_pct"], p["status"], "", asn or ""])
                if self.gp_db:
                    self.gp_db.save_probe(ts, src, None, t, p, disp, asn, disp)
                if self.exporter:
                    self.exporter.probe(src, None, t, p, sc, disp, "Globalping", asn)
                if hops:
                    fj.write(json.dumps({"ts": ts.isoformat(timespec="seconds"), "source_type": "Globalping",
                                         "source": src, "source_asn": asn, "display": disp, "source_location": disp,
                                         "target": t["ip"], "hops": hops, "analysis": a}, ensure_ascii=False) + "\n")
                    if self.gp_db:
                        self.gp_db.save_trace(ts, src, None, t, hops, a, disp, asn, disp)
                    if self.exporter:
                        self.exporter.trace(src, None, t, hops, a, disp, "Globalping", asn)
                items.append(((disp, f"{src} · {asn or '?'}"), t, p, hops, a, L))

        def render(color):
            if not items:
                return "[gp] no results from Globalping in this round\n"
            blocks = []
            for (disp, sub), *rest in items:             # heading = display_name, line below = source_key · source_asn
                head, _, body = format_block(disp, *rest, color=color).partition("\n")
                blocks.append(f"{head}\n  {sub}\n{body}")
            return "=== Source Type: Globalping ===\n\n" + "\n\n".join(blocks) + "\n"

        with open(os.path.join(self.out, "latest_globalping.txt"), "w") as f:
            f.write(render(False))
        return render(self.color)

    def gp_loop(self):
        n = len(self.gp.pick(self.targets()))
        print(f"[gp] {len(self.gp.locations)} locations x {n} servers = {len(self.gp.locations) * n} tests/round, "
              f"1 round every {self.gp.interval(n) // 60} min (limit {self.gp.limit} tests/hour)", file=sys.stderr)
        while True:
            started = time.time()
            try:
                self.gp_cycle()
            except Exception as e:
                print(f"[gp] error: {e}", file=sys.stderr)
            n = len(self.gp.pick(self.targets()))
            time.sleep(max(60, self.gp.interval(n) - (time.time() - started)))

    def loop(self):
        if self.exporter:
            self.exporter.start()
        for k in range(int(self.c["TRACE_WORKERS"])):            # background trace threads
            threading.Thread(target=self.trace_worker, name=f"trace-{k + 1}", daemon=True).start()
        if self.gp:
            threading.Thread(target=self.gp_loop, daemon=True).start()
        last_purge, last_rollup = 0.0, 0.0
        while True:
            started = time.time()
            self.cycle()
            # hourly aggregation / old-data cleanup: run by the systemd timers (netmon-rollup / netmon-retention,
            # monitor/jobs.py); done here only when the timer is not active, so the same job never runs in 2 places
            if self.db and started - last_rollup > 3600:
                if not timer_active("netmon-rollup.timer"):
                    self.db.rollup()
                last_rollup = started
            if self.db and started - last_purge > 86400:
                if not timer_active("netmon-retention.timer"):
                    self.db.purge(int(self.c["PG_RETENTION_DAYS"]), int(self.c.get("PG_LONG_RETENTION_DAYS", 365)))
                last_purge = started
            time.sleep(max(1, int(self.c["INTERVAL"]) - (time.time() - started)))


def timer_active(name):
    """Is the systemd timer `name` active? (no systemd -> False)"""
    try:
        return subprocess.run(["systemctl", "is-active", "--quiet", name], timeout=5).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--once", action="store_true", help="measure once (with traces), print to the screen, then exit")
    ap.add_argument("--test-alert", action="store_true", help="send a test Telegram message")
    ap.add_argument("--conf", help="path of netmon.conf")
    ap.add_argument("--tool", choices=["mtr", "traceroute"], help="route tracing tool (overrides TRACE_TOOL)")
    ap.add_argument("--target", help="measure only 1 server (IP or name in targets.csv)")
    ap.add_argument("--iface", help="measure only through 1 sub-interface, e.g. mon1")
    ap.add_argument("--color", choices=["auto", "always", "never"], default="auto",
                    help="color the output (auto = only when printing to a terminal)")
    ap.add_argument("--globalping", action="store_true",
                    help="run 1 round from Globalping probes in many countries (GP_LOCATIONS), then exit")
    ap.add_argument("--job", choices=jobs.JOBS, help="run 1 automation job, then exit (called by the systemd timers)")
    args = ap.parse_args()

    load_env()                       # a manual sudo run gets TELEGRAM_* and NETMON_PG_DSN like the service
    conf = load_conf(args.conf)
    uplinks(conf)                    # invalid UPLINKS -> error right at startup
    if args.job:
        sys.exit(jobs.run(args.job, conf))
    if args.test_alert:
        sys.exit(0 if alert.telegram(f"✅ NetMon ({machine_display(source_name(conf))}): test message") else 1)
    if args.tool:
        conf["TRACE_TOOL"] = args.tool
    mon = Monitor(conf)
    mon.only_target, mon.only_iface = args.target, args.iface
    mon.color = use_color(args.color)
    if args.globalping:
        mon.gp = mon.gp or Globalping(conf, mon.geo, os.environ.get("GP_TOKEN"))
        dsn = os.environ.get("NETMON_PG_DSN")
        mon.gp_db = mon.gp_db or (Storage(dsn) if dsn else None)
        print(mon.gp_cycle())
    elif args.once:
        print(mon.cycle(sync=True))
    else:
        mon.loop()


if __name__ == "__main__":
    main()

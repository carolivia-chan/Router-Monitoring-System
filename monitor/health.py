"""NETWORK HEALTH: classify the connection state of 1 (measurement point, server) pair after each probe round.

There is no single fixed threshold for every server: 300-400 ms is normal for Cairo / Johannesburg. What matters is
the deviation FROM THE ROUTE'S OWN NORMAL LEVEL (baseline):

    high_latency = median > min(LATENCY_WARN, baseline + max(LATENCY_RISE_MS, LATENCY_RISE_PCT% baseline))
    high_jitter  = jitter > max(JITTER_WARN, JITTER_FACTOR x baseline jitter)
    packet_loss  = loss   > LOSS_UNSTABLE

    HEALTHY   no abnormal metric
    DEGRADED  exactly 1 abnormal metric
    UNSTABLE  2 or more abnormal metrics (no need to pass through DEGRADED first)
    DOWN      the target answered no packet
    UNKNOWN   measurement tool error / missing data: counted neither as good nor as bad

Severity does not depend only on the number of abnormal metrics: 1 metric far beyond its threshold (twice the
allowed margin, loss >= LOSS_WARN) or lasting >= ALERT_ESCALATE is CRITICAL too.

This module only computes (it sends and stores nothing) so it can be tested; duration tracking, debouncing and
Telegram sending live in alert.track / alert.decide, wired together in main.py.

CONNECTION STATUS (window_status): the UP / DOWN state shown in Grafana is not taken from 1 probe round but from a
MAJORITY over the last 5 rounds of each pair: >= 3 UP rounds -> UP, >= 3 DOWN rounds -> DOWN, otherwise UNKNOWN. A
single round with total loss does not flip the dashboard UP -> DOWN -> UP. Separate from Network Health (quality)
above: a route that is UP in 3 of 5 rounds is still UP, but its availability is only 60%.

AUTOMATED INCIDENT ANALYSIS (incident_lines): as soon as a route becomes abnormal NetMon traces it
(main.schedule_traces); when the alert is sent, that trace is compared with the route's usual path (route change?)
and the hop where real loss starts is reported (hops that only rate-limit ICMP replies are ignored). This is evidence
to support investigation, not a conclusion about the cause.
"""
import time

HEALTHY, DEGRADED, UNSTABLE, DOWN, UNKNOWN = "HEALTHY", "DEGRADED", "UNSTABLE", "DOWN", "UNKNOWN"
LEVEL = {HEALTHY: 0, DEGRADED: 1, UNSTABLE: 2, DOWN: 3}       # UNKNOWN has no level: that round is skipped
STATUS = {v: k for k, v in LEVEL.items()}
WARNING, CRITICAL = "WARNING", "CRITICAL"
ICON = {DEGRADED: "🟡", UNSTABLE: "🟠", DOWN: "🔴", HEALTHY: "🟢"}
METRIC = {"lat": "latency", "jit": "jitter", "loss": "packet loss"}
# Connection Status: number of most recent probe rounds considered. Fixed (not in netmon.conf) because it is the
# DEFINITION of the UP / DOWN state: the metric names (netmon_status_5probe...) and Grafana panel texts say "5 rounds"
STATUS_WINDOW = 5


def assess(p, base_lat, base_jit, c):
    """p: probe result (median_ms, jitter_ms, loss_pct, status); base_lat / base_jit: baselines of the route
    (None = not enough data yet, then only the absolute thresholds apply). c: configuration. Returns a dict:
      status, level, flags {lat, jit, loss}, severe {lat, jit, loss}, lat_limit, jit_limit, loss_limit."""
    out = {"status": UNKNOWN, "level": None, "flags": {}, "severe": {},
           "lat_limit": None, "jit_limit": None, "loss_limit": float(c["LOSS_UNSTABLE"]),
           "base_lat": base_lat, "base_jit": base_jit}
    st = p.get("status")
    if st == "DOWN":
        out.update(status=DOWN, level=LEVEL[DOWN])
        return out
    if st != "UP" or p.get("median_ms") is None:
        return out                                    # ERROR / missing data -> UNKNOWN

    med, jit, loss = p["median_ms"], p["jitter_ms"], p["loss_pct"]
    lat_warn = float(c["LATENCY_WARN"])
    if base_lat is not None:
        rise = max(float(c["LATENCY_RISE_MS"]), base_lat * float(c["LATENCY_RISE_PCT"]) / 100)
        lat_limit = min(lat_warn, base_lat + rise)
        lat_severe = med > base_lat + 2 * rise or med > 1.5 * lat_warn
    else:
        lat_limit, lat_severe = lat_warn, med > 1.5 * lat_warn
    jit_limit = float(c["JITTER_WARN"])
    if base_jit is not None:
        jit_limit = max(jit_limit, float(c["JITTER_FACTOR"]) * base_jit)

    flags = {"lat": med > lat_limit, "jit": jit > jit_limit, "loss": loss > out["loss_limit"]}
    severe = {"lat": flags["lat"] and lat_severe,
              "jit": flags["jit"] and jit > 2 * jit_limit,
              "loss": loss >= float(c["LOSS_WARN"])}
    n = sum(flags.values())
    status = UNSTABLE if n >= 2 else DEGRADED if n == 1 else HEALTHY
    out.update(status=status, level=LEVEL[status], flags=flags, severe=severe,
               lat_limit=round(lat_limit, 1), jit_limit=round(jit_limit, 1))
    return out


def window_status(results, size=STATUS_WINDOW):
    """Connection Status of 1 (measurement point, server) pair by majority over the last `size` probe rounds.
    results: status of each round ('UP' / 'DOWN' / 'ERROR'), oldest first; only the last `size` rounds count.
      UP       >= size // 2 + 1 UP rounds     (5 rounds: >= 3 UP; 3 UP - 2 DOWN is still UP)
      DOWN     >= size // 2 + 1 DOWN rounds   (5 rounds: >= 3 DOWN)
      UNKNOWN  no majority yet: just started (only 1-2 rounds, 1 UP round is not enough to conclude) or ERROR rounds
               take some of the slots (e.g. 2 UP - 2 DOWN - 1 ERROR)
    An ERROR round (fping failed) is neither UP nor DOWN: it is a failure of the measurement tool, not of the target,
    so it is not counted in availability (same as the probe_hourly rollup). With 5 valid rounds the result equals the
    availability >= 50% rule.
    Returns a dict: status, level (1 UP / 0 DOWN / -1 UNKNOWN), up, down, valid (= up + down),
    availability = up / valid (0..1; None if there is no valid round yet)."""
    last = list(results)[-size:]
    up, down = last.count("UP"), last.count("DOWN")
    need = size // 2 + 1
    status = "UP" if up >= need else DOWN if down >= need else UNKNOWN
    valid = up + down
    return {"status": status, "level": {"UP": 1, DOWN: 0}.get(status, -1), "up": up, "down": down,
            "valid": valid, "availability": up / valid if valid else None}


def severity(status, a, duration, c):
    """CRITICAL if UNSTABLE / DOWN, a metric far beyond its threshold, or lasting >= ALERT_ESCALATE seconds."""
    if status in (UNSTABLE, DOWN) or any((a or {}).get("severe", {}).values()) \
            or duration >= float(c["ALERT_ESCALATE"]):
        return CRITICAL
    return WARNING


def minutes(sec):
    return f"{round(sec / 60)} min"


def _metric_lines(p, a):
    """Metric lines: current value, normal level, threshold; '⚠' marks an abnormal metric."""
    if a["status"] == DOWN:
        return [f"• Packet loss: {p.get('loss_pct', 100):.0f}% (the target answered no packet)"]
    f, out = a["flags"], []
    base = f"normal ~{a['base_lat']:.0f} ms, " if a.get("base_lat") is not None else ""
    out.append(f"• Median latency: {p['median_ms']} ms{' ⚠' if f.get('lat') else ''} "
               f"({base}threshold {a['lat_limit']:.0f} ms)")
    base = f"normal ~{a['base_jit']:.0f} ms, " if a.get("base_jit") is not None else ""
    out.append(f"• Jitter: {p['jitter_ms']} ms{' ⚠' if f.get('jit') else ''} ({base}threshold {a['jit_limit']:.0f} ms)")
    out.append(f"• Packet loss: {p['loss_pct']:.0f}%{' ⚠' if f.get('loss') else ''} (threshold {a['loss_limit']:.0f}%)")
    return out


def assessment(status, a, duration, c):
    """Assessment sentence at the end of an alert."""
    if status == DOWN:
        return "The target did not answer ICMP during the whole confirmation period."
    bad = [METRIC[k] for k in ("lat", "jit", "loss") if a["flags"].get(k)]
    if status == UNSTABLE:
        return f"{' + '.join(bad).capitalize()} abnormal together for a sustained period -> unstable connection."
    why = []
    if any(a["severe"].values()):
        why.append("far beyond the threshold")
    if duration >= float(c["ALERT_ESCALATE"]):
        why.append(f"lasting more than {minutes(float(c['ALERT_ESCALATE']))}")
    what = bad[0] if bad else "one metric"
    return f"Only {what} is abnormal" + (f", but {' and '.join(why)}." if why else " -> degraded connection.")


def incident_lines(trace, stable, now=None):
    """Automated incident analysis from the latest trace of the route.
    trace : (hops, analysis, loss_analysis, time the trace finished) or None (not traced yet)
    stable: the usual route of this route (Monitor.route_stable in main.py) or None (not known yet)
    Returns the lines added to the alert."""
    if not trace:
        return ["• Trace: not available yet (waiting for the background trace)"]
    _hops, a, L, at = trace
    now = time.time() if now is None else now
    out = [f"• Trace {minutes(max(now - at, 0))} ago: {a['hop_count']} hops, "
           f"{'destination reached' if a['reached'] else 'destination NOT reached'}"]
    path = " > ".join(a["asn_path"]) or "?"
    if stable and stable.get("sig") and stable["sig"] != a["signature"]:
        out.append(f"• Route DIFFERS from the usual one: {path} (usual: {' > '.join(stable.get('asn') or []) or '?'})")
    elif stable:
        out.append(f"• Same route as usual: {path}")
    if L and L.get("real") and L.get("where") != "unknown":
        out.append(f"• Packet loss starts at: {L['where_text']}")
    elif L and L.get("fake_hops"):
        out.append(f"• Hop {', '.join(map(str, L['fake_hops']))} shows loss but the later hops still reply: "
                   f"the router rate-limits ICMP, not packet loss")
    return out


def alert_text(action, status, sev, who, dest, p, a, duration, c, loss_where=None, peers=None, incident=None):
    """Telegram message combining every metric of 1 route (instead of separate latency / jitter / loss messages).
    action: alert | remind. peers: OTHER servers on the same measurement point that are also abnormal in this round
    (e.g. Cairo and Johannesburg at once: hints at a shared path segment, not enough to conclude).
    incident: incident analysis lines (incident_lines); without them only the loss location (loss_where) is shown."""
    head = f"{ICON.get(status, '⚠️')} NetMon · {status} · {sev}" + (" (reminder)" if action == "remind" else "")
    lines = [head, f"Source: {who}", f"Destination: {dest}"] + _metric_lines(p, a)
    if incident:
        lines += incident
    elif loss_where and status != DOWN:
        lines.append(f"• Packet loss location (latest trace): {loss_where}")
    if peers:
        more = f" (+{len(peers) - 5})" if len(peers) > 5 else ""
        lines.append(f"• Also abnormal on this measurement point: {', '.join(peers[:5])}{more}")
    note = " Several servers abnormal at once -> possibly a shared path segment." if peers else ""
    lines += [f"Duration: {minutes(duration)}", f"Assessment: {assessment(status, a, duration, c)}{note}"]
    return "\n".join(lines)


def recover_text(who, dest, p, worst, duration):
    now = (f"median {p['median_ms']} ms, jitter {p['jitter_ms']} ms, loss {p['loss_pct']:.0f}%"
           if p.get("median_ms") is not None else f"status {p.get('status')}")
    return "\n".join([f"🟢 NetMon · HEALTHY", f"Source: {who}", f"Destination: {dest}",
                      f"Stable again after {minutes(duration)} (worst level: {worst})",
                      f"Now: {now}"])


# ------------------------------------------------------------------ shared-path incident of 1 measurement point
def path_assess(items, c):
    """items: [(target, assessment), ...] of the SAME measurement point in 1 round. Many servers abnormal at once
    (>= PATH_MIN_TARGETS and >= PATH_RATIO of the measured servers) -> suspect a problem on the shared path segment."""
    known = [(t, a) for t, a in items if a["status"] != UNKNOWN]
    bad = [(t, a) for t, a in known if a["level"]]
    hit = len(bad) >= int(c["PATH_MIN_TARGETS"]) and len(bad) >= float(c["PATH_RATIO"]) * max(len(known), 1)
    return {"bad": hit, "affected": bad, "known": len(known)}


def gateway_verdict(gw_ip, gp, c):
    """Evaluate the gateway (Wi-Fi router) measured in the same round: gateway also bad -> suspect Wi-Fi / local
    network; gateway fine -> suspect the ISP / transit side. Returns (verdict, gateway description line)."""
    if not gw_ip or not gp or gp.get("status") == "ERROR":
        return "unknown", "Gateway: not measured"
    if gp.get("status") != "UP":
        return "local", f"Gateway {gw_ip}: no reply"
    desc = f"Gateway {gw_ip}: median {gp['median_ms']} ms, jitter {gp['jitter_ms']} ms, loss {gp['loss_pct']:.0f}%"
    bad = gp["jitter_ms"] > float(c["GW_JITTER_WARN"]) or gp["loss_pct"] > float(c["GW_LOSS_WARN"])
    return ("local", desc + " ⚠") if bad else ("upstream", desc + " (stable)")


def path_text(action, sev, who, pa, gw_kind, gw_desc, duration):
    names = [f"{t['name']} ({a['status']})" for t, a in pa["affected"]]
    shown = ", ".join(names[:6]) + (f" (+{len(names) - 6})" if len(names) > 6 else "")
    verdict = {
        "local": "The gateway is abnormal too -> suspect Wi-Fi / local network (signal, power saving, router).",
        "upstream": "The gateway is stable but many servers are abnormal -> suspect a shared ISP / transit segment "
                    "(check the traces; not enough to conclude the ISP is at fault).",
        "unknown": "Many servers abnormal at once -> suspect a shared path segment; the gateway could not be measured.",
    }[gw_kind]
    head = f"🛰 NetMon · PATH ISSUE · {sev}" + (" (reminder)" if action == "remind" else "")
    return "\n".join([head, f"Source: {who}",
                      f"{len(pa['affected'])}/{pa['known']} servers abnormal at once: {shown}",
                      gw_desc, f"Duration: {minutes(duration)}", f"Assessment: {verdict}"])

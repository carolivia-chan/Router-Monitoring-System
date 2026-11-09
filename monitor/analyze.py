"""Route analysis from hops + MaxMind data: ASN path, country path, transit countries, bottleneck hop, route
signature (to detect route changes), the ISP of the measurement machine, and a quality score.
The MEDIAN latency is used because it is less affected than the mean by a few abnormally late packets."""
from collections import Counter


def _dedupe(seq):
    out = []
    for x in seq:
        if x and (not out or out[-1] != x):
            out.append(x)
    return out


def hop_latency(h):
    """Representative latency of 1 hop: the median, else the mean; None if the hop did not reply."""
    v = h.get("median_ms")
    if v is None:
        v = h.get("avg_ms")
    return v if v else None


def analyze(hops, target_ip):
    pub = [h for h in hops if h.get("public")]
    asn_path = _dedupe([h.get("asn") for h in pub])
    country_path = _dedupe([h.get("country") for h in pub])

    src_c = country_path[0] if country_path else None
    dst_c = country_path[-1] if country_path else None
    transit = [c for c in country_path if c not in (src_c, dst_c)]

    # bottleneck hop: the hop with the largest median-latency increase over the previous replying hop
    bottleneck, prev = None, 0.0
    for h in hops:
        lat = hop_latency(h)
        if h["ip"] and lat is not None:
            delta = lat - prev
            if bottleneck is None or delta > bottleneck["delta_ms"]:
                bottleneck = {"hop": h["hop"], "ip": h["ip"], "delta_ms": round(delta, 1)}
            prev = lat
    if bottleneck and bottleneck["delta_ms"] <= 0:
        bottleneck = None

    last = hops[-1] if hops else None
    return {
        "hop_count": len(hops),
        "reached": bool(last and last["ip"] == target_ip),
        "dest_median_ms": hop_latency(last) if last and last["ip"] == target_ip else None,
        "asn_path": asn_path,
        "country_path": country_path,
        "transit": transit,
        "bottleneck": bottleneck,
        "signature": "|".join(asn_path) + "#" + "|".join(country_path),
    }


def isp_of(hops, target_ip=None):
    """ISP of the measurement machine according to 1 trace: ASN + organization name (MaxMind GeoLite2-ASN) of the
    first PUBLIC hop, i.e. the first router outside the home network / CGNAT. The destination server itself is
    skipped (if every hop in between is '*', the first public hop is the destination, not the ISP).
    Returns (asn, org) or None."""
    for h in hops or []:
        if h.get("public") and h.get("asn") and h.get("ip") != target_ip:
            return h["asn"], h.get("org")
    return None


def pick_isp(traces):
    """traces: [(hops, target_ip), ...] of the SAME monN. Every trace of 1 monN goes through the same ISP, so the
    most frequent ASN wins (majority vote): 1 odd trace (ISP hop not replying...) cannot mislabel it. None if unknown."""
    votes = Counter(x for x in (isp_of(h, ip) for h, ip in traces) if x)
    return votes.most_common(1)[0][0] if votes else None


def _where(hops, i):
    """Classify the location of hops[i]: local (machine / Wi-Fi / home router) | isp | transit | destination."""
    h = hops[i]
    pub = [x for x in hops if x.get("public") and x.get("asn")]
    src_asn = pub[0]["asn"] if pub else None
    dst_asn = pub[-1]["asn"] if pub else None
    if not h.get("public"):
        # private IP: if no public IP came before it -> home network; otherwise -> private IP inside the ISP (CGNAT...)
        if not any(x.get("public") for x in hops[:i]):
            return "local", "local network (machine / Wi-Fi / home router)"
        return "isp", f"inside the ISP network ({src_asn or '?'})"
    asn = h.get("asn")
    name = f"{asn} {h.get('org') or ''}".strip() if asn else "Unknown"
    if asn and asn == src_asn:
        return "isp", f"source ISP network ({name})"
    if asn and asn == dst_asn:
        return "destination", f"destination server network ({name})"
    return "transit", f"transit network ({name}, {h.get('country') or '?'})"


def loss_analysis(hops, target_ip, probe=None, threshold=10.0):
    """Locate packet loss along the path.

    Principle (the standard way to read mtr): REAL packet loss is loss that continues all the way to the
    destination. If a hop in the middle shows loss but the later hops and the destination do not -> that router
    only rate-limits its ICMP replies (rate-limit), user traffic still passes normally -> 'fake loss', no alert.

    Algorithm: take the loss at the destination (max of trace and probe). If it is >= threshold, walk back from the
    destination towards the source, merging the hops whose loss is still >= threshold/2; the earliest merged hop is
    where the loss STARTS.
    """
    resp = [i for i, h in enumerate(hops) if h["ip"]]
    reached = bool(hops) and hops[-1]["ip"] == target_ip
    trace_dest_loss = hops[-1]["loss_pct"] if reached else None
    probe_loss = probe["loss_pct"] if probe and probe.get("status") in ("UP", "DOWN") else None
    known = [x for x in (trace_dest_loss, probe_loss) if x is not None]
    dest_loss = max(known) if known else None
    out = {"real": False, "reached": reached,
           "dest_loss_pct": round(dest_loss, 1) if dest_loss is not None else None,
           "start": None, "prev": None, "where": None, "where_text": None, "fake_hops": []}

    # Neither a valid fping sample nor a destination trace sample exists.
    # This is UNKNOWN, not proof of packet loss or recovery.
    if dest_loss is None or not resp:
        return out
    info = lambda i: {k: hops[i].get(k) for k in ("hop", "ip", "asn", "org", "country", "loss_pct")}  # noqa: E731

    if not reached and (probe is None or probe.get("status") == "DOWN"):
        last = resp[-1]                                      # broken path: the destination is not reached
        out.update(real=True, start=info(last), where="unreachable",
                   where_text=f"destination unreachable, path breaks after hop {hops[last]['hop']} "
                              f"({_where(hops, last)[1]})")
        return out

    tol = threshold / 2
    if dest_loss >= threshold and reached and trace_dest_loss is not None and trace_dest_loss < tol:
        # fping saw loss but the trace (run afterwards) could not reproduce it -> intermittent loss,
        # not enough data to locate it; do NOT guess a location
        out.update(real=True, where="unknown",
                   where_text="intermittent loss: the following trace could not reproduce it, location unknown "
                              "(increase TRACE_CYCLES or look at the next measurements)")
        out["fake_hops"] = [hops[i]["hop"] for i in resp[:-1] if hops[i]["loss_pct"] >= threshold]
        return out
    if dest_loss >= threshold:
        start = resp[-1]
        for i in reversed(resp[:-1]):
            if hops[i]["loss_pct"] >= tol:
                start = i
            else:
                break
        prev = max([i for i in resp if i < start], default=None)
        kind, text = _where(hops, start)
        seg = (f"between hop {hops[prev]['hop']} ({hops[prev]['ip']}) and hop {hops[start]['hop']} "
               f"({hops[start]['ip']})") if prev is not None else f"right from hop {hops[start]['hop']}"
        out.update(real=True, start=info(start), prev=info(prev) if prev is not None else None,
                   where=kind, where_text=f"{text}; starts {seg}")
        real_from = start
    else:
        real_from = len(hops)
    # hop with loss that does not continue to the destination -> ICMP rate limiting, not real packet loss
    out["fake_hops"] = [hops[i]["hop"] for i in resp[:-1] if i < real_from and hops[i]["loss_pct"] >= threshold]
    return out


def score(probe_result, hop_count=0):
    """Lower is better: median latency + 10*loss% + 2*hops. DOWN = infinity."""
    lat = probe_result.get("median_ms")
    if lat is None:
        lat = probe_result.get("avg_ms")
    if lat is None:
        return float("inf")
    return round(lat + 10 * probe_result["loss_pct"] + 2 * hop_count, 1)


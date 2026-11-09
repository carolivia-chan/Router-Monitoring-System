"""PROBE IP: measure latency (avg + median) / jitter / loss with `fping -I <sub-interface>`.

Each sub-interface runs ONE fping command for ALL servers (fping interleaves the packets across the targets itself):
    fping -I mon1 -S <IP of mon1> -C 20 -p 2500 -i 100 -t 1000 -q 192.168.0.1 89.187.162.1 ... 8.8.8.8 1.1.1.1
-> 5 monN x 24 servers = 5 fping processes instead of 120.

-i (gap between 2 consecutive packets, to any target) spreads the packets evenly over each -p period. By default
fping sends them 10 ms apart, i.e. 25 packets within 0.25 s; 5 monN at once make ~125 ICMP packets per 0.25 s, so the
router / ISP rate-limits ICMP and drops some -> fake loss on the servers at the end of the list (see Monitor.pacing in
main.py).

DOWN and ERROR are 2 different states:
  DOWN   fping DID print a result line for the target and every packet is '-': packets were sent, the target answered none
  ERROR  fping failed (exit code >= 3, could not bind to monN, timeout...) or printed no result line for the target:
         the target's state is UNKNOWN -> no data (loss/jitter = None), never counted as DOWN
"""
import re
import statistics
import subprocess

_NUM = re.compile(r"^(-|\d+(?:\.\d+)?)$")


def error_result(count, reason):
    """Result when the target could NOT be measured (fping failed / no result line for it): status ERROR, no data.
    health.assess treats it as UNKNOWN; PostgreSQL stores NULL; Prometheus has no value; not counted in availability."""
    return {"avg_ms": None, "median_ms": None, "min_ms": None, "max_ms": None, "jitter_ms": None,
            "loss_pct": None, "lost_seq": [], "loss_burst": 0, "dup_count": 0, "samples": [None] * count,
            "status": "ERROR", "error": reason}


def parse_fping(stderr, count):
    """Read the summary line of `fping -C`:  '8.8.8.8 : 12.1 12.4 - 12.2 12.3'  ('-' = lost packet).

    Other lines fping may print are skipped, for example
      '8.8.8.8 : duplicate for [0], 84 bytes, 25.4 ms'   (duplicate reply)
      'ICMP Host Unreachable from ...'
    Only a line whose values after ':' are ALL numbers or '-' is accepted.
    """
    seq, found, dup = [None] * count, False, 0
    for line in stderr.splitlines():
        if ":" not in line:
            continue
        if "duplicate for" in line:      # duplicate reply: NOT counted as an extra reply, only counted as a duplicate
            dup += 1
            continue
        vals = line.split(":", 1)[1].split()
        if vals and all(_NUM.match(v) for v in vals):
            seq = [None if v == "-" else float(v) for v in vals]
            found = True
    if not found:                        # fping printed no result line for the target: unknown, NOT DOWN
        return dict(error_result(count, "fping printed no result for this target"), dup_count=dup)
    rtts = [x for x in seq if x is not None]
    lost_seq = [i + 1 for i, x in enumerate(seq) if x is None]      # which packets were lost (1..count)
    burst = run = 0
    for x in seq:                                                     # longest run of consecutive lost packets
        run = run + 1 if x is None else 0
        burst = max(burst, run)
    loss = 100.0 * (count - len(rtts)) / count if count else 100.0
    # jitter = mean |difference| between 2 ADJACENT packets that were both received
    # (a lost packet in between means the 2 non-adjacent packets are not paired)
    diffs = [abs(a - b) for a, b in zip(seq, seq[1:]) if a is not None and b is not None]
    jitter = statistics.mean(diffs) if diffs else 0.0
    return {
        "avg_ms": round(statistics.mean(rtts), 1) if rtts else None,
        "median_ms": round(statistics.median(rtts), 1) if rtts else None,
        "min_ms": round(min(rtts), 1) if rtts else None,
        "max_ms": round(max(rtts), 1) if rtts else None,
        "jitter_ms": round(jitter, 1),
        "loss_pct": round(loss, 1),
        "lost_seq": lost_seq,
        "loss_burst": burst,
        "dup_count": dup,
        "samples": seq,                  # RTT of each packet in order (None = lost), for the sparkline
        "status": "UP" if rtts else "DOWN",
    }


def parse_fping_multi(stderr, ips, count):
    """Split the output of 1 fping run with MANY targets into {ip: parse_fping result}.

    Each line starts with the target address:  '8.8.8.8 : 25.1 132 68.9'  or
    '180.76.76.76 : duplicate for [14], 64 bytes, 51.0 ms'. Lines are grouped by address, then each target is
    parsed as for a single-target fping. A target with no line -> ERROR (unknown), not DOWN.
    """
    by_ip = {ip: [] for ip in ips}
    for line in stderr.splitlines():
        host = line.split(":", 1)[0].strip()
        if ":" in line and host in by_ip:
            by_ip[host].append(line)
    return {ip: parse_fping("\n".join(by_ip[ip]), count) for ip in ips}


def probe_many(iface, target_ips, count=5, src_ip=None, period_ms=1000, timeout_ms=1000, interval_ms=None):
    """ONE fping -C command for many targets through the same sub-interface. Returns {ip: result}.

    Each target gets `count` packets, `period_ms` apart; each packet is waited for at most `timeout_ms`; 2 consecutive
    packets (to different targets) are `interval_ms` apart (None = fping default, 10 ms). Packets follow the order of
    target_ips.
    NOTE: in counting mode (-c/-C) fping uses timeout = period by default. With a small period (e.g. 200 ms), servers
    with RTT > 200 ms (Europe, US...) would count as LOST even though they reply -> false DOWN.
    """
    ips = list(dict.fromkeys(target_ips))            # drop duplicate IPs, keep the order
    cmd = ["fping", "-I", iface, "-C", str(count), "-p", str(period_ms), "-t", str(timeout_ms), "-q"]
    if interval_ms:
        cmd += ["-i", str(int(interval_ms))]
    if src_ip:
        cmd += ["-S", src_ip]
    limit = count * period_ms / 1000 + timeout_ms / 1000 + len(ips) * max(interval_ms or 0, 50) / 1000 + 10
    r = subprocess.run(cmd + ips, capture_output=True, text=True, timeout=limit)
    # error reason: the first stderr line that is not a result line of a target
    # (e.g. 'binding to specific interface (SO_BINDTODEVICE): No such device')
    why = next((ln.strip() for ln in r.stderr.splitlines()
                if ln.strip() and ln.split(":", 1)[0].strip() not in ips), None)
    if r.returncode >= 3:                # 3 = bad arguments, 4 = system error: the whole command failed, no target measured
        return {ip: error_result(count, why or f"fping exited with code {r.returncode}") for ip in ips}
    res = parse_fping_multi(r.stderr, ips, count)
    for v in res.values():
        if v["status"] == "ERROR" and why:
            v["error"] = why
    return res


def probe(iface, target_ip, count=5, src_ip=None, period_ms=1000, timeout_ms=1000):
    """fping a single target (kept for manual tests / compatibility)."""
    return probe_many(iface, [target_ip], count, src_ip, period_ms, timeout_ms)[target_ip]

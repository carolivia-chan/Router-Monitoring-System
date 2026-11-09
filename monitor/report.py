"""Format measurement results: bordered hop table, colored by thresholds (when printing to a terminal).

Colors are only used when printing to a terminal (TTY); latest.txt is always plain text (no color codes).
"""
import os
import re
import sys

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_CODES = {"reset": "0", "bold": "1", "dim": "2", "red": "31", "green": "32", "yellow": "33",
          "cyan": "36", "grey": "90", "orange": "38;5;214"}
TH = {"lat_warn": 300.0, "jit_warn": 50.0, "lat_high": 150.0}     # overridden by set_thresholds()


def set_thresholds(lat_warn, jit_warn):
    TH["lat_warn"], TH["jit_warn"] = float(lat_warn), float(jit_warn)


def use_color(mode="auto"):
    if mode == "always":
        return True
    if mode == "never":
        return False
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ


class _St:
    def __init__(self, on):
        self.on = on

    def __call__(self, text, *styles):
        text = str(text)
        styles = [s for s in styles if s]
        if not self.on or not styles:
            return text
        return "\x1b[" + ";".join(_CODES[s] for s in styles) + "m" + text + "\x1b[0m"


def _vlen(s):
    return len(_ANSI.sub("", s))


def _pad(s, w):
    return s + " " * (w - _vlen(s))


# ------------------------------------------------------------------ colors by threshold
def loss_color(v):
    if v is None:
        return "grey"
    return "green" if v == 0 else ("yellow" if v < 50 else "red")


def lat_color(v):
    if v is None:
        return "grey"
    return "red" if v >= TH["lat_warn"] else ("orange" if v >= TH["lat_high"] else None)


def jit_color(v):
    return "red" if v >= TH["jit_warn"] else ("orange" if v >= 10 else "green")


def _num(v):
    return f"{v:.1f}" if v is not None else "—"


# ------------------------------------------------------------------ bordered table
def box_table(headers, rows, st):
    widths = [max(_vlen(r[i]) for r in [headers] + rows) for i in range(len(headers))]

    def border(l, m, r):
        return l + m.join("─" * (w + 2) for w in widths) + r

    out = [border("┌", "┬", "┐"),
           "│" + "│".join(f" {_pad(st(h, 'bold'), w)} " for h, w in zip(headers, widths)) + "│",
           border("├", "┼", "┤")]
    out += ["│" + "│".join(f" {_pad(c, w)} " for c, w in zip(r, widths)) + "│" for r in rows]
    out.append(border("└", "┴", "┘"))
    return out


def hop_rows(hops, a, st):
    rows = []
    for h in hops:
        n = str(h["hop"])
        if not h["ip"]:
            rows.append([st(n, "grey"), st("*", "grey")] + [st("—", "grey")] * 6)
            continue
        loss = st(f"{h.get('loss_pct', 0):.0f}%", loss_color(h.get("loss_pct", 0)))
        if h.get("dup"):
            loss += st(f" +{h['dup']}dup", "grey")
        med = st(_num(h.get("median_ms")), lat_color(h.get("median_ms")))
        if h.get("public"):
            country = st(h.get("country") or "Unknown", None if h.get("country") else "grey")
            asn = h.get("asn") or st("—", "grey")
            org = h.get("org") or st("—", "grey")
        else:
            country, asn, org = st("(private)", "grey"), st("—", "grey"), st("—", "grey")
        rows.append([n, h["ip"], loss, st(_num(h.get("avg_ms")), lat_color(h.get("avg_ms"))), med,
                     country, asn, org])
    return rows


# ------------------------------------------------------------------ loss line
def format_loss(L, st=None):
    st = st or _St(False)
    if not L:
        return None
    if L["real"]:
        return st(f"destination loss {L['dest_loss_pct']:.0f}% -> {L['where_text']}", "red")
    msg = st(f"no real packet loss (destination loss {L['dest_loss_pct']:.0f}%)", "green")
    if L["fake_hops"]:
        msg += st(f"; hop {', '.join(map(str, L['fake_hops']))} shows loss that does not continue to the destination "
                  f"-> the router rate-limits ICMP replies, not packet loss", "grey")
    return msg


# ------------------------------------------------------------------ 1 result block
def format_block(iface, target, p, hops=None, a=None, L=None, color=False):
    st = _St(color)
    status = p["status"]
    dot = st(f"● {status}", {"UP": "green", "ERROR": "yellow"}.get(status, "red"), "bold")
    lines = [f"{st(iface, 'bold')} {st('→', 'grey')} {st(target['name'], 'bold')}  "
             f"{st(target['ip'], 'dim')} {st('[' + target['country'] + ']', 'dim')}  {dot}"]

    if status == "ERROR":                # could not measure: no data, not DOWN
        lines.append(f"  {st('probe', 'dim')}  {st('not measured: ' + (p.get('error') or 'fping error'), 'yellow')}"
                     f" {st('(not counted as DOWN)', 'grey')}")
    else:
        lat, med = p.get("avg_ms"), p.get("median_ms")
        lost = p.get("lost_seq") or []
        loss_txt = st(f"{p['loss_pct']:.0f}%", loss_color(p["loss_pct"]))
        if lost and status == "UP":
            loss_txt += st(f" (lost packets #{',#'.join(map(str, lost))}; longest run {p.get('loss_burst', 0)})",
                           "yellow")
        if p.get("dup_count"):
            loss_txt += st(f"  dup {p['dup_count']}", "grey")
        jit = p["jitter_ms"]
        lines.append(f"  {st('probe', 'dim')}  latency {st(_num(lat) + ' ms', lat_color(lat))}  "
                     f"median {st(_num(med) + ' ms', lat_color(med))}  "
                     f"jitter {st(f'{jit:.1f} ms', jit_color(jit))}  loss {loss_txt}")

    if hops:
        lines.append("")
        lines += ["  " + r for r in box_table(
            ["#", "IP", "Loss", "Avg ms", "Median ms", "Country", "ASN", "Org"], hop_rows(hops, a, st), st)]
    if a:
        bn = a["bottleneck"]
        bn_txt = st(f"hop {bn['hop']} (+{bn['delta_ms']} ms)", "yellow", "bold") if bn else "n/a"
        tool = (hops or [{}])[0].get("tool", "mtr")
        lines += ["",
                  f"  {st('analysis', 'dim')}  tool={tool}  hops={a['hop_count']}  "
                  f"reached={st('yes', 'green') if a['reached'] else st('no', 'red')}  "
                  f"bottleneck={bn_txt}  transit={', '.join(a['transit']) or 'none'}",
                  f"  {st('ASN path', 'dim')}  {st(' → '.join(a['asn_path']) or 'n/a', 'cyan')}"]
    return "\n".join(lines)

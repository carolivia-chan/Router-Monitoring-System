"""Unit tests of the data analysis (no fping/mtr/root needed). Run: python3 -m unittest discover -s tests -v"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from monitor.analyze import analyze, loss_analysis, score             # noqa: E402
from monitor.probe import parse_fping, parse_fping_multi   # noqa: E402
from monitor.report import format_block                # noqa: E402
from monitor.trace import parse_mtr_raw, parse_traceroute   # noqa: E402

TARGET = "108.61.210.117"


class FakeGeo:
    DB = {"116.97.90.97": ("Vietnam", "AS7552", "Viettel Group"),
          "129.250.4.81": ("United States", "AS2914", "NTT America, Inc."),
          "212.119.15.18": ("United Kingdom", "AS2914", "NTT America, Inc."),
          TARGET: ("Germany", "AS20473", "The Constant Company, LLC")}

    def lookup(self, ip):
        if not ip:
            return {}
        if ip.startswith(("10.", "192.168.")):
            return {"public": False}
        c, a, o = self.DB.get(ip, (None, None, None))
        return {"public": True, "country": c, "asn": a, "org": o}


def enrich(hops):
    for h in hops:
        h.update(FakeGeo().lookup(h["ip"]))
    return hops


# real mtr --raw output (format from mtr 0.95): pos starts at 0, p = microseconds
MTR_RAW = """x 0 33000
h 0 192.168.0.1
h 0 192.168.0.1
p 0 1800 33000
x 1 33001
x 2 33002
h 2 116.97.90.97
p 2 3500 33002
x 3 33003
h 3 129.250.4.81
p 3 216300 33003
x 4 33004
h 4 212.119.15.18
p 4 241200 33004
x 5 33005
h 5 108.61.210.117
p 5 207100 33005
x 6 33006
x 0 33007
p 0 1000 33007
x 2 33008
p 2 16200 33008
x 3 33009
p 3 187700 33009
x 4 33010
p 4 235900 33010
x 5 33011
p 5 254100 33011
x 0 33012
p 0 1100 33012
x 2 33013
p 2 3600 33013
x 3 33014
p 3 228600 33014
x 4 33015
p 4 248700 33015
x 5 33016
p 5 220900 33016
"""

TRACEROUTE = """traceroute to 108.61.210.117 (108.61.210.117), 30 hops max, 60 byte packets
 1  192.168.0.1  1.812 ms  1.020 ms  1.104 ms
 2  * * *
 3  116.97.90.97  3.512 ms  16.201 ms 116.97.90.98  3.601 ms
 4  129.250.4.81  216.3 ms !H  187.7 ms  *
 5  212.119.15.18  241.2 ms  235.9 ms  248.7 ms
 6  108.61.210.117  207.1 ms  254.1 ms  220.9 ms
"""


class ProbeTest(unittest.TestCase):
    def test_all_ok_median(self):
        r = parse_fping("8.8.8.8 : 65.0 48.7 25.5 44.1 25.4\n", 5)   # real figures from the measurement laptop
        self.assertEqual((r["avg_ms"], r["median_ms"], r["loss_pct"], r["status"]), (41.7, 44.1, 0.0, "UP"))

    def test_duplicate_line_is_ignored(self):
        # old bug: could not convert string to float: 'duplicate'
        err = ("108.61.219.200 : duplicate for [2], 84 bytes, 193 ms\n"
               "108.61.219.200 : 193.1 192.8 193.0 - 194.2\n")
        r = parse_fping(err, 5)
        self.assertEqual((r["loss_pct"], r["status"]), (20.0, "UP"))
        self.assertAlmostEqual(r["median_ms"], 193.0, delta=0.1)

    def test_partial_loss(self):
        r = parse_fping("8.8.8.8 : 10.0 - 12.0 - 11.0\n", 5)
        self.assertEqual((r["loss_pct"], r["median_ms"], r["status"]), (40.0, 11.0, "UP"))

    def test_down(self):
        r = parse_fping("8.8.8.8 : - - - - -\n", 5)
        self.assertEqual((r["avg_ms"], r["median_ms"], r["loss_pct"], r["status"]), (None, None, 100.0, "DOWN"))

    def test_only_garbage(self):
        r = parse_fping("8.8.8.8 : duplicate for [0], 84 bytes, 25 ms\n", 5)
        self.assertEqual((r["status"], r["loss_pct"], r["jitter_ms"]), ("ERROR", None, None))   # unknown != DOWN


class MtrRawTest(unittest.TestCase):
    def setUp(self):
        self.hops = enrich(parse_mtr_raw(MTR_RAW, TARGET, 3))

    def test_truncated_at_target(self):
        # mtr also probes pos 6 (beyond the destination) -> must be cut
        self.assertEqual(len(self.hops), 6)
        self.assertEqual(self.hops[-1]["ip"], TARGET)

    def test_silent_hop(self):
        h2 = self.hops[1]
        self.assertIsNone(h2["ip"])
        self.assertEqual(h2["loss_pct"], 100.0)

    def test_median(self):
        # hop 3 (116.97.90.97): 3.5, 16.2, 3.6 -> median 3.6 (avg 7.8 pulled up by 1 late packet)
        h3 = self.hops[2]
        self.assertEqual((h3["median_ms"], h3["avg_ms"], h3["loss_pct"]), (3.6, 7.8, 0.0))
        self.assertEqual(self.hops[-1]["median_ms"], 220.9)

    def test_analyze(self):
        a = analyze(self.hops, TARGET)
        self.assertTrue(a["reached"])
        self.assertEqual(a["asn_path"], ["AS7552", "AS2914", "AS20473"])
        self.assertEqual(a["transit"], ["United States", "United Kingdom"])
        self.assertEqual(a["bottleneck"]["hop"], 4)
        self.assertEqual(a["dest_median_ms"], 220.9)


class UnreachableTest(unittest.TestCase):
    def test_repeated_unreachable_router_is_cut(self):
        # real output for a nonexistent destination: router 10.0.12.2 answers 'host unreachable' for every TTL >= 3
        raw = ("x 0 1\nh 0 192.168.1.1\np 0 100 1\nx 1 2\nh 1 10.0.12.2\np 1 90 2\n"
               "x 2 3\nh 2 10.0.12.2\np 2 3051200 3\nx 3 4\nx 4 5\nx 11 6\nh 11 10.0.12.2\np 11 3053100 6\n")
        hops = parse_mtr_raw(raw, "203.0.113.99", 1)
        self.assertEqual([h["ip"] for h in hops], ["192.168.1.1", "10.0.12.2"])
        self.assertFalse(analyze(hops, "203.0.113.99")["reached"])


class TracerouteTest(unittest.TestCase):
    def setUp(self):
        self.hops = enrich(parse_traceroute(TRACEROUTE, TARGET, 3))

    def test_parse(self):
        self.assertEqual(len(self.hops), 6)
        self.assertIsNone(self.hops[1]["ip"])
        self.assertEqual(self.hops[2]["ip"], "116.97.90.97")          # ECMP: keep the first IP
        self.assertEqual(self.hops[2]["median_ms"], 3.6)
        self.assertEqual((self.hops[3]["recv"], self.hops[3]["median_ms"]), (2, 202.0))   # '!H' and '*'
        self.assertEqual(self.hops[-1]["median_ms"], 220.9)

    def test_same_result_as_mtr(self):
        a = analyze(self.hops, TARGET)
        self.assertTrue(a["reached"])
        self.assertEqual(a["asn_path"], ["AS7552", "AS2914", "AS20473"])


def mk(rows):
    """rows: (ip, loss%, median, country, asn) -> enriched hop list."""
    hops = []
    for i, (ip, loss, med, c, asn) in enumerate(rows, 1):
        h = {"hop": i, "ip": ip, "loss_pct": loss, "median_ms": med, "avg_ms": med}
        if ip and not ip.startswith(("10.", "192.168.")):
            h.update(public=True, country=c, asn=asn, org=asn and asn + " Org")
        elif ip:
            h.update(public=False)
        hops.append(h)
    return hops


PATH = [("192.168.0.1", 0, 1, None, None),          # 1 home router
        ("116.97.90.97", 0, 4, "Vietnam", "AS7552"),  # 2 Viettel
        (None, 100, None, None, None),                # 3 '*'
        ("129.250.4.81", 0, 200, "United States", "AS2914"),  # 4 NTT
        ("212.119.15.18", 0, 240, "United Kingdom", "AS2914"),  # 5 NTT
        ("108.61.210.117", 0, 220, "Germany", "AS20473")]   # 6 destination


def path_with(**loss):
    rows = [list(r) for r in PATH]
    for idx, v in loss.items():
        rows[int(idx[1:]) - 1][1] = v
    return mk([tuple(r) for r in rows])


class LossLocalizationTest(unittest.TestCase):
    T = "108.61.210.117"

    def test_no_loss(self):
        L = loss_analysis(path_with(), self.T)
        self.assertFalse(L["real"])
        self.assertEqual(L["fake_hops"], [])

    def test_fake_loss_icmp_ratelimit(self):
        # hop 4 loses 60% but hop 5 and the destination 0% -> the router rate-limits ICMP, NOT packet loss
        L = loss_analysis(path_with(h4=60), self.T)
        self.assertFalse(L["real"])
        self.assertEqual(L["fake_hops"], [4])

    def test_real_loss_in_transit(self):
        # loss from hop 4 (NTT) continues to the destination -> real packet loss, at a transit network
        L = loss_analysis(path_with(h4=30, h5=40, h6=30), self.T)
        self.assertTrue(L["real"])
        self.assertEqual((L["start"]["hop"], L["prev"]["hop"], L["where"]), (4, 2, "transit"))
        self.assertIn("between hop 2 (116.97.90.97) and hop 4 (129.250.4.81)", L["where_text"])

    def test_real_loss_from_wifi(self):
        L = loss_analysis(path_with(h1=30, h2=25, h4=30, h5=35, h6=30), self.T)
        self.assertEqual((L["start"]["hop"], L["where"]), (1, "local"))

    def test_real_loss_at_isp(self):
        L = loss_analysis(path_with(h2=20, h4=20, h5=25, h6=20), self.T)
        self.assertEqual((L["start"]["hop"], L["where"]), (2, "isp"))

    def test_loss_only_at_destination(self):
        L = loss_analysis(path_with(h6=40), self.T)
        self.assertEqual((L["start"]["hop"], L["where"]), (6, "destination"))

    def test_fake_upstream_plus_real_downstream(self):
        # hop 2 rate-limits (50%), hop 4 0%, real loss from hop 5 -> hop 2 is fake, loss starts at hop 5
        L = loss_analysis(path_with(h2=50, h5=30, h6=30), self.T)
        self.assertEqual(L["start"]["hop"], 5)
        self.assertEqual(L["fake_hops"], [2])

    def test_probe_loss_counts(self):
        # the trace sees 10% destination loss (few samples), fping sees 40% -> use 40%, still located (from hop 4)
        probe = {"loss_pct": 40.0, "status": "UP"}
        L = loss_analysis(path_with(h4=30, h5=30, h6=10), self.T, probe)
        self.assertTrue(L["real"])
        self.assertEqual((L["dest_loss_pct"], L["start"]["hop"]), (40.0, 4))

    def test_probe_loss_not_reproduced_by_trace(self):
        # fping lost 30% but the following trace shows 0% at the destination -> intermittent loss, NO location guessed
        L = loss_analysis(path_with(), self.T, {"loss_pct": 30.0, "status": "UP"})
        self.assertTrue(L["real"])
        self.assertEqual((L["where"], L["start"]), ("unknown", None))

    def test_unreachable(self):
        hops = path_with()[:5]                    # the trace stops at hop 5, destination not reached
        L = loss_analysis(hops, self.T, {"loss_pct": 100.0, "status": "DOWN"})
        self.assertEqual((L["where"], L["start"]["hop"]), ("unreachable", 5))
        self.assertIn("path breaks after hop 5", L["where_text"])


class DuplicateTest(unittest.TestCase):
    def test_fping_duplicate_not_counted_as_received(self):
        err = ("8.8.8.8 : duplicate for [0], 64 bytes, 30.1 ms\n"
               "8.8.8.8 : 30.2 - 28.0 26.0 55.2\n")
        r = parse_fping(err, 5)
        self.assertEqual((r["loss_pct"], r["dup_count"], r["lost_seq"]), (20.0, 1, [2]))

    def test_mtr_duplicate_does_not_hide_loss(self):
        # hop 1: 3 probes sent (seq 1,2,3), probe 2 LOST, probe 1 answered twice (duplicate)
        raw = ("x 0 1\nh 0 8.8.8.8\np 0 30000 1\np 0 31600 1\nx 0 2\nx 0 3\np 0 29000 3\n")
        h = parse_mtr_raw(raw, "8.8.8.8", 3)[0]
        self.assertEqual((h["sent"], h["recv"], h["dup"], round(h["loss_pct"])), (3, 2, 1, 33))


class ProbeLossSeqTest(unittest.TestCase):
    def test_lost_seq_and_jitter(self):
        r = parse_fping("1.1.1.1 : 10.0 - 30.0 31.0 - \n", 5)
        self.assertEqual((r["lost_seq"], r["loss_burst"], r["loss_pct"]), ([2, 5], 1, 40.0))
        # only packets 3-4 are paired (adjacent, both received) -> jitter 1.0; 10 is NOT paired with 30
        self.assertEqual(r["jitter_ms"], 1.0)

    def test_burst(self):
        r = parse_fping("1.1.1.1 : 10.0 - - - 11.0\n", 5)
        self.assertEqual((r["loss_burst"], r["lost_seq"]), (3, [2, 3, 4]))


class ReportTest(unittest.TestCase):
    def _block(self, color=False):
        hops = enrich(parse_mtr_raw(MTR_RAW, TARGET, 3))
        for h in hops:
            h["tool"] = "mtr"
        p = parse_fping(f"{TARGET} : 207.1 254.1 220.9 - 216.2\n", 5)
        a = analyze(hops, TARGET)
        return format_block("mon1", {"name": "Host 7", "ip": TARGET, "country": "Germany"},
                            p, hops, a, loss_analysis(hops, TARGET, p), color=color)

    def test_format_plain(self):
        txt = self._block()
        self.assertNotIn("\x1b[", txt)                              # file: no color codes
        self.assertIn("mon1 → Host 7  108.61.210.117 [Germany]  ● UP", txt)
        self.assertIn("median 218.6 ms  jitter", txt)              # median shows only the number
        self.assertNotIn("destination loss", txt)                  # no loss line
        self.assertIn("(lost packets #4; longest run 1)", txt)
        self.assertIn("│ # │ IP", txt)
        self.assertIn("(private)", txt)
        self.assertNotIn("◀BN", txt)
        self.assertIn("bottleneck=hop", txt)
        self.assertIn("United States  │ AS2914", txt)
        self.assertIn("ASN path  AS7552 → AS2914 → AS20473", txt)
        # every line of the table has the same width
        rows = [l for l in txt.splitlines() if l.strip().startswith(("│", "┌", "├", "└"))]
        self.assertEqual(len({len(r) for r in rows}), 1)

    def test_no_loss_line_when_no_real_loss(self):
        hops = enrich(parse_mtr_raw(MTR_RAW, TARGET, 3))
        p = parse_fping(f"{TARGET} : 207.1 254.1 220.9 218.0 216.2\n", 5)
        txt = format_block("mon1", {"name": "Host 7", "ip": TARGET, "country": "Germany"},
                           p, hops, analyze(hops, TARGET), loss_analysis(hops, TARGET, p))
        self.assertNotIn("no real packet loss", txt)
        self.assertNotIn("  loss  ", txt)

    def test_format_color_same_width(self):
        import re
        col = self._block(color=True)
        self.assertIn("\x1b[", col)
        plain = re.sub(r"\x1b\[[0-9;]*m", "", col)
        self.assertEqual(plain, self._block(color=False))         # colors do not misalign the columns

    def test_score_uses_median(self):
        self.assertEqual(score({"median_ms": 100.0, "avg_ms": 300.0, "loss_pct": 1.0}, 5), 120.0)
        self.assertEqual(score({"median_ms": None, "avg_ms": None, "loss_pct": 100.0}, 0), float("inf"))

class FpingMultiTest(unittest.TestCase):
    """1 fping command for many targets (real output from the machine, 20 packets)."""
    OUT = """180.76.76.76     : duplicate for [14], 64 bytes, 51.0 ms
114.114.114.114 : - - - - - - - - - - - - - - - - - - - -
223.5.5.5       : 143 143 144 144 144 143 144 144 143 145 144 144 150 144 146 146 144 144 145 144
119.29.29.29    : 62.3 61.9 62.0 61.4 61.3 60.9 61.5 61.5 62.7 61.8 61.4 62.2 61.0 61.3 61.4 62.4 62.2 62.0 63.5 61.2
180.76.76.76    : 60.3 49.8 49.7 49.1 49.5 49.5 50.6 48.9 49.7 49.2 49.0 49.2 53.1 49.5 50.1 50.1 49.3 50.1 49.2 49.8
59.56.22.40     : 312 - 314 - - - 313 313 409 - 317 312 - - 312 - - 313 - -
"""
    IPS = ["114.114.114.114", "223.5.5.5", "119.29.29.29", "180.76.76.76", "59.56.22.40", "10.9.9.9"]

    def test_split_per_target(self):
        r = parse_fping_multi(self.OUT, self.IPS, 20)
        self.assertEqual(set(r), set(self.IPS))
        self.assertEqual(r["114.114.114.114"]["status"], "DOWN")
        self.assertEqual(r["114.114.114.114"]["loss_pct"], 100.0)
        self.assertEqual((r["223.5.5.5"]["loss_pct"], r["223.5.5.5"]["median_ms"]), (0.0, 144.0))
        self.assertEqual(r["180.76.76.76"]["dup_count"], 1)              # the duplicate line is only counted
        self.assertEqual(r["180.76.76.76"]["loss_pct"], 0.0)
        self.assertEqual(r["59.56.22.40"]["loss_pct"], 55.0)             # 11/20 lost
        self.assertEqual(r["59.56.22.40"]["lost_seq"][:3], [2, 4, 5])
        self.assertEqual(r["10.9.9.9"]["status"], "ERROR")               # no line at all -> unknown, not DOWN

    def test_single_target_same_as_before(self):
        one = "8.8.8.8 : 25.1 132 68.9\n"
        self.assertEqual(parse_fping_multi(one, ["8.8.8.8"], 3)["8.8.8.8"], parse_fping(one, 3))


class SourceTest(unittest.TestCase):
    """Source labels: SOURCE_NAME + ISP label per UPLINKS (parsed like bash, quotes included)."""

    def conf(self, text):
        import tempfile
        from monitor.common import load_conf
        f = tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False)
        f.write(text)
        f.close()
        return load_conf(f.name)

    def test_single_machine(self):
        from monitor.common import source_label
        c = self.conf("SOURCE_NAME=laptop\n")
        self.assertEqual(source_label(c), "laptop")                 # ISP not identified yet
        self.assertEqual(source_label(c, "vnpt"), "laptop/vnpt")    # ISP from MaxMind

    def test_uplinks_quoted_like_bash(self):
        from monitor.common import uplinks
        c = self.conf('SOURCE_NAME=laptop\nUPLINKS="1-5:wlp1s0 6-10:usb0"   # a comment\n')
        self.assertEqual(uplinks(c), [(1, 5, "wlp1s0"), (6, 10, "usb0")])

    def test_old_uplinks_label_ignored(self):
        from monitor.common import uplinks
        c = self.conf('UPLINKS="1-5:wlp1s0:viettel 6-10:usb0:4g"\n')  # old format: the label part is ignored
        self.assertEqual(uplinks(c), [(1, 5, "wlp1s0"), (6, 10, "usb0")])

    def test_bad_uplinks(self):
        from monitor.common import uplinks
        with self.assertRaises(ValueError):
            uplinks(self.conf("UPLINKS=x-5:wlp1s0\n"))

    def test_exporter_has_source_label(self):
        from prometheus_client import CollectorRegistry, generate_latest
        from monitor.exporter import Exporter
        reg = CollectorRegistry()
        e = Exporter(0, registry=reg)
        up = {"status": "UP", "avg_ms": 30.0, "median_ms": 29.0, "jitter_ms": 1.0, "loss_pct": 0.0}
        e.probe("laptop/viettel", "mon6", {"ip": "8.8.8.8", "name": "G", "country": "Anycast"}, up, 31.0,
                "Laptop · Viettel · mon6", "Local", "AS7552")
        e.probe("gp/JP/Tokyo", None, {"ip": "8.8.8.8", "name": "G", "country": "Anycast"}, up, 31.0,
                "Tokyo, Japan", "Globalping", "AS2516")
        out = generate_latest(reg).decode()
        self.assertIn('netmon_latency_median_ms{country="Anycast",display="Laptop · Viettel · mon6",iface="mon6",'
                      'name="G",source="laptop/viettel",source_asn="AS7552",source_type="Local",target="8.8.8.8"} 29.0', out)
        self.assertIn('netmon_latency_median_ms{country="Anycast",display="Tokyo, Japan",iface="",'
                      'name="G",source="gp/JP/Tokyo",source_asn="AS2516",source_type="Globalping",target="8.8.8.8"} 29.0',
                      out)                                      # Globalping probe: no iface, ASN in source_asn


class IspTest(unittest.TestCase):
    """ISP of the measurement machine = ASN (MaxMind) of the first public hop, majority vote over the traces."""
    T = "8.8.8.8"

    @staticmethod
    def hop(n, ip, asn=None, org=None):
        return {"hop": n, "ip": ip, "public": bool(asn), "asn": asn, "org": org}

    def path(self, *asns):
        hops = [self.hop(1, "192.168.1.1"), self.hop(2, "100.64.0.1")]      # home router, CGNAT: not the ISP
        for i, (asn, org) in enumerate(asns, start=3):
            hops.append(self.hop(i, f"113.171.{i}.1", asn, org))
        return hops

    def test_first_public_hop(self):
        from monitor.analyze import isp_of
        hops = self.path(("AS45899", "VNPT Corp"), ("AS15169", "Google LLC"))
        self.assertEqual(isp_of(hops, self.T), ("AS45899", "VNPT Corp"))

    def test_destination_is_not_isp(self):
        from monitor.analyze import isp_of
        hops = [self.hop(1, "192.168.1.1"), self.hop(2, None), self.hop(3, self.T, "AS15169", "Google LLC")]
        self.assertIsNone(isp_of(hops, self.T))                  # ISP hop not replying: no guessing

    def test_vote(self):
        from monitor.analyze import pick_isp
        vnpt, odd = ("AS45899", "VNPT Corp"), ("AS7552", "Viettel Group")
        traces = [(self.path(vnpt), "1.1.1.1"), (self.path(vnpt), "9.9.9.9"), (self.path(odd), "8.8.4.4"),
                  ([self.hop(1, "192.168.1.1")], "8.8.8.8")]
        self.assertEqual(pick_isp(traces), vnpt)
        self.assertIsNone(pick_isp([([self.hop(1, "192.168.1.1")], "8.8.8.8")]))

    def test_label(self):
        from monitor.common import isp_label
        self.assertEqual(isp_label("AS45899", "VNPT Corp"), "vnpt")
        self.assertEqual(isp_label("AS7552", "Viettel Group"), "viettel")
        self.assertEqual(isp_label("AS18403", "FPT Telecom Company"), "fpt")
        self.assertEqual(isp_label("AS7643", "Vietnam Posts and Telecommunications (VNPT)"), "vnpt")
        self.assertEqual(isp_label("AS45899", None), "as45899")


class DisplayTest(unittest.TestCase):
    """Consistent display names: 'Laptop · VNPT · mon1' (measurement machine) and 'Tokyo, Japan' (Globalping probe)."""

    def test_isp_name_keeps_case(self):
        from monitor.common import isp_label, isp_name
        self.assertEqual(isp_name("AS45899", "VNPT Corp"), "VNPT")
        self.assertEqual(isp_name("AS7552", "Viettel Group"), "Viettel")
        self.assertEqual(isp_name("AS18403", "FPT Telecom Company"), "FPT")
        self.assertEqual(isp_name("AS7643", "Vietnam Posts and Telecommunications (VNPT)"), "VNPT")
        self.assertEqual(isp_name("AS45899", None), "AS45899")
        for org in ("VNPT Corp", "Viettel Group", "FPT Telecom Company", "MOBIFONE Corporation"):
            self.assertEqual(isp_name("AS1", org).lower(), isp_label("AS1", org))   # same ISP, different spelling

    def test_local(self):
        from monitor.common import DEFAULTS, display_name, source_display, source_label
        c = dict(DEFAULTS, SOURCE_NAME="laptop")
        self.assertEqual(display_name(source_label(c, "vnpt"), source_display(c, "VNPT"), "mon1"), "Laptop · VNPT · mon1")
        self.assertEqual(display_name(source_label(c), source_display(c), "mon2"), "Laptop · mon2")   # unknown ISP

    def test_globalping_location_not_isp(self):
        from monitor.common import display_name, gp_location, gp_source, source_type
        self.assertEqual(gp_source("JP", "Tokyo"), "gp/JP/Tokyo")
        self.assertEqual(gp_location("JP", "Tokyo"), "Tokyo, Japan")
        self.assertEqual(gp_location("DE", "Frankfurt"), "Frankfurt, Germany")
        self.assertEqual(gp_location("SG", "Singapore"), "Singapore")                # city = country name
        self.assertEqual(gp_location("KR", None), "South Korea")
        self.assertEqual(display_name("gp/JP/Tokyo", gp_location("JP", "Tokyo"), None), "Tokyo, Japan")
        self.assertEqual((source_type("gp/JP/Tokyo"), source_type("laptop/vnpt")), ("Globalping", "Local"))

    def test_display_for_old_keys(self):
        from monitor.common import display_for_key
        names = {"vnpt": "VNPT", "viettel": "Viettel"}
        self.assertEqual(display_for_key("laptop/vnpt", names), "Laptop · VNPT")
        self.assertEqual(display_for_key("laptop/viettel", names), "Laptop · Viettel")
        self.assertEqual(display_for_key("laptop", names), "Laptop")
        self.assertEqual(display_for_key("gp/JP", names), "Japan")
        self.assertEqual(display_for_key("gp/SG/Singapore", names), "Singapore")

    def test_monitor_tag(self):
        import main
        from monitor.common import DEFAULTS
        m = object.__new__(main.Monitor)
        m.c, m.isp, m.isp_traces = dict(DEFAULTS, SOURCE_NAME="laptop"), {}, {}
        h = lambda n, ip, asn=None, org=None: {"hop": n, "ip": ip, "public": bool(asn), "asn": asn, "org": org}  # noqa: E731
        path = [h(1, "192.168.1.1"), h(2, "113.171.1.1", "AS45899", "VNPT Corp"), h(3, "8.8.8.8", "AS15169", "Google")]
        self.assertEqual(m.tag("mon1"), "Laptop · mon1")
        m.vote_isp("mon1", path, "8.8.8.8")
        self.assertEqual((m.tag("mon1"), m.src("mon1"), m.src_display("mon1"), m.src_asn("mon1")),
                         ("Laptop · VNPT · mon1", "laptop/vnpt", "Laptop · VNPT", "AS45899"))


class GlobalpingTest(unittest.TestCase):
    """Measure from Globalping probes in many countries: convert API results to the NetMon probe/trace format.
    Simulated data following the Globalping API schema (MeasurementResponse / FinishedMtrTestResult)."""
    T = "89.187.162.1"

    def mtr_result(self):
        t10 = lambda base: [{"rtt": base + i * 0.5} for i in range(10)]           # noqa: E731
        st = lambda rcv, jav=0.5: {"min": 0, "avg": 0, "max": 0, "stDev": 0, "jMin": 0, "jAvg": jav,   # noqa: E731
                                   "jMax": 0, "total": 10, "rcv": rcv, "drop": 10 - rcv, "loss": (10 - rcv) * 10}
        return {"status": "finished", "rawOutput": "", "resolvedAddress": self.T, "resolvedHostname": self.T,
                "hops": [
                    {"resolvedAddress": "192.168.1.1", "resolvedHostname": "", "asn": [], "timings": t10(1), "stats": st(10)},
                    {"resolvedAddress": None, "resolvedHostname": None, "asn": [], "timings": [], "stats": st(0)},
                    {"resolvedAddress": "129.250.4.81", "resolvedHostname": "", "asn": [2914], "timings": t10(60)[:6],
                     "stats": st(6)},                                   # 40% loss mid-path but none at the destination
                    {"resolvedAddress": self.T, "resolvedHostname": "", "asn": [60068], "timings": t10(70),
                     "stats": st(10, 1.5)}]}

    def response(self):
        probe = {"continent": "AS", "region": "Eastern Asia", "country": "JP", "state": None, "city": "Tokyo",
                 "asn": 2516, "network": "KDDI CORPORATION", "latitude": 35.69, "longitude": 139.69,
                 "tags": [], "resolvers": []}
        return {"id": "m1", "type": "mtr", "status": "finished", "target": self.T, "probesCount": 2,
                "createdAt": "", "updatedAt": "",
                "results": [{"probe": probe, "result": self.mtr_result()},
                            {"probe": dict(probe, country="DE", asn=3320), "result": {"status": "offline"}}]}

    def gp(self, **kw):
        from monitor.common import DEFAULTS
        from monitor.globalping import Globalping
        c = dict(DEFAULTS, **kw)
        return Globalping(c, FakeGeo())

    def fake_api(self, posts):
        import monitor.globalping as g
        calls = {"get": 0}

        def _req(method, url, body=None, token=None, timeout=20):
            if method == "POST":
                return posts(body)
            calls["get"] += 1
            return {"status": "in-progress"} if calls["get"] == 1 else self.response()
        self._orig = (g._req, g.time.sleep)
        g._req, g.time.sleep = _req, (lambda s: None)
        return calls

    def tearDown(self):
        import monitor.globalping as g
        if hasattr(self, "_orig"):
            g._req, g.time.sleep = self._orig

    def test_parse_mtr(self):
        from monitor.globalping import parse_mtr
        p, hops = parse_mtr(self.mtr_result(), self.T, 10)
        self.assertEqual([h["hop"] for h in hops], [1, 2, 3, 4])
        self.assertIsNone(hops[1]["ip"])
        self.assertEqual(hops[2]["loss_pct"], 40.0)
        self.assertEqual((p["status"], p["loss_pct"], p["median_ms"], p["jitter_ms"]), ("UP", 0.0, 72.2, 1.5))

    def test_unreached_is_down(self):
        from monitor.globalping import parse_mtr
        r = self.mtr_result()
        r["hops"] = r["hops"][:3]
        p, hops = parse_mtr(r, self.T, 10)
        self.assertEqual((p["status"], p["loss_pct"]), ("DOWN", 100.0))

    def test_run_maps_probe_to_source(self):
        bodies = []
        self.fake_api(lambda body: bodies.append(body) or {"id": "m1", "probesCount": 2})
        out = self.gp(GP_LOCATIONS="JP DE").run([{"name": "SG", "ip": self.T, "country": "Singapore"}])
        self.assertEqual(bodies[0]["locations"], [{"magic": "JP", "limit": 1}, {"magic": "DE", "limit": 1}])
        self.assertEqual(bodies[0]["measurementOptions"], {"packets": 10})
        self.assertEqual(len(out), 1)                                  # DE probe offline -> skipped
        src, asn, disp, t, p, hops = out[0]
        self.assertEqual((src, asn, disp), ("gp/JP/Tokyo", "AS2516", "Tokyo, Japan"))
        self.assertEqual(hops[2]["asn"], "AS2914")                     # enriched with MaxMind (FakeGeo)
        self.assertEqual(hops[0]["tool"], "globalping")
        from monitor.analyze import analyze, loss_analysis
        L = loss_analysis(hops, self.T, p)
        self.assertFalse(L["real"])                                    # hop 3 loses 40% but destination 0% -> fake loss
        self.assertEqual(L["fake_hops"], [3])
        self.assertTrue(analyze(hops, self.T)["reached"])

    def test_422_retries_each_location(self):
        import urllib.error
        tried = []

        def posts(body):
            locs = [x["magic"] for x in body["locations"]]
            tried.append(locs)
            if len(locs) > 1 or locs == ["XX"]:
                raise urllib.error.HTTPError("u", 422, "no probes", {}, None)
            return {"id": "m1", "probesCount": 1}
        self.fake_api(posts)
        out = self.gp(GP_LOCATIONS="JP XX").run([{"name": "SG", "ip": self.T, "country": "Singapore"}])
        self.assertEqual(tried, [["JP", "XX"], ["JP"], ["XX"]])
        self.assertEqual(len(out), 1)

    def test_429_stops_round(self):
        import urllib.error
        n = {"post": 0}

        def posts(body):
            n["post"] += 1
            raise urllib.error.HTTPError("u", 429, "too many", {}, None)
        self.fake_api(posts)
        ts = [{"name": f"S{i}", "ip": f"1.1.1.{i}", "country": "?"} for i in range(5)]
        self.assertEqual(self.gp().run(ts), [])
        self.assertEqual(n["post"], 1)                                 # stops at once, no more quota burned

    def test_budget_interval_and_pick(self):
        g = self.gp(GP_TARGETS="Host 01 - Singapore, 8.8.8.8")
        self.assertEqual(g.interval(24), 3840)                         # 10 countries x 24 servers = 240 tests > 250*0.9/hour
        self.assertEqual(g.interval(2), 3600)
        ts = [{"name": "Host 01 - Singapore", "ip": "89.187.162.1"}, {"name": "G", "ip": "8.8.8.8"},
              {"name": "X", "ip": "1.1.1.1"}]
        self.assertEqual([t["ip"] for t in g.pick(ts)], ["89.187.162.1", "8.8.8.8"])

    def test_gp_cycle_report_and_csv(self):
        import tempfile
        import main
        from monitor.common import DEFAULTS
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "targets.csv"), "w") as f:
            f.write(f"name,ip,country\nHost 01 - Singapore,{self.T},Singapore\n")
        self.fake_api(lambda body: {"id": "m1", "probesCount": 2})
        m = object.__new__(main.Monitor)
        m.c = dict(DEFAULTS, TARGETS=os.path.join(d, "targets.csv"), GP_LOCATIONS="JP DE")
        m.out, m.color, m.only_target, m.exporter, m.gp_db = d, False, None, None, None
        m.gp = self.gp(GP_LOCATIONS="JP DE")
        txt = m.gp_cycle()
        self.assertTrue(txt.startswith("=== Source Type: Globalping ==="))
        self.assertIn("Tokyo, Japan → Host 01 - Singapore  89.187.162.1", txt)
        self.assertIn("\n  gp/JP/Tokyo · AS2516\n", txt)              # line under the name: source_key · source_asn
        self.assertIn("median 72.2 ms", txt)
        with open(os.path.join(d, "globalping.csv")) as f:
            rows = f.read().splitlines()
        cols = rows[1].split(",")
        self.assertEqual((cols[1], cols[2], cols[-1]), ("gp/JP/Tokyo", "", "AS2516"))   # empty iface, ASN in the last column


class HoldTest(unittest.TestCase):
    """ALERT_HOLD: a problem must last continuously before Telegram is sent; a new route must be stable before it is reported."""

    def setUp(self):
        from monitor import alert
        self.alert, self.now, self.sent = alert, [1000.0], []
        alert._state.update(last={}, hist={}, since={}, route={})
        self._orig = (alert.telegram, alert.time.time)
        alert.telegram = lambda text: self.sent.append(text) or True
        alert.time.time = lambda: self.now[0]

    def tearDown(self):
        self.alert.telegram, self.alert.time.time = self._orig

    def tick(self, minutes):
        self.now[0] += minutes * 60

    def ev(self, bad):
        self.alert.evaluate("mon1|x|loss", bad, "⚠️ loss 30%\nLocation: transit", "🟢 cleared", 600, 1200)

    def test_short_problem_sends_nothing(self):
        for _ in range(10):                       # bad for 10 minutes, then gone
            self.ev(True)
            self.tick(1)
        self.ev(False)
        self.assertEqual(self.sent, [])           # no alert, and no "cleared" message either

    def test_long_problem_alerts_after_20_minutes(self):
        for _ in range(20):
            self.ev(True)
            self.tick(1)
        self.assertEqual(self.sent, [])           # 19 minutes: not sent yet
        self.ev(True)                             # minute 20
        self.assertEqual(self.sent, ["⚠️ loss 30% (lasting 20 min)\nLocation: transit"])
        self.tick(1)
        self.ev(False)
        self.assertEqual(self.sent[-1], "🟢 cleared")

    def test_gap_resets_counter(self):
        self.ev(True)
        self.tick(30)                             # 30 minutes without evaluation (service stopped)
        self.ev(True)
        self.assertEqual(self.sent, [])           # no accumulation across the gap

    def route(self, sig):
        return self.alert.route_changed("mon4|eg", {"sig": sig, "asn": [sig], "cc": [], "hops": 19}, 1200)

    def test_route_flap_not_reported(self):
        self.assertIsNone(self.route("A"))        # first time: recorded
        for sig in ("B", "A", "B", "A"):          # flapping every 5 minutes
            self.tick(5)
            self.assertIsNone(self.route(sig))

    def test_route_change_reported_when_stable(self):
        self.route("A")
        for _ in range(4):                        # route B kept at 0, 5, 10, 15 minutes
            self.assertIsNone(self.route("B"))
            self.tick(5)
        old, new = self.route("B")                # minute 20
        self.assertEqual((old["sig"], new["sig"]), ("A", "B"))
        self.tick(5)
        self.assertIsNone(self.route("B"))        # now the stable route, not reported again


class SplitSqlTest(unittest.TestCase):
    """storage.split_sql: split schema.sql into statements, never inside $$ blocks or '...' strings."""

    def test_schema_file(self):
        from monitor.storage import split_sql
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "monitor", "schema.sql")
        stmts = split_sql(open(path).read())
        do = [x for x in stmts if x.startswith("DO $$")]
        self.assertEqual(len(do), 4)              # old source table, foreign keys, source_asn (fact), source_asn (hourly)
        self.assertTrue(all(x.endswith("END $$") for x in do))        # the whole DO block is 1 statement
        self.assertIn("ADD COLUMN probe_city", do[0])
        self.assertIn("ADD CONSTRAINT fk_hop_asn", do[1])
        self.assertIn("SET source_asn = iface, iface = NULL", do[2])
        self.assertIn("ADD PRIMARY KEY (hour, source, iface, target_ip, source_asn)", do[3])
        fn = [x for x in stmts if x.startswith("CREATE OR REPLACE FUNCTION netmon_display")]
        self.assertEqual(len(fn), 1)
        self.assertTrue(fn[0].endswith("$$"))
        self.assertTrue(all("--" not in x for x in stmts))            # comments removed

    def test_quotes_and_comments(self):
        from monitor.storage import split_sql
        self.assertEqual(split_sql("SELECT 'a;b'; -- x;y\nSELECT 2;"), ["SELECT 'a;b'", "SELECT 2"])


def make_monitor(hold=0, **conf):
    """Monitor without GeoIP / exporter / DB, used by the alert and background trace tests."""
    import itertools
    import queue
    import tempfile
    import threading
    import main
    from monitor.common import DEFAULTS
    m = object.__new__(main.Monitor)
    m.c = dict(DEFAULTS, SOURCE_NAME="laptop", **conf)
    m.cooldown, m.base_min, m.hold = int(m.c["ALERT_COOLDOWN"]), 5, hold
    m.isp, m.gw, m.gw_probe, m.loss_where, m._probe_err = {}, {}, {}, {}, {}
    m.db = m.trace_db = m.exporter = m.geo = None
    m.tool, m.out, m.color, m.only_target, m.only_iface = "mtr", tempfile.mkdtemp(), False, None, None
    m.trace_lock, m.q_lock, m.trace_q, m.trace_seq = threading.Lock(), threading.Lock(), queue.PriorityQueue(), \
        itertools.count()
    m.trace_pending, m.trace_at, m.last_trace, m.last_probe, m.isp_traces, m.isp_tried = set(), {}, {}, {}, {}, {}
    m.sweep_no, m.next_sweep = 0, 0.0
    m.win = {}
    return m


class HealthAssessTest(unittest.TestCase):
    """health.assess: compare with the route's own baseline, not 1 fixed threshold for every server."""

    def setUp(self):
        from monitor.common import DEFAULTS
        self.c = dict(DEFAULTS)

    def p(self, med, jit=5.0, loss=0.0, status="UP"):
        return {"status": status, "median_ms": med, "avg_ms": med, "jitter_ms": jit, "loss_pct": loss}

    def test_conf_template_values(self):
        from monitor.common import load_conf
        c = load_conf(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "etc", "netmon.conf"))
        self.assertEqual([c[k] for k in ("JITTER_WARN", "JITTER_FACTOR", "LATENCY_WARN", "LATENCY_RISE_MS",
                                         "LATENCY_RISE_PCT", "ALERT_HOLD", "ALERT_COOLDOWN")],
                         ["20", "2", "600", "80", "40", "1200", "1800"])

    def test_cairo_example_is_unstable(self):
        from monitor import health
        a = health.assess(self.p(421.0, 121.9, 5.0), 250.0, 31.0, self.c)
        self.assertEqual((a["lat_limit"], a["jit_limit"]), (350.0, 62.0))       # 250 + max(80, 40% x 250)
        self.assertEqual(a["flags"], {"lat": True, "jit": True, "loss": False})  # loss must be > 5%
        self.assertEqual(a["status"], health.UNSTABLE)
        self.assertEqual(health.severity(a["status"], a, 0, self.c), health.CRITICAL)

    def test_far_server_normal(self):
        from monitor import health
        self.assertEqual(health.assess(self.p(371.0), 365.0, 5.0, self.c)["status"], health.HEALTHY)

    def test_single_metric_degraded_and_severity(self):
        from monitor import health
        a = health.assess(self.p(30.0, 25.0), 25.0, 5.0, self.c)       # jitter only: > max(20, 2 x 5)
        self.assertEqual(a["status"], health.DEGRADED)
        self.assertEqual(health.severity(a["status"], a, 600, self.c), health.WARNING)
        self.assertEqual(health.severity(a["status"], a, 3600, self.c), health.CRITICAL)   # lasting >= 1 hour
        a = health.assess(self.p(30.0, 45.0), 25.0, 5.0, self.c)       # jitter > 2 x threshold 20 -> far beyond
        self.assertEqual((a["status"], health.severity(a["status"], a, 0, self.c)), (health.DEGRADED, health.CRITICAL))

    def test_jitter_factor_and_zero(self):
        from monitor import health
        self.assertFalse(health.assess(self.p(300.0, 66.0), 300.0, 40.0, self.c)["flags"]["jit"])   # < 2 x 40
        self.assertTrue(health.assess(self.p(300.0, 95.0), 300.0, 40.0, self.c)["flags"]["jit"])
        c0 = dict(self.c, JITTER_FACTOR="0")
        self.assertTrue(health.assess(self.p(30.0, 21.0), 30.0, 19.0, c0)["flags"]["jit"])          # > 20 is enough

    def test_absolute_ceiling_without_baseline(self):
        from monitor import health
        self.assertEqual(health.assess(self.p(650.0), None, None, self.c)["status"], health.DEGRADED)

    def test_down_and_unknown(self):
        from monitor import health
        self.assertEqual(health.assess(self.p(None, 0, 100, "DOWN"), 1, 1, self.c)["status"], health.DOWN)
        a = health.assess(self.p(None, 0, 100, "ERROR"), 1, 1, self.c)
        self.assertEqual((a["status"], a["level"]), (health.UNKNOWN, None))


class HealthAlertTest(unittest.TestCase):
    """Combined alerts by Network Health: ALERT_HOLD, debouncing, escalation, reminders, recovery, gaps."""

    def setUp(self):
        import tempfile
        from monitor import alert
        self.alert, self.tmp, self.now, self.sent = alert, tempfile.mkdtemp(), [1000.0], []
        alert._state.update(last={}, hist={}, since={}, route={}, health={})
        alert.load_state(os.path.join(self.tmp, "state.json"), 30)
        self._orig = (alert.telegram, alert.time.time)
        alert.telegram = lambda text: self.sent.append(text) or True
        alert.time.time = lambda: self.now[0]
        self.t = {"name": "Host 11 - Cairo", "ip": "196.1.1.1", "country": "Egypt"}

    def tearDown(self):
        self.alert.telegram, self.alert.time.time = self._orig

    def p(self, med, jit=5.0, loss=0.0, status="UP"):
        return {"status": status, "median_ms": med, "avg_ms": med, "jitter_ms": jit, "loss_pct": loss}

    def run_min(self, m, minutes, *args, **kw):
        for _ in range(minutes):
            m.check("mon1", self.t, self.p(*args, **kw))
            self.now[0] += 60

    def learn(self, m):
        self.run_min(m, 5, 250.0, 15.0)                  # baseline: 250 ms, jitter 15 ms

    def test_one_combined_message_not_three(self):
        m = make_monitor(hold=0)
        self.learn(m)
        m.check("mon1", self.t, self.p(421.0, 121.9, 10.0))
        self.assertEqual(len(self.sent), 1)
        msg = self.sent[0]
        self.assertTrue(msg.startswith("🟠 NetMon · UNSTABLE · CRITICAL"))
        for s in ("Source: Laptop · mon1", "Destination: Host 11 - Cairo 196.1.1.1 (Egypt)",
                  "Median latency: 421.0 ms ⚠ (normal ~250 ms, threshold 350 ms)",
                  "Jitter: 121.9 ms ⚠ (normal ~15 ms, threshold 30 ms)", "Packet loss: 10% ⚠ (threshold 5%)",
                  "Assessment: Latency + jitter + packet loss abnormal together"):
            self.assertIn(s, msg)

    def test_peers_noted(self):
        m = make_monitor(hold=0)
        self.learn(m)
        m.check("mon1", self.t, self.p(421.0, 121.9, 10.0), peers=["Host 12 - Johannesburg (UNSTABLE)"])
        self.assertIn("• Also abnormal on this measurement point: Host 12 - Johannesburg (UNSTABLE)", self.sent[0])
        self.assertIn("possibly a shared path segment", self.sent[0])

    def test_far_server_not_alerted(self):
        m = make_monitor(hold=0)
        self.run_min(m, 10, 371.0)
        self.assertEqual(self.sent, [])

    def test_hold_and_flapping(self):
        m = make_monitor(hold=1200)
        self.learn(m)
        for i in range(20):                               # minutes 0..19: bad and good alternating (flapping connection)
            m.check("mon1", self.t, self.p(250.0, 90.0 if i % 2 == 0 else 15.0))
            self.now[0] += 60
        self.assertEqual(self.sent, [])
        m.check("mon1", self.t, self.p(250.0, 90.0))      # minute 20: 1 good round does not reset the counter -> confirmed
        self.assertEqual(len(self.sent), 1)
        self.assertIn("DEGRADED", self.sent[0])
        self.assertIn("Duration: 20 min", self.sent[0])

    def test_short_problem_and_recovery_rules(self):
        m = make_monitor(hold=1200)
        self.learn(m)
        self.run_min(m, 10, 250.0, 90.0)                  # bad for 10 minutes, then gone
        self.run_min(m, 5, 250.0, 15.0)
        self.assertEqual(self.sent, [])                   # no alert, no recovery message

    def test_escalation_reminder_recovery(self):
        m = make_monitor(hold=0, ALERT_COOLDOWN="1800")
        m.cooldown = 1800
        self.learn(m)
        self.run_min(m, 1, 250.0, 90.0)                   # jitter only -> DEGRADED · CRITICAL? (90 > 2 x 30: far beyond)
        self.assertIn("DEGRADED", self.sent[-1])
        self.run_min(m, 1, 420.0, 90.0)                   # plus latency -> UNSTABLE: sent at once (escalation)
        self.assertIn("UNSTABLE", self.sent[-1])
        n = len(self.sent)
        self.run_min(m, 29, 420.0, 90.0)
        self.assertEqual(len(self.sent), n)               # within the cooldown: not sent again
        self.run_min(m, 1, 420.0, 90.0)
        self.assertIn("(reminder)", self.sent[-1])
        self.run_min(m, 2, 250.0, 15.0)
        self.assertNotIn("HEALTHY", self.sent[-1])         # only 2 good rounds: not recovered yet
        self.run_min(m, 1, 250.0, 15.0)
        self.assertTrue(self.sent[-1].startswith("🟢 NetMon · HEALTHY"))
        self.assertIn("worst level: UNSTABLE · CRITICAL", self.sent[-1])

    def test_gap_is_not_counted_as_sustained(self):
        m = make_monitor(hold=1200)
        self.learn(m)
        self.run_min(m, 10, 250.0, 90.0)
        self.now[0] += 30 * 60                            # 30 minutes without data (service stopped, measurement errors...)
        self.run_min(m, 10, 250.0, 90.0)
        self.assertEqual(self.sent, [])                   # 10 + 30 + 10 minutes are not added into 1 incident

    def test_unknown_samples_not_counted(self):
        m = make_monitor(hold=0)
        self.learn(m)
        self.run_min(m, 3, None, 0.0, 100.0, status="ERROR")
        self.assertEqual(self.sent, [])

    def test_down_confirmed_faster(self):
        m = make_monitor(hold=1200)
        self.learn(m)
        self.run_min(m, 5, None, 0.0, 100.0, status="DOWN")
        self.assertEqual(self.sent, [])
        self.run_min(m, 1, None, 0.0, 100.0, status="DOWN")     # DOWN_HOLD = 5 minutes
        self.assertTrue(self.sent[-1].startswith("🔴 NetMon · DOWN · CRITICAL"))

    def test_baseline_not_learning_the_incident(self):
        m = make_monitor(hold=1200)
        self.learn(m)
        self.run_min(m, 40, 250.0, 60.0)                   # jitter 60 ms for 40 minutes
        self.assertTrue(any("DEGRADED" in x for x in self.sent))
        self.assertEqual(self.alert.baseline("mon1|196.1.1.1|jit", None, "median", 5), 15.0)

    def test_state_survives_restart(self):
        m = make_monitor(hold=0)
        self.learn(m)
        self.alert.save_state()
        self.alert._state.update(last={}, hist={}, since={}, route={}, health={})     # simulated restart
        self.alert.load_state(os.path.join(self.tmp, "state.json"), 30)
        m.check("mon1", self.t, self.p(520.0))
        self.assertIn("normal ~250 ms", self.sent[-1])

    def test_load_env(self):
        from monitor.common import load_env
        path = os.path.join(self.tmp, "netmon.env")
        with open(path, "w") as f:
            f.write("# comment\nNETMON_TEST_TOKEN=\"abc:123\"\nexport NETMON_TEST_CHAT=42\n")
        os.environ.pop("NETMON_TEST_TOKEN", None)
        os.environ.pop("NETMON_TEST_CHAT", None)
        load_env(path)
        self.assertEqual(os.environ["NETMON_TEST_TOKEN"], "abc:123")
        self.assertEqual(os.environ["NETMON_TEST_CHAT"], "42")
        load_env(os.path.join(self.tmp, "missing.env"))          # no file: no error


class PathIssueTest(unittest.TestCase):
    """Many servers abnormal on 1 measurement point -> 1 PATH ISSUE message, narrowed down with the gateway."""

    def setUp(self):
        from monitor import alert
        self.alert, self.sent = alert, []
        alert._state.update(last={}, hist={}, since={}, route={}, health={})
        self._orig = alert.telegram
        alert.telegram = lambda text: self.sent.append(text) or True
        self.ts = [{"name": f"Host {i:02d}", "ip": f"10.0.0.{i}", "country": "X"} for i in range(1, 11)]

    def tearDown(self):
        self.alert.telegram = self._orig

    def lap(self, m, bad_n, gw):
        from monitor import health
        m.gw, m.gw_probe = {"mon1": "192.168.0.1"}, {"mon1": gw}
        checks = []
        for i, t in enumerate(self.ts):
            p = {"status": "UP", "median_ms": 250.0, "avg_ms": 250.0, "loss_pct": 0.0,
                 "jitter_ms": 120.0 if i < bad_n else 5.0}
            checks.append((t, p, m.assess("mon1", t, p)))
        active = m.check_path("mon1", [(t, a) for t, _p, a in checks])
        for t, p, a in checks:
            m.check("mon1", t, p, a, suppress=active)
        self.assertTrue(all(a["status"] in (health.HEALTHY, health.DEGRADED) for _t, _p, a in checks))
        return active

    def test_many_targets_one_message_upstream(self):
        m = make_monitor(hold=0)
        for _ in range(5):
            self.lap(m, 0, {"status": "UP", "median_ms": 2.0, "jitter_ms": 0.5, "loss_pct": 0.0})
        self.assertTrue(self.lap(m, 4, {"status": "UP", "median_ms": 2.1, "jitter_ms": 0.8, "loss_pct": 0.0}))
        self.assertEqual(len(self.sent), 1)                # 1 message for all 4 servers, not 4 messages
        msg = self.sent[0]
        self.assertTrue(msg.startswith("🛰 NetMon · PATH ISSUE"))
        self.assertIn("4/10 servers abnormal at once: Host 01 (DEGRADED)", msg)
        self.assertIn("Gateway 192.168.0.1: median 2.1 ms, jitter 0.8 ms, loss 0% (stable)", msg)
        self.assertIn("suspect a shared ISP / transit segment", msg)

    def test_gateway_also_bad_means_local(self):
        m = make_monitor(hold=0)
        for _ in range(5):
            self.lap(m, 0, {"status": "UP", "median_ms": 2.0, "jitter_ms": 0.5, "loss_pct": 0.0})
        self.lap(m, 5, {"status": "UP", "median_ms": 30.0, "jitter_ms": 35.0, "loss_pct": 0.0})
        self.assertIn("suspect Wi-Fi / local network", self.sent[0])

    def test_single_target_is_not_path_issue(self):
        m = make_monitor(hold=0)
        for _ in range(5):
            self.lap(m, 0, None)
        self.assertFalse(self.lap(m, 1, None))
        self.assertEqual(len(self.sent), 1)
        self.assertTrue(self.sent[0].startswith("🟡 NetMon · DEGRADED"))


class PacingTest(unittest.TestCase):
    """Packet pacing: total ICMP packets/s of all monN <= PROBE_PPS, packets evenly spread, gateway sent first."""

    def test_stretch_period_for_many_ifaces(self):
        m = make_monitor()
        self.assertEqual(m.pacing(5, 25), (2500, 100))       # 125 packets / 50 packets/s = 2.5 s, spread every 100 ms
        self.assertEqual(m.pacing(2, 25), (1000, 40))        # 50 packets/s: PING_PERIOD kept
        self.assertEqual(make_monitor(PROBE_PPS="0").pacing(5, 25), (1000, 40))   # no limit: only spread evenly

    def test_fping_command(self):
        import subprocess
        from monitor import probe
        seen = {}

        def fake_run(cmd, **kw):
            seen["cmd"] = cmd
            return subprocess.CompletedProcess(cmd, 0, "", "192.168.0.1 : 1.0 1.1\n8.8.8.8 : 24.0 -\n")
        orig, probe.subprocess.run = probe.subprocess.run, fake_run
        try:
            res = probe.probe_many("mon1", ["192.168.0.1", "8.8.8.8"], 2, src_ip="192.168.0.201",
                                   period_ms=2500, interval_ms=100)
        finally:
            probe.subprocess.run = orig
        self.assertEqual(seen["cmd"][:12], ["fping", "-I", "mon1", "-C", "2", "-p", "2500", "-t", "1000", "-q",
                                            "-i", "100"])
        self.assertEqual(res["8.8.8.8"]["loss_pct"], 50.0)

    def test_gateway_first_and_stagger(self):
        import main
        m = make_monitor()
        m.gw = {"mon1": "192.168.0.1"}
        calls = []
        orig = main.probe_many
        main.probe_many = lambda iface, ips, count, **kw: calls.append((ips, kw)) or {ip: {"status": "UP"} for ip in ips}
        try:
            res = m.probe_iface(("mon1", "192.168.0.201"), [{"ip": "8.8.8.8"}, {"ip": "1.1.1.1"}], 2500, 100, 1)
        finally:
            main.probe_many = orig
        self.assertEqual(calls[0][0], ["192.168.0.1", "8.8.8.8", "1.1.1.1"])
        self.assertEqual((calls[0][1]["period_ms"], calls[0][1]["interval_ms"]), (2500, 100))
        self.assertEqual(sorted(res), ["1.1.1.1", "8.8.8.8"])             # gateway kept separately
        self.assertEqual(m.gw_probe["mon1"], {"status": "UP"})


class ProbeErrorTest(unittest.TestCase):
    """fping failure -> ERROR (UNKNOWN), not DOWN; the operator is still alerted when it lasts."""

    def fping(self, rc, stderr, ips=("8.8.8.8", "1.1.1.1")):
        import subprocess
        from monitor import probe
        orig = probe.subprocess.run
        probe.subprocess.run = lambda cmd, **kw: subprocess.CompletedProcess(cmd, rc, "", stderr)
        try:
            return probe.probe_many("mon1", list(ips), 3)
        finally:
            probe.subprocess.run = orig

    def test_exit_code_4_is_error(self):
        r = self.fping(4, "fping: can't create socket (must run as root?): Operation not permitted\n")
        self.assertEqual({v["status"] for v in r.values()}, {"ERROR"})
        self.assertIn("must run as root", r["8.8.8.8"]["error"])
        self.assertIsNone(r["8.8.8.8"]["loss_pct"])

    def test_bind_failure_without_result_lines_is_error(self):
        r = self.fping(1, "binding to specific interface (SO_BINDTODEVICE): No such device\n")
        self.assertEqual({v["status"] for v in r.values()}, {"ERROR"})
        self.assertIn("SO_BINDTODEVICE", r["1.1.1.1"]["error"])

    def test_real_down_still_down(self):
        r = self.fping(1, "8.8.8.8 : 24.0 25.0 24.5\n1.1.1.1 : - - -\n")
        self.assertEqual((r["8.8.8.8"]["status"], r["1.1.1.1"]["status"]), ("UP", "DOWN"))

    def test_error_is_unknown_and_reported_without_crash(self):
        from prometheus_client import CollectorRegistry
        from monitor import health
        from monitor.exporter import Exporter
        from monitor.probe import error_result
        from monitor.common import DEFAULTS
        p = error_result(20, "fping error")
        self.assertEqual(health.assess(p, 100, 5, dict(DEFAULTS))["status"], health.UNKNOWN)
        t = {"name": "Google", "ip": "8.8.8.8", "country": "US"}
        self.assertIn("not measured: fping error", format_block("mon1", t, p))
        reg = CollectorRegistry()
        Exporter(0, reg).probe("laptop", "mon1", t, p, float("inf"), "Laptop · mon1", "Local", "", None)
        self.assertIsNone(reg.get_sample_value("netmon_up", {
            "source": "laptop", "source_type": "Local", "iface": "mon1", "source_asn": "", "target": "8.8.8.8",
            "name": "Google", "country": "US", "display": "Laptop · mon1"}))          # no series, not 0

    def test_probe_error_alert_then_ok(self):
        from monitor import alert
        from monitor.probe import error_result
        alert._state.update(last={}, hist={}, since={}, route={}, health={})
        sent, orig = [], alert.telegram
        alert.telegram = lambda text: sent.append(text) or True
        try:
            m = make_monitor(DOWN_HOLD="0")
            bad = {ip: error_result(20, "binding to specific interface (SO_BINDTODEVICE): No such device")
                   for ip in ("8.8.8.8", "1.1.1.1")}
            m.check_probe("mon1", bad)
            m.check_probe("mon1", {"8.8.8.8": {"status": "UP"}, "1.1.1.1": {"status": "DOWN"}})
        finally:
            alert.telegram = orig
        self.assertEqual(len(sent), 2)
        self.assertTrue(sent[0].startswith("⚠️ NetMon · PROBE ERROR"))
        self.assertIn("SO_BINDTODEVICE", sent[0])
        self.assertTrue(sent[1].startswith("🟢 NetMon · PROBE OK"))


class BackgroundTraceTest(unittest.TestCase):
    """Background traces: the probe loop does not wait for traces; periodic traces rotate the monN; loss triggers a trace at once."""

    IF = [(f"mon{i}", f"192.168.0.{200 + i}") for i in range(1, 6)]
    T = [{"name": f"Host {i:02d}", "ip": f"10.0.0.{i}", "country": "X"} for i in range(1, 25)]

    def setUp(self):
        from monitor import alert
        alert._state.update(last={}, hist={}, since={}, route={}, health={})

    def probes(self, loss=0.0, bad=()):
        return {f: {t["ip"]: {"status": "UP", "median_ms": 20.0, "avg_ms": 20.0, "jitter_ms": 1.0,
                              "loss_pct": 40.0 if (f[0], t["ip"]) in bad else loss} for t in self.T} for f in self.IF}

    def drain(self, m):
        out = []
        while not m.trace_q.empty():
            out.append(m.trace_q.get())
        return out

    def test_rotation_one_iface_per_target(self):
        m = make_monitor()
        m.schedule_traces(self.IF, self.T, self.probes())
        jobs = self.drain(m)
        self.assertEqual(len(jobs), 24)                                   # 24 instead of 5 x 24 = 120
        per_if = {}
        for _p, _n, iface, _ip, t in jobs:
            per_if[iface] = per_if.get(iface, 0) + 1
        self.assertEqual(sorted(per_if.values()), [4, 5, 5, 5, 5])        # spread evenly over the monN
        m.trace_pending.clear()
        m.schedule_traces(self.IF, self.T, self.probes())                 # next sweep not due yet: nothing added
        self.assertEqual(self.drain(m), [])
        m.next_sweep = 0
        m.schedule_traces(self.IF, self.T, self.probes())
        second = {t["ip"]: iface for _p, _n, iface, _ip, t in self.drain(m)}
        first = {t["ip"]: iface for _p, _n, iface, _ip, t in jobs}
        self.assertTrue(all(first[ip] != second[ip] for ip in first))     # the next sweep rotates to another monN

    def test_no_rotation_traces_all(self):
        m = make_monitor(TRACE_ROTATE="0")
        m.schedule_traces(self.IF, self.T, self.probes())
        self.assertEqual(len(self.drain(m)), 120)

    def test_loss_traces_first_and_once(self):
        m = make_monitor()
        bad = {("mon3", "10.0.0.20")}
        m.schedule_traces(self.IF, self.T, self.probes(bad=bad))
        first = m.trace_q.get()
        self.assertEqual((first[0], first[2], first[4]["ip"]), (0, "mon3", "10.0.0.20"))   # higher priority
        self.assertFalse(m.enqueue_trace("mon3", "192.168.0.203", self.T[19], urgent=True))  # already waiting: no duplicate
        m.trace_pending.discard(("mon3", "10.0.0.20"))
        m.trace_at[("mon3", "10.0.0.20")] = __import__("time").time()
        self.drain(m)
        m.trace_pending.clear()
        m.schedule_traces(self.IF, self.T, self.probes(bad=bad))                   # just traced: not traced again
        self.assertEqual(self.drain(m), [])

    def test_worker_records_and_clears_pending(self):
        import threading
        import main
        m = make_monitor()
        seen = []
        orig = main.trace
        main.trace = lambda iface, src, ip, geo, cycles, tool: (seen.append((iface, ip)) or
                                                                 [{"hop": 1, "ip": ip, "public": True, "asn": "AS1",
                                                                   "org": "X Corp", "loss_pct": 0.0, "median_ms": 5.0,
                                                                   "avg_ms": 5.0, "country": "X"}])
        try:
            m.enqueue_trace("mon1", "192.168.0.201", self.T[0])
            threading.Thread(target=m.trace_worker, daemon=True).start()
            for _ in range(200):
                if not m.trace_pending:
                    break
                __import__("time").sleep(0.01)
        finally:
            main.trace = orig
        self.assertEqual(seen, [("mon1", "10.0.0.1")])
        self.assertEqual(m.trace_pending, set())
        self.assertIn(("mon1", "10.0.0.1"), m.last_trace)
        with open(os.path.join(m.out, "trace.jsonl")) as f:
            self.assertEqual(len(f.read().splitlines()), 1)

    def test_isp_known_before_first_probe(self):
        import main
        m = make_monitor()
        orig = main.trace
        main.trace = lambda iface, src, ip, geo, cycles, tool: [
            {"hop": 1, "ip": "192.168.0.1", "public": False, "loss_pct": 0.0},
            {"hop": 2, "ip": "27.68.1.1", "public": True, "asn": "AS7552", "org": "Viettel Group", "loss_pct": 0.0,
             "median_ms": 3.0, "avg_ms": 3.0, "country": "Vietnam"},
            {"hop": 3, "ip": ip, "public": True, "asn": "AS1", "org": "X", "loss_pct": 0.0, "median_ms": 9.0,
             "avg_ms": 9.0, "country": "X"}]
        try:
            m.ensure_isp(self.IF[:2], self.T)
        finally:
            main.trace = orig
        self.assertEqual((m.src("mon1"), m.tag("mon2")), ("laptop/viettel", "Laptop · Viettel · mon2"))

    def test_alert_state_thread_safe(self):
        import threading
        from monitor import alert
        alert._cfg["path"] = os.path.join(make_monitor().out, "state.json")
        errors = []

        def writer(n):
            try:
                for k in range(300):
                    alert.route_changed(f"mon{n}|10.0.0.{k}", {"sig": "a", "asn": [], "cc": [], "hops": 1})
            except Exception as e:
                errors.append(e)

        def saver():
            try:
                for _ in range(100):
                    alert.save_state()
            except Exception as e:
                errors.append(e)
        ts = [threading.Thread(target=writer, args=(n,)) for n in range(3)] + [threading.Thread(target=saver)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        alert._cfg["path"] = None
        self.assertEqual(errors, [])


class StorageTxTest(unittest.TestCase):
    """trace_run + trace_hop in 1 transaction; 1 failing schema statement does not lose the connection."""

    class Cur:
        def __init__(self, conn):
            self.conn = conn

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, sql, args=None):
            self.conn.log.append(sql)
            if self.conn.fail_on and self.conn.fail_on in sql:
                raise RuntimeError("canceling statement due to lock timeout")

        def executemany(self, sql, rows):
            self.conn.log.append(sql)
            if self.conn.fail_many:
                raise RuntimeError("connection lost")

        def fetchone(self):
            return (1,)

        def fetchall(self):
            return []

    class Conn:
        def __init__(self, fail_on=None, fail_many=False):
            self.log, self.fail_on, self.fail_many = [], fail_on, fail_many
            self.autocommit, self.closed, self.ended = True, 0, []

        def cursor(self):
            return StorageTxTest.Cur(self)

        def __enter__(self):                 # psycopg2: with conn -> COMMIT / ROLLBACK
            self.ended.append(("begin", self.autocommit))
            return self

        def __exit__(self, typ, *a):
            self.ended.append("rollback" if typ else "commit")
            return False

    def storage(self, conn):
        from monitor import storage
        st = object.__new__(storage.Storage)
        st.conn, st._seen, st.schema_ok, st.next_try, st.failing = conn, set(), True, 0.0, False
        return st

    def trace_args(self):
        t = {"name": "Google", "ip": "8.8.8.8", "country": "US"}
        hops = [{"hop": 1, "ip": "192.168.0.1", "loss_pct": 0.0}, {"hop": 2, "ip": "8.8.8.8", "asn": "AS15169",
                                                                     "org": "Google", "loss_pct": 0.0}]
        a = {"bottleneck": None, "hop_count": 2, "reached": True, "asn_path": ["AS15169"], "country_path": ["US"]}
        return t, hops, a

    def test_trace_hops_fail_rolls_back_run(self):
        conn = self.Conn(fail_many=True)
        st = self.storage(conn)
        st._seen.add(("s", "laptop", None, None))
        t, hops, a = self.trace_args()
        st.save_trace(None, "laptop", "mon1", t, hops, a)
        self.assertEqual(conn.ended, [("begin", False), "rollback"])     # trace_run is rolled back too
        self.assertTrue(conn.autocommit)                                  # autocommit restored
        self.assertEqual(st._seen, set())                                 # dimension rows will be added again

    def test_trace_ok_commits_once(self):
        conn = self.Conn()
        st = self.storage(conn)
        t, hops, a = self.trace_args()
        st.save_trace(None, "laptop", "mon1", t, hops, a)
        self.assertEqual(conn.ended, [("begin", False), "commit"])

    def test_schema_statement_failure_keeps_going(self):
        from monitor import storage
        conn = self.Conn(fail_on="CREATE OR REPLACE VIEW v_probe")
        ok = storage.Storage._apply_schema(conn.cursor())
        self.assertFalse(ok)
        self.assertTrue(any("CREATE OR REPLACE VIEW v_trace" in x for x in conn.log))   # the next statements still run


class IncidentAnalysisTest(unittest.TestCase):
    """Automated incident analysis: trace as soon as a route is abnormal, compare with the usual route, report where loss starts."""

    def a(self, sig, asn):
        return {"hop_count": 9, "reached": True, "signature": sig, "asn_path": asn, "country_path": []}

    def test_route_changed_and_loss_start(self):
        from monitor import health
        L = {"real": True, "where": "transit", "where_text": "hop 6 72.14.207.14 (AS15169, transit)", "fake_hops": []}
        lines = health.incident_lines(([], self.a("B", ["AS45899", "AS7473", "AS15169"]), L, 1000.0),
                                      {"sig": "A", "asn": ["AS45899", "AS15169"]}, now=1180.0)
        self.assertEqual(lines[0], "• Trace 3 min ago: 9 hops, destination reached")
        self.assertIn("Route DIFFERS from the usual one: AS45899 > AS7473 > AS15169 (usual: AS45899 > AS15169)", lines[1])
        self.assertIn("Packet loss starts at: hop 6 72.14.207.14", lines[2])

    def test_same_route_rate_limit_only(self):
        from monitor import health
        L = {"real": False, "where": None, "where_text": None, "fake_hops": [4, 5]}
        lines = health.incident_lines(([], self.a("A", ["AS45899"]), L, 0.0), {"sig": "A", "asn": ["AS45899"]}, now=0)
        self.assertIn("Same route as usual", lines[1])
        self.assertIn("the router rate-limits ICMP, not packet loss", lines[2])
        self.assertEqual(health.incident_lines(None, None), ["• Trace: not available yet (waiting for the background trace)"])

    def test_anomaly_triggers_trace_without_loss(self):
        m = make_monitor()
        m.next_sweep = 1e12                                                # no periodic sweep
        t = {"name": "Cairo", "ip": "10.0.0.11", "country": "EG"}
        p = {"status": "UP", "median_ms": 420.0, "avg_ms": 420.0, "jitter_ms": 120.0, "loss_pct": 0.0}
        ifc = [("mon1", "192.168.0.201")]
        m.schedule_traces(ifc, [t], {ifc[0]: {t["ip"]: p}}, [("mon1", t, p, {"level": 2})])
        job = m.trace_q.get_nowait()
        self.assertEqual((job[0], job[2], job[4]["ip"]), (0, "mon1", "10.0.0.11"))
        m.trace_pending.clear()
        m.schedule_traces(ifc, [t], {ifc[0]: {t["ip"]: p}}, [("mon1", t, p, {"level": 0})])
        self.assertTrue(m.trace_q.empty())                                 # HEALTHY: no extra trace


class JobsTest(unittest.TestCase):
    """Automation jobs (systemd timers): lock against concurrent runs, freshness, report, backup."""

    def setUp(self):
        import tempfile
        from monitor import alert
        from monitor.common import DEFAULTS
        self.alert, self.sent = alert, []
        alert._state.update(last={}, hist={}, since={}, route={}, health={})
        alert.listeners.clear()
        self._orig = alert.telegram
        alert.telegram = lambda text: self.sent.append(text) or True
        self.tmp = tempfile.mkdtemp()
        self.c = dict(DEFAULTS, STATE_DIR=self.tmp, REPORT_DIR=self.tmp, BACKUP_DIR=os.path.join(self.tmp, "bk"))

    def tearDown(self):
        self.alert.telegram = self._orig
        self.alert.listeners.clear()
        self.alert._cfg["path"] = None

    def test_lock_skips_second_run(self):
        import fcntl
        from monitor import jobs
        orig_dir, jobs.LOCK_DIR = jobs.LOCK_DIR, self.tmp
        calls = []
        jobs.JOB_FN["rollup"], orig = (lambda c: calls.append(1) or True), jobs.JOB_FN["rollup"]
        try:
            with open(os.path.join(self.tmp, "netmon-rollup.lock"), "w") as held:
                fcntl.flock(held, fcntl.LOCK_EX)
                self.assertEqual(jobs.run("rollup", self.c), 0)            # another run in progress: skipped
            self.assertEqual(calls, [])
            self.assertEqual(jobs.run("rollup", self.c), 0)
            self.assertEqual(calls, [1])
        finally:
            jobs.JOB_FN["rollup"], jobs.LOCK_DIR = orig, orig_dir

    def test_freshness_one_message_then_ok(self):
        from monitor import jobs

        class FakeDB:
            ages = {"mon1": (30.0, "laptop/vnpt"), "mon2": (900.0, "laptop/vnpt")}

            def probe_age(self):
                return self.ages

            def save_alert(self, *a):
                pass
        db = FakeDB()
        orig = (jobs._db, jobs.list_subifs, jobs.iface_ip, jobs._service_state)
        jobs._db, jobs.list_subifs = (lambda: db), (lambda prefix: ["mon1", "mon2", "mon4"])
        jobs.iface_ip, jobs._service_state = (lambda n: "192.168.0.2"), (lambda u: "active")
        try:
            self.assertTrue(jobs.freshness(self.c))
            db.ages = {k: (20.0, "laptop/vnpt") for k in ("mon1", "mon2", "mon4")}
            self.alert._state["last"]["data|stale"] -= 10000                 # (independent of the cooldown)
            self.assertTrue(jobs.freshness(self.c))
        finally:
            jobs._db, jobs.list_subifs, jobs.iface_ip, jobs._service_state = orig
        self.assertEqual(len(self.sent), 2)
        self.assertTrue(self.sent[0].startswith("🟠 NetMon · DATA STALE"))
        self.assertIn("mon2 (last round 900 s ago)", self.sent[0])
        self.assertIn("mon4 (no round in the last 24 hours)", self.sent[0])
        self.assertNotIn("mon1", self.sent[0])
        self.assertTrue(self.sent[1].startswith("🟢 NetMon · DATA OK"))

    def test_freshness_db_down(self):
        from monitor import jobs
        orig = (jobs._db, jobs.list_subifs, jobs._service_state)
        jobs._db, jobs.list_subifs, jobs._service_state = (lambda: None), (lambda p: []), (lambda u: "active")
        try:
            self.assertTrue(jobs.freshness(self.c))
        finally:
            jobs._db, jobs.list_subifs, jobs._service_state = orig
        self.assertTrue(self.sent[0].startswith("🔴 NetMon · DATABASE"))

    def test_report_text(self):
        from monitor import jobs
        data = {"targets": [{"name": "Google", "ip": "8.8.8.8", "samples": 1440, "up": 1440, "median": 24.0,
                             "p95": 30.0, "loss": 0.5},
                            {"name": "Cairo", "ip": "10.0.0.11", "samples": 1440, "up": 1437, "median": 250.0,
                             "p95": 400.0, "loss": 2.0}],
                "alerts": {"UNSTABLE": 1}, "route_changes": 2, "sources": ["Laptop · VNPT"]}
        msg, full = jobs.report_text("2026-10-19", data)
        self.assertIn("Laptop · VNPT · 2 servers · 2,880 probe rounds", msg)
        self.assertIn("Servers with DOWN rounds: Cairo (3 rounds)", msg)
        self.assertIn(" 1. Cairo: median 250 ms", msg)                      # worst first
        self.assertIn("Alerts sent: UNSTABLE 1 · AS path changes: 2", msg)
        self.assertIn("All servers", full)

    def test_backup_atomic_and_keep(self):
        import subprocess
        from monitor import jobs
        os.makedirs(self.c["BACKUP_DIR"])
        old = os.path.join(self.c["BACKUP_DIR"], "netmon-2000-01-01.dump")
        open(old, "w").write("x")
        os.utime(old, (0, 0))
        seen = {}

        def fake_run(cmd, stdout=None, stderr=None, timeout=None):
            seen["cmd"] = cmd
            stdout.write(b"PGDMP...")
            return subprocess.CompletedProcess(cmd, 0, None, b"")
        orig, jobs.subprocess.run = jobs.subprocess.run, fake_run
        try:
            self.assertTrue(jobs.backup(self.c))
        finally:
            jobs.subprocess.run = orig
        self.assertEqual(seen["cmd"][:3], ["docker", "exec", "netmon-postgres-1"])
        files = os.listdir(self.c["BACKUP_DIR"])
        self.assertEqual(len(files), 1)                                     # the copy older than 7 days was deleted
        self.assertTrue(files[0].endswith(".dump") and not files[0].endswith(".tmp"))


class ConnectionStatusTest(unittest.TestCase):
    """Connection Status: majority over the last 5 probe rounds (>= 3/5 UP -> UP), not the latest round alone."""

    T = {"name": "Google", "ip": "8.8.8.8", "country": "US"}
    LV = {"source": "laptop/vnpt", "source_type": "Local", "iface": "mon1", "source_asn": "AS45899",
          "target": "8.8.8.8", "name": "Google", "country": "US", "display": "Laptop · VNPT · mon1"}

    def test_majority_table(self):
        from monitor.health import window_status
        for ups, status, avail in ((5, "UP", 1.0), (4, "UP", 0.8), (3, "UP", 0.6),
                                   (2, "DOWN", 0.4), (1, "DOWN", 0.2), (0, "DOWN", 0.0)):
            w = window_status(["UP"] * ups + ["DOWN"] * (5 - ups))
            self.assertEqual((w["status"], w["valid"]), (status, 5), ups)
            self.assertAlmostEqual(w["availability"], avail)
            self.assertEqual(w["level"], 1 if status == "UP" else 0)

    def test_order_does_not_matter_only_last_five(self):
        from monitor.health import window_status
        self.assertEqual(window_status(["UP", "UP", "DOWN", "UP", "UP"])["status"], "UP")    # example 10:00 - 10:04
        w = window_status(["DOWN"] * 3 + ["UP"] * 3)             # only the last 5 rounds count: DOWN DOWN UP UP UP
        self.assertEqual((w["status"], w["up"], w["down"]), ("UP", 3, 2))

    def test_not_enough_probes_is_unknown(self):
        from monitor.health import window_status
        self.assertEqual(window_status(["UP"])["status"], "UNKNOWN")          # 1 UP round is not enough to conclude
        self.assertEqual(window_status(["UP", "UP"])["level"], -1)
        self.assertEqual(window_status(["UP", "UP", "UP"])["status"], "UP")  # 3/5 majority reached, later rounds cannot change it
        self.assertEqual(window_status(["DOWN"] * 3)["status"], "DOWN")
        self.assertEqual(window_status(["UP", "DOWN", "UP", "DOWN"])["status"], "UNKNOWN")

    def test_error_rounds_not_counted(self):
        from monitor.health import window_status
        w = window_status(["UP", "UP", "DOWN", "DOWN", "ERROR"])
        self.assertEqual((w["status"], w["valid"], w["availability"]), ("UNKNOWN", 4, 0.5))
        w = window_status(["UP", "UP", "UP", "DOWN", "ERROR"])
        self.assertEqual((w["status"], w["availability"]), ("UP", 0.75))
        w = window_status(["ERROR"] * 5)
        self.assertEqual((w["status"], w["valid"], w["availability"]), ("UNKNOWN", 0, None))

    def test_monitor_window_counts_probe_rounds_and_resets_after_gap(self):
        m = make_monitor()
        seq = ["UP", "UP", "DOWN", "UP", "UP", "DOWN", "DOWN"]
        out = [m.window("mon1", self.T, {"status": s}, now=60.0 * k)["status"] for k, s in enumerate(seq)]
        self.assertEqual(out, ["UNKNOWN", "UNKNOWN", "UNKNOWN", "UP", "UP", "UP", "DOWN"])
        self.assertEqual(len(m.win[("mon1", "8.8.8.8")]), 5)
        w = m.window("mon1", self.T, {"status": "UP"}, now=60.0 * 6 + m._gap() + 1)   # NetMon stopped longer than ALERT_GAP
        self.assertEqual((w["status"], w["valid"]), ("UNKNOWN", 1))                  # the window starts over
        self.assertEqual(m.window("mon2", self.T, {"status": "UP"}, now=0)["valid"], 1)   # each pair has its own window

    def test_exporter_metrics_and_prune(self):
        from prometheus_client import CollectorRegistry
        from monitor.exporter import Exporter
        from monitor.health import window_status
        from monitor.probe import error_result
        reg = CollectorRegistry()
        e = Exporter(0, reg)
        up = {"status": "UP", "avg_ms": 30.0, "median_ms": 29.0, "jitter_ms": 1.0, "loss_pct": 0.0}
        e.probe("laptop/vnpt", "mon1", self.T, up, 31.0, "Laptop · VNPT · mon1", "Local", "AS45899", None,
                window_status(["UP", "DOWN", "UP", "UP", "DOWN"]))
        val = lambda n: reg.get_sample_value(n, self.LV)                               # noqa: E731
        self.assertEqual((val("netmon_status_5probe"), val("netmon_valid_probes_5probe")), (1.0, 5.0))
        self.assertAlmostEqual(val("netmon_availability_5probe"), 0.6)
        e.probe("laptop/vnpt", "mon1", self.T, error_result(20, "x"), float("inf"), "Laptop · VNPT · mon1", "Local",
                "AS45899", None, window_status(["ERROR"] * 5))
        self.assertEqual(val("netmon_status_5probe"), -1.0)                        # UNKNOWN, still shown on the dashboard
        self.assertIsNone(val("netmon_availability_5probe"))                       # no ratio: no NaN written
        e.probe("gp/JP/Tokyo", None, self.T, up, 31.0, "Tokyo, Japan", "Globalping", "AS2516")
        e.prune(300, now=__import__("time").time() + 301)                          # mon1 no longer measured
        self.assertIsNone(val("netmon_status_5probe"))
        self.assertIsNone(val("netmon_valid_probes_5probe"))
        self.assertEqual(reg.get_sample_value("netmon_up", dict(self.LV, source="gp/JP/Tokyo", source_type="Globalping",
                                                                iface="", source_asn="AS2516", display="Tokyo, Japan")),
                         1.0)                                                      # Globalping (once an hour) is not removed


if __name__ == "__main__":
    unittest.main()

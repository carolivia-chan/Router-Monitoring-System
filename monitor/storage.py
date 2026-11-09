"""Store the history in PostgreSQL. A database error never crashes the measurement loop.

Star schema (see schema.sql): before writing 1 fact row (probe_result, trace_run, trace_hop, alert_event) the matching
rows must exist in the dimension tables (source, target, asn) because of the foreign keys. _dims() adds those rows
and remembers in memory what it has added, so it does not run again for every measurement.

The connection runs in autocommit (each statement commits by itself). What must be written TOGETHER (1 trace = 1
trace_run row + its trace_hop rows) runs in 1 transaction (_tx): either both are written, or nothing is.
"""
import os
import re
import sys
import time
from contextlib import contextmanager

try:
    import psycopg2
except ImportError:                      # psycopg2 not installed -> database storage disabled
    psycopg2 = None

from monitor.common import display_for_key, isp_label, isp_name, source_type

SCHEMA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")


RETRY_SECONDS = 60          # broken connection: wait 60 s before retrying (no log flood, no slowdown of the loop)


def split_sql(text):
    """Split an SQL file into statements on ';', dropping '--' comments.
    Does not split inside '...' strings or $$ ... $$ blocks (DO / function bodies contain many ';')."""
    out, cur, i, n = [], [], 0, len(text)
    quote = dollar = False
    while i < n:
        c = text[i]
        if dollar:
            if text.startswith("$$", i):
                dollar = False
                cur.append("$$")
                i += 2
                continue
        elif quote:
            if c == "'":
                quote = False
        elif text.startswith("--", i):               # comment until the end of the line
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        elif text.startswith("$$", i):
            dollar = True
            cur.append("$$")
            i += 2
            continue
        elif c == "'":
            quote = True
        elif c == ";":
            stmt = "".join(cur).strip()
            if stmt:
                out.append(stmt)
            cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    stmt = "".join(cur).strip()
    if stmt:
        out.append(stmt)
    return out


class Storage:
    def __init__(self, dsn, schema=True):
        """schema=False: do not apply schema.sql on connect (the automation jobs in monitor/jobs.py run every
        2 minutes, do not need it, and should not lock the views each time)."""
        self.dsn, self.conn, self.schema = dsn, None, schema
        self.next_try, self.failing = 0.0, False
        self.schema_ok = False               # whether schema.sql fully ran (failed statements retried after RETRY_SECONDS)
        self._seen = set()                   # dimension keys already added in this connection session
        if psycopg2 is None:
            print("[db] psycopg2-binary is not installed, skipping PostgreSQL", file=sys.stderr)
        else:
            self._connect()

    def _connect(self):
        self.next_try = time.time() + RETRY_SECONDS
        try:
            # no statement may hang the measurement loop: wait at most 10 s for a lock, at most 120 s per statement
            # (rollup / purge), otherwise fail -> log it and skip that round. Before, 1 INSERT waiting for a lock could
            # hang NetMon forever: Prometheus kept showing the old value (UP) while PostgreSQL received no new rows.
            self.conn = psycopg2.connect(self.dsn, connect_timeout=5,
                                         options="-c lock_timeout=10s -c statement_timeout=120s")
            self.conn.autocommit = True
            self._seen = set()                       # the DB may have just been recreated: add the dimensions again
            if self.schema:
                with self.conn.cursor() as cur:
                    self.schema_ok = self._apply_schema(cur)
                    self._fill_display(cur)
            else:
                self.schema_ok = True
            if self.failing:
                print("[db] reconnected to PostgreSQL", file=sys.stderr)
            self.failing = False
        except Exception as e:
            if not self.failing:                     # report only once until the connection is back
                msg = str(e).strip().splitlines()[0] if str(e).strip() else repr(e)
                hint = (" -- check the port in NETMON_PG_DSN: docker compose exposes PostgreSQL on 127.0.0.1:PG_PORT"
                        " (default 5433), not 5432" if "refused" in msg or "could not connect" in msg else "")
                print(f"[db] cannot connect to PostgreSQL ({msg}){hint}; skipping database storage, "
                      f"retrying every {RETRY_SECONDS} s", file=sys.stderr)
            if self.conn is not None:
                try:
                    self.conn.close()                # half-open connection (failure in the schema step): close it
                except Exception:
                    pass
            self.failing, self.conn = True, None

    @staticmethod
    def _apply_schema(cur):
        """Run schema.sql ONE STATEMENT AT A TIME (each statement is its own transaction).

        Sending the whole file in 1 execute makes PostgreSQL run it as 1 transaction: the ALTER TABLE statements hold
        exclusive locks on probe_result, trace_run... until the end of the file. If Grafana is reading trace_hop and
        then trace_run at that moment, both sides wait for each other -> "deadlock detected" (HINT: See server log for
        query details). ALTER is skipped for columns that already exist (no table lock), so a normal restart never
        blocks Grafana.
        lock_timeout: if a session holds a table / view too long (Grafana reading v_probe...), SKIP THAT STATEMENT,
        continue with the next ones and keep the connection for writing data; skipped statements are retried after
        RETRY_SECONDS (see _ok). Before, 1 failing statement broke the whole connection -> NetMon wrote nothing to
        PostgreSQL and kept retrying.
        Returns True if every statement ran."""
        cur.execute("SET lock_timeout = '5s'")
        with open(SCHEMA) as f:
            stmts = split_sql(f.read())
        failed = []
        for stmt in stmts:
            m = re.match(r"\s*ALTER TABLE\s+(\w+)\s+ADD COLUMN IF NOT EXISTS\s+(\w+)", stmt, re.I)
            try:
                if m:                                # column already exists: skip, no need to lock the table
                    cur.execute("SELECT 1 FROM information_schema.columns WHERE table_name = %s AND column_name = %s",
                                (m.group(1), m.group(2)))
                    if cur.fetchone():
                        continue
                cur.execute(stmt)
            except Exception as e:                   # autocommit: a failed statement does not affect the next ones
                failed.append(f"{' '.join(stmt.split()[:4])}...: {str(e).strip().splitlines()[0]}")
        cur.execute("RESET lock_timeout")
        if failed:
            print(f"[db] {len(failed)} schema statements could not run yet (data is still written, retry in {RETRY_SECONDS} s): "
                  f"{failed[0]}", file=sys.stderr)
        return not failed

    @staticmethod
    def _fill_display(cur):
        """Fill display_name / source_location for sources that lack them (older data): built from the source key,
        with the ISP name in the exact case from the asn table (MaxMind): laptop/vnpt -> 'Laptop · VNPT',
        gp/JP/Tokyo -> 'Tokyo, Japan' (both display_name and location)."""
        cur.execute("SELECT name FROM source WHERE display IS NULL OR (kind = 'globalping' AND location IS NULL)")
        names = [r[0] for r in cur.fetchall()]
        if not names:
            return
        cur.execute("SELECT asn, org FROM asn")
        isp_names = {isp_label(a, o): isp_name(a, o) for a, o in cur.fetchall()}
        for n in names:
            d = display_for_key(n, isp_names)
            cur.execute("UPDATE source SET display = %s, location = %s WHERE name = %s",
                        (d, d if source_type(n) == "Globalping" else None, n))

    @contextmanager
    def _tx(self):
        """1 transaction: every statement in the block commits together, or rolls back together on an error.
        A rollback also loses the dimension rows added in the block -> forget the _seen cache so they are added again."""
        self.conn.autocommit = False
        try:
            with self.conn:                          # psycopg2: end of block -> COMMIT, exception -> ROLLBACK
                with self.conn.cursor() as cur:
                    yield cur
        except Exception:
            self._seen = set()
            raise
        finally:
            if not self.conn.closed:
                self.conn.autocommit = True

    def _ok(self):
        if psycopg2 is None:
            return False
        if self.conn is None or self.conn.closed:
            if time.time() < self.next_try:
                return False
            self._connect()
        elif not self.schema_ok and time.time() >= self.next_try:   # schema statements failed last time: run again
            self.next_try = time.time() + RETRY_SECONDS
            try:
                with self.conn.cursor() as cur:
                    self.schema_ok = self._apply_schema(cur)
            except Exception as e:
                print(f"[db] schema retry failed: {e}", file=sys.stderr)
        return self.conn is not None

    # ------------------------------------------------------------ dimension tables
    def _dims(self, cur, src=None, t=None, hops=None, target_ip=None, src_display=None, src_location=None):
        """Add (if missing) the source / target / asn rows that the fact row about to be written points to.
        src_display: display_name of the source ('Laptop · VNPT', 'Tokyo, Japan'); src_location: where the Globalping
        probe is ('Tokyo, Japan'). Updated when they change."""
        if src and ("s", src, src_display, src_location) not in self._seen:
            cur.execute(
                "INSERT INTO source (name, display, location) VALUES (%s, %s, %s) ON CONFLICT (name) DO UPDATE"
                " SET display = coalesce(EXCLUDED.display, source.display),"
                "     location = coalesce(EXCLUDED.location, source.location)"
                " WHERE (EXCLUDED.display IS NOT NULL AND source.display IS DISTINCT FROM EXCLUDED.display)"
                "    OR (EXCLUDED.location IS NOT NULL AND source.location IS DISTINCT FROM EXCLUDED.location)",
                (src, src_display, src_location))
            self._seen.add(("s", src, src_display, src_location))
        if t:
            key = ("t", t["ip"], t.get("name"), t.get("country"))
            if key not in self._seen:                # new server, or name / country changed in targets.csv
                cur.execute(
                    "INSERT INTO target (ip, name, country) VALUES (%s, %s, %s) ON CONFLICT (ip) DO UPDATE"
                    " SET name = EXCLUDED.name, country = EXCLUDED.country, updated_at = now()"
                    " WHERE (target.name, target.country) IS DISTINCT FROM (EXCLUDED.name, EXCLUDED.country)",
                    (t["ip"], t.get("name"), t.get("country")))
                self._seen.add(key)
        if target_ip and ("ti", target_ip) not in self._seen:
            cur.execute("INSERT INTO target (ip) VALUES (%s) ON CONFLICT (ip) DO NOTHING", (target_ip,))
            self._seen.add(("ti", target_ip))
        for h in hops or []:
            a = h.get("asn")
            if a and ("a", a) not in self._seen:
                cur.execute("INSERT INTO asn (asn, org) VALUES (%s, %s) ON CONFLICT (asn) DO NOTHING", (a, h.get("org")))
                self._seen.add(("a", a))

    # ------------------------------------------------------------ fact tables
    def save_probe(self, ts, src, iface, t, p, src_display=None, source_asn=None, src_location=None,
                   health=None, base_median=None, base_jitter=None):
        """iface: sub-interface (None for Globalping probes); source_asn: ASN of the measurement point's network;
        health: HEALTHY / DEGRADED / UNSTABLE / DOWN / UNKNOWN of this round, base_*: baselines used to assess it."""
        if not self._ok():
            return
        try:
            with self.conn.cursor() as cur:
                self._dims(cur, src, t, src_display=src_display, src_location=src_location)
                cur.execute(
                    "INSERT INTO probe_result (ts,source,source_asn,iface,target_name,target_ip,country,avg_ms,median_ms,"
                    "jitter_ms,loss_pct,status,health,base_median_ms,base_jitter_ms)"
                    " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    (ts, src, source_asn, iface, t["name"], t["ip"], t["country"], p["avg_ms"], p.get("median_ms"),
                     p["jitter_ms"], p["loss_pct"], p["status"], health, base_median, base_jitter))
        except Exception as e:
            print(f"[db] save_probe error: {e}", file=sys.stderr)

    def save_trace(self, ts, src, iface, t, hops, a, src_display=None, source_asn=None, src_location=None):
        if not self._ok():
            return
        bn = a["bottleneck"]
        L = a.get("loss") or {}
        try:
            with self._tx() as cur:                      # trace_run + trace_hop: both written or nothing
                self._dims(cur, src, t, hops, src_display=src_display, src_location=src_location)
                cur.execute(
                    "INSERT INTO trace_run (ts,source,source_asn,iface,target_ip,hop_count,reached,asn_path,country_path,"
                    "bottleneck_hop,bottleneck_ms,tool,dest_loss_pct,loss_start_hop,loss_where,loss_text)"
                    " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                    (ts, src, source_asn, iface, t["ip"], a["hop_count"], a["reached"], " > ".join(a["asn_path"]),
                     " > ".join(a["country_path"]), bn["hop"] if bn else None, bn["delta_ms"] if bn else None,
                     hops[0].get("tool") if hops else None,
                     L.get("dest_loss_pct"), (L.get("start") or {}).get("hop") if L.get("real") else None,
                     L.get("where"), L.get("where_text")))
                run_id = cur.fetchone()[0]
                cur.executemany(
                    "INSERT INTO trace_hop (run_id,hop,ip,country,asn,org,loss_pct,avg_ms,median_ms,best_ms,worst_ms)"
                    " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    [(run_id, h["hop"], h["ip"], h.get("country"), h.get("asn"), h.get("org"),
                      h["loss_pct"], h.get("avg_ms"), h.get("median_ms"), h.get("best_ms"), h.get("worst_ms"))
                     for h in hops])
        except Exception as e:
            print(f"[db] save_trace error, rolled back (no trace_run without its hops): {e}", file=sys.stderr)

    def save_alert(self, src, iface, target_ip, kind, state, message, src_display=None, status=None, severity=None):
        """1 alert_event row per Telegram message (state: alert | recover | event;
        kind: health | path | route | probe-error | no-subif; status / severity of Network Health)."""
        if not self._ok():
            return
        try:
            with self.conn.cursor() as cur:
                self._dims(cur, src, target_ip=target_ip, src_display=src_display)
                cur.execute("INSERT INTO alert_event (source, iface, target_ip, kind, state, message, status, severity)"
                            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                            (src, iface, target_ip, kind, state, message, status, severity))
        except Exception as e:
            print(f"[db] save_alert error: {e}", file=sys.stderr)

    # ------------------------------------------------------------ aggregation + cleanup
    def rollup(self):
        """Aggregate probe_result -> probe_hourly. Recomputes from the latest hour already present (that hour may have
        been incomplete last time), so it is correct no matter how often it runs; the first run aggregates all old data.
        ERROR rounds (fping failed, no data) are excluded: they neither lower availability nor add 100% loss.
        Returns True when it finished (used as the exit code by monitor/jobs.py)."""
        if not self._ok():
            return False
        try:
            with self.conn.cursor() as cur:
                cur.execute("SELECT coalesce(max(hour), '-infinity'::timestamptz) FROM probe_hourly")
                since = cur.fetchone()[0]
                # empty iface / source_asn ('') instead of NULL because they are primary key columns (Globalping has no iface)
                cur.execute(
                    "INSERT INTO probe_hourly (hour, source, iface, target_ip, source_asn, samples, up_samples, median_ms,"
                    " p95_ms, avg_jitter_ms, avg_loss_pct)"
                    " SELECT date_trunc('hour', ts), source, coalesce(iface, ''), target_ip, coalesce(source_asn, ''),"
                    "        count(*), count(*) FILTER (WHERE status = 'UP'),"
                    "        percentile_cont(0.5) WITHIN GROUP (ORDER BY median_ms),"
                    "        percentile_cont(0.95) WITHIN GROUP (ORDER BY median_ms),"
                    "        avg(jitter_ms), avg(loss_pct)"
                    " FROM probe_result WHERE source IS NOT NULL AND status <> 'ERROR' AND ts >= %s"
                    " GROUP BY 1, 2, 3, 4, 5"
                    " ON CONFLICT (hour, source, iface, target_ip, source_asn) DO UPDATE SET"
                    "   samples = EXCLUDED.samples, up_samples = EXCLUDED.up_samples, median_ms = EXCLUDED.median_ms,"
                    "   p95_ms = EXCLUDED.p95_ms, avg_jitter_ms = EXCLUDED.avg_jitter_ms,"
                    "   avg_loss_pct = EXCLUDED.avg_loss_pct", (since,))
                print(f"[db] rollup: {cur.rowcount} probe_hourly rows (from {since})")
            return True
        except Exception as e:
            print(f"[db] rollup error: {e}", file=sys.stderr)
            return False

    def purge(self, days, long_days=365):
        """Raw data (probe_result, trace_run + trace_hop) is kept `days` days;
        aggregates (probe_hourly) and alert history are kept `long_days` days. Returns True when it finished."""
        if not self._ok():
            return False
        try:
            with self.conn.cursor() as cur:
                done = []
                for sql, n in (("DELETE FROM probe_result WHERE ts < now() - %s * interval '1 day'", days),
                               ("DELETE FROM trace_run WHERE ts < now() - %s * interval '1 day'", days),
                               ("DELETE FROM probe_hourly WHERE hour < now() - %s * interval '1 day'", long_days),
                               ("DELETE FROM alert_event WHERE ts < now() - %s * interval '1 day'", long_days)):
                    cur.execute(sql, (n,))
                    done.append(f"{sql.split()[2]} {cur.rowcount}")
                print(f"[db] purge: deleted expired rows: {', '.join(done)}")
            return True
        except Exception as e:
            print(f"[db] purge error: {e}", file=sys.stderr)
            return False

    # ------------------------------------------------------------ queries for the automation jobs (monitor/jobs.py)
    def probe_age(self):
        """Latest probe round of each monN in the last 24 hours: {iface: (seconds ago, source)}. Error -> None."""
        if not self._ok():
            return None
        try:
            with self.conn.cursor() as cur:
                cur.execute("SELECT iface, extract(epoch FROM now() - max(ts)), max(source) FROM probe_result"
                            " WHERE iface IS NOT NULL AND ts > now() - interval '1 day' GROUP BY iface")
                return {r[0]: (float(r[1]), r[2]) for r in cur.fetchall()}
        except Exception as e:
            print(f"[db] probe_age error: {e}", file=sys.stderr)
            return None

    def report_rows(self, start, end):
        """Report figures of the local measurement machine in [start, end): each server (from probe_hourly), alerts by
        level, number of AS path changes, names of the sources. Error -> None."""
        if not self._ok():
            return None
        try:
            with self.conn.cursor() as cur:
                cur.execute(
                    "SELECT t.name, h.target_ip, sum(h.samples), sum(h.up_samples),"
                    "       percentile_cont(0.5) WITHIN GROUP (ORDER BY h.median_ms), max(h.p95_ms), avg(h.avg_loss_pct)"
                    " FROM probe_hourly h JOIN target t ON t.ip = h.target_ip"
                    " WHERE h.iface <> '' AND h.hour >= %s AND h.hour < %s GROUP BY 1, 2", (start, end))
                targets = [{"name": r[0] or r[1], "ip": r[1], "samples": int(r[2]), "up": int(r[3]),
                            "median": r[4], "p95": r[5], "loss": float(r[6] or 0)} for r in cur.fetchall()]
                cur.execute("SELECT coalesce(status, kind), count(*) FROM alert_event"
                            " WHERE state = 'alert' AND ts >= %s AND ts < %s GROUP BY 1 ORDER BY 2 DESC", (start, end))
                alerts = {r[0]: int(r[1]) for r in cur.fetchall()}
                cur.execute("SELECT count(*) FROM v_route_change"
                            " WHERE ts >= %s AND ts < %s AND source NOT LIKE 'gp/%%'", (start, end))
                changes = int(cur.fetchone()[0])
                cur.execute("SELECT DISTINCT s.display FROM probe_hourly h JOIN source s ON s.name = h.source"
                            " WHERE h.iface <> '' AND h.hour >= %s AND h.hour < %s ORDER BY 1", (start, end))
                sources = [r[0] for r in cur.fetchall() if r[0]]
            return {"targets": targets, "alerts": alerts, "route_changes": changes, "sources": sources}
        except Exception as e:
            print(f"[db] report_rows error: {e}", file=sys.stderr)
            return None

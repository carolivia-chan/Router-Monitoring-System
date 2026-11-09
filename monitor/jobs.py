"""Scheduled automation jobs: systemd timer -> netmon-job@<job>.service -> main.py --job <job>.

  rollup     hourly     aggregate probe_result -> probe_hourly (Storage.rollup: correct no matter how often it runs)
  retention  daily      delete expired data (PG_RETENTION_DAYS / PG_LONG_RETENTION_DAYS)
  backup     daily      pg_dump of PostgreSQL (inside container PG_CONTAINER) -> BACKUP_DIR, kept BACKUP_KEEP_DAYS days
  freshness  2 minutes  a running monN whose measurements have not reached PostgreSQL for FRESHNESS_MAX seconds, or
                        PostgreSQL unreachable -> Telegram (morning of 20/10: NetMon wrote to the wrong port 5432 and
                        3 hours of data were lost unnoticed, because Prometheus still showed UP)
  report     daily      network report of the previous day -> Telegram + REPORT_DIR/netmon-report-<date>.txt

Rules shared by every job:
  - hold the lock /run/lock/netmon-<job>.lock: never 2 runs at once, even when run by hand while the timer runs it;
  - re-running never duplicates data (rollup ON CONFLICT, backup overwrites the day's copy, report overwrites the
    day's file);
  - log to stdout / stderr -> journalctl -u netmon-job@<job>; exit code 0 = done, 1 = error (systemctl --failed).
Prometheus still covers real time (scrape every 15 s); these jobs cover the history in PostgreSQL.
"""
import datetime as dt
import fcntl
import glob
import os
import statistics
import subprocess
import sys
import time
import urllib.parse

from monitor import alert
from monitor.common import iface_ip, list_subifs
from monitor.storage import Storage

JOBS = ("rollup", "retention", "backup", "freshness", "report")
LOCK_DIR = "/run/lock"


def run(name, conf):
    """Run 1 job and return its exit code."""
    lock_path = os.path.join(LOCK_DIR if os.path.isdir(LOCK_DIR) else "/tmp", f"netmon-{name}.lock")
    with open(lock_path, "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(f"[job] {name}: the previous run has not finished, skipping this one")
            return 0
        t0 = time.time()
        try:
            ok = JOB_FN[name](conf)
        except Exception as e:
            print(f"[job] {name}: error {type(e).__name__}: {e}", file=sys.stderr)
            ok = False
        print(f"[job] {name}: {'done' if ok else 'FAILED'} after {time.time() - t0:.1f} s")
        return 0 if ok else 1


def _db():
    """PostgreSQL connection for 1 job (schema.sql is not re-applied). Not configured / unreachable -> None."""
    dsn = os.environ.get("NETMON_PG_DSN")
    if not dsn:
        print("[job] NETMON_PG_DSN is not set in /etc/netmon/netmon.env", file=sys.stderr)
        return None
    st = Storage(dsn, schema=False)
    return st if st.conn is not None else None


def _service_state(unit):
    try:
        return subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True,
                              timeout=5).stdout.strip() or "unknown"
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"


# ------------------------------------------------------------------ rollup / retention
def rollup(conf):
    st = _db()
    return bool(st and st.rollup())


def retention(conf):
    st = _db()
    return bool(st and st.purge(int(conf["PG_RETENTION_DAYS"]), int(conf.get("PG_LONG_RETENTION_DAYS", 365))))


# ------------------------------------------------------------------ backup
def backup(conf):
    """pg_dump in custom format (-Fc, restore with pg_restore) run INSIDE the PostgreSQL container, so the pg_dump
    version always matches the server (the machine has another PostgreSQL on port 5432 whose pg_dump may differ).
    Written to a temporary file, then renamed: a half-written backup is never left behind."""
    u = urllib.parse.urlparse(os.environ.get("NETMON_PG_DSN", ""))
    user, db = u.username or "netmon", (u.path or "").lstrip("/") or "netmon"
    folder, keep, ctr = conf["BACKUP_DIR"], int(conf["BACKUP_KEEP_DAYS"]), conf["PG_CONTAINER"]
    os.makedirs(folder, mode=0o700, exist_ok=True)
    out = os.path.join(folder, f"netmon-{dt.date.today():%Y-%m-%d}.dump")
    tmp = out + ".tmp"
    with open(tmp, "wb") as f:
        r = subprocess.run(["docker", "exec", ctr, "pg_dump", "-U", user, "-d", db, "-Fc"],
                           stdout=f, stderr=subprocess.PIPE, timeout=1800)
    if r.returncode != 0 or os.path.getsize(tmp) == 0:
        os.remove(tmp)
        print(f"[job] backup: pg_dump failed (container {ctr}): {r.stderr.decode(errors='replace').strip()}",
              file=sys.stderr)
        return False
    os.replace(tmp, out)
    cutoff = time.time() - keep * 86400
    old = [p for p in glob.glob(os.path.join(folder, "netmon-*.dump")) if os.path.getmtime(p) < cutoff]
    for p in old:
        os.remove(p)
    print(f"[job] backup: {out} ({os.path.getsize(out) / 1e6:.1f} MB), deleted {len(old)} copies older than {keep} days")
    return True


# ------------------------------------------------------------------ freshness
def freshness(conf):
    """Is the measurement data still fresh? 1 message for all late monN (not N messages), reminded after
    ALERT_COOLDOWN, and a recovery message once new data arrives. Sending state is kept in jobs_state.json
    (state.json belongs to netmon.service)."""
    alert.load_state(os.path.join(conf["STATE_DIR"], "jobs_state.json"), conf["BASELINE_SAMPLES"])
    cooldown = int(conf["ALERT_COOLDOWN"])
    limit = max(int(conf["FRESHNESS_MAX"]), 3 * int(conf["INTERVAL"]))
    ifaces = [n for n in list_subifs(conf["NAME_PREFIX"]) if iface_ip(n)]
    svc = _service_state("netmon.service")
    st = _db()
    alert.evaluate("db|down", st is None,
                   "🔴 NetMon · DATABASE\nCannot connect to PostgreSQL (NETMON_PG_DSN): NetMon cannot store data, "
                   "the PostgreSQL panels in Grafana will be empty.",
                   "🟢 NetMon · DATABASE\nReconnected to PostgreSQL", cooldown)
    if st is not None:
        alert.listeners.append(lambda key, state, text, meta: st.save_alert(
            None, None, None, key.split("|")[-1], state, text, None, meta.get("status"), meta.get("severity")))
        ages = st.probe_age()
        if ages is None:
            alert.save_state()
            return False
        stale = []
        for i in ifaces:
            age, _src = ages.get(i, (None, None))
            if age is None or age > limit:
                stale.append(f"{i} ({'no round in the last 24 hours' if age is None else f'last round {int(age)} s ago'})")
        alert.evaluate("data|stale", bool(stale),
                       f"🟠 NetMon · DATA STALE\nPostgreSQL has received no new measurement for more than {limit} s: "
                       f"{', '.join(stale)}\nnetmon.service: {svc}. Check: journalctl -u netmon -n 50",
                       "🟢 NetMon · DATA OK\nPostgreSQL is receiving new measurements from every running monN", cooldown)
        print(f"[job] freshness: {len(ifaces)} monN running, {len(stale)} late (limit {limit} s); netmon: {svc}")
    alert.save_state()
    return True


# ------------------------------------------------------------------ report
def report_text(day, data, top=5):
    """(short Telegram message, full file content) of the report for day `day`."""
    ts = data["targets"]
    if not ts:
        msg = f"📊 NetMon · Daily report {day}\nNo measurement data from the local measurement machine on that day."
        return msg, msg + "\n"
    samples, up = sum(t["samples"] for t in ts), sum(t["up"] for t in ts)
    meds = [t["median"] for t in ts if t["median"] is not None]
    for t in ts:
        t["avail"] = 100.0 * t["up"] / t["samples"] if t["samples"] else 0.0
        t["score"] = (t["median"] if t["median"] is not None else 1e9) + 10 * t["loss"]
    worst = sorted(ts, key=lambda t: t["score"], reverse=True)
    down = [t for t in ts if t["up"] < t["samples"]]
    row = lambda t: (f"{t['name']}: median {t['median']:.0f} ms, p95 {t['p95'] or 0:.0f} ms, "  # noqa: E731
                     f"loss {t['loss']:.1f}%, availability {t['avail']:.2f}%") if t["median"] is not None \
        else f"{t['name']}: no reply, availability {t['avail']:.2f}%"
    alerts = ", ".join(f"{k} {v}" for k, v in data["alerts"].items()) or "none"
    summary = [f"📊 NetMon · Daily report {day}",
               f"Sources: {', '.join(data['sources']) or '?'} · {len(ts)} servers · {samples:,} probe rounds",
               f"Availability: {100.0 * up / samples:.2f}% · median latency (median over servers): "
               f"{statistics.median(meds) if meds else 0:.0f} ms · mean loss: "
               f"{statistics.mean(t['loss'] for t in ts):.2f}%",
               "Servers with DOWN rounds: " + (", ".join(f"{t['name']} ({t['samples'] - t['up']} rounds)" for t in down)
                                               if down else "none")]
    tail = [f"Alerts sent: {alerts} · AS path changes: {data['route_changes']}"]
    msg = summary + [f"{min(top, len(worst))} worst routes (median + 10 x loss%):"] + \
        [f" {n}. {row(t)}" for n, t in enumerate(worst[:top], 1)] + tail
    full = summary + ["", "All servers (worst first):"] + [f" - {row(t)}" for t in worst] + [""] + tail
    return "\n".join(msg), "\n".join(full) + "\n"


def report(conf):
    st = _db()
    if st is None:
        return False
    st.rollup()                                      # make sure probe_hourly is complete up to the latest hour
    today = dt.datetime.now().astimezone().replace(hour=0, minute=0, second=0, microsecond=0)
    start = today - dt.timedelta(days=1)
    data = st.report_rows(start, today)
    if data is None:
        return False
    msg, full = report_text(start.date(), data)
    os.makedirs(conf["REPORT_DIR"], exist_ok=True)
    path = os.path.join(conf["REPORT_DIR"], f"netmon-report-{start.date()}.txt")
    with open(path, "w") as f:
        f.write(full)
    alert.telegram(msg[:4000] + f"\nDetails: {path}")
    print(f"[job] report: {path}")
    return True


JOB_FN = {"rollup": rollup, "retention": retention, "backup": backup, "freshness": freshness, "report": report}

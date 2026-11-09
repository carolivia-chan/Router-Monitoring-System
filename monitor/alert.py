"""Telegram alerts: only report problems that last (ALERT_HOLD), cooldown against spam, 'recovered' messages,
baselines (the normal level of each route), Network Health tracking (track / decide).

State is kept in STATE_DIR/state.json (default /var/lib/netmon/state.json):
  last   : key -> time of the latest alert sent (cooldown)
  since  : key -> [time the problem started, last time it was still seen]  (duration counting)
  hist   : key -> recent measured values (for the baseline)
  route  : key -> current stable route + new candidate route waiting for ALERT_HOLD
  health : key -> incident being tracked + level already alerted (see track)
So restarting the service or running --once several times neither repeats messages nor relearns baselines.

Every message names the measurement point with the same display name (e.g. 'Laptop · VNPT · mon1 -> ...'), so no
[machine name] prefix is added as before.

The probe thread and the background trace threads both read/write _state: every function below holds the same lock
(_lock), so save_state() never writes the file while another thread is changing the data.
"""
import functools
import json
import os
import statistics
import threading
import time
import urllib.parse
import urllib.request

_state = {"last": {}, "hist": {}, "since": {}, "route": {}, "health": {}}
STALE = 900          # not re-evaluated for 15 minutes (service stopped, --once runs far apart) -> start counting over
_cfg = {"path": None, "max": 30, "warned": False}
listeners = []       # functions (key, state, text, meta) called for every message sent; main.py records alert_event
SEV = {None: -1, "WARNING": 0, "CRITICAL": 1}
_lock = threading.RLock()


def _locked(fn):
    @functools.wraps(fn)
    def wrap(*a, **kw):
        with _lock:
            return fn(*a, **kw)
    return wrap


def _notify(key, state, text, meta=None):
    """Send to Telegram, then notify the listeners (state: alert | recover | event; meta: status, severity)."""
    telegram(text)
    for fn in listeners:
        try:
            fn(key, state, text, meta or {})
        except Exception as e:
            print(f"[alert] listener error: {e}")


notify = _notify


def telegram(text):
    token, chat = os.environ.get("TELEGRAM_BOT_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
    if not token or not chat:
        print("[alert] (Telegram not configured)", text)
        return False
    data = urllib.parse.urlencode({"chat_id": chat, "text": text}).encode()
    try:
        urllib.request.urlopen(f"https://api.telegram.org/bot{token}/sendMessage", data, timeout=10)
        return True
    except Exception as e:
        print("[alert] Telegram send error:", e)
        return False


# ------------------------------------------------------------------ state
@_locked
def load_state(path, hist_max=30):
    """Read state.json (if present). Called once at startup."""
    _cfg["path"], _cfg["max"] = path, int(hist_max)
    try:
        with open(path) as f:
            data = json.load(f)
        for k in ("last", "hist", "since", "route", "health"):
            _state[k] = dict(data.get(k, {}))
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"[alert] ignoring corrupted state file {path}: {e}")


@_locked
def save_state():
    """Write state.json (to a temporary file, then rename: a half-written file is never left behind)."""
    path = _cfg["path"]
    if not path:
        return
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path + ".tmp", "w") as f:
            json.dump(_state, f)
        os.replace(path + ".tmp", path)
    except OSError as e:
        if not _cfg["warned"]:                       # warn only once, no log spam
            print(f"[alert] cannot write {path}: {e} (baselines/cooldowns are kept in memory only)")
            _cfg["warned"] = True


@_locked
def baseline(key, value, how="min", min_samples=5):
    """Return the normal level COMPUTED FROM PREVIOUS ROUNDS, then add `value` to the history.

    how="min"    : smallest recent value  -> used for latency (median), because RTT cannot go below what the
                   path allows; congestion only makes it rise.
    how="median" : recent median          -> used for jitter.
    Returns None while the history has fewer than `min_samples` values (still learning).
    """
    h = _state["hist"].setdefault(key, [])
    ref = None
    if len(h) >= min_samples:
        ref = min(h) if how == "min" else statistics.median(h)
    if value is not None:
        learn(key, value)
    return ref


@_locked
def learn(key, value):
    """Add 1 value to the baseline history. main.py only calls it when that metric is NOT abnormal, so the baseline
    does not 'learn' the incident itself (15 minutes of high jitter would raise the median and clear the alert)."""
    if value is None:
        return
    h = _state["hist"].setdefault(key, [])
    h.append(value)
    del h[:-_cfg["max"]]


# ------------------------------------------------------------------ sending alerts
@_locked
def evaluate(key, bad, text, ok_text, cooldown, hold=0):
    """bad=True continuously for >= hold seconds -> send an alert (then at most once per cooldown).
    bad=False -> reset the counter; if an alert WAS sent before, send ok_text.
    A problem shorter than hold (a few minutes of loss that goes away) sends nothing, not even a recovery message."""
    now, last, since = time.time(), _state["last"], _state["since"]
    if bad:
        start, seen = since.get(key, (now, now))
        if now - seen > STALE:                       # not evaluated for a long time: do not accumulate
            start = now
        since[key] = [start, now]
        if now - start >= hold and now - last.get(key, 0) >= cooldown:
            last[key] = now
            if hold:                                 # append the duration to the end of the first line
                head, sep, rest = text.partition("\n")
                text = f"{head} (lasting {round((now - start) / 60)} min){sep}{rest}"
            _notify(key, "alert", text)
    else:
        since.pop(key, None)
        if key in last:
            del last[key]
            if ok_text:
                _notify(key, "recover", ok_text)


@_locked
def route_changed(key, info, hold=0):
    """Track the route of 1 (monN, server) pair. info = {"sig", "asn", "cc", "hops"}.

    A route change is only reported once the NEW route has stayed the same for >= hold seconds. Flapping (ECMP, a hop
    that sometimes replies and sometimes not) that returns to the old route before that time -> not reported.
    Returns (old route, new route) when a report is due, otherwise None. First time seen -> recorded, not reported.
    """
    now, routes = time.time(), _state["route"]
    r = routes.get(key)
    if r is None:
        routes[key] = {"stable": info, "cand": None, "since": None}
        return None
    if info["sig"] == r["stable"]["sig"]:             # still (or back) on the old route
        r["cand"] = r["since"] = None
        return None
    if r["cand"] is None or info["sig"] != r["cand"]["sig"]:
        r["cand"], r["since"] = info, now             # new route: start counting
    if now - r["since"] >= hold:
        old = r["stable"]
        r["stable"], r["cand"], r["since"] = info, None, None
        return old, info
    return None


# ------------------------------------------------------------------ Network Health: lasting incidents
@_locked
def track(key, level, hold, down_hold, clear=3, ratio=0.5, gap=300, now=None):
    """Record 1 probe round of a route (level: 0 HEALTHY, 1 DEGRADED, 2 UNSTABLE, 3 DOWN; None = UNKNOWN).

    Each level L has its own "episode" (starting at the first round with level >= L):
      - an episode only ends after `clear` CONSECUTIVE rounds below L: a flapping connection (bad - good - bad)
        stays 1 episode, a single good round does not reset the counter;
      - an episode is CONFIRMED once it lasts >= hold (DOWN: down_hold) and >= `ratio` of its rounds are at level >= L;
      - if data is missing for more than `gap` seconds (service stopped, measurement errors...) every episode is
        cleared: an incident is not considered continuous across a period without data. UNKNOWN rounds do not count,
        so many consecutive UNKNOWN rounds also make a gap.
    UNSTABLE does not require passing through DEGRADED first: both episodes are counted in parallel.
    Returns (confirmed level 0..3, seconds since the anomaly started); (None, 0) for an UNKNOWN round."""
    now = time.time() if now is None else now
    h = _state["health"].setdefault(key, {"last": None, "ep": {}, "sent": 0, "sev": None, "sent_at": 0,
                                          "start": None})
    if level is None:
        return None, 0
    if h["last"] is not None and now - h["last"] > gap:
        h["ep"] = {}
    h["last"] = now
    for L in (1, 2, 3):
        e = h["ep"].get(str(L))
        if level >= L:
            if e is None:
                e = h["ep"][str(L)] = {"since": now, "below": 0, "n": 0, "bad": 0}
            e["below"], e["n"], e["bad"] = 0, e["n"] + 1, e["bad"] + 1
        elif e is not None:
            e["below"], e["n"] = e["below"] + 1, e["n"] + 1
            if e["below"] >= clear:
                del h["ep"][str(L)]
    confirmed = 0
    for L in (3, 2, 1):
        e = h["ep"].get(str(L))
        if e and now - e["since"] >= (down_hold if L == 3 else hold) and e["bad"] / e["n"] >= ratio:
            confirmed = L
            break
    e1 = h["ep"].get("1")
    return confirmed, (now - e1["since"]) if e1 else 0


@_locked
def decide(key, confirmed, sev, cooldown, now=None):
    """Decide what to send after track():
      'alert'   the new confirmed level is higher than the level already reported, or the severity rose
                (WARNING -> CRITICAL): send immediately;
      'remind'  the incident continues and the cooldown since the last message has passed: remind with the new duration;
      'recover' the episode has ended (`clear` consecutive good rounds) after an alert was sent.
    A lower level (UNSTABLE -> DEGRADED) is not sent separately; the reminder shows the current level."""
    now = time.time() if now is None else now
    h = _state["health"].get(key)
    if h is None or confirmed is None:
        return None
    if confirmed and (confirmed > h["sent"] or SEV[sev] > SEV[h["sev"]]):
        if not h["sent"]:
            h["start"] = h["ep"]["1"]["since"] if "1" in h["ep"] else now
        h["sent"], h["sev"], h["sent_at"] = max(h["sent"], confirmed), max(h["sev"], sev, key=SEV.get), now
        return "alert"
    if confirmed and h["sent"] and now - h["sent_at"] >= cooldown:
        h["sent_at"] = now
        return "remind"
    if h["sent"] and "1" not in h["ep"]:
        return "recover"
    return None


@_locked
def recovered(key, now=None):
    """After the recovery message: return (worst level reported, severity, incident seconds) and clear the sending state."""
    now = time.time() if now is None else now
    h = _state["health"][key]
    out = (h["sent"], h["sev"], now - (h["start"] or now))
    h.update(sent=0, sev=None, sent_at=0, start=None)
    return out


@_locked
def event(key, text, cooldown):
    """One-off event (e.g. a route change)."""
    now, last = time.time(), _state["last"]
    if now - last.get(key, 0) >= cooldown:
        last[key] = now
        _notify(key, "event", text)

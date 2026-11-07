import contextlib
import hashlib
import json
import os
import re
import sqlite3
import threading
import time

import config

def _load_accounts():
    if not config.ACCOUNTS_FILE:
        return {}
    try:
        with open(config.ACCOUNTS_FILE) as f:
            data = json.load(f)
        return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


# account id -> friendly name; empty unless WAF_ACCOUNTS_FILE points at a JSON object
ACCOUNT_NAMES = _load_accounts()

_local = threading.local()
_write_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY, ts INTEGER NOT NULL, account TEXT, account_name TEXT, region TEXT,
  ip TEXT, country TEXT, resource TEXT, svc TEXT, host TEXT, path TEXT, args TEXT, method TEXT,
  ua TEXT, req_id TEXT, referrer TEXT, xff TEXT, status INTEGER,
  rule TEXT, rule_type TEXT, rule_scope TEXT, rule_short TEXT, inner_rule TEXT, term_label TEXT,
  term_action TEXT, cond TEXT, match_loc TEXT, match_det TEXT, matched_field TEXT,
  evaluated_groups TEXT, nonterm_rules TEXT, ja3 TEXT, ja4 TEXT, labels TEXT, rate_limit INTEGER
);
CREATE INDEX IF NOT EXISTS ix_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ix_rule ON events(rule, ts);
CREATE INDEX IF NOT EXISTS ix_ip ON events(ip, ts);
CREATE INDEX IF NOT EXISTS ix_host ON events(host, ts);
CREATE INDEX IF NOT EXISTS ix_account ON events(account, ts);
CREATE TABLE IF NOT EXISTS minute_agg (
  minute INTEGER NOT NULL, src TEXT NOT NULL, account TEXT NOT NULL, host TEXT NOT NULL,
  disp TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (minute, src, account, host, disp)
);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS ip_info (
  addr TEXT PRIMARY KEY, org TEXT, net_name TEXT, asn TEXT, geo_country TEXT, geo_city TEXT,
  via TEXT, fetched INTEGER NOT NULL
);
DROP VIEW IF EXISTS v_events;
CREATE VIEW v_events AS
  SELECT events.*, ip_info.org AS org, ip_info.net_name AS net_name, ip_info.asn AS asn,
         ip_info.geo_country AS geo_country, ip_info.geo_city AS geo_city, ip_info.via AS org_via,
         CASE WHEN ip_info.addr IS NULL THEN 'pending' WHEN ip_info.org IS NULL THEN 'unknown' ELSE 'done' END AS org_state
  FROM events LEFT JOIN ip_info ON ip_info.addr = events.ip;
"""

COLUMNS = [
    "id", "ts", "account", "account_name", "region", "ip", "country", "resource", "svc", "host", "path",
    "args", "method", "ua", "req_id", "referrer", "xff", "status", "rule", "rule_type", "rule_scope",
    "rule_short", "inner_rule", "term_label", "term_action", "cond", "match_loc", "match_det",
    "matched_field", "evaluated_groups", "nonterm_rules", "ja3", "ja4", "labels", "rate_limit",
]

# Columns the UI may sort on.
SORTABLE = {"org", "ts", "account_name", "ip", "country", "host", "path", "method", "status", "rule", "rule_type", "inner_rule"}


def _deadline_check():
    # Non-zero aborts the running statement with sqlite3.OperationalError("interrupted").
    d = getattr(_local, "deadline", 0)
    return 1 if d and time.monotonic() > d else 0


def _open(check_same_thread=True):
    os.makedirs(config.DATA_DIR, exist_ok=True)
    c = sqlite3.connect(config.DB_PATH, timeout=30, check_same_thread=check_same_thread)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA synchronous=NORMAL")
    return c


def conn():
    """Per-thread connection. API threads may set a deadline with set_deadline(); ingest threads never do."""
    c = getattr(_local, "c", None)
    if c is None:
        c = _open()
        c.set_progress_handler(_deadline_check, 20000)
        _local.c = c
    return c


@contextlib.contextmanager
def deadline(seconds):
    """Bound the run time of queries issued from the current thread inside the block."""
    _local.deadline = time.monotonic() + seconds
    try:
        yield
    finally:
        _local.deadline = 0


def stream_conn():
    """Private connection for a streaming response, which may be iterated from different worker threads."""
    return _open(check_same_thread=False)


def init():
    with _write_lock:
        c = conn()
        c.executescript(SCHEMA)
        c.commit()


def meta_get(k, default=None):
    r = conn().execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
    return r["v"] if r else default


def meta_set(k, v):
    with _write_lock:
        c = conn()
        c.execute("INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, str(v)))
        c.commit()


def _clean(v):
    if v is None or v == "" or v == "null" or v == "[null]":
        return None
    return v


def classify_rule(rule, rule_type, evaluated_groups=None):
    """Returns (scope, short display name) for a terminating rule.

    Scopes: aws-managed, managed (other managed rule groups), rate-based, custom, other.
    """
    short = rule
    for p in config.RULE_STRIP_PREFIXES:
        if rule.startswith(p) and len(rule) > len(p):
            short = rule[len(p):]
            break
    if rule_type == "MANAGED_RULE_GROUP":
        if "AWSManagedRules" in rule or (evaluated_groups or "").startswith("AWS#") or "AWS#" in (evaluated_groups or ""):
            if short.startswith("AWS-"):
                short = short[4:]
            return "aws-managed", short
        return "managed", short
    if rule_type == "RATE_BASED":
        return "rate-based", short
    if rule_type == "REGULAR":
        return "custom", short
    return "other", short


_RESOURCE = re.compile(r"^\d+-(?:app|net)/([^/]+)/")


def enrich(row, src_region):
    """Turn a raw Athena row into the stored event shape, including the terminating rule."""
    r = {k: _clean(v) for k, v in row.items()}
    rule = r.get("rule") or "unknown"
    rtype = r.get("rule_type")
    inner = r.get("inner_rule") if rtype == "MANAGED_RULE_GROUP" else None
    scope, short = classify_rule(rule, rtype, r.get("evaluated_groups"))
    res = r.get("resource") or ""
    m = _RESOURCE.match(res)
    labels = r.get("labels") or ""
    label_names = re.findall(r'"name"\s*:\s*"([^"]+)"', labels)
    ts = int(r["ts"])
    ident = r.get("req_id") or hashlib.sha1(f"{ts}|{r.get('ip')}|{r.get('path')}|{rule}".encode()).hexdigest()
    ident = f"{src_region}:{ident}"
    out = {
        "id": ident, "ts": ts, "account": r.get("account"),
        "account_name": ACCOUNT_NAMES.get(r.get("account") or "", r.get("account")),
        "region": r.get("region"), "ip": r.get("ip"), "country": r.get("country"),
        "resource": m.group(1) if m else (res or None), "svc": r.get("svc"),
        "host": r.get("host"), "path": r.get("path"), "args": (r.get("args") or "")[:2000] or None,
        "method": (r.get("method") or "").upper() or None, "ua": (r.get("ua") or "")[:1000] or None,
        "req_id": r.get("req_id"), "referrer": (r.get("referrer") or "")[:1000] or None, "xff": r.get("xff"),
        "status": int(r["status"]) if r.get("status") else None,
        "rule": rule, "rule_type": rtype, "rule_scope": scope, "rule_short": short, "inner_rule": inner,
        "term_label": f"{rule} > {inner}" if inner else rule,
        "term_action": r.get("term_action") or "BLOCK", "cond": r.get("cond"), "match_loc": r.get("match_loc"),
        "match_det": r.get("match_det"), "matched_field": r.get("matched_field"),
        "evaluated_groups": r.get("evaluated_groups"), "nonterm_rules": r.get("nonterm_rules"),
        "ja3": r.get("ja3"), "ja4": r.get("ja4"), "labels": "|".join(label_names) or None,
        "rate_limit": int(r["rate_limit"]) if r.get("rate_limit") else None,
    }
    return out


def insert_events(events):
    """Returns the events that were new."""
    if not events:
        return []
    ph = ",".join("?" * len(COLUMNS))
    new = []
    with _write_lock:
        c = conn()
        for e in events:
            cur = c.execute(f"INSERT OR IGNORE INTO events({','.join(COLUMNS)}) VALUES({ph})", [e[k] for k in COLUMNS])
            if cur.rowcount:
                new.append(e)
        c.commit()
    return new


def replace_agg(src, start_minute, end_minute, rows):
    with _write_lock:
        c = conn()
        c.execute("DELETE FROM minute_agg WHERE src=? AND minute>=? AND minute<?", (src, start_minute, end_minute))
        c.executemany(
            "INSERT OR REPLACE INTO minute_agg(minute,src,account,host,disp,n) VALUES(?,?,?,?,?,?)",
            [(int(r["minute"]), src, r["account"] or "", r["host"] or "", r["disp"], int(r["n"])) for r in rows],
        )
        c.commit()


def prune():
    cutoff = int((time.time() - config.RETENTION_HOURS * 3600) * 1000)
    with _write_lock:
        c = conn()
        c.execute("DELETE FROM events WHERE ts<?", (cutoff,))
        c.execute("DELETE FROM minute_agg WHERE minute<?", (cutoff // 1000,))
        c.commit()


def ips_needing_info(limit=200, retry_after=1800):
    cutoff = int(time.time()) - retry_after
    return [r[0] for r in conn().execute(
        "SELECT e.ip FROM events e LEFT JOIN ip_info i ON i.addr = e.ip "
        "WHERE e.ip IS NOT NULL AND (i.addr IS NULL OR (i.org IS NULL AND i.fetched < ?)) "
        "GROUP BY e.ip ORDER BY max(e.ts) DESC LIMIT ?", (cutoff, limit))]


def save_ip_info(recs):
    now = int(time.time())
    with _write_lock:
        c = conn()
        c.executemany(
            "INSERT OR REPLACE INTO ip_info(addr,org,net_name,asn,geo_country,geo_city,via,fetched) VALUES(?,?,?,?,?,?,?,?)",
            [(ip, r.get("org"), r.get("net_name"), r.get("asn"), r.get("geo_country"), r.get("geo_city"), r.get("via"), now)
             for ip, r in recs.items()])
        c.commit()


def ip_info_for(ips):
    ips = list(set(i for i in ips if i))
    if not ips:
        return {}
    out = {}
    for i in range(0, len(ips), 500):
        part = ips[i:i + 500]
        q = f"SELECT addr,org,net_name,asn,geo_country,geo_city,via,fetched FROM ip_info WHERE addr IN ({','.join('?' * len(part))})"
        for r in conn().execute(q, part):
            out[r["addr"]] = dict(r)
    return out


def ip_info_stats():
    c = conn()
    pending = c.execute("SELECT count(DISTINCT e.ip) FROM events e LEFT JOIN ip_info i ON i.addr=e.ip "
                        "WHERE e.ip IS NOT NULL AND i.addr IS NULL").fetchone()[0]
    return {"resolved": c.execute("SELECT count(*) FROM ip_info WHERE org IS NOT NULL").fetchone()[0], "pending": pending}

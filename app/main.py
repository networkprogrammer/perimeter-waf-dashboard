import asyncio
import base64
import collections
import contextlib
import csv
import functools
import io
import hmac
import ipaddress
import json
import logging
import os
import re
import sqlite3
import time
import uuid

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.datastructures import Headers

import config
import queries
import store
from engine import Engine, now_ms

logging.basicConfig(level=logging.INFO, format='{"t":"%(asctime)s","lvl":"%(levelname)s","msg":"%(message)s"}')
log = logging.getLogger("waf")

@contextlib.asynccontextmanager
async def lifespan(_app):
    store.init()
    if os.environ.get("WAF_DEV_FAKE") == "1":
        import devfake
        engine.loop = asyncio.get_running_loop()
        devfake.seed()
        tasks = [asyncio.create_task(devfake.live(engine))]
        engine.fake = True
    else:
        tasks = engine.start()
    try:
        yield
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        engine.loop = None


app = FastAPI(title="WAF Dashboard", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
engine = Engine()
STATIC = os.path.join(os.path.dirname(__file__), "static")

RANGES = {"5m": 300, "15m": 900, "30m": 1800, "1h": 3600, "3h": 10800, "6h": 21600, "12h": 43200,
          "24h": 86400, "48h": 172800, "72h": 259200}
LIST_FILTERS = {"account": "account", "host": "host", "rule": "rule", "inner_rule": "inner_rule", "country": "country",
                "ip": "ip", "org": "org", "path": "path", "ua": "ua", "method": "method", "rule_type": "rule_type", "scope": "rule_scope", "region": "region"}
TOP_N = 10
EXPORT_MAX_SECONDS = 60


# access guard ----------------------------------------------------------------
def parse_basic_auth(value):
    """Expected Authorization header for WAF_BASIC_AUTH, or None when unset. Malformed values raise (fail closed)."""
    if not value:
        return None
    user, sep, password = value.partition(":")
    if not sep or not user or len(password) < config.BASIC_AUTH_MIN_PASSWORD:
        raise RuntimeError(f"WAF_BASIC_AUTH must be 'user:password' with a password of at least "
                           f"{config.BASIC_AUTH_MIN_PASSWORD} characters; refusing to start")
    return "Basic " + base64.b64encode(value.encode()).decode()


_BASIC_EXPECTED = parse_basic_auth(config.BASIC_AUTH)
_BAD_HOST = re.compile(r"[/?#@\\\s]")
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_auth_fails = {}


def _host_name(h):
    h = h.strip().lower()
    if h.startswith("["):
        end = h.find("]")
        return h[1:end] if end > 0 else ""
    return h.rsplit(":", 1)[0] if h.count(":") == 1 else h


def host_allowed(h):
    if not h or _BAD_HOST.search(h):
        return False
    name = _host_name(h)
    for a in config.ALLOWED_HOSTS:
        if a == "*" or a == name or (a.startswith("*.") and name.endswith(a[1:])):
            return True
    return False


def _cross_site(headers):
    if headers.get("sec-fetch-site") == "cross-site":
        return True
    origin = headers.get("origin")
    if origin is None:
        return False
    return origin.split("://", 1)[-1].lower() != headers.get("host", "").lower()


def _throttled(client, now):
    q = _auth_fails.get(client)
    while q and q[0] < now - config.AUTH_FAIL_WINDOW_SECONDS:
        q.popleft()
    return bool(q) and len(q) >= config.AUTH_FAIL_LIMIT


def _record_fail(client, now):
    if len(_auth_fails) > 10000:
        for k in [k for k, q in _auth_fails.items() if not q or q[-1] < now - config.AUTH_FAIL_WINDOW_SECONDS]:
            _auth_fails.pop(k, None)
    _auth_fails.setdefault(client, collections.deque(maxlen=config.AUTH_FAIL_LIMIT)).append(now)


class Guard:
    """Host allow-list (DNS rebinding), cross-site write rejection and the optional basic-auth gate.

    Decisions use the routed path from the ASGI scope, never a URL rebuilt from the Host header.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"] == "/healthz":
            return await self.app(scope, receive, send)
        headers = Headers(scope=scope)
        if not host_allowed(headers.get("host", "")):
            return await JSONResponse({"detail": "host not allowed (see WAF_ALLOWED_HOSTS)"}, 400)(scope, receive, send)
        if scope["method"] not in _SAFE_METHODS and _cross_site(headers):
            return await JSONResponse({"detail": "cross-site request rejected"}, 403)(scope, receive, send)
        if _BASIC_EXPECTED:
            client = (scope.get("client") or ("?",))[0]
            now = time.monotonic()
            if _throttled(client, now):
                return await JSONResponse({"detail": "too many failed logins, try later"}, 429,
                                          headers={"Retry-After": str(config.AUTH_FAIL_WINDOW_SECONDS)})(scope, receive, send)
            given = headers.get("authorization", "")
            if not hmac.compare_digest(given.encode(), _BASIC_EXPECTED.encode()):
                if given:
                    _record_fail(client, now)
                    log.warning("basic auth failure from %s", client)
                return await JSONResponse({"detail": "authentication required"}, 401,
                                          headers={"WWW-Authenticate": 'Basic realm="waf-dashboard"'})(scope, receive, send)
            _auth_fails.pop(client, None)
        return await self.app(scope, receive, send)


app.add_middleware(Guard)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Frame-Options"] = "DENY"
    if request.url.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


# filters ---------------------------------------------------------------------
class Filters:
    def __init__(self, params):
        now = now_ms()
        rng = params.get("range")
        if params.get("from"):
            try:
                self.start = int(params["from"])
                self.end = int(params.get("to") or now)
            except ValueError:
                raise HTTPException(400, "bad from/to")
        else:
            secs = RANGES.get(rng or "1h")
            if not secs:
                raise HTTPException(400, "bad range")
            self.start, self.end = now - secs * 1000, now
        if self.end <= self.start or self.end - self.start > config.RETENTION_HOURS * 3600 * 1000 + 60000:
            raise HTTPException(400, "bad time window")
        self.lists = {}
        for k in LIST_FILTERS:
            vals = [v for v in params.getlist(k) if v][:50]
            if vals:
                self.lists[k] = vals
        self.q = (params.get("q") or "").strip()[:200]
        self.status = [int(s) for s in params.getlist("status") if s.isascii() and s.isdigit() and len(s) <= 3][:10]

    @property
    def traffic_scoped(self):
        """True when allowed-request counts (aggregated per account/host) still apply to these filters."""
        return not self.q and not self.status and set(self.lists) <= {"account", "host"}

    def where(self):
        w, p = ["ts >= ?", "ts < ?"], [self.start, self.end]
        for k, vals in self.lists.items():
            col = LIST_FILTERS[k]
            w.append(f"{col} IN ({','.join('?' * len(vals))})")
            p += [v.upper() if k == "method" else v for v in vals]
        if self.status:
            w.append(f"status IN ({','.join('?' * len(self.status))})")
            p += self.status
        if self.q:
            like = "%" + self.q.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            cols = ["ip", "host", "path", "rule", "inner_rule", "ua", "args", "account", "account_name", "country",
                    "resource", "req_id", "term_label", "org", "net_name", "asn"]
            w.append("(" + " OR ".join(f"lower(coalesce({c},'')) LIKE ? ESCAPE '\\'" for c in cols) + ")")
            p += [like] * len(cols)
        return " AND ".join(w), p


def F(request: Request):
    return Filters(request.query_params)


def rows(sql, p=()):
    return [dict(r) for r in store.conn().execute(sql, p).fetchall()]


def bounded(fn):
    """Sync handlers run in the threadpool (off the event loop) with a cap on SQLite query time."""
    @functools.wraps(fn)
    def wrapper(*a, **kw):
        with store.deadline(config.API_QUERY_TIMEOUT_SECONDS):
            return fn(*a, **kw)
    return wrapper


@app.exception_handler(sqlite3.OperationalError)
async def sqlite_error(_request, exc):
    if "interrupted" in str(exc):
        return JSONResponse({"detail": "query took too long; narrow the filters or time range"}, 503)
    log.warning("sqlite: %s", exc)
    return JSONResponse({"detail": "database error"}, 500)


# api -------------------------------------------------------------------------
@app.get("/healthz")
async def healthz():
    return {"ok": True}


@app.get("/api/status")
@bounded
def status():
    return engine.status()


@app.get("/api/events")
@bounded
def events(request: Request, sort: str = "ts", dir: str = "desc", limit: int = 100, offset: int = 0):
    f = F(request)
    if sort not in store.SORTABLE:
        raise HTTPException(400, "bad sort")
    d = "ASC" if dir.lower() == "asc" else "DESC"
    limit, offset = max(1, min(limit, 500)), max(0, offset)
    where, p = f.where()
    total = store.conn().execute(f"SELECT count(*) FROM v_events WHERE {where}", p).fetchone()[0]
    data = rows(
        f"SELECT id,ts,account,account_name,region,ip,country,resource,host,path,method,status,rule,rule_type,"
        f"rule_scope,rule_short,inner_rule,term_label,term_action,cond,match_loc,matched_field,ua,org,net_name,asn,org_state FROM v_events "
        f"WHERE {where} ORDER BY {'org IS NULL, ' if sort == 'org' else ''}{sort} {d}, ts DESC LIMIT ? OFFSET ?", p + [limit, offset])
    return {"total": total, "rows": data, "limit": limit, "offset": offset}


@app.get("/api/events/{event_id:path}")
@bounded
def event_detail(event_id: str):
    r = store.conn().execute("SELECT * FROM v_events WHERE id=?", (event_id,)).fetchone()
    if not r:
        raise HTTPException(404, "not found")
    return dict(r)


def _bucket(span_s):
    for b in (60, 300, 900, 1800, 3600, 7200, 14400):
        if span_s / b <= 160:
            return b
    return 14400


@app.get("/api/summary")
@bounded
def summary(request: Request):
    f = F(request)
    where, p = f.where()
    c = store.conn()
    span_s = (f.end - f.start) / 1000
    b = _bucket(span_s)
    first = f.start // 1000 // b * b
    blocked_series = {r["t"]: r["n"] for r in c.execute(
        f"SELECT (ts/1000/{b})*{b} AS t, count(*) n FROM v_events WHERE {where} GROUP BY t", p)}
    allowed_series, traffic_hosts, allowed_total = {}, None, None
    if f.traffic_scoped:
        aw, ap = ["minute >= ?", "minute < ?"], [f.start // 1000, f.end // 1000]
        for k, col in (("account", "account"), ("host", "host")):
            if k in f.lists:
                aw.append(f"{col} IN ({','.join('?' * len(f.lists[k]))})")
                ap += f.lists[k]
        aw = " AND ".join(aw)
        allowed_series = {r["t"]: r["n"] for r in c.execute(
            f"SELECT (minute/{b})*{b} AS t, sum(n) n FROM minute_agg WHERE disp='Allowed' AND {aw} GROUP BY t", ap)}
        allowed_total = sum(allowed_series.values())
        traffic_hosts = rows(
            f"SELECT host, account, sum(CASE WHEN disp='Allowed' THEN n ELSE 0 END) allowed, "
            f"sum(CASE WHEN disp='Blocked' THEN n ELSE 0 END) blocked FROM minute_agg WHERE {aw} "
            f"GROUP BY host, account ORDER BY allowed+blocked DESC LIMIT 15", ap)
        for r in traffic_hosts:
            r["account_name"] = store.ACCOUNT_NAMES.get(r["account"], r["account"])
    series = []
    t = first
    while t * 1000 < f.end:
        series.append({"t": t * 1000, "blocked": blocked_series.get(t, 0),
                       "allowed": allowed_series.get(t, 0) if allowed_total is not None else None})
        t += b
    k = c.execute(
        f"SELECT count(*) blocked, count(DISTINCT ip) ips, count(DISTINCT rule) rules, count(DISTINCT host) hosts, "
        f"count(DISTINCT account) accounts, max(ts) last_ts FROM v_events WHERE {where}", p).fetchone()
    blocked = k["blocked"]
    kpis = {"blocked": blocked, "allowed": allowed_total, "unique_ips": k["ips"], "unique_rules": k["rules"],
            "unique_hosts": k["hosts"], "unique_accounts": k["accounts"], "last_blocked_ms": k["last_ts"],
            "block_rate": (blocked / (blocked + allowed_total)) if allowed_total is not None and (blocked + allowed_total) else None}

    def top(sql):
        return rows(sql + f" LIMIT {TOP_N}", p)

    topd = {
        "rules": top(f"SELECT rule, rule_type, rule_scope, inner_rule, term_label, count(*) n, count(DISTINCT ip) ips, "
                     f"max(ts) last_ts FROM v_events WHERE {where} GROUP BY rule, rule_type, rule_scope, inner_rule ORDER BY n DESC"),
        "ips": top(f"SELECT ip, country, max(org) org, max(asn) asn, count(*) n, count(DISTINCT rule) rules, count(DISTINCT host) hosts, max(ts) last_ts "
                   f"FROM v_events WHERE {where} GROUP BY ip, country ORDER BY n DESC"),
        "orgs": top(f"SELECT org, max(asn) asn, count(*) n, count(DISTINCT ip) ips, count(DISTINCT rule) rules, max(ts) last_ts "
                    f"FROM v_events WHERE {where} AND org IS NOT NULL GROUP BY org ORDER BY n DESC"),
        "hosts": top(f"SELECT host, count(*) n, count(DISTINCT ip) ips, max(ts) last_ts FROM v_events WHERE {where} "
                     f"GROUP BY host ORDER BY n DESC"),
        "accounts": top(f"SELECT account, account_name, count(*) n, max(ts) last_ts FROM v_events WHERE {where} "
                        f"GROUP BY account, account_name ORDER BY n DESC"),
        "countries": top(f"SELECT country, count(*) n FROM v_events WHERE {where} GROUP BY country ORDER BY n DESC"),
        "paths": top(f"SELECT path, count(*) n FROM v_events WHERE {where} GROUP BY path ORDER BY n DESC"),
        "user_agents": top(f"SELECT ua, count(*) n FROM v_events WHERE {where} GROUP BY ua ORDER BY n DESC"),
        "methods": rows(f"SELECT method, count(*) n FROM v_events WHERE {where} GROUP BY method ORDER BY n DESC", p),
        "rule_types": rows(f"SELECT rule_type, count(*) n FROM v_events WHERE {where} GROUP BY rule_type ORDER BY n DESC", p),
        "scopes": rows(f"SELECT rule_scope, count(*) n FROM v_events WHERE {where} GROUP BY rule_scope ORDER BY n DESC", p),
    }
    if topd["rules"]:
        kpis["top_rule"] = topd["rules"][0]["term_label"]
    return {"range": {"from": f.start, "to": f.end, "bucket_s": b}, "kpis": kpis, "series": series,
            "top": topd, "traffic_hosts": traffic_hosts, "allowed_applicable": allowed_total is not None}


@app.get("/api/facets")
@bounded
def facets(request: Request):
    f = Filters(_TimeOnly(request.query_params))
    where, p = f.where()

    def fac(col, extra="", n=200):
        return rows(f"SELECT {col} AS value, count(*) n FROM v_events WHERE {where} AND {col} IS NOT NULL GROUP BY {col} "
                    f"ORDER BY n DESC LIMIT {n}", p)
    accounts = rows(f"SELECT account AS value, account_name AS label, count(*) n FROM v_events WHERE {where} "
                    f"AND account IS NOT NULL GROUP BY account, account_name ORDER BY n DESC LIMIT 300", p)
    return {"accounts": accounts, "hosts": fac("host"), "rules": fac("rule"), "inner_rules": fac("inner_rule"),
            "countries": fac("country"), "orgs": fac("org"), "methods": fac("method"), "rule_types": fac("rule_type"),
            "scopes": fac("rule_scope"), "regions": fac("region"), "ips": fac("ip", n=100)}


class _TimeOnly:
    """Facets ignore every filter except the time window."""
    def __init__(self, qp):
        self.qp = qp

    def get(self, k, d=None):
        return self.qp.get(k, d) if k in ("range", "from", "to") else d

    def __getitem__(self, k):
        return self.qp[k]

    def getlist(self, k):
        return []


@app.get("/api/export.csv")
def export_csv(request: Request, sort: str = "ts", dir: str = "desc"):
    f = F(request)
    if sort not in store.SORTABLE:
        raise HTTPException(400, "bad sort")
    where, p = f.where()
    d = "ASC" if dir.lower() == "asc" else "DESC"
    cols = ["ts", "account", "account_name", "region", "ip", "org", "net_name", "asn", "country", "host", "path", "args", "method", "status", "rule",
            "rule_type", "inner_rule", "term_action", "cond", "match_loc", "matched_field", "ua", "resource", "req_id"]
    sql = f"SELECT {','.join(cols)} FROM v_events WHERE {where} ORDER BY {sort} {d} LIMIT 50000"

    def gen():
        # Starlette iterates sync generators on arbitrary worker threads, so this uses its own connection.
        c = store.stream_conn()
        stop_at = time.monotonic() + EXPORT_MAX_SECONDS
        c.set_progress_handler(lambda: 1 if time.monotonic() > stop_at else 0, 20000)
        try:
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["time_utc"] + cols[1:])
            yield buf.getvalue()
            for r in c.execute(sql, p):
                buf.seek(0), buf.truncate()
                vals = list(r)
                vals[0] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(vals[0] / 1000))
                # neutralise spreadsheet formula injection
                vals = [("'" + v) if isinstance(v, str) and v[:1] in "=+-@\t\r" else v for v in vals]
                w.writerow(vals)
                yield buf.getvalue()
        except sqlite3.OperationalError as e:
            log.warning("csv export stopped: %s", e)
            yield "# export truncated: time limit reached\n"
        finally:
            c.close()
    return StreamingResponse(gen(), media_type="text/csv",
                             headers={"Content-Disposition": 'attachment; filename="waf-blocked.csv"'})


@app.get("/api/stream")
async def stream(request: Request):
    if len(engine.subscribers) >= config.MAX_STREAMS:
        raise HTTPException(503, "too many live connections", headers={"Retry-After": "30"})
    q = asyncio.Queue(maxsize=200)
    engine.subscribers.add(q)

    async def gen():
        try:
            yield "retry: 3000\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=15)
                    yield f"event: {msg['type']}\ndata: {json.dumps(msg, default=str)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            engine.subscribers.discard(q)
    return StreamingResponse(gen(), media_type="text/event-stream", headers={"X-Accel-Buffering": "no"})


# on-demand search over the full lake (allowed + blocked) -------------------------------
JOBS = {}
RATE = {}           # client -> start times within the last hour
GLOBAL_STARTS = collections.deque()
SCAN_DAY = {"day": None, "bytes": 0}
HOST_RE = re.compile(r"^[A-Za-z0-9._:\-]{1,255}$")
RULE_RE = re.compile(r"^[A-Za-z0-9._:\-#]{1,200}$")
PATH_RE = re.compile(r"^[^\x00-\x1f'\"\\]{1,200}$")


def _validate_search(b):
    out = {}
    s = str(b.get("disposition") or "")
    if s in ("Allowed", "Blocked"):
        out["disposition"] = s
    if b.get("ip"):
        try:
            out["ip"] = str(ipaddress.ip_address(str(b["ip"]).strip()))
        except ValueError:
            raise HTTPException(400, "invalid IP address")
    if b.get("account"):
        if not re.fullmatch(r"\d{12}", str(b["account"])):
            raise HTTPException(400, "account must be a 12 digit ID")
        out["account"] = str(b["account"])
    if b.get("host"):
        if not HOST_RE.match(str(b["host"])):
            raise HTTPException(400, "invalid host")
        out["host"] = str(b["host"]).lower()
    if b.get("country"):
        if not re.fullmatch(r"[A-Za-z]{2}", str(b["country"])):
            raise HTTPException(400, "invalid country code")
        out["country"] = str(b["country"]).upper()
    if b.get("rule"):
        if not RULE_RE.match(str(b["rule"])):
            raise HTTPException(400, "invalid rule")
        out["rule"] = str(b["rule"])
    if b.get("path"):
        if not PATH_RE.match(str(b["path"])):
            raise HTTPException(400, "invalid path")
        out["path"] = str(b["path"])
    if b.get("method"):
        if not re.fullmatch(r"[A-Za-z]{3,8}", str(b["method"])):
            raise HTTPException(400, "invalid method")
        out["method"] = str(b["method"])
    if b.get("status"):
        if not str(b["status"]).isdigit() or not (100 <= int(b["status"]) <= 599):
            raise HTTPException(400, "invalid status")
        out["status"] = int(b["status"])
    return out


def _search_region_reason(error=None, unavailable=False):
    """Return actionable messages without exposing AWS resource names or credential details."""
    detail = str(error or "").lower()
    if "accessdenied" in detail or "lake formation" in detail:
        return "Access denied. Check IAM and Lake Formation permissions for this region, then retry."
    if "credential" in detail or "token" in detail or "expired" in detail:
        return "Credentials unavailable or expired. Check the AWS credential chain, then retry after the next probe."
    if "timed out" in detail or "timeout" in detail:
        return "Query timed out. Narrow the time window or filters and retry."
    if "table" in detail or "database" in detail:
        return "Source unavailable. Check the regional Security Lake database and table configuration, then retry."
    if unavailable:
        return "Region unavailable. Check AWS credentials and regional Security Lake access, then retry after the next probe."
    return "Query failed. Check regional Athena access and service health, then retry."


def _run_job(job):
    scanned = 0
    terminal_state = "error"
    searched, skipped = [], {}
    job.update(partial=False, searched_regions=searched, skipped_regions=skipped)
    try:
        runner = engine.runner
        available = set(engine.regions) if runner else set()
        res = []
        for region in job["regions"]:
            if region not in available:
                detail = next((a.get("regions", {}).get(region) or a.get("error") for a in engine.attempts
                               if a.get("regions", {}).get(region) or a.get("error")), None)
                skipped[region] = _search_region_reason(detail, unavailable=True)
                continue
            try:
                sql, params = queries.search(region, job["filters"], job["start"], job["end"], job["limit"])
                data, sc = runner.run(region, sql, params, timeout=240, max_rows=job["limit"])
                scanned += sc
                for r in data:
                    r["src_region"] = region
                    r["account_name"] = store.ACCOUNT_NAMES.get(r.get("account"), r.get("account"))
                    if r.get("rule"):
                        r["rule_scope"], r["rule_short"] = store.classify_rule(r["rule"], r.get("rule_type"))
                res += data
                searched.append(region)
            except Exception as e:
                log.warning("search %s region %s failed: %s", job["id"], region, e)
                skipped[region] = _search_region_reason(e)
        if not searched:
            raise RuntimeError("No requested regions could be searched. Check skipped_regions for next steps.")
        res.sort(key=lambda r: -int(r["ts"]))
        res = res[:job["limit"]]
        known = engine.enrich_ips({r["ip"] for r in res if r.get("ip")}, budget=40)
        for r in res:
            i = known.get(r.get("ip"), {})
            r["org"], r["net_name"], r["asn"] = i.get("org"), i.get("net_name"), i.get("asn")
        job.update(rows=res)
        terminal_state = "done"
    except Exception as e:
        log.warning("search %s failed: %s", job["id"], e)
        message = ("No requested regions could be searched. Check skipped_regions for next steps."
                   if not searched else "Search results could not be prepared. Check service health and retry.")
        job.update(error=message)
    finally:
        job.update(partial=bool(skipped), scanned_mb=round(scanned / 1048576, 1), finished=time.time())
        _add_scanned(scanned)
        # Terminal state is the publication barrier for polling clients.
        job["state"] = terminal_state


def _today():
    return time.strftime("%Y-%m-%d", time.gmtime())


def _add_scanned(n):
    if SCAN_DAY["day"] != _today():
        SCAN_DAY.update(day=_today(), bytes=0)
    SCAN_DAY["bytes"] += n or 0


def _check_search_limits(client, now):
    cutoff = now - 3600
    if len(RATE) > 1000:
        for k in [k for k, v in RATE.items() if not v or v[-1] <= cutoff]:
            RATE.pop(k, None)
    hits = [t for t in RATE.get(client, []) if t > cutoff]
    RATE[client] = hits
    while GLOBAL_STARTS and GLOBAL_STARTS[0] <= cutoff:
        GLOBAL_STARTS.popleft()
    if len(hits) >= config.SEARCH_PER_CLIENT_HOUR:
        raise HTTPException(429, f"search limit reached ({config.SEARCH_PER_CLIENT_HOUR} per hour per client)")
    if len(GLOBAL_STARTS) >= config.SEARCH_GLOBAL_HOUR:
        raise HTTPException(429, f"search limit reached ({config.SEARCH_GLOBAL_HOUR} per hour for this dashboard)")
    if config.SEARCH_DAILY_SCAN_GB:
        _add_scanned(0)
        if SCAN_DAY["bytes"] >= config.SEARCH_DAILY_SCAN_GB * 1024 ** 3:
            raise HTTPException(429, "daily Deep Search scan budget used up (WAF_SEARCH_DAILY_SCAN_GB)")
    for jid in [j for j, v in JOBS.items() if now - v["created"] > 900]:
        JOBS.pop(jid, None)
    if sum(1 for j in JOBS.values() if j["state"] == "running") >= config.SEARCH_MAX_RUNNING:
        raise HTTPException(429, "too many searches running, try again shortly")


@app.post("/api/search")
async def search_start(request: Request):
    client = request.client.host if request.client else "?"
    if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
        raise HTTPException(415, "Content-Type must be application/json")
    try:
        b = await request.json()
    except Exception:
        raise HTTPException(400, "invalid JSON")
    if not isinstance(b, dict):
        raise HTTPException(400, "invalid JSON")
    filters = _validate_search(b)
    narrowing = [k for k in filters if k not in ("disposition",)]
    if not narrowing:
        raise HTTPException(400, "add at least one filter (IP, host, account, path, rule, country, status or method)")
    try:
        hours = min(max(float(b.get("hours") or 1), 0.25), config.SEARCH_MAX_HOURS)
        limit = min(max(int(b.get("limit") or 500), 1), config.SEARCH_MAX_ROWS)
    except (TypeError, ValueError):
        raise HTTPException(400, "invalid hours or limit")
    end = now_ms()
    region = b.get("region") or "all"
    if not isinstance(region, str):
        raise HTTPException(400, "unknown region")
    regions = list(config.SOURCES) if region == "all" else [region]
    if any(r not in config.SOURCES for r in regions):
        raise HTTPException(400, "unknown region")
    # Admission is atomic on the event loop: no await between checking and reserving a slot.
    now = time.time()
    _check_search_limits(client, now)
    RATE[client].append(now)
    GLOBAL_STARTS.append(now)
    job = {"id": uuid.uuid4().hex[:12], "state": "running", "created": now, "filters": filters,
           "start": int(end - hours * 3600 * 1000), "end": end, "regions": regions, "limit": limit, "rows": [],
           "partial": False, "searched_regions": [], "skipped_regions": {}}
    JOBS[job["id"]] = job
    asyncio.get_running_loop().run_in_executor(None, _run_job, job)
    return {"id": job["id"]}


@app.get("/api/search/{job_id}")
async def search_get(job_id: str):
    j = JOBS.get(job_id)
    if not j:
        raise HTTPException(404, "unknown search")
    return {"id": j["id"], "state": j["state"], "elapsed_s": round((j.get("finished") or time.time()) - j["created"], 1),
            "rows": j["rows"] if j["state"] == "done" else [], "error": j.get("error"), "scanned_mb": j.get("scanned_mb"),
            "partial": j.get("partial", False), "searched_regions": list(j.get("searched_regions", [])),
            "skipped_regions": dict(j.get("skipped_regions", {})),
            "filters": j["filters"], "window": {"from": j["start"], "to": j["end"]}, "truncated": len(j["rows"]) >= j["limit"]}


# static ----------------------------------------------------------------------
@app.get("/")
async def index():
    return FileResponse(os.path.join(STATIC, "index.html"), headers={"Cache-Control": "no-cache"})


app.mount("/static", StaticFiles(directory=STATIC), name="static")

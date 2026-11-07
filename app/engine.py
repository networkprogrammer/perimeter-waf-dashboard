import asyncio
import json
import logging
import threading
import time

import athena
import whois
import config
import queries
import store

log = logging.getLogger("waf")

CHUNK_BLOCKED_MS = 4 * 3600 * 1000
CHUNK_AGG_MS = 2 * 3600 * 1000


def now_ms():
    return int(time.time() * 1000)


def _short_err(e):
    s = str(e)
    return s.split(": ", 1)[-1][:300] if "AccessDenied" in s or "Lake Formation" in s else s[:300]


class Engine:
    def __init__(self):
        self.runner = None
        self.regions = []
        self.attempts = []
        self.last_select = 0
        self.subscribers = set()
        self.loop = None
        self.progress = {}
        self.last_poll_ms = None
        self.last_error = None
        self.errors_in_row = 0
        self.stream_errors = {}
        self.last_prune_ms = None
        self.last_prune_error = None
        self._ipinfo_lock = threading.Lock()
        self.scanned_bytes = 0
        self.queries_run = 0
        self.started_ms = now_ms()
        self.fake = False
        self.selecting = False

    # credentials
    def select_credentials(self):
        """Build a session from the credential chain and probe every configured region.

        Regions where the probe fails are skipped and retried at the next selection. The result and
        each region's error are exposed through /api/status so the UI can explain what is wrong.
        """
        self.selecting = True
        a = {"profile": config.AWS_PROFILE or "default credential chain", "label": self._label(),
             "kind": "assume-role" if config.ASSUME_ROLE_ARN else "default-chain",
             "ok": False, "identity": None, "regions": {}}
        self.attempts = [a]
        chosen, ok_regions = None, []
        try:
            r = athena.Runner()
            a["identity"] = r.identity()
            for region in config.SOURCES:
                try:
                    r.run(region, queries.probe(region), timeout=60)
                    a["regions"][region] = "ok"
                    ok_regions.append(region)
                except Exception as e:
                    a["regions"][region] = _short_err(e)
            if ok_regions:
                a["ok"] = True
                chosen = r
        except Exception as e:
            a["error"] = _short_err(e)
        self.selecting = False
        self.last_select = time.time()
        if chosen:
            self.runner, self.regions = chosen, ok_regions
            log.info("credentials ok, regions=%s", ok_regions)
        else:
            self.runner, self.regions = None, []
            log.warning("no usable credentials: %s", json.dumps(self.attempts))
        return bool(chosen)

    @staticmethod
    def _label():
        base = "AWS default credential chain"
        if config.AWS_PROFILE:
            base = f"AWS profile {config.AWS_PROFILE}"
        return base + (" + assume role" if config.ASSUME_ROLE_ARN else "")

    # pub/sub
    def publish(self, payload):
        for q in list(self.subscribers):
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                pass

    def _emit(self, payload):
        if self.loop:
            self.loop.call_soon_threadsafe(self.publish, payload)

    # ingestion
    def _run(self, region, sql):
        rows, scanned = self.runner.run(region, sql)
        self.scanned_bytes += scanned
        self.queries_run += 1
        return rows

    def blocked_step(self, region):
        key = f"blocked_wm:{region}"
        wm = store.meta_get(key)
        now = now_ms()
        floor = now - config.BACKFILL_HOURS * 3600 * 1000
        start = max(floor, int(wm) - config.BLOCKED_OVERLAP_SECONDS * 1000) if wm else floor
        end = min(start + CHUNK_BLOCKED_MS, now)
        rows = self._run(region, queries.blocked_since(region, start, end))
        new = store.insert_events([store.enrich(r, region) for r in rows])
        store.meta_set(key, end)
        total = max(now - floor, 1)
        self.progress[f"blocked:{region}"] = {"done": min(1.0, (end - floor) / total), "caught_up": end >= now - 1000}
        self.last_poll_ms = now_ms()
        if new and end >= now - 120_000:
            self._emit({"type": "blocked", "count": len(new), "rows": new[-50:]})
        return end >= now - 1000

    def agg_step(self, region):
        key = f"agg_wm:{region}"
        wm = store.meta_get(key)
        now = now_ms()
        floor = (now - config.BACKFILL_HOURS * 3600 * 1000) // 60000 * 60000
        start = max(floor, (int(wm) - config.AGG_OVERLAP_SECONDS * 1000) // 60000 * 60000) if wm else floor
        end = min(start + CHUNK_AGG_MS, now)
        rows = self._run(region, queries.minute_aggregate(region, start, end))
        store.replace_agg(region, start // 1000, (end // 60000 + 1) * 60 if end >= now - 1000 else end // 1000, rows)
        store.meta_set(key, end)
        total = max(now - floor, 1)
        self.progress[f"agg:{region}"] = {"done": min(1.0, (end - floor) / total), "caught_up": end >= now - 1000}
        self._emit({"type": "tick"})
        return end >= now - 1000

    async def _work(self, operation, *args):
        # Cancelling to_thread alone leaves its worker running after lifespan shutdown.
        task = asyncio.create_task(asyncio.to_thread(operation, *args))
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            await asyncio.gather(task, return_exceptions=True)
            raise

    def _refresh_ingest_error(self):
        failures = list(self.stream_errors.values())
        self.errors_in_row = max((f["consecutive_failures"] for f in failures), default=0)
        self.last_error = failures[-1]["last_error"] if failures else None

    async def _loop(self, name, step, region, every):
        key = f"{name}/{region}"
        while True:
            if not self.runner or region not in self.regions:
                await asyncio.sleep(5)
                continue
            try:
                caught_up = await self._work(step, region)
                self.stream_errors.pop(key, None)
                self._refresh_ingest_error()
                await asyncio.sleep(every if caught_up else 0.2)
            except Exception as e:
                count = self.stream_errors.get(key, {}).get("consecutive_failures", 0) + 1
                error = f"{key}: {_short_err(e)}"
                self.stream_errors.pop(key, None)
                self.stream_errors[key] = {"consecutive_failures": count, "last_error": error}
                self._refresh_ingest_error()
                log.warning("%s", error)
                if count >= 4:
                    self.last_select = 0
                await asyncio.sleep(min(60, 5 * count))

    async def _selector(self):
        while True:
            stale = time.time() - self.last_select
            retry = 60 if not self.runner else 1800
            if stale >= retry or self.last_select == 0:
                try:
                    await self._work(self.select_credentials)
                except Exception as e:
                    log.warning("credential selection failed: %s", e)
                    self.last_select = time.time()
                self._emit({"type": "tick"})
            await asyncio.sleep(5)

    def enrich_ips(self, ips, budget=200):
        """Resolve ownership for IPs (cache first, then lookups). Used by the background worker and Deep Search."""
        ips = list(dict.fromkeys(i for i in ips if i))
        # Workers and Deep Search share the cache; recheck it after any concurrent batch finishes.
        with self._ipinfo_lock:
            have = store.ip_info_for(ips)
            if not whois.ENABLED:
                return have
            cutoff = int(time.time()) - 1800
            todo = [i for i in ips if i not in have or
                    (have[i].get("org") is None and have[i]["fetched"] < cutoff)][:budget]
            if todo:
                recs = whois.lookup_many(todo)
                store.save_ip_info(recs)
                have.update(recs)
            return have

    def ipinfo_step(self):
        """Returns True when there is nothing left to resolve."""
        if not whois.ENABLED:
            return True
        ips = store.ips_needing_info(200)
        if ips:
            self.enrich_ips(ips, budget=200)
            self._emit({"type": "tick"})
            return len(ips) < 200
        return True

    async def _ipinfo_loop(self):
        while True:
            try:
                done = await self._work(self.ipinfo_step)
                await asyncio.sleep(10 if done else 0.5)
            except Exception as e:
                log.warning("ipinfo: %s", _short_err(e))
                await asyncio.sleep(30)

    async def _pruner(self):
        delay, failures = 600, 0
        while True:
            await asyncio.sleep(delay)
            try:
                await self._work(store.prune)
                self.last_prune_ms = now_ms()
                self.last_prune_error = None
                delay, failures = 600, 0
            except Exception as e:
                failures += 1
                self.last_prune_error = _short_err(e)
                log.warning("prune: %s", self.last_prune_error)
                delay = min(60, 5 * failures)

    def start(self):
        self.loop = asyncio.get_running_loop()
        tasks = [self._selector(), self._pruner(), self._ipinfo_loop()]
        for region in config.SOURCES:
            tasks.append(self._loop("blocked", self.blocked_step, region, config.POLL_SECONDS))
            tasks.append(self._loop("agg", self.agg_step, region, config.AGG_EVERY_SECONDS))
        return [asyncio.create_task(t) for t in tasks]

    def status(self):
        cur = next((a for a in self.attempts if a["ok"]), None) if self.runner else None
        prog = self.progress
        backfilling = any(not p["caught_up"] for k, p in prog.items() if k.split(":")[1] in self.regions)
        done = [p["done"] for k, p in prog.items() if k.split(":")[1] in self.regions]
        c = store.conn()
        latest = c.execute("SELECT max(ts) m, count(*) n FROM events").fetchone()
        return {
            "ok": bool(self.runner) or self.fake,
            "credential": {
                "profile": (cur["profile"] if cur else None) if self.runner else ("dev-fake" if self.fake else None),
                "label": cur["label"] if (self.runner and cur) else ("Offline demo data" if self.fake else None),
                "kind": cur["kind"] if (self.runner and cur) else ("dev" if self.fake else None),
                "identity": cur["identity"] if cur else None,
                "regions": self.regions,
            },
            "configured_regions": list(config.SOURCES),
            "selecting": self.selecting,
            "attempts": self.attempts,
            "backfilling": backfilling, "backfill_progress": (sum(done) / len(done)) if done else 0,
            "last_poll_ms": self.last_poll_ms, "last_error": self.last_error,
            "ingest_errors": {k: dict(v) for k, v in self.stream_errors.items()},
            "prune": {"last_success_ms": self.last_prune_ms, "last_error": self.last_prune_error},
            "events_stored": latest["n"], "latest_event_ms": latest["m"],
            "athena_queries": self.queries_run, "athena_scanned_mb": round(self.scanned_bytes / 1048576, 1),
            "whois": {"enabled": whois.ENABLED, **store.ip_info_stats()},
            "started_ms": self.started_ms, "now_ms": now_ms(),
            "retention_hours": config.RETENTION_HOURS, "poll_seconds": config.POLL_SECONDS,
        }

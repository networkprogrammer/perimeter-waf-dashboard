import atexit
import asyncio
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

_project_dir = os.path.dirname(os.path.dirname(__file__))
_test_data = tempfile.TemporaryDirectory(prefix=".test-data-", dir=_project_dir)
atexit.register(_test_data.cleanup)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

_test_env = {k: v for k, v in os.environ.items() if not k.startswith(("WAF_", "AWS_"))}
_test_env.update(WAF_DATA_DIR=_test_data.name, WAF_WHOIS="off", AWS_EC2_METADATA_DISABLED="true")
with patch.dict(os.environ, _test_env, clear=True):
    import athena  # noqa: E402
    import config  # noqa: E402
    import queries  # noqa: E402
    import store  # noqa: E402
    import main  # noqa: E402
from fastapi import HTTPException  # noqa: E402


def isolate_store(test):
    """Give each stateful regression its own database, including thread-local connections."""
    data = tempfile.TemporaryDirectory(prefix=".test-data-", dir=_project_dir)
    test.addCleanup(data.cleanup)
    for setting, value in (("DATA_DIR", data.name), ("DB_PATH", os.path.join(data.name, "waf.db"))):
        p = patch.object(config, setting, value)
        p.start()
        test.addCleanup(p.stop)
    p = patch.object(store, "_local", threading.local())
    p.start()
    test.addCleanup(p.stop)
    store.init()


def raw(**kw):
    base = {"ts": "1793632000000", "account": "111111111111", "region": "us-east-1", "ip": "192.0.2.4", "country": "US",
            "resource": "111111111111-app/my-alb/abc", "svc": "ALB", "host": "h.example.com", "path": "/",
            "method": "get", "req_id": "1-abc", "rule": "AWS-AWSManagedRulesCommonRuleSet", "evaluated_groups": "AWS#AWSManagedRulesCommonRuleSet",
            "rule_type": "MANAGED_RULE_GROUP", "inner_rule": "GenericLFI_BODY", "status": "",
            "labels": '{"name":"awswaf:clientip:geo:country:US"}|{"name":"x"}'}
    base.update(kw)
    return base


class EnrichTests(unittest.TestCase):
    def test_managed_terminating_rule(self):
        e = store.enrich(raw(), "us-east-1")
        self.assertEqual(e["rule_scope"], "aws-managed")
        self.assertEqual(e["rule_short"], "AWSManagedRulesCommonRuleSet")
        self.assertEqual(e["term_label"], "AWS-AWSManagedRulesCommonRuleSet > GenericLFI_BODY")
        self.assertEqual(e["resource"], "my-alb")
        self.assertEqual(e["method"], "GET")
        self.assertEqual(e["labels"], "awswaf:clientip:geo:country:US|x")

    def test_regular_rule_ignores_inner(self):
        e = store.enrich(raw(rule="restrict-foo", rule_type="REGULAR", inner_rule="Default_Action"), "us-east-1")
        self.assertIsNone(e["inner_rule"])
        self.assertEqual(e["rule_scope"], "custom")
        self.assertEqual(e["term_label"], "restrict-foo")

    def test_scope_classification(self):
        self.assertEqual(store.classify_rule("x", "RATE_BASED")[0], "rate-based")
        self.assertEqual(store.classify_rule("vendor-group", "MANAGED_RULE_GROUP", "Vendor#Rules")[0], "managed")
        self.assertEqual(store.classify_rule("anything", "GROUP")[0], "other")

    def test_strip_prefixes(self):
        old = config.RULE_STRIP_PREFIXES
        config.RULE_STRIP_PREFIXES = ["acme-custom-"]
        try:
            self.assertEqual(store.classify_rule("acme-custom-block-ips", "REGULAR"), ("custom", "block-ips"))
        finally:
            config.RULE_STRIP_PREFIXES = old

    def test_ids_are_unique_per_region(self):
        self.assertNotEqual(store.enrich(raw(), "us-east-1")["id"], store.enrich(raw(), "ca-central-1")["id"])


class SqlGuardTests(unittest.TestCase):
    def setUp(self):
        self.r = athena.Runner.__new__(athena.Runner)

    def test_rejects_mutation(self):
        for sql in ("DROP TABLE x", "select 1; select 2", "INSERT INTO t SELECT 1", "WITH a AS (SELECT 1) DELETE FROM t"):
            with self.assertRaises(athena.AthenaError):
                athena.Runner.run(self.r, "us-east-1", sql)

    def test_search_binds_text(self):
        sql, params = queries.search("us-east-1", {"host": "a' OR 1=1 --", "disposition": "Blocked"}, 0, 1000, 10)
        self.assertNotIn("OR 1=1", sql)
        self.assertEqual(params, ["a' OR 1=1 --"])


class SearchValidationTests(unittest.TestCase):
    def test_validation(self):
        import main
        ok = main._validate_search({"ip": "198.51.100.8", "host": "A.example.com", "account": "123456789012", "country": "us"})
        self.assertEqual(ok["host"], "a.example.com")
        self.assertEqual(ok["country"], "US")
        for bad in ({"ip": "192.0.2"}, {"account": "12"}, {"host": "a b"}, {"host": "x'; drop"}, {"path": "a'b"}, {"status": "abc"}):
            with self.assertRaises(HTTPException):
                main._validate_search(bad)



class IpInfoTests(unittest.TestCase):
    def test_private_addresses_are_labelled_locally(self):
        import whois
        res = whois.lookup_many(["10.1.2.3", "192.0.2.5"])
        self.assertEqual(res["10.1.2.3"]["org"], "Private / reserved address")
        self.assertEqual(res["192.0.2.5"]["via"], "local")

    def test_ip_info_roundtrip(self):
        store.init()
        store.save_ip_info({"198.51.100.9": {"org": "Example Net", "asn": "AS64496", "net_name": "EX", "via": "cymru"}})
        self.assertEqual(store.ip_info_for(["198.51.100.9"])["198.51.100.9"]["asn"], "AS64496")


class ConfigTests(unittest.TestCase):
    def test_security_lake_names_follow_convention(self):
        self.assertEqual(queries.table("us-east-1"),
                         "amazon_security_lake_glue_db_us_east_1.amazon_security_lake_table_us_east_1_waf_2_0")



class EngineTests(unittest.TestCase):
    """Drives the ingest path with a stub runner, so no AWS access is needed."""

    class StubRunner:
        def identity(self):
            return "arn:aws:sts::111111111111:assumed-role/example-reader/session"

        def run(self, region, sql, params=None, timeout=None, max_rows=None):
            if sql.lstrip().startswith("SELECT count(*) AS n FROM") and "interval" in sql:
                return [{"n": "0"}], 0
            if "minute" in sql:
                return [{"minute": "1793632020", "account": "111111111111", "host": "h.example.com", "disp": "Allowed", "n": "7"}], 10
            return [{"ts": str(int(__import__("time").time() * 1000)), "account": "111111111111", "region": region,
                     "ip": "192.0.2.9", "rule": "geo-block", "rule_type": "REGULAR", "req_id": "1-xyz"}], 10

    def test_selection_and_ingest(self):
        import engine
        store.init()
        e = engine.Engine()
        orig = athena.Runner
        athena.Runner = self.StubRunner
        try:
            self.assertTrue(e.select_credentials())
        finally:
            athena.Runner = orig
        self.assertEqual(e.regions, ["us-east-1"])
        self.assertTrue(e.status()["ok"])
        e.blocked_step("us-east-1")
        e.agg_step("us-east-1")
        n = store.conn().execute("SELECT count(*) FROM events WHERE rule='geo-block'").fetchone()[0]
        self.assertEqual(n, 1)

    def test_failed_selection_is_reported(self):
        import engine
        store.init()

        class Broken:
            def __init__(self):
                raise RuntimeError("Unable to locate credentials")
        e = engine.Engine()
        orig = athena.Runner
        athena.Runner = Broken
        try:
            self.assertFalse(e.select_credentials())
        finally:
            athena.Runner = orig
        st = e.status()
        self.assertFalse(st["ok"])
        self.assertIn("credentials", st["attempts"][0]["error"])


def client():
    import main
    from fastapi.testclient import TestClient
    store.init()
    return TestClient(main.app, base_url="http://localhost")


class AuthTests(unittest.TestCase):
    def setUp(self):
        import base64
        import main
        self.main = main
        self.old = main._BASIC_EXPECTED
        main._BASIC_EXPECTED = "Basic " + base64.b64encode(b"u:long-enough-pass").decode()
        main._auth_fails.clear()

    def tearDown(self):
        self.main._BASIC_EXPECTED = self.old
        self.main._auth_fails.clear()

    def test_gate(self):
        c = client()
        self.assertEqual(c.get("/healthz").status_code, 200)
        self.assertEqual(c.get("/api/status").status_code, 401)
        self.assertEqual(c.get("/api/status", auth=("u", "long-enough-pass")).status_code, 200)

    def test_host_header_cannot_reach_protected_route_via_healthz(self):
        # Regression for the Starlette "BadHost" path confusion: the exemption must use the routed path.
        c = client()
        for host in ("x/healthz?", "localhost/healthz?", "localhost/healthz#"):
            r = c.get("/api/status", headers={"host": host})
            self.assertIn(r.status_code, (400, 401), host)

    def test_failed_logins_are_throttled(self):
        c = client()
        for _ in range(10):
            self.assertEqual(c.get("/api/status", auth=("u", "wrong")).status_code, 401)
        self.assertEqual(c.get("/api/status", auth=("u", "long-enough-pass")).status_code, 429)

    def test_config_fails_closed(self):
        for bad in ("justapassword", ":password-is-long", "user:short", "user:"):
            with self.assertRaises(RuntimeError):
                self.main.parse_basic_auth(bad)
        self.assertIsNone(self.main.parse_basic_auth(""))
        self.assertTrue(self.main.parse_basic_auth("u:long-enough-pass").startswith("Basic "))


class HostAndOriginTests(unittest.TestCase):
    def test_host_allow_list(self):
        import main
        c = client()
        self.assertEqual(c.get("/api/status").status_code, 200)
        self.assertEqual(c.get("/api/status", headers={"host": "127.0.0.1:8080"}).status_code, 200)
        self.assertEqual(c.get("/api/status", headers={"host": "[::1]:8080"}).status_code, 200)
        self.assertEqual(c.get("/api/status", headers={"host": "attacker.example"}).status_code, 400)
        self.assertEqual(c.get("/healthz", headers={"host": "10.0.0.5"}).status_code, 200)
        old = config.ALLOWED_HOSTS
        config.ALLOWED_HOSTS = ["*.example.com"]
        try:
            self.assertTrue(main.host_allowed("waf.example.com:443"))
            self.assertFalse(main.host_allowed("example.com.evil.net"))
            self.assertFalse(main.host_allowed("waf.example.com/x"))
        finally:
            config.ALLOWED_HOSTS = old

    def test_cross_site_post_rejected(self):
        c = client()
        body = '{"host": "a.example.com"}'
        r = c.post("/api/search", content=body, headers={"content-type": "text/plain", "origin": "http://evil.example"})
        self.assertEqual(r.status_code, 403)
        r = c.post("/api/search", content=body, headers={"content-type": "text/plain"})
        self.assertEqual(r.status_code, 415)
        r = c.post("/api/search", content=body, headers={"content-type": "application/json", "sec-fetch-site": "cross-site"})
        self.assertEqual(r.status_code, 403)


class ApiRobustnessTests(unittest.TestCase):
    def test_unicode_digit_status_is_ignored(self):
        self.assertEqual(client().get("/api/events", params={"status": "\u00b2"}).status_code, 200)

    def test_csv_export_streams(self):
        store.init()
        store.insert_events([store.enrich(raw(ts=str(int(__import__("time").time() * 1000)), req_id="1-csv"), "us-east-1")])
        r = client().get("/api/export.csv?range=1h")
        self.assertEqual(r.status_code, 200)
        self.assertGreaterEqual(len(r.text.strip().splitlines()), 2)

    def test_stream_limit(self):
        import main
        old = config.MAX_STREAMS
        config.MAX_STREAMS = 0
        try:
            self.assertEqual(client().get("/api/stream").status_code, 503)
        finally:
            config.MAX_STREAMS = old

    def test_query_deadline_interrupts(self):
        import sqlite3
        store.init()
        with store.deadline(0.05):
            with self.assertRaises(sqlite3.OperationalError):
                store.conn().execute("WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r) "
                                     "SELECT count(*) FROM r").fetchone()
        self.assertEqual(store.conn().execute("SELECT 1").fetchone()[0], 1)

    def test_search_limits(self):
        import main
        main.RATE.clear()
        main.GLOBAL_STARTS.clear()
        old = config.SEARCH_GLOBAL_HOUR
        config.SEARCH_GLOBAL_HOUR = 2
        try:
            now = __import__("time").time()
            main.GLOBAL_STARTS.extend([now, now])
            with self.assertRaises(HTTPException) as cm:
                main._check_search_limits("198.51.100.1", now)
            self.assertEqual(cm.exception.status_code, 429)
        finally:
            config.SEARCH_GLOBAL_HOUR = old
            main.GLOBAL_STARTS.clear()


class AthenaParameterTests(unittest.TestCase):
    def test_literals(self):
        self.assertEqual(athena.sql_literal("example.com"), "'example.com'")
        self.assertEqual(athena.sql_literal("a' OR '1'='1"), "'a'' OR ''1''=''1'")
        self.assertEqual(athena.sql_literal("http_request.url.path"), "'http_request.url.path'")
        self.assertEqual(athena.sql_literal(403), "403")
        with self.assertRaises(athena.AthenaError):
            athena.sql_literal(1.5)

    def test_runner_sends_quoted_parameters(self):
        sent = {}

        class Client:
            def start_query_execution(self, **kw):
                sent.update(kw)
                return {"QueryExecutionId": "q"}

            def get_query_execution(self, **kw):
                return {"QueryExecution": {"Status": {"State": "SUCCEEDED"}, "Statistics": {"DataScannedInBytes": 0}}}

            def get_paginator(self, _name):
                class P:
                    def paginate(self, **kw):
                        return [{"ResultSet": {"Rows": [{"Data": [{"VarCharValue": "n"}]}]}}]
                return P()

        import threading
        r = athena.Runner.__new__(athena.Runner)
        r._sem = threading.BoundedSemaphore(1)
        r.client = lambda region: Client()
        sql, params = queries.search("us-east-1", {"host": "a.example.com", "ip": "192.0.2.1", "path": "/x"}, 0, 1000, 10)
        r.run("us-east-1", sql, params)
        self.assertEqual(sent["ExecutionParameters"], ["'192.0.2.1'", "'a.example.com'", "'%/x%'"])


class SearchAdmissionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        import collections
        import main
        for name, value in (("JOBS", {}), ("RATE", {}), ("GLOBAL_STARTS", collections.deque())):
            p = patch.object(main, name, value)
            p.start()
            self.addCleanup(p.stop)

    async def test_concurrent_json_bodies_cannot_overbook_search_limits(self):
        import main
        from starlette.requests import Request

        for setting in ("SEARCH_MAX_RUNNING", "SEARCH_GLOBAL_HOUR", "SEARCH_PER_CLIENT_HOUR"):
            with self.subTest(limit=setting):
                main.JOBS.clear()
                main.RATE.clear()
                main.GLOBAL_STARTS.clear()
                both_reading = asyncio.Event()
                readers = 0

                async def receive():
                    nonlocal readers
                    readers += 1
                    if readers == 2:
                        both_reading.set()
                    await both_reading.wait()
                    return {"type": "http.request", "body": b'{"host":"example.com"}', "more_body": False}

                scope = {"type": "http", "method": "POST", "path": "/api/search",
                         "headers": [(b"content-type", b"application/json")], "client": ("192.0.2.1", 1)}
                with patch.object(config, setting, 1), patch.object(main, "_run_job", lambda job: None):
                    results = await asyncio.gather(*(main.search_start(Request(dict(scope), receive))
                                                     for _ in range(2)), return_exceptions=True)
                self.assertEqual(sum(isinstance(r, dict) for r in results), 1)
                self.assertEqual([r.status_code for r in results if isinstance(r, HTTPException)], [429])
                self.assertEqual(len(main.JOBS), 1)
                self.assertEqual(len(main.GLOBAL_STARTS), 1)
        main.JOBS.clear()
        main.RATE.clear()
        main.GLOBAL_STARTS.clear()


class SearchRegionTests(unittest.TestCase):
    def setUp(self):
        import engine
        import main
        import whois
        self.main = main
        isolate_store(self)
        self.engine = engine.Engine()
        self.engine.regions = ["us-east-1"]
        self.engine.runner = self.Runner()
        self.sources = {r: {"db": "example_db", "table": "example_waf"}
                        for r in ("us-east-1", "us-west-2")}
        self.patches = [patch.object(main, "engine", self.engine), patch.object(config, "SOURCES", self.sources),
                        patch.object(whois, "ENABLED", False)]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(main.JOBS.clear)

    class Runner:
        def run(self, region, sql, params=None, **kw):
            if region == "us-west-2":
                raise athena.AthenaError("AccessDenied: https://private.example/secret")
            return [{"ts": "100", "ip": "192.0.2.7", "account": "111111111111"}], 1048576

    def job(self, regions=None, all_regions=True):
        return {"id": "region-test", "state": "running", "created": time.time(), "filters": {"host": "example.com"},
                "start": 0, "end": 1000, "regions": regions or list(self.sources), "limit": 10,
                "all_regions": all_regions, "rows": []}

    def result(self, job):
        self.main.JOBS[job["id"]] = job
        self.main._run_job(job)
        return asyncio.run(self.main.search_get(job["id"]))

    def test_explicit_unavailable_region_is_error_not_empty_success(self):
        result = self.result(self.job(["us-west-2"], all_regions=False))
        self.assertEqual(result["state"], "error")
        self.assertTrue(result["error"])
        self.assertTrue(result.get("skipped_regions", {}).get("us-west-2"))

    def test_all_regions_reports_unavailable_region_and_retains_results(self):
        self.engine.attempts = [{"ok": True, "regions": {"us-east-1": "ok", "us-west-2": "AccessDenied: secret"}}]
        result = self.result(self.job())
        self.assertEqual(result["state"], "done")
        self.assertEqual(len(result["rows"]), 1)
        self.assertTrue(result.get("partial", False))
        self.assertEqual(result.get("searched_regions"), ["us-east-1"])
        self.assertTrue(result.get("skipped_regions", {}).get("us-west-2"))
        self.assertNotIn("secret", json.dumps(result))
        self.assertEqual(result["scanned_mb"], 1.0)

    def test_no_regions_available_is_error(self):
        self.engine.regions = []
        result = self.result(self.job())
        self.assertEqual(result["state"], "error")
        self.assertEqual(set(result.get("skipped_regions", {})), set(self.sources))
        self.assertEqual(result.get("searched_regions"), [])

    def test_one_query_failure_retains_other_regions_and_is_partial(self):
        self.engine.regions = list(self.sources)
        result = self.result(self.job())
        self.assertEqual(result["state"], "done")
        self.assertTrue(result.get("partial", False))
        self.assertEqual(result.get("searched_regions"), ["us-east-1"])
        self.assertEqual(len(result["rows"]), 1)
        self.assertTrue(result.get("skipped_regions", {}).get("us-west-2"))
        self.assertNotIn("private.example", json.dumps(result))

    def test_all_queries_failing_exposes_error_without_raw_service_details(self):
        self.engine.regions = ["us-west-2"]
        result = self.result(self.job(["us-west-2"]))
        self.assertEqual(result["state"], "error")
        self.assertNotIn("private.example", json.dumps(result))
        self.assertTrue(result.get("skipped_regions", {}).get("us-west-2"))

    def assert_terminal_metadata_published_before_state(self, regions, terminal_state):
        finalizing = threading.Event()
        release = threading.Event()

        class PausedFinalization(dict):
            def update(self, *args, **kw):
                if "finished" in kw:
                    finalizing.set()
                    release.wait(3)
                super().update(*args, **kw)

        job = PausedFinalization(self.job(regions))
        self.main.JOBS[job["id"]] = job
        worker = threading.Thread(target=self.main._run_job, args=(job,))
        worker.start()
        try:
            self.assertTrue(finalizing.wait(3))
            payload = client().get("/api/search/" + job["id"]).json()
            self.assertEqual(payload["state"], "running", "polling exposed terminal state before final metadata")
            self.assertEqual(payload["rows"], [])
        finally:
            release.set()
            worker.join(3)
        self.assertFalse(worker.is_alive())
        payload = client().get("/api/search/" + job["id"]).json()
        self.assertEqual(payload["state"], terminal_state)
        self.assertTrue(payload["partial"])
        self.assertIsNotNone(payload["scanned_mb"])
        self.assertIsNotNone(job.get("finished"))
        self.assertTrue(payload["skipped_regions"].get("us-west-2"))
        if terminal_state == "done":
            self.assertEqual(payload["searched_regions"], ["us-east-1"])
            self.assertEqual(len(payload["rows"]), 1)
            self.assertEqual(payload["scanned_mb"], 1.0)
        else:
            self.assertEqual(payload["searched_regions"], [])
            self.assertTrue(payload["error"])

    def test_poll_cannot_observe_done_before_partial_metadata_is_published(self):
        self.assert_terminal_metadata_published_before_state(["us-east-1", "us-west-2"], "done")

    def test_poll_cannot_observe_error_before_failure_metadata_is_published(self):
        self.assert_terminal_metadata_published_before_state(["us-west-2"], "error")

    def test_successful_empty_search_is_complete_not_partial(self):
        class Empty:
            def run(self, *args, **kw):
                return [], 0
        self.engine.runner = Empty()
        result = self.result(self.job(["us-east-1"], all_regions=False))
        self.assertEqual(result["state"], "done")
        self.assertIs(result.get("partial"), False)
        self.assertEqual(result.get("searched_regions"), ["us-east-1"])
        self.assertEqual(result.get("skipped_regions"), {})


class PathSearchTests(unittest.TestCase):
    def test_deep_path_search_matches_literal_percent_underscore_and_escape(self):
        import main
        import sqlite3
        # SQLite and Athena both support LIKE ... ESCAPE with a single-character escape.
        c = sqlite3.connect(":memory:")
        paths = ["/a_b%20!", "/ab20!", "/axb-any20!", "/A_B%20!tail"]
        c.execute("CREATE TABLE paths(path TEXT)")
        c.executemany("INSERT INTO paths VALUES (?)", [(p,) for p in paths])
        filters = main._validate_search({"path": "/a_b%20!"})
        sql, params = queries.search("us-east-1", filters, 0, 1000, 10)
        predicate = sql.split("lower(http_request.url.path)", 1)[1].split("\nORDER BY", 1)[0]
        matched = [r[0] for r in c.execute("SELECT path FROM paths WHERE lower(path)" + predicate, params)]
        c.close()
        self.assertEqual(matched, ["/a_b%20!", "/A_B%20!tail"])
        self.assertNotIn("/a_b%20!", sql)
        for unsafe in ("/bad'path", "/bad\\path", "/bad\x00path"):
            with self.assertRaises(HTTPException):
                main._validate_search({"path": unsafe})


class IpRetryTests(unittest.TestCase):
    def setUp(self):
        import engine
        import whois
        self.engine = engine.Engine()
        isolate_store(self)
        self.enabled = patch.object(whois, "ENABLED", True)
        self.enabled.start()
        self.addCleanup(self.enabled.stop)

    def test_expired_failed_ownership_is_retried_by_worker(self):
        import whois
        ip = "192.0.2.41"
        store.insert_events([store.enrich(raw(ip=ip, req_id="ip-retry"), "us-east-1")])
        store.save_ip_info({ip: {"org": None, "via": "none"}})
        c = store.conn()
        c.execute("UPDATE ip_info SET fetched=? WHERE addr=?", (int(time.time()) - 1801, ip))
        c.commit()
        with patch.object(whois, "lookup_many", lambda ips: {i: {"org": "Example Net", "via": "cymru"} for i in ips}):
            self.engine.ipinfo_step()
        self.assertEqual(store.ip_info_for([ip])[ip]["org"], "Example Net")
        self.assertNotIn(ip, store.ips_needing_info())

    def test_cache_retains_successes_and_recent_failures(self):
        import whois
        store.save_ip_info({"192.0.2.42": {"org": "Cached Net", "via": "cymru"},
                            "192.0.2.43": {"org": None, "via": "none"}})
        with patch.object(whois, "lookup_many", side_effect=AssertionError("cache should avoid network")):
            result = self.engine.enrich_ips(["192.0.2.42", "192.0.2.43"])
        self.assertEqual(result["192.0.2.42"]["org"], "Cached Net")
        self.assertIsNone(result["192.0.2.43"]["org"])

    def test_duplicate_addresses_use_single_lookup(self):
        import whois
        looked_up = []
        def lookup(ips):
            looked_up.extend(ips)
            return {i: {"org": "Example Net", "via": "cymru"} for i in ips}
        with patch.object(whois, "lookup_many", lookup):
            self.engine.enrich_ips(["192.0.2.44", "192.0.2.44"])
        self.assertEqual(looked_up, ["192.0.2.44"])
        self.assertEqual(store.ip_info_for(looked_up)["192.0.2.44"]["org"], "Example Net")

    def test_off_mode_avoids_lookup_even_for_deep_search(self):
        import whois
        with patch.object(whois, "ENABLED", False), patch.object(whois, "lookup_many", side_effect=AssertionError("off")):
            try:
                result = self.engine.enrich_ips(["192.0.2.45"])
            except AssertionError:
                self.fail("enrich_ips attempted ownership lookup when disabled")
        self.assertNotIn("192.0.2.45", result)

    def test_overlapping_enrichment_requests_share_completed_lookup(self):
        import whois
        entered = threading.Event()
        release = threading.Event()
        looked_up = []
        results = []
        second_started = threading.Event()
        def lookup(ips):
            looked_up.extend(ips)
            entered.set()
            release.wait(2)
            return {i: {"org": "Example Net", "via": "cymru"} for i in ips}
        def enrich(second=False):
            if second:
                second_started.set()
            results.append(self.engine.enrich_ips(["192.0.2.46"]))
        with patch.object(whois, "lookup_many", lookup):
            first = threading.Thread(target=enrich)
            second = threading.Thread(target=enrich, args=(True,))
            first.start()
            self.assertTrue(entered.wait(2))
            second.start()
            self.assertTrue(second_started.wait(2))
            time.sleep(0.02)
            release.set()
            first.join(3)
            second.join(3)
        self.assertFalse(first.is_alive() or second.is_alive())
        self.assertEqual(looked_up, ["192.0.2.46"])
        self.assertEqual(len(results), 2)


class EngineRecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        import engine
        isolate_store(self)
        self.engine = engine.Engine()
        self.engine.runner = object()
        self.engine.regions = ["us-east-1", "us-west-2"]

    async def one_step(self, name, region, fails=False):
        def step(_region):
            if fails:
                raise RuntimeError("fixture failure")
            return True
        delays = []
        async def sleep(delay):
            delays.append(delay)
            raise asyncio.CancelledError
        with patch.object(asyncio, "sleep", sleep):
            with self.assertRaises(asyncio.CancelledError):
                await self.engine._loop(name, step, region, 30)
        return delays[0]

    async def test_successful_stream_does_not_clear_another_stream_failure(self):
        await self.one_step("blocked", "us-east-1", fails=True)
        await self.one_step("agg", "us-east-1")
        self.assertIn("blocked/us-east-1", self.engine.status()["last_error"] or "")

    async def test_backoff_and_reprobe_track_operation_and_region_separately(self):
        self.engine.last_select = time.time()
        delays = []
        for _ in range(4):
            delays.append(await self.one_step("blocked", "us-east-1", fails=True))
            await self.one_step("agg", "us-east-1")
            await self.one_step("blocked", "us-west-2")
        self.assertEqual(delays, [5, 10, 15, 20])
        self.assertEqual(self.engine.last_select, 0)

    async def test_recovering_stream_leaves_other_error_visible(self):
        await self.one_step("blocked", "us-east-1", fails=True)
        await self.one_step("agg", "us-west-2", fails=True)
        await self.one_step("agg", "us-west-2")
        self.assertIn("blocked/us-east-1", self.engine.status()["last_error"] or "")
        await self.one_step("blocked", "us-east-1")
        self.assertIsNone(self.engine.status()["last_error"])

    async def test_pruner_recovers_with_bounded_backoff_and_reports_health(self):
        calls = 0
        delays = []
        states = []
        def prune():
            nonlocal calls
            calls += 1
            if calls <= 14:
                raise RuntimeError("database busy")
        async def sleep(delay):
            delays.append(delay)
            states.append(self.engine.status().get("prune", {}))
            if calls >= 15:
                raise asyncio.CancelledError
        with patch.object(store, "prune", prune), patch.object(asyncio, "sleep", sleep):
            try:
                await self.engine._pruner()
            except asyncio.CancelledError:
                pass
            except RuntimeError:
                pass
        self.assertEqual(calls, 15, "pruner must survive failures and eventually retry successfully")
        self.assertEqual(delays[0], 600)
        self.assertTrue(all(0 < d <= 60 for d in delays[1:-1]))
        self.assertEqual(delays[-1], 600)
        self.assertTrue(states[1].get("last_error"))
        self.assertIsNone(states[-1].get("last_error"))
        self.assertIsNotNone(states[-1].get("last_success_ms"))


class LifespanTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        isolate_store(self)

    async def test_engine_workers_are_cancelled_and_awaited_on_shutdown(self):
        import engine
        import main
        e = engine.Engine()
        workers = []
        stopped = []
        ready = asyncio.Event()
        expected = 3 + 2 * len(config.SOURCES)
        async def worker(*args):
            workers.append(asyncio.current_task())
            if len(workers) == expected:
                ready.set()
            try:
                await asyncio.Event().wait()
            finally:
                stopped.append(asyncio.current_task())
        with patch.object(main, "engine", e), patch.dict(os.environ, {"WAF_DEV_FAKE": "0"}), \
                patch.object(e, "_selector", worker), patch.object(e, "_pruner", worker), \
                patch.object(e, "_ipinfo_loop", worker), patch.object(e, "_loop", worker):
            try:
                async with main.lifespan(main.app):
                    await asyncio.wait_for(ready.wait(), 2)
                    self.assertEqual(store.conn().execute("SELECT count(*) FROM sqlite_master WHERE type='table' "
                                                          "AND name IN ('events','minute_agg','ip_info','meta')").fetchone()[0], 4)
                self.assertEqual(len(stopped), expected, "lifespan leaked background workers")
                self.assertTrue(all(t.done() for t in workers))
            finally:
                for t in workers:
                    t.cancel()
                await asyncio.gather(*workers, return_exceptions=True)

    async def test_shutdown_waits_for_inflight_ingest_before_releasing_engine_loop(self):
        import engine
        import main
        e = engine.Engine()
        e.runner = object()
        e.regions = list(config.SOURCES)
        entered = threading.Event()
        release = threading.Event()
        finished = threading.Event()
        real_sleep = asyncio.sleep
        async def idle(*args):
            await asyncio.Event().wait()
        def step(_region):
            entered.set()
            release.wait(2)
            finished.set()
            return True
        with patch.object(main, "engine", e), patch.dict(os.environ, {"WAF_DEV_FAKE": "0"}), \
                patch.object(e, "_selector", idle), patch.object(e, "_pruner", idle), \
                patch.object(e, "_ipinfo_loop", idle), patch.object(e, "blocked_step", step), \
                patch.object(e, "agg_step", step):
            context = main.lifespan(main.app)
            await context.__aenter__()
            self.assertTrue(await asyncio.to_thread(entered.wait, 2))
            closing = asyncio.create_task(context.__aexit__(None, None, None))
            try:
                await real_sleep(0.02)
                self.assertFalse(closing.done(), "shutdown returned while ingest still owns background work")
                self.assertIsNotNone(e.loop)
            finally:
                release.set()
                await closing
            self.assertTrue(finished.is_set())
            self.assertIsNone(e.loop)

    async def test_demo_worker_is_cancelled_and_awaited_on_shutdown(self):
        import engine
        import main
        import devfake
        e = engine.Engine()
        ready = asyncio.Event()
        stopped = asyncio.Event()
        workers = []
        async def live(_engine):
            workers.append(asyncio.current_task())
            ready.set()
            try:
                await asyncio.Event().wait()
            finally:
                stopped.set()
        with patch.object(main, "engine", e), patch.dict(os.environ, {"WAF_DEV_FAKE": "1"}), \
                patch.object(devfake, "seed", lambda: None), patch.object(devfake, "live", live):
            try:
                async with main.lifespan(main.app):
                    await asyncio.wait_for(ready.wait(), 2)
                    self.assertTrue(e.status()["ok"])
                self.assertTrue(stopped.is_set(), "lifespan leaked demo worker")
            finally:
                for t in workers:
                    t.cancel()
                await asyncio.gather(*workers, return_exceptions=True)


if __name__ == "__main__":
    unittest.main()

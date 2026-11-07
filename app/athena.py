"""Thin Athena runner. Only fixed SELECT templates are ever submitted; user text is passed as quoted execution parameters."""
import re
import threading
import time

import boto3
from botocore.config import Config
from botocore.credentials import RefreshableCredentials
from botocore.session import get_session

import config

_SELECT_ONLY = re.compile(r"^\s*(select|with)\b", re.I)
_FORBIDDEN = re.compile(r"\b(insert|update|delete|drop|create|alter|merge|unload|grant|revoke|call)\b", re.I)


class AthenaError(Exception):
    pass


def sql_literal(v):
    """Athena parses each ExecutionParameters entry as a SQL expression, so text must be sent as a quoted literal.

    Integers are passed as numeric literals; everything else becomes a single-quoted string with quotes doubled.
    """
    if isinstance(v, bool) or not isinstance(v, (int, str)):
        raise AthenaError(f"unsupported parameter type {type(v).__name__}")
    if isinstance(v, int):
        return str(v)
    if "\x00" in v:
        raise AthenaError("NUL in parameter")
    return "'" + v.replace("'", "''") + "'"


def build_session():
    """boto3 session from the default credential chain, optionally followed by one assume-role hop.

    The assumed-role credentials refresh themselves, so long-running containers keep working.
    """
    base = boto3.Session(profile_name=config.AWS_PROFILE)
    if not config.ASSUME_ROLE_ARN:
        return base
    sts = base.client("sts")

    def fetch():
        kw = {"RoleArn": config.ASSUME_ROLE_ARN, "RoleSessionName": config.ASSUME_ROLE_SESSION, "DurationSeconds": 3600}
        if config.ASSUME_ROLE_EXTERNAL_ID:
            kw["ExternalId"] = config.ASSUME_ROLE_EXTERNAL_ID
        c = sts.assume_role(**kw)["Credentials"]
        return {"access_key": c["AccessKeyId"], "secret_key": c["SecretAccessKey"],
                "token": c["SessionToken"], "expiry_time": c["Expiration"].isoformat()}

    creds = RefreshableCredentials.create_from_metadata(metadata=fetch(), refresh_using=fetch, method="sts-assume-role")
    bs = get_session()
    bs._credentials = creds
    bs.set_config_variable("region", "us-east-1")
    return boto3.Session(botocore_session=bs)


class Runner:
    def __init__(self):
        self.session = build_session()
        self._clients = {}
        self._lock = threading.Lock()
        self._sem = threading.BoundedSemaphore(config.ATHENA_CONCURRENCY)

    def client(self, region):
        with self._lock:
            if region not in self._clients:
                self._clients[region] = self.session.client(
                    "athena", region_name=region,
                    config=Config(retries={"max_attempts": 8, "mode": "adaptive"}, read_timeout=30))
            return self._clients[region]

    def identity(self):
        sts = self.session.client("sts", region_name="us-east-1")
        return sts.get_caller_identity()["Arn"]

    def run(self, region, sql, params=None, timeout=None, max_rows=None):
        if not _SELECT_ONLY.match(sql) or _FORBIDDEN.search(re.sub(r"'[^']*'", "''", sql)):
            raise AthenaError("only a single SELECT is allowed")
        if ";" in sql.strip().rstrip(";"):
            raise AthenaError("multiple statements are not allowed")
        timeout = timeout or config.QUERY_TIMEOUT_SECONDS
        c = self.client(region)
        kw = {
            "QueryString": sql,
            "WorkGroup": config.WORKGROUP,
        }
        if params:
            kw["ExecutionParameters"] = [sql_literal(p) for p in params]
        out = config.OUTPUT_LOCATION.format(region=region) if config.OUTPUT_LOCATION else ""
        if out:
            kw["ResultConfiguration"] = {"OutputLocation": out}
        with self._sem:
            qid = c.start_query_execution(**kw)["QueryExecutionId"]
            deadline = time.time() + timeout
            delay = 0.6
            while True:
                q = c.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
                st = q["Status"]["State"]
                if st == "SUCCEEDED":
                    break
                if st in ("FAILED", "CANCELLED"):
                    raise AthenaError(q["Status"].get("StateChangeReason", st)[:400])
                if time.time() > deadline:
                    try:
                        c.stop_query_execution(QueryExecutionId=qid)
                    except Exception:
                        pass
                    raise AthenaError("query timed out")
                time.sleep(delay)
                delay = min(delay * 1.3, 3)
            scanned = q.get("Statistics", {}).get("DataScannedInBytes", 0)
            rows, cols = [], None
            for page in c.get_paginator("get_query_results").paginate(QueryExecutionId=qid):
                for r in page["ResultSet"]["Rows"]:
                    vals = [d.get("VarCharValue") for d in r["Data"]]
                    if cols is None:
                        cols = vals
                        continue
                    rows.append(dict(zip(cols, vals)))
                if max_rows and len(rows) >= max_rows:
                    break
        return rows, scanned

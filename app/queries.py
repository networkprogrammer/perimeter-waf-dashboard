"""Fixed SQL templates against the Security Lake OCSF WAF table. Numeric values are int-cast; text is bound."""
import config


def table(region):
    s = config.SOURCES[region]
    return f"{s['db']}.{s['table']}"


def _ms_to_ts(ms):
    return f"from_unixtime({int(ms) // 1000})"


PROBE = "SELECT count(*) AS n FROM {t} WHERE time_dt > current_timestamp - interval '10' minute AND disposition = 'Blocked'"


def probe(region):
    return PROBE.format(t=table(region))


def blocked_since(region, start_ms, end_ms):
    return f"""
SELECT CAST(to_unixtime(time_dt) * 1000 AS bigint) AS ts,
  accountid AS account, region,
  src_endpoint.ip AS ip, src_endpoint.location.country AS country,
  src_endpoint.uid AS resource, src_endpoint.svc_name AS svc,
  http_request.url.hostname AS host, http_request.url.path AS path, http_request.args AS args,
  http_request.http_method AS method, http_request.user_agent AS ua, http_request.uid AS req_id,
  http_request.referrer AS referrer, array_join(http_request.x_forwarded_for, ',') AS xff,
  http_status AS status,
  firewall_rule.uid AS rule, firewall_rule.type AS rule_type, firewall_rule.condition AS cond,
  firewall_rule.match_location AS match_loc, array_join(firewall_rule.match_details, '|') AS match_det,
  firewall_rule.rate_limit AS rate_limit,
  element_at(unmapped, 'ruleGroupList[].terminatingRule.ruleId') AS inner_rule,
  element_at(unmapped, 'ruleGroupList[].terminatingRule.action') AS term_action,
  element_at(unmapped, 'ruleGroupList[].ruleGroupId') AS evaluated_groups,
  element_at(unmapped, 'terminatingRuleMatchDetails[].matchedFieldName') AS matched_field,
  element_at(unmapped, 'ruleGroupList[].nonTerminatingMatchingRules[].ruleId') AS nonterm_rules,
  element_at(unmapped, 'ja3Fingerprint') AS ja3, element_at(unmapped, 'ja4Fingerprint') AS ja4,
  array_join(metadata.labels, '|') AS labels
FROM {table(region)}
WHERE time_dt >= {_ms_to_ts(start_ms)} AND time_dt < {_ms_to_ts(end_ms)}
  AND disposition = 'Blocked'
ORDER BY time_dt
"""


def minute_aggregate(region, start_ms, end_ms):
    return f"""
SELECT CAST(to_unixtime(date_trunc('minute', time_dt)) AS bigint) AS minute,
  accountid AS account, http_request.url.hostname AS host, disposition AS disp, count(*) AS n
FROM {table(region)}
WHERE time_dt >= {_ms_to_ts(start_ms)} AND time_dt < {_ms_to_ts(end_ms)}
GROUP BY 1, 2, 3, 4
"""


def search(region, filters, start_ms, end_ms, limit):
    """Returns (sql, params). `filters` is already validated by the caller."""
    where = [f"time_dt >= {_ms_to_ts(start_ms)}", f"time_dt < {_ms_to_ts(end_ms)}"]
    params = []
    if filters.get("disposition") in ("Allowed", "Blocked"):
        where.append(f"disposition = '{filters['disposition']}'")
    for col, key in (
        ("accountid", "account"), ("src_endpoint.ip", "ip"), ("http_request.url.hostname", "host"),
        ("src_endpoint.location.country", "country"), ("firewall_rule.uid", "rule"),
    ):
        if filters.get(key):
            where.append(f"{col} = ?")
            params.append(filters[key])
    if filters.get("path"):
        where.append("lower(http_request.url.path) LIKE ? ESCAPE '!'")
        path = filters["path"].lower().replace("!", "!!").replace("%", "!%").replace("_", "!_")
        params.append("%" + path + "%")
    if filters.get("method"):
        where.append("upper(http_request.http_method) = ?")
        params.append(filters["method"].upper())
    if filters.get("status"):
        where.append(f"http_status = {int(filters['status'])}")
    sql = f"""
SELECT CAST(to_unixtime(time_dt) * 1000 AS bigint) AS ts, accountid AS account, region,
  src_endpoint.ip AS ip, src_endpoint.location.country AS country, src_endpoint.uid AS resource,
  http_request.url.hostname AS host, http_request.url.path AS path, http_request.http_method AS method,
  http_request.user_agent AS ua, http_status AS status, disposition AS disp,
  firewall_rule.uid AS rule, firewall_rule.type AS rule_type,
  element_at(unmapped, 'ruleGroupList[].terminatingRule.ruleId') AS inner_rule
FROM {table(region)}
WHERE {' AND '.join(where)}
ORDER BY time_dt DESC
LIMIT {int(limit)}
"""
    return sql, params

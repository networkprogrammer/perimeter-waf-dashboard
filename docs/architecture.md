# Architecture

## Components

| Component | File | Responsibility |
|-----------|------|----------------|
| Config | `app/config.py` | All settings from environment variables; builds the per-region database/table map. |
| Athena runner | `app/athena.py` | Builds the boto3 session (default chain, optional profile, optional assume-role hop with auto-refresh). Runs one `SELECT`/`WITH` statement at a time with quoted execution parameters, polls with backoff, enforces a concurrency semaphore, returns `(rows, bytes_scanned)`. |
| Queries | `app/queries.py` | Fixed SQL templates: `probe`, `blocked_since`, `minute_aggregate`, `search`. Numeric values are int-cast; user text is only ever passed as `ExecutionParameters` (quoted by the runner). |
| Store | `app/store.py` | SQLite schema, `enrich()` (raw Athena row to stored event), `classify_rule()`, inserts, pruning, IP ownership cache, the `v_events` view. |
| Engine | `app/engine.py` | Credential/region probe, per-region ingest loops, SSE pub/sub, IP ownership worker, status document. |
| WHOIS | `app/whois.py` | Source IP to organisation: Team Cymru, RDAP, RADb. Local labelling of private/reserved ranges. |
| API | `app/main.py` | FastAPI: filters to SQL, summary, events, facets, CSV export, SSE, Deep Search jobs, security headers, optional basic-auth gate. |
| UI | `app/static/` | Vanilla ES modules, no build, no network access beyond the same origin. |
| Demo data | `app/devfake.py` | Synthetic data for `WAF_DEV_FAKE=1`. |

## Data flow

```
Security Lake (Glue + Lake Formation) --Athena--> engine --> SQLite --> FastAPI --> browser
                                                      \--> IP ownership lookups --> SQLite
```

### Blocked rows (`blocked_since`)

```sql
SELECT CAST(to_unixtime(time_dt) * 1000 AS bigint) AS ts, accountid, region,
       src_endpoint.ip, src_endpoint.location.country, src_endpoint.uid, src_endpoint.svc_name,
       http_request.url.hostname, http_request.url.path, http_request.args, http_request.http_method,
       http_request.user_agent, http_request.uid, http_request.referrer,
       array_join(http_request.x_forwarded_for, ','), http_status,
       firewall_rule.uid, firewall_rule.type, firewall_rule.condition, firewall_rule.match_location,
       array_join(firewall_rule.match_details, '|'), firewall_rule.rate_limit,
       element_at(unmapped, 'ruleGroupList[].terminatingRule.ruleId')            AS inner_rule,
       element_at(unmapped, 'ruleGroupList[].terminatingRule.action')            AS term_action,
       element_at(unmapped, 'ruleGroupList[].ruleGroupId')                       AS evaluated_groups,
       element_at(unmapped, 'terminatingRuleMatchDetails[].matchedFieldName')    AS matched_field,
       element_at(unmapped, 'ruleGroupList[].nonTerminatingMatchingRules[].ruleId') AS nonterm_rules,
       element_at(unmapped, 'ja3Fingerprint'), element_at(unmapped, 'ja4Fingerprint'),
       array_join(metadata.labels, '|')
FROM   <security lake waf table>
WHERE  time_dt >= <start> AND time_dt < <end> AND disposition = 'Blocked'
ORDER  BY time_dt
```

(The exact text is in `app/queries.py`.) Use `time_dt` (timestamp) for time predicates, not the epoch `time` column.
`element_at(map, key)` returns NULL when a key is absent, which keeps the query valid for every record shape.

### Per-minute counts (`minute_aggregate`)

```sql
SELECT CAST(to_unixtime(date_trunc('minute', time_dt)) AS bigint) AS minute,
       accountid, http_request.url.hostname, disposition, count(*) AS n
FROM   <table> WHERE time_dt >= <start> AND time_dt < <end>
GROUP  BY 1, 2, 3, 4
```

### Terminating rule

- `firewall_rule.uid` is the web ACL rule or rule group that ended evaluation; `firewall_rule.type` is
  `REGULAR`, `RATE_BASED`, `GROUP` or `MANAGED_RULE_GROUP`.
- For managed rule groups the specific inner rule is `unmapped['ruleGroupList[].terminatingRule.ruleId']`
  (for example `GenericLFI_BODY`). `term_label` is `<rule> > <inner rule>`.
- `unmapped['ruleGroupList[].ruleGroupId']` lists the groups evaluated (`AWS#AWSManagedRulesCommonRuleSet`).
  A managed group is classified `aws-managed` when its name contains `AWSManagedRules` or an evaluated group starts with `AWS#`.
- Scopes (`store.classify_rule`): `aws-managed`, `managed` (other managed groups), `rate-based`, `custom`, `other`.
  `WAF_RULE_STRIP_PREFIXES` hides your naming-convention prefixes in the UI (display only; filters use the full name).
- `src_endpoint.uid` looks like `<account>-app/<load-balancer-name>/<id>`; the middle part is shown as the resource.

## Storage schema (SQLite, WAL)

| Table | Purpose |
|-------|---------|
| `events` | One row per blocked request. Primary key `id` is `<region>:<request id>` (hash fallback), so re-reads are idempotent. Indexes on `ts`, `(rule, ts)`, `(ip, ts)`, `(host, ts)`, `(account, ts)`. |
| `minute_agg` | `(minute, src, account, host, disp, n)`; `src` is the Security Lake region. Replaced per window. |
| `ip_info` | Cached ownership per IP: `org`, `net_name`, `asn`, geo, `via`, `fetched`. |
| `meta` | Watermarks: `blocked_wm:<region>` and `agg_wm:<region>` (epoch ms). |
| `v_events` (view) | `events` joined with `ip_info`; every filter and list query reads this view. |

## Ingest details

- Chunking: backfill and catch-up read at most 4 hours of rows or 2 hours of counts per query.
- Watermark overlap: 10 minutes for rows, 15 minutes for counts, to absorb late-arriving data. Counts use `DELETE` then `INSERT`
  inside the replaced window; rows use `INSERT OR IGNORE`.
- New rows are pushed over SSE only once a poll has caught up (the chunk ends within two minutes of now), never during backfill.
- Retention pruning removes rows and counts older than `WAF_RETENTION_HOURS`.
- Error handling: failures are tracked separately per operation and region. A successful stream cannot clear another
  stream's error or reset its backoff. `last_error` preserves the latest active failure, `ingest_errors` exposes each
  failing stream, and four consecutive failures in that stream force a credential/region re-probe.
- Retention cleanup retries failures with bounded backoff. `/api/status` includes `prune.last_success_ms` and
  `prune.last_error`; normal cleanup runs every 10 minutes.
- Application lifespan retains and cancels background tasks, then awaits outstanding ingest worker operations before shutdown.

## API behaviour notes

- Filters are repeatable query parameters; values are always bound parameters (`?` in SQLite). Free-text `q` escapes `%`, `_` and `\` and matches
  a fixed column list.
- `range` accepts `5m 15m 30m 1h 3h 6h 12h 24h 48h 72h`; `from`/`to` (epoch ms) must fit in the retention window.
- `/api/summary` includes allowed counts only when every active filter is `account` or `host` (counts are aggregated per account and host).
  Otherwise `allowed_applicable` is false and the UI hides allowed series.
- `/api/events` sorts only on a whitelist of columns and returns 400 for anything else; `limit` is capped at 500.
- Deep Search: `POST /api/search` validates every field (IP via `ipaddress`, account 12 digits, host/rule/path with strict patterns, country 2 letters,
  status 100-599), requires at least one narrowing filter, then reserves rate/concurrency admission without an intervening await.
  It runs in a worker thread, and `GET /api/search/{id}` polls the job. Jobs expire after 15 minutes.
- Deep Search path `LIKE` parameters escape literal wildcard characters instead of removing them. User text remains
  bound through Athena execution parameters.
- Successful search jobs retain `state="done"` and include `partial`, `searched_regions`, and `skipped_regions`.
  An explicitly unavailable region is an error; multi-region results identify any unavailable/failed regions.
- Live SSE reconnection reloads the current table, summary and status. Polling fallback reloads the same data every
  30 seconds while live; paused views do not receive an automatic table reload.

## Security model

- The app is read-only against AWS: the Athena runner rejects anything that is not a single `SELECT`/`WITH` statement.
- Athena `ExecutionParameters` are parsed as SQL expressions, so `athena.sql_literal()` sends every text value as a quoted
  string literal (quotes doubled) and numbers as numerals. Deep Search input is also validated with strict patterns first.
- `Guard` middleware (ASGI): `Host` allow-list against DNS rebinding, rejection of cross-site non-GET requests, optional
  basic auth (fail closed on bad config, constant-time compare, throttled after repeated failures). It decides on
  `scope["path"]`, not on a URL rebuilt from `Host`. POST requires `application/json`.
- SQLite work runs in the threadpool with a per-request progress-handler deadline; streaming CSV uses a dedicated connection.
- No credentials are stored in the repo or image. The default container runs as uid 10001, read-only root filesystem, no capabilities,
  `no-new-privileges`, memory/CPU/pid limits.
- Response headers: strict CSP (`default-src 'none'`, same-origin scripts/styles/fonts/connect), `X-Frame-Options: DENY`,
  `nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` on API responses.
- The UI renders log-derived strings with `textContent` only (log data is attacker-controlled).
- CSV export prefixes cells that start with `= + - @` to defuse spreadsheet formula injection.
- No built-in user accounts. Bind to loopback or put the service behind your network controls or an authenticating proxy.
  `WAF_BASIC_AUTH` is a minimal shared-secret gate for small setups (use HTTPS).
- Supply chain: base image pinned by digest, hash-locked dependencies installed with `--require-hashes`, `pip-audit` in CI.

## Extending to another Security Lake source

The same pattern works for any OCSF source (VPC Flow, Route 53, CloudTrail, ALB access logs where available):
copy `queries.py` templates for the new table, decide per source which class of record is stored as rows and which as counts
(measure volume first), adapt `store.enrich()` and the schema, and reuse the engine loops, API filters and UI shell.

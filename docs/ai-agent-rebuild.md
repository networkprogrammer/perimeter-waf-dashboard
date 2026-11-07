# Rebuild guide for AI coding agents

This document is a complete brief for an AI agent (or a human) to rebuild this project from scratch, or to adapt it
to a different Security Lake source. It assumes the person who cloned the repo will supply the environment-specific
values. **Do not guess those values and never invent real-looking ones.**

The project was originally built this way: a human architect set the design and constraints and reviewed the result,
and AI agents wrote the code and UI. Keep that division of labour.

## 0. How to run this brief

Recommended models:

| Phase | Model | Why |
|-------|-------|-----|
| 1-6 (interview, backend, tests, packaging, docs) | Sonnet-class | Fast, reliable incremental coding. |
| 7 (UI design and implementation) | Opus-class | Better visual design and interaction judgment. Give it the API contract in section 6 and the UI spec in section 7. |
| 8 (review) | A different model than the one that wrote the code | Independent check of SQL construction, validation, and data leakage. |

Work in small steps. After each phase run the checks listed for it. Keep a short progress log in your own scratch
space (not in the repo).

## 1. Interview the user first

Ask for the following before writing code (ask one grouped question; offer the defaults). Use a placeholder in the
repo for anything the user does not want written down; the values belong in `.env`, which is git-ignored.

| Input | Placeholder / default | Used for |
|-------|----------------------|----------|
| Security Lake regions that hold the WAF source | `us-east-1` | `WAF_REGIONS` |
| Glue database / table naming (if non-default) | Security Lake convention | `WAF_SL_DB_TEMPLATE`, `WAF_SL_TABLE_TEMPLATE` |
| Account that owns the Security Lake tables | `<SECURITY_LAKE_ACCOUNT_ID>` | IAM policy ARNs, Lake Formation grants |
| Account where Athena will run | `<ACCOUNT_ID>` | IAM policy, role ARN |
| Athena workgroup | `primary` | `WAF_ATHENA_WORKGROUP` |
| S3 results location | `s3://<ATHENA_RESULTS_BUCKET>/waf-dashboard/` | `WAF_ATHENA_OUTPUT` |
| How the container gets credentials | EC2 instance profile / ECS task role / profile / env keys / assume-role | docs and compose volumes |
| Optional friendly account names | `accounts.json` | `WAF_ACCOUNTS_FILE` |
| Rule naming prefixes to hide | none | `WAF_RULE_STRIP_PREFIXES` |
| Where it will be hosted and who may reach it | loopback only | `WAF_BIND`, proxy/auth advice |
| Allow public WHOIS lookups of source IPs? | yes | `WAF_WHOIS` |
| License and copyright holder | MIT, `<COPYRIGHT HOLDER>` | `LICENSE` |

Verify, if the user has AWS access configured, with read-only calls only: `aws athena list-work-groups`,
`aws glue get-tables --database-name <DB>`, then one `SELECT count(*)` over the last 10 minutes. If that fails with
`TABLE_NOT_FOUND`, the cause is almost always a missing Lake Formation grant (see `docs/iam.md`).

## 2. Hard requirements

1. **Source**: Amazon Security Lake WAF source (OCSF, `waf_2_0`) queried through Athena. No other log source in the core.
2. **Read-only**: only `SELECT`/`WITH`; reject everything else in code. Single statement. User text only via execution
   parameters. Athena parses each `ExecutionParameters` entry as a SQL expression, so text must be sent as a single-quoted
   literal with `'` doubled (`'a''b'`); numbers as plain numerals.
3. **Credentials are pluggable**: standard boto3 chain, optional `WAF_AWS_PROFILE`, optional assume-role hop with automatic refresh.
   No mechanism-specific code (no Roles Anywhere, SSO or instance-role specifics in the application).
4. **Self-contained**: one container, SQLite on a volume, one uvicorn worker, no external services, no CDN, no LLM at runtime.
5. **Privacy of the repository**: no real account IDs, bucket names, ARNs, hostnames, IPs, company names, certificates, tokens.
   Placeholders only. Screenshots must be anonymised.
6. **Safe defaults**: bind to loopback, non-root, read-only filesystem, dropped capabilities, resource limits, strict CSP.
7. **Show the terminating rule** for every blocked request, including the inner managed rule.
8. ASCII punctuation in strings (no em dashes).

## 3. Phase 1 - configuration and Athena runner

Files: `app/config.py`, `app/athena.py`.

- All settings from environment variables with the defaults in `README.md` (treat an empty variable as unset).
- `SOURCES` is derived from `WAF_REGIONS` using the db/table templates (`{region_u}` is the region with `-` replaced by `_`).
- `athena.build_session()` returns `boto3.Session(profile_name=...)`; if `WAF_ASSUME_ROLE_ARN` is set, wrap `sts.assume_role` in
  botocore `RefreshableCredentials` (3600 s) so credentials renew themselves.
- `Runner.run(region, sql, params, timeout, max_rows)`:
  - reject unless it matches `^\s*(select|with)\b`, contains none of the mutation keywords (checked after blanking string literals),
    and contains no second statement;
  - `start_query_execution` with `WorkGroup`, `ExecutionParameters` (each text value quoted as a SQL string literal), and `ResultConfiguration.OutputLocation`
    (`WAF_ATHENA_OUTPUT` with `{region}` substituted) only when configured;
  - poll with backoff `0.6 s x 1.3` up to 3 s, stop the query on timeout, raise a short error on failure;
  - paginate results into dicts; return `(rows, DataScannedInBytes)`;
  - per-process semaphore (`WAF_ATHENA_CONCURRENCY`), adaptive retries in the boto client config.

Check: unit tests for the guard (`DROP`, `;` chains, `INSERT ... SELECT`, `WITH ... DELETE` are rejected).

## 4. Phase 2 - queries, store, engine

Files: `app/queries.py`, `app/store.py`, `app/engine.py`, `app/whois.py`.

- `queries.py`: `probe`, `blocked_since`, `minute_aggregate`, `search` as in `docs/architecture.md`. Numeric inputs are int-cast;
  `search` returns `(sql, params)` with all user text as `?` placeholders; `LIKE` parameters escape literal `%`, `_`
  and the escape character rather than deleting path content.
- `store.py`: schema and `v_events` view exactly as in `docs/architecture.md`; `enrich()` maps a raw row to the stored event
  (id `<region>:<request id>` or a SHA-1 fallback, upper-case method, truncated args/ua/referrer, `term_label`, scope via
  `classify_rule`, `account_name` from the optional accounts file, load balancer name from `src_endpoint.uid`); `insert_events` uses
  `INSERT OR IGNORE`; `replace_agg` deletes then inserts a window; `prune` by retention.
- `engine.py`:
  - `select_credentials()` builds the session, resolves the caller identity, probes every region, records one "attempt" object
    (`profile`, `label`, `kind`, `ok`, `identity`, `regions{region: "ok"|error}`) and keeps the working regions;
  - `blocked_step` / `agg_step` per region with watermarks, chunking (4 h rows / 2 h counts), overlap (10 min / 15 min),
    backfill from `WAF_BACKFILL_HOURS`, progress reporting;
  - loops: poll interval when caught up, 0.2 s between backfill chunks, per-operation/region error backoff
    `min(60, 5 x n)`, re-probe after 4 errors in the same stream; healthy streams must not clear another stream's errors;
  - selector task: every 5 s check; re-probe when stale for 30 min, or 60 s when there is no working runner;
  - SSE pub/sub with bounded per-subscriber queues; IP ownership worker retries expired unresolved cache entries;
  - pruner every 10 min, retry failures with bounded backoff and expose cleanup health;
  - retain background task handles and cancel/await them during application lifespan shutdown;
  - `status()` document (see section 6).
- `whois.py`: classify private/reserved ranges locally (RFC 1918, loopback, link-local, reserved, multicast, `100.64.0.0/10`);
  public lookups through Team Cymru (`whois.cymru.com`, ASN), RDAP (`rdap.org`, then ARIN), RADb; first non-empty organisation wins;
  `WAF_WHOIS=off` disables all network lookups.

Check: offline regressions prove ingestion, independent stream failures/recovery, expired ownership retries,
retention recovery, and lifespan startup/shutdown without AWS access.

## 5. Phase 3 - API

File: `app/main.py`. Implement the contract in section 6, with these rules:

- Every list filter goes through a whitelist (`LIST_FILTERS` maps parameter to column); sort columns are whitelisted; limits are capped.
- Free-text `q` escapes `% _ \` and uses `LIKE ... ESCAPE '\'`.
- Bad input returns 400 (never 500). Time window must satisfy `to > from` and fit in retention.
- Security headers middleware (CSP `default-src 'none'`; script/style/font/connect/img `'self'`, `style-src` also `'unsafe-inline'`, `img-src` also `data:`;
  `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`; `Cache-Control: no-store` for `/api/`).
- One ASGI guard middleware: `Host` allow-list (`WAF_ALLOWED_HOSTS`, DNS rebinding), reject non-GET requests that are
  cross-site (`Origin` differs from `Host`, or `Sec-Fetch-Site: cross-site`), and the optional `WAF_BASIC_AUTH` gate
  (validated at startup and fail closed, constant-time comparison, throttle after 10 failures in 5 minutes, log failures).
  Exempt only `scope["path"] == "/healthz"`; never decide on `request.url`, which is rebuilt from the `Host` header.
- Handlers that touch SQLite are sync functions (threadpool), with a per-request SQLite time limit via a progress handler.
  Streaming CSV export opens its own connection (`check_same_thread=False`) because Starlette iterates sync generators on
  worker threads.
- POST bodies must be `application/json`. Cap SSE subscribers. Parse `status` with `isascii() and isdigit()`.
- Deep Search: strict validators, at least one narrowing filter, 30 searches/hour/client and 120/hour total (pruned maps),
  optional daily scan budget, max 4 running, 24 h and 2,000 row caps,
  async job in a worker thread, results enriched with ownership and rule scope, jobs expire after 15 minutes.
- CSV export: stream, cap 50,000 rows, prefix cells starting with `= + - @ \t \r` with `'`.
- Demo mode: `WAF_DEV_FAKE=1` seeds `devfake.py` data and emits fake live events; it must use only fictional values
  (`example.com`, `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, account IDs like `111111111111`).

## 6. API contract (what the UI consumes)

Filters (all endpoints except where noted): `range` (`5m|15m|30m|1h|3h|6h|12h|24h|48h|72h`) or `from`/`to` epoch ms;
repeatable `account host rule inner_rule country ip org path ua method rule_type scope region status`; free text `q` (max 200 chars).

- `GET /api/status` ->
  `{ok, credential{profile,label,kind,identity,regions[]}, selecting, attempts[{profile,label,kind,ok,identity,error?,regions{}}],
  backfilling, backfill_progress, last_poll_ms, last_error, events_stored, latest_event_ms, athena_queries, athena_scanned_mb,
  whois{enabled,resolved,pending}, started_ms, now_ms, retention_hours, poll_seconds}`
- `GET /api/summary` ->
  `{range{from,to,bucket_s}, kpis{blocked,allowed|null,unique_ips,unique_rules,unique_hosts,unique_accounts,last_blocked_ms,block_rate|null,top_rule?},
  series[{t,blocked,allowed|null}], top{rules,ips,orgs,hosts,accounts,countries,paths,user_agents,methods,rule_types,scopes},
  traffic_hosts[{host,account,account_name,allowed,blocked}]|null, allowed_applicable}`
  Bucket size is the smallest of 60 s, 5 min, 15 min, 30 min, 1 h, 2 h, 4 h that yields at most 160 buckets.
- `GET /api/events?sort&dir&limit&offset` -> `{total, rows[...], limit, offset}`; row fields:
  `id ts account account_name region ip country resource host path method status rule rule_type rule_scope rule_short inner_rule term_label term_action cond match_loc matched_field ua org net_name asn org_state`.
- `GET /api/events/{id}` -> every stored column plus `org net_name asn geo_country geo_city org_via org_state`. The id contains `:` and may contain `/`.
- `GET /api/facets?range=` -> `{accounts[{value,label,n}], hosts, rules, inner_rules, countries, orgs, methods, rule_types, scopes, regions, ips}` (each `[{value,n}]`).
- `GET /api/export.csv` -> streamed CSV of the current filters.
- `GET /api/stream` -> SSE; events `blocked` `{count, rows[]}` and `tick`; keepalive comment every 15 s; `retry: 3000`.
- `POST /api/search` `{disposition?, ip?, account?, host?, country?, rule?, path?, method?, status?, hours?, limit?, region?}` -> `{id}`;
  `GET /api/search/{id}` -> `{id, state: running|done|error, elapsed_s, rows[], error, scanned_mb, filters, window{from,to}, truncated,
  partial, searched_regions[], skipped_regions{region: reason}}`. Fail an unavailable explicitly selected region;
  preserve rows from successful regions and warn when an all-regions search is partial.

## 7. Phase 4 - UI (use the Opus-class model)

Directory: `app/static/`. Vanilla ES modules, no build tooling, no frameworks, no CDN, self-hosted OFL fonts. The result should
feel like a calm, dense security operations console, not a generic admin template.

Design direction (what the shipped UI does; reproduce or improve):

- Dark theme with one hot accent for "blocked" (red-orange) and one cool accent for "allowed" (teal). Rule scopes have fixed colours:
  custom (amber), rate-based (blue), AWS managed (orange), other managed (violet), other (grey).
- Type: a condensed display face for numerals and headings, a clean grotesque for text, a monospace for data (IPs, rules, paths).
- Layout, top to bottom: brand and telemetry strip (live state, newest block age, last poll age, credential label, IP-owner progress, backfill bar);
  tabs (Blocked traffic, Deep search); time presets, search box and filter chips; KPI strip; traffic-over-time chart
  (split allowed/blocked or log scale, drag to zoom, click bucket to focus); terminating-rules panel with scope and type breakdown bars;
  top lists (source IPs, networks/orgs, countries, hosts, accounts, paths, user agents, methods and rule types); traffic-by-host
  (allowed vs blocked, block rate); the blocked-requests table (sortable, paged, row density toggle); row drawer; Deep Search form and results table.
- The terminating rule is a "verdict stamp": scope tag, short rule name, rule-type tag and, for managed groups, the inner rule chip.
- Every value that can be filtered is clickable and adds a filter chip. Filters are mirrored in the URL hash so views are shareable.
- States to design explicitly: loading skeletons, empty results, backfilling, reconnecting, no working credentials (banner listing
  each attempted region and its error), pending/unknown IP ownership, private-range source IPs.
- Accessibility: keyboard-first (`/` search, `j`/`k` rows, `Enter` details, `Esc` close, `[`/`]` pages, `g` newest, `l` live,
  `u` UTC/local, `d` density, `1`/`2` tabs, `?` help), visible focus, labelled controls, colour is never the only signal, responsive down to tablet width.
- Safety: render all log-derived strings with `textContent`/DOM APIs only. No `innerHTML`. No inline scripts (CSP).
- Test it with headless Chrome at several widths against `WAF_DEV_FAKE=1` data, and review screenshots before accepting.

Hand the UI model: the API contract above, the CSP constraints, the demo-mode command, and the design direction. Do not hand it credentials.

## 8. Phase 5 - packaging

- `Dockerfile`: `python:3.12-slim` pinned by digest, `pip install --require-hashes --only-binary :all:` from a pip-compile lock, non-root uid 10001, `/data` volume, healthcheck on `/healthz`, one uvicorn worker, no signing helper or credentials.
- `docker-compose.yml`: loopback port binding by default, env passthrough from `.env`, named volume, read-only root FS with a `/tmp` tmpfs,
  `cap_drop: [ALL]`, `no-new-privileges`, 1 GiB / 1.5 CPU / 256 pids, bounded logs; optional commented volume mounts
  for `accounts.json` and an AWS config directory.
- `.env.example` with placeholders only; `.gitignore` covers `.env`, `accounts.json`, data, keys and certificates.

## 9. Phase 6 - docs and screenshots

- `README.md` (what, AI disclosure, features, architecture, polling schedule, quick start, credentials, configuration, API, troubleshooting),
  `docs/architecture.md`, `docs/iam.md`, this file, `AGENTS.md`, `LICENSE`.
- Screenshots: run demo mode, capture with headless Chrome (`scripts/screenshots.py`). If you capture from a real deployment instead,
  you must anonymise every account, host, IP, rule, user agent, path and organisation first, then re-scan the images and their source data.

## 10. Phase 7 - acceptance checklist

- [ ] `python -m unittest tests.test_backend` passes with no AWS credentials.
- [ ] `WAF_DEV_FAKE=1` starts, `/api/status`, `/api/summary`, `/api/events` respond, and the UI renders with no console errors.
- [ ] `docker compose build` succeeds; the container is healthy and runs as a non-root user.
- [ ] With real credentials: status shows each region `ok`, backfill completes, a count of blocked requests matches a direct Athena query
  for the same window (within the Security Lake delay), the terminating rule column is populated.
- [ ] A bogus credential produces a clear banner with per-region errors, not a crash.
- [ ] `grep -rniE "<your-org-terms>|[0-9]{12}|arn:aws|AKIA|ASIA|BEGIN .*KEY"` over the tree finds only placeholders and the documented fake IDs.
- [ ] No `.env`, certificates, keys, cached data or `__pycache__` in the tree.
- [ ] All mutating AWS actions are absent from the code and from the IAM policy in `docs/iam.md`.
- [ ] `pip-audit -r requirements.txt` reports no known vulnerabilities.
- [ ] A request with `Host: x/healthz?` to a protected route is rejected; a foreign `Host` gets 400; a cross-site POST gets 403.
- [ ] One Deep Search per filter type (IP, host, account, path, rule, country, method, status) succeeds against a real workgroup.

## 11. Lessons learned (read before debugging)

- **Lake Formation, not IAM, usually hides the tables.** `TABLE_NOT_FOUND` means "no `DESCRIBE`", not "no table". Grant `DESCRIBE` on the
  database and `DESCRIBE`+`SELECT` on the table to the role.
- The Athena `primary` workgroup has no result location unless you set one; pass `WAF_ATHENA_OUTPUT`.
- Use `time_dt` for time predicates. `time` is an epoch value and does not prune well.
- Allowed traffic volume dwarfs blocked traffic. Measure first, then decide rows vs counts per source.
- Security Lake data arrives a few minutes late and sometimes later. Overlap windows and idempotent writes are what make counts match.
- Containers on EC2 need IMDSv2 hop limit 2 to use the instance profile.
- Custom Docker networks can have broken DNS on some hosts; if credential probes hang, try the default bridge network.
- WHOIS-style lookups can be slow; never block the ingest path on them and never mark a source down on a single slow call.
- Keep one worker process: ingest loops and SSE subscribers live in memory.
- Athena `ExecutionParameters` are expressions, not bound strings: unquoted text either errors or is read as a column name.
- An independent security audit of the first public version found a Host-header auth bypass in an old Starlette, missing
  DNS-rebinding protection, a fail-open auth config and the parameter-quoting issue above. Keep the regression tests.

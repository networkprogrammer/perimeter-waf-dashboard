# Front-end (static)

Vanilla ES modules, no build step, no runtime external requests (strict Content-Security-Policy).

- `index.html`, `app.css`, `app.js` (entry module)
- `js/` - `state.js` (filters, URL hash, API), `filterbar.js`, `panels.js` (KPIs, rules, top lists),
  `chart.js` (SVG), `table.js`, `drawer.js`, `search.js` (Deep Search), `components.js`, `util.js`
- `fonts/` - self-hosted OFL fonts, see `fonts/LICENSE-fonts.txt`

All log-derived values are rendered with `textContent` / DOM APIs only. Do not introduce `innerHTML`.

Filters (all repeatable, mirrored in the URL hash and sent to `/api/summary`, `/api/events`,
`/api/export.csv`): account, host, rule, inner_rule, country, ip, org, path, ua, method, rule_type,
scope, region, status, plus free-text `q` (also matches org / net_name / asn). `path` and `ua` are exact-match;
their popover suggestions come from the current summary top lists because `/api/facets` does not return them.

Rule scopes (`rule_scope`, computed by `store.classify_rule`): `custom`, `rate-based`, `aws-managed`, `managed`, `other`.
Labels and colours live in `components.js` (`SCOPE_LABEL`, `SCOPE_TITLE`) and `app.css` (`[data-scope=...]`).

IP ownership (`org`, `net_name`, `asn`, `org_state`): rendered by `orgCell()` in `components.js` with four states -
resolved (org + ASN tag), `pending` ("resolving..." shimmer), `unknown` (muted) and the "Private / reserved address"
org (PRIVATE tag). Live SSE rows carry no ownership yet and are shown as pending; `table.js` re-reads the current page
every 15 s while pending rows are visible and patches only the org cells.

Custom windows (drag-zoom on the chart) request facets with the exact selected `from`/`to` window.
Relative windows continue to use the selected `range=` preset.

Live recovery: if SSE disconnects, the 30 s fallback reloads the current table page, summary and status while
live updates are enabled. Every SSE `open` also reloads them because the stream does not replay missed events.
Recovery preserves the current filters, sort and page, and does not reload paused views; incoming blocked
messages still use the existing pending-row pill behavior.

Deep Search jobs keep `state: "done"` for partial success. When `partial` is true, the results panel shows a
warning with `searched_regions` and `skipped_regions` (region-to-reason mapping). Successful rows remain sortable,
filterable and exportable as CSV. Empty partial results describe only the searched regions, not the whole lake.
An explicitly selected unavailable region remains a failed search. Coverage and errors render only as text.

## Behavioral regression tests

Run without AWS, browser packages, npm dependencies or a build step (Node.js 20+):

```sh
node --experimental-vm-modules --test tests/test_frontend.mjs
```

The built-in Node test runner loads the real entry/search modules in isolated VM contexts with fake event
streams, timers, API responses and a minimal DOM. It exercises fallback/reconnect recovery, pause semantics,
exact facet windows, partial-result warnings, sorting/filtering/redraw and successful-row CSV export.
The VM modules flag is required; Node may print an experimental-feature warning. Browser smoke checks are
still needed for actual EventSource reconnects, focus/layout and warning accessibility.

Keyboard: `/` search, `j`/`k` rows, `Enter` details, `Esc` close, `[`/`]` page, `g` newest,
`i`/`r`/`h`/`o`/`s` drawer actions, `l` live, `u` UTC, `d` density, `1`/`2` views, `?` help.

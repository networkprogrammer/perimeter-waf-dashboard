// Global filter state, URL-hash mirroring, query building, API access and client-side matching
// of live SSE rows against the active filters.

export const RANGES = ["5m", "15m", "30m", "1h", "3h", "6h", "12h", "24h", "48h", "72h"];
export const RANGE_SECS = { "5m": 300, "15m": 900, "30m": 1800, "1h": 3600, "3h": 10800, "6h": 21600, "12h": 43200, "24h": 86400, "48h": 172800, "72h": 259200 };

// key: query param; facet: /api/facets key; field: row column
export const FILTERS = [
  { key: "account", label: "Account", facet: "accounts", field: "account" },
  { key: "host", label: "Host", facet: "hosts", field: "host" },
  { key: "rule", label: "Rule", facet: "rules", field: "rule" },
  { key: "inner_rule", label: "Inner rule", facet: "inner_rules", field: "inner_rule" },
  { key: "country", label: "Country", facet: "countries", field: "country" },
  { key: "ip", label: "Source IP", facet: "ips", field: "ip", free: true },
  { key: "org", label: "Org", facet: "orgs", field: "org" },
  { key: "path", label: "Path", facet: null, top: "paths", topField: "path", field: "path", free: true },
  { key: "ua", label: "User agent", facet: null, top: "user_agents", topField: "ua", field: "ua", free: true },
  { key: "method", label: "Method", facet: "methods", field: "method" },
  { key: "rule_type", label: "Rule type", facet: "rule_types", field: "rule_type" },
  { key: "scope", label: "Scope", facet: "scopes", field: "rule_scope" },
  { key: "region", label: "Region", facet: "regions", field: "region" },
  { key: "status", label: "Status", facet: null, field: "status", free: true,
    preset: ["403", "405", "429", "400", "404", "200", "302", "500", "502", "503"] },
];
export const FILTER_BY_KEY = Object.fromEntries(FILTERS.map((f) => [f.key, f]));
export const SORTABLE = new Set(["ts", "account_name", "ip", "org", "country", "host", "path", "method", "status", "rule", "rule_type", "inner_rule"]);

const emptyLists = () => Object.fromEntries(FILTERS.map((f) => [f.key, []]));

export const state = {
  view: "live",
  range: "1h",
  from: null,
  to: null,
  q: "",
  f: emptyLists(),
  sort: "ts",
  dir: "desc",
  limit: 100,
  offset: 0,
  live: localStorage.getItem("waf.live") !== "0",
};

// labels for values (account id -> name), filled from facets / summaries
export const labels = { account: new Map() };
export function valueLabel(key, v) {
  if (key === "account") {
    const n = labels.account.get(String(v));
    return n && n !== v ? n : String(v);
  }
  return String(v);
}

// tiny event bus -----------------------------------------------------------
const subs = new Map();
export function on(name, fn) {
  if (!subs.has(name)) subs.set(name, new Set());
  subs.get(name).add(fn);
}
export function emit(name, data) {
  for (const fn of subs.get(name) || []) {
    try { fn(data); } catch (e) { console.error(e); }
  }
}

// filters -----------------------------------------------------------------
export function hasFilter(key, v) {
  return state.f[key].includes(String(v));
}
export function addFilter(key, v, { replace = false } = {}) {
  if (v == null || v === "" || !FILTER_BY_KEY[key]) return;
  v = String(v);
  if (key === "method") v = v.toUpperCase();
  if (replace) state.f[key] = [v];
  else if (!state.f[key].includes(v)) state.f[key] = [...state.f[key], v];
  else return;
  filtersChanged();
}
export function removeFilter(key, v) {
  state.f[key] = state.f[key].filter((x) => x !== String(v));
  filtersChanged();
}
export function setFilterValues(key, vals) {
  state.f[key] = [...new Set(vals.map(String))];
  filtersChanged();
}
export function clearAll() {
  state.f = emptyLists();
  state.q = "";
  filtersChanged();
}
export function setRange(r) {
  state.range = r;
  state.from = state.to = null;
  filtersChanged({ time: true });
}
export function setWindow(from, to) {
  from = Math.floor(from);
  to = Math.ceil(to);
  if (to - from < 60000) {
    const mid = (from + to) / 2;
    from = Math.floor(mid - 30000);
    to = Math.ceil(mid + 30000);
  }
  state.from = from;
  state.to = Math.min(to, Date.now() + 1000);
  filtersChanged({ time: true });
}
export function setQ(q) {
  if (q === state.q) return;
  state.q = q;
  filtersChanged();
}
export function filtersChanged(opts = {}) {
  state.offset = 0;
  writeHash();
  emit("filters", opts);
}
export const activeCount = () => FILTERS.reduce((n, f) => n + state.f[f.key].length, 0) + (state.q ? 1 : 0);

// query string ------------------------------------------------------------
export function timeParams(p = new URLSearchParams()) {
  if (state.from) {
    p.set("from", state.from);
    p.set("to", state.to || Date.now());
  } else p.set("range", state.range);
  return p;
}
export function filterParams({ withSort = false, withPage = false } = {}) {
  const p = timeParams();
  if (state.q) p.set("q", state.q);
  for (const f of FILTERS) for (const v of state.f[f.key]) p.append(f.key, v);
  if (withSort) {
    p.set("sort", state.sort);
    p.set("dir", state.dir);
  }
  if (withPage) {
    p.set("limit", state.limit);
    p.set("offset", state.offset);
  }
  return p;
}
export function windowBounds() {
  if (state.from) return [state.from, state.to || serverNow()];
  const now = serverNow();
  return [now - RANGE_SECS[state.range] * 1000, now];
}

// hash --------------------------------------------------------------------
let lastHash = "";
export function writeHash() {
  const p = new URLSearchParams();
  if (state.view !== "live") p.set("view", state.view);
  if (state.from) {
    p.set("from", state.from);
    p.set("to", state.to);
  } else if (state.range !== "1h") p.set("range", state.range);
  if (state.q) p.set("q", state.q);
  for (const f of FILTERS) for (const v of state.f[f.key]) p.append(f.key, v);
  if (state.sort !== "ts") p.set("sort", state.sort);
  if (state.dir !== "desc") p.set("dir", state.dir);
  if (state.limit !== 100) p.set("limit", state.limit);
  const hstr = p.toString();
  lastHash = hstr;
  const url = location.pathname + location.search + (hstr ? "#" + hstr : "");
  if (url !== location.pathname + location.search + location.hash) history.replaceState(null, "", url);
}
export function readHash() {
  const raw = location.hash.replace(/^#/, "");
  if (raw === lastHash && raw !== "") return false;
  lastHash = raw;
  const p = new URLSearchParams(raw);
  state.view = p.get("view") === "search" ? "search" : "live";
  const from = parseInt(p.get("from"), 10), to = parseInt(p.get("to"), 10);
  if (from > 0 && to > from) {
    state.from = from;
    state.to = to;
  } else {
    state.from = state.to = null;
  }
  state.range = RANGES.includes(p.get("range")) ? p.get("range") : "1h";
  state.q = (p.get("q") || "").slice(0, 200);
  state.f = emptyLists();
  for (const f of FILTERS) state.f[f.key] = [...new Set(p.getAll(f.key).filter(Boolean))].slice(0, 50);
  state.sort = SORTABLE.has(p.get("sort")) ? p.get("sort") : "ts";
  state.dir = p.get("dir") === "asc" ? "asc" : "desc";
  const lim = parseInt(p.get("limit"), 10);
  state.limit = [50, 100, 250, 500].includes(lim) ? lim : 100;
  state.offset = 0;
  return true;
}

// client-side match, mirroring the server's Filters.where() ---------------
const Q_COLS = ["ip", "host", "path", "rule", "inner_rule", "ua", "args", "account", "account_name", "country", "resource", "req_id", "term_label", "org", "net_name", "asn"];
export function matchRow(r) {
  const [from, to] = windowBounds();
  if (r.ts < from || (state.from && r.ts >= to)) return false;
  for (const f of FILTERS) {
    const vals = state.f[f.key];
    if (!vals.length) continue;
    const v = r[f.field];
    if (v == null || !vals.includes(String(v))) return false;
  }
  if (state.q) {
    const needle = state.q.toLowerCase();
    if (!Q_COLS.some((c) => r[c] != null && String(r[c]).toLowerCase().includes(needle))) return false;
  }
  return true;
}

// API ---------------------------------------------------------------------
export class ApiError extends Error {
  constructor(msg, status) {
    super(msg);
    this.status = status;
  }
}
export async function api(path, { signal, method = "GET", body } = {}) {
  let res;
  try {
    res = await fetch(path, {
      method, signal, credentials: "same-origin",
      headers: body ? { "Content-Type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch (e) {
    if (e.name === "AbortError") throw e;
    throw new ApiError("Network error: server unreachable", 0);
  }
  if (!res.ok) {
    let detail = res.statusText || "HTTP " + res.status;
    try {
      const j = await res.json();
      if (j && j.detail) detail = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail);
    } catch { /* non-JSON error body */ }
    throw new ApiError(detail, res.status);
  }
  return res.json();
}

// Cancels the previous in-flight request of the same slot.
const slots = new Map();
export async function latest(slot, path) {
  slots.get(slot)?.abort();
  const ac = new AbortController();
  slots.set(slot, ac);
  try {
    return await api(path, { signal: ac.signal });
  } finally {
    if (slots.get(slot) === ac) slots.delete(slot);
  }
}

// server clock skew (server now - client now), updated from /api/status
export const clock = { skew: 0 };
export const serverNow = () => Date.now() + clock.skew;

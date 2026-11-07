import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { SourceTextModule, SyntheticModule, createContext } from "node:vm";

const STATIC = new URL("../app/static/", import.meta.url);

class DomNode {
  constructor(tag = "#text", text = "") {
    this.tagName = tag.toUpperCase();
    this.children = [];
    this.attributes = {};
    this.dataset = {};
    this.style = {};
    this.listeners = new Map();
    this.value = "";
    this._text = text;
    this.classList = {
      add: (...names) => { this.className = [...new Set([...(this.className || "").split(" "), ...names])].filter(Boolean).join(" "); },
      toggle: () => {},
    };
  }
  set textContent(text) { this._text = String(text); this.children = []; }
  get textContent() { return this._text + this.children.map((node) => node.textContent).join(""); }
  get firstChild() { return this.children[0]; }
  appendChild(node) { this.children.push(node); node.parentElement = this; return node; }
  removeChild(node) { this.children.splice(this.children.indexOf(node), 1); return node; }
  replaceChildren(...nodes) {
    this._text = "";
    this.children = [];
    for (const node of nodes) this.appendChild(node instanceof DomNode ? node : new DomNode("#text", String(node)));
  }
  setAttribute(key, value) { this.attributes[key] = String(value); if (key === "class") this.className = String(value); }
  removeAttribute(key) { delete this.attributes[key]; }
  getAttribute(key) { return this.attributes[key]; }
  addEventListener(event, handler) {
    if (!this.listeners.has(event)) this.listeners.set(event, []);
    this.listeners.get(event).push(handler);
  }
  async dispatch(event, data = {}) {
    for (const handler of this.listeners.get(event) || []) await handler({ preventDefault() {}, ...data });
  }
  contains(node) { return this === node || this.children.some((child) => child.contains(node)); }
  querySelectorAll(selector) {
    const nodes = this.children.flatMap((child) => [child, ...child.querySelectorAll("*")]);
    if (selector === "*") return nodes;
    if (selector === "[aria-invalid]") return nodes.filter((node) => node.attributes["aria-invalid"]);
    return nodes.filter((node) => node.tagName.toLowerCase() === selector);
  }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  focus() {}
  reset() {}
  click() { return this.dispatch("click"); }
  remove() { this.parentElement?.removeChild(this); }
}

function environment() {
  const nodes = new Map();
  const get = (id) => {
    if (!nodes.has(id)) nodes.set(id, new DomNode("div"));
    return nodes.get(id);
  };
  const document = {
    getElementById: get,
    querySelector: (selector) => get(selector.slice(1)),
    createElement: (tag) => new DomNode(tag),
    createTextNode: (text) => new DomNode("#text", text),
    documentElement: new DomNode("html"),
    body: new DomNode("body"),
    addEventListener() {},
  };
  const intervals = new Map(), timeouts = new Map();
  let timerId = 0;
  const timers = {
    setInterval: (fn, ms) => { intervals.set(++timerId, { fn, ms }); return timerId; },
    clearInterval: (id) => intervals.delete(id),
    setTimeout: (fn, ms) => { timeouts.set(++timerId, { fn, ms }); return timerId; },
    clearTimeout: (id) => timeouts.delete(id),
  };
  const storage = new Map();
  const globals = {
    console, URLSearchParams, Date, Intl, performance, Blob, Node: DomNode, document,
    localStorage: { getItem: (key) => storage.get(key) ?? null, setItem: (key, value) => storage.set(key, value) },
    ...timers,
  };
  return { nodes, get, document, globals, intervals, timeouts };
}

async function loadModule(entry, globals, stubs = {}) {
  const context = createContext(globals);
  const modules = new Map();
  async function load(relative) {
    if (modules.has(relative)) return modules.get(relative);
    let module;
    if (stubs[relative]) {
      const exports = stubs[relative];
      module = new SyntheticModule(Object.keys(exports), function () {
        for (const [name, value] of Object.entries(exports)) this.setExport(name, value);
      }, { context, identifier: new URL(relative, STATIC).href });
    } else {
      module = new SourceTextModule(await readFile(new URL(relative, STATIC), "utf8"), {
        context, identifier: new URL(relative, STATIC).href,
      });
    }
    modules.set(relative, module);
    return module;
  }
  const module = await load(entry);
  await module.link((specifier, referencing) => load(new URL(specifier, referencing.identifier).href.slice(STATIC.href.length)));
  await module.evaluate();
  return module.namespace;
}

async function appHarness({ live = true, from = null, to = null } = {}) {
  const env = environment();
  const state = { live, from, to, range: "1h", view: "live", offset: 0, sort: "ts", dir: "desc" };
  const requests = [], connections = [];
  const calls = { summary: 0, status: 0, table: 0, blocked: 0 };
  const noop = () => {};
  class EventSource extends DomNode {
    static CLOSED = 2;
    constructor(url) { super(); this.url = url; this.readyState = 0; connections.push(this); }
    close() { this.readyState = EventSource.CLOSED; }
  }
  const timeParams = () => new URLSearchParams(state.from ? { from: state.from, to: state.to } : { range: state.range });
  const util = {
    $: (selector) => env.get(selector.slice(1)), h: () => new DomNode("div"), replace: noop,
    fmtAge: String, fmtPct: String, fmtInt: String, prefs: {}, throttle: (fn) => fn,
    debounce: (fn) => fn, toast: noop,
  };
  const panels = Object.fromEntries([
    "initKpis", "renderKpis", "kpiError", "noteLiveBlock", "initRules", "renderRules", "initTops",
    "renderTops", "topsLoading", "topsError", "initWire", "pushWire",
  ].map((name) => [name, noop]));
  const filterbar = Object.fromEntries([
    "initFilterbar", "setFacets", "setTopOptions", "renderRange", "renderChips", "closePopover", "popoverOpen",
  ].map((name) => [name, noop]));
  env.get("ds-region").dataset.regions = "";
  await loadModule("app.js", { ...env.globals, EventSource, window: { addEventListener() {} } }, {
    "js/util.js": util,
    "js/state.js": {
      state, on: noop, emit: noop, readHash: noop, writeHash: noop, filterParams: timeParams, timeParams,
      latest: async (key, path) => {
        requests.push(path);
        if (key === "summary") {
          calls.summary++;
          return { top: {}, series: [], range: { bucket_s: 60 }, kpis: {} };
        }
        return {};
      },
      api: async () => { calls.status++; return { ok: true }; },
      addFilter: noop, clock: {}, serverNow: Date.now, setWindow: noop, labels: { account: new Map() },
      RANGES: ["1h", "24h", "72h"], RANGE_SECS: { "1h": 3600, "24h": 86400, "72h": 259200 },
    },
    "js/filterbar.js": filterbar,
    "js/panels.js": panels,
    "js/chart.js": { createChart: () => Object.fromEntries(["loading", "update", "error"].map((name) => [name, noop])) },
    "js/table.js": { createTable: () => ({ load: () => calls.table++, addLive: () => { calls.blocked++; return 1; }, showPill: noop }) },
    "js/drawer.js": { createDrawer: () => ({}) },
    "js/search.js": { createSearch: () => ({ setOptions: noop }) },
  });
  return { ...env, state, calls, requests, connections, stream: connections[0] };
}

function fireIntervals(env, ms) {
  for (const timer of [...env.intervals.values()]) if (timer.ms === ms) timer.fn();
}

const settle = () => new Promise((resolve) => setImmediate(resolve));

test("polling fallback resynchronizes table rows as well as summary and status", async () => {
  const env = await appHarness();
  const before = { ...env.calls };
  await env.stream.dispatch("error");
  fireIntervals(env, 30000);
  assert.equal(env.calls.table, before.table + 1, "missed rows must be fetched during polling fallback");
  assert.equal(env.calls.summary, before.summary + 1);
  assert.equal(env.calls.status, before.status + 1);
});

test("SSE open resynchronizes missed rows and cancels fallback after reconnect", async () => {
  const env = await appHarness();
  await env.stream.dispatch("open");
  await env.stream.dispatch("error");
  const before = { ...env.calls };
  await env.stream.dispatch("open");
  assert.equal(env.calls.table, before.table + 1, "reconnecting must fetch rows missed while disconnected");
  assert.equal(env.calls.summary, before.summary + 1);
  assert.equal(env.calls.status, before.status + 1);
  assert.equal([...env.intervals.values()].filter((timer) => timer.ms === 30000).length, 0);
});

test("paused reconnect and fallback keep the table and summary unchanged", async () => {
  const env = await appHarness({ live: false });
  const before = { ...env.calls };
  await env.stream.dispatch("error");
  fireIntervals(env, 30000);
  await env.stream.dispatch("open");
  assert.deepEqual(env.calls, before);
  await env.stream.dispatch("blocked", { data: JSON.stringify({ rows: [{ ts: 1 }] }) });
  assert.equal(env.calls.blocked, before.blocked + 1, "paused mode still tracks the existing pending-row pill");
  assert.equal(env.calls.table, before.table);
});

test("fallback evaluates live state on every poll and recovers after resuming", async () => {
  const env = await appHarness();
  await env.stream.dispatch("error");
  const before = { ...env.calls };
  env.state.live = false;
  fireIntervals(env, 30000);
  assert.deepEqual(env.calls, before);
  env.state.live = true;
  fireIntervals(env, 30000);
  assert.equal(env.calls.table, before.table + 1);
  assert.equal(env.calls.summary, before.summary + 1);
  assert.equal(env.calls.status, before.status + 1);
});

test("first SSE open catches rows missed during the initial connection", async () => {
  const env = await appHarness();
  const before = { ...env.calls };
  await env.stream.dispatch("open");
  assert.equal(env.calls.table, before.table + 1);
  assert.equal(env.calls.summary, before.summary + 1);
  assert.equal(env.calls.status, before.status + 1);
});

test("repeated stream errors only start one polling interval", async () => {
  const env = await appHarness();
  await env.stream.dispatch("error");
  await env.stream.dispatch("error");
  const before = env.calls.table;
  fireIntervals(env, 30000);
  assert.equal([...env.intervals.values()].filter((timer) => timer.ms === 30000).length, 1);
  assert.equal(env.calls.table, before + 1);
});

test("facets request the exact selected custom window", async () => {
  const to = Date.now() - 60000;
  const from = to - 300000;
  const env = await appHarness({ from, to });
  const path = env.requests.find((request) => request.startsWith("/api/facets?"));
  const params = new URLSearchParams(path.split("?")[1]);
  assert.equal(params.get("from"), String(from));
  assert.equal(params.get("to"), String(to));
  assert.equal(params.has("range"), false);
});

test("facets retain the selected relative range", async () => {
  const env = await appHarness();
  assert.ok(env.requests.includes("/api/facets?range=1h"));
});

const successfulRow = {
  ts: 1700000000000, account: "123456789012", ip: "192.0.2.1", host: "example.com", path: "/example",
  method: "GET", status: "403", disp: "Blocked", rule: "ExampleRule", src_region: "us-east-1",
};

async function searchHarness(result) {
  const env = environment();
  const values = { ip: "192.0.2.1", hours: "1", region: "all", limit: "500" };
  const downloads = [];
  const form = env.get("ds-form");
  form.elements = Object.fromEntries(["ip", "host", "account", "path", "country", "rule", "method", "status"].map((key) => [key, new DomNode("input")]));
  const module = await loadModule("js/search.js", {
    ...env.globals,
    FormData: class { get(key) { return values[key] || ""; } },
    URL: { createObjectURL: (blob) => { downloads.push(blob); return "blob:example"; }, revokeObjectURL() {} },
  }, { "js/state.js": { api: async (path) => path === "/api/search" ? { id: "example-job" } : result } });
  const search = module.createSearch();
  await form.dispatch("submit");
  await settle();
  return { ...env, downloads, search };
}

function findNode(root, predicate) {
  if (predicate(root)) return root;
  for (const child of root.children) {
    const found = findNode(child, predicate);
    if (found) return found;
  }
  return null;
}

const partialResult = (rows = [successfulRow]) => ({
  state: "done", rows, elapsed_s: 1, scanned_mb: 2, partial: true,
  searched_regions: ["us-east-1"], skipped_regions: { "us-west-2": "Table unavailable <script>alert(1)</script>" },
});

test("partial Deep Search warns with searched/skipped regions and preserves rows and CSV", async () => {
  const env = await searchHarness(partialResult());
  const body = env.get("ds-body");
  assert.match(body.textContent, /Partial results/i);
  assert.match(body.textContent, /Searched regions: us-east-1/);
  assert.match(body.textContent, /Skipped regions: us-west-2/);
  assert.match(body.textContent, /Table unavailable <script>alert\(1\)<\/script>/);
  assert.equal(findNode(body, (node) => node.tagName === "SCRIPT"), null, "region errors must remain literal text");
  assert.ok(findNode(body, (node) => node.getAttribute("role") === "status"), "warning should be announced");
  assert.ok(findNode(body, (node) => node.tagName === "TABLE"));
  assert.match(body.textContent, /example.com/);
  assert.equal(env.get("ds-csv").disabled, false);
  await env.get("ds-csv").dispatch("click");
  assert.equal(env.downloads.length, 1);
  assert.match(await env.downloads[0].text(), /example.com/);
  assert.doesNotMatch(await env.downloads[0].text(), /Table unavailable/);
});

test("partial warning survives table sorting, filtering and timezone redraw", async () => {
  const env = await searchHarness(partialResult());
  const sortButton = findNode(env.get("ds-body"), (node) => node.tagName === "BUTTON");
  await sortButton.dispatch("click");
  assert.match(env.get("ds-body").textContent, /Partial results/i);
  env.get("ds-filter").value = "no-match";
  await env.get("ds-filter").dispatch("input");
  for (const [id, timer] of [...env.timeouts.entries()]) {
    if (timer.ms === 150) { env.timeouts.delete(id); timer.fn(); }
  }
  assert.match(env.get("ds-body").textContent, /Partial results/i);
  assert.match(env.get("ds-body").textContent, /FILTERED OUT/);
  env.search.redraw();
  assert.match(env.get("ds-body").textContent, /Partial results/i);
  assert.match(env.get("ds-body").textContent, /Skipped regions: us-west-2/);
});

test("zero-row partial results do not claim all regions had no matches", async () => {
  const env = await searchHarness(partialResult([]));
  assert.match(env.get("ds-body").textContent, /Partial results/i);
  assert.match(env.get("ds-body").textContent, /NO MATCHES IN SEARCHED REGIONS/);
  assert.equal(env.get("ds-csv").disabled, true);
});

test("complete Deep Search keeps successful results without a partial warning", async () => {
  const env = await searchHarness({ ...partialResult(), partial: false, skipped_regions: {} });
  assert.doesNotMatch(env.get("ds-body").textContent, /Partial results/i);
  assert.ok(findNode(env.get("ds-body"), (node) => node.tagName === "TABLE"));
  assert.equal(env.get("ds-csv").disabled, false);
});

test("an explicit unavailable-region error remains an error with no CSV", async () => {
  const env = await searchHarness({ state: "error", error: "Selected region is unavailable", elapsed_s: 1 });
  assert.match(env.get("ds-body").textContent, /SEARCH FAILED/);
  assert.match(env.get("ds-body").textContent, /Selected region is unavailable/);
  assert.equal(env.get("ds-csv").disabled, true);
  assert.equal(findNode(env.get("ds-body"), (node) => node.tagName === "TABLE"), null);
});

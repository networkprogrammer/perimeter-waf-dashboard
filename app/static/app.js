// Perimeter - WAF Watch. Entry module: wires state, panels, table, drawer, deep search, live stream.
import { $, h, replace, fmtAge, fmtPct, fmtInt, prefs, throttle, debounce, toast } from "./js/util.js";
import {
  state, on, emit, readHash, writeHash, filterParams, timeParams, latest, api, addFilter, clock, setWindow, labels,
} from "./js/state.js";
import { initFilterbar, setFacets, setTopOptions, renderRange, renderChips, closePopover, popoverOpen } from "./js/filterbar.js";
import { initKpis, renderKpis, kpiError, noteLiveBlock, initRules, renderRules, initTops, renderTops, topsLoading, topsError, initWire, pushWire } from "./js/panels.js";
import { createChart } from "./js/chart.js";
import { createTable } from "./js/table.js";
import { createDrawer } from "./js/drawer.js";
import { createSearch } from "./js/search.js";

readHash();

// ---------------------------------------------------------------- prefs: density / tz
const densityBtn = $("#density-toggle");
const tzBtn = $("#tz-toggle");
function applyDensity(d) {
  document.documentElement.dataset.density = d;
  densityBtn.textContent = d === "compact" ? "COMPACT" : "COZY";
  densityBtn.setAttribute("aria-pressed", String(d === "compact"));
  localStorage.setItem("waf.density", d);
}
applyDensity(localStorage.getItem("waf.density") === "compact" ? "compact" : "cozy");
densityBtn.addEventListener("click", () => applyDensity(document.documentElement.dataset.density === "compact" ? "cozy" : "compact"));
function applyTz() {
  tzBtn.textContent = prefs.utc ? "UTC" : "LOCAL";
  tzBtn.setAttribute("aria-pressed", String(prefs.utc));
}
applyTz();
tzBtn.addEventListener("click", toggleTz);
function toggleTz() {
  prefs.utc = !prefs.utc;
  localStorage.setItem("waf.utc", prefs.utc ? "1" : "0");
  applyTz();
  renderRange();
  if (lastSummary) { chart.update(lastSummary); renderKpis(lastSummary, lastSummary); }
  table.refreshTimes();
  search.redraw();
  if (drawer.isOpen && drawer.current) drawer.open(drawer.current);
}

// ---------------------------------------------------------------- components
initFilterbar();
initKpis($("#kpis"));
initRules();
initTops($("#tops"));
initWire();

const chart = createChart($("#chart"), {
  onZoom: (a, b) => setWindow(a, b),
  onFocus: (a, b) => setWindow(a, b),
});
for (const b of $("#chart-mode").querySelectorAll("button")) {
  b.addEventListener("click", () => {
    for (const x of $("#chart-mode").querySelectorAll("button")) x.setAttribute("aria-pressed", String(x === b));
    localStorage.setItem("waf.chart", b.dataset.mode);
    chart.setMode(b.dataset.mode);
  });
}
if (localStorage.getItem("waf.chart") === "log") $("#chart-mode [data-mode='log']").click();

const drawer = createDrawer({
  onNav: (d) => {
    const r = table.move(d);
    if (r) drawer.open(r);
  },
  onDeepSearch: (r) => openDeepSearch({ ip: r.ip, hours: 1 }),
});
const table = createTable({ onOpen: (r) => drawer.open(r) });
const search = createSearch();

// ---------------------------------------------------------------- data loading
let lastSummary = null;
let summaryErr = false;
async function loadSummary() {
  if (!lastSummary) { chart.loading(); topsLoading(); }
  try {
    const d = await latest("summary", "/api/summary?" + filterParams());
    // accounts in summaries label chips even before facets load
    for (const a of d.top.accounts || []) if (a.account_name) labels.account.set(String(a.account), a.account_name);
    setTopOptions(d);
    renderKpis(d, lastSummary);
    chart.update(d);
    renderRules(d);
    renderTops(d);
    $("#chart-meta").textContent = `${fmtInt(d.series.length)} buckets of ${d.range.bucket_s >= 3600 ? d.range.bucket_s / 3600 + "h" : d.range.bucket_s / 60 + "m"}` +
      (d.allowed_applicable && d.kpis.block_rate != null ? `  /  block rate ${fmtPct(d.kpis.block_rate)}` : "");
    lastSummary = d;
    summaryErr = false;
  } catch (e) {
    if (e.name === "AbortError") return;
    summaryErr = true;
    lastSummary = null;
    kpiError(e.message);
    chart.error("Could not load: " + e.message);
    topsError("Could not load: " + e.message);
  }
}
const loadSummarySoon = throttle(loadSummary, 5000);

let facetsKey = "", facetsAt = 0;
async function loadFacets(force) {
  const key = timeParams().toString();
  if (!force && key === facetsKey && Date.now() - facetsAt < 60000) return;
  facetsKey = key;
  facetsAt = Date.now();
  try {
    const f = await latest("facets", "/api/facets?" + key);
    setFacets(f);
    search.setOptions(f);
  } catch (e) {
    if (e.name !== "AbortError") facetsAt = 0;
  }
}

function refreshAll(opts = {}) {
  loadSummary();
  table.load();
  loadFacets(opts.time);
}
const refreshSoon = debounce(refreshAll, 120);
on("filters", (opts) => {
  refreshSoon(opts || {});
  if (state.view !== "live") switchView("live");
});

// ---------------------------------------------------------------- status / header
const connEl = $("#conn"), connText = $("#conn-text");
let status = null, statusAt = 0, sseState = "connecting";
function setConn(st) {
  sseState = st;
  const shown = !state.live ? "paused" : st;
  connEl.dataset.state = shown;
  connText.textContent = { live: "Live", reconnecting: "Reconnecting", connecting: "Connecting", paused: "Paused" }[shown];
  connEl.title = st === "live" ? "Event stream connected" : st === "reconnecting" ? "Event stream lost; retrying. Falling back to polling every 30s." : "";
}

async function loadStatus() {
  try {
    status = await api("/api/status");
    statusAt = Date.now();
    if (status.now_ms) clock.skew = status.now_ms - Date.now();
    renderStatus();
  } catch (e) {
    renderBanners([{ kind: "bad", tag: "Server", msg: "Status endpoint unreachable: " + e.message }]);
  }
}
function tickFreshness() {
  if (!status) return;
  const since = Date.now() - statusAt;
  const fe = $("#fresh-event"), fp = $("#fresh-poll");
  const evAge = status.latest_event_ms ? status.now_ms - status.latest_event_ms + since : null;
  fe.textContent = evAge == null ? "none" : fmtAge(evAge) + " ago";
  fe.parentElement.classList.toggle("warn", evAge != null && evAge > 15 * 60000);
  if (status.last_poll_ms) {
    const pa = status.now_ms - status.last_poll_ms + since;
    fp.textContent = fmtAge(pa) + " ago";
    const lim = (status.poll_seconds || 30) * 1000;
    fp.parentElement.classList.toggle("warn", pa > lim * 3 && pa <= lim * 10);
    fp.parentElement.classList.toggle("bad", pa > lim * 10);
  } else {
    fp.textContent = status.credential && status.credential.kind === "dev" ? "n/a (dev)" : "never";
    fp.parentElement.classList.toggle("warn", !(status.credential && status.credential.kind === "dev"));
  }
}
setInterval(tickFreshness, 1000);

function renderStatus() {
  const s = status;
  const cred = s.credential || {};
  const ce = $("#cred");
  $("#cred-text").textContent = s.ok ? cred.label || cred.profile || "unknown" : "NO WORKING CREDENTIALS";
  ce.classList.toggle("bad", !s.ok);
  ce.title = [
    cred.profile && `profile: ${cred.profile}`, cred.kind && `kind: ${cred.kind}`,
    cred.identity && `identity: ${typeof cred.identity === "string" ? cred.identity : JSON.stringify(cred.identity)}`,
    cred.regions && cred.regions.length && `regions: ${cred.regions.join(", ")}`,
    `events stored: ${fmtInt(s.events_stored)}`, `athena: ${fmtInt(s.athena_queries)} queries / ${s.athena_scanned_mb} MB`,
    `retention: ${s.retention_hours}h, poll every ${s.poll_seconds}s`,
  ].filter(Boolean).join("\n");

  const rs = $("#ds-region");
  const want = (s.configured_regions || []).join(",");
  if (rs && rs.dataset.regions !== want) {
    rs.dataset.regions = want;
    const keep = rs.value;
    replace(rs, [h("option", { value: "all" }, "All regions"), ...(s.configured_regions || []).map((r) => h("option", { value: r }, r))]);
    if ([...rs.options].some((o) => o.value === keep)) rs.value = keep;
  }

  const bf = $("#backfill");
  bf.hidden = !s.backfilling;
  if (s.backfilling) {
    const pct = Math.round((s.backfill_progress || 0) * 100);
    $("#bf-fill").style.width = pct + "%";
    $("#bf-bar").setAttribute("aria-valuenow", String(pct));
    $("#bf-text").textContent = pct + "%";
  }

  renderWhois(s.whois);

  const banners = [];
  if (!s.ok) {
    banners.push({ kind: "bad", tag: "Credentials", msg: "The configured AWS credentials cannot read Security Lake. Data is stale until this succeeds. Last attempt:", attempts: s.attempts || [] });
  } else if (s.last_error) {
    banners.push({ kind: "warn", tag: "Ingest", msg: "Last poll failed: " + s.last_error });
  }
  renderBanners(banners);
  tickFreshness();
}

function renderWhois(w) {
  const el = $("#whois"), txt = $("#whois-text");
  if (!w) { el.hidden = true; return; }
  const pending = w.pending || 0;
  el.hidden = !pending || w.enabled === false;
  txt.textContent = `resolving ${fmtInt(pending)} IP${pending === 1 ? "" : "s"}`;
  el.classList.toggle("muted", true);
  el.title = `IP ownership (public WHOIS: Team Cymru / RDAP / RADb): ${fmtInt(w.resolved || 0)} resolved, ${fmtInt(pending)} queued`;
}

function renderBanners(list) {
  const root = $("#banners");
  replace(root, list.map((b) => {
    const msg = h("div.banner-msg", b.msg);
    if (b.attempts) {
      const ul = h("ul.attempts");
      if (!b.attempts.length) ul.appendChild(h("li", h("span.p", "-"), h("span.e", "no attempts recorded yet (credential selection pending)")));
      for (const a of b.attempts) {
        const regs = a.regions && Object.keys(a.regions).length
          ? Object.entries(a.regions).map(([r, v]) => h("div", { class: v === "ok" ? "ok" : "e" }, `${r}: ${v}`)) : null;
        ul.appendChild(h("li", h("span.p", { title: a.label || "" }, a.profile),
          h("span", { class: a.ok ? "ok" : "e" }, a.error || (a.ok ? "ok" : "no region usable"), regs)));
      }
      msg.appendChild(ul);
    }
    return h("div.banner", { class: "banner " + (b.kind === "warn" ? "warn" : ""), role: b.kind === "bad" ? "alert" : "status" },
      h("span.banner-tag", b.tag), msg, h("span"));
  }));
}

// ---------------------------------------------------------------- live stream
let es = null, fallbackT = null;
function resyncLive() {
  if (!state.live) return;
  loadSummary();
  loadStatus();
  table.load();
}
function startFallback() {
  if (fallbackT) return;
  fallbackT = setInterval(resyncLive, 30000);
}
function stopFallback() {
  clearInterval(fallbackT);
  fallbackT = null;
}
function connect() {
  if (es) es.close();
  setConn("connecting");
  es = new EventSource("/api/stream");
  es.addEventListener("open", () => {
    setConn("live");
    stopFallback();
    // SSE has no replay cursor; fetch the current page to recover rows missed while disconnected.
    resyncLive();
  });
  es.addEventListener("error", () => {
    setConn("reconnecting");
    startFallback();
    if (es.readyState === EventSource.CLOSED) setTimeout(connect, 5000);
  });
  es.addEventListener("blocked", (ev) => {
    let d;
    try { d = JSON.parse(ev.data); } catch { return; }
    const rows = Array.isArray(d.rows) ? d.rows : [];
    if (!rows.length) return;
    const n = table.addLive(rows);
    if (!state.live) return;
    pushWire(rows);
    if (n) for (const r of rows) noteLiveBlock(r.ts);
    loadSummarySoon();
  });
  es.addEventListener("tick", () => {
    if (!state.live) return;
    loadStatusSoon();
    loadSummarySoon();
  });
}
const loadStatusSoon = throttle(loadStatus, 3000);

// keep relative windows sliding even when the stream is quiet
setInterval(() => { if (state.live && !state.from && sseState === "live") loadSummary(); }, 60000);
setInterval(loadStatus, 15000);

const liveBtn = $("#live-toggle");
function applyLive() {
  liveBtn.setAttribute("aria-checked", String(state.live));
  liveBtn.title = state.live ? "Live updates on (L)" : "Live updates paused (L)";
  setConn(sseState);
  table.showPill();
}
function toggleLive() {
  state.live = !state.live;
  localStorage.setItem("waf.live", state.live ? "1" : "0");
  applyLive();
  if (state.live) {
    loadSummary();
    loadStatus();
    if (table.pending && state.offset === 0 && state.sort === "ts" && state.dir === "desc") table.jumpNewest();
  }
  toast(state.live ? "Live updates on" : "Live updates paused");
}
liveBtn.addEventListener("click", toggleLive);
applyLive();

// ---------------------------------------------------------------- click-to-filter (delegated)
document.addEventListener("click", (e) => {
  const t = e.target.closest("[data-fk]");
  if (!t || !t.dataset.fval) return;
  e.preventDefault();
  addFilter(t.dataset.fk, t.dataset.fval);
});

// ---------------------------------------------------------------- views
const views = { live: $("#view-live"), search: $("#view-search") };
const tabs = { live: $("#tab-live"), search: $("#tab-search") };
function switchView(v, { focus = false } = {}) {
  state.view = v;
  for (const k of Object.keys(views)) {
    views[k].hidden = k !== v;
    tabs[k].setAttribute("aria-selected", String(k === v));
    tabs[k].tabIndex = k === v ? 0 : -1;
  }
  if (focus) tabs[v].focus();
  writeHash();
  table.showPill();
  if (v === "live" && lastSummary) chart.update(lastSummary);
}
for (const [k, t] of Object.entries(tabs)) {
  t.addEventListener("click", () => switchView(k));
  t.addEventListener("keydown", (e) => {
    if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
      e.preventDefault();
      switchView(k === "live" ? "search" : "live", { focus: true });
    }
  });
}
function openDeepSearch(vals) {
  drawer.close();
  search.prefill(vals);
  switchView("search");
  search.focus();
}

// ---------------------------------------------------------------- keyboard
const help = $("#help");
$("#help-btn").addEventListener("click", () => help.showModal());
$("#help-close").addEventListener("click", () => help.close());

function typing(el) {
  return el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.tagName === "SELECT" || el.isContentEditable);
}
document.addEventListener("keydown", (e) => {
  if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey) return;
  if (help.open) return;
  if (e.key === "Escape") {
    if (popoverOpen()) { closePopover(); return; }
    if (drawer.isOpen) { drawer.close(); return; }
    if (typing(document.activeElement)) document.activeElement.blur();
    return;
  }
  if (typing(document.activeElement)) return;
  if (popoverOpen()) return;
  const k = e.key;
  if (k === "/") {
    e.preventDefault();
    if (state.view !== "live") switchView("live");
    $("#q").focus();
    $("#q").select();
  } else if (k === "?") {
    e.preventDefault();
    help.showModal();
  } else if (k === "1") switchView("live");
  else if (k === "2") switchView("search");
  else if (k === "l" || k === "L") toggleLive();
  else if (k === "u" || k === "U") toggleTz();
  else if (k === "d" || k === "D") densityBtn.click();
  else if (state.view === "live") {
    const chartFocused = document.activeElement === $("#chart");
    if (k === "j" || (k === "ArrowDown" && !chartFocused)) {
      e.preventDefault();
      const r = table.move(1);
      if (r && drawer.isOpen) drawer.open(r);
    } else if (k === "k" || (k === "ArrowUp" && !chartFocused)) {
      e.preventDefault();
      const r = table.move(-1);
      if (r && drawer.isOpen) drawer.open(r);
    } else if (k === "Enter" && !drawer.isOpen && !document.activeElement.closest("button, a, [role='tab'], #chart")) {
      const r = table.selectedRow();
      if (r) { e.preventDefault(); drawer.open(r); }
    } else if (k === "[") table.page(-1);
    else if (k === "]") table.page(1);
    else if (k === "g") table.jumpNewest();
    else if (drawer.isOpen && drawer.current) {
      const r = drawer.current;
      if (k === "i") addFilter("ip", r.ip);
      else if (k === "h") addFilter("host", r.host);
      else if (k === "o" && r.org) addFilter("org", r.org);
      else if (k === "r") { addFilter("rule", r.rule); if (r.inner_rule) addFilter("inner_rule", r.inner_rule); }
      else if (k === "s") openDeepSearch({ ip: r.ip, hours: 1 });
    }
  }
});

// ---------------------------------------------------------------- hash navigation
window.addEventListener("hashchange", () => {
  if (!readHash()) return;
  $("#q").value = state.q;
  table.syncFromState();
  renderRange();
  renderChips();
  switchView(state.view);
  refreshAll({ time: true });
});

// ---------------------------------------------------------------- boot
switchView(state.view);
writeHash();
loadStatus();
refreshAll({ time: true });
connect();
emit("boot");

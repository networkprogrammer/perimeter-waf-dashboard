// Deep Search: POST /api/search -> poll GET /api/search/{id} -> client-sortable results + CSV.
import { h, clear, replace, fmtInt, fmtTime, isoUtc, ccBadge, toCsv, download, debounce, countryName } from "./util.js";
import { verdict, orgTitle } from "./components.js";
import { api } from "./state.js";

const FIELDS = ["ip", "host", "account", "path", "country", "rule", "method", "status"];
const COLS = [
  { id: "ts", label: "Time", cls: "c-time" },
  { id: "account_name", label: "Account", cls: "c-acct" },
  { id: "ip", label: "Source", cls: "c-ip" },
  { id: "org", label: "Org", cls: "c-org" },
  { id: "host", label: "Host", cls: "c-host" },
  { id: "path", label: "Path", cls: "c-path" },
  { id: "method", label: "Meth", cls: "c-meth" },
  { id: "status", label: "Status", cls: "c-st" },
  { id: "disp", label: "Disp.", cls: "c-disp" },
  { id: "rule", label: "Rule (blocked)", cls: "c-rule" },
  { id: "src_region", label: "Region", cls: "c-reg" },
];

export function createSearch() {
  const form = document.getElementById("ds-form");
  const errEl = document.getElementById("ds-err");
  const runBtn = document.getElementById("ds-run");
  const bodyEl = document.getElementById("ds-body");
  const meta = document.getElementById("ds-meta");
  const csvBtn = document.getElementById("ds-csv");
  const filt = document.getElementById("ds-filter");

  let job = null, rows = [], sort = { k: "ts", dir: "desc" }, ticker = null, pollT = null, startedAt = 0, lastQuery = null, textFilter = "", coverage = null;

  idle();

  function idle() {
    meta.textContent = "";
    replace(bodyEl, h("div.ds-idle", h("span.big", "NO QUERY"),
      "Set a narrowing filter on the left and run. Results include allowed traffic that never reaches the live table."));
  }

  function showErr(msg) {
    errEl.hidden = !msg;
    errEl.textContent = msg || "";
  }

  function readForm() {
    const fd = new FormData(form);
    const body = {};
    const disp = fd.get("disposition");
    if (disp) body.disposition = disp;
    for (const k of FIELDS) {
      const v = String(fd.get(k) || "").trim();
      if (v) body[k] = k === "status" ? (/^\d+$/.test(v) ? parseInt(v, 10) : v) : k === "country" ? v.toUpperCase() : v;
    }
    const hours = parseFloat(fd.get("hours"));
    body.hours = isNaN(hours) ? 1 : Math.min(24, Math.max(0.25, hours));
    body.region = fd.get("region") || "all";
    body.limit = parseInt(fd.get("limit"), 10) || 500;
    return body;
  }
  function validate(b) {
    for (const el of form.querySelectorAll("[aria-invalid]")) el.removeAttribute("aria-invalid");
    const bad = (name, msg) => {
      const el = form.elements[name];
      if (el) { el.setAttribute("aria-invalid", "true"); el.focus(); }
      return msg;
    };
    if (!FIELDS.some((k) => b[k] != null && b[k] !== "")) return bad("ip", "Add at least one narrowing filter (IP, host, account, path, rule, country, status or method).");
    if (b.account && !/^\d{12}$/.test(b.account)) return bad("account", "Account must be a 12 digit ID.");
    if (b.country && !/^[A-Z]{2}$/.test(b.country)) return bad("country", "Country must be a two-letter code.");
    if (b.status != null && (typeof b.status !== "number" || b.status < 100 || b.status > 599)) return bad("status", "Status must be 100-599.");
    if (b.ip && !/^[0-9a-fA-F:.]+$/.test(b.ip)) return bad("ip", "That does not look like an IP address.");
    return null;
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (job) return;
    const b = readForm();
    const v = validate(b);
    if (v) { showErr(v); return; }
    showErr(null);
    lastQuery = b;
    start(b);
  });
  document.getElementById("ds-reset").addEventListener("click", () => {
    form.reset();
    showErr(null);
    for (const el of form.querySelectorAll("[aria-invalid]")) el.removeAttribute("aria-invalid");
  });

  async function start(b) {
    setRunning(true);
    startedAt = performance.now();
    renderRunning(b, null);
    ticker = setInterval(() => renderClock(), 100);
    try {
      const { id } = await api("/api/search", { method: "POST", body: b });
      job = id;
      poll();
    } catch (e) {
      finish();
      fail(e.status === 429 ? "Rate limited" : e.status === 400 ? "Rejected" : "Could not start", e.message);
    }
  }
  async function poll() {
    if (!job) return;
    try {
      const d = await api("/api/search/" + encodeURIComponent(job));
      if (d.state === "done") {
        finish();
        results(d);
      } else if (d.state === "error") {
        finish();
        fail("Search failed", d.error || "Unknown error", d);
      } else {
        renderRunning(lastQuery, d);
        pollT = setTimeout(poll, 2000);
      }
    } catch (e) {
      if (e.status === 404) { finish(); fail("Search expired", "The server no longer knows this search. Run it again."); return; }
      pollT = setTimeout(poll, 3000);
    }
  }
  function finish() {
    clearInterval(ticker);
    clearTimeout(pollT);
    job = null;
    setRunning(false);
  }
  function setRunning(on) {
    runBtn.disabled = on;
    runBtn.textContent = on ? "Searching..." : "Run search";
    form.setAttribute("aria-busy", on ? "true" : "false");
  }

  let clockEl = null;
  function renderClock() {
    if (!clockEl) return;
    const s = (performance.now() - startedAt) / 1000;
    clockEl.replaceChildren(String(Math.floor(s)).padStart(2, "0"), h("small", "." + Math.floor((s % 1) * 10) + "s"));
  }
  function describe(b) {
    if (!b) return "";
    const parts = [];
    if (b.disposition) parts.push(b.disposition.toLowerCase());
    for (const k of FIELDS) if (b[k] != null && b[k] !== "") parts.push(`${k}=${b[k]}`);
    parts.push(`last ${b.hours}h`, b.region === "all" ? "all regions" : b.region, `limit ${b.limit}`);
    return parts.join("  /  ");
  }
  function renderRunning(b, d) {
    rows = [];
    coverage = null;
    csvBtn.disabled = true;
    filt.disabled = true;
    meta.textContent = d ? `server ${d.elapsed_s}s` : "starting";
    if (!clockEl || !bodyEl.contains(clockEl)) {
      clockEl = h("div.clock");
      replace(bodyEl, h("div.ds-run", { role: "status", "aria-live": "polite" },
        clockEl,
        h("div.stage", "Scanning Security Lake via Athena"),
        h("div.scan"),
        h("div.q", describe(b))));
    }
    renderClock();
  }
  function fail(head, msg, d) {
    meta.textContent = d ? `${d.elapsed_s}s` : "";
    clockEl = null;
    replace(bodyEl, h("div.ds-fail", { role: "alert" }, h("div.big", head.toUpperCase()), h("p", msg),
      lastQuery ? h("p", { style: { color: "var(--muted)" } }, describe(lastQuery)) : null));
  }

  function partialWarning() {
    if (!coverage) return null;
    const skipped = Object.entries(coverage.skipped);
    return h("div.banner.warn", { role: "status", "aria-live": "polite" },
      h("span.banner-tag", "Partial results"),
      h("div.banner-msg",
        h("div", "Some regions could not be searched. Results and CSV contain only the searched regions."),
        h("div", "Searched regions: " + (coverage.searched.join(", ") || "none")),
        h("div", "Skipped regions: " + (skipped.map(([region]) => region).join(", ") || "none")),
        skipped.map(([region, reason]) => h("div", { style: { overflowWrap: "anywhere" } }, `${region}: ${reason}`))));
  }

  function results(d) {
    clockEl = null;
    coverage = d.partial ? { searched: d.searched_regions || [], skipped: d.skipped_regions || {} } : null;
    rows = (d.rows || []).map((r) => ({ ...r, ts: Number(r.ts), status: r.status == null || r.status === "" ? null : Number(r.status) }));
    sort = { k: "ts", dir: "desc" };
    textFilter = "";
    filt.value = "";
    const nA = rows.filter((r) => r.disp === "Allowed").length;
    meta.textContent = `${fmtInt(rows.length)} rows${coverage ? " (partial results)" : ""}${d.truncated ? " (limit reached, truncated)" : ""} / ${fmtInt(nA)} allowed / ${fmtInt(rows.length - nA)} blocked / ${d.elapsed_s}s / ${d.scanned_mb ?? 0} MB scanned`;
    csvBtn.disabled = !rows.length;
    filt.disabled = !rows.length;
    if (!rows.length) {
      replace(bodyEl, partialWarning(), h("div.ds-idle", h("span.big", coverage ? "NO MATCHES IN SEARCHED REGIONS" : "NO MATCHES"),
        coverage ? "Nothing matched in the searched regions. Skipped regions may still contain matching traffic." : "Nothing in the lake matched. Widen the lookback or loosen the filters."));
      return;
    }
    drawTable();
  }

  function visibleRows() {
    let out = rows;
    if (textFilter) {
      const n = textFilter.toLowerCase();
      out = out.filter((r) => ["ip", "host", "path", "account", "account_name", "rule", "inner_rule", "country", "method", "disp", "org", "net_name", "asn"].some((k) => r[k] != null && String(r[k]).toLowerCase().includes(n)));
    }
    const { k, dir } = sort;
    const m = dir === "asc" ? 1 : -1;
    return [...out].sort((a, b) => {
      const x = a[k], y = b[k];
      if (x == null && y == null) return 0;
      if (x == null) return 1;
      if (y == null) return -1;
      return (typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y))) * m || b.ts - a.ts;
    });
  }

  function drawTable() {
    const vis = visibleRows();
    const headRow = h("tr");
    for (const c of COLS) {
      const active = sort.k === c.id;
      const th = h("th", { class: c.cls, scope: "col" });
      if (active) th.setAttribute("aria-sort", sort.dir === "asc" ? "ascending" : "descending");
      const b = h("button", { type: "button" }, c.label, h("span.arr", { "aria-hidden": "true" }, active ? (sort.dir === "asc" ? "\u25B2" : "\u25BC") : ""));
      b.addEventListener("click", () => {
        sort = sort.k === c.id ? { k: c.id, dir: sort.dir === "asc" ? "desc" : "asc" } : { k: c.id, dir: c.id === "ts" ? "desc" : "asc" };
        drawTable();
      });
      th.appendChild(b);
      headRow.appendChild(th);
    }
    const tb = h("tbody");
    const shown = vis.slice(0, 2000);
    for (const r of shown) {
      tb.appendChild(h("tr",
        h("td.c-time", { title: isoUtc(r.ts) + " (UTC)" }, fmtTime(r.ts)),
        h("td.c-acct", { title: r.account || "" }, r.account_name || r.account || "-"),
        h("td.c-ip", h("span.cell-ip", ccBadge(r.country), h("span", { title: countryName(r.country) }, r.ip || "-"))),
        h("td.c-org", r.org ? h("span.org", h("span.org-n", { title: orgTitle(r) }, r.org), r.asn ? h("span.asn", r.asn) : null) : h("span.dim", r.asn || "-")),
        h("td.c-host", { title: r.host || "" }, r.host || "-"),
        h("td.c-path", { title: r.path || "" }, r.path || "-"),
        h("td.c-meth", { class: "c-meth m-" + r.method }, r.method || "-"),
        h("td.c-st", r.status ? h("span", { class: "st-" + String(r.status)[0] }, r.status) : h("span.dim", "-")),
        h("td.c-disp", h("span", { class: "disp disp-" + r.disp }, r.disp || "?")),
        h("td.c-rule", r.disp === "Blocked" && r.rule ? verdict(r, { clickable: false }) : h("span.dim", "-")),
        h("td.c-reg", r.src_region || "-")));
    }
    const table = h("table.evt.ds-table", h("thead", headRow), tb);
    const wrap = h("div.table-wrap", table);
    replace(bodyEl, partialWarning(), wrap);
    if (!vis.length) wrap.appendChild(h("div.table-state", h("div", h("span.big", "FILTERED OUT"), "No result rows match the text filter.")));
  }

  filt.addEventListener("input", debounce(() => { textFilter = filt.value.trim(); if (rows.length) drawTable(); }, 150));

  csvBtn.addEventListener("click", () => {
    const vis = visibleRows();
    const cols = ["ts", "account", "account_name", "ip", "org", "net_name", "asn", "country", "host", "path", "method", "status", "disp", "rule", "rule_type", "inner_rule", "src_region"];
    const csv = toCsv(["time_utc", ...cols.slice(1)], vis.map((r) => [isoUtc(r.ts), ...cols.slice(1).map((c) => r[c])]));
    download(`waf-deep-search-${new Date().toISOString().replace(/[:.]/g, "-")}.csv`, csv);
  });

  return {
    prefill(vals) {
      if (job) return;
      form.reset();
      for (const [k, v] of Object.entries(vals)) {
        if (k === "disposition") {
          const r = form.querySelector(`input[name="disposition"][value="${v}"]`);
          if (r) r.checked = true;
        } else if (form.elements[k] && v != null) form.elements[k].value = String(v);
      }
      showErr(null);
    },
    setOptions(facets) {
      const fillDl = (id, items, lbl) => {
        const dl = document.getElementById(id);
        clear(dl);
        for (const it of items || []) {
          const o = document.createElement("option");
          o.value = it.value;
          if (lbl && it.label) o.label = it.label;
          dl.appendChild(o);
        }
      };
      fillDl("ds-accounts", facets.accounts, true);
      fillDl("ds-rules", facets.rules);
      fillDl("ds-hosts", facets.hosts);
    },
    focus() { form.elements.ip.focus(); },
    redraw() { if (rows.length) drawTable(); },
    get running() { return !!job; },
  };
}

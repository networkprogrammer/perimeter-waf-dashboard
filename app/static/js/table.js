// Blocked-events table: server-side sort + pagination, live prepend, keyboard selection.
import { h, clear, replace, fmtInt, fmtTime, fmtAge, isoUtc, ccBadge, reducedMotion } from "./util.js";
import { verdict, fv, orgCell, orgState } from "./components.js";
import { state, filterParams, latest, matchRow, writeHash, serverNow, emit } from "./state.js";

const COLS = [
  { id: "ts", label: "Time", cls: "c-time", sort: "ts" },
  { id: "acct", label: "Account", cls: "c-acct", sort: "account_name" },
  { id: "host", label: "Host", cls: "c-host", sort: "host" },
  { id: "path", label: "Path", cls: "c-path", sort: "path" },
  { id: "meth", label: "Meth", cls: "c-meth", sort: "method" },
  { id: "ip", label: "Source", cls: "c-ip", sort: "ip" },
  { id: "org", label: "Org / network", cls: "c-org", sort: "org" },
  { id: "rule", label: "Terminating rule", cls: "c-rule", sort: "rule" },
  { id: "act", label: "Action", cls: "c-act", sort: null },
  { id: "st", label: "Status", cls: "c-st", sort: "status" },
];

export function timeCell(ts) {
  return h("td.c-time", { title: `${isoUtc(ts)}  (UTC)` },
    h("span.t-abs", fmtTime(ts)), h("span.t-rel", { dataset: { ts: String(ts) } }, fmtAge(serverNow() - ts)));
}

export function createTable({ onOpen }) {
  const head = document.getElementById("evt-head");
  const body = document.getElementById("evt-body");
  const wrap = document.getElementById("table-wrap");
  const stateEl = document.getElementById("table-state");
  const meta = document.getElementById("table-meta");
  const pager = document.getElementById("pager");
  const pill = document.getElementById("new-pill");
  const pageSize = document.getElementById("page-size");
  const badge = document.getElementById("tab-live-badge");

  let rows = [], total = 0, selected = -1, loading = false, pending = 0, loadedOnce = false, lastErr = null;

  // headers
  function renderHead() {
    clear(head);
    for (const c of COLS) {
      const th = h("th", { class: c.cls, scope: "col" });
      if (c.sort) {
        const active = state.sort === c.sort;
        if (active) th.setAttribute("aria-sort", state.dir === "asc" ? "ascending" : "descending");
        const b = h("button", { type: "button", title: `Sort by ${c.label}` }, c.label,
          h("span.arr", { "aria-hidden": "true" }, active ? (state.dir === "asc" ? "\u25B2" : "\u25BC") : ""));
        b.addEventListener("click", () => {
          if (state.sort === c.sort) state.dir = state.dir === "asc" ? "desc" : "asc";
          else {
            state.sort = c.sort;
            state.dir = c.sort === "ts" || c.sort === "status" ? "desc" : "asc";
          }
          state.offset = 0;
          writeHash();
          renderHead();
          load();
        });
        th.appendChild(b);
      } else th.appendChild(h("span.nosort", c.label));
      head.appendChild(th);
    }
  }

  function rowEl(r, fresh) {
    const st = r.status;
    const tr = h("tr", { tabindex: "-1", dataset: { id: r.id } },
      timeCell(r.ts),
      h("td.c-acct", fv("account", r.account, r.account_name || r.account, { title: `${r.account_name || ""} ${r.account}\nClick to filter` })),
      h("td.c-host", fv("host", r.host)),
      h("td.c-path", fv("path", r.path, null, { title: `${r.path || ""}\nClick to filter by this exact path` })),
      h("td.c-meth", fv("method", r.method, null, { cls: "m-" + r.method })),
      h("td.c-ip", h("span.cell-ip", fv("country", r.country, ccBadge(r.country), { title: `Filter country ${r.country}` }), fv("ip", r.ip))),
      h("td.c-org", orgCell(r)),
      h("td.c-rule", verdict(r)),
      h("td.c-act", h("span.act", { class: "act" + (r.term_action && r.term_action !== "BLOCK" ? " other" : "") }, r.term_action || "BLOCK")),
      h("td.c-st", st ? h("span", { class: "st-" + String(st)[0] }, st) : h("span.dim", "-")));
    if (fresh) tr.classList.add("fresh");
    return tr;
  }

  function renderRows() {
    clear(body);
    const frag = document.createDocumentFragment();
    rows.forEach((r) => frag.appendChild(rowEl(r)));
    body.appendChild(frag);
    if (selected >= rows.length) selected = rows.length - 1;
    markSel(false);
  }
  function skeleton() {
    clear(body);
    for (let i = 0; i < 12; i++) {
      const tr = h("tr.sk-row");
      COLS.forEach((c, j) => tr.appendChild(h("td", { class: c.cls }, h("span.sk", { style: { width: 30 + ((i * 13 + j * 29) % 60) + "%" } }))));
      body.appendChild(tr);
    }
  }

  function renderMeta() {
    const from = total ? state.offset + 1 : 0;
    const to = Math.min(state.offset + rows.length, total);
    meta.textContent = `${fmtInt(from)}-${fmtInt(to)} of ${fmtInt(total)} blocked` + (state.sort !== "ts" || state.dir !== "desc" ? `  / sorted by ${state.sort} ${state.dir}` : "");
    clear(pager);
    const pages = Math.max(1, Math.ceil(total / state.limit));
    const cur = Math.floor(state.offset / state.limit);
    const go = (p) => { state.offset = p * state.limit; load(); wrap.scrollTop = 0; };
    const btn = (label, p, opts = {}) => {
      const b = h("button", { type: "button", "aria-label": opts.aria || `Page ${p + 1}` }, label);
      if (opts.disabled) b.disabled = true;
      if (opts.current) b.setAttribute("aria-current", "page");
      b.addEventListener("click", () => go(p));
      return b;
    };
    pager.appendChild(h("span", `Page ${fmtInt(cur + 1)} / ${fmtInt(pages)}`));
    pager.appendChild(h("span.sp"));
    pager.appendChild(btn("\u2039 Prev", cur - 1, { disabled: cur === 0, aria: "Previous page" }));
    const set = new Set([0, pages - 1, cur - 2, cur - 1, cur, cur + 1, cur + 2].filter((p) => p >= 0 && p < pages));
    let prev = -1;
    for (const p of [...set].sort((a, b) => a - b)) {
      if (p - prev > 1) pager.appendChild(h("span.gap", "\u2026"));
      pager.appendChild(btn(String(p + 1), p, { current: p === cur }));
      prev = p;
    }
    pager.appendChild(btn("Next \u203A", cur + 1, { disabled: cur >= pages - 1, aria: "Next page" }));
  }

  function showState(kind, big, msg) {
    if (!kind) { stateEl.hidden = true; return; }
    stateEl.className = "table-state" + (kind === "err" ? " err" : "");
    replace(stateEl, h("div", h("span.big", big), msg));
    stateEl.hidden = false;
  }

  let reqSeq = 0;
  async function load() {
    const seq = ++reqSeq;
    loading = true;
    if (!loadedOnce) skeleton();
    else wrap.style.opacity = ".6";
    try {
      const d = await latest("events", "/api/events?" + filterParams({ withSort: true, withPage: true }));
      if (seq !== reqSeq) return;
      const keepId = rows[selected]?.id;
      rows = d.rows;
      total = d.total;
      loadedOnce = true;
      lastErr = null;
      selected = keepId ? rows.findIndex((r) => r.id === keepId) : -1;
      renderRows();
      renderMeta();
      if (!rows.length) showState("empty", "ALL QUIET", state.offset ? "No rows on this page." : "No blocked requests match these filters in this window.");
      else showState(null);
      if (state.offset === 0 && state.sort === "ts" && state.dir === "desc") clearPending();
    } catch (e) {
      if (e.name === "AbortError" || seq !== reqSeq) return;
      lastErr = e.message;
      if (!loadedOnce) clear(body);
      showState("err", "COULD NOT LOAD", e.message);
    } finally {
      if (seq === reqSeq) {
        loading = false;
        wrap.style.opacity = "";
      }
    }
  }

  // selection ---------------------------------------------------------------
  function markSel(scroll = true) {
    const trs = body.children;
    for (let i = 0; i < trs.length; i++) {
      const on = i === selected;
      trs[i].classList.toggle("is-sel", on);
      trs[i].tabIndex = on ? 0 : -1;
      if (on) trs[i].setAttribute("aria-selected", "true");
      else trs[i].removeAttribute("aria-selected");
    }
    if (selected < 0 && trs.length && trs[0].dataset.id) trs[0].tabIndex = 0;
    if (scroll && selected >= 0 && trs[selected]) {
      trs[selected].focus({ preventScroll: true });
      const tr = trs[selected], top = tr.offsetTop - 31, bottom = tr.offsetTop + tr.offsetHeight;
      if (top < wrap.scrollTop) wrap.scrollTop = top;
      else if (bottom > wrap.scrollTop + wrap.clientHeight) wrap.scrollTop = bottom - wrap.clientHeight;
    }
  }
  function select(i, scroll = true) {
    if (!rows.length) return;
    selected = Math.max(0, Math.min(rows.length - 1, i));
    markSel(scroll);
  }

  body.addEventListener("click", (e) => {
    if (e.target.closest(".fv")) return; // filter values handled globally
    const tr = e.target.closest("tr[data-id]");
    if (!tr) return;
    const i = rows.findIndex((r) => r.id === tr.dataset.id);
    if (i < 0) return;
    select(i, false);
    onOpen(rows[i]);
  });
  body.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && e.target.matches("tr[data-id]")) {
      e.preventDefault();
      const i = rows.findIndex((r) => r.id === e.target.dataset.id);
      if (i >= 0) { select(i, false); onOpen(rows[i]); }
    }
  });

  // live --------------------------------------------------------------------
  const atHead = () => state.offset === 0 && state.sort === "ts" && state.dir === "desc";
  function canPrepend() {
    return state.live && atHead() && !loading && wrap.scrollTop < 30 && state.view === "live";
  }
  function addLive(newRows) {
    const fresh = newRows.filter(matchRow);
    if (!fresh.length) return 0;
    if (!canPrepend()) {
      pending += fresh.length;
      showPill();
      return fresh.length;
    }
    const have = new Set(rows.map((r) => r.id));
    const add = fresh.filter((r) => !have.has(r.id)).sort((a, b) => b.ts - a.ts);
    if (!add.length) return 0;
    const selId = rows[selected]?.id;
    const frag = document.createDocumentFragment();
    const anim = !reducedMotion();
    add.forEach((r) => frag.appendChild(rowEl(r, anim)));
    body.insertBefore(frag, body.firstChild);
    rows = add.concat(rows);
    total += add.length;
    while (rows.length > state.limit) {
      rows.pop();
      body.lastChild.remove();
    }
    if (selId) selected = rows.findIndex((r) => r.id === selId);
    markSel(false);
    showState(null);
    renderMeta();
    return add.length;
  }
  function showPill() {
    if (!pending) { pill.hidden = true; badge.hidden = true; return; }
    pill.hidden = false;
    pill.textContent = `\u2191 ${fmtInt(pending)} new event${pending === 1 ? "" : "s"}` + (state.live ? "" : " (live paused)") + " - show";
    badge.hidden = state.view === "live";
    badge.textContent = pending > 999 ? "999+" : String(pending);
  }
  function clearPending() {
    pending = 0;
    showPill();
  }
  pill.addEventListener("click", () => jumpNewest());
  function jumpNewest() {
    const changed = state.sort !== "ts" || state.dir !== "desc";
    state.sort = "ts";
    state.dir = "desc";
    state.offset = 0;
    if (changed) { writeHash(); renderHead(); }
    wrap.scrollTop = 0;
    selected = -1;
    load();
  }
  wrap.addEventListener("scroll", () => {
    if (wrap.scrollTop < 30 && pending && state.live && atHead()) jumpNewest();
  }, { passive: true });

  pageSize.value = String(state.limit);
  pageSize.addEventListener("change", () => {
    state.limit = parseInt(pageSize.value, 10);
    state.offset = 0;
    writeHash();
    load();
    emit("pagesize");
  });

  // Pending ownership lookups resolve server-side; quietly re-read the page and patch only org cells.
  async function refreshOrgs() {
    if (!state.live || loading || state.view !== "live" || !rows.some((r) => orgState(r) === "pending")) return;
    let d;
    try { d = await latest("events-org", "/api/events?" + filterParams({ withSort: true, withPage: true })); } catch { return; }
    const byId = new Map(d.rows.map((r) => [r.id, r]));
    rows.forEach((r, i) => {
      const n = byId.get(r.id);
      if (!n || orgState(r) !== "pending" || orgState(n) === "pending") return;
      Object.assign(r, { org: n.org, net_name: n.net_name, asn: n.asn, org_state: n.org_state });
      const td = body.children[i] && body.children[i].querySelector("td.c-org");
      if (td) replace(td, orgCell(r));
    });
  }
  setInterval(refreshOrgs, 15000);

  setInterval(() => {
    const now = serverNow();
    for (const el of body.querySelectorAll(".t-rel")) el.textContent = fmtAge(now - Number(el.dataset.ts));
  }, 5000);

  renderHead();

  return {
    load,
    addLive,
    renderHead,
    refreshTimes() { renderRows(); },
    move(d) {
      if (!rows.length) return null;
      select(selected < 0 ? (d > 0 ? 0 : rows.length - 1) : selected + d);
      return rows[selected];
    },
    selectedRow: () => rows[selected] || null,
    page(d) {
      const pages = Math.max(1, Math.ceil(total / state.limit));
      const cur = Math.floor(state.offset / state.limit);
      const n = Math.max(0, Math.min(pages - 1, cur + d));
      if (n === cur) return;
      state.offset = n * state.limit;
      wrap.scrollTop = 0;
      selected = -1;
      load();
    },
    jumpNewest,
    syncFromState() { pageSize.value = String(state.limit); renderHead(); },
    showPill,
    get pending() { return pending; },
    get error() { return lastErr; },
  };
}

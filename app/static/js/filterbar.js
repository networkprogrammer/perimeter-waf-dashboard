// Filter bar: time presets, debounced search, facet popovers (multi-select), applied chips, export.
import { h, clear, replace, fmtInt, fmtTime, fmtSpan, debounce, countryName } from "./util.js";
import { SCOPE_LABEL } from "./components.js";
import {
  state, RANGES, FILTERS, labels, valueLabel, setRange, setQ, removeFilter, clearAll,
  setFilterValues, filterParams, on,
} from "./state.js";

let facets = {};
// path / ua have no facet endpoint; their options come from the latest summary top lists
const topOpts = {};
export function setTopOptions(sum) {
  for (const f of FILTERS) if (f.top) topOpts[f.key] = ((sum && sum.top[f.top]) || []).filter((x) => x[f.topField]).map((x) => ({ value: String(x[f.topField]), n: x.n }));
}
export function setFacets(f) {
  facets = f || {};
  for (const a of facets.accounts || []) labels.account.set(String(a.value), a.label);
  renderChips();
}

export function initFilterbar() {
  const seg = document.getElementById("range-seg");
  for (const r of RANGES) {
    const b = h("button", { type: "button", dataset: { range: r }, "aria-pressed": "false" }, r);
    b.addEventListener("click", () => setRange(r));
    seg.appendChild(b);
  }
  const custom = h("button.custom", { type: "button", hidden: true, title: "Custom window (click to return to the last preset)" });
  custom.addEventListener("click", () => setRange(state.range));
  seg.appendChild(custom);

  const q = document.getElementById("q");
  q.value = state.q;
  const push = debounce(() => setQ(q.value.trim().slice(0, 200)), 350);
  q.addEventListener("input", push);
  q.addEventListener("keydown", (e) => {
    if (e.key === "Enter") { push.cancel(); setQ(q.value.trim().slice(0, 200)); }
    if (e.key === "Escape") { if (q.value) { q.value = ""; push.cancel(); setQ(""); } else q.blur(); e.stopPropagation(); }
  });

  const btns = document.getElementById("facet-btns");
  for (const f of FILTERS) {
    const b = h("button.fbtn", { type: "button", dataset: { key: f.key }, "aria-haspopup": "dialog", "aria-expanded": "false" }, f.label);
    b.addEventListener("click", () => openPopover(f, b));
    btns.appendChild(b);
  }

  document.getElementById("clear-all").addEventListener("click", () => {
    q.value = "";
    clearAll();
  });
  document.getElementById("export-btn").addEventListener("click", () => {
    const a = h("a", { href: "/api/export.csv?" + filterParams({ withSort: true }), download: "" });
    document.body.appendChild(a);
    a.click();
    a.remove();
  });

  on("filters", () => { renderRange(); renderChips(); if (q.value.trim() !== state.q) q.value = state.q; });
  renderRange();
  renderChips();
}

export function renderRange() {
  const seg = document.getElementById("range-seg");
  for (const b of seg.querySelectorAll("button[data-range]")) b.setAttribute("aria-pressed", String(!state.from && b.dataset.range === state.range));
  const c = seg.querySelector(".custom");
  if (state.from) {
    c.hidden = false;
    c.setAttribute("aria-pressed", "true");
    c.textContent = `${fmtTime(state.from, { secs: false })} \u2192 ${fmtTime(state.to, { secs: false })} (${fmtSpan(state.to - state.from)}) \u00d7`;
  } else c.hidden = true;
}

function chipValue(key, v) {
  if (key === "account") {
    const n = valueLabel(key, v);
    return n !== v ? `${n}` : v;
  }
  if (key === "country") return `${v} ${countryName(v) && countryName(v) !== v ? "- " + countryName(v) : ""}`.trim();
  if (key === "scope") return `${SCOPE_LABEL[v] || v} (${v})`;
  return v;
}
export function renderChips() {
  const row = document.getElementById("chips-row");
  const chips = document.getElementById("chips");
  clear(chips);
  let n = 0;
  if (state.q) {
    n++;
    chips.appendChild(chip("search", `"${state.q}"`, () => { document.getElementById("q").value = ""; setQ(""); }, state.q));
  }
  for (const f of FILTERS) {
    for (const v of state.f[f.key]) {
      n++;
      chips.appendChild(chip(f.label, chipValue(f.key, v), () => removeFilter(f.key, v), `${f.key} = ${v}`));
    }
  }
  row.hidden = n === 0;
  for (const b of document.querySelectorAll(".fbtn")) {
    const cnt = state.f[b.dataset.key].length;
    b.classList.toggle("active", cnt > 0);
    const old = b.querySelector(".n");
    if (old) old.remove();
    if (cnt) b.appendChild(h("span.n", String(cnt)));
  }
}
function chip(k, v, onRemove, title) {
  const x = h("button", { type: "button", "aria-label": `Remove filter ${k} ${v}` }, "\u00d7");
  x.addEventListener("click", onRemove);
  return h("span.chip", { title }, h("span.k", k), h("span.v", v), x);
}

// ---------------------------------------------------------------- popover
const pop = () => document.getElementById("popover");
let popFor = null, popAnchor = null;

export function closePopover(refocus = true) {
  const p = pop();
  if (p.hidden) return false;
  p.hidden = true;
  if (popAnchor) {
    popAnchor.setAttribute("aria-expanded", "false");
    if (refocus) popAnchor.focus();
  }
  popFor = popAnchor = null;
  return true;
}
export const popoverOpen = () => !pop().hidden;

function optionsFor(f) {
  if (f.key === "status") {
    const present = new Set(state.f.status);
    return [...new Set([...f.preset, ...present])].map((v) => ({ value: v, n: null }));
  }
  const list = f.top ? [...(topOpts[f.key] || [])] : (facets[f.facet] || []).map((x) => ({ value: String(x.value), label: x.label, n: x.n }));
  for (const v of state.f[f.key]) if (!list.some((x) => x.value === v)) list.unshift({ value: v, n: null });
  return list;
}
function optLabel(f, o) {
  if (f.key === "account") return [o.label || o.value, h("small", o.value)];
  if (f.key === "country") return [o.value, h("small", countryName(o.value))];
  if (f.key === "scope") return [o.value, h("small", SCOPE_LABEL[o.value] || "")];
  return [o.value];
}

function openPopover(f, anchor) {
  if (popFor === f.key) { closePopover(); return; }
  closePopover(false);
  popFor = f.key;
  popAnchor = anchor;
  anchor.setAttribute("aria-expanded", "true");
  const p = pop();
  const sel = new Set(state.f[f.key]);
  const input = h("input", { type: "search", placeholder: f.free ? `Filter or type a ${f.label.toLowerCase()}...` : `Find ${f.label.toLowerCase()}...`, "aria-label": `Find ${f.label}`, autocomplete: "off", spellcheck: "false" });
  const list = h("ul.pop-list", { role: "listbox", "aria-multiselectable": "true", "aria-label": f.label });
  const foot = h("div.pop-f");
  const apply = h("button.btn.btn-ghost", { type: "button", style: { height: "24px", fontSize: "11px" } }, "Done");
  const none = h("button.btn-link", { type: "button" }, "Clear");
  let cur = -1;

  const commit = () => setFilterValues(f.key, [...sel]);
  const toggle = (v) => {
    if (sel.has(v)) sel.delete(v); else sel.add(v);
    commit();
    draw();
  };
  function draw() {
    const qv = input.value.trim().toLowerCase();
    let opts = optionsFor(f).filter((o) => !qv || o.value.toLowerCase().includes(qv) || (o.label || "").toLowerCase().includes(qv) ||
      (f.key === "country" && countryName(o.value).toLowerCase().includes(qv)));
    clear(list);
    const raw = input.value.trim();
    if (f.free && raw && !opts.some((o) => o.value === raw)) {
      const valid = f.key === "status" ? /^\d{3}$/.test(raw) : f.key === "ip" ? /^[0-9a-fA-F:.]{2,45}$/.test(raw) : raw.length <= 1000;
      if (valid) opts = [{ value: raw, n: null, add: true }, ...opts];
    }
    if (!opts.length) list.appendChild(h("li.pop-empty", f.top ? "Type an exact value to add it" : (facets[f.facet] || []).length || !f.facet ? "No matches" : "No values in this window"));
    opts.slice(0, 200).forEach((o, i) => {
      const b = h("button.pop-opt", { type: "button", role: "option", "aria-checked": String(sel.has(o.value)), "aria-selected": String(sel.has(o.value)), dataset: { v: o.value }, tabindex: "-1" },
        h("span.box", { "aria-hidden": "true" }),
        h("span.lbl", o.add ? [`Add "${o.value}"`] : optLabel(f, o)),
        h("span.cnt", o.n != null ? fmtInt(o.n) : ""));
      if (i === cur) b.classList.add("cur");
      b.addEventListener("click", () => { toggle(o.value); input.focus(); });
      list.appendChild(h("li", b));
    });
    replace(foot, h("span", { title: f.facet ? "Counts cover the time window only and ignore other filters" : f.top ? "Suggestions are the current top 10 (respecting filters); exact match" : "" }, `${sel.size} selected` + (f.top ? " / exact match" : "")), h("span", none, " ", apply));
  }
  input.addEventListener("input", () => { cur = -1; draw(); });
  input.addEventListener("keydown", (e) => {
    const items = list.querySelectorAll(".pop-opt");
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      cur = Math.max(0, Math.min(items.length - 1, cur + (e.key === "ArrowDown" ? 1 : -1)));
      items.forEach((x, i) => x.classList.toggle("cur", i === cur));
      items[cur]?.scrollIntoView({ block: "nearest" });
    } else if (e.key === "Enter") {
      e.preventDefault();
      const target = items[cur >= 0 ? cur : 0];
      if (target) toggle(target.dataset.v);
    } else if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      closePopover();
    }
  });
  apply.addEventListener("click", () => closePopover());
  none.addEventListener("click", () => { sel.clear(); commit(); draw(); });

  replace(p, h("div.pop-h", input), list, foot);
  p.setAttribute("role", "dialog");
  p.setAttribute("aria-label", `${f.label} filter`);
  draw();
  p.hidden = false;
  const r = anchor.getBoundingClientRect();
  const w = p.offsetWidth;
  p.style.left = Math.max(8, Math.min(r.left, window.innerWidth - w - 8)) + "px";
  p.style.top = r.bottom + 6 + "px";
  input.focus();
}

document.addEventListener("pointerdown", (e) => {
  const p = pop();
  if (p.hidden) return;
  if (p.contains(e.target) || (popAnchor && popAnchor.contains(e.target))) return;
  closePopover(false);
});
window.addEventListener("resize", () => closePopover(false));

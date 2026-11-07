// KPI strip, terminating-rule panel, scope/type breakdown, top lists and the header "wire".
import { h, clear, replace, fmtInt, fmtCompact, fmtPct, fmtAge, fmtTime, ccBadge, countryName } from "./util.js";
import { verdict, scopeOf, orgCell, SCOPE_LABEL, SCOPE_TITLE, TYPE_LABEL, PRIVATE_ORG } from "./components.js";
import { addFilter, serverNow } from "./state.js";

// ---------------------------------------------------------------- KPIs
let kpiEls = null, lastBlockedMs = null;
const KPI_DEFS = [
  ["blocked", "Blocked", "kpi-block"],
  ["allowed", "Allowed", "kpi-allow"],
  ["ips", "Unique IPs"],
  ["rules", "Rules hit"],
  ["hosts", "Hosts"],
  ["accounts", "Accounts"],
  ["top", "Top terminating rule", "kpi-rule"],
  ["last", "Since last block"],
];
export function initKpis(root) {
  kpiEls = {};
  for (const [k, label, cls] of KPI_DEFS) {
    const v = h("div.kpi-v", h("span.sk", { style: { width: "70%", height: "26px" } }));
    const sub = h("div.kpi-s", "\u00a0");
    const el = h("div.kpi", { role: "group", "aria-label": label }, h("div.kpi-k", label), v, sub);
    if (cls) el.classList.add(cls);
    kpiEls[k] = { el, v, sub };
    root.appendChild(el);
  }
  setInterval(tickLast, 1000);
}
function bump(k) {
  const el = kpiEls[k].el;
  el.classList.remove("bump");
  void el.offsetWidth;
  el.classList.add("bump");
}
export function renderKpis(sum, prev) {
  const k = sum.kpis;
  const set = (key, val, sub) => {
    const e = kpiEls[key];
    e.v.className = "kpi-v";
    e.v.textContent = val;
    e.sub.textContent = sub || "\u00a0";
  };
  const span = sum.range.to - sum.range.from;
  const perMin = k.blocked / Math.max(1, span / 60000);
  set("blocked", fmtInt(k.blocked), `${perMin >= 10 ? Math.round(perMin) : perMin.toFixed(1)} / min avg`);
  if (prev && prev.kpis.blocked !== k.blocked) bump("blocked");

  const a = kpiEls.allowed;
  if (sum.allowed_applicable && k.allowed != null) {
    a.v.className = "kpi-v";
    a.v.textContent = fmtCompact(k.allowed);
    a.v.title = fmtInt(k.allowed) + " allowed";
    replace(a.sub, h("span", `block rate ${fmtPct(k.block_rate)}`));
    const bar = h("div.rate-bar", { title: "Block rate " + fmtPct(k.block_rate) }, h("span", { style: { width: Math.min(100, (k.block_rate || 0) * 100 * 20) + "%" } }));
    a.sub.appendChild(bar);
  } else {
    a.v.className = "kpi-v na";
    a.v.textContent = "n/a with these filters";
    a.v.title = "Allowed traffic is only aggregated per account and host; other filters cannot be applied to it.";
    a.sub.textContent = "only account / host filters apply";
  }
  set("ips", fmtInt(k.unique_ips), k.blocked ? `${(k.blocked / Math.max(1, k.unique_ips)).toFixed(1)} req / ip` : "");
  set("rules", fmtInt(k.unique_rules));
  set("hosts", fmtInt(k.unique_hosts));
  set("accounts", fmtInt(k.unique_accounts));

  const t = kpiEls.top;
  const top = sum.top.rules && sum.top.rules[0];
  t.v.className = "kpi-v";
  if (top) {
    const b = h("button", { type: "button", title: `${top.term_label}\nClick to filter` }, top.inner_rule || shortName(top.rule));
    b.addEventListener("click", () => {
      addFilter("rule", top.rule);
      if (top.inner_rule) addFilter("inner_rule", top.inner_rule);
    });
    replace(t.v, b);
    t.sub.textContent = `${fmtInt(top.n)} blocks / ${fmtPct(top.n / Math.max(1, k.blocked), 1)}` + (top.inner_rule ? ` / ${shortName(top.rule)}` : "");
  } else {
    t.v.textContent = "-";
    t.sub.textContent = "no blocks";
  }
  lastBlockedMs = k.last_blocked_ms;
  tickLast();
}
function shortName(rule) {
  return (rule || "").replace(/^AWS-/, "");
}
function tickLast() {
  if (!kpiEls) return;
  const e = kpiEls.last;
  if (lastBlockedMs == null) {
    if (e.v.querySelector(".sk")) return;
    e.v.textContent = "-";
    e.sub.textContent = "none in window";
    return;
  }
  e.v.className = "kpi-v";
  e.v.textContent = fmtAge(serverNow() - lastBlockedMs);
  e.sub.textContent = "at " + fmtTime(lastBlockedMs);
}
export function noteLiveBlock(ts) {
  if (!lastBlockedMs || ts > lastBlockedMs) {
    lastBlockedMs = ts;
    tickLast();
  }
}
export function kpiError(msg) {
  for (const [k] of KPI_DEFS) {
    const e = kpiEls[k];
    e.v.className = "kpi-v na";
    e.v.textContent = k === "blocked" ? "error" : "-";
    e.sub.textContent = k === "blocked" ? msg : "\u00a0";
  }
}

// ---------------------------------------------------------------- skeleton helpers
function skList(n = 6) {
  const out = [];
  for (let i = 0; i < n; i++) out.push(h("li", { style: { padding: "8px 12px" } }, h("span.sk", { style: { width: 40 + ((i * 37) % 50) + "%" } })));
  return out;
}
const emptyLi = (msg) => h("li.empty", msg);

// ---------------------------------------------------------------- terminating rules panel
let rulesEls = null;
export function initRules() {
  rulesEls = { list: document.getElementById("rules-list"), meta: document.getElementById("rules-meta"), sb: document.getElementById("scope-break") };
  replace(rulesEls.list, skList(7));
}
export function renderRules(sum) {
  const { list, meta, sb } = rulesEls;
  const rules = sum.top.rules || [];
  const total = sum.kpis.blocked || 0;
  meta.textContent = `${fmtInt(sum.kpis.unique_rules)} distinct / top ${rules.length}`;

  // breakdown bars
  clear(sb);
  const scopes = (sum.top.scopes || []).filter((r) => r.n > 0);
  const types = (sum.top.rule_types || []).filter((r) => r.n > 0);
  if (scopes.length) sb.appendChild(breakRow("Scope", scopes.map((r) => ({
    v: r.rule_scope, n: r.n, label: SCOPE_LABEL[r.rule_scope] || r.rule_scope, title: SCOPE_TITLE[r.rule_scope] || r.rule_scope, key: "scope", scope: r.rule_scope,
  }))));
  if (types.length) sb.appendChild(breakRow("Type", types.map((r, i) => ({
    v: r.rule_type, n: r.n, label: TYPE_LABEL[r.rule_type] || r.rule_type || "?", title: r.rule_type, key: "rule_type",
    color: ["#ece6da", "#8d959c", "#5d666e", "#bcc2c6"][i % 4],
  }))));
  sb.hidden = !scopes.length && !types.length;

  clear(list);
  if (!rules.length) {
    list.appendChild(emptyLi("No terminating rules in this window."));
    return;
  }
  const max = Math.max(...rules.map((r) => r.n));
  const now = serverNow();
  for (const r of rules) {
    const sc = scopeOf(r.rule, r.rule_scope);
    const btn = h("button.rule-btn", { type: "button", title: `${r.term_label}\n${fmtInt(r.n)} blocks. Click to filter.` },
      h("span.rb-name", verdict(r, { clickable: false })),
      h("span.rb-n", fmtInt(r.n)),
      h("span.rb-bar", h("span", { dataset: { scope: sc }, style: { width: (r.n / max) * 100 + "%" } })),
      h("span.rb-meta",
        h("span", fmtPct(r.n / Math.max(1, total), 1)),
        h("span", `${fmtInt(r.ips)} IPs`),
        h("span", `last ${fmtAge(now - r.last_ts)} ago`)));
    btn.addEventListener("click", () => {
      addFilter("rule", r.rule);
      if (r.inner_rule) addFilter("inner_rule", r.inner_rule);
    });
    list.appendChild(h("li.rule-item", btn));
  }
}
function breakRow(label, segs) {
  const total = segs.reduce((a, x) => a + x.n, 0) || 1;
  const bar = h("div.sb-bar");
  for (const x of segs) {
    const b = h("button.sb-seg", {
      type: "button",
      title: `${x.title}: ${fmtInt(x.n)} (${fmtPct(x.n / total, 1)}). Click to filter.`,
      style: { flexGrow: String(x.n), flexBasis: "0", background: x.color || undefined },
      dataset: x.scope ? { scope: x.scope, fk: x.key, fval: x.v } : { fk: x.key, fval: x.v },
    }, h("span", x.n / total > 0.12 ? `${x.label} ${Math.round((x.n / total) * 100)}%` : ""));
    bar.appendChild(b);
  }
  return h("div.sb-row", h("span.sb-k", label), bar);
}

// ---------------------------------------------------------------- top lists
const TOPS = [
  { id: "ips", title: "Source IPs", idx: "C1" },
  { id: "orgs", title: "Networks / orgs", idx: "C2" },
  { id: "countries", title: "Countries", idx: "C3" },
  { id: "hosts", title: "Hosts", idx: "C4" },
  { id: "accounts", title: "Accounts", idx: "C5" },
  { id: "paths", title: "Paths", idx: "C6" },
  { id: "user_agents", title: "User agents", idx: "C7" },
  { id: "methods", title: "Methods & rule types", idx: "C8" },
  { id: "traffic", title: "Traffic by host", idx: "C9", wide: true },
];
const topEls = {};
export function initTops(root) {
  for (const t of TOPS) {
    const list = h("ol.tl", skList(6));
    const meta = h("div.ph-meta.mono");
    const extra = t.id === "methods" ? h("div.methods") : null;
    const panel = h("section.panel", { "aria-label": t.title, dataset: { top: t.id } },
      h("header.ph", h("h3", h("span.ph-idx", { style: { width: "22px" } }, t.idx), t.title), meta), extra, list);
    topEls[t.id] = { list, meta, extra };
    if (t.wide) panel.classList.add("panel-wide");
    root.appendChild(panel);
  }
}

function row(content, n, max, metaParts, onClick, title) {
  const b = h("button.tl-btn", { type: "button", title },
    h("span.tl-v", content),
    h("span.tl-n", fmtInt(n)),
    metaParts && metaParts.length ? h("span.tl-m", metaParts.map((m) => h("span", m))) : null,
    h("span.tl-bar", { style: { width: max ? (n / max) * 100 + "%" : "0" } }));
  b.addEventListener("click", onClick);
  return h("li", b);
}
const txt = (v) => h("span.t", v);

export function renderTops(sum) {
  const T = sum.top;
  const now = serverNow();
  const fill = (id, items, mk, metaText) => {
    const { list, meta } = topEls[id];
    clear(list);
    meta.textContent = metaText || "";
    if (!items || !items.length) { list.appendChild(emptyLi("Nothing in this window.")); return; }
    const max = Math.max(...items.map((x) => x.n));
    for (const it of items) list.appendChild(mk(it, max));
  };
  // IP rows: the org line sits outside the IP button so it can be its own click-to-filter target
  fill("ips", T.ips, (r, max) => {
    const li = row([ccBadge(r.country), txt(r.ip)], r.n, max, null,
      () => addFilter("ip", r.ip), `${r.ip} (${countryName(r.country)})\nClick to filter`);
    li.classList.add("ip-li");
    li.appendChild(h("div.tl-m.tl-m2", orgCell({ org: r.org, asn: r.asn, org_state: r.org ? "done" : "pending" }),
      h("span", `${r.rules} rule${r.rules === 1 ? "" : "s"}`), h("span", `${r.hosts} host${r.hosts === 1 ? "" : "s"}`), h("span", `${fmtAge(now - r.last_ts)} ago`)));
    return li;
  }, "by blocks");
  fill("orgs", T.orgs, (r, max) => row(
    [r.org === PRIVATE_ORG ? h("span.org-private-tag", "PRIVATE") : null, txt(r.org === PRIVATE_ORG ? "reserved / RFC1918" : r.org), r.asn ? h("span.asn", r.asn) : null],
    r.n, max, [`${fmtInt(r.ips)} IP${r.ips === 1 ? "" : "s"}`, `${r.rules} rule${r.rules === 1 ? "" : "s"}`, fmtPct(r.n / Math.max(1, sum.kpis.blocked), 1), `${fmtAge(now - r.last_ts)} ago`],
    () => addFilter("org", r.org), `${r.org}${r.asn ? " (" + r.asn + ")" : ""}\n${r.ips} distinct IPs. Click to filter`), "owner of source IP");
  fill("hosts", T.hosts, (r, max) => row(txt(r.host || "(none)"), r.n, max, [`${fmtInt(r.ips)} IPs`, `${fmtAge(now - r.last_ts)} ago`],
    () => addFilter("host", r.host), `${r.host}\nClick to filter`));
  fill("countries", T.countries, (r, max) => row([ccBadge(r.country), txt(countryName(r.country) || "Unknown")], r.n, max,
    [fmtPct(r.n / Math.max(1, sum.kpis.blocked), 1)], () => addFilter("country", r.country), `Click to filter ${r.country}`));
  fill("accounts", T.accounts, (r, max) => row(txt(r.account_name || r.account), r.n, max, [r.account, `${fmtAge(now - r.last_ts)} ago`],
    () => addFilter("account", r.account), `${r.account_name} (${r.account})\nClick to filter`));
  fill("paths", T.paths, (r, max) => row(txt(r.path || "(none)"), r.n, max, null,
    () => r.path && addFilter("path", r.path), `${r.path}\nClick to filter (exact path)`));
  fill("user_agents", T.user_agents, (r, max) => row(txt(r.ua || "(none)"), r.n, max, null,
    () => r.ua && addFilter("ua", r.ua), `${r.ua}\nClick to filter (exact user agent)`));

  // methods + rule types
  const m = topEls.methods;
  clear(m.extra);
  for (const r of T.methods || []) {
    m.extra.appendChild(h("button.mchip", { type: "button", class: "mchip m-" + r.method, dataset: { fk: "method", fval: r.method }, title: "Filter method " + r.method }, r.method || "?", h("b", fmtInt(r.n))));
  }
  if (!(T.methods || []).length) m.extra.appendChild(h("span.dim", "no methods"));
  fill("methods", T.rule_types, (r, max) => row(txt(r.rule_type || "(none)"), r.n, max, [TYPE_LABEL[r.rule_type] || ""],
    () => addFilter("rule_type", r.rule_type), "Filter rule type"), "rule types");

  // traffic by host
  const tr = topEls.traffic;
  clear(tr.list);
  if (!sum.traffic_hosts) {
    tr.meta.textContent = "";
    tr.list.appendChild(emptyLi("Allowed volume is aggregated per account + host only. Remove other filters to see it."));
  } else if (!sum.traffic_hosts.length) {
    tr.list.appendChild(emptyLi("No aggregated traffic yet."));
  } else {
    tr.meta.textContent = "allowed vs blocked";
    for (const r of sum.traffic_hosts) {
      const tot = (r.allowed || 0) + (r.blocked || 0);
      const rate = tot ? r.blocked / tot : 0;
      const b = h("button.tl-btn.th-row", { type: "button", title: `${r.host} / ${r.account_name}\nClick to filter host` },
        h("span.tl-v", r.host || "(no host)"),
        h("span.th-rate", fmtPct(rate)),
        h("span.th-bar", { title: `block rate ${fmtPct(rate)}` }, h("span.bb", { style: { width: Math.max(rate > 0 ? 0.6 : 0, Math.min(100, rate * 100 * 20)) + "%" } })),
        h("span.th-m", h("span.a", "A " + fmtCompact(r.allowed)), h("span.b", "B " + fmtCompact(r.blocked)), h("span", r.account_name || r.account)));
      b.addEventListener("click", () => addFilter("host", r.host));
      tr.list.appendChild(h("li", b));
    }
  }
}
export function topsLoading() {
  for (const t of TOPS) if (!topEls[t.id].list.children.length) replace(topEls[t.id].list, skList(6));
}
export function topsError(msg) {
  for (const t of TOPS) replace(topEls[t.id].list, h("li.err", msg));
  replace(rulesEls.list, h("li.err", msg));
}

// ---------------------------------------------------------------- wire (latest blocks ticker)
let wireEl = null;
export function initWire() {
  wireEl = document.getElementById("wire");
  wireEl.appendChild(h("li.wire-label", "WIRE"));
}
export function pushWire(rows) {
  if (!wireEl) return;
  const sorted = [...rows].sort((a, b) => a.ts - b.ts).slice(-6);
  for (const r of sorted) {
    const li = h("li.in", { title: `${r.ip} -> ${r.host}${r.path || ""}\n${r.term_label}` },
      h("span", fmtTime(r.ts, { date: false })),
      h("b", "BLOCK"),
      h("span", r.ip),
      h("span.w-r", (r.inner_rule || r.rule_short || r.rule || "").slice(0, 40)));
    wireEl.insertBefore(li, wireEl.children[1] || null);
  }
  while (wireEl.children.length > 16) wireEl.lastChild.remove();
}

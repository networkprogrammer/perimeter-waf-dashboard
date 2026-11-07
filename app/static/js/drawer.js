// Row detail drawer: GET /api/events/{id} and render every field, grouped.
import { h, clear, replace, fmtFull, fmtAge, isoUtc, copyText, toast, countryName, ccBadge } from "./util.js";
import { scopeTag, typeTag, shortRule, scopeOf, orgCell, orgState } from "./components.js";

const VIA = {
  cymru: "Team Cymru IP-to-ASN (public)",
  rdap: "RDAP registry lookup (public)",
  radb: "RADb routing registry (public)",
  local: "Local rule (private / reserved range)",
};
import { api, addFilter, serverNow } from "./state.js";

// The route is /api/events/{id:path}: ids contain ':' (and may contain '/'), so the raw id is appended.
// Only characters that would end the path segment early are escaped.
const idPath = (id) => "/api/events/" + String(id).replace(/[?#%\s]/g, (c) => encodeURIComponent(c));

function pretty(v) {
  if (v == null) return null;
  const sv = String(v).trim();
  if ((sv.startsWith("{") || sv.startsWith("[")) && sv.length < 100000) {
    try { return JSON.stringify(JSON.parse(sv), null, 2); } catch { /* not JSON */ }
  }
  return sv;
}

export function createDrawer({ onNav, onDeepSearch }) {
  const el = document.getElementById("drawer");
  const scrim = document.getElementById("scrim");
  const body = document.getElementById("drawer-body");
  const title = document.getElementById("drawer-title");
  const kicker = document.getElementById("drawer-kicker");
  let current = null, prevFocus = null, seq = 0;

  document.getElementById("drawer-close").addEventListener("click", close);
  document.getElementById("drawer-prev").addEventListener("click", () => onNav(-1));
  document.getElementById("drawer-next").addEventListener("click", () => onNav(1));
  scrim.addEventListener("click", close);
  el.addEventListener("keydown", (e) => {
    if (e.key !== "Tab") return;
    const f = [...el.querySelectorAll("button:not([disabled]), [href], input, [tabindex]:not([tabindex='-1'])")].filter((x) => x.offsetParent !== null);
    if (!f.length) return;
    if (e.shiftKey && document.activeElement === f[0]) { e.preventDefault(); f[f.length - 1].focus(); }
    else if (!e.shiftKey && document.activeElement === f[f.length - 1]) { e.preventDefault(); f[0].focus(); }
  });

  function kv(label, value, { pre = false, copy = true, node = null } = {}) {
    const empty = value == null || value === "";
    const dd = h("dd");
    if (node) dd.appendChild(node);
    else if (pre && !empty) dd.appendChild(h("pre", pretty(value)));
    else dd.appendChild(h("span.val", { class: "val" + (empty ? " none" : "") }, empty ? "-" : String(value)));
    if (copy && !empty) {
      const b = h("button.copy", { type: "button", "aria-label": `Copy ${label}` }, "COPY");
      b.addEventListener("click", async () => {
        const ok = await copyText(String(value));
        b.textContent = ok ? "DONE" : "FAIL";
        b.classList.toggle("done", ok);
        setTimeout(() => { b.textContent = "COPY"; b.classList.remove("done"); }, 1200);
      });
      dd.appendChild(b);
    }
    return [h("dt", label), dd];
  }
  const sec = (name, ...items) => h("section.d-sec", h("h3", name), h("dl.kv", items));

  function action(label, key, fn) {
    const b = h("button.btn.btn-ghost", { type: "button", title: key ? `Shortcut: ${key}` : undefined }, label);
    b.addEventListener("click", fn);
    return b;
  }

  function render(r, full) {
    current = r;
    const sc = scopeOf(r.rule, r.rule_scope);
    kicker.textContent = `Blocked request / ${fmtAge(serverNow() - r.ts)} ago`;
    title.textContent = `${r.method || ""} ${r.host || ""}${r.path || ""}`.trim() || r.id;

    const labelsNode = r.labels ? h("span.lchips", String(r.labels).split("|").filter(Boolean).map((l) => h("span.lchip", l))) : null;
    const hero = h("div.d-hero", { dataset: { scope: sc } },
      h("div.d-hero-k", "Terminating rule"),
      h("div.d-hero-rule", shortRule(r.rule, r.rule_short)),
      r.inner_rule ? h("div.d-hero-inner", { title: "Inner rule inside the managed rule group" }, r.inner_rule) : null,
      h("div.d-hero-full", r.term_label || r.rule),
      h("div.d-tags", scopeTag(sc), typeTag(r.rule_type), h("span.vt", { title: "Action" }, r.term_action || "BLOCK")));

    const actions = h("div.d-actions",
      action("Filter IP", "i", () => addFilter("ip", r.ip)),
      action("Filter rule", "r", () => { addFilter("rule", r.rule); if (r.inner_rule) addFilter("inner_rule", r.inner_rule); }),
      action("Filter host", "h", () => addFilter("host", r.host)),
      r.path ? action("Filter path", null, () => addFilter("path", r.path)) : null,
      r.org ? action("Filter org", "o", () => addFilter("org", r.org)) : null,
      r.ua ? action("Filter UA", null, () => addFilter("ua", r.ua)) : null,
      action("Search IP in full lake \u2192", "s", () => onDeepSearch(r)),
      action("Copy JSON", null, async () => toast((await copyText(JSON.stringify(full || r, null, 2))) ? "Event JSON copied" : "Copy failed")));

    const parts = [hero, actions,
      sec("Request",
        kv("Time", fmtFull(r.ts)),
        kv("Time (UTC)", isoUtc(r.ts)),
        kv("Method", r.method),
        kv("Host", r.host),
        kv("Path", r.path),
        kv("Query args", full ? full.args : undefined, { pre: true }),
        kv("User agent", r.ua),
        kv("Referrer", full ? full.referrer : undefined),
        kv("X-Forwarded-For", full ? full.xff : undefined),
        kv("Status", r.status)),
      sec("Source",
        kv("IP", r.ip),
        kv("Org / owner", r.org, { node: h("span.val", orgCell(r, { clickable: false, asn: false })) }),
        kv("ASN", r.asn),
        kv("Network name", r.net_name),
        kv("Geo (whois)", full ? [full.geo_city, full.geo_country].filter(Boolean).join(", ") || null : undefined),
        kv("Resolved via", full ? (full.org_via ? `${VIA[full.org_via] || full.org_via} (${full.org_via})` : orgState(r) === "pending" ? "lookup queued" : null) : undefined),
        kv("Country", r.country ? `${r.country} - ${countryName(r.country)}` : null, { node: r.country ? h("span.val", ccBadge(r.country), " ", countryName(r.country)) : null }),
        kv("Labels", full ? full.labels : undefined, { node: labelsNode }),
        kv("JA3", full ? full.ja3 : undefined),
        kv("JA4", full ? full.ja4 : undefined)),
      sec("Termination",
        kv("Rule", r.rule),
        kv("Friendly name", shortRule(r.rule, r.rule_short)),
        kv("Rule type", r.rule_type),
        kv("Scope", r.rule_scope || sc),
        kv("Inner rule", r.inner_rule),
        kv("Action", r.term_action),
        kv("Condition", r.cond),
        kv("Match location", r.match_loc),
        kv("Matched field", r.matched_field),
        kv("Match details", full ? full.match_det : undefined, { pre: true }),
        kv("Rate limit", full ? full.rate_limit : undefined)),
      sec("Context",
        kv("Evaluated rule groups", full ? full.evaluated_groups : undefined, { pre: true }),
        kv("Non-terminating matches", full ? full.nonterm_rules : undefined, { pre: true }),
        kv("Account", r.account),
        kv("Account name", r.account_name),
        kv("Region", r.region),
        kv("Load balancer", r.resource),
        kv("Service", full ? full.svc : undefined),
        kv("Request ID", full ? full.req_id : undefined),
        kv("Event ID", r.id)),
    ];
    if (!full) parts.push(h("div.d-loading", h("span.sk", { style: { width: "60%" } }), h("span.sk", { style: { width: "40%" } })));
    replace(body, parts);
  }

  async function open(row) {
    const wasOpen = !el.hidden;
    if (!wasOpen) prevFocus = document.activeElement;
    el.hidden = false;
    scrim.hidden = false;
    const my = ++seq;
    render(row, null);
    if (!wasOpen) {
      body.scrollTop = 0;
      document.getElementById("drawer-close").focus();
    }
    try {
      const full = await api(idPath(row.id));
      if (my !== seq) return;
      render({ ...row, ...full }, full);
    } catch (e) {
      if (my !== seq) return;
      const err = body.querySelector(".d-loading");
      if (err) replace(err, h("div.err", { style: { color: "var(--block-2)", font: "12px var(--f-mono)" } }, "Could not load full event: " + e.message));
    }
  }
  function close() {
    if (el.hidden) return;
    el.hidden = true;
    scrim.hidden = true;
    current = null;
    seq++;
    if (prevFocus && document.contains(prevFocus)) prevFocus.focus({ preventScroll: true });
  }

  return {
    open, close,
    get isOpen() { return !el.hidden; },
    get current() { return current; },
  };
}

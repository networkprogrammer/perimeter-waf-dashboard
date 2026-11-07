// Shared renderers: the terminating-rule "verdict stamp", tags and click-to-filter values.
import { h } from "./util.js";

export const SCOPE_LABEL = {
  custom: "CUSTOM",
  "rate-based": "RATE",
  "aws-managed": "AWS",
  managed: "MANAGED",
  other: "OTHER",
};
export const SCOPE_TITLE = {
  custom: "Custom rule defined in your web ACL",
  "rate-based": "Rate-based rule",
  "aws-managed": "AWS managed rule group",
  managed: "Third-party managed rule group",
  other: "Other / unclassified rule",
};
export const TYPE_LABEL = { REGULAR: "REG", MANAGED_RULE_GROUP: "MRG", RATE_BASED: "RATE", GROUP: "GROUP" };

export function scopeOf(rule, scope) {
  return scope || "other";
}
// the backend supplies rule_short (configured prefixes stripped); this is the fallback for aggregates without it
export function shortRule(rule, short) {
  if (short) return short;
  if (!rule) return "unknown";
  return rule.startsWith("AWS-") ? rule.slice(4) : rule;
}
// compact display name: AWS managed groups drop their redundant "AWSManagedRules" prefix
export function displayRule(rule, short) {
  const n = shortRule(rule, short);
  return n.startsWith("AWSManagedRules") && n.length > 15 ? n.slice(15) : n;
}
export function scopeTag(scope) {
  const sc = scope || "other";
  return h("span.scope-tag", { dataset: { scope: sc }, title: SCOPE_TITLE[sc] || sc }, SCOPE_LABEL[sc] || sc);
}
export function typeTag(t) {
  if (!t) return null;
  return h("span.vt", { title: "Rule type: " + t }, TYPE_LABEL[t] || t);
}

// clickable value that adds a filter (handled by a delegated listener in app.js)
export function fv(key, value, content, { title, tab = -1, cls } = {}) {
  if (value == null || value === "") return h("span.dim", "-");
  const b = h("button.fv", {
    type: "button",
    tabindex: tab,
    dataset: { fk: key, fval: String(value) },
    title: title || `Filter: ${key} = ${value}`,
  }, content == null ? String(value) : content);
  if (cls) b.classList.add(cls);
  return b;
}

// Source-IP ownership. org_state: done | pending (lookup queued) | unknown. Live SSE rows carry no
// org fields yet (the backend joins ownership at query time), so missing state is treated as pending.
export const PRIVATE_ORG = "Private / reserved address";
export function orgState(r) {
  if (r.org === PRIVATE_ORG) return "private";
  if (r.org) return "done";
  if (r.org_state === "unknown") return "unknown";
  if (r.org_state === "done") return "unknown";
  return "pending";
}
export function orgTitle(r) {
  return [r.org, r.net_name && `network ${r.net_name}`, r.asn].filter(Boolean).join("\n");
}
export function orgCell(r, { clickable = true, asn = true } = {}) {
  const st = orgState(r);
  if (st === "pending") return h("span.org.org-pending", { title: "Ownership lookup queued" }, h("span.org-sk", { "aria-hidden": "true" }), "resolving\u2026");
  if (st === "unknown") return h("span.org.org-unknown", { title: "No owner found for this address" }, "unknown");
  if (st === "private") return h("span.org.org-private", { title: PRIVATE_ORG }, clickable ? fv("org", r.org, "PRIVATE", { title: PRIVATE_ORG + "\nClick to filter" }) : "PRIVATE");
  const name = clickable ? fv("org", r.org, r.org, { title: orgTitle(r) + "\nClick to filter by this org" }) : h("span.org-n", { title: orgTitle(r) }, r.org);
  return h("span.org", name, asn && r.asn ? h("span.asn", { title: r.net_name ? `network ${r.net_name}` : r.asn }, r.asn) : null);
}

// Verdict stamp. `r` needs rule, rule_type, rule_scope, rule_short?, inner_rule.
export function verdict(r, { clickable = true, showType = true } = {}) {
  const sc = scopeOf(r.rule, r.rule_scope);
  const name = displayRule(r.rule, r.rule_short);
  const el = h("span.verdict", { dataset: { scope: sc } });
  el.appendChild(h("span.vs", { title: SCOPE_TITLE[sc] || sc }, SCOPE_LABEL[sc] || sc));
  const nm = clickable ? fv("rule", r.rule, name, { title: `${r.rule}\nClick to filter by this rule` }) : h("span", { title: r.rule }, name);
  el.appendChild(h("span.vn", nm));
  if (r.inner_rule) {
    el.appendChild(clickable
      ? h("span.vi", fv("inner_rule", r.inner_rule, r.inner_rule, { title: `Inner rule ${r.inner_rule}\nClick to filter` }))
      : h("span.vi", { title: "Inner rule" }, r.inner_rule));
  }
  if (showType && r.rule_type) el.appendChild(typeTag(r.rule_type));
  return el;
}

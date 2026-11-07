// DOM + formatting helpers. Everything renders through textContent / DOM APIs: log-derived
// strings (paths, UAs, args, IPs) are attacker controlled and must never reach innerHTML.

export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const SVG_NS = "http://www.w3.org/2000/svg";

// h("div.cls#id", {attrs, on: {click}}, ...children)
export function h(tag, attrs, ...kids) {
  return build(document.createElement.bind(document), tag, attrs, kids);
}
export function s(tag, attrs, ...kids) {
  return build((t) => document.createElementNS(SVG_NS, t), tag, attrs, kids);
}
function build(make, tag, attrs, kids) {
  const m = /^([a-z0-9]+)((?:[.#][\w-]+)*)$/i.exec(tag);
  const el = make(m ? m[1] : tag);
  if (m && m[2]) {
    for (const part of m[2].match(/[.#][\w-]+/g)) {
      if (part[0] === ".") el.classList.add(part.slice(1));
      else el.id = part.slice(1);
    }
  }
  if (attrs != null && (typeof attrs !== "object" || attrs instanceof Node || Array.isArray(attrs))) {
    kids.unshift(attrs);
    attrs = null;
  }
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v == null || v === false) continue;
      if (k === "on") for (const [ev, fn] of Object.entries(v)) el.addEventListener(ev, fn);
      else if (k === "text") el.textContent = String(v);
      else if (k === "style" && typeof v === "object") Object.assign(el.style, v);
      else if (k === "dataset") Object.assign(el.dataset, v);
      else el.setAttribute(k, v === true ? "" : String(v));
    }
  }
  append(el, kids);
  return el;
}
function append(el, kids) {
  for (const k of kids) {
    if (k == null || k === false) continue;
    if (Array.isArray(k)) append(el, k);
    else if (k instanceof Node) el.appendChild(k);
    else el.appendChild(document.createTextNode(String(k)));
  }
}
export function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}
export function replace(el, ...kids) {
  clear(el);
  append(el, kids);
  return el;
}

// numbers ------------------------------------------------------------------
const nf = new Intl.NumberFormat("en-US");
export const fmtInt = (n) => (n == null ? "-" : nf.format(n));
export function fmtCompact(n) {
  if (n == null) return "-";
  const a = Math.abs(n);
  if (a >= 1e9) return (n / 1e9).toFixed(a >= 1e10 ? 1 : 2).replace(/\.?0+$/, "") + "B";
  if (a >= 1e6) return (n / 1e6).toFixed(a >= 1e7 ? 1 : 2).replace(/\.?0+$/, "") + "M";
  if (a >= 1e4) return (n / 1e3).toFixed(a >= 1e5 ? 0 : 1).replace(/\.0$/, "") + "k";
  return nf.format(n);
}
export function fmtPct(r, digits) {
  if (r == null || isNaN(r)) return "-";
  const p = r * 100;
  const d = digits != null ? digits : p === 0 ? 0 : p < 0.01 ? 4 : p < 0.1 ? 3 : p < 10 ? 2 : 1;
  return p.toFixed(d) + "%";
}

// time ---------------------------------------------------------------------
export const prefs = {
  utc: localStorage.getItem("waf.utc") === "1",
};
const pad = (n, w = 2) => String(n).padStart(w, "0");
function parts(ms, utc) {
  const d = new Date(ms);
  return utc
    ? { Y: d.getUTCFullYear(), M: d.getUTCMonth() + 1, D: d.getUTCDate(), h: d.getUTCHours(), m: d.getUTCMinutes(), s: d.getUTCSeconds() }
    : { Y: d.getFullYear(), M: d.getMonth() + 1, D: d.getDate(), h: d.getHours(), m: d.getMinutes(), s: d.getSeconds() };
}
export function fmtTime(ms, { utc = prefs.utc, date = "auto", secs = true } = {}) {
  if (ms == null || isNaN(ms)) return "-";
  const p = parts(ms, utc);
  const t = `${pad(p.h)}:${pad(p.m)}${secs ? ":" + pad(p.s) : ""}`;
  const today = parts(Date.now(), utc);
  const showDate = date === true || (date === "auto" && (p.D !== today.D || p.M !== today.M || p.Y !== today.Y));
  return (showDate ? `${pad(p.M)}-${pad(p.D)} ` : "") + t + (utc ? "Z" : "");
}
export function fmtFull(ms, utc = prefs.utc) {
  if (ms == null || isNaN(ms)) return "-";
  const p = parts(ms, utc);
  return `${p.Y}-${pad(p.M)}-${pad(p.D)} ${pad(p.h)}:${pad(p.m)}:${pad(p.s)}.${pad(new Date(ms).getMilliseconds(), 3)} ${utc ? "UTC" : tzName()}`;
}
export const isoUtc = (ms) => new Date(ms).toISOString();
let _tz;
function tzName() {
  if (_tz) return _tz;
  try {
    _tz = new Intl.DateTimeFormat("en-US", { timeZoneName: "short" }).formatToParts(new Date()).find((x) => x.type === "timeZoneName").value;
  } catch {
    _tz = "local";
  }
  return _tz;
}
export function fmtAge(ms) {
  if (ms == null || isNaN(ms)) return "-";
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return s + "s";
  const m = Math.floor(s / 60);
  if (m < 60) return m + "m" + (m < 10 ? " " + pad(s % 60) + "s" : "");
  const hh = Math.floor(m / 60);
  if (hh < 48) return hh + "h " + pad(m % 60) + "m";
  return Math.floor(hh / 24) + "d " + (hh % 24) + "h";
}
export function fmtSpan(ms) {
  const m = Math.round(ms / 60000);
  if (m < 60) return m + " min";
  const hh = m / 60;
  return (Number.isInteger(hh) ? hh : hh.toFixed(1)) + " h";
}

// countries ----------------------------------------------------------------
let _dn;
export function countryName(cc) {
  if (!cc || cc.length !== 2) return cc || "";
  try {
    _dn = _dn || new Intl.DisplayNames(["en"], { type: "region" });
    return _dn.of(cc.toUpperCase()) || cc;
  } catch {
    return cc;
  }
}
export function ccBadge(cc) {
  const name = countryName(cc) || "Unknown country";
  return h("span.cc", { title: name, "aria-label": name }, cc || "--");
}

// misc ---------------------------------------------------------------------
export function debounce(fn, ms) {
  let t;
  const d = (...a) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...a), ms);
  };
  d.cancel = () => clearTimeout(t);
  return d;
}
// leading + trailing throttle: run now, then at most once per `ms`
export function throttle(fn, ms) {
  let last = 0, t = null;
  return (...a) => {
    const now = Date.now();
    const wait = ms - (now - last);
    if (wait <= 0) {
      last = now;
      fn(...a);
    } else if (!t) {
      t = setTimeout(() => {
        t = null;
        last = Date.now();
        fn(...a);
      }, wait);
    }
  };
}

export async function copyText(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch { /* fall back below */ }
  const ta = h("textarea", { style: { position: "fixed", left: "-9999px", top: "0" }, readonly: true });
  ta.value = text;
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try { ok = document.execCommand("copy"); } catch { ok = false; }
  ta.remove();
  return ok;
}

let toastT;
export function toast(msg) {
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.hidden = false;
  clearTimeout(toastT);
  toastT = setTimeout(() => (el.hidden = true), 2200);
}

// CSV with spreadsheet formula neutralisation
export function toCsv(header, rows) {
  const esc = (v) => {
    if (v == null) return "";
    let x = String(v);
    if (/^[=+\-@\t\r]/.test(x)) x = "'" + x;
    return /[",\n\r]/.test(x) ? '"' + x.replace(/"/g, '""') + '"' : x;
  };
  return [header.map(esc).join(","), ...rows.map((r) => r.map(esc).join(","))].join("\r\n") + "\r\n";
}
export function download(name, text, type = "text/csv") {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = h("a", { href: url, download: name });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export const reducedMotion = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;

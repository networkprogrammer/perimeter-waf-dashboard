// Hand-rolled SVG time-series: allowed (top) and blocked (bottom) in two aligned panels, or a single
// log-scale panel. Hover crosshair + tooltip, drag to brush-zoom, click to focus a bucket.
import { s, h, clear, fmtInt, fmtCompact, fmtPct, fmtTime, prefs } from "./util.js";

const M = { l: 54, r: 14, t: 16, b: 24 };

function niceTicks(max, count = 4) {
  if (!(max > 0)) return [0];
  const raw = max / count;
  const mag = Math.pow(10, Math.floor(Math.log10(raw)));
  const step = [1, 2, 2.5, 5, 10].map((m) => m * mag).find((st) => st >= raw) || 10 * mag;
  const out = [];
  for (let v = 0; v <= max * 1.0001 + step * 0.0001; v += step) out.push(+v.toFixed(10));
  if (out[out.length - 1] < max) out.push(out[out.length - 1] + step);
  return out;
}
function timeTicks(from, to, width) {
  const span = to - from;
  const target = Math.max(2, Math.floor(width / 110));
  const steps = [60e3, 120e3, 300e3, 600e3, 900e3, 1800e3, 3600e3, 7200e3, 10800e3, 21600e3, 43200e3, 86400e3];
  const step = steps.find((st) => span / st <= target) || 86400e3;
  // align hour+ steps on local (or UTC) boundaries so labels read naturally
  const off = step >= 3600e3 && !prefs.utc ? new Date().getTimezoneOffset() * 60000 : 0;
  const out = [];
  let t = Math.ceil((from - off) / step) * step + off;
  for (; t <= to; t += step) out.push(t);
  return out;
}

export function createChart(root, { onZoom, onFocus }) {
  let data = null, mode = "split", hover = -1, drag = null, geom = null;
  const tip = document.getElementById("tooltip");
  const svg = s("svg", { "aria-hidden": "true" });
  root.appendChild(svg);
  const empty = h("div.chart-empty", { hidden: true });
  root.appendChild(empty);
  root.tabIndex = 0;

  const defs = s("defs",
    s("linearGradient", { id: "gA", x1: 0, x2: 0, y1: 0, y2: 1 },
      s("stop", { offset: "0%", "stop-color": "#5fb3a0", "stop-opacity": ".38" }),
      s("stop", { offset: "100%", "stop-color": "#5fb3a0", "stop-opacity": ".02" })),
    s("linearGradient", { id: "gB", x1: 0, x2: 0, y1: 0, y2: 1 },
      s("stop", { offset: "0%", "stop-color": "#ff5b3a", "stop-opacity": ".35" }),
      s("stop", { offset: "100%", "stop-color": "#ff5b3a", "stop-opacity": ".02" })));
  svg.appendChild(defs);
  const gAxes = s("g.ax");
  const gAllowed = s("g");
  const gBlocked = s("g");
  const gOver = s("g");
  svg.append(gAxes, gAllowed, gBlocked, gOver);
  const bars = new Map(); // t -> rect, reused so heights animate between refreshes

  function layout(hasAllowed) {
    const W = root.clientWidth, H = root.clientHeight;
    const iw = Math.max(10, W - M.l - M.r), ih = Math.max(10, H - M.t - M.b);
    if (mode === "split" && !hasAllowed) {
      // allowed is not applicable: give blocked the full height, keep a slim labelled strip
      const ah = 14;
      return { W, H, iw, ih, a: { y: M.t, h: ah }, b: { y: M.t + ah + 10, h: ih - ah - 10 } };
    }
    if (mode === "split") {
      const gap = 22;
      const ah = Math.round((ih - gap) * 0.42);
      return { W, H, iw, ih, a: { y: M.t, h: ah }, b: { y: M.t + ah + gap, h: ih - ah - gap } };
    }
    return { W, H, iw, ih, a: { y: M.t, h: ih }, b: { y: M.t, h: ih } };
  }

  function render() {
    if (!data) return;
    const series = data.series || [];
    const hasAllowed = data.allowed_applicable && series.some((p) => p.allowed != null);
    const L = layout(hasAllowed);
    svg.setAttribute("viewBox", `0 0 ${L.W} ${L.H}`);
    clear(gAxes); clear(gAllowed); clear(gOver);
    const from = data.range.from, to = data.range.to, bms = data.range.bucket_s * 1000;
    const x0 = Math.min(from, series.length ? series[0].t : from);
    const x1 = to;
    const X = (t) => M.l + ((t - x0) / Math.max(1, x1 - x0)) * L.iw;
    const totalBlocked = series.reduce((a, p) => a + p.blocked, 0);
    const maxB = Math.max(1, ...series.map((p) => p.blocked));
    const maxA = hasAllowed ? Math.max(1, ...series.map((p) => p.allowed || 0)) : 1;
    geom = { L, X, x0, x1, bms, series };

    empty.hidden = series.length > 0 && (totalBlocked > 0 || hasAllowed);
    empty.textContent = "No traffic in this window";

    // x axis
    const yBase = L.b.y + L.b.h;
    for (const t of timeTicks(x0, x1, L.iw)) {
      const x = X(t);
      if (x < M.l - 1 || x > M.l + L.iw + 1) continue;
      gAxes.appendChild(s("line", { x1: x, x2: x, y1: M.t, y2: yBase, class: "grid-l", "stroke-opacity": ".5" }));
      gAxes.appendChild(s("text", { x, y: yBase + 15, "text-anchor": "middle" }, fmtTime(t, { secs: false, date: x1 - x0 > 86400e3 ? true : "auto" })));
    }

    let YA, YB;
    if (mode === "split") {
      YA = (v) => L.a.y + L.a.h - (v / niceMax(maxA)) * L.a.h;
      YB = (v) => L.b.y + L.b.h - (v / niceMax(maxB)) * L.b.h;
      if (hasAllowed) yAxis(niceTicks(maxA, 2), YA, L.a);
      yAxis(niceTicks(maxB, 3), YB, L.b);
      gAxes.appendChild(s("text", { x: M.l + 6, y: L.a.y + 10, class: "lbl lbl-a" }, hasAllowed ? "ALLOWED / BUCKET" : "ALLOWED - N/A WITH THESE FILTERS"));
      gAxes.appendChild(s("text", { x: M.l + 6, y: L.b.y + (hasAllowed ? 10 : 14), class: "lbl lbl-b" }, "BLOCKED / BUCKET"));
      if (hasAllowed) gAxes.appendChild(s("line", { x1: M.l, x2: M.l + L.iw, y1: L.a.y + L.a.h, y2: L.a.y + L.a.h }));
    } else {
      const top = Math.max(maxA, maxB, 10);
      const lmax = Math.ceil(Math.log10(top * 1.2));
      const Y = (v) => L.a.y + L.a.h - (Math.log10(Math.max(1, v)) / lmax) * L.a.h;
      YA = YB = Y;
      const ticks = [];
      for (let i = 0; i <= lmax; i++) ticks.push(Math.pow(10, i));
      yAxis(ticks, Y, L.a, true);
      gAxes.appendChild(s("text", { x: M.l + 6, y: L.a.y + 10, class: "lbl" }, "LOG SCALE  "));
    }
    gAxes.appendChild(s("line", { x1: M.l, x2: M.l + L.iw, y1: yBase, y2: yBase }));

    // allowed area
    if (hasAllowed && series.length) {
      const pts = series.map((p) => [X(p.t + bms / 2), YA(p.allowed || 0)]);
      const base = mode === "split" ? L.a.y + L.a.h : YA(1);
      const line = "M" + pts.map((p) => p[0].toFixed(1) + "," + p[1].toFixed(1)).join("L");
      gAllowed.appendChild(s("path", { class: "a-area", d: `${line}L${pts[pts.length - 1][0].toFixed(1)},${base}L${pts[0][0].toFixed(1)},${base}Z` }));
      gAllowed.appendChild(s("path", { class: "a-line", d: line }));
    }

    // blocked bars (keyed)
    const bw = Math.max(1, (bms / Math.max(1, x1 - x0)) * L.iw - (series.length > 80 ? 1 : 2));
    const seen = new Set();
    const baseB = mode === "split" ? L.b.y + L.b.h : YB(1);
    for (const p of series) {
      seen.add(p.t);
      let r = bars.get(p.t);
      if (!r) {
        r = s("rect", { class: "b" });
        r.style.y = baseB + "px";
        r.style.height = "0px";
        bars.set(p.t, r);
        gBlocked.appendChild(r);
      }
      const y = p.blocked > 0 ? Math.min(YB(p.blocked), baseB - 1.5) : baseB;
      r.setAttribute("x", X(p.t) + (series.length > 80 ? 0 : 1));
      r.setAttribute("width", bw);
      // style geometry so CSS transitions animate live refreshes
      r.style.y = y + "px";
      r.style.height = Math.max(0, baseB - y) + "px";
    }
    for (const [t, r] of bars) if (!seen.has(t)) { r.remove(); bars.delete(t); }

    drawOverlay();
  }

  function niceMax(m) {
    const t = niceTicks(m, mode === "split" ? 3 : 4);
    return t[t.length - 1] || 1;
  }
  function yAxis(ticks, Y, band, log) {
    for (const v of ticks) {
      const y = Y(v);
      if (y < band.y - 1 || y > band.y + band.h + 1) continue;
      gAxes.appendChild(s("line", { x1: M.l, x2: M.l + geom.L.iw, y1: y, y2: y, class: "grid-l", "stroke-opacity": ".6" }));
      gAxes.appendChild(s("text", { x: M.l - 8, y: y + 3.5, "text-anchor": "end" }, log ? fmtCompact(v) : fmtCompact(v)));
    }
  }

  function drawOverlay() {
    clear(gOver);
    if (!geom) return;
    const { L, X, series, bms } = geom;
    const yBase = L.b.y + L.b.h;
    if (hover >= 0 && hover < series.length && !drag) {
      const p = series[hover];
      gOver.appendChild(s("rect", { class: "hot", x: X(p.t), y: M.t, width: Math.max(1, X(p.t + bms) - X(p.t)), height: yBase - M.t }));
      const cx = X(p.t + bms / 2);
      gOver.appendChild(s("line", { class: "xh", x1: cx, x2: cx, y1: M.t, y2: yBase }));
    }
    if (drag && Math.abs(drag.x1 - drag.x0) > 2) {
      const a = Math.min(drag.x0, drag.x1), b = Math.max(drag.x0, drag.x1);
      gOver.appendChild(s("rect", { class: "brush", x: a, y: M.t, width: b - a, height: yBase - M.t }));
    }
    for (const [t, r] of bars) r.classList.toggle("hi", hover >= 0 && series[hover] && series[hover].t === t);
  }

  function idxAt(clientX) {
    if (!geom || !geom.series.length) return -1;
    const rect = root.getBoundingClientRect();
    const x = clientX - rect.left;
    const { X, series, bms } = geom;
    if (x < M.l || x > M.l + geom.L.iw) return -1;
    let lo = 0, hi = series.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (X(series[mid].t) <= x) lo = mid; else hi = mid - 1;
    }
    return X(series[lo].t + bms) >= x - 0.5 ? lo : -1;
  }
  const xToT = (x) => geom.x0 + ((x - M.l) / geom.L.iw) * (geom.x1 - geom.x0);
  const localX = (e) => {
    const rect = root.getBoundingClientRect();
    return Math.min(Math.max(e.clientX - rect.left, M.l), M.l + geom.L.iw);
  };

  function showTip(i, clientX, clientY) {
    if (i < 0 || !geom) { tip.hidden = true; return; }
    const p = geom.series[i];
    const end = p.t + geom.bms;
    const total = p.allowed != null ? p.allowed + p.blocked : null;
    tip.replaceChildren(
      h("div.t", `${fmtTime(p.t, { date: true })} - ${fmtTime(end, { date: false })}`),
      h("div.r.b", h("i", "Blocked"), h("b", fmtInt(p.blocked))),
      h("div.r.a", h("i", "Allowed"), h("b", p.allowed == null ? "n/a" : fmtInt(p.allowed))),
      ...(total ? [h("div.r", h("i", "Block rate"), h("b", fmtPct(p.blocked / total)))] : []),
    );
    tip.hidden = false;
    const tw = tip.offsetWidth, th = tip.offsetHeight;
    let left = clientX + 16, top = clientY - th - 12;
    if (left + tw > window.innerWidth - 8) left = clientX - tw - 16;
    if (top < 8) top = clientY + 18;
    tip.style.left = left + "px";
    tip.style.top = top + "px";
  }

  root.addEventListener("pointermove", (e) => {
    if (!geom) return;
    if (drag) {
      drag.x1 = localX(e);
      drawOverlay();
      tip.hidden = true;
      return;
    }
    const i = idxAt(e.clientX);
    if (i !== hover) { hover = i; drawOverlay(); }
    showTip(i, e.clientX, e.clientY);
  });
  root.addEventListener("pointerleave", () => {
    if (drag) return;
    hover = -1;
    drawOverlay();
    tip.hidden = true;
  });
  root.addEventListener("pointerdown", (e) => {
    if (!geom || e.button !== 0) return;
    const x = localX(e);
    drag = { x0: x, x1: x, i: idxAt(e.clientX) };
    root.setPointerCapture(e.pointerId);
  });
  const endDrag = (e, cancel) => {
    if (!drag) return;
    const d = drag;
    drag = null;
    try { root.releasePointerCapture(e.pointerId); } catch { /* not captured */ }
    drawOverlay();
    if (cancel) return;
    if (Math.abs(d.x1 - d.x0) > 6) {
      const a = xToT(Math.min(d.x0, d.x1)), b = xToT(Math.max(d.x0, d.x1));
      onZoom(a, b);
    } else if (d.i >= 0) {
      const p = geom.series[d.i];
      onFocus(p.t, p.t + geom.bms);
    }
  };
  root.addEventListener("pointerup", (e) => endDrag(e, false));
  root.addEventListener("pointercancel", (e) => endDrag(e, true));
  root.addEventListener("keydown", (e) => {
    if (!geom || !geom.series.length) return;
    if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
      e.preventDefault();
      e.stopPropagation();
      hover = Math.max(0, Math.min(geom.series.length - 1, (hover < 0 ? geom.series.length - 1 : hover) + (e.key === "ArrowRight" ? 1 : -1)));
      drawOverlay();
      const rect = root.getBoundingClientRect();
      const p = geom.series[hover];
      showTip(hover, rect.left + geom.X(p.t + geom.bms / 2), rect.top + 40);
    } else if (e.key === "Enter" && hover >= 0) {
      e.preventDefault();
      e.stopPropagation();
      const p = geom.series[hover];
      tip.hidden = true;
      onFocus(p.t, p.t + geom.bms);
    }
  });
  root.addEventListener("blur", () => { hover = -1; drawOverlay(); tip.hidden = true; });

  new ResizeObserver(() => render()).observe(root);

  return {
    update(summary) { data = summary; render(); },
    setMode(m) {
      mode = m;
      for (const r of bars.values()) r.remove();
      bars.clear();
      render();
    },
    loading() {
      if (!data) { empty.hidden = false; empty.textContent = "Loading..."; }
    },
    error(msg) {
      data = null;
      clear(gAxes); clear(gAllowed); clear(gOver);
      for (const r of bars.values()) r.remove();
      bars.clear();
      empty.hidden = false;
      empty.textContent = msg;
    },
  };
}

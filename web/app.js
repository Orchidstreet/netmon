// SPDX-License-Identifier: AGPL-3.0-or-later
"use strict";
/* Netmon web interface. Plain JavaScript, no libraries. Times are shown in the viewer's local time zone,
   with UTC beside them where a full stamp is written out. Names of the site's own equipment come from
   NOW.site (see "site names" below). */

const $ = (s, el = document) => el.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const store = {
  get(k, d) { try { const v = localStorage.getItem("netmon." + k); return v === null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem("netmon." + k, JSON.stringify(v)); } catch { /* private window */ } },
};

/* ---------------------------------------------------------------- formatting */
const TZ = Intl.DateTimeFormat().resolvedOptions().timeZone;
const TZL = "local";
const F_LOC = new Intl.DateTimeFormat("en-GB", { timeZone: TZ, hour: "2-digit", minute: "2-digit" });
const F_UTC = new Intl.DateTimeFormat("en-GB", { timeZone: "UTC", hour: "2-digit", minute: "2-digit" });
const F_DAY = new Intl.DateTimeFormat("en-GB", { timeZone: TZ, day: "numeric", month: "short" });
const locTime = ts => F_LOC.format(new Date(ts * 1000));
const dayOf = ts => F_DAY.format(new Date(ts * 1000));
function stamp(ts) {
  if (!ts) return "never";
  const d = new Date(ts * 1000), today = F_DAY.format(d) === F_DAY.format(new Date());
  return `${today ? "" : F_DAY.format(d) + ", "}${F_LOC.format(d)} ${TZL} / ${F_UTC.format(d)} UTC`;
}
function dur(sec) {
  sec = Math.max(0, Math.round(sec));
  if (sec < 60) return `${sec} s`;
  const m = Math.floor(sec / 60), h = Math.floor(m / 60), d = Math.floor(h / 24);
  if (d >= 2) return `${d} days`;
  if (h >= 1) return `${h} h ${m % 60} min`;
  return `${m} min`;
}
function ago(ts) {
  if (!ts) return "never";
  const s = Date.now() / 1000 - ts;
  if (s < 45) return "just now";
  if (s < 86400 * 2) return dur(s) + " ago";
  return dayOf(ts);
}
function bytes(n) {
  n = +n || 0;
  const u = ["B", "kB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1000 && i < u.length - 1) { n /= 1000; i++; }
  return `${n >= 100 || i === 0 ? Math.round(n) : n.toFixed(1)} ${u[i]}`;
}
function bits(bps) {
  bps = +bps || 0;
  if (bps >= 1e9) return [(bps / 1e9).toFixed(2), "Gbit/s"];
  if (bps >= 1e6) return [(bps / 1e6).toFixed(bps >= 1e8 ? 0 : 1), "Mbit/s"];
  if (bps >= 1e3) return [Math.round(bps / 1e3), "kbit/s"];
  return [Math.round(bps), "bit/s"];
}
const bitsText = v => bits(v).join(" ");

/* ---------------------------------------------------------------- site names
   The collector sends NOW.site, built from its config.json: the site, its router, uplink, ISP, DNS filter,
   network zones and VPN. Every page reads names from here. SITE_FALLBACK holds neutral words for the
   moments before the first payload arrives and for any key the payload leaves out. */
const SITE_FALLBACK = {
  name: "", short: "", cc: "",
  router: { name: "the router", model: "", ip: "" },
  uplink: { name: "the uplink", kind: "", ip: "" },
  isp: { name: "the ISP" },
  collector: "the collector",
  filter: "the DNS filter",
  zones: [{ key: "lan", name: "Local network", sub: "", fenced: false }],
  vpn: { enabled: false, label: "VPN" },
};
function site() {
  const s = (typeof NOW !== "undefined" && NOW && NOW.site) || {};
  const pick = (k, sub) => ({ ...SITE_FALLBACK[k], ...(s[k] && typeof s[k] === "object" ? s[k] : {}), ...sub });
  return {
    ...SITE_FALLBACK, ...s,
    router: pick("router"), uplink: pick("uplink"), isp: pick("isp"), vpn: pick("vpn"),
    collector: typeof s.collector === "string" && s.collector ? s.collector : (s.collector && s.collector.name) || SITE_FALLBACK.collector,
    filter: typeof s.filter === "string" && s.filter ? s.filter : (s.filter && s.filter.name) || SITE_FALLBACK.filter,
    zones: Array.isArray(s.zones) && s.zones.length ? s.zones : SITE_FALLBACK.zones,
  };
}
const rtrName = () => site().router.name;
const upName = () => site().uplink.name;
const ispName = () => site().isp.name;
const filterName = () => site().filter;
const collectorName = () => site().collector;
/* The VPN's state: NOW.site.vpn when the payload carries it, else /api/vpnswitch (enabled, can_switch,
   profile), read at start and every minute. */
let VPN_INFO = null;
const siteVpn = () => (typeof NOW !== "undefined" && NOW && NOW.site && NOW.site.vpn) || null;
const vpnLabel = () => (siteVpn() && siteVpn().label) || (VPN_INFO && VPN_INFO.profile) || "VPN";
const vpnEnabled = () => siteVpn() ? !!siteVpn().enabled : !!(VPN_INFO && VPN_INFO.enabled);
const vpnCanSwitch = () => vpnEnabled() && (!VPN_INFO || VPN_INFO.can_switch !== false);
/* Capitalises the neutral fallback words ("the router" becomes "The router"); configured names stay as written. */
const cap = s => /^the /.test(String(s)) ? "T" + String(s).slice(1) : String(s);
/* Router vitals in the live payload. */
const vitalsOf = d => (d && (d.vitals || d.router)) || null;
/* A wired link through a fast adapter named in config.json (link.adapter), or one faster than 1 Gbit/s. */
const isMultigig = l => !!(l && l.kind === "wired" && (l.adapter || l.multigig || parseInt(l.speed, 10) > 1000));

/* Zones: the payload may tag a device or link with its zone key; otherwise the device's address is
   matched against each zone's cidr. Fenced zones are kept apart from the main network. */
function ip4(ip) { const m = String(ip || "").match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/); return m ? ((+m[1] << 24) >>> 0) + (+m[2] << 16) + (+m[3] << 8) + +m[4] : null; }
function inCidr(ip, cidr) {
  const [net, bits] = String(cidr || "").split("/"), a = ip4(ip), b = ip4(net), n = +bits;
  if (a == null || b == null || !(n >= 0 && n <= 32)) return false;
  const mask = n === 0 ? 0 : (0xFFFFFFFF << (32 - n)) >>> 0;
  return ((a & mask) >>> 0) === ((b & mask) >>> 0);
}
function zoneKeyOf(d, l) {
  const k = (l && l.zone) || (d && d.zone);
  if (k) return k;
  const zs = site().zones, ip = (l && l.ip) || (d && d.ip);
  const z = zs.find(z => inCidr(ip, z.cidr || z.sub));
  return z ? z.key : zs[0].key;
}
const fencedKeys = () => new Set(site().zones.filter(z => z.fenced).map(z => z.key));
const isFencedIp = ip => fencedKeys().has(zoneKeyOf({ ip }));

/* ---------------------------------------------------------------- api */
async function api(path) {
  const r = await fetch(path, { cache: "no-store" });
  if (!r.ok) throw new Error(`${path}: ${r.status}`);
  return r.json();
}
async function post(path, body) {
  const r = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json", "X-Netmon": "1" }, body: JSON.stringify(body) });
  return r.json();
}

/* ---------------------------------------------------------------- charts (SVG) */
const NS = "http://www.w3.org/2000/svg";
function el(tag, attrs = {}, parent) {
  const e = document.createElementNS(NS, tag);
  for (const k in attrs) e.setAttribute(k, attrs[k]);
  if (parent) parent.appendChild(e);
  return e;
}
function niceMax(v) {
  if (!(v > 0)) return 1;
  const e = Math.pow(10, Math.floor(Math.log10(v))), f = v / e;
  return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10) * e;
}
function timeTicks(t0, t1, width) {
  const steps = [60, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 172800, 604800, 2592000];
  const want = Math.max(2, Math.floor(width / 110));
  const step = steps.find(s => (t1 - t0) / s <= want) || steps[steps.length - 1];
  const out = [];   // ticks fall on UTC boundaries; labels are in local time
  for (let t = Math.ceil(t0 / step) * step; t <= t1; t += step) out.push(t);
  return { ticks: out, fmt: (t1 - t0) <= 172800 ? locTime : dayOf };
}
function segments(pts, maxGap) {
  const segs = [];
  let cur = [];
  for (let i = 0; i < pts.length; i++) {
    if (cur.length && pts[i][0] - pts[i - 1][0] > maxGap) { segs.push(cur); cur = []; }
    cur.push(pts[i]);
  }
  if (cur.length) segs.push(cur);
  return segs;
}
function medianGap(pts) {
  if (pts.length < 3) return 60;
  const g = [];
  for (let i = 1; i < pts.length; i++) g.push(pts[i][0] - pts[i - 1][0]);
  g.sort((a, b) => a - b);
  return g[Math.floor(g.length / 2)];
}

/* Hover layer shared by all charts: crosshair + tooltip built from rows(i). */
function hover(host, svg, box, xs, xOf, rows) {
  let tip = host.querySelector(".tip");
  if (!tip) { tip = document.createElement("div"); tip.className = "tip"; tip.hidden = true; host.appendChild(tip); }
  const hair = el("line", { class: "x-hair", y1: box.top, y2: box.bottom, visibility: "hidden" }, svg);
  const hit = el("rect", { class: "hit", x: box.left, y: box.top, width: Math.max(0, box.right - box.left), height: Math.max(0, box.bottom - box.top) }, svg);
  const move = ev => {
    if (!xs.length) return;
    const r = svg.getBoundingClientRect(), x = ev.clientX - r.left;
    let lo = 0, hi = xs.length - 1;
    while (hi - lo > 1) { const m = (lo + hi) >> 1; if (xOf(xs[m]) < x) lo = m; else hi = m; }
    const i = Math.abs(xOf(xs[lo]) - x) < Math.abs(xOf(xs[hi]) - x) ? lo : hi;
    const px = xOf(xs[i]);
    hair.setAttribute("x1", px); hair.setAttribute("x2", px); hair.setAttribute("visibility", "visible");
    tip.innerHTML = rows(i);
    tip.hidden = false;
    tip.style.left = Math.min(Math.max(px, 90), r.width - 90) + "px";
    tip.style.top = box.top + 4 + "px";
  };
  hit.addEventListener("pointermove", move);
  hit.addEventListener("pointerleave", () => { hair.setAttribute("visibility", "hidden"); tip.hidden = true; });
}

/* The wire: download above the line, upload below. pts = [[t, down_bps, up_bps], ...] */
function wireChart(host, pts, { t0, t1, height = 230, padR = 0, live = false, minScale = 250e3 } = {}) {
  host.querySelectorAll("svg").forEach(s => s.remove());
  const W = host.clientWidth || 600, H = height, padT = 8, padB = 22, padL = 0;
  const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, height: H, role: "img", "aria-label": "Internet traffic: download above the line, upload below" });
  host.prepend(svg);
  const mid = padT + (H - padT - padB) / 2, half = (H - padT - padB) / 2 - 2;
  const peak = Math.max(minScale, ...pts.map(p => Math.max(p[1], p[2])));
  const yMax = niceMax(peak * 1.08);
  const x = t => padL + (t - t0) / (t1 - t0 || 1) * (W - padL - padR);
  for (const f of [1, 0.5]) {
    for (const s of [-1, 1]) el("line", { class: "grid-line", x1: 0, x2: W - padR, y1: mid + s * f * half, y2: mid + s * f * half }, svg);
    el("text", { x: 2, y: mid - f * half - 4 }, svg).textContent = bitsText(yMax * f);
  }
  const { ticks, fmt } = timeTicks(t0, t1, W - padR);
  for (const t of ticks) {
    const tx = x(t);
    if (tx < 24 || tx > W - padR - 24) continue;
    el("text", { x: tx, y: H - 6, "text-anchor": "middle" }, svg).textContent = fmt(t);
  }
  const gap = medianGap(pts) * 3.5;
  for (const seg of segments(pts, gap)) {
    if (seg.length < 2) continue;
    const dn = seg.map(p => `${x(p[0]).toFixed(1)},${(mid - p[1] / yMax * half).toFixed(1)}`);
    const up = seg.map(p => `${x(p[0]).toFixed(1)},${(mid + p[2] / yMax * half).toFixed(1)}`);
    const a = x(seg[0][0]).toFixed(1), b = x(seg[seg.length - 1][0]).toFixed(1);
    el("path", { class: "a-down", d: `M${a},${mid} L${dn.join(" L")} L${b},${mid} Z` }, svg);
    el("path", { class: "a-up", d: `M${a},${mid} L${up.join(" L")} L${b},${mid} Z` }, svg);
    el("path", { class: "l-down", d: `M${dn.join(" L")}` }, svg);
    el("path", { class: "l-up", d: `M${up.join(" L")}` }, svg);
  }
  el("line", { class: "axis-line", x1: 0, x2: W - padR, y1: mid, y2: mid }, svg);
  if (live && pts.length) {
    const p = pts[pts.length - 1];
    el("circle", { cx: x(p[0]), cy: mid - p[1] / yMax * half, r: 3.5, fill: "var(--down)", class: "lead" }, svg);
    el("circle", { cx: x(p[0]), cy: mid - p[1] / yMax * half, r: 3, fill: "var(--down)" }, svg);
    el("circle", { cx: x(p[0]), cy: mid + p[2] / yMax * half, r: 3, fill: "var(--up)" }, svg);
  }
  hover(host, svg, { left: 0, right: W - padR, top: padT, bottom: H - padB }, pts.map(p => p[0]), x, i => {
    const p = pts[i];
    return `<div class="t">${stamp(p[0])}</div>
      <div class="r"><span class="swatch sw-down"></span>Download<b>${bitsText(p[1])}</b></div>
      <div class="r"><span class="swatch sw-up"></span>Upload<b>${bitsText(p[2])}</b></div>`;
  });
}

/* Single-series line with optional min-max band and loss marks. pts = [[t, v]], band = [[t, lo, hi]] */
function lineChart(host, pts, { t0, t1, height = 150, fmt = v => v.toFixed(0), unit = "", band = null, loss = null,
  yMin = 0, yMaxMin = 1, color = "var(--c3)", label = "" } = {}) {
  host.querySelectorAll("svg").forEach(s => s.remove());
  const W = host.clientWidth || 400, H = height, padT = 8, padB = 22, padL = 0, padR = 0;
  const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, height: H, role: "img", "aria-label": label });
  host.prepend(svg);
  const vals = pts.map(p => p[1]).filter(v => v != null);
  const hiVals = band ? band.map(b => b[2]).filter(v => v != null) : [];
  const yMax = niceMax(Math.max(yMaxMin, ...vals, ...hiVals) * 1.05);
  const x = t => padL + (t - t0) / (t1 - t0 || 1) * (W - padL - padR);
  const y = v => padT + (1 - (v - yMin) / (yMax - yMin || 1)) * (H - padT - padB);
  for (const f of [0, 0.5, 1]) {
    const v = yMin + f * (yMax - yMin);
    el("line", { class: f === 0 ? "axis-line" : "grid-line", x1: 0, x2: W, y1: y(v), y2: y(v) }, svg);
    if (f > 0) el("text", { x: 2, y: y(v) - 4 }, svg).textContent = fmt(v) + unit;
  }
  const { ticks, fmt: tf } = timeTicks(t0, t1, W);
  for (const t of ticks) {
    const tx = x(t);
    if (tx < 24 || tx > W - 24) continue;
    el("text", { x: tx, y: H - 6, "text-anchor": "middle" }, svg).textContent = tf(t);
  }
  const gap = medianGap(pts) * 3.5;
  if (band) {
    for (const seg of segments(band.filter(b => b[1] != null), gap)) {
      if (seg.length < 2) continue;
      const top = seg.map(b => `${x(b[0]).toFixed(1)},${y(b[2]).toFixed(1)}`);
      const bot = seg.slice().reverse().map(b => `${x(b[0]).toFixed(1)},${y(b[1]).toFixed(1)}`);
      el("path", { class: "band", fill: color, d: `M${top.join(" L")} L${bot.join(" L")} Z` }, svg);
    }
  }
  for (const seg of segments(pts.filter(p => p[1] != null), gap)) {
    if (seg.length < 2) { if (seg.length === 1) el("circle", { cx: x(seg[0][0]), cy: y(seg[0][1]), r: 2, fill: color }, svg); continue; }
    el("path", { d: "M" + seg.map(p => `${x(p[0]).toFixed(1)},${y(p[1]).toFixed(1)}`).join(" L"), fill: "none", stroke: color, "stroke-width": 2, "stroke-linejoin": "round" }, svg);
  }
  if (loss) for (const [t, l] of loss) if (l > 0) el("rect", { class: "loss", x: x(t) - 1.5, y: H - padB - Math.min(14, 3 + l / 8), width: 3, height: Math.min(14, 3 + l / 8), rx: 1 }, svg);
  hover(host, svg, { left: 0, right: W, top: padT, bottom: H - padB }, pts.map(p => p[0]), x, i => {
    const p = pts[i], b = band ? band[i] : null, l = loss ? loss[i] : null;
    let s = `<div class="t">${stamp(p[0])}</div><div class="r">${esc(label)}<b>${p[1] == null ? "no data" : fmt(p[1]) + unit}</b></div>`;
    if (b && b[1] != null) s += `<div class="r">Range<b>${fmt(b[1])}–${fmt(b[2])}${unit}</b></div>`;
    if (l) s += `<div class="r">Lost<b>${(+l[1]).toFixed(0)}%</b></div>`;
    return s;
  });
}

/* Stacked columns per time bucket. rows = [[t, allowed, blocked]] */
function columnsChart(host, rows, { t0, t1, bucket, height = 150, label = "Lookups" } = {}) {
  host.querySelectorAll("svg").forEach(s => s.remove());
  const W = host.clientWidth || 400, H = height, padT = 8, padB = 22;
  const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, height: H, role: "img", "aria-label": label });
  host.prepend(svg);
  const yMax = niceMax(Math.max(4, ...rows.map(r => r[1] + r[2])) * 1.05);
  const x = t => (t - t0) / (t1 - t0 || 1) * W;
  const y = v => padT + (1 - v / yMax) * (H - padT - padB);
  for (const f of [0, 0.5, 1]) {
    el("line", { class: f === 0 ? "axis-line" : "grid-line", x1: 0, x2: W, y1: y(f * yMax), y2: y(f * yMax) }, svg);
    if (f > 0) el("text", { x: 2, y: y(f * yMax) - 4 }, svg).textContent = Math.round(f * yMax).toLocaleString("en-GB");
  }
  const { ticks, fmt } = timeTicks(t0, t1, W);
  for (const t of ticks) { const tx = x(t); if (tx > 24 && tx < W - 24) el("text", { x: tx, y: H - 6, "text-anchor": "middle" }, svg).textContent = fmt(t); }
  const bw = Math.max(1, bucket / (t1 - t0) * W - 2);
  for (const [t, ok, bl] of rows) {
    const bx = x(t) + 1, base = y(0);
    const hOk = base - y(ok), hBl = base - y(bl);
    if (ok) el("rect", { class: "c-ok", x: bx, y: base - hOk, width: bw, height: hOk, rx: Math.min(1.5, bw / 2) }, svg);
    if (bl) el("rect", { class: "c-bl", x: bx, y: base - hOk - (ok ? 2 : 0) - hBl, width: bw, height: hBl, rx: Math.min(1.5, bw / 2) }, svg);
  }
  hover(host, svg, { left: 0, right: W, top: padT, bottom: H - padB }, rows.map(r => r[0] + bucket / 2), x, i => {
    const r = rows[i];
    return `<div class="t">${stamp(r[0])}</div><div class="r"><span class="swatch sw-ok"></span>Allowed<b>${r[1]}</b></div><div class="r"><span class="swatch sw-bl"></span>Blocked<b>${r[2]}</b></div>`;
  });
}
const legendAB = `<span class="legend"><span><i class="swatch sw-ok"></i>Allowed</span><span><i class="swatch sw-bl"></i>Blocked</span></span>`;
const ST_LABEL = { blocked: "Blocked", cached: "From cache", forwarded: "Forwarded", asked: "Asked", other: "Other" };
const stChip = s => `<span class="st ${esc(s)}">${ST_LABEL[s] || esc(s)}</span>`;
function upstreamName(u) { return u || "Unknown"; }
/* One line about the DNS source: its name, and whatever optional facts the source reports
   (blocking on or off, blocklist size, upstream). Facts the source does not report are left out. */
function dnsStatus(src) {
  const s = src || {}, bits = [`<span>Lookups from <b>${esc(s.name || filterName())}</b></span>`];
  if (s.blocking != null) bits.unshift(`${pill(s.blocking ? 0 : 2)}<span>${s.blocking ? "Blocking is on" : "Blocking is OFF"}</span><span class="muted">·</span>`);
  if (s.blocklist_size) bits.push(`<span class="muted">· ${(+s.blocklist_size).toLocaleString("en-GB")} names on the blocklist</span>`);
  if (s.upstream) bits.push(`<span class="muted">· upstream ${esc(s.upstream)}</span>`);
  return bits.join("");
}

/* ---------------------------------------------------------------- shared bits */
const ICON = {
  0: '<svg viewBox="0 0 12 12"><circle cx="6" cy="6" r="5.2" fill="currentColor"/><path d="M3.6 6.2l1.6 1.6 3.2-3.4" stroke="var(--panel)" stroke-width="1.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  1: '<svg viewBox="0 0 12 12"><path d="M6 .9l5.4 9.6H.6z" fill="currentColor"/><path d="M6 4.3v3M6 8.9v.1" stroke="var(--panel)" stroke-width="1.4" stroke-linecap="round"/></svg>',
  2: '<svg viewBox="0 0 12 12"><rect x=".8" y=".8" width="10.4" height="10.4" rx="2.4" fill="currentColor"/><path d="M4 4l4 4M8 4l-4 4" stroke="var(--panel)" stroke-width="1.5" stroke-linecap="round"/></svg>',
  3: '<svg viewBox="0 0 12 12"><circle cx="6" cy="6" r="5.2" fill="currentColor"/><path d="M4.4 4.6a1.7 1.7 0 1 1 2.2 1.6c-.4.2-.6.5-.6.9M6 8.8v.1" stroke="var(--panel)" stroke-width="1.3" fill="none" stroke-linecap="round"/></svg>',
};
const STATE = { 0: "OK", 1: "Warning", 2: "Critical", 3: "Unknown" };
const evIcon = e => ICON[e.state] ? `<span class="pill s${e.state}" style="padding:0;background:none">${ICON[e.state]}</span>`
  : `<span class="pill" style="padding:0;color:var(--c4)"><svg viewBox="0 0 12 12"><circle cx="6" cy="6" r="3.2" fill="currentColor"/></svg></span>`;
const pill = s => `<span class="pill s${s}">${ICON[s]}${STATE[s]}</span>`;

function rangeSeg(key, opts, def, onChange, aria = "Time range") {
  const cur = store.get("range." + key, def);
  const wrap = document.createElement("div");
  wrap.className = "seg";
  wrap.setAttribute("role", "group");
  wrap.setAttribute("aria-label", aria);
  const labels = { "1h": "Hour", "6h": "6 hours", "24h": "Day", "7d": "Week", "30d": "Month", "1y": "Year" };
  for (const o of opts) {
    const b = document.createElement("button");
    b.textContent = labels[o] ?? o;
    b.setAttribute("aria-pressed", o === cur);
    b.onclick = () => {
      store.set("range." + key, o);
      wrap.querySelectorAll("button").forEach(x => x.setAttribute("aria-pressed", x === b));
      onChange(o);
    };
    wrap.appendChild(b);
  }
  return { node: wrap, value: cur };
}
const SPAN = { "1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800, "30d": 2592000, "1y": 31536000 };

function barRows(items, { href, meta, tags } = {}) {
  if (!items.length) return `<div class="empty">Nothing has moved in the last five minutes.</div>`;
  const max = Math.max(...items.map(i => i.down + i.up), 1);
  return `<div class="bars">${items.map(i => {
    const tag = href ? "a" : "div";
    return `<${tag} class="bar-row" ${href ? `href="${href(i)}"` : ""}>
      <div class="who"><b>${esc(i.name)}</b>${meta ? `<span class="meta">${esc(meta(i))}</span>` : ""}</div>
      <div class="vals">${bytes(i.down)} · ${bytes(i.up)}</div>
      <div class="track" aria-hidden="true"><i class="d" style="width:${(i.down / max * 100).toFixed(1)}%"></i><i class="u" style="width:${(i.up / max * 100).toFixed(1)}%"></i></div>
      ${tags ? `<div class="tags">${esc(tags(i))}</div>` : ""}
    </${tag}>`;
  }).join("")}</div>`;
}
const legendDU = `<span class="legend"><span><i class="swatch sw-down"></i>Download</span><span><i class="swatch sw-up"></i>Upload</span></span>`;

function sigMeter(dbm) {
  if (dbm == null) return "";
  const bars = dbm >= -55 ? 4 : dbm >= -65 ? 3 : dbm >= -72 ? 2 : 1;
  const cls = dbm >= -67 ? "ok" : dbm >= -74 ? "warn" : "crit";
  let h = `<span class="sig ${cls}" title="${dbm} dBm">`;
  for (let i = 1; i <= 4; i++) h += `<i${i <= bars ? " class='on'" : ""}></i>`;
  return h + "</span>";
}
function linkCell(l) {
  if (!l) return `<span class="muted">—</span>`;
  if (l.kind === "wired") return isMultigig(l)
    ? `<span class="lchip ug"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M13 2 4 14h6l-1 8 9-12h-6z"/></svg>Multi-gig${l.speed ? " · " + esc(l.speed) : ""}</span>`
    : `<span class="lchip">Wired${l.speed ? " · " + esc(l.speed) : ""}</span>`;
  return `<span class="lwifi">${sigMeter(l.signal)}<span>Wi-Fi ${esc(l.band || "")}${l.signal != null ? ` · ${l.signal} dBm` : ""}</span></span>`;
}
function linkSortKey(l) { return !l ? "z" : l.kind === "wired" ? (isMultigig(l) ? "0" : "1") : "2" + (l.signal ?? -99); }

/* Dual-homed machines: rows that report the same hostname from more than one card address (a laptop on a
   cable and on Wi-Fi, say) are one physical machine. mergeDevices folds them into one row with several
   links and records the grouping in GROUP_OF, which groupKey reads on other pages. */
const GROUP_OF = {};
const hostKey = r => { const h = String(r.hostname || "").trim().toLowerCase(); return h && !TOPO.generic.has(h) ? h : ""; };
function mergeDevices(rows) {
  const macsOf = new Map();
  for (const r of rows) { const h = hostKey(r); if (h) macsOf.set(h, (macsOf.get(h) || new Set()).add((r.mac || "").toLowerCase())); }
  const byGroup = new Map(), out = [];
  for (const r of rows) {
    const h = hostKey(r), gi = h && macsOf.get(h).size > 1 ? h : null;
    const link = r.link ? { ...r.link, _bytes: r.down + r.up, _mac: r.mac } : null;
    if (gi == null) { out.push({ ...r, links: link ? [link] : [], macs: [r.mac], ips: r.ip ? [r.ip] : [] }); continue; }
    let g = byGroup.get(gi);
    if (!g) {
      g = { ...r, known: r.known, down: 0, up: 0,
            last_seen: 0, first_seen: r.first_seen, links: [], macs: [], ips: [], top_app: "", grouped: true };
      byGroup.set(gi, g); out.push(g);
    }
    g.known = g.known && r.known;
    GROUP_OF[(r.mac || "").toLowerCase()] = { key: "g:" + gi, name: g.name };
    g.down += r.down; g.up += r.up; g.last_seen = Math.max(g.last_seen, r.last_seen);
    g.first_seen = Math.min(g.first_seen || r.first_seen, r.first_seen || g.first_seen);
    if (link) g.links.push(link);
    g.macs.push(r.mac); if (r.ip) g.ips.push(r.ip);
    if (!g.top_app && r.top_app) g.top_app = r.top_app;
  }
  for (const g of out) {
    g.mac = g.macs[0]; g.ip = g.ips[0] || g.ip;
    if (g.grouped) g.grouped = g.macs.length > 1;
    g.carry = carryingIndex(g.links);
  }
  return out;
}
function carryingIndex(links) {
  let best = 0, bestB = -1;
  links.forEach((l, i) => { const b = (l && l._bytes) || 0; if (b > bestB) { bestB = b; best = i; } });
  if (bestB <= 0) { const w = links.findIndex(l => l && l.kind === "wired"); return w >= 0 ? w : 0; }
  return best;
}
function linkCellMulti(row) {
  const links = row.links || (row.link ? [row.link] : []);
  if (!links.length) return `<span class="muted">—</span>`;
  if (links.length === 1) return linkCell(links[0]);
  const carry = row.carry ?? carryingIndex(links);
  return `<div class="lstack">${links.map((l, i) => {
    const active = i === carry;
    return `<div class="lrow ${active ? "carry" : "stby"}">${linkCell(l)}<span class="lstate">${active ? "carrying" : "standby"}</span></div>`;
  }).join("")}</div>`;
}

function sortable(table, rows, cols, render, initial) {
  let key = initial.key, dir = initial.dir;
  const draw = () => {
    const sorted = rows.slice().sort((a, b) => {
      const va = cols[key].value(a), vb = cols[key].value(b);
      return (va < vb ? -1 : va > vb ? 1 : 0) * dir;
    });
    table.querySelector("thead").innerHTML = "<tr>" + Object.entries(cols).map(([k, c]) =>
      `<th class="sort ${c.num ? "num" : ""}" data-k="${k}" aria-sort="${k === key ? (dir > 0 ? "ascending" : "descending") : "none"}">${c.label}${k === key ? `<span class="arrow">${dir > 0 ? "▲" : "▼"}</span>` : ""}</th>`).join("") + "</tr>";
    table.querySelector("tbody").innerHTML = sorted.map(render).join("") ||
      `<tr><td colspan="${Object.keys(cols).length}" class="empty">Nothing recorded in this period yet. Data arrives every 15 seconds.</td></tr>`;
    table.querySelectorAll("th").forEach(th => th.onclick = () => {
      if (th.dataset.k === key) dir = -dir; else { key = th.dataset.k; dir = cols[key].num ? -1 : 1; }
      draw();
    });
  };
  draw();
}

/* ---------------------------------------------------------------- live data */
let NOW = null, live = false, pollTimer = null;
const listeners = new Set();
function startLive() {
  let es;
  try { es = new EventSource("api/stream"); } catch { es = null; }
  if (!es) return startPolling();
  es.onmessage = e => { live = true; NOW = JSON.parse(e.data); listeners.forEach(f => f(NOW)); chrome(); };
  es.onerror = () => { live = false; chrome(); };
}
function startPolling() {
  const tick = async () => { try { NOW = await api("api/now"); live = true; } catch { live = false; } listeners.forEach(f => NOW && f(NOW)); chrome(); };
  tick();
  pollTimer = setInterval(tick, 10000);
}
function chrome() {
  const dot = $("#live-dot"), txt = $("#live-text");
  const age = NOW && NOW.feed ? NOW.feed.age : null;
  if (!live) { dot.className = "dot off"; txt.textContent = "Not connected to the collector"; }
  else if (age == null || age > 90) { dot.className = "dot off"; txt.textContent = `No traffic data from ${rtrName()}`; }
  else { dot.className = "dot on"; txt.textContent = `Live · ${rtrName()} data ${age} s old`; }
  siteChrome();
  if (NOW) {
    const c = NOW.checks, b = $("#b-chk");
    b.hidden = !(c.crit || c.warn);
    b.className = "badge " + (c.crit ? "crit" : "warn");
    b.textContent = c.crit || c.warn || "";
    const st = NOW.selftest, sb = $("#b-st");
    if (sb) {
      const stale = !st || Date.now() / 1000 - st.ts > 2700;
      sb.hidden = !(stale || st.fail);
      sb.className = "badge " + (st && st.fail ? "crit" : "warn");
      sb.textContent = st && st.fail ? st.fail : "!";
      sb.title = st && st.fail ? `${st.fail} self-tests failing` : "The self-test has not run recently";
    }
    const d = $("#b-dev");
    d.hidden = !NOW.new_devices;
    d.textContent = NOW.new_devices || "";
  }
}
/* Sidebar names and the VPN pages follow NOW.site: the VPN pages are hidden when the VPN is disabled.
   When the site metadata first arrives, or changes, the current page is drawn again with the new names. */
let SITE_SEEN = JSON.stringify([null, false]);
async function loadVpnInfo() {
  try { const v = await api("api/vpnswitch"); VPN_INFO = { enabled: !!v.enabled, can_switch: !!v.can_switch, profile: v.profile || "" }; } catch { return; }
  siteChrome();
}
function siteChrome() {
  const s = site(), sub = $("#brand-sub"), rl = $("#nav-router");
  const named = NOW && NOW.site && NOW.site.router && NOW.site.router.name;
  if (sub) sub.textContent = [s.name, named].filter(Boolean).join(" · ") || "Collector";
  if (rl) rl.textContent = named || "Router";
  document.querySelectorAll("[data-vpn]").forEach(a => { a.hidden = !vpnEnabled(); });
  const sig = JSON.stringify([(NOW && NOW.site) || null, vpnEnabled()]);
  if (sig !== SITE_SEEN) { SITE_SEEN = sig; route(); }
}
setInterval(() => {
  const n = Date.now() / 1000;
  $("#clock").textContent = `${locTime(n)} ${TZL} / ${F_UTC.format(new Date())} UTC`;
}, 1000);

/* ---------------------------------------------------------------- views */
const VIEWS = {};
let teardown = null;

VIEWS.now = main => {
  main.innerHTML = `
    <div class="head"><h1>Now</h1><p>${esc(site().name ? site().name + " · " : "")}The internet link through ${esc(rtrName())}, last 30 minutes</p></div>
    <section class="panel wire" aria-label="Internet link">
      <div class="chart" id="wire"></div>
      <div class="readouts" aria-live="polite">
        <div class="readout dn"><div class="k"><span class="swatch sw-down"></span>Download</div><span class="v" id="r-dn">–</span><span class="u" id="r-dn-u"></span></div>
        <div class="readout"><span class="v" id="r-up">–</span><span class="u" id="r-up-u"></span><div class="k"><span class="swatch sw-up"></span>Upload</div></div>
      </div>
    </section>
    <section class="panel health" id="health" style="margin-top:14px"></section>
    <div class="grid g2" style="margin-top:14px">
      <section class="panel"><div class="ph"><h2>Devices</h2><span class="sub">last 5 min</span><span class="right">${legendDU}</span></div><div id="devs"></div></section>
      <section class="panel"><div class="ph"><h2>Applications</h2><span class="sub">last 5 min</span><span class="right">${legendDU}</span></div><div id="apps"></div></section>
    </div>
    <div class="grid g2" style="margin-top:14px">
      <section class="panel"><div class="ph"><h2>DNS</h2><span class="sub">last 15 min</span><a class="sub right" href="#/dns">Everything</a></div>
        <div class="pistatus" id="pist"></div><div class="tiles four" id="dnst"></div>
        <div class="ph" style="margin:14px 0 6px"><span class="sub">Lookups per minute, last 30 min</span><span class="right">${legendAB}</span></div><div class="chart" id="dnsc"></div></section>
      <section class="panel"><div class="ph"><h2>Latest lookups</h2><span class="sub">live</span></div><table class="live-list"><tbody id="dnsl"></tbody></table></section>
    </div>
    <div class="grid g3" style="margin-top:14px">
      <section class="panel"><div class="ph"><h2>${esc(cap(rtrName()))}</h2><a class="sub right" href="#/router">History</a></div><div class="tiles" id="rtr"></div></section>
      <section class="panel"><div class="ph"><h2>Round trip</h2><a class="sub right" href="#/latency">History</a></div><div class="tiles two" id="lat"></div></section>
      <section class="panel"><div class="ph"><h2>Events</h2><a class="sub right" href="#/checks">All checks</a></div><ul class="events" id="events"></ul></section>
    </div>`;
  const draw = d => {
    const now = d.now;
    wireChart($("#wire"), d.trace, { t0: now - 1800, t1: now, height: 240, padR: 170, live: true });
    const last = d.trace[d.trace.length - 1];
    if (last) {
      const [dv, du] = bits(last[1]), [uv, uu] = bits(last[2]);
      $("#r-dn").textContent = dv; $("#r-dn-u").textContent = du;
      $("#r-up").textContent = uv; $("#r-up-u").textContent = uu;
    }
    const c = d.checks, worst = c.crit ? 2 : c.warn ? 1 : 0;
    $("#health").innerHTML = `
      <div class="big">${pill(worst)}<span>${worst === 0 ? "Everything is working" : worst === 1 ? "Something needs a look" : "Something is broken"}</span></div>
      <div class="counts"><span><b>${c.ok}</b> OK</span><span><b>${c.warn}</b> warning</span><span><b>${c.crit}</b> critical</span></div>
      <div class="problems">${c.problems.slice(0, 3).map(p => `<a href="#/checks" class="pill s${p.hard}" title="${esc(p.output)}">${ICON[p.hard]}${esc(p.title)}</a>`).join("")}</div>`;
    $("#devs").innerHTML = barRows(d.devices, { href: i => `#/devices/${encodeURIComponent(i.mac)}`, meta: i => i.ip, tags: i => i.apps.map(a => a.app).join(" · ") });
    $("#apps").innerHTML = barRows(d.apps, { meta: i => `${i.devices} device${i.devices === 1 ? "" : "s"}` });
    const f = vitalsOf(d);
    $("#rtr").innerHTML = f ? [
      ["CPU", Math.round(f.cpu_pct ?? 0), "%"],
      ["Temperature", Math.round(f.temp_mc / 1000), "°C"],
      ["Free memory", Math.round(f.mem_avail_kb / 1024), "MB"],
      ["Connections", f.conntrack[0], ""],
      ["Wi-Fi clients", f.wifi_clients, ""],
      ["Up for", f.uptime ? dur(f.uptime) : "–", ""],
    ].map(([k, v, u]) => `<div class="tile"><div class="label">${k}</div><div class="v${typeof v === "string" ? " txt" : ""}">${esc(v)}<small>${u}</small></div></div>`).join("") : `<div class="tile empty">Waiting for ${esc(rtrName())}.</div>`;
    $("#lat").innerHTML = Object.entries(d.latency).map(([k, v]) =>
      `<div class="tile"><div class="label">${esc(k)}</div><div class="v">${v.med == null ? "—" : v.med < 10 ? v.med.toFixed(1) : Math.round(v.med)}<small>ms</small></div><div class="n">${v.loss ? `${Math.round(v.loss)}% lost` : "no loss"}</div></div>`).join("");
    const q = d.dns, pct = n => q.queries ? Math.round(100 * n / q.queries) : 0;
    $("#pist").innerHTML = dnsStatus(q.source);
    $("#dnst").innerHTML = `<div class="tile"><div class="label">Lookups</div><div class="v">${q.queries.toLocaleString("en-GB")}</div></div>
      <div class="tile"><div class="label">Blocked</div><div class="v">${pct(q.blocked)}<small>%</small></div><div class="n">${q.blocked} lookups</div></div>
      <div class="tile"><div class="label">From cache</div><div class="v">${pct(q.cached)}<small>%</small></div></div>
      <div class="tile"><div class="label">Typical reply</div><div class="v">${q.reply_ms == null ? "—" : Math.round(q.reply_ms)}<small>ms</small></div><div class="n">from upstream</div></div>`;
    columnsChart($("#dnsc"), q.series, { t0: now - 1800, t1: now, bucket: 60, height: 120 });
    $("#dnsl").innerHTML = q.live.map(x => `<tr><td class="mono muted">${locTime(x.ts)}</td><td class="who">${esc(x.device)}</td><td class="dom" title="${esc(x.domain)}">${esc(x.domain)}</td><td>${stChip(x.status)}</td></tr>`).join("")
      || `<tr><td class="empty">Waiting for the first lookup.</td></tr>`;
    $("#events").innerHTML = d.events.length ? d.events.map(e => `<li>${evIcon(e)}<span>${esc(e.text)}</span><span class="when">${stamp(e.ts)}</span></li>`).join("")
      : `<li class="empty">No events yet. Changes in the checks appear here.</li>`;
  };
  listeners.add(draw);
  if (NOW) draw(NOW);
  const onResize = () => NOW && draw(NOW);
  addEventListener("resize", onResize);
  return () => { listeners.delete(draw); removeEventListener("resize", onResize); };
};

VIEWS.devices = (main, arg) => {
  if (arg) return deviceDetail(main, decodeURIComponent(arg));
  main.innerHTML = `<div class="head"><h1>Devices</h1><p>Everything ${esc(rtrName())} has seen</p><div class="grow"></div><input class="search" type="search" placeholder="Find a device" aria-label="Find a device"><span id="seg"></span></div>
    <section class="panel"><div class="tscroll"><table><thead></thead><tbody></tbody></table></div></section>`;
  let rows = [];
  const load = async range => {
    rows = mergeDevices((await api(`api/devices?range=${range}`)).devices);
    render();
  };
  const render = () => {
    const q = $("input.search", main).value.toLowerCase();
    const shown = rows.filter(r => !q || [r.name, r.vendor, r.hostname, ...(r.ips || [r.ip]), ...(r.macs || [r.mac])].join(" ").toLowerCase().includes(q));
    sortable($("table", main), shown, {
      name: { label: "Device", value: r => r.name.toLowerCase() },
      link: { label: "Link", value: r => linkSortKey((r.links && r.links[r.carry ?? 0]) || r.link) },
      down: { label: "Downloaded", num: true, value: r => r.down },
      up: { label: "Uploaded", num: true, value: r => r.up },
      app: { label: "Mostly", value: r => r.top_app },
      seen: { label: "Last seen", num: true, value: r => r.last_seen },
    }, r => {
      const sub = r.grouped
        ? `${esc(r.vendor)} · ${(r.ips || []).map(esc).join(" / ")} · ${r.macs.length} interfaces`
        : `${esc(r.ip)} · ${esc(r.mac)}${r.vendor && r.vendor !== r.name ? " · " + esc(r.vendor) : ""}`;
      return `<tr class="click" data-mac="${esc((r.links && r.links[r.carry ?? 0] && r.links[r.carry ?? 0]._mac) || r.mac)}">
        <td><b>${esc(r.name)}</b>${r.grouped ? `<span class="gtag">dual-homed</span>` : ""}${r.known ? "" : `<span class="new">NEW</span>`}<span class="sub">${sub}</span>
          ${r.known ? "" : `<button class="btn" data-known="${esc(r.mac)}" style="margin-top:5px">Mark as known</button>`}</td>
        <td>${linkCellMulti(r)}</td>
        <td class="num">${bytes(r.down)}</td><td class="num">${bytes(r.up)}</td>
        <td>${esc(r.top_app || "—")}</td><td class="num">${ago(r.last_seen)}</td></tr>`;
    }, { key: "down", dir: -1 });
    main.querySelectorAll("tr.click").forEach(tr => tr.onclick = ev => {
      if (ev.target.dataset.known) return;
      location.hash = `#/devices/${encodeURIComponent(tr.dataset.mac)}`;
    });
    main.querySelectorAll("[data-known]").forEach(b => b.onclick = async ev => {
      ev.stopPropagation();
      await post("api/device/known", { mac: b.dataset.known });
      load(seg.value);
    });
  };
  const seg = rangeSeg("devices", ["1h", "24h", "7d", "30d"], "24h", r => { seg.value = r; load(r); });
  $("#seg", main).replaceWith(seg.node);
  $("input.search", main).addEventListener("input", render);
  load(seg.value);
  const t = setInterval(() => load(seg.value), 60000);
  return () => clearInterval(t);
};

async function deviceDetail(main, mac) {
  main.innerHTML = `<a class="back" href="#/devices">‹ Devices</a><div class="head" style="margin-top:6px"><h1 id="dname">Device</h1><button class="edit" id="rename" title="Rename">Rename</button><div class="grow"></div><span id="seg"></span></div>
    <div class="grid g3">
      <section class="panel"><dl class="kv" id="facts"></dl></section>
      <section class="panel" style="grid-column: span 2"><div class="ph"><h2>Traffic</h2><span class="right">${legendDU}</span></div><div class="chart" id="dchart"></div></section>
    </div>
    <div class="grid g3" style="margin-top:14px">
      <section class="panel"><div class="ph"><h2>Applications</h2></div><div id="dapps"></div></section>
      <section class="panel"><div class="ph"><h2>Sites looked up</h2><span class="sub">from the DNS log</span></div><table class="fixed"><thead><tr><th>Domain</th><th class="num">Lookups</th><th class="num">Last</th></tr></thead><tbody id="ddns"></tbody></table></section>
      <section class="panel"><div class="ph"><h2>Addresses it talks to</h2></div><table class="fixed"><thead><tr><th>Destination</th><th class="num">Down</th><th class="num">Up</th></tr></thead><tbody id="dpeers"></tbody></table></section>
    </div>`;
  const load = async range => {
    const d = await api(`api/device?mac=${encodeURIComponent(mac)}&range=${range}`);
    if (d.error || !d.device) { main.innerHTML = `<a class="back" href="#/devices">‹ Devices</a><p class="empty">${esc(d.error || "No record of this device.")}</p>`; return; }
    const v = d.device, now = Date.now() / 1000;
    $("#dname").textContent = v.name;
    $("#facts").innerHTML = `<dt>Address</dt><dd class="mono">${esc(v.ip)}</dd><dt>Card address</dt><dd class="mono">${esc(v.mac)}</dd>
      <dt>Maker</dt><dd>${esc(v.vendor || "Unknown")}</dd><dt>Name it gives</dt><dd>${esc(v.hostname || "None")}</dd>
      <dt>First seen</dt><dd>${stamp(v.first_seen)}</dd><dt>Last seen</dt><dd>${stamp(v.last_seen)}</dd>
      <dt>Status</dt><dd>${v.known ? "Known" : `<span class="new" style="margin:0">NEW</span> <button class="btn" id="known">Mark as known</button>`}</dd>`;
    const kb = $("#known");
    if (kb) kb.onclick = async () => { await post("api/device/known", { mac }); load(seg.value); };
    const pts = d.series.map(([t, dn, up]) => [t + d.bucket / 2, dn * 8 / d.bucket, up * 8 / d.bucket]);
    wireChart($("#dchart"), pts, { t0: now - SPAN[range], t1: now, height: 180, minScale: 8e3 });
    $("#dapps").innerHTML = barRows(d.apps.map(a => ({ ...a })), {});
    $("#ddns").innerHTML = d.domains.map(x => `<tr><td>${esc(x.domain)}${x.blocked ? ` <span class="dns-blocked">blocked ${x.blocked}×</span>` : ""}</td><td class="num">${x.n}</td><td class="num">${locTime(x.last)}</td></tr>`).join("")
      || `<tr><td colspan="3" class="empty">No lookups from ${esc(v.ip)} in this period.</td></tr>`;
    $("#dpeers").innerHTML = d.peers.map(x => `<tr><td>${esc(x.name || x.dst)}<span class="sub">${x.app ? esc(x.app) + " · " : ""}<span class="mono">${esc(x.dst)}:${x.dport}</span> ${esc(x.proto)}${x.name_src === "reverse DNS" ? " · reverse DNS" : ""}</span></td><td class="num">${bytes(x.down)}</td><td class="num">${bytes(x.up)}</td></tr>`).join("")
      || `<tr><td colspan="3" class="empty">No connections recorded in this period.</td></tr>`;
  };
  const seg = rangeSeg("device", ["1h", "24h", "7d", "30d"], "24h", r => { seg.value = r; load(r); });
  $("#seg", main).replaceWith(seg.node);
  $("#rename").onclick = () => {
    const h1 = $("#dname"), inp = document.createElement("input");
    inp.className = "inline"; inp.value = h1.textContent; inp.setAttribute("aria-label", "Device name");
    h1.replaceWith(inp); inp.focus(); inp.select();
    const done = async save => {
      if (save) await post("api/device/label", { mac, label: inp.value });
      load(seg.value);
      const n = document.createElement("h1"); n.id = "dname"; inp.replaceWith(n);
    };
    inp.onkeydown = e => { if (e.key === "Enter") done(true); if (e.key === "Escape") done(false); };
    inp.onblur = () => done(true);
  };
  load(seg.value);
}

VIEWS.apps = main => {
  main.innerHTML = `<div class="head"><h1>Applications</h1><p>Recognised by ${esc(rtrName())} from the traffic itself, grouped into classes.</p><div class="grow"></div><span id="mseg" style="margin-right:10px"></span><span id="seg"></span></div>
    <section class="panel"><div id="abody"></div></section>`;
  let data = { apps: [] }, mode = "By class";
  const renderTree = () => {
    const groups = new Map();
    for (const a of (data.apps || [])) {
      const c = classOf(a.name);
      const g = groups.get(c) || { name: c, color: CLASS_COLOR[c] || CLASS_OTHER[1], down: 0, up: 0, apps: [] };
      g.down += a.down; g.up += a.up; g.apps.push(a); groups.set(c, g);
    }
    const cats = [...groups.values()].sort((a, b) => (b.down + b.up) - (a.down + a.up));
    const gmax = Math.max(...cats.map(c => c.down + c.up), 1);
    $("#abody").innerHTML = `<div class="tree">` + (cats.map(c => {
      c.apps.sort((a, b) => (b.down + b.up) - (a.down + a.up));
      return `<div class="tnode lvl0"><div class="trow has" role="button" tabindex="0" aria-expanded="true">
        <span class="tw">▾</span><span class="cdot" style="background:${c.color}"></span>
        <div class="who"><b>${esc(c.name)}</b><span class="meta">${c.apps.length} app${c.apps.length === 1 ? "" : "s"}</span></div>
        <div class="vals">${bytes(c.down)} · ${bytes(c.up)}</div>
        <div class="track"><i class="d" style="width:${(c.down / gmax * 100).toFixed(1)}%"></i><i class="u" style="width:${(c.up / gmax * 100).toFixed(1)}%"></i></div></div>
        <div class="tchildren">${c.apps.map(a => `<div class="tnode lvl2"><div class="trow">
          <span class="tw"><span class="leafdot"></span></span><span class="cdot" style="background:transparent"></span>
          <div class="who"><b>${esc(a.name)}</b><span class="meta">${a.devices} device${a.devices === 1 ? "" : "s"}${a.users && a.users.length ? " · " + a.users.map(u => esc(u.name)).join(", ") : ""}</span></div>
          <div class="vals">${bytes(a.down)} · ${bytes(a.up)}</div>
          <div class="track"><i class="d" style="width:${(a.down / gmax * 100).toFixed(1)}%"></i><i class="u" style="width:${(a.up / gmax * 100).toFixed(1)}%"></i></div>
        </div></div>`).join("")}</div></div>`;
    }).join("") || `<div class="empty">No applications recorded yet. Data arrives every 15 seconds.</div>`) + `</div>`;
    $("#abody").querySelectorAll(".trow.has").forEach(row => {
      const t = () => { const k = row.nextElementSibling, o = !k.hidden; k.hidden = o; row.setAttribute("aria-expanded", String(!o)); row.querySelector(".tw").textContent = o ? "▸" : "▾"; };
      row.onclick = t; row.onkeydown = e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); t(); } };
    });
  };
  const renderFlat = () => {
    $("#abody").innerHTML = `<table><thead></thead><tbody></tbody></table>`;
    window.APPS_BASE = data.apps_baseline || 0;
    sortable($("table", main), data.apps || [], {
      name: { label: "Application", value: r => r.name.toLowerCase() },
      class: { label: "Class", value: r => classOf(r.name) },
      down: { label: "Downloaded", num: true, value: r => r.down },
      up: { label: "Uploaded", num: true, value: r => r.up },
      devices: { label: "Used by", num: true, value: r => r.devices },
      first: { label: "First seen", num: true, value: r => r.first_seen || 0 },
    }, r => { const cls = classOf(r.name); return `<tr><td><b>${esc(r.name)}</b>${r.first_seen && Date.now() / 1000 - r.first_seen < 86400 && r.first_seen > (window.APPS_BASE || 0) ? `<span class="new">NEW</span>` : ""}</td>
      <td><span class="ccell"><span class="cdot" style="background:${CLASS_COLOR[cls] || CLASS_OTHER[1]}"></span>${esc(cls)}</span></td>
      <td class="num">${bytes(r.down)}</td><td class="num">${bytes(r.up)}</td>
      <td class="num" style="text-align:left;font-family:var(--sans)">${r.users.map(u => esc(u.name)).join(", ")}${r.devices > r.users.length ? ` and ${r.devices - r.users.length} more` : ""}</td>
      <td class="num">${r.first_seen ? ago(r.first_seen) : "—"}</td></tr>`; }, { key: "down", dir: -1 });
  };
  const render = () => mode === "Flat" ? renderFlat() : renderTree();
  const load = async range => { data = await api(`api/apps?range=${range}`); render(); };
  const mseg = rangeSeg("apps-mode", ["By class", "Flat"], "By class", m => { mode = m; mseg.value = m; render(); }, "Grouping");
  $("#mseg", main).replaceWith(mseg.node); mode = mseg.value;
  const seg = rangeSeg("apps", ["1h", "24h", "7d", "30d"], "24h", r => { seg.value = r; load(r); });
  $("#seg", main).replaceWith(seg.node);
  load(seg.value);
};

VIEWS.connections = main => {
  main.innerHTML = `<div class="head"><h1>Connections</h1><p>Open now, from the connection table of ${esc(rtrName())}. Refreshes every 30 seconds.</p><div class="grow"></div><input class="search" type="search" placeholder="Find a device or site" aria-label="Find"><span id="cseg" style="margin-left:10px"></span></div>
    <section class="panel"><div id="cbody"></div></section>`;
  let rows = [], mode = "By class";
  const clsOf = r => classify({ app: r.app, host: r.name || r.dst, port: r.dport });
  const filtered = () => {
    const q = $("input.search", main).value.toLowerCase();
    return rows.filter(r => !q || [r.device, r.name, r.dst, r.src, r.app].join(" ").toLowerCase().includes(q));
  };
  const wireTree = () => $("#cbody").querySelectorAll(".trow.has").forEach(row => {
    const toggle = () => { const k = row.nextElementSibling, o = !k.hidden; k.hidden = o; row.setAttribute("aria-expanded", String(!o)); row.querySelector(".tw").textContent = o ? "▸" : "▾"; };
    row.onclick = toggle; row.onkeydown = e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } };
  });
  const renderTree = () => {
    const shown = filtered(), groups = new Map();
    for (const r of shown) {
      const c = clsOf(r);
      const g = groups.get(c) || { name: c, color: CLASS_COLOR[c] || CLASS_OTHER[1], down: 0, up: 0, conns: [] };
      g.down += r.bytes_down; g.up += r.bytes_up; g.conns.push(r); groups.set(c, g);
    }
    const cats = [...groups.values()].sort((a, b) => (b.down + b.up) - (a.down + a.up));
    const gmax = Math.max(...cats.map(c => c.down + c.up), 1);
    $("#cbody").innerHTML = `<div class="tree">` + (cats.map(c => {
      c.conns.sort((a, b) => (b.bytes_down + b.bytes_up) - (a.bytes_down + a.bytes_up));
      return `<div class="tnode lvl0"><div class="trow has" role="button" tabindex="0" aria-expanded="true">
        <span class="tw">▾</span><span class="cdot" style="background:${c.color}"></span>
        <div class="who"><b>${esc(c.name)}</b><span class="meta">${c.conns.length} connection${c.conns.length === 1 ? "" : "s"}</span></div>
        <div class="vals">${bytes(c.down)} · ${bytes(c.up)}</div>
        <div class="track"><i class="d" style="width:${(c.down / gmax * 100).toFixed(1)}%"></i><i class="u" style="width:${(c.up / gmax * 100).toFixed(1)}%"></i></div></div>
        <div class="tchildren">${c.conns.map(r => `<div class="tnode lvl2"><div class="trow">
          <span class="tw"><span class="leafdot"></span></span><span class="cdot" style="background:transparent"></span>
          <div class="who"><b>${esc(r.device || r.src)}</b><span class="meta">${esc(r.name || r.dst)} · <span class="mono">${esc(r.proto)} ${r.dport}</span>${r.app ? " · " + esc(r.app) : ""}</span></div>
          <div class="vals">${bytes(r.bytes_down)} · ${bytes(r.bytes_up)}</div>
          <div class="track"><i class="d" style="width:${(r.bytes_down / gmax * 100).toFixed(1)}%"></i><i class="u" style="width:${(r.bytes_up / gmax * 100).toFixed(1)}%"></i></div>
        </div></div>`).join("")}</div></div>`;
    }).join("") || `<div class="empty">No open connections match.</div>`) + `</div>`;
    wireTree();
  };
  const renderFlat = () => {
    $("#cbody").innerHTML = `<table><thead></thead><tbody></tbody></table>`;
    sortable($("table", main), filtered(), {
      device: { label: "Device", value: r => (r.device || "").toLowerCase() },
      dest: { label: "Talking to", value: r => (r.name || r.dst) },
      app: { label: "Application", value: r => r.app || "~" },
      class: { label: "Class", value: r => clsOf(r) },
      proto: { label: "Protocol", value: r => r.proto + r.dport },
      down: { label: "Downloaded", num: true, value: r => r.bytes_down },
      up: { label: "Uploaded", num: true, value: r => r.bytes_up },
      first: { label: "Open for", num: true, value: r => -r.first },
    }, r => {
      const cls = clsOf(r);
      return `<tr><td>${esc(r.device)}<span class="sub mono">${esc(r.src)}</span></td>
      <td>${esc(r.name || r.dst)}<span class="sub">${r.name ? `<span class="mono">${esc(r.dst)}</span> · name from ${esc(r.name_src)}` : "no name found"}</span></td>
      <td>${r.app ? esc(r.app) + `<span class="sub">by ${esc(r.app_via)}</span>` : `<span class="muted">not recognised</span>`}</td>
      <td><span class="ccell"><span class="cdot" style="background:${CLASS_COLOR[cls] || CLASS_OTHER[1]}"></span>${esc(cls)}</span></td>
      <td class="mono">${esc(r.proto)} ${r.dport}${r.state ? `<span class="sub">${esc(r.state.toLowerCase())}</span>` : ""}</td>
      <td class="num">${bytes(r.bytes_down)}</td><td class="num">${bytes(r.bytes_up)}</td><td class="num">${dur(r.last - r.first) === "0 s" ? "new" : dur(r.last - r.first)}</td></tr>`;
    }, { key: "down", dir: -1 });
  };
  const render = () => mode === "Flat" ? renderFlat() : renderTree();
  const seg = rangeSeg("conns-mode", ["By class", "Flat"], "By class", m => { mode = m; seg.value = m; render(); }, "Grouping");
  $("#cseg", main).replaceWith(seg.node);
  mode = seg.value;
  const load = async () => { rows = (await api("api/conns")).conns; render(); };
  $("input.search", main).addEventListener("input", render);
  load();
  const t = setInterval(load, 30000);
  return () => clearInterval(t);
};

VIEWS.dns = main => {
  main.innerHTML = `<div class="head"><h1>DNS</h1><p>Every name looked up on the network, and what ${esc(filterName())} did with it</p><div class="grow"></div><span id="seg"></span></div>
    <div class="pistatus" id="pist"></div>
    <section class="panel"><div class="tiles five" id="pt"></div></section>
    <section class="panel" style="margin-top:14px"><div class="ph"><h2>Lookups over time</h2><span class="right">${legendAB}</span></div><div class="chart" id="pc"></div></section>
    <div class="grid g3" style="margin-top:14px">
      <section class="panel"><div class="ph"><h2>Most looked up</h2></div><table class="fixed"><thead><tr><th>Domain</th><th class="num">Lookups</th><th class="num">Devices</th></tr></thead><tbody id="top"></tbody></table></section>
      <section class="panel"><div class="ph"><h2>Most blocked</h2></div><table class="fixed"><thead><tr><th>Domain</th><th class="num">Blocked</th><th class="num">Devices</th></tr></thead><tbody id="blk"></tbody></table></section>
      <section class="panel"><div class="ph"><h2>Devices asking most</h2></div><table class="fixed"><thead><tr><th>Device</th><th class="num">Lookups</th><th class="num">Blocked</th></tr></thead><tbody id="cli"></tbody></table></section>
    </div>
    <div class="grid g2" style="margin-top:14px">
      <section class="panel"><div class="ph"><h2>How lookups were answered</h2></div><div class="split"><div id="how"></div><div><div class="label" style="margin-bottom:6px">Kinds of lookup</div><table><tbody id="types"></tbody></table></div></div></section>
      <section class="panel"><div class="ph"><h2>Live</h2><span class="sub">refreshes every 5 seconds</span></div><table class="live-list"><tbody id="live"></tbody></table></section>
    </div>`;
  const load = async range => {
    const d = await api(`api/dns?range=${range}`), now = Date.now() / 1000, pct = n => d.total ? Math.round(100 * n / d.total) : 0;
    $("#pist").innerHTML = dnsStatus(d.source);
    $("#pt").innerHTML = `<div class="tile"><div class="label">Lookups</div><div class="v">${d.total.toLocaleString("en-GB")}</div></div>
      <div class="tile"><div class="label">Blocked</div><div class="v">${pct(d.blocked_total)}<small>%</small></div><div class="n">${d.blocked_total.toLocaleString("en-GB")} lookups</div></div>
      <div class="tile"><div class="label">From cache</div><div class="v">${pct(d.cached_total)}<small>%</small></div></div>
      <div class="tile"><div class="label">Typical reply</div><div class="v">${d.reply_ms == null ? "—" : Math.round(d.reply_ms)}<small>ms</small></div><div class="n">when upstream is asked</div></div>
      <div class="tile"><div class="label">Devices asking</div><div class="v">${d.client_count}</div></div>`;
    columnsChart($("#pc"), d.series, { t0: now - SPAN[range], t1: now, bucket: d.bucket, height: 170 });
    const row = x => `<tr><td title="${esc(x.domain)}">${esc(x.domain)}</td><td class="num">${x.n.toLocaleString("en-GB")}</td><td class="num">${x.clients}</td></tr>`;
    $("#top").innerHTML = d.top.map(row).join("") || `<tr><td colspan="3" class="empty">No lookups in this period.</td></tr>`;
    $("#blk").innerHTML = d.blocked.map(row).join("") || `<tr><td colspan="3" class="empty">Nothing blocked in this period.</td></tr>`;
    $("#cli").innerHTML = d.clients.map(c => `<tr><td>${esc(c.device)}<span class="sub mono">${esc(c.client)}</span></td><td class="num">${c.n.toLocaleString("en-GB")}</td><td class="num">${c.blocked ? Math.round(100 * c.blocked / c.n) + "%" : "0%"}</td></tr>`).join("");
    const how = [["forwarded", "Forwarded upstream", d.forwarded_total], ["cached", "From cache", d.cached_total], ["blocked", "Blocked", d.blocked_total],
      ["other", "Other", d.total - d.forwarded_total - d.cached_total - d.blocked_total]];
    const mx = Math.max(1, ...how.map(h => h[2]));
    $("#how").innerHTML = how.map(([k, name, n]) => `<div class="bar-row" style="border-top:0;padding:5px 0"><div class="who">${stChip(k).replace(ST_LABEL[k], name)}</div><div class="vals">${n.toLocaleString("en-GB")} · ${pct(n)}%</div>
      <div class="track"><i style="width:${(n / mx * 100).toFixed(1)}%;background:${k === "blocked" ? "var(--c4)" : k === "forwarded" ? "var(--c3)" : "var(--ink-3)"}"></i></div></div>`).join("")
      + d.upstreams.map(u => `<div class="muted" style="margin-top:8px">Upstream: ${esc(upstreamName(u.upstream))}, typical ${Math.round(u.ms)} ms over ${u.n.toLocaleString("en-GB")} lookups.</div>`).join("");
    $("#types").innerHTML = d.types.map(t => `<tr><td class="mono">${esc(t.qtype)}</td><td class="num">${t.n.toLocaleString("en-GB")}</td></tr>`).join("");
    drawLive(d.live);
  };
  const drawLive = live => {
    $("#live").innerHTML = live.slice(0, 40).map(x => `<tr><td class="mono muted">${locTime(x.ts)}</td><td class="who">${esc(x.device)}</td><td class="dom" title="${esc(x.domain)}">${esc(x.domain)}</td><td>${stChip(x.status)}</td></tr>`).join("")
      || `<tr><td class="empty">Waiting for the first lookup.</td></tr>`;
  };
  const seg = rangeSeg("dns", ["1h", "24h", "7d", "30d"], "24h", r => { seg.value = r; load(r); });
  $("#seg", main).replaceWith(seg.node);
  load(seg.value);
  const t1 = setInterval(async () => { try { drawLive((await api("api/dns?range=1h")).live); } catch { /* next tick */ } }, 5000);
  const t2 = setInterval(() => load(seg.value), 60000);
  return () => { clearInterval(t1); clearInterval(t2); };
};

VIEWS.checks = main => {
  main.innerHTML = `<div class="head"><h1>Checks</h1><p>Tested on a schedule. A problem must repeat before it counts.</p></div><div id="groups"></div>
    <section class="panel" style="margin-top:14px"><div class="ph"><h2>History</h2><span class="sub">changes of state, newest first</span></div><ul class="events" id="hist"></ul></section>`;
  const load = async () => {
    const d = await api("api/checks"), now = Date.now() / 1000, groups = {};
    d.checks.forEach(c => (groups[c.group] = groups[c.group] || []).push(c));
    $("#groups").innerHTML = Object.entries(groups).map(([g, cs]) => `
      <section class="panel check-group"><div class="ph"><h2>${esc(g)}</h2></div>
      ${cs.map(c => `<div class="check">
        <div>${pill(c.state)}</div>
        <div><div class="title">${esc(c.title)}</div><div class="out">${esc(c.output)}${c.soft != null && c.soft !== c.state ? ` <span class="muted">(retrying: ${STATE[c.soft].toLowerCase()} ${c.attempts} of ${c.max_attempts})</span>` : ""}</div></div>
        <div class="when">${c.since ? `${STATE[c.state]} for ${dur(now - c.since)}` : ""}<br>checked ${ago(c.last_run)}<br><button class="btn" data-run="${esc(c.name)}">Check now</button></div>
      </div>`).join("")}</section>`).join("");
    main.querySelectorAll("[data-run]").forEach(b => b.onclick = async () => {
      b.disabled = true; b.textContent = "Checking";
      await post("api/check/run", { name: b.dataset.run });
      setTimeout(load, 4000);
    });
    $("#hist").innerHTML = d.events.map(e => `<li>${evIcon(e)}<span>${esc(e.text)}</span><span class="when">${stamp(e.ts)}</span></li>`).join("")
      || `<li class="empty">No changes yet.</li>`;
  };
  load();
  const t = setInterval(load, 20000);
  return () => clearInterval(t);
};

VIEWS.latency = main => {
  main.innerHTML = `<div class="head"><h1>Latency</h1><p>Round trip from the collector, five pings a minute. Line is the median, shading the fastest to slowest, red marks lost pings.</p><div class="grow"></div><span id="seg"></span></div><div class="grid g2" id="lg"></div>`;
  const load = async range => {
    const d = await api(`api/latency?range=${range}`), now = Date.now() / 1000;
    $("#lg").innerHTML = d.targets.map((t, i) => `<section class="panel"><div class="ph"><h2>${esc(t)}</h2><span class="sub" id="ls${i}"></span></div><div class="chart" id="lc${i}"></div></section>`).join("");
    d.targets.forEach((t, i) => {
      const s = d.series[t] || [];
      const med = s.map(r => r[2]).filter(v => v != null).sort((a, b) => a - b);
      $(`#ls${i}`).textContent = med.length ? `typical ${med[Math.floor(med.length / 2)].toFixed(1)} ms` : "no data yet";
      lineChart($(`#lc${i}`), s.map(r => [r[0] + d.bucket / 2, r[2]]), {
        t0: now - SPAN[range], t1: now, height: 160, unit: " ms", fmt: v => v < 10 ? v.toFixed(1) : v.toFixed(0), yMaxMin: 2, label: t,
        band: s.map(r => [r[0] + d.bucket / 2, r[1], r[3]]), loss: s.map(r => [r[0] + d.bucket / 2, r[4]]),
      });
    });
  };
  const seg = rangeSeg("latency", ["1h", "24h", "7d", "30d", "1y"], "24h", r => { seg.value = r; load(r); });
  $("#seg", main).replaceWith(seg.node);
  load(seg.value);
  const onResize = () => load(seg.value);
  addEventListener("resize", onResize);
  return () => removeEventListener("resize", onResize);
};

VIEWS.router = main => {
  main.innerHTML = `<div class="head"><h1>${esc(cap(rtrName()))}</h1><p>${esc(site().router.model ? "The " + site().router.model + " router" : "The router")}, read every 10 seconds, kept as one-minute averages</p><div class="grow"></div><span id="seg"></span></div>
    <section class="panel"><div class="ph"><h2>Internet link</h2><span class="sub">average per interval</span><span class="right">${legendDU}</span></div><div class="chart" id="fw"></div></section>
    <div class="grid g3" style="margin-top:14px">
      <section class="panel"><div class="ph"><h2>CPU</h2></div><div class="chart" id="f1"></div></section>
      <section class="panel"><div class="ph"><h2>Temperature</h2></div><div class="chart" id="f2"></div></section>
      <section class="panel"><div class="ph"><h2>Free memory</h2></div><div class="chart" id="f3"></div></section>
      <section class="panel"><div class="ph"><h2>Connections tracked</h2></div><div class="chart" id="f4"></div></section>
      <section class="panel"><div class="ph"><h2>Wi-Fi clients</h2></div><div class="chart" id="f5"></div></section>
    </div>`;
  const load = async range => {
    const d = await api(`api/series?range=${range}`), now = Date.now() / 1000, t0 = now - SPAN[range], t1 = now;
    const R = d.rows, mid = r => r[0] + d.bucket / 2;
    wireChart($("#fw"), R.map(r => [mid(r), r[1], r[2]]), { t0, t1, height: 200 });
    lineChart($("#f1"), R.map(r => [mid(r), r[5]]), { t0, t1, unit: "%", yMaxMin: 10, label: "CPU" });
    lineChart($("#f2"), R.map(r => [mid(r), r[7]]), { t0, t1, unit: " °C", yMaxMin: 60, label: "Temperature" });
    lineChart($("#f3"), R.map(r => [mid(r), r[8] / 1024]), { t0, t1, unit: " MB", yMaxMin: 100, label: "Free memory" });
    lineChart($("#f4"), R.map(r => [mid(r), r[9]]), { t0, t1, yMaxMin: 100, label: "Connections" });
    lineChart($("#f5"), R.map(r => [mid(r), r[10]]), { t0, t1, yMaxMin: 5, label: "Wi-Fi clients" });
  };
  const seg = rangeSeg("router", ["6h", "24h", "7d", "30d", "1y"], "24h", r => { seg.value = r; load(r); });
  $("#seg", main).replaceWith(seg.node);
  load(seg.value);
  const t = setInterval(() => load(seg.value), 60000);
  const onResize = () => load(seg.value);
  addEventListener("resize", onResize);
  return () => { clearInterval(t); removeEventListener("resize", onResize); };
};

/* ---------------------------------------------------------------- traffic classes
   Deterministic classifier: exact app name, then keyword, then destination host, then port. Anything left
   is "Unclassified". Order matters: specific classes come before generic ones. */
const CLASS_DEFS = [
  { name: "Streaming & media", color: "#8A4FD1",
    apps: ["youtube","netflix","amazon prime","amazon prime video","prime video","disney+","disney plus","spotify","twitch","hulu","hbo max","apple tv","apple tv+","bbc iplayer","itv","itvx","channel 4","dazn","plex","tidal","soundcloud","vimeo","deezer","pandora","sky go","now tv","crunchyroll","peacock","paramount+","apple music","youtube music","soundcloud"],
    keys: ["stream","iptv","video","music"], ports: [] },
  { name: "AI assistants", color: "#6E56E6",
    apps: ["claude","chatgpt","openai","gemini","google gemini","copilot","github copilot","perplexity","anthropic","poe","midjourney","apple siri","siri","huggingface"],
    keys: ["openai","anthropic"], ports: [] },
  { name: "Social & chat", color: "#C4692D",
    apps: ["facebook","meta","meta messaging","whatsapp","instagram","messenger","telegram","signal","tiktok","snapchat","twitter","x","reddit","discord","pinterest","threads","mastodon","linkedin","tumblr","bluesky","google chat","nextdoor"],
    keys: ["messeng","chat","social"], ports: [5222,5223] },
  { name: "Real-time calls", color: "#0E8C7E",
    apps: ["zoom","microsoft teams","teams","facetime","google meet","webex","skype","jitsi","hangouts","whatsapp call","signal call","discord voice"],
    keys: ["voip","sip","rtp","webrtc","turn","stun"], ports: [3478,3479,3480,5060,5061,19302] },
  { name: "Mail", color: "#C0407A",
    apps: ["gmail","outlook","icloud mail","yahoo mail","fastmail","zoho mail","exchange"],
    keys: ["webmail","imap","smtp","pop3"], ports: [25,110,143,465,587,993,995] },
  { name: "Gaming", color: "#D14FA0",
    apps: ["steam","playstation network","playstation","xbox live","xbox","nintendo","nintendo switch","epic games","riot games","battle.net","blizzard","roblox","minecraft","ea","electronic arts","ubisoft","origin","twitch"],
    keys: ["game","gaming","playstation","xbox"], ports: [3074,27015,27036] },
  { name: "Remote access", color: "#556CC9",
    apps: ["teamviewer","anydesk","splashtop","chrome remote desktop","remote desktop","rdp","vnc","screen sharing","logmein","parsec"],
    keys: ["remote desktop","rdp","vnc","teamviewer","anydesk","screen shar"], ports: [3389,5900,5938] },
  { name: "File sharing", color: "#4C8B9E",
    apps: ["bittorrent","utorrent","qbittorrent","transmission","deluge","webtorrent","usenet","emule","soulseek"],
    keys: ["torrent","p2p","magnet","dht","usenet"], ports: [6881,6882,6883,6884,6885,6886,6887,6888,6889,4662] },
  { name: "IoT & smart home", color: "#B25FA0",
    apps: ["tp-link","tapo","kasa","philips hue","google nest","nest","amazon alexa","alexa","amazon echo","echo","homekit","matter","tuya","shelly","sonos","ring","wyze","ecobee","smartthings","roku","chromecast","google home","fire tv"],
    keys: ["smart home","iot","mqtt","tuya","homekit","matter","camera"], ports: [1883,8883] },
  { name: "Education", color: "#C77D2E",
    apps: ["duolingo","coursera","khan academy","udemy","kindle","audible","babbel","skillshare","brilliant"],
    keys: ["learn","course","education","tutor"], ports: [] },
  { name: "Cloud, sync & storage", color: "#2F5BEA",
    apps: ["amazon s3","amazon aws","amazon web services","amazon cloudfront","amazon devices","apple icloud","icloud","icloud private relay","dropbox","google drive","onedrive","backblaze","box","mega","mapbox","firebase","gsuite","google workspace","datadog","google play","google cloud","azure","digitalocean","cloudflare workers"],
    keys: ["cloud","backup","s3","storage","cdn"], ports: [548,445,873,2049] },
  { name: "Web & news", color: "#5A86FF",
    apps: ["cnn","bbc","the guardian","new york times","reddit","wikipedia","wikimedia","mozilla","ebay gumtree","google search","bing","duckduckgo","medium","stack overflow","imgur","google maps"],
    keys: ["http","https","tls","quic","ssl","web","akamai","fastly","jsdelivr","cloudflare","googleapis","google apis","wikimedia","news"], ports: [80,443,8080,8443] },
  { name: "Shopping", color: "#E08A1E",
    apps: ["amazon","ebay","etsy","aliexpress","argos","john lewis","asos","ikea","wise"],
    keys: ["shop","store","retail"], ports: [] },
  { name: "Finance & payments", color: "#2E9E68",
    apps: ["stripe","paypal","wise","revolut","monzo","starling","barclays","hsbc","visa","mastercard","coinbase","binance"],
    keys: ["bank","pay","payment"], ports: [] },
  { name: "Software & updates", color: "#3E8E5A",
    apps: ["apple","apple itunes","apple updates","apple search","apple id","apple store","app store","microsoft","windows update","google","google play store","mozilla updates","ubuntu","debian","adobe","nvidia","steam"],
    keys: ["update","software","ota","apt","packages"], ports: [] },
  { name: "Developer & infra", color: "#8A6D3B",
    apps: ["github","gitlab","jsdelivr","npm","docker","bitbucket","cloudflare","fastly","vercel","netlify","heroku","sentry","crashlytics","grafana"],
    keys: ["git","registry","ci"], ports: [22] },
  { name: "VPN & encrypted DNS", color: "#A8791F",
    apps: ["tailscale","mullvad vpn","mullvad","wireguard","openvpn","nordvpn","expressvpn","surfshark","icloud private relay","private relay","nextdns","adguard dns","controld","dnscrypt","quad9 doh","cloudflare warp","warp"],
    keys: ["vpn","wireguard","tailscale","ipsec","private relay","dns over","doh","dot ","doq","dnscrypt","oblivious","encrypted dns"],
    hosts: ["cloudflare-dns.com","dns.google","doh.opendns.com","dns.nextdns.io","dns.adguard.com","dns.adguard-dns.com","dns.quad9.net","doh.cleanbrowsing.org","dns.controld.com","one.one.one.one","mask.icloud.com","mask-h2.icloud.com","mullvad.net","wg.","vpn."],
    ports: [1194,51820,500,4500,853] },
  { name: "Security & auth", color: "#7E8A3C",
    apps: ["google safe browsing","google authentication","arkose labs","forter","1password","bitwarden","okta","duo","recaptcha","hcaptcha","let's encrypt","digicert","sectigo"],
    keys: ["safe browsing","captcha","auth","antivirus","malware","two-factor","2fa","certificate"],
    hosts: ["safebrowsing.googleapis.com","arkoselabs.com","forter.com","1password.com","okta.com","duosecurity.com","recaptcha.net"], ports: [] },
  { name: "Analytics & tracking", color: "#9A5B8C",
    apps: ["analytics","google analytics","crashlytics","adjust","appsflyer","revenuecat","segment","mixpanel","amplitude","branch","firebase analytics","doubleclick","arkose labs"],
    keys: ["analytic","telemetry","tracking","metric","ads","adservice"], ports: [] },
  { name: "Name & time", color: "#6B8794",
    apps: ["apple dns","time sync (ntp)","quad9","cloudflare dns","google dns","apple push","google play services"],
    keys: ["dns","ntp","push","time sync","resolver"], ports: [53,123,853,5353] },
];
const CLASS_OTHER = ["Unclassified", "#7A828D"];
const CLASS_COLOR = Object.fromEntries([...CLASS_DEFS.map(d => [d.name, d.color]), CLASS_OTHER]);
// Destination-domain rules, matched against the reverse-DNS names of peers. The longest suffix wins.
const HOST_EXTRA = [
  ["nflxvideo.net","Streaming & media"],["nflxso.net","Streaming & media"],["googlevideo.com","Streaming & media"],
  ["ytimg.com","Streaming & media"],["ggpht.com","Streaming & media"],["spotify.com","Streaming & media"],
  ["scdn.co","Streaming & media"],["ttvnw.net","Streaming & media"],["akamaihd.net","Streaming & media"],
  ["dssott.com","Streaming & media"],["media-amazon.com","Streaming & media"],["aiv-cdn.net","Streaming & media"],
  ["doubleclick.net","Analytics & tracking"],["google-analytics.com","Analytics & tracking"],["googlesyndication.com","Analytics & tracking"],
  ["googletagmanager.com","Analytics & tracking"],["adsystem.com","Analytics & tracking"],["scorecardresearch.com","Analytics & tracking"],
  ["crashlytics.com","Analytics & tracking"],["app-measurement.com","Analytics & tracking"],["branch.io","Analytics & tracking"],
  ["tplinkcloud.com","IoT & smart home"],["tplinkra.com","IoT & smart home"],["tuyaus.com","IoT & smart home"],
  ["tuya.com","IoT & smart home"],["nest.com","IoT & smart home"],["amazonalexa.com","IoT & smart home"],
  ["sonos.com","IoT & smart home"],["ring.com","IoT & smart home"],["ecobee.com","IoT & smart home"],
  ["1e100.net","Web & news"],["gstatic.com","Web & news"],["googleapis.com","Web & news"],
  ["cloudfront.net","Web & news"],["fastly.net","Web & news"],["akamai.net","Web & news"],["edgekey.net","Web & news"],
  ["aaplimg.com","Software & updates"],["mzstatic.com","Software & updates"],["apple.com","Software & updates"],
  ["windowsupdate.com","Software & updates"],["update.microsoft.com","Software & updates"],
  ["github.com","Developer & infra"],["githubusercontent.com","Developer & infra"],["jsdelivr.net","Developer & infra"],
  ["icloud.com","Cloud, sync & storage"],["dropbox.com","Cloud, sync & storage"],["backblaze.com","Cloud, sync & storage"],
  ["amazonaws.com","Cloud, sync & storage"],["s3.amazonaws.com","Cloud, sync & storage"],
];
const HOST_RULES = [];
for (const d of CLASS_DEFS) for (const h of (d.hosts || [])) HOST_RULES.push([h.toLowerCase(), d.name]);
for (const [h, c] of HOST_EXTRA) HOST_RULES.push([h.toLowerCase(), c]);
HOST_RULES.sort((a, b) => b[0].length - a[0].length);  // longest/most-specific first
const EXACT = new Map();
for (const d of CLASS_DEFS) for (const a of d.apps) if (!EXACT.has(a)) EXACT.set(a, d.name);
const PORT_CLASS = new Map();
for (const d of CLASS_DEFS) for (const p of (d.ports || [])) if (!PORT_CLASS.has(p)) PORT_CLASS.set(p, d.name);
const UNKNOWN = new Set();  // names with no app, host or port match

function classByApp(name) {
  const n = (name || "").trim().toLowerCase();
  if (!n || n === "unclassified") return null;
  if (EXACT.has(n)) return EXACT.get(n);
  for (const d of CLASS_DEFS) if (d.keys.some(k => n.includes(k))) return d.name;
  return null;
}
function classByHost(host) {
  const h = (host || "").trim().toLowerCase().replace(/\.$/, "");
  if (!h || /^\d+\.\d+\.\d+\.\d+$/.test(h)) return null;
  const doh = window.DOH_HOSTS;   // known DNS-over-HTTPS resolvers (doh.js): encrypted DNS on port 443
  if (doh) {
    const labels = h.split(".");
    for (let i = 0; i < labels.length - 1; i++) if (doh.has(labels.slice(i).join("."))) return "VPN & encrypted DNS";
  }
  for (const [suffix, cat] of HOST_RULES) if (h === suffix || h.endsWith("." + suffix)) return cat;
  return null;
}
// Layered deterministic classification: app name, then reverse-DNS host, then port.
function classify({ app, host, port } = {}) {
  return classByApp(app) || classByHost(host) || (port != null ? PORT_CLASS.get(+port) : null) || (UNKNOWN.add(app || host || port), CLASS_OTHER[0]);
}
function classOf(name) { return classByApp(name) || (UNKNOWN.add(name), CLASS_OTHER[0]); }

/* Super-classes group the classes into a partition tree: super-class → class → application. */
const SUPERCLASS = [
  ["Entertainment",      "#8A4FD1", ["Streaming & media", "Gaming", "Social & chat"]],
  ["Communication",      "#0E8C7E", ["Real-time calls", "Mail"]],
  ["Productivity & web", "#2F5BEA", ["Web & news", "AI assistants", "Cloud, sync & storage", "Developer & infra", "Education", "Shopping", "Finance & payments"]],
  ["Infrastructure",     "#3E8E5A", ["Software & updates", "Name & time", "Security & auth", "Analytics & tracking", "IoT & smart home", "Remote access", "File sharing"]],
  ["Encrypted & hidden", "#A8791F", ["VPN & encrypted DNS"]],
];
const SUPER_OF = {}, SUPER_COLOR = { "Other traffic": "#7A828D" };
for (const [s, col, cs] of SUPERCLASS) { SUPER_COLOR[s] = col; for (const c of cs) SUPER_OF[c] = s; }

/* ---- zoomable traffic sunburst (hand-rolled SVG, animated) ---- */
function trafficHierarchy(apps, scale = "Bytes") {
  const w = b => scale === "Balanced" ? Math.sqrt(Math.max(b, 0)) : Math.max(b, 0);
  const classMap = new Map();
  for (const a of apps) {
    const cn = classOf(a.name), col = CLASS_COLOR[cn] || CLASS_OTHER[1];
    let g = classMap.get(cn);
    if (!g) { g = { name: cn, color: col, kind: "class", children: [] }; classMap.set(cn, g); }
    g.children.push({ name: a.name, value: w(a.down + a.up), bytes: Math.max(a.down + a.up, 0), color: col, kind: "app" });
  }
  const superMap = new Map();
  for (const cls of classMap.values()) {
    const s = SUPER_OF[cls.name] || "Other traffic";
    let g = superMap.get(s);
    if (!g) { g = { name: s, color: SUPER_COLOR[s], kind: "super", children: [] }; superMap.set(s, g); }
    g.children.push(cls);
  }
  return { name: "All traffic", color: "var(--ink-3)", kind: "root", children: [...superMap.values()] };
}
function sumValues(n) {
  if (n.children && n.children.length) {
    n.value = n.children.reduce((s, c) => s + sumValues(c), 0);
    n.bytes = n.children.reduce((s, c) => s + (c.bytes || 0), 0);
  }
  return n.value || 0;
}
function layoutPartition(root) {
  sumValues(root);
  (function assign(n, depth, x0, x1, parent) {
    n.depth = depth; n.x0 = x0; n.x1 = x1; n.parent = parent;
    if (n.children && n.children.length) {
      n.children.sort((a, b) => b.value - a.value);
      let x = x0; const span = x1 - x0, tot = n.value || 1;
      for (const c of n.children) { const cx1 = x + span * (c.value / tot); assign(c, depth + 1, x, cx1, n); x = cx1; }
    }
  })(root, 0, 0, 1, null);
  const nodes = []; (function walk(n) { n._i = nodes.length; nodes.push(n); (n.children || []).forEach(walk); })(root);
  root._nodes = nodes; return root;
}
function arcPath(cx, cy, ir, or_, a0, a1) {
  const large = (a1 - a0) > Math.PI ? 1 : 0, p = (r, a) => [cx + r * Math.cos(a), cy + r * Math.sin(a)];
  const [xo0, yo0] = p(or_, a0), [xo1, yo1] = p(or_, a1), [xi1, yi1] = p(ir, a1), [xi0, yi0] = p(ir, a0);
  return `M${xo0.toFixed(2)} ${yo0.toFixed(2)} A${or_} ${or_} 0 ${large} 1 ${xo1.toFixed(2)} ${yo1.toFixed(2)} L${xi1.toFixed(2)} ${yi1.toFixed(2)} A${ir} ${ir} 0 ${large} 0 ${xi0.toFixed(2)} ${yi0.toFixed(2)} Z`;
}
function sunburst(host, root) {
  const size = Math.max(240, Math.min(host.clientWidth || 440, 440)), cx = size / 2, cy = size / 2;
  const RINGS = 3, r0 = Math.round(size * 0.145), rw = (size / 2 - r0 - 8) / RINGS;
  host.innerHTML = `<div class="sun-wrap"><svg viewBox="0 0 ${size} ${size}" class="sun" role="img" aria-label="Traffic map"></svg><div class="sun-tip" hidden></div></div>`;
  const svg = host.querySelector("svg"), tip = host.querySelector(".sun-tip"), nodes = root._nodes;
  let focus = root;
  const short = s => s.length > 15 ? s.slice(0, 14) + "…" : s;
  const radii = d => d <= 0 ? [0, r0] : [r0 + (d - 1) * rw, r0 + d * rw];
  function target(f) {
    const span = (f.x1 - f.x0) || 1;
    for (const n of nodes) {
      const x0 = Math.max(0, Math.min(1, (n.x0 - f.x0) / span)), x1 = Math.max(0, Math.min(1, (n.x1 - f.x0) / span));
      n._tar = { x0, x1, d: n.depth - f.depth, vis: n.depth >= f.depth && x1 - x0 > 1e-4 && (n.depth - f.depth) <= RINGS };
    }
  }
  function draw() {
    let h = "";
    for (const n of nodes) {
      const c = n._cur; if (!c || c.x1 - c.x0 < 1e-4 || c.d < 0.02) continue;
      const [ir, or_] = radii(c.d); if (or_ <= ir) continue;
      const a0 = c.x0 * 2 * Math.PI - Math.PI / 2, a1 = c.x1 * 2 * Math.PI - Math.PI / 2;
      if (a1 - a0 < 0.004) continue;
      const op = n.kind === "super" ? 1 : n.kind === "class" ? 0.9 : 0.72;
      h += `<path d="${arcPath(cx, cy, ir + 0.6, or_ - 0.6, a0, a1)}" fill="${n.color}" fill-opacity="${op}" class="sun-seg" data-i="${n._i}"></path>`;
      const mid = (a0 + a1) / 2, rm = (ir + or_) / 2, arcLen = (a1 - a0) * rm, label = short(n.name);
      if (arcLen > 26 && (or_ - ir) > 16 && label.length * 5.6 < Math.max(arcLen, or_ - ir) * 1.05) {
        const norm = r => ((r % 360) + 360) % 360;
        const deg = mid * 180 / Math.PI, radial = arcLen < label.length * 5.8;
        let rot = norm(radial ? deg : deg + 90);
        if (rot > 90 && rot < 270) rot = norm(rot + 180);
        const lx = (cx + rm * Math.cos(mid)).toFixed(1), ly = (cy + rm * Math.sin(mid)).toFixed(1);
        h += `<text class="sun-wl" x="${lx}" y="${ly}" text-anchor="middle" dominant-baseline="central" transform="rotate(${rot.toFixed(1)} ${lx} ${ly})">${esc(label)}</text>`;
      }
    }
    h += `<circle cx="${cx}" cy="${cy}" r="${r0 - 3}" class="sun-center" data-center="1"></circle>`
      + `<text x="${cx}" y="${cy - 3}" class="sun-lbl" text-anchor="middle">${esc(short(focus.name))}</text>`
      + `<text x="${cx}" y="${cy + 13}" class="sun-sub" text-anchor="middle">${bytes(focus.bytes || 0)}</text>`
      + (focus.parent ? `<text x="${cx}" y="${cy + 27}" class="sun-hint" text-anchor="middle">↑ back</text>` : "");
    svg.innerHTML = h;
  }
  function animateTo(f) {
    target(f);
    const from = nodes.map(n => ({ ...(n._cur || { x0: n._tar.x0, x1: n._tar.x0, d: n._tar.d, vis: false }) }));
    nodes.forEach((n, i) => { if (!from[i].vis && n._tar.vis) from[i] = { x0: n._tar.x0, x1: n._tar.x0, d: n._tar.d, vis: true }; });
    focus = f; const t0 = performance.now(), dur = 640;
    (function frame(t) {
      const k = Math.min(1, (t - t0) / dur), e = 1 - Math.pow(1 - k, 3);
      nodes.forEach((n, i) => { const a = from[i], b = n._tar; n._cur = { x0: a.x0 + (b.x0 - a.x0) * e, x1: a.x1 + (b.x1 - a.x1) * e, d: a.d + (b.d - a.d) * e }; });
      draw();
      if (k < 1) requestAnimationFrame(frame); else { nodes.forEach(n => n._cur = { ...n._tar }); draw(); }
    })(t0);
  }
  target(root); nodes.forEach(n => n._cur = { ...n._tar }); draw();
  svg.addEventListener("click", ev => {
    if (ev.target.closest("[data-center]")) { if (focus.parent) animateTo(focus.parent); return; }
    const seg = ev.target.closest("[data-i]"); if (!seg) return;
    const n = nodes[+seg.dataset.i]; if (n.children && n.children.length) animateTo(n);
  });
  svg.addEventListener("mousemove", ev => {
    const seg = ev.target.closest("[data-i]"); if (!seg) { tip.hidden = true; return; }
    const n = nodes[+seg.dataset.i], pct = root.bytes ? n.bytes / root.bytes * 100 : 0;
    const path = []; for (let p = n; p && p.parent; p = p.parent) path.unshift(p.name);
    tip.hidden = false; tip.innerHTML = `<div class="t">${esc(n.name)}</div><div class="p">${esc(path.slice(0, -1).join(" › "))}</div><div>${bytes(n.bytes || 0)} · ${pct < 0.1 ? "<0.1" : pct.toFixed(1)}% of all traffic</div>`;
    const r = host.getBoundingClientRect();
    tip.style.left = (ev.clientX - r.left) + "px"; tip.style.top = (ev.clientY - r.top) + "px";
  });
  svg.addEventListener("mouseleave", () => tip.hidden = true);
}

VIEWS.traffic = main => {
  main.innerHTML = `<div class="head"><h1>Traffic</h1><p>The link, partitioned into classes and the apps inside them — like a traffic shaper's tree</p><div class="grow"></div><span class="right" style="margin-right:12px">${legendDU}</span><span id="seg"></span></div>
    <div class="traffic-grid">
      <section class="panel sun-panel"><div class="ph"><h2>Traffic map</h2><span class="sub" id="sunsub">Click a wedge to zoom in · click the centre to step back</span><span class="right" id="scaleseg"></span></div><div id="sun"></div><div class="sun-legend" id="sunleg"></div></section>
      <section class="panel"><div class="ph"><h2>Partition</h2><span class="sub">super-class → class → app</span></div><div class="tree" id="tree"></div></section>
    </div>`;
  const byBytes = (a, b) => (b.down + b.up) - (a.down + a.up);
  const load = async (range, withSun = true) => {
    const apps = (await api(`api/apps?range=${range}`)).apps || [];
    if (withSun) {
      try {
        const h = layoutPartition(trafficHierarchy(apps, scaleSeg.value));
        $("#sunsub").textContent = scaleSeg.value === "Balanced" ? "Sized by √bytes so small classes stay visible · click to zoom" : "Sized by bytes · click a wedge to zoom, the centre to step back";
        sunburst($("#sun"), h);
        $("#sunleg").innerHTML = h.children.map(s => { const pc = h.bytes ? s.bytes / h.bytes * 100 : 0; return `<span><i style="background:${s.color}"></i>${esc(s.name)} <b>${pc < 0.1 ? "<0.1" : pc.toFixed(pc < 10 ? 1 : 0)}%</b></span>`; }).join("");
      } catch (e) { console.warn("sunburst", e); $("#sun").innerHTML = `<div class="empty">Map unavailable.</div>`; }
    }
    const classMap = new Map();
    for (const a of apps) {
      const c = classOf(a.name);
      const g = classMap.get(c) || { name: c, down: 0, up: 0, color: CLASS_COLOR[c] || CLASS_OTHER[1], kind: "class", children: [] };
      g.down += a.down; g.up += a.up;
      g.children.push({ name: a.name, down: a.down, up: a.up, kind: "app", meta: `${a.devices} device${a.devices === 1 ? "" : "s"}` });
      classMap.set(c, g);
    }
    const superMap = new Map();
    for (const cls of classMap.values()) {
      const s = SUPER_OF[cls.name] || "Other traffic";
      const g = superMap.get(s) || { name: s, down: 0, up: 0, color: SUPER_COLOR[s], kind: "super", children: [] };
      g.down += cls.down; g.up += cls.up; g.children.push(cls); superMap.set(s, g);
    }
    const roots = [...superMap.values()].sort(byBytes);
    for (const s of roots) { s.children.sort(byBytes); for (const c of s.children) c.children.sort(byBytes); }
    const gmax = Math.max(...roots.map(n => n.down + n.up), 1);
    const total = roots.reduce((s, n) => s + n.down + n.up, 0) || 1;
    const node = (n, level) => {
      const has = n.children && n.children.length;
      const pct = (n.down + n.up) / total * 100;
      const meta = n.kind === "super" ? `${n.children.length} class${n.children.length === 1 ? "" : "es"}`
        : n.kind === "class" ? `${n.children.length} app${n.children.length === 1 ? "" : "s"}` : (n.meta || "");
      return `<div class="tnode lvl${level}">
        <div class="trow${has ? " has" : ""}"${has ? ` role="button" tabindex="0" aria-expanded="true"` : ""}>
          <span class="tw">${has ? "▾" : "<span class='leafdot'></span>"}</span>
          <span class="cdot" style="background:${n.color || CLASS_OTHER[1]}"></span>
          <div class="who"><b>${esc(n.name)}</b>${meta ? `<span class="meta">${meta} · ${pct.toFixed(pct < 10 ? 1 : 0)}%</span>` : ""}</div>
          <div class="vals">${bytes(n.down)} · ${bytes(n.up)}</div>
          <div class="track" aria-hidden="true"><i class="d" style="width:${(n.down / gmax * 100).toFixed(1)}%"></i><i class="u" style="width:${(n.up / gmax * 100).toFixed(1)}%"></i></div>
        </div>
        ${has ? `<div class="tchildren">${n.children.map(c => node(c, level + 1)).join("")}</div>` : ""}
      </div>`;
    };
    $("#tree").innerHTML = roots.map(n => node(n, 0)).join("") || `<div class="empty">No traffic recorded in this period yet. Data arrives every 15 seconds.</div>`;
    $("#tree").querySelectorAll(".trow.has").forEach(row => {
      const toggle = () => {
        const kids = row.nextElementSibling, open = !kids.hidden;
        kids.hidden = open; row.setAttribute("aria-expanded", String(!open));
        row.querySelector(".tw").textContent = open ? "▸" : "▾";
      };
      row.onclick = toggle;
      row.onkeydown = e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } };
    });
  };
  const scaleSeg = rangeSeg("traffic-scale", ["Balanced", "Bytes"], "Balanced", v => { scaleSeg.value = v; load(seg.value, true); }, "Map scale");
  $("#scaleseg", main).replaceWith(scaleSeg.node);
  const seg = rangeSeg("traffic", ["1h", "24h", "7d", "30d"], "24h", r => { seg.value = r; load(r, true); });
  $("#seg", main).replaceWith(seg.node);
  load(seg.value, true);
  const t = setInterval(() => load(seg.value, false), 60000);   // refresh the tree; keep the map's zoom
  return () => clearInterval(t);
};

/* ---------------------------------------------------------------- topology
   Live map: the internet, the uplink, the router, the zones it serves, and every device on its real link.
   Flow dots run along each link at a speed set by its live rate: cobalt = download, copper = upload.
   Zones come from NOW.site.zones. A device row with hosted_on (the name of another device) is drawn
   under that device instead of on a link of its own. */
const TOPO = {
  hubs: { wired: "Wired ports", w5: "Wi-Fi 5 GHz", w6: "Wi-Fi 6 GHz", w2: "Wi-Fi 2.4 GHz", off: "Not connected now" },
  hubOrder: ["wired", "w5", "w6", "w2", "off"],
  generic: new Set(["connection", "localhost", "unknown", ""]),
};
const TICON = {
  globe: `<circle cx="8" cy="8" r="6.5"/><path d="M1.5 8h13M8 1.5c2 2 2 11 0 13M8 1.5c-2 2-2 11 0 13"/>`,
  modem: `<rect x="1.5" y="6" width="13" height="7" rx="1.5"/><path d="M4 9.5h.01M6.5 9.5h.01M9 9.5h3M5 6l1-3.5M11 6l-1-3.5"/>`,
  router: `<rect x="1.5" y="8.5" width="13" height="5" rx="1.2"/><path d="M4 11h.01M6.5 11h.01M5 8.5l-1-4M11 8.5l1-4M8 8.5V3.5"/>`,
  wired: `<path d="M5 1.5v4M11 1.5v4M3.5 5.5h9v3a4.5 4.5 0 0 1-9 0zM8 13v1.5"/>`,
  wifi: `<path d="M1.8 6.2a9 9 0 0 1 12.4 0M4.1 8.7a5.6 5.6 0 0 1 7.8 0M6.4 11.2a2.3 2.3 0 0 1 3.2 0"/><circle cx="8" cy="13.4" r=".6"/>`,
  off: `<circle cx="8" cy="8" r="6"/><path d="M3.8 3.8l8.4 8.4"/>`,
  laptop: `<rect x="3" y="3.5" width="10" height="7" rx="1"/><path d="M1.5 12.5h13"/>`,
  phone: `<rect x="4.5" y="1.5" width="7" height="13" rx="1.6"/><path d="M7.2 12.4h1.6"/>`,
  tv: `<rect x="1.5" y="3" width="13" height="8.5" rx="1.2"/><path d="M5.5 14h5"/>`,
  camera: `<circle cx="8" cy="7" r="4.6"/><circle cx="8" cy="7" r="1.7"/><path d="M5 14.5h6M8 11.6v2.9"/>`,
  switch: `<rect x="1.5" y="5" width="13" height="6" rx="1"/><path d="M4 8h.01M6.5 8h.01M9 8h.01M11.5 8h.01"/>`,
  shield: `<path d="M8 1.5l5.5 2v4c0 3.5-2.5 6-5.5 7-3-1-5.5-3.5-5.5-7v-4z"/><path d="M5.5 8l2 2 3-3.5"/>`,
  device: `<rect x="3" y="3" width="10" height="10" rx="2.2"/><path d="M6 8h4"/>`,
};
function topoKind(d) {
  const s = `${d.name} ${d.vendor || ""} ${d.hostname || ""}`.toLowerCase();
  if (s.includes(String(filterName()).toLowerCase())) return "shield";
  if (/iphone|android|pixel|galaxy|samsung|\bs2[0-9]\b/.test(s)) return "phone";
  if (/c200|camera|tapo|\bcam\b|doorbell/.test(s)) return "camera";
  if (/amazon|fire ?tv|fire ?stick|roku|chromecast|apple tv/.test(s)) return "tv";
  if (/netgear|switch|ubiquiti/.test(s)) return "switch";
  if (/mac|book|imac|\bm[1-4]\b/.test(s)) return "laptop";
  return "device";
}
const TKIND_WORD = { tv: "TV streamer", camera: "camera", switch: "switch", phone: "phone", laptop: "computer", shield: "DNS filter", device: "device" };
function topoName(d) {
  if (!TOPO.generic.has(String(d.name || "").trim().toLowerCase())) return d.name;
  const v = String(d.vendor || "").replace(/\b(Technologies|Limited|Ltd|Inc|Group|Systems|Co\.?)\b.*$/i, "").trim();
  return `${v || "Unnamed"} ${TKIND_WORD[topoKind(d)]}`;
}
const topoZone = (d, l) => zoneKeyOf(d, l);
/* The router's own row in the device list is the router node, not a device. */
const isRouterRow = d => { const s = site().router; return (s.ip && d.ip === s.ip) || (s.name && String(d.name || "").toLowerCase() === String(s.name).toLowerCase()); };
function topoHub(l) {
  if (!l) return "off";
  if (l.kind === "wired") return l.port ? "port:" + l.port : "wired";
  const b = String(l.band || "");
  return b.startsWith("5") ? "w5" : b.startsWith("6") ? "w6" : "w2";
}
const hubRank = k => k.startsWith("port:") ? parseInt(k.replace(/\D/g, "") || "0", 10) / 100 : TOPO.hubOrder.indexOf(k);
const mbit = v => v == null ? "?" : v >= 1000 ? `${v / 1000} Gbit/s` : `${v} Mbit/s`;
const sigClass = dbm => dbm == null ? "" : dbm >= -67 ? "ok" : dbm >= -74 ? "warn" : "crit";
const flowSpeed = bps => bps > 0 ? 16 + 24 * Math.log10(1 + bps / 2000) : 0;

/* Turn devices into a laid-out graph. Coordinates are world units; the SVG viewBox scales them. */
function topoGraph(devs, now, ports = []) {
  const X = { inet: 92, uplink: 342, rtr: 592, hub: 840, dev: 1110 };
  const W = { core: 204, hub: 150, dev: 236 };
  const nodes = [], edges = [], byId = {};
  const add = n => (nodes.push(n), byId[n.id] = n, n);
  const f = vitalsOf(now), lat = (now && now.latency) || {}, s = site();
  const ms = t => lat[t] && lat[t].med != null ? `${Math.round(lat[t].med)} ms` : "";
  // the first latency target that is neither the router nor the uplink stands for the internet
  const inetT = Object.keys(lat).find(k => k !== s.router.name && k !== s.uplink.name);
  add({ id: "inet", type: "core", icon: "globe", x: X.inet, w: W.core, name: "Internet",
        sub: inetT && ms(inetT) ? `${inetT} ping ${ms(inetT)}` : `via ${s.isp.name}`, lat: inetT ? lat[inetT] : null });
  add({ id: "uplink", type: "core", icon: "modem", x: X.uplink, w: W.core, name: cap(s.uplink.name),
        sub: [s.uplink.kind || s.isp.name, ms(s.uplink.name)].filter(Boolean).join(" · "), lat: lat[s.uplink.name] });
  add({ id: "rtr", type: "core", icon: "router", x: X.rtr, w: W.core, name: [cap(s.router.name), s.router.model].filter(Boolean).join(" "),
        sub: f ? `CPU ${Math.round(f.cpu_pct || 0)}% · ${(f.temp_mc / 1000).toFixed(0)} °C` : "waiting for vitals",
        lat: lat[s.router.name], vit: f });
  edges.push({ id: "e-inet-uplink", from: "inet", to: "uplink", kind: "wan", label: "ISP" });
  edges.push({ id: "e-uplink-rtr", from: "uplink", to: "rtr", kind: "wan", label: "WAN" });

  const portOf = Object.fromEntries(ports.map(p => [p.name, p]));
  // a switch seen on a router port becomes that port's hub node, not a device
  const switchOn = {};
  for (const d of devs) if (d.link && d.link.port && d.link.port_shared && topoKind(d) === "switch") switchOn[d.link.port] = d;
  const switchMacs = new Set(Object.values(switchOn).map(d => d.mac));
  const rows = mergeDevices(devs.filter(d => !isRouterRow(d) && !switchMacs.has(d.mac)));
  const zones = s.zones.map(z => ({ ...z, sub: z.sub || z.cidr || "", devs: [], hubs: [] }));
  const zoneOf = k => zones.find(z => z.key === k);
  for (const d of rows) {
    const links = d.links && d.links.length ? d.links : [null];
    const carry = d.carry ?? 0;
    const lz = topoZone(d, links[carry]);
    const hostOn = d.hosted_on && rows.some(r => r.name === d.hosted_on) ? { host: d.hosted_on, what: `runs on ${d.hosted_on}` } : null;
    const n = { id: "d:" + d.mac, type: "dev", icon: topoKind(d), x: X.dev, w: W.dev, name: topoName(d), row: d, zone: lz,
                links, carry, hosted: hostOn,
                stale: !d.links?.length && now && now.now - d.last_seen > 900 };
    n.hubKeys = n.hosted ? [] : links.map(topoHub);
    n.order = n.hosted ? 99 : n.hubKeys.reduce((a, k) => a + hubRank(k), 0) / n.hubKeys.length;
    (zoneOf(lz) || zones[0]).devs.push(n);
  }
  // order devices: by hub (dual-homed land between their two hubs), then busiest first; hosted ones follow their host
  let y = 0;
  const SLOT = 60, HEAD = 46, GAP = 40;
  for (const z of zones) {
    if (!z.devs.length) continue;
    const hosted = z.devs.filter(n => n.hosted);
    const main = z.devs.filter(n => !n.hosted).sort((a, b) => a.order - b.order || (b.row.down + b.row.up) - (a.row.down + a.row.up));
    for (const h of hosted) {
      const hostIx = main.findIndex(n => n.row.name === h.hosted.host);
      main.splice(hostIx >= 0 ? hostIx + 1 : main.length, 0, h);
    }
    z.top = y; y += HEAD;
    for (const n of main) { n.y = y + SLOT / 2; y += n.hosted ? SLOT - 6 : SLOT; add(n); }
    z.bottom = y + 8;
    // hubs sit at the mean height of their devices, kept apart and inside the zone
    const keys = [...new Set(main.flatMap(n => n.hubKeys))].sort((a, b) => hubRank(a) - hubRank(b));
    let last = z.top + HEAD - 10;
    for (const k of keys) {
      const ys = main.filter(n => n.hubKeys.includes(k)).map(n => n.y);
      let hy = ys.reduce((a, b) => a + b, 0) / ys.length;
      hy = Math.max(hy, last + 66);
      last = hy;
      const pn = k.startsWith("port:") ? k.slice(5) : null, port = pn && portOf[pn], sw = pn && switchOn[pn];
      const hub = add({ id: `h:${z.key}:${k}`, type: "hub", icon: sw ? "switch" : pn || k === "wired" ? "wired" : k === "off" ? "off" : "wifi",
                        x: X.hub, y: hy, w: W.hub, name: sw ? topoName(sw) : pn ? `Port ${pn}` : TOPO.hubs[k], zone: z.key, key: k,
                        port, sw, degraded: !!(port && port.degraded) });
      z.hubs.push(hub);
      edges.push({ id: `e-rtr-${hub.id}`, from: "rtr", to: hub.id, kind: k === "off" ? "off" : "trunk", port,
                   degraded: hub.degraded, label: port ? `${pn} · ${mbit(port.speed)}` : "" });
    }
    z.bottom = Math.max(z.bottom, last + 30);
    y = z.bottom + GAP;
    for (const n of main) {
      if (n.hosted) {
        const host = main.find(m => m.row.name === n.hosted.host);
        if (host) edges.push({ id: `e-host-${n.id}`, from: host.id, to: n.id, kind: "hosted", label: n.hosted.what });
        continue;
      }
      n.links.forEach((l, i) => edges.push({
        id: `e-${n.id}-${i}`, from: `h:${z.key}:${n.hubKeys[i]}`, to: n.id, link: l, mac: l ? l._mac : n.row.mac,
        kind: !l ? "off" : l.kind === "wired" ? (isMultigig(l) ? "ug" : "wired") : "wifi",
        standby: n.links.length > 1 && i !== n.carry, sig: l && sigClass(l.signal),
      }));
    }
  }
  const hubs = nodes.filter(n => n.type === "hub");
  const mid = hubs.length ? (Math.min(...hubs.map(h => h.y)) + Math.max(...hubs.map(h => h.y))) / 2 : 60;
  byId.inet.y = byId.uplink.y = byId.rtr.y = mid;
  return { nodes, edges, byId, zones: zones.filter(z => z.devs.length), X, W, height: Math.max(y - GAP, mid + 60), hadNow: !!vitalsOf(now) };
}

function edgePath(a, b, e) {
  if (e.kind === "hosted") {        // short bracket down the left of the device column
    const x = a.x - a.w / 2 + 14, y1 = a.y + 19, y2 = b.y;
    return `M${x} ${y1} L${x} ${y2 - 8} Q${x} ${y2} ${x + 8} ${y2} L${b.x - b.w / 2} ${y2}`;
  }
  const x1 = a.x + a.w / 2, x2 = b.x - b.w / 2, y1 = a.y, y2 = b.y, m = (x1 + x2) / 2;
  return `M${x1} ${y1} C${m} ${y1}, ${m} ${y2}, ${x2} ${y2}`;
}

VIEWS.topology = main => {
  main.innerHTML = `<div class="head"><h1>Topology</h1><p>Every device on its real link, live. Dots flow at the speed of the traffic.</p><div class="grow"></div>
      <span class="legend"><span><i class="swatch sw-down"></i>Download</span><span><i class="swatch sw-up"></i>Upload</span></span></div>
    <div class="topo-stats" id="tstats"></div>
    <section class="panel topo-panel">
      <div class="topo-tools">
        <span class="topo-hint">Thumb wheel, pinch or double-click to zoom · 🔍 button: click to zoom · drag to move · zoom in for more detail</span>
      </div>
      <div class="topo-host" id="thost"><svg class="topo" id="tsvg" role="img" aria-label="Network topology"></svg><div class="tip topo-tip" hidden></div></div>
      <div class="topo-legend">
        <span><i class="lk ug"></i>Multi-gig</span><span><i class="lk wired"></i>Wired</span>
        <span><i class="lk wifi ok"></i>Wi-Fi, strong</span><span><i class="lk wifi warn"></i>Wi-Fi, fair</span><span><i class="lk wifi crit"></i>Wi-Fi, weak</span>
        <span><i class="lk stby"></i>Standby link</span><span><i class="lk fence"></i>Fenced zone</span>
      </div>
    </section>
    <section class="panel topo-card" id="tcard" hidden></section>`;
  const svg = $("#tsvg", main), host = $("#thost", main), tip = $(".topo-tip", main), card = $("#tcard", main);
  let G = null, view = { k: 1, x: 0, y: 0 }, base = null, sel = null, flows = [], raf = 0, devs = [], ports = [];

  /* ---------- zoom and pan ---------- */
  const vp = () => svg.querySelector(".vp");
  const apply = () => {
    const g = vp(); if (!g) return;
    g.setAttribute("transform", `translate(${view.x} ${view.y}) scale(${view.k})`);
    svg.classList.toggle("lod2", view.k >= 1.5);
    svg.classList.toggle("lod0", view.k < .8);
  };
  let tw = 0;
  const tween = to => {
    cancelAnimationFrame(tw);
    const from = { ...view }, t0 = performance.now(), D = 420;
    const step = t => {
      const p = Math.min(1, (t - t0) / D), e = 1 - Math.pow(1 - p, 3);
      view = { k: from.k + (to.k - from.k) * e, x: from.x + (to.x - from.x) * e, y: from.y + (to.y - from.y) * e };
      apply();
      if (p < 1) tw = requestAnimationFrame(step);
    };
    tw = requestAnimationFrame(step);
  };
  const toWorld = (cx, cy) => {         // client pixels -> viewBox units
    const pt = svg.createSVGPoint(); pt.x = cx; pt.y = cy;
    return pt.matrixTransform(svg.getScreenCTM().inverse());
  };
  const zoomAt = (k, wx, wy, animate) => {
    k = Math.max(.5, Math.min(4, k));
    const to = { k, x: wx - (wx - view.x) * (k / view.k), y: wy - (wy - view.y) * (k / view.k) };
    animate ? tween(to) : (view = to, apply());
  };
  const centre = () => base ? [base.x + base.w / 2, base.y + base.h / 2] : [0, 0];
  zoomCtl(host, { zin: () => zoomAt(view.k * 1.4, ...centre(), true), zout: () => zoomAt(view.k / 1.4, ...centre(), true), fit: () => tween({ k: 1, x: 0, y: 0 }),
    at: (e, f) => { const p = toWorld(e.clientX, e.clientY); zoomAt(view.k * f, p.x, p.y, true); } });
  svg.addEventListener("wheel", ev => {
    if (!isZoomWheel(ev) && view.k === 1) return;       // plain scroll moves the page until you have zoomed
    ev.preventDefault();
    if (isZoomWheel(ev)) {
      const p = toWorld(ev.clientX, ev.clientY);
      zoomAt(view.k * wheelFactor(ev), p.x, p.y);
    } else {
      const s = svg.getScreenCTM().a; view.x -= ev.deltaX / s; view.y -= ev.deltaY / s; apply();
    }
  }, { passive: false });
  svg.addEventListener("dblclick", ev => { const p = toWorld(ev.clientX, ev.clientY); zoomAt(view.k * 1.8, p.x, p.y, true); });
  let drag = null;
  svg.addEventListener("pointerdown", ev => {
    if (ev.button !== 0) return;
    drag = { x: ev.clientX, y: ev.clientY, vx: view.x, vy: view.y, moved: false };
  });
  const onMove = ev => {
    if (!drag) return;
    const s = svg.getScreenCTM().a, dx = (ev.clientX - drag.x) / s, dy = (ev.clientY - drag.y) / s;
    if (!drag.moved && Math.hypot(dx, dy) * s < 4) return;
    if (!drag.moved) { drag.moved = true; svg.classList.add("grabbing"); try { svg.setPointerCapture(ev.pointerId); } catch { /* ignore */ } }
    view.x = drag.vx + dx; view.y = drag.vy + dy; apply();
  };
  addEventListener("pointermove", onMove);
  const endDrag = () => { if (drag && drag.moved) setTimeout(() => drag = null, 0); else drag = null; svg.classList.remove("grabbing"); };
  addEventListener("pointerup", endDrag);

  /* ---------- live rates ---------- */
  const rateOf = mac => {
    const d = NOW && NOW.devices && NOW.devices.find(x => x.mac === mac);
    return d ? { down: d.down * 8 / 300, up: d.up * 8 / 300 } : { down: 0, up: 0 };
  };
  function computeRates() {
    if (!G) return;
    const f = vitalsOf(NOW);
    const r = {};
    for (const e of G.edges) {
      if (e.kind === "wan") r[e.id] = { down: f ? f.down_bps : 0, up: f ? f.up_bps : 0 };
      else if (e.to.startsWith("d:") && e.kind !== "hosted") r[e.id] = e.standby ? rateOf(e.mac) : rateOf(e.mac);
      else if (e.kind === "hosted") r[e.id] = rateOf(G.byId[e.to].row.mac);
    }
    for (const e of G.edges) if (e.kind === "trunk" || e.kind === "off") {
      const hub = e.to;
      r[e.id] = G.edges.filter(x => x.from === hub).reduce((a, x) => ({ down: a.down + r[x.id].down, up: a.up + r[x.id].up }), { down: 0, up: 0 });
    }
    for (const fl of flows) fl.rate = r[fl.e.id] || { down: 0, up: 0 };
    // live rate text on nodes
    for (const n of G.nodes) {
      const t = svg.querySelector(`[data-id="${CSS.escape(n.id)}"] .rate`);
      if (!t) continue;
      let rr;
      if (n.type === "dev") rr = G.edges.filter(e => e.to === n.id).reduce((a, e) => ({ down: a.down + (r[e.id]?.down || 0), up: a.up + (r[e.id]?.up || 0) }), { down: 0, up: 0 });
      else if (n.type === "hub") rr = r[`e-rtr-${n.id}`];
      else rr = r["e-uplink-rtr"];
      n.rate = rr;
      t.textContent = rr && (rr.down + rr.up) > 0 ? `↓ ${bitsText(rr.down)} · ↑ ${bitsText(rr.up)}` : "idle";
      t.classList.toggle("idle", !rr || rr.down + rr.up === 0);
    }
  }
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  let tPrev = 0;
  const animate = t => {
    const dt = tPrev ? Math.min(.1, (t - tPrev) / 1000) : 0; tPrev = t;
    for (const fl of flows) {
      const sd = flowSpeed(fl.rate?.down), su = flowSpeed(fl.rate?.up);
      fl.od -= sd * dt; fl.ou += su * dt;
      fl.d.style.strokeDashoffset = fl.od; fl.u.style.strokeDashoffset = fl.ou;
      fl.d.style.opacity = sd ? 1 : 0; fl.u.style.opacity = su ? 1 : 0;
    }
    raf = requestAnimationFrame(animate);
  };

  /* ---------- drawing ---------- */
  function nodeSVG(n) {
    const h = n.type === "core" ? 58 : n.type === "hub" ? 36 : n.hosted ? 40 : 48;
    const x = n.x - n.w / 2, y = n.y - h / 2;
    n.h = h;
    const l = n.links && n.links[n.carry];
    let badge = "";
    if (n.type === "dev" && n.links.length > 1) badge = `<g class="badge2" transform="translate(${n.w - 108} -10)"><rect width="96" height="20" rx="10"/><text x="48" y="14.5">dual-homed</text></g>`;
    else if (n.type === "dev" && isMultigig(l)) badge = `<g class="badgeug" transform="translate(${n.w - 108} -10)"><rect width="96" height="20" rx="10"/><text x="48" y="14.5">⚡ multi-gig</text></g>`;
    let sub = n.sub || "";
    if (n.type === "dev") {
      const r = n.row;
      sub = n.hosted ? n.hosted.what : [r.ips?.[n.carry] || r.ip, l ? (l.kind === "wired" ? (isMultigig(l) ? "multi-gig" : "wired") : `${l.signal} dBm`) : "offline"].filter(Boolean).join(" · ");
    }
    if (n.type === "hub") {
      const count = G.edges.filter(e => e.from === n.id).length;
      sub = n.sw ? `on ${n.port.name} · ${count} ${count === 1 ? "device" : "devices"}` : `${count} ${count === 1 ? "link" : "links"}`;
    }
    const detail = n.type === "dev" ? [
      n.row.macs?.length > 1 ? n.row.macs.join("  ") : n.row.mac,
      l && l.kind === "wifi" ? `${l.rate_mbps || "?"} Mbit/s PHY · SNR ${l.snr ?? "?"} dB` : l && l.speed ? l.speed : "",
      n.row.top_app ? `Top app: ${n.row.top_app}` : "",
    ].filter(Boolean) : n.type === "core" && n.vit ? [
      `${(n.vit.conntrack || [0])[0]} connections · ${n.vit.wifi_clients} Wi-Fi clients`,
      `Load ${n.vit.load?.[0]} · ${Math.round(n.vit.mem_avail_kb / 1024)} MB free`,
    ] : [];
    const sig = n.type === "dev" && l && l.kind === "wifi" ? `<g transform="translate(${n.w - 24} ${h - 18})" class="tsig ${sigClass(l.signal)}">${[1, 2, 3, 4].map(i =>
      `<rect x="${(i - 1) * 4}" y="${12 - i * 3}" width="2.6" height="${i * 3}" rx=".8" class="${i <= (l.signal >= -55 ? 4 : l.signal >= -65 ? 3 : l.signal >= -72 ? 2 : 1) ? "on" : ""}"/>`).join("")}</g>` : "";
    return `<g class="node n-${n.type}${n.stale ? " stale" : ""}${n.hosted ? " hosted" : ""}${n.degraded ? " degraded" : ""}" data-id="${esc(n.id)}" transform="translate(${x} ${y})" tabindex="0" role="button" aria-label="${esc(n.name)}">
      <rect class="card" width="${n.w}" height="${h}" rx="${n.type === "hub" ? 18 : 11}"/>
      ${n.type === "core" ? `<circle class="halo" cx="${n.w / 2}" cy="${h / 2}" r="${n.w / 2}"/>` : ""}
      <g class="ico" transform="translate(${n.type === "hub" ? 12 : 12} ${h / 2 - 9}) scale(1.15)">${TICON[n.icon] || TICON.device}</g>
      <text class="nm" x="${n.type === "hub" ? 36 : 38}" y="${n.type === "hub" ? h / 2 - 1 : n.type === "core" ? 20 : h / 2 - 3}">${esc(n.name)}</text>
      <text class="sb" x="${n.type === "hub" ? 36 : 38}" y="${n.type === "hub" ? h / 2 + 11 : n.type === "core" ? 34 : h / 2 + 10}">${esc(sub)}</text>
      ${n.type !== "hub" || true ? `<text class="rate" x="${n.type === "hub" ? n.w / 2 : n.type === "core" ? 14 : 38}" y="${n.type === "core" ? 48 : n.type === "hub" ? h + 13 : h / 2 + 22}" ${n.type === "hub" ? `text-anchor="middle"` : ""}></text>` : ""}
      ${badge}${sig}
      ${detail.map((t, i) => `<text class="lod" x="${n.w + 10}" y="${h / 2 - (detail.length - 1) * 6 + i * 12 + 3}">${esc(t)}</text>`).join("")}
    </g>`;
  }
  function draw() {
    const pad = 24;
    const x0 = 0, x1 = G.X.dev + G.W.dev / 2 + 30, H = G.height;
    base = { x: x0 - pad, y: -pad, w: x1 - x0 + pad * 2, h: H + pad * 2 };
    svg.setAttribute("viewBox", `${base.x} ${base.y} ${base.w} ${base.h}`);
    svg.style.minWidth = Math.round(base.w * 0.9) + "px";      // at least 90% of full size, so labels stay readable
    svg.style.minHeight = Math.round(base.h * 0.9) + "px";
    const zx0 = G.X.hub - G.W.hub / 2 - 22, zx1 = G.X.dev + G.W.dev / 2 + 22;
    const zones = G.zones.map(z => `<g class="zone${z.fenced ? " fenced" : ""}">
      <rect x="${zx0}" y="${z.top}" width="${zx1 - zx0}" height="${z.bottom - z.top}" rx="16"/>
      ${z.fenced ? `<g class="lock" transform="translate(${zx0 + 14} ${z.top + 11})"><rect x="2" y="7" width="11" height="8" rx="2"/><path d="M4.5 7V5a3 3 0 0 1 6 0v2"/></g>` : ""}
      <text class="zn" x="${zx0 + (z.fenced ? 36 : 16)}" y="${z.top + 22}">${esc(z.name)}</text>
      <text class="zs" x="${zx0 + (z.fenced ? 36 : 16)}" y="${z.top + 36}">${esc(z.sub)}</text></g>`).join("");
    const edgeEls = G.edges.map(e => {
      const a = G.byId[e.from], b = G.byId[e.to];
      const d = edgePath(a, b, e);
      e.d = d;
      const cls = `edge k-${e.kind}${e.sig ? " s-" + e.sig : ""}${e.standby ? " standby" : ""}${e.degraded ? " degraded" : ""}`;
      const flowOK = !e.standby || true;
      let label = "";
      if (e.standby) {
        const mx = (a.x + a.w / 2 + b.x - b.w / 2) / 2, my = (a.y + b.y) / 2;
        label = `<text class="elabel" x="${mx}" y="${my - 5}" text-anchor="middle">standby</text>`;
      } else if (e.kind === "trunk" && e.label) {
        const x2 = b.x - b.w / 2;
        label = `<text class="elabel${e.degraded ? " bad" : ""}" x="${x2 - 8}" y="${b.y - 8}" text-anchor="end">${esc(e.label)}${e.degraded ? ` ⚠ should be ${mbit(e.port.best)}` : ""}</text>`;
      } else if (e.kind === "wan") {
        const mx = (a.x + a.w / 2 + b.x - b.w / 2) / 2;
        label = `<text class="elabel" x="${mx}" y="${a.y - 9}" text-anchor="middle">${esc(e.label)}</text>`;
      }
      return `<g class="${cls}" data-edge="${esc(e.id)}" data-from="${esc(e.from)}" data-to="${esc(e.to)}">
        <path class="wire" d="${d}"/>${flowOK ? `<path class="fd" d="${d}"/><path class="fu" d="${d}"/>` : ""}${label}</g>`;
    }).join("");
    const nodes = G.nodes.map(nodeSVG).join("");
    svg.innerHTML = `<defs>
        <filter id="tshadow" x="-20%" y="-30%" width="140%" height="170%"><feDropShadow dx="0" dy="1" stdDeviation="1.6" flood-opacity=".14"/></filter>
        <radialGradient id="thalo"><stop offset="0" stop-color="var(--down)" stop-opacity=".16"/><stop offset="1" stop-color="var(--down)" stop-opacity="0"/></radialGradient>
      </defs>
      <g class="vp">${zones}<g class="edges">${edgeEls}</g>
        <g class="nodes">${nodes}</g></g>`;
    flows = [...svg.querySelectorAll(".edge")].map(g => {
      const e = G.edges.find(x => x.id === g.dataset.edge);
      return { e, d: g.querySelector(".fd"), u: g.querySelector(".fu"), od: 0, ou: 7, rate: null };
    }).filter(fl => fl.d);
    apply();
    computeRates();
    bindNodes();
    if (sel && G.byId[sel]) focus(sel, true); else { sel = null; card.hidden = true; }
  }

  /* ---------- focus: trace a node's path to the Internet ---------- */
  function related(id) {
    const ns = new Set([id]), es = new Set();
    let front = [id];
    while (front.length) {                      // upstream
      const nx = [];
      for (const cur of front) for (const e of G.edges) if (e.to === cur && !ns.has(e.from)) { ns.add(e.from); es.add(e.id); nx.push(e.from); }
      for (const cur of front) for (const e of G.edges) if (e.to === cur) es.add(e.id);
      front = nx;
    }
    front = [id];
    while (front.length) {                      // downstream
      const nx = [];
      for (const cur of front) for (const e of G.edges) if (e.from === cur) { es.add(e.id); if (!ns.has(e.to)) { ns.add(e.to); nx.push(e.to); } }
      front = nx;
    }
    return { ns, es };
  }
  function focus(id, on) {
    svg.classList.toggle("focusing", !!on);
    svg.querySelectorAll(".node.on,.edge.on").forEach(x => x.classList.remove("on"));
    if (!on) return;
    const { ns, es } = related(id);
    ns.forEach(n => svg.querySelector(`.node[data-id="${CSS.escape(n)}"]`)?.classList.add("on"));
    es.forEach(e => svg.querySelector(`.edge[data-edge="${CSS.escape(e)}"]`)?.classList.add("on"));
  }
  function tipHTML(n) {
    if (n.type === "dev") {
      const r = n.row;
      const links = n.links.map((l, i) => !l ? `<div class="r">No live link<b>last seen ${esc(ago(r.last_seen))}</b></div>` :
        `<div class="r">${l.kind === "wired" ? (isMultigig(l) ? "⚡ Multi-gig" : "Wired") : `Wi-Fi ${esc(l.band || "")}`}${n.links.length > 1 ? (i === n.carry ? " · carrying" : " · standby") : ""}<b>${l.kind === "wifi" ? `${l.signal} dBm · ${l.rate_mbps} Mbit/s` : esc(l.speed || "")}</b></div>`).join("");
      return `<div class="t">${esc(r.vendor || "")}</div><div class="r"><strong>${esc(n.name)}</strong></div>${links}
        <div class="r">Last hour<b>${bytes(r.down)} ↓ · ${bytes(r.up)} ↑</b></div>${r.top_app ? `<div class="r">Top app<b>${esc(r.top_app)}</b></div>` : ""}
        <div class="t" style="margin-top:4px">Click to trace its path</div>`;
    }
    if (n.type === "hub") {
      const kids = G.edges.filter(e => e.from === n.id).map(e => G.byId[e.to].name);
      return `<div class="t">${esc(site().zones.find(z => z.key === n.zone)?.name || "")}</div><div class="r"><strong>${esc(n.name)}</strong></div>
        <div class="r">Links<b>${kids.length}</b></div>
        ${n.port ? `<div class="r">Router port<b>${esc(n.port.name)} · ${mbit(n.port.speed)}</b></div>
          <div class="r">Both ends can do<b>${mbit(n.port.best)}</b></div>
          <div class="r">Errors / drops<b>${(n.port.rx_errors || 0) + (n.port.tx_errors || 0)} / ${(n.port.rx_dropped || 0) + (n.port.tx_dropped || 0)}</b></div>
          ${n.degraded ? `<div class="r bad">Running below its best speed. Check the cable.</div>` : ""}` : ""}
        <div class="t" style="margin-top:3px;white-space:normal;max-width:240px">${esc(kids.join(", "))}</div>`;
    }
    const L = n.lat;
    return `<div class="r"><strong>${esc(n.name)}</strong></div><div class="r">${esc(n.sub)}</div>
      ${L ? `<div class="r">Ping from the collector<b>${Math.round(L.med)} ms · ${Math.round(L.loss)}% lost</b></div>` : ""}
      ${n.id === "rtr" && n.vit ? `<div class="r">Connections<b>${n.vit.conntrack[0]} of ${n.vit.conntrack[1]}</b></div><div class="r">Wi-Fi clients<b>${n.vit.wifi_clients}</b></div>` : ""}
      ${n.rate ? `<div class="r">Now<b>↓ ${bitsText(n.rate.down)} · ↑ ${bitsText(n.rate.up)}</b></div>` : ""}`;
  }
  function showCard(n) {
    if (!n || n.type !== "dev") { card.hidden = true; return; }
    const r = n.row;
    card.hidden = false;
    card.innerHTML = `<div class="ph"><h2>${esc(n.name)}</h2><span class="sub">${esc(r.vendor || "")}</span>
        <a class="right tlink" href="#/devices/${encodeURIComponent(r.mac)}">Open device ›</a></div>
      <div class="topo-card-grid">
        <div><div class="k">Link</div>${linkCellMulti(r)}</div>
        <div><div class="k">Address</div><div class="mono">${esc((r.ips || [r.ip]).join(", "))}</div><div class="mono muted">${esc((r.macs || [r.mac]).join(", "))}</div></div>
        <div><div class="k">Last hour</div><div>${bytes(r.down)} down · ${bytes(r.up)} up</div>${r.top_app ? `<div class="muted">Mostly ${esc(r.top_app)}</div>` : ""}</div>
        <div><div class="k">Path to the Internet</div><div>${esc(n.name)} → ${esc(G.byId[G.edges.find(e => e.to === n.id)?.from]?.name || "")} → ${esc(G.byId.rtr.name)} → ${esc(G.byId.uplink.name)} → Internet</div></div>
      </div>`;
  }
  function bindNodes() {
    svg.querySelectorAll(".node").forEach(g => {
      const n = G.byId[g.dataset.id];
      const place = ev => { tip.style.left = Math.min(Math.max(ev.clientX, 140), innerWidth - 140) + "px"; tip.style.top = ev.clientY + "px"; };
      g.onmouseenter = ev => { if (drag && drag.moved) return; if (!sel) focus(n.id, true); tip.innerHTML = tipHTML(n); place(ev); tip.hidden = false; };
      g.onmousemove = place;
      g.onmouseleave = () => { tip.hidden = true; if (!sel) focus(null, false); else focus(sel, true); };
      g.onclick = ev => {
        ev.stopPropagation();
        if (drag && drag.moved) return;
        tip.hidden = true;
        sel = sel === n.id ? null : n.id;
        focus(sel, !!sel); showCard(sel ? n : null);
      };
      g.onkeydown = ev => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); g.onclick(ev); } };
    });
  }
  svg.addEventListener("click", () => { if (drag && drag.moved) return; if (sel) { sel = null; focus(null, false); card.hidden = true; } });

  function stats() {
    const devNodes = G.nodes.filter(n => n.type === "dev");
    const online = devNodes.filter(n => n.links.some(Boolean)).length;
    const dual = devNodes.filter(n => n.links.length > 1);
    const ug = G.edges.filter(e => e.kind === "ug" && !e.standby).length;
    const wifi = G.edges.filter(e => e.kind === "wifi" && e.link);
    const weakest = wifi.length ? wifi.reduce((a, e) => e.link.signal < a.link.signal ? e : a) : null;
    const fenced = G.zones.filter(z => z.fenced);
    const tile = (k, v, s, cls = "") => `<div class="tstat ${cls}"><div class="k">${k}</div><div class="v">${v}</div><div class="s">${s}</div></div>`;
    $("#tstats", main).innerHTML =
      tile("Devices", `${online}<small> of ${devNodes.length}</small>`, "online now") +
      tile("Multi-gig", ug, dual.length ? `${dual.filter(n => isMultigig(n.links[n.carry])).length} of ${dual.length} dual-homed machines carrying on it` : "wired links faster than 1 Gbit/s", "ug") +
      tile("Wi-Fi clients", wifi.length, weakest ? `weakest ${esc(G.byId[weakest.to].name)}, ${weakest.link.signal} dBm` : "none", weakest ? sigClass(weakest.link.signal) : "") +
      tile("Fenced zones", fenced.reduce((s, z) => s + z.devs.length, 0), fenced.length ? `devices in ${fenced.map(z => esc(z.name)).join(", ")}` : "no fenced zone configured", "fence");
  }

  async function load() {
    try { const r = await api("api/devices?range=1h"); devs = r.devices; ports = r.ports || []; } catch { return; }
    G = topoGraph(devs, NOW, ports);
    draw(); stats();
  }
  const onLive = () => { if (!G) return; if (!G.hadNow && vitalsOf(NOW)) { G = topoGraph(devs, NOW, ports); draw(); stats(); } else computeRates(); };
  listeners.add(onLive);
  load();
  if (!reduced) raf = requestAnimationFrame(animate);
  const t = setInterval(load, 30000);
  return () => { clearInterval(t); cancelAnimationFrame(raf); cancelAnimationFrame(tw); listeners.delete(onLive); removeEventListener("pointerup", endDrag); removeEventListener("pointermove", onMove); };
};

/* ---------------------------------------------------------------- 3D helpers (canvas, no libraries) */
const clsObj = name => ({ name, color: CLASS_COLOR[name] || CLASS_OTHER[1] });
const cssVar = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
function hexRgb(h) {
  h = String(h).replace("#", "");
  if (h.length === 3) h = h.split("").map(c => c + c).join("");
  const n = parseInt(h, 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}
const rgba = (h, a) => { const [r, g, b] = hexRgb(h); return `rgba(${r},${g},${b},${a})`; };
const shade = (h, f) => { const [r, g, b] = hexRgb(h); const k = v => Math.max(0, Math.min(255, Math.round(f >= 1 ? v + (255 - v) * (f - 1) : v * f))); return `rgb(${k(r)},${k(g)},${k(b)})`; };
function fitCanvas(cv, w, h) {
  const d = window.devicePixelRatio || 1;
  cv.width = Math.round(w * d); cv.height = Math.round(h * d);
  cv.style.width = w + "px"; cv.style.height = h + "px";
  const c = cv.getContext("2d"); c.setTransform(d, 0, 0, d, 0, 0);
  return c;
}
function inPoly(x, y, p) {
  let c = false;
  for (let i = 0, j = p.length - 2; i < p.length; j = i, i += 2)
    if ((p[i + 1] > y) !== (p[j + 1] > y) && x < (p[j] - p[i]) * (y - p[i + 1]) / (p[j + 1] - p[i + 1]) + p[i]) c = !c;
  return c;
}
function groupKey(mac, name, vendor = "") {
  const g = GROUP_OF[(mac || "").toLowerCase()];
  return g ? { key: g.key, name: g.name } : { key: mac, name: topoName({ name, vendor }) || name || mac };
}

/* ---------------------------------------------------------------- globe
   Where the data goes. Orthographic globe of dotted land (Natural Earth), one arc from home to
   each country the network talked to, coloured by the main traffic class, pulses flowing home.
   IP geography from DB-IP Lite (CC BY 4.0), looked up on the collector. */
const GEO_EU = new Set("AT BE BG HR CY CZ DK EE FI FR DE GR HU IE IT LV LT LU MT NL PL PT RO SK SI ES SE".split(" "));
const flagOf = cc => cc && /^[A-Z]{2}$/.test(cc) && cc !== "ZZ" ? String.fromCodePoint(...[...cc].map(c => 0x1F1E6 + c.charCodeAt(0) - 65)) : "🌐";
const unitVec = (lat, lon) => { const a = lat * Math.PI / 180, b = lon * Math.PI / 180; return [Math.cos(a) * Math.sin(b), Math.sin(a), Math.cos(a) * Math.cos(b)]; };
const kmBetween = (a, b) => 6371 * Math.acos(Math.max(-1, Math.min(1, a[0] * b[0] + a[1] * b[1] + a[2] * b[2])));
const CC = {};
(window.GEO_COUNTRIES || []).forEach((c, i) => CC[c[0]] = { i, cc: c[0], name: c[1], lat: c[2], lon: c[3], cont: c[4] });

VIEWS.globe = main => {
  main.innerHTML = `<div class="head"><h1>Globe</h1><p>Where your data goes. Arcs run from home to every country your devices talked to.</p><div class="grow"></div>
      <select class="search gsel" id="gdev" aria-label="Device"><option value="">All devices</option></select><span id="seg" style="margin-left:10px"></span></div>
    <div class="topo-stats" id="gstats"></div>
    <div class="globe-grid">
      <section class="panel globe-panel">
        <div class="globe-host" id="ghost"><canvas id="gcv" aria-label="Globe of traffic destinations"></canvas><div class="tip globe-tip" hidden></div>
          <div class="globe-hint">Drag to spin · thumb wheel or pinch to zoom · click a city or country to fly there</div></div>
        <div class="globe-insight" id="ginsight"></div>
        <div class="globe-legend" id="glegend"></div>
      </section>
      <section class="panel globe-list"><div class="ph"><h2 id="gltitle">Countries</h2><span class="sub" id="glsub"></span><a class="right tlink" id="gclear" href="javascript:void 0" hidden>All countries</a></div><div id="glist"></div>
        <p class="attrib">IP geography: <a href="https://db-ip.com" target="_blank" rel="noopener">DB-IP</a> Lite (country, city, network), CC BY 4.0, looked up on the collector. Land: Natural Earth.</p></section>
    </div>`;
  const cv = $("#gcv", main), host = $("#ghost", main), tip = $(".globe-tip", main);
  let ctx, W = 0, H = 0, R = 0, zoom = 1, raf = 0, data = null, sel = "", focus = null, countries = [], arcs = [];
  let lat0 = 30, lon0 = 10, vLon = 0, vLat = 0, lastUser = 0, tween = null;
  const devSel = $("#gdev", main);

  // dots: unit vectors + country index
  const L = window.GEO_LAND || new Int16Array(0), ND = L.length / 3;
  const DX = new Float32Array(ND), DY = new Float32Array(ND), DZ = new Float32Array(ND), DC = new Int16Array(ND);
  for (let i = 0; i < ND; i++) { const v = unitVec(L[i * 3] / 10, L[i * 3 + 1] / 10); DX[i] = v[0]; DY[i] = v[1]; DZ[i] = v[2]; DC[i] = L[i * 3 + 2]; }
  let heatOf = new Float32Array(Object.keys(CC).length + 1);

  function size() {
    const w = host.clientWidth, h = Math.max(380, Math.min(660, Math.round(w * 0.78)));
    ctx = fitCanvas(cv, w, h); W = w; H = h; R = Math.min(w, h) * 0.41;
  }
  const rot = () => { const a = lon0 * Math.PI / 180, b = lat0 * Math.PI / 180; return [Math.cos(a), Math.sin(a), Math.cos(b), Math.sin(b)]; };
  function proj(v, r, m = 1) {        // -> [sx, sy, z, visible]
    const [ca, sa, cb, sb] = r;
    const x1 = v[0] * ca - v[2] * sa, z1 = v[0] * sa + v[2] * ca;
    const y2 = v[1] * cb - z1 * sb, z2 = v[1] * sb + z1 * cb;
    const x = x1 * m, y = y2 * m, z = z2 * m;
    const vis = z > 0 || (x * x + y * y) > 1;
    return [W / 2 + x * R * zoom, H / 2 - y * R * zoom, z, vis];
  }

  function build() {
    if (!data) return;
    const homeCc = (data.home && data.home.cc) || site().cc;
    const home = CC[homeCc] || { i: -1, cc: homeCc || "", name: "Home", lat: 0, lon: 0 };
    const hv = unitVec(home.lat, home.lon);
    const byCC = new Map();
    const selKeys = sel ? new Set((data.devices || []).filter(d => groupKey(d.mac, d.name).key === sel).map(d => d.mac)) : null;
    for (const d of data.dests) {
      let b = d.down + d.up;
      if (selKeys) { b = 0; for (const m in d.macs) if (selKeys.has(m)) b += d.macs[m]; if (!b && !Object.keys(d.macs).some(m => selKeys.has(m))) continue; }
      const cc = d.cc || "ZZ";
      let c = byCC.get(cc);
      if (!c) byCC.set(cc, c = { cc, bytes: 0, n: 0, orgs: new Map(), hosts: new Map(), classes: new Map(), devs: new Map(), places: new Map(), ...(CC[cc] || { name: cc === "ZZ" ? "Unknown" : cc }) });
      c.bytes += b; c.n++;
      const org = d.org || "Unknown network";
      c.orgs.set(org, (c.orgs.get(org) || 0) + b);
      if (d.host) c.hosts.set(d.host, (c.hosts.get(d.host) || 0) + b);
      const port = +String(d.ports[0] || "").split("/")[1];
      const k = clsObj(classify({ host: d.host, port }));
      const ce = c.classes.get(k.name) || { cls: k, b: 0 }; ce.b += b || 1; c.classes.set(k.name, ce);
      if (d.place) {                                   // city level, from DB-IP City Lite
        const pk = d.place.city + "|" + d.place.region;
        let pl = c.places.get(pk);
        if (!pl) c.places.set(pk, pl = { name: d.place.city || d.place.region || c.name, region: d.place.region, lat: d.place.lat, lon: d.place.lon, cc, bytes: 0, n: 0, orgs: new Map(), classes: new Map() });
        pl.bytes += b; pl.n++; pl.orgs.set(org, (pl.orgs.get(org) || 0) + b);
        const pe = pl.classes.get(k.name) || { cls: k, b: 0 }; pe.b += b || 1; pl.classes.set(k.name, pe);
      }
      for (const m in d.macs) { const dv = data.devices.find(x => x.mac === m) || {}, g = groupKey(m, dv.name, dv.vendor); c.devs.set(g.name, (c.devs.get(g.name) || 0) + d.macs[m]); }
    }
    countries = [...byCC.values()].sort((a, b) => b.bytes - a.bytes || b.n - a.n);
    const max = Math.max(1, ...countries.map(c => c.bytes));
    heatOf = new Float32Array(heatOf.length);
    arcs = [];
    const arcTo = (lat, lon) => {
      const dv = unitVec(lat, lon);
      const om = Math.acos(Math.max(-1, Math.min(1, hv[0] * dv[0] + hv[1] * dv[1] + hv[2] * dv[2])));
      const pts = [];
      if (om > 0.004) {
        const h = 0.03 + 0.34 * om / Math.PI, S = 56;
        for (let s = 0; s <= S; s++) {
          const t = s / S, k1 = Math.sin((1 - t) * om) / Math.sin(om), k2 = Math.sin(t * om) / Math.sin(om), m = 1 + h * Math.sin(Math.PI * t);
          pts.push([(hv[0] * k1 + dv[0] * k2) * m, (hv[1] * k1 + dv[1] * k2) * m, (hv[2] * k1 + dv[2] * k2) * m]);
        }
      }
      return { dv, pts, km: Math.round(kmBetween(hv, dv)) };
    };
    const allPlaces = [];
    for (const c of countries) {
      c.heat = c.bytes > 0 ? Math.log10(1 + c.bytes) / Math.log10(1 + max) : 0.05;
      c.cls = [...c.classes.values()].sort((a, b) => b.b - a.b)[0]?.cls || clsObj("Unclassified");
      if (c.i != null) heatOf[c.i] = Math.max(0.12, c.heat);
      if (c.lat != null) c.km = Math.round(kmBetween(hv, unitVec(c.lat, c.lon)));
      const pls = c.places.size ? [...c.places.values()] : c.lat != null ? [{ name: c.name, lat: c.lat, lon: c.lon, cc: c.cc, bytes: c.bytes, n: c.n, orgs: c.orgs, classes: c.classes }] : [];
      for (const pl of pls) { pl.c = c; allPlaces.push(pl); }
    }
    allPlaces.sort((a, b) => b.bytes - a.bytes || b.n - a.n);
    const maxP = Math.max(1, ...allPlaces.map(p => p.bytes));
    for (const pl of allPlaces.slice(0, 90)) {
      pl.heat = pl.bytes > 0 ? Math.log10(1 + pl.bytes) / Math.log10(1 + maxP) : 0.05;
      pl.cls = [...pl.classes.values()].sort((a, b) => b.b - a.b)[0]?.cls || pl.c.cls;
      const g = arcTo(pl.lat, pl.lon);
      pl.km = g.km;
      arcs.push({ c: pl.c, p: pl, dv: g.dv, pts: g.pts, w: 0.7 + 3.1 * pl.heat, pulses: Math.min(4, 1 + Math.floor(Math.log10(1 + pl.n))), ph: Math.random() });
    }
    data.hv = hv; data.homeC = home;
    stats(); list(); legend(); insight();
  }

  function draw(t) {
    if (!ctx) return;
    const ink3 = cssVar("--ink-3"), down = cssVar("--down"), panel = cssVar("--panel"), ink = cssVar("--ink");
    ctx.clearRect(0, 0, W, H);
    const cx = W / 2, cy = H / 2, r = R * zoom;
    // atmosphere and body
    const g1 = ctx.createRadialGradient(cx, cy, r * 0.96, cx, cy, r * 1.16);
    g1.addColorStop(0, rgba(down, 0.20)); g1.addColorStop(1, rgba(down, 0));
    ctx.fillStyle = g1; ctx.beginPath(); ctx.arc(cx, cy, r * 1.16, 0, 7); ctx.fill();
    const g2 = ctx.createRadialGradient(cx - r * 0.35, cy - r * 0.4, r * 0.1, cx, cy, r);
    g2.addColorStop(0, shade(panel, 1.04)); g2.addColorStop(1, cssVar("--panel-2"));
    ctx.fillStyle = g2; ctx.beginPath(); ctx.arc(cx, cy, r, 0, 7); ctx.fill();
    ctx.strokeStyle = rgba(ink3, 0.25); ctx.lineWidth = 1; ctx.stroke();
    // land dots: back side faint, front side by depth, countries with traffic in cobalt
    const [ca, sa, cb, sb] = rot();
    const ds = Math.max(1.1, r * 0.0105);
    const focusI = focus && focus.i != null ? focus.i : -1;
    ctx.fillStyle = rgba(ink3, 0.10);
    for (let i = 0; i < ND; i++) {
      const x1 = DX[i] * ca - DZ[i] * sa, z1 = DX[i] * sa + DZ[i] * ca, z2 = DY[i] * sb + z1 * cb;
      if (z2 >= 0) continue;
      const y2 = DY[i] * cb - z1 * sb;
      ctx.fillRect(cx + x1 * r - ds * 0.3, cy - y2 * r - ds * 0.3, ds * 0.6, ds * 0.6);
    }
    for (let pass = 0; pass < 3; pass++) {
      ctx.fillStyle = pass === 0 ? rgba(ink3, 0.55) : pass === 1 ? rgba(down, 0.8) : cssVar("--up");
      ctx.beginPath();
      for (let i = 0; i < ND; i++) {
        const h = heatOf[DC[i]], isF = DC[i] === focusI;
        if (pass === 0 ? (h > 0 || isF) : pass === 1 ? (!h || isF) : !isF) continue;
        const x1 = DX[i] * ca - DZ[i] * sa, z1 = DX[i] * sa + DZ[i] * ca, z2 = DY[i] * sb + z1 * cb;
        if (z2 < 0) continue;
        const y2 = DY[i] * cb - z1 * sb, s = ds * (0.55 + 0.45 * z2) * (pass ? 0.8 + 0.5 * h : 1);
        ctx.rect(cx + x1 * r - s / 2, cy - y2 * r - s / 2, s, s);
      }
      ctx.fill();
    }
    // arcs and pulses
    const R4 = [ca, sa, cb, sb];
    for (const a of arcs) {
      if (!a.pts.length) continue;
      const dim = focus && focus !== a.c;
      const col = a.p.cls.color;
      ctx.lineWidth = a.w; ctx.lineCap = "round";
      let prev = null;
      ctx.strokeStyle = rgba(col, dim ? 0.12 : 0.85);
      ctx.beginPath();
      for (const p of a.pts) {
        const q = proj(p, R4);
        if (q[3] && prev && prev[3]) { ctx.moveTo(prev[0], prev[1]); ctx.lineTo(q[0], q[1]); }
        prev = q;
      }
      ctx.stroke();
      if (dim) continue;
      for (let k = 0; k < a.pulses; k++) {                // pulses travel from the destination towards home
        const u = 1 - ((t / 2600 + a.ph + k / a.pulses) % 1);
        const idx = Math.min(a.pts.length - 1, Math.floor(u * (a.pts.length - 1)));
        const q = proj(a.pts[idx], R4);
        if (!q[3]) continue;
        ctx.fillStyle = rgba(col, 0.25); ctx.beginPath(); ctx.arc(q[0], q[1], a.w + 3, 0, 7); ctx.fill();
        ctx.fillStyle = shade(col, 1.45); ctx.beginPath(); ctx.arc(q[0], q[1], a.w * 0.7 + 1, 0, 7); ctx.fill();
      }
    }
    // destination markers; labels for the biggest, never overlapping each other or home
    const placed = [];
    if (data && data.hv) { const q = proj(data.hv, R4); if (q[2] > 0) placed.push([q[0] - 8, q[1] - 22, 60, 30]); }
    const fits = (x, y, w, h) => !placed.some(b => x < b[0] + b[2] && x + w > b[0] && y < b[1] + b[3] && y + h > b[1]);
    let labelled = 0;
    for (const a of arcs) {
      const q = proj(a.dv, R4);
      a.sx = q[0]; a.sy = q[1]; a.vis = q[2] > 0;
      if (!a.vis) continue;
      const rr = 2.2 + 4.8 * a.p.heat;
      ctx.fillStyle = rgba(a.p.cls.color, focus && focus !== a.c ? 0.2 : 0.95);
      ctx.beginPath(); ctx.arc(q[0], q[1], rr, 0, 7); ctx.fill();
      ctx.strokeStyle = panel; ctx.lineWidth = 1.5; ctx.stroke();
      if ((!focus && labelled < 8) || (focus === a.c && labelled < 14)) {
        ctx.font = "600 13px -apple-system, BlinkMacSystemFont, sans-serif";
        const w = ctx.measureText(a.p.name).width, lx = q[0] + rr + 4, ly = q[1] + 4;
        if (fits(lx, ly - 11, w, 14)) {
          placed.push([lx, ly - 11, w, 14]); labelled++;
          ctx.fillStyle = ink; ctx.strokeStyle = panel; ctx.lineWidth = 3; ctx.strokeText(a.p.name, lx, ly); ctx.fillText(a.p.name, lx, ly);
        }
      }
    }
    // home
    if (data && data.hv) {
      const q = proj(data.hv, R4);
      if (q[2] > 0) {
        const p = (t / 1800) % 1;
        ctx.strokeStyle = rgba(cssVar("--up"), 1 - p); ctx.lineWidth = 2;
        ctx.beginPath(); ctx.arc(q[0], q[1], 5 + p * 16, 0, 7); ctx.stroke();
        ctx.fillStyle = cssVar("--up"); ctx.beginPath(); ctx.arc(q[0], q[1], 5, 0, 7); ctx.fill();
        ctx.strokeStyle = panel; ctx.lineWidth = 2; ctx.stroke();
        ctx.font = "700 13px -apple-system, BlinkMacSystemFont, sans-serif"; ctx.fillStyle = ink;
        ctx.strokeStyle = panel; ctx.lineWidth = 3; const hl = (data.home && data.home.label) || site().short || "Home"; ctx.strokeText(hl, q[0] + 9, q[1] - 8); ctx.fillText(hl, q[0] + 9, q[1] - 8);
      }
    }
  }

  let tPrev = 0;
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  function frame(t) {
    const dt = tPrev ? Math.min(0.05, (t - tPrev) / 1000) : 0; tPrev = t;
    if (tween) {
      const p = Math.min(1, (t - tween.t0) / 900), e = 1 - Math.pow(1 - p, 3);
      lon0 = tween.lon + tween.dLon * e; lat0 = tween.lat + (tween.toLat - tween.lat) * e;
      if (p >= 1) tween = null;
    } else if (!drag) {
      lon0 += vLon * dt; lat0 = Math.max(-70, Math.min(70, lat0 + vLat * dt));
      vLon *= Math.pow(0.08, dt); vLat *= Math.pow(0.08, dt);
      if (!reduced && !focus && performance.now() - lastUser > 4000) lon0 -= 5 * dt;
    }
    draw(reduced ? 0 : t);
    raf = requestAnimationFrame(frame);
  }
  function flyTo(c) {
    if (c.lat == null) return;
    let d = ((c.lon - lon0) % 360 + 540) % 360 - 180;
    tween = { t0: performance.now(), lon: lon0, dLon: d, lat: lat0, toLat: Math.max(-60, Math.min(60, c.lat * 0.8)) };
  }

  // interaction
  let drag = null;
  cv.addEventListener("pointerdown", e => { drag = { x: e.clientX, y: e.clientY, lon: lon0, lat: lat0, t: performance.now(), moved: false }; cv.setPointerCapture(e.pointerId); tween = null; });
  cv.addEventListener("pointermove", e => {
    if (drag) {
      const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
      if (Math.hypot(dx, dy) > 3) drag.moved = true;
      const k = 180 / (Math.PI * R * zoom);
      const nl = drag.lon - dx * k, nt = Math.max(-70, Math.min(70, drag.lat + dy * k));
      const dt = Math.max(0.016, (performance.now() - drag.t) / 1000);
      vLon = (nl - lon0) / dt * 0.5; vLat = (nt - lat0) / dt * 0.5;
      lon0 = nl; lat0 = nt; drag.t = performance.now(); lastUser = drag.t;
      tip.hidden = true; return;
    }
    hoverAt(e);
  });
  cv.addEventListener("pointerup", e => {
    const wasDrag = drag && drag.moved; drag = null;
    if (!wasDrag) { const c = pick(e); setFocus(c && focus === c && !lastPlace ? null : c, lastPlace); }
  });
  cv.addEventListener("pointerleave", () => { tip.hidden = true; });
  cv.addEventListener("wheel", e => {
    if (!isZoomWheel(e)) return;
    e.preventDefault(); zoom = Math.max(0.7, Math.min(3.5, zoom * wheelFactor(e))); lastUser = performance.now();
  }, { passive: false });
  const zoomAnim = z2 => { const z0 = zoom, s0 = performance.now(); lastUser = s0; const st = t => { const p = Math.min(1, (t - s0) / 380), e = 1 - Math.pow(1 - p, 3); zoom = z0 + (z2 - z0) * e; if (p < 1) requestAnimationFrame(st); }; requestAnimationFrame(st); };
  zoomCtl(host, { zin: () => zoomAnim(Math.min(3.5, zoom * 1.4)), zout: () => zoomAnim(Math.max(0.7, zoom / 1.4)), fit: () => { zoomAnim(1); setFocus(null); } });
  function pick(e) {
    const b = cv.getBoundingClientRect(), x = e.clientX - b.left, y = e.clientY - b.top;
    let best = null, bd = 14;
    lastPlace = null;
    for (const a of arcs) if (a.vis) { const d = Math.hypot(a.sx - x, a.sy - y); if (d < bd) { bd = d; best = a; } }
    if (best) { lastPlace = best.p; return best.c; }
    // a land dot under the pointer: its country
    const [ca, sa, cb, sb] = rot(), r = R * zoom;
    let bi = -1; bd = 6;
    for (let i = 0; i < ND; i++) {
      const x1 = DX[i] * ca - DZ[i] * sa, z1 = DX[i] * sa + DZ[i] * ca, z2 = DY[i] * sb + z1 * cb;
      if (z2 < 0) continue;
      const d = Math.hypot(W / 2 + x1 * r - x, H / 2 - (DY[i] * cb - z1 * sb) * r - y);
      if (d < bd) { bd = d; bi = DC[i]; }
    }
    if (bi < 0) return null;
    const meta = window.GEO_COUNTRIES[bi];
    return countries.find(c => c.cc === meta[0]) || { cc: meta[0], name: meta[1], lat: meta[2], lon: meta[3], i: bi, bytes: 0, n: 0, none: true };
  }
  let lastPlace = null;
  function tipPlace(p) {
    const c = p.c;
    return `<div class="t">${flagOf(c.cc)} ${esc(c.name)}${p.km != null ? ` · ${p.km.toLocaleString("en-GB")} km from home` : ""}</div>
      <div class="r"><strong>${esc(p.name)}</strong></div>${p.region && p.region !== p.name ? `<div class="t">${esc(p.region)}</div>` : ""}
      <div class="r">Data<b>${bytes(p.bytes)}</b></div><div class="r">Addresses<b>${p.n}</b></div>
      <div class="r">Mostly<b>${esc(p.cls.name)}</b></div>
      ${topN(p.orgs, 3).map(([o, b]) => `<div class="r">${esc(o.length > 30 ? o.slice(0, 29) + "…" : o)}<b>${bytes(b)}</b></div>`).join("")}`;
  }
  function hoverAt(e) {
    const c = pick(e);
    if (!c) { tip.hidden = true; cv.style.cursor = "grab"; return; }
    cv.style.cursor = "pointer";
    tip.innerHTML = c.none ? `<div class="r"><strong>${flagOf(c.cc)} ${esc(c.name)}</strong></div><div class="t">No traffic in this period</div>` : lastPlace ? tipPlace(lastPlace) : tipCountry(c);
    tip.hidden = false;
    tip.style.left = Math.min(Math.max(e.clientX, 150), innerWidth - 150) + "px"; tip.style.top = e.clientY + "px";
  }
  const topN = (m, n) => [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
  function tipCountry(c) {
    return `<div class="t">${esc(c.cont || "")}${c.km != null ? ` · ${c.km.toLocaleString("en-GB")} km from home` : ""}</div>
      <div class="r"><strong>${flagOf(c.cc)} ${esc(c.name)}</strong></div>
      <div class="r">Data<b>${bytes(c.bytes)}</b></div><div class="r">Addresses<b>${c.n}</b></div>
      <div class="r">Mostly<b>${esc(c.cls.name)}</b></div>
      ${topN(c.orgs, 3).map(([o, b]) => `<div class="r">${esc(o.length > 30 ? o.slice(0, 29) + "…" : o)}<b>${bytes(b)}</b></div>`).join("")}`;
  }
  function setFocus(c, place) {
    focus = c && !c.none ? c : null;
    if (c) flyTo(place || c);
    list();
  }

  /* ---------- side panel, tiles, legend, insight ---------- */
  function stats() {
    const tot = countries.reduce((a, c) => a + c.bytes, 0) || 1;
    const orgs = new Set(); countries.forEach(c => c.orgs.forEach((_, o) => orgs.add(o)));
    const eu = countries.filter(c => GEO_EU.has(c.cc)).reduce((a, c) => a + c.bytes, 0);
    const far = countries.filter(c => c.km != null).sort((a, b) => b.km - a.km)[0];
    const tile = (k, v, s, cls = "") => `<div class="tstat ${cls}"><div class="k">${k}</div><div class="v">${v}</div><div class="s">${s}</div></div>`;
    $("#gstats", main).innerHTML =
      tile("Countries", countries.filter(c => c.cc !== "ZZ").length, `${countries.reduce((a, c) => a + c.n, 0)} outside addresses`) +
      tile("Networks", orgs.size, `top: ${esc(topN(countries.reduce((m, c) => (c.orgs.forEach((b, o) => m.set(o, (m.get(o) || 0) + b)), m), new Map()), 1)[0]?.[0] || "none")}`, "ug") +
      tile("Stays in the EU", `${Math.round(100 * eu / tot)}<small>%</small>`, `${bytes(eu)} of ${bytes(tot)}`, "ok") +
      tile("Farthest", far ? `${flagOf(far.cc)} ${Math.round(far.km / 100) / 10}<small>k km</small>` : "–", far ? esc(far.name) : "", "fence");
  }
  function list() {
    const tot = countries.reduce((a, c) => a + c.bytes, 0) || 1, max = Math.max(1, ...countries.map(c => c.bytes));
    $("#gclear", main).hidden = !focus;
    $("#gclear", main).onclick = () => setFocus(null);
    if (!focus) {
      $("#gltitle", main).textContent = "Countries";
      $("#glsub", main).textContent = "by data, click to fly there";
      $("#glist", main).innerHTML = countries.map((c, i) => `<button class="gc" data-i="${i}">
          <span class="fl">${flagOf(c.cc)}</span><span class="nm"><b>${esc(c.name)}</b><small>${c.n} ${c.n === 1 ? "address" : "addresses"} · ${esc(topN(c.orgs, 1)[0]?.[0] || "")}</small></span>
          <span class="v">${bytes(c.bytes)}<small>${(100 * c.bytes / tot).toFixed(c.bytes / tot < 0.01 ? 1 : 0)}%</small></span>
          <i class="bar" style="width:${(100 * c.bytes / max).toFixed(1)}%;background:${c.cls.color}"></i></button>`).join("") || `<p class="muted">No outside connections in this period.</p>`;
      main.querySelectorAll(".gc").forEach(b => b.onclick = () => setFocus(countries[+b.dataset.i]));
      return;
    }
    const c = focus;
    $("#gltitle", main).textContent = `${flagOf(c.cc)} ${c.name}`;
    $("#glsub", main).textContent = `${bytes(c.bytes)} · ${c.km != null ? c.km.toLocaleString("en-GB") + " km" : ""}`;
    const sec = (title, m, fmt) => `<h3 class="gh">${title}</h3>` + topN(m, 8).map(([k, v]) => fmt(k, v)).join("");
    $("#glist", main).innerHTML =
      (c.places.size ? sec("Cities", new Map([...c.places.values()].map(p => [p.name + (p.region && p.region !== p.name ? ", " + p.region : ""), p.bytes])), (k, v) => `<div class="gr"><span>${esc(k)}</span><b>${bytes(v)}</b></div>`) : "") +
      sec("Networks", c.orgs, (k, v) => `<div class="gr"><span>${esc(k)}</span><b>${bytes(v)}</b></div>`) +
      sec("Names", c.hosts, (k, v) => { const cl = clsObj(classify({ host: k })); return `<div class="gr"><span><i class="dot" style="background:${cl.color}"></i>${esc(k)}</span><b>${bytes(v)}</b></div>`; }) +
      sec("Devices", c.devs, (k, v) => `<div class="gr"><span>${esc(k)}</span><b>${bytes(v)}</b></div>`) +
      sec("Traffic classes", new Map([...c.classes.values()].map(x => [x.cls.name, x.b])), (k, v) => `<div class="gr"><span><i class="dot" style="background:${CLASS_COLOR[k] || CLASS_OTHER[1]}"></i>${esc(k)}</span><b>${bytes(v)}</b></div>`);
  }
  function legend() {
    const seen = new Map();
    for (const c of countries) if (!seen.has(c.cls.name)) seen.set(c.cls.name, c.cls.color);
    $("#glegend", main).innerHTML = `<span><i class="hm"></i>Home</span>` + [...seen].slice(0, 8).map(([n, col]) => `<span><i class="sw" style="background:${col}"></i>${esc(n)}</span>`).join("") + `<span class="muted">Arc width = data · dots flow towards home</span>`;
  }
  function insight() {
    const out = [];
    const top = countries[0];
    if (top) {
      const org = topN(top.orgs, 1)[0], hst = topN(top.hosts, 1)[0];
      out.push(`Most data came from <b>${flagOf(top.cc)} ${esc(top.name)}</b>: ${bytes(top.bytes)}${org ? `, from ${esc(org[0])}` : ""}${hst ? ` (${esc(hst[0])})` : ""}.`);
    }
    const outside = countries.filter(c => !GEO_EU.has(c.cc) && c.cc !== "ZZ");
    if (outside.length) out.push(`${outside.length} ${outside.length === 1 ? "country" : "countries"} outside the EU: ${outside.slice(0, 6).map(c => flagOf(c.cc) + " " + esc(c.name)).join(", ")}${outside.length > 6 ? "…" : ""}.`);
    if (data && !sel) {
      const fen = data.devices.filter(d => isFencedIp(d.ip));
      for (const d of fen) {
        const cs = new Set(data.dests.filter(x => x.macs[d.mac]).map(x => x.cc));
        if (cs.size) out.push(`Fenced zone: <b>${esc(topoName({ name: d.name, vendor: d.vendor || "" }))}</b> reached ${[...cs].map(c => flagOf(c) + " " + esc(CC[c]?.name || c)).join(", ")}.`);
      }
    }
    $("#ginsight", main).innerHTML = out.map(s => `<p>${s}</p>`).join("");
  }

  async function load(range) {
    try { data = await api(`api/geo?range=${range}`); } catch { return; }
    if (!data.ready) { $("#ginsight", main).innerHTML = `<p>Loading the IP geography on the collector. Try again in a few seconds.</p>`; }
    const opts = new Map();
    for (const d of data.devices) { const g = groupKey(d.mac, d.name, d.vendor); if (!opts.has(g.key)) opts.set(g.key, g.name); }
    devSel.innerHTML = `<option value="">All devices</option>` + [...opts].map(([k, n]) => `<option value="${esc(k)}"${k === sel ? " selected" : ""}>${esc(n)}</option>`).join("");
    build();
    if (focus) focus = countries.find(c => c.cc === focus.cc) || null;
    list();
  }
  devSel.onchange = () => { sel = devSel.value; focus = null; build(); };
  const seg = rangeSeg("globe", ["1h", "6h", "24h", "7d"], "24h", r => { seg.value = r; load(r); });
  $("#seg", main).replaceWith(seg.node);
  size();
  const ro = new ResizeObserver(() => size()); ro.observe(host);
  load(seg.value);
  raf = requestAnimationFrame(frame);
  const iv = setInterval(() => load(seg.value), 60000);
  return () => { cancelAnimationFrame(raf); clearInterval(iv); ro.disconnect(); };
};

/* ---------------------------------------------------------------- skyline
   A city of traffic: one row of towers per device, one column per time slot. Tower height is the
   data moved, colour is the traffic class of its busiest app. Night hours (00-06 local time) are shaded. */
const locHour = ts => +new Intl.DateTimeFormat("en-GB", { timeZone: TZ, hour: "2-digit", hour12: false }).format(new Date(ts * 1000)) % 24;

const SKY_NAME_FONT = "600 13.5px -apple-system, BlinkMacSystemFont, sans-serif";
const skyName = n => n.length > 30 ? n.slice(0, 29) + "…" : n;   // the full name is in the tooltip
VIEWS.skyline = main => {
  main.innerHTML = `<div class="head"><h1>Skyline</h1><p>Who used the network, and when. Each tower is one device in one time slot.</p><div class="grow"></div>
      <span id="sscale" style="margin-right:10px"></span><span id="seg"></span></div>
    <div class="topo-stats" id="sstats"></div>
    <section class="panel sky-panel">
      <div class="topo-tools"><div class="seg" role="group" aria-label="View">
        <button id="sv-iso" title="Three-quarter view">3D</button><button id="sv-top" title="From above, like a heat map">Top</button><button id="sv-side" title="From the front, like a bar chart">Front</button></div>
        <span class="topo-hint">Drag to turn the city · thumb wheel or pinch to zoom · hover a tower</span></div>
      <div class="sky-host" id="shost"><canvas id="scv" aria-label="3D skyline of traffic per device over time"></canvas><div class="tip sky-tip" hidden></div></div>
      <div class="globe-legend" id="slegend"></div>
    </section>`;
  const cv = $("#scv", main), host = $("#shost", main), tip = $(".sky-tip", main);
  let ctx, W = 0, H = 0, data = null, rows = [], slots = [], grid = null, maxB = 1;
  let yaw = -0.5, pitch = 0.78, zoom = 1, grow = 0, growT0 = 0, hovered = null, faces = [], raf = 0, scale = "Balanced";

  function size() { const w = host.clientWidth, h = Math.max(380, Math.min(620, Math.round(w * 0.56))); ctx = fitCanvas(cv, w, h); W = w; H = h; request(); }
  let pending = false;
  const request = () => { if (!pending) { pending = true; raf = requestAnimationFrame(t => { pending = false; draw(t); }); } };

  function build(animate) {
    const b = data.bucket, n = Math.max(1, Math.round((data.t1 - data.t0) / b));
    slots = Array.from({ length: n }, (_, i) => data.t0 + i * b);
    const byKey = new Map();
    for (const d of data.devices) {
      const g = groupKey(d.mac, d.name, d.vendor);
      if (!byKey.has(g.key)) byKey.set(g.key, { key: g.key, name: g.name, macs: new Set(), total: 0, cells: new Array(n).fill(null) });
      byKey.get(g.key).macs.add(d.mac);
    }
    const rowOf = new Map();
    for (const r of byKey.values()) for (const m of r.macs) rowOf.set(m, r);
    for (const [t, mac, d, u, top] of data.cells) {
      const r = rowOf.get(mac); if (!r) continue;
      const i = Math.floor((t - data.t0) / b); if (i < 0 || i >= n) continue;
      const c = r.cells[i] || (r.cells[i] = { d: 0, u: 0, top: null, tb: 0, t });
      c.d += d; c.u += u;
      if (top && d + u > c.tb) { c.tb = d + u; c.top = top; }
      r.total += d + u;
    }
    rows = [...byKey.values()].filter(r => r.total > 0).sort((a, b) => b.total - a.total).slice(0, 14);
    maxB = 1;
    for (const r of rows) for (const c of r.cells) if (c) { c.cls = clsObj(c.top ? classOf(c.top) : "Unclassified"); maxB = Math.max(maxB, c.d + c.u); }
    stats(); legend();
    if (animate) { growT0 = performance.now(); grow = 0; animateGrow(); } else request();
  }
  const hOf = b => (scale === "Bytes" ? b / maxB : Math.sqrt(b / maxB)) * 150;

  // world: x along time, z along devices, y up. Camera: yaw about y, pitch about x, then perspective.
  function camera() {
    const n = slots.length, cw = Math.min(18, 760 / Math.max(1, n)), rz = Math.max(30, Math.min(48, 420 / Math.max(1, rows.length)));
    const cxw = n * cw / 2, czw = rows.length * rz / 2, Z = rows.length * rz;
    const cy = Math.cos(yaw), sy = Math.sin(yaw), cp = Math.cos(pitch), sp = Math.sin(pitch);
    const base = (x, y, z) => {
      x -= cxw; z -= czw;
      const x1 = x * cy - z * sy, z1 = x * sy + z * cy;
      return [x1, y * cp - z1 * sp, y * sp + z1 * cp];
    };
    let x0 = 1e9, x1 = -1e9, y0 = 1e9, y1 = -1e9;       // fit the whole city, towers included, into the canvas
    for (const x of [0, n * cw]) for (const z of [0, Z]) for (const y of [0, 150]) {
      const b = base(x, y, z); x0 = Math.min(x0, b[0]); x1 = Math.max(x1, b[0]); y0 = Math.min(y0, b[1]); y1 = Math.max(y1, b[1]);
    }
    ctx.font = SKY_NAME_FONT;
    const gut = Math.min(W * 0.34, 24 + Math.max(0, ...rows.map(r => ctx.measureText(skyName(r.name)).width)));
    const s = zoom * Math.min((W - gut - 30) / Math.max(1, x1 - x0), (H - 80) / Math.max(1, y1 - y0));
    const mx = (x0 + x1) / 2, my = (y0 + y1) / 2, f = 1800;
    const P = (x, y, z) => {
      const b = base(x, y, z), k = f / (f + b[2] * s);
      return [gut + (W - gut - 10) / 2 + (b[0] - mx) * s * k, H / 2 + 6 - (b[1] - my) * s * k, b[2]];
    };
    return { P, cw, rz, n };
  }
  function draw() {
    if (!ctx || !data) return;
    const ink = cssVar("--ink"), ink2 = cssVar("--ink-2"), ink3 = cssVar("--ink-3"), panel = cssVar("--panel"), rule = cssVar("--rule");
    ctx.clearRect(0, 0, W, H);
    if (!rows.length) { ctx.fillStyle = ink3; ctx.font = "14.5px -apple-system, sans-serif"; ctx.fillText("No traffic recorded in this period yet.", 20, 30); return; }
    const { P, cw, rz, n } = camera();
    const Z = rows.length * rz;
    const quad = (pts, fill, stroke) => { ctx.beginPath(); pts.forEach((p, i) => i ? ctx.lineTo(p[0], p[1]) : ctx.moveTo(p[0], p[1])); ctx.closePath(); if (fill) { ctx.fillStyle = fill; ctx.fill(); } if (stroke) { ctx.strokeStyle = stroke; ctx.stroke(); } };
    // floor, night bands, grid
    quad([P(0, 0, 0), P(n * cw, 0, 0), P(n * cw, 0, Z), P(0, 0, Z)], rgba(ink3, 0.06), rgba(ink3, 0.25));
    for (let i = 0; i < n; i++) {
      const hr = locHour(slots[i]);
      if (hr < 6) quad([P(i * cw, 0, 0), P((i + 1) * cw, 0, 0), P((i + 1) * cw, 0, Z), P(i * cw, 0, Z)], rgba("#3B4A8C", 0.16));
    }
    ctx.lineWidth = 0.6;
    for (let j = 0; j <= rows.length; j++) { const a = P(0, 0, j * rz), b = P(n * cw, 0, j * rz); ctx.strokeStyle = rgba(ink3, 0.18); ctx.beginPath(); ctx.moveTo(a[0], a[1]); ctx.lineTo(b[0], b[1]); ctx.stroke(); }
    // towers, far to near
    const boxes = [];
    rows.forEach((r, j) => r.cells.forEach((c, i) => { if (c && c.d + c.u > 0) boxes.push({ r, c, i, j }); }));
    for (const bx of boxes) { bx.depth = P((bx.i + 0.5) * cw, 0, (bx.j + 0.5) * rz)[2]; }
    boxes.sort((a, b) => b.depth - a.depth);
    faces = [];
    const g = grow < 1 ? 1 - Math.pow(1 - grow, 3) : 1;
    ctx.lineWidth = 0.5;
    for (const bx of boxes) {
      const pad = cw * 0.14, pz = rz * 0.2;
      const x0 = bx.i * cw + pad, x1 = (bx.i + 1) * cw - pad, z0 = bx.j * rz + pz, z1 = (bx.j + 1) * rz - pz;
      const h = Math.max(1.2, hOf(bx.c.d + bx.c.u) * g);
      const v = [P(x0, 0, z0), P(x1, 0, z0), P(x1, 0, z1), P(x0, 0, z1), P(x0, h, z0), P(x1, h, z0), P(x1, h, z1), P(x0, h, z1)];
      const col = bx.c.cls.color, hot = hovered && hovered.c === bx.c, rowHot = hovered && hovered.r === bx.r;
      const F = [[0, 1, 5, 4, 0.78], [1, 2, 6, 5, 0.62], [2, 3, 7, 6, 0.70], [3, 0, 4, 7, 0.55], [4, 5, 6, 7, 1.18]];
      for (const [a, b2, c2, d, lum] of F) {
        const p = [v[a], v[b2], v[c2], v[d]];
        const area = (p[1][0] - p[0][0]) * (p[2][1] - p[0][1]) - (p[2][0] - p[0][0]) * (p[1][1] - p[0][1]);
        if (area >= 0) continue;                                  // facing away
        quad(p, hot ? shade(col, lum * 1.25) : shade(col, lum * (hovered && !rowHot ? 0.9 : 1)), rgba(panel, 0.35));
        faces.push({ poly: p.flat(), bx });
      }
    }
    // labels: device names along the left edge, times along the front edge
    ctx.font = SKY_NAME_FONT; ctx.textAlign = "right";
    const placed = [], lh = 16;
    const order = rows.map((r, j) => ({ r, j })).sort((a, b) => (hovered && b.r === hovered.r) - (hovered && a.r === hovered.r));
    for (const { r, j } of order) {
      const p = P(-6, 0, (j + 0.5) * rz), t = skyName(r.name), w = ctx.measureText(t).width;
      const box = [p[0] - w, p[1] - lh / 2, p[0], p[1] + lh / 2];
      if (placed.some(q => box[0] < q[2] && q[0] < box[2] && box[1] < q[3] && q[1] < box[3])) continue;
      placed.push(box);
      ctx.fillStyle = hovered && hovered.r === r ? ink : ink2;
      ctx.lineWidth = 4; ctx.strokeStyle = panel; ctx.strokeText(t, p[0], p[1] + 5); ctx.fillText(t, p[0], p[1] + 5);
    }
    ctx.textAlign = "center"; ctx.font = "12.5px ui-monospace, SF Mono, Menlo, monospace";
    const every = Math.max(1, Math.ceil(n / Math.max(4, Math.min(9, Math.floor((W - 200) / 90)))));
    for (let i = 0; i < n; i += every) {
      const p = P((i + 0.5) * cw, 0, Z + 14);
      ctx.fillStyle = locHour(slots[i]) < 6 ? "#6C7BC4" : ink3;
      ctx.fillText(data.bucket >= 86400 ? dayOf(slots[i]) : locTime(slots[i]), p[0], p[1] + 8);
    }
    ctx.textAlign = "start";
  }
  function animateGrow() {
    const step = t => { grow = Math.min(1, (t - growT0) / 900); draw(); if (grow < 1) raf = requestAnimationFrame(step); };
    raf = requestAnimationFrame(step);
  }
  function tweenView(y2, p2) {
    tip.hidden = true; hovered = null;
    const y1 = yaw, p1 = pitch, t0 = performance.now();
    const step = t => { const k = Math.min(1, (t - t0) / 600), e = 1 - Math.pow(1 - k, 3); yaw = y1 + (y2 - y1) * e; pitch = p1 + (p2 - p1) * e; draw(); if (k < 1) raf = requestAnimationFrame(step); };
    raf = requestAnimationFrame(step);
  }
  $("#sv-iso", main).onclick = () => tweenView(-0.5, 0.78);
  $("#sv-top", main).onclick = () => tweenView(0, 1.52);
  $("#sv-side", main).onclick = () => tweenView(0, 0.05);

  let drag = null;
  cv.addEventListener("pointerdown", e => { drag = { x: e.clientX, y: e.clientY, yaw, pitch }; cv.setPointerCapture(e.pointerId); });
  cv.addEventListener("pointermove", e => {
    if (drag) {
      yaw = drag.yaw + (e.clientX - drag.x) * 0.008;
      pitch = Math.max(0.02, Math.min(1.55, drag.pitch + (e.clientY - drag.y) * 0.006));
      tip.hidden = true; request(); return;
    }
    const b = cv.getBoundingClientRect(), x = e.clientX - b.left, y = e.clientY - b.top;
    let hit = null;
    for (let k = faces.length - 1; k >= 0; k--) if (inPoly(x, y, faces[k].poly)) { hit = faces[k].bx; break; }
    if ((hit && hit.c) !== (hovered && hovered.c)) { hovered = hit; request(); }
    if (!hit) { tip.hidden = true; return; }
    const c = hit.c, night = locHour(c.t) < 6;
    tip.innerHTML = `<div class="t">${stamp(c.t)}${night ? " · night" : ""}</div><div class="r"><strong>${esc(hit.r.name)}</strong></div>
      <div class="r">Download<b>${bytes(c.d)}</b></div><div class="r">Upload<b>${bytes(c.u)}</b></div>
      <div class="r">Busiest app<b>${esc(c.top || "–")}</b></div><div class="r">Class<b>${esc(c.cls.name)}</b></div>`;
    tip.hidden = false;
    tip.style.left = Math.min(Math.max(e.clientX, 140), innerWidth - 140) + "px"; tip.style.top = e.clientY + "px";
  });
  cv.addEventListener("pointerup", () => { drag = null; });
  cv.addEventListener("pointerleave", () => { tip.hidden = true; if (hovered) { hovered = null; request(); } });
  cv.addEventListener("wheel", e => { if (!isZoomWheel(e)) return; e.preventDefault(); zoom = Math.max(0.6, Math.min(4, zoom * wheelFactor(e))); request(); }, { passive: false });
  const skyZoom = z2 => { const z0 = zoom, s0 = performance.now(); const st = t => { const p = Math.min(1, (t - s0) / 380), e = 1 - Math.pow(1 - p, 3); zoom = z0 + (z2 - z0) * e; draw(); if (p < 1) requestAnimationFrame(st); }; requestAnimationFrame(st); };
  cv.addEventListener("dblclick", e => skyZoom(Math.min(4, e.shiftKey ? zoom / 1.6 : zoom * 1.6)));
  zoomCtl(host, { zin: () => skyZoom(Math.min(4, zoom * 1.4)), zout: () => skyZoom(Math.max(0.6, zoom / 1.4)), fit: () => { skyZoom(1); tweenView(-0.5, 0.58); } });

  function stats() {
    const tile = (k, v, s, cls = "") => `<div class="tstat ${cls}"><div class="k">${k}</div><div class="v">${v}</div><div class="s">${s}</div></div>`;
    let peak = null, night = 0, nightBy = new Map(), nightSlots = 0;
    for (const r of rows) r.cells.forEach(c => {
      if (!c) return;
      const b = c.d + c.u;
      if (!peak || b > peak.b) peak = { b, r, c };
      if (locHour(c.t) < 6) { night += b; nightBy.set(r.name, (nightBy.get(r.name) || 0) + b); }
    });
    nightSlots = slots.filter(t => locHour(t) < 6).length;
    const always = rows.filter(r => r.cells.filter(Boolean).length >= slots.length * 0.9);
    const nightTop = [...nightBy].sort((a, b) => b[1] - a[1])[0];
    $("#sstats", main).innerHTML =
      tile("Busiest moment", peak ? bytes(peak.b) : "–", peak ? `${esc(peak.r.name)} at ${locTime(peak.c.t)} ${TZL}${peak.c.top ? ", " + esc(peak.c.top) : ""}` : "") +
      tile("Night traffic", nightSlots ? bytes(night) : "–", nightSlots ? (nightTop ? `00:00 to 06:00 local, most from ${esc(nightTop[0])}` : "00:00 to 06:00 local, all quiet") : "no night hours in this range yet", "fence") +
      tile("Always on", always.length, always.length ? esc(always.map(r => r.name).join(", ")) : "no device active in every slot", "ug") +
      tile("Devices", rows.length, `${slots.length} slots of ${data.bucket >= 3600 ? data.bucket / 3600 + " h" : data.bucket / 60 + " min"}`, "ok");
  }
  function legend() {
    const seen = new Map();
    for (const r of rows) for (const c of r.cells) if (c && !seen.has(c.cls.name)) seen.set(c.cls.name, c.cls.color);
    $("#slegend", main).innerHTML = [...seen].map(([n, col]) => `<span><i class="sw" style="background:${col}"></i>${esc(n)}</span>`).join("") +
      `<span><i class="sw" style="background:rgba(59,74,140,.35)"></i>Night, 00:00 to 06:00 local</span><span class="muted">Height ${scale === "Bytes" ? "= data" : "= √data, so small towers stay visible"}</span>`;
  }
  async function load(range, animate) {
    try { data = await api(`api/skyline?range=${range}`); } catch { return; }
    build(animate);
  }
  const scaleSeg = rangeSeg("sky-scale", ["Balanced", "Bytes"], "Balanced", v => { scale = v; legend(); draw(); }, "Height scale");
  scale = scaleSeg.value;
  $("#sscale", main).replaceWith(scaleSeg.node);
  const seg = rangeSeg("skyline", ["1h", "6h", "24h", "7d"], "6h", r => { seg.value = r; load(r, true); });
  $("#seg", main).replaceWith(seg.node);
  size();
  const ro = new ResizeObserver(() => size()); ro.observe(host);
  load(seg.value, true);
  const iv = setInterval(() => load(seg.value), 120000);
  return () => { cancelAnimationFrame(raf); clearInterval(iv); ro.disconnect(); };
};

/* ---------------------------------------------------------------- flows (Sankey)
   Who sends what, where: devices -> traffic classes -> countries. Band width is data.
   Click any node to follow only its traffic. Data: the connection log with DB-IP geography. */
const shortOrg = o => String(o || "Unknown network").replace(/,?\s+(Inc\.?|LLC|Ltd\.?|Limited|GmbH|B\.V\.|AG|PBC|S\.A\.|Corporation|Corp\.?|Co\.?)$/i, "").replace(/,$/, "");
const tile4 = (k, v, s, cls = "") => `<div class="tstat ${cls}"><div class="k">${k}</div><div class="v">${v}</div><div class="s" title="${esc(String(s).replace(/<[^>]+>/g, ""))}">${s}</div></div>`;
function geoRows(data) {        // one row per (device group, destination) with bytes, class and country
  const out = [];
  for (const d of data.dests) {
    const cls = classify({ host: d.host, port: +String(d.ports[0] || "").split("/")[1] });
    for (const m in d.macs) {
      const b = d.macs[m]; if (!b) continue;
      const dv = data.devices.find(x => x.mac === m) || {};
      const g = groupKey(m, dv.name, dv.vendor);
      out.push({ dev: g.key, devName: g.name, ip: dv.ip || "", cls, cc: d.cc || "ZZ", org: d.org || "Unknown network", host: d.host, b });
    }
  }
  return out;
}

VIEWS.flows = main => {
  main.innerHTML = `<div class="head"><h1>Flows</h1><p>Who sends what, where. Devices on the left, traffic classes in the middle, countries on the right.</p><div class="grow"></div><span id="seg"></span></div>
    <div class="topo-stats" id="fstats"></div>
    <section class="panel flow-panel">
      <div class="topo-tools"><span class="chipf" id="ffilter" hidden></span><span class="topo-hint">Hover to trace a band · click a device, class or country to follow only its traffic · Thumb wheel, pinch or double-click to zoom · 🔍 button: click to zoom · drag to move</span></div>
      <div class="flow-host" id="fhost"><svg id="fsvg" role="img" aria-label="Sankey diagram of traffic from devices through classes to countries"></svg><div class="tip flow-tip" hidden></div></div>
    </section>`;
  const svg = $("#fsvg", main), host = $("#fhost", main), tip = $(".flow-tip", main);
  const zm = svgZoom(svg, host, { max: 6 });
  let data = null, filter = null, raf = 0;

  function draw() {
    if (!data) return;
    let rows = geoRows(data);
    if (filter) rows = rows.filter(r => r[filter.col] === filter.key);
    // collapse the long tail so the diagram stays readable
    const sum = (arr, k) => { const m = new Map(); for (const r of arr) m.set(r[k], (m.get(r[k]) || 0) + r.b); return m; };
    const topKeys = (m, n) => new Set([...m].sort((a, b) => b[1] - a[1]).slice(0, n).map(x => x[0]));
    const keepDev = topKeys(sum(rows, "dev"), 10), keepCC = topKeys(sum(rows, "cc"), 10);
    const devName = new Map(rows.map(r => [r.dev, r.devName]));
    for (const r of rows) {
      if (!keepDev.has(r.dev)) { r.dev = "_od"; devName.set("_od", "Other devices"); }
      if (!keepCC.has(r.cc)) r.cc = "_oc";
    }
    const W = host.clientWidth, total = rows.reduce((a, r) => a + r.b, 0);
    const cols = [[...sum(rows, "dev")], [...sum(rows, "cls")], [...sum(rows, "cc")]].map(c => c.sort((a, b) => b[1] - a[1]));
    const maxN = Math.max(...cols.map(c => c.length), 1);
    const H = Math.max(360, Math.min(760, maxN * 44 + 40)), pad = 12, nw = 14;
    zm.base(0, 0, W, H); svg.style.height = H + "px";
    if (!total) { svg.innerHTML = `<text x="20" y="30" class="fl-empty">No measured traffic to outside addresses in this period.</text>`; return; }
    const ky = Math.min(...cols.map(c => (H - 30 - pad * (c.length - 1)) / c.reduce((a, x) => a + x[1], 0)));
    const X = [Math.max(150, W * 0.17), W / 2 - nw / 2, W - Math.max(170, W * 0.19) - nw];
    const nodes = new Map();
    cols.forEach((c, ci) => {
      const used = c.reduce((a, x) => a + x[1] * ky, 0) + pad * (c.length - 1);
      let y = (H - used) / 2;
      for (const [k, v] of c) {
        const h = Math.max(2, v * ky), id = ci + ":" + k;
        const name = ci === 0 ? devName.get(k) : ci === 1 ? k : k === "_oc" ? "Other countries" : k === "ZZ" ? "Unknown" : (CC[k]?.name || k);
        const color = ci === 1 ? (CLASS_COLOR[k] || CLASS_OTHER[1]) : ci === 0 ? cssVar("--ink-2") : cssVar("--down");
        nodes.set(id, { id, ci, k, v, name, x: X[ci], y, h, color, out: 0, in: 0, cc: ci === 2 ? k : null });
        y += h + pad;
      }
    });
    // links: device->class and class->country
    const L1 = new Map(), L2 = new Map();
    for (const r of rows) {
      const a = `0:${r.dev}|1:${r.cls}`, b = `1:${r.cls}|2:${r.cc}`;
      L1.set(a, (L1.get(a) || 0) + r.b); L2.set(b, (L2.get(b) || 0) + r.b);
    }
    const links = [...L1, ...L2].map(([k, v]) => { const [s, t] = k.split("|"); return { id: k, s: nodes.get(s), t: nodes.get(t), v, w: Math.max(0.8, v * ky) }; });
    // stack link ends in the order of the node on the other side, so bands do not cross needlessly
    for (const n of nodes.values()) {
      links.filter(l => l.s === n).sort((a, b) => a.t.y - b.t.y).forEach(l => { l.y0 = n.y + n.out + l.w / 2; n.out += l.v * ky; });
      links.filter(l => l.t === n).sort((a, b) => a.s.y - b.s.y).forEach(l => { l.y1 = n.y + n.in + l.w / 2; n.in += l.v * ky; });
    }
    const band = l => {
      const x0 = l.s.x + nw, x1 = l.t.x, xm = (x0 + x1) / 2;
      return `M${x0} ${l.y0}C${xm} ${l.y0} ${xm} ${l.y1} ${x1} ${l.y1}`;
    };
    const pct = v => `${(100 * v / total).toFixed(v / total < 0.01 ? 1 : 0)}%`;
    svg.innerHTML = `<defs><clipPath id="freveal"><rect id="frect" x="0" y="0" width="0" height="${H}"/></clipPath></defs>
      <g clip-path="url(#freveal)">
      <g class="fl-links">${links.map(l => `<path class="fl-link" data-id="${esc(l.id)}" d="${band(l)}" stroke="${l.s.ci === 1 ? l.s.color : l.t.color}" stroke-width="${l.w.toFixed(2)}"/>`).join("")}</g>
      <g class="fl-nodes">${[...nodes.values()].map(n => `<g class="fl-node" data-id="${esc(n.id)}" tabindex="0" role="button" aria-label="${esc(n.name)}">
        <rect x="${n.x}" y="${n.y}" width="${nw}" height="${n.h}" rx="3" fill="${n.color}"/>
        <text x="${n.ci === 2 ? n.x + nw + 8 : n.ci === 0 ? n.x - 8 : n.x + nw + 8}" y="${n.y + n.h / 2 + 4}" text-anchor="${n.ci === 0 ? "end" : "start"}" class="fl-lbl">${n.ci === 2 ? flagOf(n.k === "_oc" ? "" : n.k) + " " : ""}${esc(n.name)}<tspan class="fl-v"> ${bytes(n.v)}</tspan></text></g>`).join("")}</g></g>
      <text class="fl-col" x="${X[0] + nw}" y="14" text-anchor="end">DEVICES</text><text class="fl-col" x="${X[1] + nw / 2}" y="14" text-anchor="middle">TRAFFIC CLASSES</text><text class="fl-col" x="${X[2]}" y="14">COUNTRIES</text>`;
    // reveal left to right
    const rect = $("#frect", svg), t0 = performance.now();
    cancelAnimationFrame(raf);
    const step = t => { const p = Math.max(0, Math.min(1, (t - t0) / 900)), e = 1 - Math.pow(1 - p, 3); rect.setAttribute("width", W * e); if (p < 1) raf = requestAnimationFrame(step); };
    raf = requestAnimationFrame(step);
    // hover: a band, or everything through a node
    const byId = new Map(links.map(l => [l.id, l]));
    const place = e => { tip.style.left = Math.min(Math.max(e.clientX, 140), innerWidth - 140) + "px"; tip.style.top = e.clientY + "px"; tip.hidden = false; };
    svg.querySelectorAll(".fl-link").forEach(p => {
      const l = byId.get(p.dataset.id);
      p.onmouseenter = e => { svg.classList.add("fl-focus"); p.classList.add("on"); tip.innerHTML = `<div class="r"><strong>${esc(l.s.name)} → ${esc(l.t.name)}</strong></div><div class="r">Data<b>${bytes(l.v)}</b></div><div class="r">Share of all<b>${pct(l.v)}</b></div>`; place(e); };
      p.onmousemove = place;
      p.onmouseleave = () => { svg.classList.remove("fl-focus"); p.classList.remove("on"); tip.hidden = true; };
    });
    svg.querySelectorAll(".fl-node").forEach(g => {
      const n = nodes.get(g.dataset.id);
      g.onmouseenter = e => {
        svg.classList.add("fl-focus"); g.classList.add("on");
        links.forEach(l => { if (l.s === n || l.t === n) svg.querySelector(`.fl-link[data-id="${CSS.escape(l.id)}"]`)?.classList.add("on"); });
        const outs = links.filter(l => l.s === n).sort((a, b) => b.v - a.v).slice(0, 5), ins = links.filter(l => l.t === n).sort((a, b) => b.v - a.v).slice(0, 5);
        tip.innerHTML = `<div class="r"><strong>${n.ci === 2 ? flagOf(n.k) + " " : ""}${esc(n.name)}</strong></div><div class="r">Data<b>${bytes(n.v)} · ${pct(n.v)}</b></div>` +
          (ins.length ? `<div class="t" style="margin-top:4px">From</div>` + ins.map(l => `<div class="r">${esc(l.s.name)}<b>${bytes(l.v)}</b></div>`).join("") : "") +
          (outs.length ? `<div class="t" style="margin-top:4px">To</div>` + outs.map(l => `<div class="r">${esc(l.t.name)}<b>${bytes(l.v)}</b></div>`).join("") : "") +
          (n.k.startsWith("_") ? "" : `<div class="t" style="margin-top:4px">Click to follow only this</div>`);
        place(e);
      };
      g.onmousemove = place;
      g.onmouseleave = () => { svg.classList.remove("fl-focus"); svg.querySelectorAll(".on").forEach(x => x.classList.remove("on")); tip.hidden = true; };
      g.onclick = () => {
        if (n.k.startsWith("_")) return;
        filter = { col: ["dev", "cls", "cc"][n.ci], key: n.k, name: (n.ci === 2 ? flagOf(n.k) + " " : "") + n.name };
        tip.hidden = true; chip(); draw();
      };
    });
    stats(rows, total);
  }
  function chip() {
    const c = $("#ffilter", main);
    c.hidden = !filter;
    if (filter) { c.innerHTML = `Following: <b>${esc(filter.name)}</b> <button aria-label="Show everything">✕</button>`; c.querySelector("button").onclick = () => { filter = null; chip(); draw(); }; }
  }
  function stats(rows, total) {
    const by = k => { const m = new Map(); rows.forEach(r => m.set(r[k], (m.get(r[k]) || 0) + r.b)); return [...m].sort((a, b) => b[1] - a[1]); };
    const pair = new Map(); rows.forEach(r => { const k = r.devName + "→" + r.cls; pair.set(k, (pair.get(k) || 0) + r.b); });
    const topPair = [...pair].sort((a, b) => b[1] - a[1])[0];
    const cls = by("cls"), cc = by("cc");
    const hidden = rows.filter(r => r.cls === "VPN & encrypted DNS").reduce((a, r) => a + r.b, 0);
    $("#fstats", main).innerHTML =
      tile4("Biggest flow", topPair ? bytes(topPair[1]) : "–", topPair ? esc(topPair[0]) : "") +
      tile4("Top class", cls[0] ? `${Math.round(100 * cls[0][1] / total)}<small>%</small>` : "–", cls[0] ? esc(cls[0][0]) : "", "ug") +
      tile4("Top country", cc[0] ? `${flagOf(cc[0][0])} ${Math.round(100 * cc[0][1] / total)}<small>%</small>` : "–", cc[0] ? esc(CC[cc[0][0]]?.name || cc[0][0]) : "", "ok") +
      tile4("Encrypted and hidden", bytes(hidden), "VPN and encrypted DNS traffic", "fence");
  }
  async function load(range) { try { data = await api(`api/geo?range=${range}`); } catch { return; } draw(); }
  const seg = rangeSeg("flows", ["1h", "6h", "24h", "7d"], "24h", r => { seg.value = r; load(r); });
  $("#seg", main).replaceWith(seg.node);
  let lastW = 0;
  const ro = new ResizeObserver(() => { const w = host.clientWidth; if (Math.abs(w - lastW) > 20) { lastW = w; draw(); } }); ro.observe(host);
  load(seg.value);
  const iv = setInterval(() => load(seg.value), 120000);
  return () => { cancelAnimationFrame(raf); clearInterval(iv); ro.disconnect(); };
};

/* ---------------------------------------------------------------- constellation
   Devices and the companies they talk to, as a live force-directed graph. Companies shared by
   several devices are pulled into the middle; a device's private contacts orbit it. */
VIEWS.constellation = main => {
  main.innerHTML = `<div class="head"><h1>Constellation</h1><p>Your devices and the companies they talk to. Shared companies gather in the middle.</p><div class="grow"></div><span id="seg"></span></div>
    <div class="topo-stats" id="cstats"></div>
    <section class="panel">
      <div class="topo-tools"><span class="topo-hint">Drag a star to pull it · double-click a star to zoom to its links · Thumb wheel, pinch or double-click to zoom · 🔍 button: click to zoom · drag to move</span></div>
      <div class="con-host" id="chost"><svg id="csvg" role="img" aria-label="Graph of devices and the companies they talk to"></svg><div class="tip con-tip" hidden></div></div>
    </section>`;
  const svg = $("#csvg", main), host = $("#chost", main), tip = $(".con-tip", main);
  const zm = svgZoom(svg, host, { max: 6 });
  let nodes = [], links = [], raf = 0, alpha = 1, W = 800, H = 560, drag = null, hoverN = null;

  function build(data) {
    const rows = geoRows(data);
    const devs = new Map(), orgs = new Map(), pairs = new Map();
    for (const r of rows) {
      const d = devs.get(r.dev) || { id: "d:" + r.dev, kind: "dev", name: r.devName, ip: r.ip, b: 0 }; d.b += r.b; devs.set(r.dev, d);
      const o = orgs.get(r.org) || { id: "o:" + r.org, kind: "org", name: shortOrg(r.org), full: r.org, b: 0, cls: new Map(), cc: new Map(), devs: new Set() };
      o.b += r.b; o.cls.set(r.cls, (o.cls.get(r.cls) || 0) + r.b); o.cc.set(r.cc, (o.cc.get(r.cc) || 0) + r.b); o.devs.add(r.dev); orgs.set(r.org, o);
      const k = r.dev + "|" + r.org; pairs.set(k, (pairs.get(k) || 0) + r.b);
    }
    const keepOrg = new Set([...orgs.values()].sort((a, b) => (b.devs.size - a.devs.size) * 1e12 + b.b - a.b).slice(0, 48).map(o => o.full));
    const old = new Map(nodes.map(n => [n.id, n]));
    const maxO = Math.max(1, ...[...orgs.values()].map(o => o.b));
    nodes = [];
    const dl = [...devs.values()];
    dl.forEach((d, i) => {
      const a = i / dl.length * Math.PI * 2, p = old.get(d.id);
      const ax = W / 2 + Math.cos(a - Math.PI / 2) * W * 0.40, ay = H / 2 + Math.sin(a - Math.PI / 2) * H * 0.40;   // devices ring the sky
      nodes.push(Object.assign(d, { r: 17, ax, ay, x: p ? p.x : ax, y: p ? p.y : ay, vx: 0, vy: 0, icon: topoKind({ name: d.name, vendor: "" }) }));
    });
    for (const o of orgs.values()) {
      if (!keepOrg.has(o.full)) continue;
      const p = old.get(o.id);
      o.r = 4 + 16 * Math.sqrt(o.b / maxO);
      o.color = CLASS_COLOR[[...o.cls].sort((a, b) => b[1] - a[1])[0][0]] || CLASS_OTHER[1];
      o.topCC = [...o.cc].sort((a, b) => b[1] - a[1])[0][0];
      nodes.push(Object.assign(o, { x: p ? p.x : W / 2 + (Math.random() - 0.5) * 80, y: p ? p.y : H / 2 + (Math.random() - 0.5) * 80, vx: 0, vy: 0 }));
    }
    const byId = new Map(nodes.map(n => [n.id, n]));
    const maxL = Math.max(1, ...pairs.values());
    links = [...pairs].map(([k, b]) => { const [d, o] = k.split("|"); return { s: byId.get("d:" + d), t: byId.get("o:" + o), b, w: 0.6 + 3.4 * Math.log10(1 + b) / Math.log10(1 + maxL) }; }).filter(l => l.s && l.t);
    nodes.forEach(n => n.deg = links.filter(l => l.s === n || l.t === n).length);
    alpha = 1; for (let i = 0; i < 260; i++) tick(); alpha = Math.max(alpha, 0.12); render(); kick(); stats(devs, orgs);
  }
  function render() {
    zm.base(0, 0, W, H);
    svg.innerHTML = `<defs><radialGradient id="cglow"><stop offset="0" stop-color="var(--down)" stop-opacity=".25"/><stop offset="1" stop-color="var(--down)" stop-opacity="0"/></radialGradient></defs>
      <g class="c-links">${links.map((l, i) => `<line class="c-link" data-i="${i}" stroke-width="${l.w.toFixed(2)}" stroke="${l.t.color}"/>`).join("")}</g>
      <g class="c-nodes">${nodes.map((n, i) => n.kind === "dev"
        ? `<g class="c-node c-dev" data-i="${i}"><circle r="30" fill="url(#cglow)"/><circle class="c-core" r="${n.r}"/><g class="ico" transform="translate(-9 -9) scale(1.15)">${TICON[n.icon] || TICON.device}</g><text y="${n.r + 14}" text-anchor="middle" class="c-dn">${esc(n.name)}</text></g>`
        : `<g class="c-node c-org" data-i="${i}"><circle r="${n.r.toFixed(1)}" fill="${n.color}"/>${n.r > 8 || n.devs.size > 2 ? `<text y="${(n.r + 12).toFixed(1)}" text-anchor="middle" class="c-on">${esc(n.name.length > 22 ? n.name.slice(0, 21) + "…" : n.name)}</text>` : ""}</g>`).join("")}</g>`;
    const ls = svg.querySelectorAll(".c-link"), ns = svg.querySelectorAll(".c-node");
    links.forEach((l, i) => l.el = ls[i]); nodes.forEach((n, i) => n.el = ns[i]);
    ns.forEach(g => {
      const n = nodes[+g.dataset.i];
      g.onpointerdown = e => { drag = n; n.fixed = true; svg.setPointerCapture(e.pointerId); alpha = Math.max(alpha, 0.4); kick(); e.stopPropagation(); };
      g.onmouseenter = e => { hoverN = n; highlight(n); tip.innerHTML = tipOf(n); tip.hidden = false; placeTip(e); };
      g.ondblclick = e => { e.stopPropagation(); const ns = [n, ...links.filter(l => l.s === n || l.t === n).map(l => l.s === n ? l.t : l.s)];
        const xs = ns.map(m => m.x), ys = ns.map(m => m.y), x0 = Math.min(...xs) - 60, y0 = Math.min(...ys) - 60; zm.focus(x0, y0, Math.max(...xs) + 60 - x0, Math.max(...ys) + 60 - y0); };
      g.onmousemove = placeTip;
      g.onmouseleave = () => { hoverN = null; highlight(null); tip.hidden = true; };
    });
    positions();
  }
  const placeTip = e => { tip.style.left = Math.min(Math.max(e.clientX, 140), innerWidth - 140) + "px"; tip.style.top = e.clientY + "px"; };
  function tipOf(n) {
    const mine = links.filter(l => l.s === n || l.t === n).sort((a, b) => b.b - a.b).slice(0, 6);
    if (n.kind === "dev") return `<div class="r"><strong>${esc(n.name)}</strong></div><div class="r">Data<b>${bytes(n.b)}</b></div><div class="r">Companies<b>${n.deg}</b></div>` +
      mine.map(l => `<div class="r">${esc(l.t.name)}<b>${bytes(l.b)}</b></div>`).join("");
    return `<div class="t">${flagOf(n.topCC)} ${esc(CC[n.topCC]?.name || "")}</div><div class="r"><strong>${esc(n.full)}</strong></div><div class="r">Data<b>${bytes(n.b)}</b></div>
      <div class="r">Devices<b>${n.devs.size}</b></div>` + mine.map(l => `<div class="r">${esc(l.s.name)}<b>${bytes(l.b)}</b></div>`).join("");
  }
  function highlight(n) {
    svg.classList.toggle("c-focus", !!n);
    const on = new Set(n ? [n] : []);
    links.forEach(l => { const hit = n && (l.s === n || l.t === n); l.el.classList.toggle("on", !!hit); if (hit) { on.add(l.s); on.add(l.t); } });
    nodes.forEach(x => x.el.classList.toggle("on", on.has(x)));
  }
  function positions() {
    for (const l of links) { l.el.setAttribute("x1", l.s.x.toFixed(1)); l.el.setAttribute("y1", l.s.y.toFixed(1)); l.el.setAttribute("x2", l.t.x.toFixed(1)); l.el.setAttribute("y2", l.t.y.toFixed(1)); }
    for (const n of nodes) n.el.setAttribute("transform", `translate(${n.x.toFixed(1)} ${n.y.toFixed(1)})`);
  }
  function tick() {
    const N = nodes.length;
    for (let i = 0; i < N; i++) for (let j = i + 1; j < N; j++) {           // repulsion + collision
      const a = nodes[i], b = nodes[j];
      let dx = b.x - a.x, dy = b.y - a.y, d2 = dx * dx + dy * dy || 0.01;
      const d = Math.sqrt(d2), minD = a.r + b.r + (a.kind === "dev" || b.kind === "dev" ? 26 : 6);
      let f = (a.kind === "dev" && b.kind === "dev" ? 0 : a.kind === "dev" || b.kind === "dev" ? 1200 : 900) / d2;
      if (d < minD) f += (minD - d) * 0.08;
      dx /= d; dy /= d;
      a.vx -= dx * f * alpha; a.vy -= dy * f * alpha; b.vx += dx * f * alpha; b.vy += dy * f * alpha;
    }
    for (const l of links) {                                                   // springs
      const dx = l.t.x - l.s.x, dy = l.t.y - l.s.y, d = Math.hypot(dx, dy) || 1;
      const target = 40 + l.t.r, k = 0.012 * (1 + Math.log10(1 + l.b) / 8) * (d - target) / d * alpha;
      l.t.vx -= dx * k; l.t.vy -= dy * k;
    }
    for (const n of nodes) {
      if (n.kind === "dev") { n.vx += (n.ax - n.x) * 0.08; n.vy += (n.ay - n.y) * 0.08; }
      else { n.vx += (W / 2 - n.x) * 0.002 * alpha; n.vy += (H / 2 - n.y) * 0.002 * alpha; }
      if (n.fixed) { n.vx = n.vy = 0; continue; }
      n.vx *= 0.6; n.vy *= 0.6;
      n.x = Math.max(n.r + 4, Math.min(W - n.r - 4, n.x + n.vx)); n.y = Math.max(n.r + 4, Math.min(H - n.r - 18, n.y + n.vy));
    }
    alpha *= 0.985;
  }
  function kick() {
    cancelAnimationFrame(raf);
    const loop = () => { tick(); tick(); positions(); if (alpha > 0.01 || drag) raf = requestAnimationFrame(loop); };
    raf = requestAnimationFrame(loop);
  }
  svg.addEventListener("pointermove", e => {
    if (!drag) return;
    const pt = svg.createSVGPoint(); pt.x = e.clientX; pt.y = e.clientY;
    const p = pt.matrixTransform(svg.getScreenCTM().inverse());
    drag.x = p.x; drag.y = p.y; alpha = Math.max(alpha, 0.25);
    tip.hidden = true;
  });
  svg.addEventListener("pointerup", () => { if (drag) { if (drag.kind === "dev") { drag.ax = drag.x; drag.ay = drag.y; } drag.fixed = false; drag = null; kick(); } });
  function stats(devs, orgs) {
    const ol = [...orgs.values()];
    const shared = ol.sort((a, b) => b.devs.size - a.devs.size || b.b - a.b)[0];
    const solo = ol.filter(o => o.devs.size === 1).length;
    const reach = [...devs.values()].map(d => [d.name, links.filter(l => l.s.id === d.id).length]).sort((a, b) => b[1] - a[1])[0];
    const fen = [...devs.values()].filter(d => isFencedIp(d.ip));
    $("#cstats", main).innerHTML =
      tile4("Companies", orgs.size, `${solo} talk to only one device`) +
      tile4("Most shared", shared ? `${shared.devs.size}<small> devices</small>` : "–", shared ? esc(shared.full) : "", "ug") +
      tile4("Widest reach", reach ? `${reach[1]}<small> companies</small>` : "–", reach ? esc(reach[0]) : "", "ok") +
      tile4("Fenced zone reach", fen.length ? fen.map(d => links.filter(l => l.s.id === d.id).length).reduce((a, b) => a + b, 0) : 0, fen.length ? `companies reached by ${esc(fen.map(d => d.name).join(", "))}` : "no traffic from a fenced zone", "fence");
  }
  function size() { W = Math.max(600, host.clientWidth); H = Math.max(460, Math.min(720, Math.round(W * 0.6))); if (nodes.length) { render(); alpha = Math.max(alpha, 0.3); kick(); } }
  let data = null;
  async function load(range) { try { data = await api(`api/geo?range=${range}`); } catch { return; } build(data); }
  const seg = rangeSeg("constellation", ["1h", "6h", "24h", "7d"], "24h", r => { seg.value = r; load(r); });
  $("#seg", main).replaceWith(seg.node);
  size();
  const ro = new ResizeObserver(() => { const w = host.clientWidth; if (Math.abs(w - W) > 40) size(); }); ro.observe(host);
  load(seg.value);
  return () => { cancelAnimationFrame(raf); ro.disconnect(); };
};

/* ---------------------------------------------------------------- privacy radar
   DNS behaviour per device from the DNS filter log. Distance from the centre is the share of a
   device's lookups the DNS filter blocked: the further out, the more it chases ads and trackers.
   Also counts the tell-tale signs of devices trying to get round the DNS filter. */
const SNEAKY = [
  { key: "ddr", label: "Encrypted DNS discovery", test: d => d === "_dns.resolver.arpa", why: "The device asked which encrypted DNS server to use (DDR). It wants to move DNS off the DNS filter." },
  { key: "canary", label: "Firefox DoH canary", test: d => d === "use-application-dns.net", why: "Firefox checks this name before switching on its own encrypted DNS." },
  { key: "relay", label: "iCloud Private Relay", test: d => /^mask(-h2|-api|-t)?\.icloud\.com$/.test(d), why: "An Apple device trying to route traffic through iCloud Private Relay, which hides it from the network." },
  { key: "doh", label: "DoH resolver lookups", test: d => { const h = window.DOH_HOSTS; if (!h) return false; const p = d.split("."); for (let i = 0; i < p.length - 1; i++) if (h.has(p.slice(i).join("."))) return true; return false; }, why: "Names of public encrypted-DNS servers, from the open-source DoH list." },
];
// regDomain(): see the DNS names helpers further down (function declaration, hoisted)

VIEWS.privacy = main => {
  main.innerHTML = `<div class="head"><h1>Privacy radar</h1><p>How hard each device chases ads and trackers, from the DNS filter's log. Further out means more of its lookups were blocked.</p><div class="grow"></div><span id="seg"></span></div>
    <div class="topo-stats" id="pstats"></div>
    <div class="radar-grid">
      <section class="panel radar-panel"><div class="radar-host" id="rhost"><svg id="rsvg" role="img" aria-label="Radar of blocked DNS share per device"></svg><div class="tip radar-tip" hidden></div></div>
        <div class="globe-legend"><span><i class="sw" style="background:var(--ok)"></i>Under 10% blocked</span><span><i class="sw" style="background:var(--warn)"></i>10 to 30%</span><span><i class="sw" style="background:var(--crit)"></i>Over 30%</span><span><i class="sw ring"></i>Encrypted-DNS attempts</span><span class="muted">Blip size = number of lookups</span></div></section>
      <section class="panel radar-side" id="rside"></section>
    </div>`;
  const svg = $("#rsvg", main), host = $("#rhost", main), tip = $(".radar-tip", main), side = $("#rside", main);
  const zm = svgZoom(svg, host, { max: 6 });
  let data = null, clients = [], sel = null, raf = 0;

  function prep() {
    clients = data.clients.filter(c => c.n >= 5 && c.ip !== "127.0.0.1").map(c => {
      const share = c.n ? c.b / c.n : 0;
      const sneaky = SNEAKY.map(s => ({ ...s, n: 0, names: [] }));
      for (const d of c.domains) { const k = sneaky.find(s => s.test(d[0])); if (k) { k.n += d[1]; k.names.push(d[0]); } }   // each name counts once, first match wins
      const trackers = new Map();
      for (const [d, n, b] of c.domains) if (b || classByHost(d) === "Analytics & tracking") trackers.set(regDomain(d), (trackers.get(regDomain(d)) || 0) + n);
      const unknown = c.name === c.ip;
      const nm = unknown ? `Unknown ${c.ip.split(".").pop()}` : c.vendor === "infra" ? c.name : groupKey(c.mac, c.name, c.vendor).name;
      return { ...c, share, sneaky, sneakyN: sneaky.reduce((a, s) => a + s.n, 0), trackers, nm, unknown };
    }).sort((a, b) => b.n - a.n);
    const seen = new Map(); clients.forEach(x => seen.set(x.nm, (seen.get(x.nm) || 0) + 1));
    clients.forEach(x => { if (seen.get(x.nm) > 1) x.nm += ` (.${x.ip.split(".").pop()})`; });
  }
  const col = s => s < 0.10 ? cssVar("--ok") : s < 0.30 ? cssVar("--warn") : cssVar("--crit");
  function draw() {
    const S = Math.max(360, Math.min(host.clientWidth - 180, 600)), c = S / 2, R = S / 2 - 34;
    zm.base(-90, 0, S + 180, S); svg.style.height = S + "px";
    const rOf = s => R * (0.1 + 0.9 * Math.min(1, s / 0.8));             // 0 to 80% blocked across the radius
    const maxN = Math.max(1, ...clients.map(x => x.n));
    const rings = [0, 0.1, 0.3, 0.5, 0.8];
    let h = `<defs><linearGradient id="rsweep" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="var(--ok)" stop-opacity="0"/><stop offset="1" stop-color="var(--ok)" stop-opacity=".28"/></linearGradient></defs>
      <circle cx="${c}" cy="${c}" r="${R}" class="r-bg"/>`;
    for (const s of rings.slice(1)) h += `<circle cx="${c}" cy="${c}" r="${rOf(s)}" class="r-ring ${s === 0.3 ? "warnring" : ""}"/><text x="${c + 4}" y="${c - rOf(s) - 3}" class="r-rl">${Math.round(s * 100)}%</text>`;
    const n = clients.length;
    clients.forEach((x, i) => { x.a = -Math.PI / 2 + i / n * Math.PI * 2; x.r = rOf(x.share); x.x = c + Math.cos(x.a) * x.r; x.y = c + Math.sin(x.a) * x.r; x.size = 5 + 17 * Math.sqrt(x.n / maxN); });
    for (const x of clients) h += `<line x1="${c}" y1="${c}" x2="${c + Math.cos(x.a) * R}" y2="${c + Math.sin(x.a) * R}" class="r-spoke"/>`;
    h += `<g id="rsw"><path d="M${c} ${c} L${c + R} ${c} A${R} ${R} 0 0 0 ${c + Math.cos(-0.6) * R} ${c + Math.sin(-0.6) * R} Z" fill="url(#rsweep)"/><line x1="${c}" y1="${c}" x2="${c + R}" y2="${c}" class="r-beam"/></g>`;
    clients.forEach((x, i) => {
      const lx = c + Math.cos(x.a) * (R + 14), ly = c + Math.sin(x.a) * (R + 14), anchor = Math.cos(x.a) > 0.3 ? "start" : Math.cos(x.a) < -0.3 ? "end" : "middle";
      h += `<g class="r-blip${sel === x ? " sel" : ""}${x.unknown ? " unk" : ""}" data-i="${i}" tabindex="0" role="button" aria-label="${esc(x.nm)}">
        <circle class="r-halo" cx="${x.x}" cy="${x.y}" r="${x.size + 8}" fill="${col(x.share)}"/>
        ${x.sneakyN ? `<circle class="r-sneak" cx="${x.x}" cy="${x.y}" r="${x.size + 4}"/>` : ""}
        <circle class="r-dot" cx="${x.x}" cy="${x.y}" r="${x.size}" fill="${col(x.share)}"/>
        <text class="r-lbl" x="${lx}" y="${ly + 4}" text-anchor="${anchor}">${esc(x.nm)}</text></g>`;
    });
    svg.innerHTML = h;
    svg.querySelectorAll(".r-blip").forEach(g => {
      const x = clients[+g.dataset.i];
      g.onmouseenter = e => { tip.innerHTML = `<div class="r"><strong>${esc(x.nm)}</strong></div><div class="r">Lookups<b>${x.n.toLocaleString("en-GB")}</b></div><div class="r">Blocked<b>${Math.round(x.share * 100)}%</b></div>${x.sneakyN ? `<div class="r bad">Encrypted-DNS attempts<b>${x.sneakyN}</b></div>` : ""}`; tip.hidden = false; placeTip(e); };
      g.onmousemove = placeTip;
      g.onmouseleave = () => tip.hidden = true;
      g.onclick = () => { sel = x; draw(); detail(); };
      g.onkeydown = e => { if (e.key === "Enter") g.onclick(); };
    });
    const sw = $("#rsw", svg), blips = [...svg.querySelectorAll(".r-halo")];
    cancelAnimationFrame(raf);
    if (matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const loop = t => {                                                 // the sweep lights each blip as it passes
      const ang = (t / 5200 % 1) * Math.PI * 2;
      sw.setAttribute("transform", `rotate(${ang * 180 / Math.PI} ${c} ${c})`);
      clients.forEach((x, i) => { let d = ang - x.a; d = ((d % (2 * Math.PI)) + 2 * Math.PI) % (2 * Math.PI); blips[i].style.opacity = Math.max(0, 0.55 - d / 2.2).toFixed(3); });
      raf = requestAnimationFrame(loop);
    };
    raf = requestAnimationFrame(loop);
  }
  const placeTip = e => { tip.style.left = Math.min(Math.max(e.clientX, 130), innerWidth - 130) + "px"; tip.style.top = e.clientY + "px"; };
  function detail() {
    const x = sel;
    if (!x) { side.innerHTML = ""; return; }
    const fw = x.n - x.b - x.c;
    const spark = (() => {
      if (!x.hours.length) return "";
      const w = 300, hh = 56, max = Math.max(...x.hours.map(r => r[1])), t0 = x.hours[0][0], t1 = Math.max(t0 + 3600, x.hours[x.hours.length - 1][0]);
      const bw = Math.max(2, w / ((t1 - t0) / 3600 + 1) - 2);
      return `<svg class="r-spark" viewBox="0 0 ${w} ${hh + 14}">${x.hours.map(([t, n, b]) => {
        const px = (t - t0) / (t1 - t0 + 3600) * w, hn = n / max * hh, hb = b / max * hh;
        return `<rect x="${px}" y="${hh - hn}" width="${bw}" height="${hn - hb}" rx="1" class="ok"/><rect x="${px}" y="${hh - hb}" width="${bw}" height="${hb}" rx="1" class="bl"/>`;
      }).join("")}<text x="0" y="${hh + 12}">${locTime(t0)}</text><text x="${w}" y="${hh + 12}" text-anchor="end">${locTime(t1)} ${TZL}</text></svg>`;
    })();
    const tr = [...x.trackers].sort((a, b) => b[1] - a[1]).slice(0, 8);
    side.innerHTML = `<div class="ph"><h2>${esc(x.nm)}</h2><span class="sub">${esc(x.ip)}</span></div>
      <div class="r-big" style="color:${col(x.share)}">${Math.round(x.share * 100)}<small>% blocked</small></div>
      <div class="r-stack"><i style="flex:${x.b};background:var(--crit)"></i><i style="flex:${x.c};background:var(--c3)"></i><i style="flex:${Math.max(0, fw)};background:var(--down)"></i></div>
      <div class="r-keys"><span><i style="background:var(--crit)"></i>Blocked ${x.b.toLocaleString("en-GB")}</span><span><i style="background:var(--c3)"></i>From cache ${x.c.toLocaleString("en-GB")}</span><span><i style="background:var(--down)"></i>Asked upstream ${Math.max(0, fw).toLocaleString("en-GB")}</span></div>
      <h3 class="gh">Lookups per hour, blocked in red</h3>${spark}
      <h3 class="gh">Getting round the DNS filter</h3>
      ${x.sneaky.filter(s => s.n).map(s => `<div class="r-sn"><b>${esc(s.label)}</b><span>${s.n}×</span><p>${esc(s.why)}${s.names.length ? ` <code>${esc(s.names.slice(0, 3).join(", "))}</code>` : ""}</p></div>`).join("") || `<p class="muted">No signs. It uses the DNS filter as told.</p>`}
      <h3 class="gh">Ad and tracker companies it tried</h3>
      ${tr.map(([d, n]) => `<div class="gr"><span>${esc(d)}</span><b>${n}</b></div>`).join("") || `<p class="muted">None.</p>`}
      ${x.unknown ? `<p class="r-note">This address has no device record in Netmon. It may be a phone or laptop using a private Wi-Fi address that has since changed.</p>` : ""}
      ${x.vendor === "infra" && x.ip === site().router.ip ? `<p class="r-note">Devices that ask the router for names have their lookups forwarded, so they appear here as the router.</p>` : ""}`;
  }
  function stats() {
    const tot = clients.reduce((a, x) => a + x.n, 0), bl = clients.reduce((a, x) => a + x.b, 0);
    const worst = clients.filter(x => x.n >= 100).sort((a, b) => b.share - a.share)[0];
    const sn = clients.reduce((a, x) => a + x.sneakyN, 0), snDev = clients.filter(x => x.sneakyN).length;
    $("#pstats", main).innerHTML =
      tile4("Lookups", tot.toLocaleString("en-GB"), `${clients.length} devices asked the DNS filter`) +
      tile4("Blocked", `${tot ? Math.round(100 * bl / tot) : 0}<small>%</small>`, `${bl.toLocaleString("en-GB")} ads and trackers stopped`, "crit") +
      tile4("Most tracked", worst ? `${Math.round(worst.share * 100)}<small>%</small>` : "–", worst ? `${esc(worst.nm)} blocked most` : "", "warn") +
      tile4("Getting round the DNS filter", sn, `${snDev} ${snDev === 1 ? "device" : "devices"} tried encrypted DNS or Private Relay`, "fence");
  }
  async function load(range) {
    try { data = await api(`api/privacy?range=${range}`); } catch { return; }
    prep();
    if (!sel || !clients.find(x => x.ip === sel.ip)) sel = clients.filter(x => x.n >= 100).sort((a, b) => b.share - a.share)[0] || clients[0];
    else sel = clients.find(x => x.ip === sel.ip);
    stats(); draw(); detail();
  }
  const seg = rangeSeg("privacy", ["1h", "6h", "24h", "7d"], "24h", r => { seg.value = r; load(r); });
  $("#seg", main).replaceWith(seg.node);
  let lastW = 0;
  const ro = new ResizeObserver(() => { const w = host.clientWidth; if (clients.length && Math.abs(w - lastW) > 20) { lastW = w; draw(); } }); ro.observe(host);
  load(seg.value);
  const iv = setInterval(() => load(seg.value), 60000);
  return () => { cancelAnimationFrame(raf); clearInterval(iv); ro.disconnect(); };
};

/* ---------------------------------------------------------------- beacon finder
   Malware "beacons" call home on a timer. Every device -> destination pair that connected at least
   five times is plotted by how often (x) and how regularly (y). Known, explained timers are muted;
   regular external timers with no explanation are shown in red. */
const KNOWN_TIMERS = [
  { t: (b) => b.port === 49000, why: "Router management check (TR-064)" },
  { t: (b) => /aaplimg\.com$|apple\.com$|icloud\.com$|apple-dns\.net$/.test(b.host) || /Apple Inc/.test(b.org || ""), why: "Apple push and keep-alive" },
  { t: (b) => /push\.services\.mozilla\.com$|mozilla\.(net|org|com)$|mozilla\.map\.fastly\.net$/.test(b.host), why: "Firefox push service" },
  { t: (b) => b.port === 123 || /ntp\.org$/.test(b.host), why: "Clock sync (NTP)" },
  { t: (b) => b.port === 1900 || b.port === 5351, why: "Port-mapping probes (UPnP, NAT-PMP), usually Tailscale" },
  { t: (b) => b.port === 5453 || b.port === 53 || b.port === 853, why: "DNS" },
  { t: (b) => /anthropic\.com$|claude\.ai$/.test(b.host), why: "Claude app" },
  { t: (b) => /tailscale\.com$|ts\.net$/.test(b.host) || b.port === 41641, why: "Tailscale" },
  { t: (b) => /googleapis\.com$|gstatic\.com$|google\.com$|1e100\.net$/.test(b.host) && [443, 5228].includes(b.port), why: "Google services" },
  { t: (b) => b.port === 139 || b.port === 445, why: "File sharing (SMB)" },
  { t: (b) => /youtube\.com$|googlevideo\.com$|ytimg\.com$/.test(b.host), why: "YouTube open in a browser or app" },
  { t: (b) => /frontier\.amazon\.|amazon\.(de|com|co\.uk)$/.test(b.host), why: "Amazon website open (live updates)" },
  { t: (b) => /media\.amazon|amazonvideo\.com$|aiv-cdn\.net$|aiv-delivery\.net$/.test(b.host), why: "Amazon streaming" },
  { t: (b) => /mullvad\.net$/.test(b.host), why: "Mullvad VPN app or browser checking in" },
  { t: (b) => /ohttp-relay|oblivious/.test(b.host), why: "Apple Oblivious HTTP relay (Private Relay, Siri)" },
  { t: (b) => /facebook\.com$|fbcdn\.net$|whatsapp\.net$|instagram\.com$/.test(b.host), why: "Meta app (Facebook, Instagram or WhatsApp)" },
  { t: (b) => /msedge\.net$|microsoft\.com$|office\.(com|net)$|live\.com$/.test(b.host), why: "Microsoft app" },
];
const explainTimer = b => (KNOWN_TIMERS.find(k => k.t(b)) || {}).why || "";
const fmtGap = s => s < 90 ? `${Math.round(s)} s` : s < 5400 ? `${Math.round(s / 60)} min` : `${(s / 3600).toFixed(1)} h`;

VIEWS.beacons = main => {
  main.innerHTML = `<div class="head"><h1>Beacon finder</h1><p>Anything that calls home on a timer. Top right is clockwork: many calls at a steady beat.</p><div class="grow"></div><span id="seg"></span></div>
    <div class="topo-stats" id="bstats"></div>
    <div class="radar-grid">
      <section class="panel"><div class="bc-host" id="bhost"><svg id="bsvg" role="img" aria-label="Scatter of connection interval against regularity"></svg><div class="tip bc-tip" hidden></div></div>
        <div class="globe-legend"><span><i class="sw" style="background:var(--crit)"></i>Regular, outside, not explained</span><span><i class="sw" style="background:var(--c4)"></i>Regular, inside the network</span><span><i class="sw" style="background:var(--ink-3)"></i>Explained timer</span><span class="muted">Circle size = number of calls</span></div></section>
      <section class="panel radar-side" id="bside"></section>
    </div>`;
  const svg = $("#bsvg", main), host = $("#bhost", main), tip = $(".bc-tip", main), side = $("#bside", main);
  const zm = svgZoom(svg, host, { max: 10 });
  let pairs = [], sel = null, span = 86400;
  const kind = b => b.why ? "known" : b.regular >= 0.6 && b.external ? "alert" : b.regular >= 0.6 ? "inside" : "loose";
  const colOf = b => ({ known: cssVar("--ink-3"), alert: cssVar("--crit"), inside: cssVar("--c4"), loose: cssVar("--down") })[kind(b)];
  function barcode(b, w, h) {
    const t0 = b.times[0], t1 = Math.max(t0 + 1, b.times[b.times.length - 1]);
    return `<svg class="bc-code" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">${b.times.map(t => `<rect x="${((t - t0) / (t1 - t0) * (w - 2)).toFixed(1)}" y="0" width="1.4" height="${h}"/>`).join("")}</svg>`;
  }
  function draw() {
    const W = Math.max(520, host.clientWidth), H = Math.round(Math.min(560, W * 0.62)), L = 56, R = 16, T = 18, B = 40;
    zm.base(0, 0, W, H); svg.style.height = H + "px";
    const x = g => L + (Math.log10(Math.max(5, g)) - Math.log10(5)) / (Math.log10(21600) - Math.log10(5)) * (W - L - R);
    const y = r => T + (1 - r) * (H - T - B);
    const maxN = Math.max(1, ...pairs.map(p => p.n));
    let h = `<rect x="${L}" y="${y(1)}" width="${W - L - R}" height="${y(0.8) - y(1)}" class="bc-zone"/><text x="${W - R - 6}" y="${y(1) + 14}" text-anchor="end" class="bc-zl">clockwork</text>`;
    for (const r of [0, 0.25, 0.5, 0.75, 1]) h += `<line x1="${L}" x2="${W - R}" y1="${y(r)}" y2="${y(r)}" class="bc-grid"/><text x="${L - 8}" y="${y(r) + 4}" text-anchor="end" class="bc-ax">${Math.round(r * 100)}%</text>`;
    for (const [g, lab] of [[10, "10 s"], [30, "30 s"], [60, "1 min"], [300, "5 min"], [900, "15 min"], [3600, "1 h"], [14400, "4 h"]])
      h += `<line x1="${x(g)}" x2="${x(g)}" y1="${T}" y2="${H - B}" class="bc-grid"/><text x="${x(g)}" y="${H - B + 16}" text-anchor="middle" class="bc-ax">${lab}</text>`;
    h += `<text x="${L + (W - L - R) / 2}" y="${H - 6}" text-anchor="middle" class="bc-at">Time between calls</text><text transform="translate(14 ${T + (H - T - B) / 2}) rotate(-90)" text-anchor="middle" class="bc-at">Regularity</text>`;
    const order = pairs.map((p, i) => i).sort((a, b) => (kind(pairs[a]) === "alert") - (kind(pairs[b]) === "alert") || pairs[b].n - pairs[a].n);
    for (const i of order) {
      const p = pairs[i], r = 3 + 12 * Math.sqrt(p.n / maxN);
      h += `<circle class="bc-dot k-${kind(p)}${sel === p ? " sel" : ""}" data-i="${i}" cx="${x(p.median).toFixed(1)}" cy="${y(p.regular).toFixed(1)}" r="${r.toFixed(1)}" fill="${colOf(p)}"/>`;
    }
    svg.innerHTML = h;
    svg.querySelectorAll(".bc-dot").forEach(c => {
      const p = pairs[+c.dataset.i];
      c.onmouseenter = e => {
        tip.innerHTML = `<div class="t">${esc(p.device)} → ${p.proto}/${p.port}</div><div class="r"><strong>${esc(p.host || p.dst)}</strong></div>
          <div class="r">Calls<b>${p.n}</b></div><div class="r">Every<b>${fmtGap(p.median)}</b></div><div class="r">Regularity<b>${Math.round(p.regular * 100)}%</b></div>
          ${p.why ? `<div class="r">Likely<b>${esc(p.why)}</b></div>` : ""}${barcode(p, 240, 18)}`;
        tip.hidden = false; place(e);
      };
      c.onmousemove = place;
      c.onmouseleave = () => tip.hidden = true;
      c.onclick = () => { sel = p; draw(); detail(); };
      c.ondblclick = e => { e.stopPropagation(); const cx0 = +c.getAttribute("cx"), cy0 = +c.getAttribute("cy"); zm.focus(cx0 - 90, cy0 - 60, 180, 120); };
    });
  }
  const place = e => { tip.style.left = Math.min(Math.max(e.clientX, 140), innerWidth - 140) + "px"; tip.style.top = e.clientY + "px"; };
  function detail() {
    const p = sel;
    if (!p) { side.innerHTML = ""; return; }
    const gaps = p.times.slice(1).map((t, i) => t - p.times[i]).filter(g => g > 0);
    const maxG = Math.max(...gaps, 1), bins = new Array(24).fill(0);
    gaps.forEach(g => bins[Math.min(23, Math.floor(Math.log10(Math.max(1, g)) / Math.log10(maxG + 1) * 24))]++);
    const bm = Math.max(...bins, 1);
    const k = kind(p);
    side.innerHTML = `<div class="ph"><h2>${esc(p.device)}</h2><span class="sub">${p.proto}/${p.port}</span></div>
      <div class="bc-to">→ <b>${esc(p.host || p.dst)}</b>${p.cc ? ` ${flagOf(p.cc)}` : ""}<div class="muted">${esc(p.dst)}${p.org ? " · " + esc(p.org) : ""}</div></div>
      <div class="bc-verdict k-${k}">${k === "alert" ? "Regular calls to the outside with no known explanation. Worth a look." : k === "inside" ? "A regular timer inside your network." : k === "known" ? `Likely explained: ${esc(p.why)}.` : "Repeated calls without a steady beat."}</div>
      <div class="r-big">${fmtGap(p.median)}<small> between calls · ${Math.round(p.regular * 100)}% regular</small></div>
      <h3 class="gh">Every call, as a barcode</h3>${barcode(p, 320, 34)}
      <div class="bc-span"><span>${stamp(p.first)}</span><span>${stamp(p.last)}</span></div>
      <h3 class="gh">Gaps between calls</h3>
      <svg class="bc-hist" viewBox="0 0 320 60">${bins.map((n, i) => `<rect x="${i * 13.3}" y="${56 - n / bm * 52}" width="11" height="${n / bm * 52}" rx="1.5"/>`).join("")}</svg>
      <div class="bc-span"><span>short</span><span>${fmtGap(maxG)}</span></div>
      <div class="gr"><span>Calls</span><b>${p.n}</b></div><div class="gr"><span>Data</span><b>${bytes(p.bytes)}</b></div><div class="gr"><span>Average gap</span><b>${fmtGap(p.mean)}</b></div>`;
  }
  function stats() {
    const al = pairs.filter(p => kind(p) === "alert"), inside = pairs.filter(p => kind(p) === "inside"), known = pairs.filter(p => kind(p) === "known");
    const tight = pairs.filter(p => p.regular >= 0.8).sort((a, b) => b.n - a.n)[0];
    $("#bstats", main).innerHTML =
      tile4("Repeating pairs", pairs.length, "device and destination, 5 or more calls") +
      tile4("Unexplained outside", al.length, al.length ? `top: ${esc(al[0].device)} → ${esc(al[0].host || al[0].dst)}` : "every regular outside timer is explained", al.length ? "crit" : "ok") +
      tile4("Inside timers", inside.length, inside.length ? `top: ${esc(inside[0].device)} → ${esc(inside[0].host || inside[0].dst)}` : "none", "fence") +
      tile4("Tightest clock", tight ? fmtGap(tight.median) : "–", tight ? `${esc(tight.device)} → ${esc(tight.host || tight.dst)}, ${tight.n} calls` : "", "ug");
  }
  async function load(range) {
    let d; try { d = await api(`api/beacons?range=${range}`); } catch { return; }
    span = d.span;
    pairs = d.pairs.map(p => ({ ...p, why: explainTimer(p) }));
    if (!sel || !pairs.find(p => p.src === sel.src && p.dst === sel.dst && p.port === sel.port)) sel = pairs.find(p => kind(p) === "alert") || pairs.find(p => kind(p) === "inside") || pairs[0] || null;
    else sel = pairs.find(p => p.src === sel.src && p.dst === sel.dst && p.port === sel.port);
    stats(); draw(); detail();
  }
  const seg = rangeSeg("beacons", ["6h", "24h", "7d"], "24h", r => { seg.value = r; load(r); });
  $("#seg", main).replaceWith(seg.node);
  let lastW = 0;
  const ro = new ResizeObserver(() => { const w = host.clientWidth; if (pairs.length && Math.abs(w - lastW) > 20) { lastW = w; draw(); } }); ro.observe(host);
  load(seg.value);
  const iv = setInterval(() => load(seg.value), 120000);
  return () => { clearInterval(iv); ro.disconnect(); };
};

/* ---------------------------------------------------------------- ports periodic table
   Every service in use as an element tile, grouped into families like the periodic table.
   Heat = number of connections. A red corner marks a port with no known family. */
const PORT_FAMILIES = [
  ["Web", "#2F5BEA", { "tcp/443": ["Hs", "HTTPS"], "udp/443": ["Qu", "QUIC"], "tcp/80": ["Ht", "HTTP"], "tcp/8080": ["Hp", "HTTP alt"], "tcp/8443": ["Ha", "HTTPS alt"] }],
  ["Names & time", "#3E8E5A", { "udp/53": ["Dn", "DNS"], "tcp/53": ["Dt", "DNS over TCP"], "tcp/853": ["Do", "DNS over TLS"], "udp/5453": ["Sb", "Stubby (DoT proxy)"], "udp/123": ["Nt", "NTP clock"], "udp/5353": ["Md", "mDNS"], "udp/67": ["Dh", "DHCP server"], "udp/68": ["Dc", "DHCP client"], "tcp/43": ["Wh", "WHOIS"] }],
  ["Push & messages", "#0E8C7E", { "tcp/5223": ["Ap", "Apple push"], "tcp/5228": ["Gc", "Google push"], "tcp/5222": ["Xm", "XMPP chat"], "tcp/993": ["Im", "IMAP mail (TLS)"], "tcp/587": ["Sm", "Mail submit"], "tcp/465": ["Ms", "SMTP (TLS)"], "tcp/1143": ["Pb", "Mail bridge IMAP"], "tcp/1025": ["Ps", "Mail bridge SMTP"] }],
  ["Calls", "#8A4FD1", { "udp/3478": ["St", "STUN"], "udp/19302": ["Gs", "Google STUN"], "udp/3480": ["Ft", "FaceTime"], "udp/16384": ["Rt", "RTP media"] }],
  ["Home & sharing", "#A8791F", { "tcp/445": ["Fs", "SMB file sharing"], "tcp/139": ["Nb", "NetBIOS"], "udp/137": ["Nn", "NetBIOS names"], "tcp/548": ["Af", "AFP"], "tcp/7000": ["Ai", "AirPlay"], "udp/1900": ["Sd", "SSDP / UPnP"], "udp/5351": ["Np", "NAT-PMP"], "tcp/49000": ["Tr", "TR-064 (router management)"], "udp/2002": ["Gl", "GL.iNet discovery"] }],
  ["Remote & VPN", "#C4692D", { "tcp/22": ["Sh", "SSH"], "udp/41641": ["Ts", "Tailscale"], "udp/51820": ["Wg", "WireGuard"], "udp/1194": ["Ov", "OpenVPN"], "udp/500": ["Ik", "IPsec IKE"], "udp/4500": ["Nt", "IPsec NAT-T"], "tcp/3389": ["Rd", "Remote Desktop"], "tcp/5900": ["Vn", "Screen sharing (VNC)"] }],
];
VIEWS.ports = main => {
  main.innerHTML = `<div class="head"><h1>Ports</h1><p>Every service your network used, laid out like the periodic table. Brighter tiles were used more.</p><div class="grow"></div><span id="seg"></span></div>
    <div class="topo-stats" id="pstats"></div>
    <section class="panel"><div class="pt-grid" id="ptable"></div>
      <div class="globe-legend" style="margin-top:14px"><span><i class="sw" style="background:var(--crit)"></i>Not in any known family: check it</span><span><i class="pt-io out"></i>Mostly to the internet</span><span><i class="pt-io in"></i>Mostly inside the network</span></div></section>
    <section class="panel" id="pdetail" style="margin-top:14px" hidden></section>`;
  let ports = [], sel = null;
  function draw() {
    const byKey = new Map(ports.map(p => [`${p.proto}/${p.port}`, p]));
    const max = Math.max(1, ...ports.map(p => p.conns));
    const used = new Set();
    const tile = (k, sym, name, color) => {
      const p = byKey.get(k); used.add(k);
      const heat = p ? Math.log10(1 + p.conns) / Math.log10(1 + max) : 0;
      const io = p ? (p.external >= p.internal ? "out" : "in") : "";
      return `<button class="pt-tile${p ? "" : " idle"}${sel === k ? " sel" : ""}" data-k="${k}" style="--c:${color};--h:${heat.toFixed(3)}" ${p ? "" : "disabled"}>
        <span class="pt-no">${k.split("/")[1]}</span><span class="pt-pr">${k.split("/")[0]}</span><b class="pt-sym">${sym}</b><span class="pt-nm">${esc(name)}</span>
        <span class="pt-n">${p ? p.conns.toLocaleString("en-GB") : "–"}</span>${io ? `<i class="pt-io ${io}"></i>` : ""}</button>`;
    };
    let h = PORT_FAMILIES.map(([fam, color, tiles]) => `<div class="pt-fam"><h3 style="color:${color}">${fam}</h3>${Object.entries(tiles).map(([k, [sym, name]]) => tile(k, sym, name, color)).join("")}</div>`).join("");
    const odd = ports.filter(p => !used.has(`${p.proto}/${p.port}`));
    h += `<div class="pt-fam odd"><h3>Unfamiliar</h3>${odd.map(p => tile(`${p.proto}/${p.port}`, "?", p.port >= 49152 ? "High port" : "Unknown service", cssVar("--crit"))).join("") || `<p class="muted">None. Every port in use belongs to a known family.</p>`}</div>`;
    $("#ptable", main).innerHTML = h;
    main.querySelectorAll(".pt-tile:not(.idle)").forEach(b => b.onclick = () => { sel = sel === b.dataset.k ? null : b.dataset.k; draw(); detail(); });
    stats(odd);
  }
  function detail() {
    const box = $("#pdetail", main), p = ports.find(x => `${x.proto}/${x.port}` === sel);
    if (!p) { box.hidden = true; return; }
    box.hidden = false;
    const fam = PORT_FAMILIES.find(f => f[2][sel]);
    box.innerHTML = `<div class="ph"><h2>${esc(fam ? fam[2][sel][1] : "Unfamiliar service")} · ${esc(sel)}</h2><span class="sub">${p.conns.toLocaleString("en-GB")} connections · ${bytes(p.bytes)} · ${p.dests} destinations</span></div>
      <div class="topo-card-grid"><div><div class="k">Devices</div>${p.devices.map(([n, c]) => `<div class="gr"><span>${esc(n)}</span><b>${c}</b></div>`).join("")}</div>
      <div><div class="k">Destinations</div>${p.hosts.map(([n, c]) => `<div class="gr"><span>${esc(n)}</span><b>${c}</b></div>`).join("")}</div>
      <div><div class="k">Direction</div><div class="gr"><span>To the internet</span><b>${p.external}</b></div><div class="gr"><span>Inside the network</span><b>${p.internal}</b></div></div></div>`;
  }
  function stats(odd) {
    const tot = ports.reduce((a, p) => a + p.conns, 0);
    const web = ports.filter(p => p.port === 443).reduce((a, p) => a + p.conns, 0);
    $("#pstats", main).innerHTML =
      tile4("Services in use", ports.length, `${tot.toLocaleString("en-GB")} connections`) +
      tile4("Encrypted web", `${tot ? Math.round(100 * web / tot) : 0}<small>%</small>`, "of connections use port 443", "ok") +
      tile4("Unfamiliar ports", odd.length, odd.length ? odd.slice(0, 4).map(p => `${p.proto}/${p.port}`).join(", ") : "none", odd.length ? "crit" : "ok") +
      tile4("Plain HTTP", (ports.find(p => p.proto === "tcp" && p.port === 80)?.conns || 0).toLocaleString("en-GB"), "unencrypted web connections", "warn");
  }
  async function load(range) { let d; try { d = await api(`api/ports?range=${range}`); } catch { return; } ports = d.ports; draw(); detail(); }
  const seg = rangeSeg("ports", ["1h", "6h", "24h", "7d"], "24h", r => { seg.value = r; load(r); });
  $("#seg", main).replaceWith(seg.node);
  load(seg.value);
  const iv = setInterval(() => load(seg.value), 120000);
  return () => clearInterval(iv);
};

/* ---------------------------------------------------------------- airwaves
   The router in the middle, every Wi-Fi client placed by signal strength: the closer to the
   centre, the stronger. 5 GHz clients on the right, 2.4 GHz on the left. Waves ripple out from
   the router; a client's size is its link rate. Signal history is kept per minute. */
VIEWS.air = main => {
  main.innerHTML = `<div class="head"><h1>Airwaves</h1><p>Every Wi-Fi client around ${esc(rtrName())}. Closer to the centre means a stronger signal.</p><div class="grow"></div><span id="seg"></span></div>
    <div class="topo-stats" id="astats"></div>
    <div class="radar-grid">
      <section class="panel"><div class="air-host" id="ahost"><canvas id="acv" aria-label="Wi-Fi clients placed by signal strength around the router"></canvas><div class="tip air-tip" hidden></div></div>
        <div class="globe-legend"><span><i class="sw" style="background:#2F5BEA"></i>5 GHz</span><span><i class="sw" style="background:#0E8C7E"></i>2.4 GHz</span><span><i class="sw" style="background:#8A4FD1"></i>Fenced zone</span><span><i class="sw ring" style="border-style:solid;border-color:#2F5BEA"></i>Standby (the machine carries on its cable)</span><span class="muted">Circle size = link rate · rings in dBm</span></div></section>
      <section class="panel radar-side" id="aside"></section>
    </div>`;
  const cv = $("#acv", main), host = $("#ahost", main), tip = $(".air-tip", main), side = $("#aside", main);
  let ctx, W = 0, H = 0, data = null, clients = [], raf = 0, sel = null;
  const BAND = b => String(b || "").startsWith("5") ? "#2F5BEA" : String(b || "").startsWith("6") ? "#C4692D" : "#0E8C7E";
  const colOf = c => isFencedIp(c.ip) ? "#8A4FD1" : BAND(c.band);
  function size() { const w = host.clientWidth, h = Math.max(380, Math.min(600, Math.round(w * 0.62))); ctx = fitCanvas(cv, w, h); W = w; H = h; layout(); }
  let az = 1;
  const rOf = dbm => { const R = (Math.min(W, H) / 2 - 30) * az; return R * Math.max(0.16, Math.sqrt(Math.min(1, Math.max(0, (-(dbm ?? -90) - 20) / 70)))); };   // -20 dBm centre, -90 dBm edge; square root opens up the strong end
  function layout() {
    const right = clients.filter(c => String(c.band).startsWith("5") || String(c.band).startsWith("6")), left = clients.filter(c => !right.includes(c));
    const spread = (arr, a0, a1) => arr.sort((a, b) => (a.signal ?? -99) - (b.signal ?? -99)).forEach((c, i) => { c.a = a0 + (i + 1) / (arr.length + 1) * (a1 - a0); });
    spread(right, -Math.PI * 0.42, Math.PI * 0.42); spread(left, Math.PI * 0.58, Math.PI * 1.42);
    for (const c of clients) { const r = rOf(c.signal); c.x = W / 2 + Math.cos(c.a) * r; c.y = H / 2 + Math.sin(c.a) * r; c.s = 5 + 9 * Math.sqrt(Math.min(2400, c.rate_mbps || 50) / 2400); }
  }
  function draw(t) {
    if (!ctx) return;
    const ink = cssVar("--ink"), ink3 = cssVar("--ink-3"), panel = cssVar("--panel"), cx = W / 2, cy = H / 2;
    ctx.clearRect(0, 0, W, H);
    // quality rings
    [[-40, "−40", "--ok"], [-55, "−55", "--ok"], [-67, "−67 good", "--ok"], [-75, "−75 fair", "--warn"], [-85, "−85 weak", "--crit"]].forEach(([dbm, lab, col], i) => {
      const r = rOf(dbm), a = Math.PI * (1.18 + i * 0.075);             // labels fan out along the lower left
      ctx.beginPath(); ctx.arc(cx, cy, r, 0, 7); ctx.strokeStyle = rgba(cssVar(col), dbm <= -75 ? 0.45 : 0.22); ctx.setLineDash([3, 4]); ctx.lineWidth = 1; ctx.stroke(); ctx.setLineDash([]);
      ctx.fillStyle = dbm <= -75 ? cssVar(col) : ink3; ctx.font = "12px ui-monospace, SF Mono, Menlo, monospace"; ctx.textAlign = "right";
      ctx.fillText(lab, cx + Math.cos(a) * r - 3, cy - Math.sin(a) * r + 3); ctx.textAlign = "start";
    });
    ctx.fillStyle = ink3; ctx.font = "600 12.5px -apple-system, sans-serif"; ctx.textAlign = "center";
    ctx.fillText("2.4 GHz", cx - Math.min(W, H) / 2 + 40, 16); ctx.fillText("5 GHz", cx + Math.min(W, H) / 2 - 40, 16); ctx.textAlign = "start";
    // waves from the router, one colour per band
    if (t) for (let k = 0; k < 3; k++) {
      const p = ((t / 3200) + k / 3) % 1, rr = p * Math.min(W, H) / 2;
      ctx.beginPath(); ctx.arc(cx, cy, rr, -Math.PI / 2, Math.PI / 2); ctx.strokeStyle = rgba("#2F5BEA", 0.35 * (1 - p)); ctx.lineWidth = 2; ctx.stroke();
      ctx.beginPath(); ctx.arc(cx, cy, rr * 1.12 % (Math.min(W, H) / 2), Math.PI / 2, Math.PI * 1.5); ctx.strokeStyle = rgba("#0E8C7E", 0.35 * (1 - p)); ctx.stroke();
    }
    // links and clients
    for (const c of clients) {
      const col = colOf(c);
      ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(c.x, c.y); ctx.strokeStyle = rgba(col, sel === c ? 0.7 : 0.22); ctx.lineWidth = 1 + (c.rate_mbps || 0) / 900; ctx.stroke();
    }
    for (const c of clients) {
      const col = colOf(c);
      if (sel === c) { ctx.beginPath(); ctx.arc(c.x, c.y, c.s + 6, 0, 7); ctx.fillStyle = rgba(col, 0.2); ctx.fill(); }
      ctx.beginPath(); ctx.arc(c.x, c.y, c.s, 0, 7);
      if (c.standby) { ctx.fillStyle = panel; ctx.fill(); ctx.strokeStyle = col; ctx.lineWidth = 2.5; ctx.stroke(); }     // Wi-Fi on standby: the machine carries on its cable
      else { ctx.fillStyle = col; ctx.fill(); ctx.strokeStyle = panel; ctx.lineWidth = 2; ctx.stroke(); }
      ctx.font = "600 13px -apple-system, sans-serif"; ctx.fillStyle = ink; ctx.strokeStyle = panel; ctx.lineWidth = 3;
      const left = Math.cos(c.a) < 0, lx = c.x + (left ? -c.s - 6 : c.s + 6);
      ctx.textAlign = left ? "right" : "left"; ctx.strokeText(c.nm, lx, c.y + 4); ctx.fillText(c.nm, lx, c.y + 4); ctx.textAlign = "start";
    }
    // router
    ctx.beginPath(); ctx.arc(cx, cy, 16, 0, 7); ctx.fillStyle = panel; ctx.fill(); ctx.strokeStyle = ink; ctx.lineWidth = 1.5; ctx.stroke();
    ctx.fillStyle = ink; ctx.font = "700 12px -apple-system, sans-serif"; ctx.textAlign = "center"; ctx.fillText(cap(rtrName()), cx, cy + 30); ctx.textAlign = "start";
    ctx.strokeStyle = ink; ctx.lineWidth = 1.3; ctx.beginPath(); ctx.moveTo(cx - 5, cy + 5); ctx.lineTo(cx - 5, cy - 2); ctx.moveTo(cx + 5, cy + 5); ctx.lineTo(cx + 5, cy - 2); ctx.moveTo(cx - 7, cy + 5); ctx.lineTo(cx + 7, cy + 5); ctx.stroke();
  }
  function loop(t) { draw(matchMedia("(prefers-reduced-motion: reduce)").matches ? 0 : t); raf = requestAnimationFrame(loop); }
  function pickAt(e) { const b = cv.getBoundingClientRect(), x = e.clientX - b.left, y = e.clientY - b.top; return clients.find(c => Math.hypot(c.x - x, c.y - y) < c.s + 4); }
  cv.addEventListener("mousemove", e => {
    const c = pickAt(e); cv.style.cursor = c ? "pointer" : "default";
    if (!c) { tip.hidden = true; return; }
    tip.innerHTML = `<div class="r"><strong>${esc(c.nm)}</strong></div><div class="r">Band<b>${esc(c.band || "")}</b></div><div class="r">Signal<b>${c.signal} dBm</b></div><div class="r">Link rate<b>${c.rate_mbps || "?"} Mbit/s</b></div><div class="r">Signal to noise<b>${c.snr ?? "?"} dB</b></div>`;
    tip.hidden = false; tip.style.left = Math.min(Math.max(e.clientX, 120), innerWidth - 120) + "px"; tip.style.top = e.clientY + "px";
  });
  cv.addEventListener("mouseleave", () => tip.hidden = true);
  cv.addEventListener("click", e => { const c = pickAt(e); if (c) { sel = c; detail(); } });
  const airZoom = z2 => { const z0 = az, s0 = performance.now(); const st = t => { const p = Math.min(1, (t - s0) / 380), e = 1 - Math.pow(1 - p, 3); az = z0 + (z2 - z0) * e; layout(); if (p < 1) requestAnimationFrame(st); }; requestAnimationFrame(st); };
  cv.addEventListener("wheel", e => { if (!isZoomWheel(e)) return; e.preventDefault(); az = Math.max(1, Math.min(3, az * wheelFactor(e))); layout(); }, { passive: false });
  cv.addEventListener("dblclick", e => airZoom(Math.max(1, Math.min(3, e.shiftKey ? az / 1.5 : az * 1.5))));
  zoomCtl(host, { zin: () => airZoom(Math.min(3, az * 1.4)), zout: () => airZoom(Math.max(1, az / 1.4)), fit: () => airZoom(1) });
  function spark(hist, key, lo, hi, col, w = 320, h = 54) {
    if (hist.length < 2) return `<p class="muted">Recording started ${data ? "today" : ""}. The history fills in minute by minute.</p>`;
    const t0 = hist[0][0], t1 = hist[hist.length - 1][0] || t0 + 1;
    const pts = hist.map(r => [((r[0] - t0) / Math.max(1, t1 - t0)) * w, h - ((Math.max(lo, Math.min(hi, r[key] ?? lo)) - lo) / (hi - lo)) * (h - 4) - 2]);
    return `<svg class="r-spark" viewBox="0 0 ${w} ${h + 14}"><path d="M${pts.map(p => p.map(v => v.toFixed(1)).join(" ")).join("L")}" fill="none" stroke="${col}" stroke-width="1.8"/>
      <text x="0" y="${h + 12}">${locTime(t0)}</text><text x="${w}" y="${h + 12}" text-anchor="end">${locTime(t1)} ${TZL}</text></svg>`;
  }
  function detail() {
    const c = sel;
    if (!c) { side.innerHTML = ""; return; }
    const q = c.signal >= -55 ? ["Excellent", "ok"] : c.signal >= -67 ? ["Good", "ok"] : c.signal >= -75 ? ["Fair", "warn"] : ["Weak", "crit"];
    side.innerHTML = `<div class="ph"><h2>${esc(c.nm)}</h2><span class="sub">${esc(c.ip || "")}</span></div>
      <div class="r-big" style="color:var(--${q[1]})">${c.signal}<small> dBm · ${q[0]}</small></div>
      <div class="gr"><span>Band</span><b>${esc(c.band || "")}</b></div><div class="gr"><span>Link rate</span><b>${c.rate_mbps || "?"} Mbit/s</b></div><div class="gr"><span>Signal to noise</span><b>${c.snr ?? "?"} dB</b></div>
      <h3 class="gh">Signal over time</h3>${spark(c.history, 1, -90, -20, colOf(c))}
      <h3 class="gh">Link rate over time</h3>${spark(c.history, 2, 0, 2400, cssVar("--down"))}`;
  }
  function stats() {
    const weakest = clients.slice().sort((a, b) => (a.signal ?? 0) - (b.signal ?? 0))[0];
    const on24 = clients.filter(c => !/^[56]/.test(String(c.band)) && !isFencedIp(c.ip));
    const avg = clients.length ? Math.round(clients.reduce((a, c) => a + (c.signal ?? 0), 0) / clients.length) : 0;
    const fast = clients.slice().sort((a, b) => (b.rate_mbps || 0) - (a.rate_mbps || 0))[0];
    $("#astats", main).innerHTML =
      tile4("Wi-Fi clients", clients.length, `average signal ${avg} dBm`) +
      tile4("Weakest", weakest ? `${weakest.signal}<small> dBm</small>` : "–", weakest ? esc(weakest.nm) : "", weakest && weakest.signal < -70 ? "warn" : "ok") +
      tile4("Fastest link", fast ? `${fast.rate_mbps}<small> Mbit/s</small>` : "–", fast ? esc(fast.nm) : "", "ug") +
      tile4("Devices on 2.4 GHz", on24.length, on24.length ? esc(on24.map(c => c.nm).join(", ")) : "every device outside the fenced zones is on 5 or 6 GHz", on24.length ? "warn" : "ok");
  }
  async function load(range) {
    try { data = await api(`api/air?range=${range}`); } catch { return; }
    clients = data.clients.map(c => { const dual = !!GROUP_OF[String(c.mac || "").toLowerCase()]; /* part of a dual-homed machine */ return { ...c, standby: dual, nm: groupKey(c.mac, c.name, c.vendor).name + (dual ? " (Wi-Fi, standby)" : "") }; });
    layout(); stats();
    sel = clients.find(c => sel && c.mac === sel.mac) || clients.slice().sort((a, b) => (a.signal ?? 0) - (b.signal ?? 0))[0] || null;
    detail();
  }
  const seg = rangeSeg("air", ["1h", "6h", "24h", "7d"], "6h", r => { seg.value = r; load(r); });
  $("#seg", main).replaceWith(seg.node);
  size();
  let lastW = 0;
  const ro = new ResizeObserver(() => { const w = host.clientWidth; if (Math.abs(w - lastW) > 20) { lastW = w; size(); } }); ro.observe(host);
  load(seg.value);
  raf = requestAnimationFrame(loop);
  const iv = setInterval(() => load(seg.value), 30000);
  return () => { cancelAnimationFrame(raf); clearInterval(iv); ro.disconnect(); };
};

/* ---------------------------------------------------------------- shared zoom (one behaviour on every chart)
   Thumb wheel (horizontal wheel) or trackpad pinch zooms around the pointer; the normal scroll wheel
   keeps scrolling the page. Double-click zooms in, shift + double-click zooms out, drag moves the
   view once zoomed, and the floating control has +, − and Fit. */
const isZoomWheel = e => e.ctrlKey || e.metaKey || (Math.abs(e.deltaX) > Math.abs(e.deltaY) * 1.2 && Math.abs(e.deltaX) > 0.5);
const wheelFactor = e => Math.exp(-(Math.abs(e.deltaX) > Math.abs(e.deltaY) ? e.deltaX : e.deltaY) * (e.ctrlKey || e.metaKey ? 0.012 : 0.006));
const ZTOOL = { on: store.get("ztool", false) };
function zoomCtl(host, { zin, zout, fit, at }) {
  host.querySelector(".zoomctl")?.remove();
  const d = document.createElement("div");
  d.className = "zoomctl";
  d.innerHTML = `<button data-z="tool" class="ztool-b" title="Click to zoom: when on, click the chart to zoom in there, Alt-click to zoom out" aria-label="Click to zoom" aria-pressed="${ZTOOL.on}"><svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="6.8" cy="6.8" r="4.3"/><path d="M10 10l4 4M5 6.8h3.6M6.8 5v3.6"/></svg></button><button data-z="in" title="Zoom in (thumb wheel, pinch or double-click)" aria-label="Zoom in">+</button><button data-z="out" title="Zoom out" aria-label="Zoom out">−</button><button data-z="fit" title="Fit everything" aria-label="Fit">⤢</button>`;
  const sync = () => { host.classList.toggle("ztool", ZTOOL.on); d.querySelector(".ztool-b").setAttribute("aria-pressed", ZTOOL.on); };
  d.onclick = e => { const b = e.target.closest("button"); const z = b && b.dataset.z;
    if (z === "tool") { ZTOOL.on = !ZTOOL.on; store.set("ztool", ZTOOL.on); sync(); } else if (z === "in") zin(); else if (z === "out") zout(); else if (z === "fit") fit(); };
  // click-to-zoom: with the magnifier on, a click anywhere on the chart zooms there instead of selecting
  if (!host._ztool) {
    host._ztool = true;
    host.addEventListener("click", e => {
      if (!ZTOOL.on || e.target.closest(".zoomctl")) return;
      e.stopPropagation(); e.preventDefault();
      const out = e.altKey || e.shiftKey;
      if (host._zat) host._zat(e, out ? 0.5 : 2); else (out ? host._zout : host._zin)();
    }, true);
  }
  host._zat = at; host._zin = zin; host._zout = zout;
  sync();
  d.addEventListener("pointerdown", e => e.stopPropagation());
  d.addEventListener("dblclick", e => e.stopPropagation());
  host.appendChild(d);
  return d;
}
function svgZoom(svg, host, { min = 1, max = 8 } = {}) {
  let base = null, k = 1, cx = 0, cy = 0, tw = 0, drag = null;
  const apply = () => {
    if (!base) return;
    const w = base.w / k, h = base.h / k;
    cx = Math.max(base.x + w / 2, Math.min(base.x + base.w - w / 2, cx));
    cy = Math.max(base.y + h / 2, Math.min(base.y + base.h - h / 2, cy));
    svg.setAttribute("viewBox", `${cx - w / 2} ${cy - h / 2} ${w} ${h}`);
    host.classList.toggle("zoomed", k > 1.01);
  };
  const world = e => { const r = svg.getBoundingClientRect(), w = base.w / k, h = base.h / k; return [cx - w / 2 + (e.clientX - r.left) / r.width * w, cy - h / 2 + (e.clientY - r.top) / r.height * h]; };
  const to = (k2, px, py, animate = true) => {
    k2 = Math.max(min, Math.min(max, k2));
    const k0 = k, x0 = cx, y0 = cy;
    const x1 = px + (cx - px) * (k0 / k2), y1 = py + (cy - py) * (k0 / k2);    // keep the point under the pointer still
    if (!animate) { k = k2; cx = x1; cy = y1; apply(); return; }
    cancelAnimationFrame(tw);
    const t0 = performance.now();
    const step = t => { const p = Math.min(1, Math.max(0, (t - t0) / 380)), e = 1 - Math.pow(1 - p, 3);
      k = k0 + (k2 - k0) * e; cx = x0 + (x1 - x0) * e; cy = y0 + (y1 - y0) * e; apply(); if (p < 1) tw = requestAnimationFrame(step); };
    tw = requestAnimationFrame(step);
  };
  svg.addEventListener("wheel", e => {
    if (!base || !isZoomWheel(e)) return;
    e.preventDefault();
    const [px, py] = world(e); to(k * wheelFactor(e), px, py, false);
  }, { passive: false });
  svg.addEventListener("dblclick", e => { if (!base) return; const [px, py] = world(e); to(e.shiftKey ? k / 2 : k * 2, px, py); });
  svg.addEventListener("pointerdown", e => { if (k > 1.01 && e.button === 0) drag = { x: e.clientX, y: e.clientY, cx, cy, moved: false }; });
  svg.addEventListener("pointermove", e => {
    if (!drag) return;
    const r = svg.getBoundingClientRect(), dx = (e.clientX - drag.x) / r.width * base.w / k, dy = (e.clientY - drag.y) / r.height * base.h / k;
    if (!drag.moved && Math.hypot(e.clientX - drag.x, e.clientY - drag.y) < 4) return;
    drag.moved = true; host.classList.add("grabbing");
    cx = drag.cx - dx; cy = drag.cy - dy; apply();
  });
  const end = () => { if (drag && drag.moved) svg.addEventListener("click", ev => ev.stopPropagation(), { capture: true, once: true }); drag = null; host.classList.remove("grabbing"); };
  svg.addEventListener("pointerup", end); svg.addEventListener("pointerleave", end);
  const api = {
    base(x, y, w, h) { const first = !base || base.w !== w || base.h !== h; base = { x, y, w, h }; if (first && k === 1) { cx = x + w / 2; cy = y + h / 2; } apply(); },
    focus(x, y, w, h) { const k2 = Math.min(max, Math.max(1, Math.min(base.w / w, base.h / h) * 0.8)); const k0 = k, x0 = cx, y0 = cy, x1 = x + w / 2, y1 = y + h / 2, t0 = performance.now();
      cancelAnimationFrame(tw); const step = t => { const p = Math.min(1, Math.max(0, (t - t0) / 520)), e = 1 - Math.pow(1 - p, 3); k = k0 + (k2 - k0) * e; cx = x0 + (x1 - x0) * e; cy = y0 + (y1 - y0) * e; apply(); if (p < 1) tw = requestAnimationFrame(step); }; tw = requestAnimationFrame(step); },
    fit() { to(1, cx, cy); },
    get k() { return k; },
  };
  zoomCtl(host, { zin: () => to(k * 1.5, cx, cy), zout: () => to(k / 1.5, cx, cy), fit: () => api.fit(), at: (e, f) => { if (!base) return; const [px, py] = world(e); to(k * f, px, py); } });
  return api;
}

/* ---------------------------------------------------------------- numbers that roll to their new value */
const LASTNUM = new Map();
function rollNumbers(root) {
  root.querySelectorAll(".tstat").forEach(t => {
    const v = t.querySelector(".v"), key = (t.querySelector(".k")?.textContent || "") + "|" + location.hash;
    const node = v && [...v.childNodes].find(n => n.nodeType === 3 && /\d/.test(n.textContent));
    if (!node) return;
    const m = node.textContent.match(/^(\D*)([\d,]+(?:\.\d+)?)(.*)$/s);
    if (!m) return;
    const target = parseFloat(m[2].replace(/,/g, "")), dec = (m[2].split(".")[1] || "").length, comma = m[2].includes(",");
    const from = LASTNUM.has(key) ? LASTNUM.get(key) : 0;
    LASTNUM.set(key, target);
    if (from === target || matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const fmt = x => { const s = x.toFixed(dec); return comma ? Number(s).toLocaleString("en-GB", { minimumFractionDigits: dec, maximumFractionDigits: dec }) : s; };
    const t0 = performance.now();
    const step = t => { const p = Math.min(1, Math.max(0, (t - t0) / 700)), e = 1 - Math.pow(1 - p, 3); node.textContent = m[1] + fmt(from + (target - from) * e) + m[3]; if (p < 1) requestAnimationFrame(step); };
    requestAnimationFrame(step);
  });
}
new MutationObserver(ms => { for (const m of ms) for (const n of m.addedNodes) if (n.nodeType === 1 && (n.classList.contains("tstat") || n.querySelector?.(".tstat"))) { rollNumbers(m.target.closest?.("#view") || document); return; } })
  .observe(document.getElementById("view"), { childList: true, subtree: true });

/* ---------------------------------------------------------------- threat map
   Heuristic detections from the collector (connection log, DNS log, devices, checks), plus unexplained
   regular timers from the beacon finder. The map puts the local network in the middle, the router and the
   uplink as two walls, and the internet outside, split into attack tactics. Every finding is a vector from its
   device to its tactic; a contained one stops at the wall that caught it. */
const TACTICS = ["Initial access", "Discovery", "Lateral movement", "Defense evasion", "Persistence", "Credential access", "Collection", "Command and control", "Exfiltration", "Impact"];
const SEV = { critical: ["Critical", "--crit", 5], high: ["High", "--crit", 4], medium: ["Medium", "--warn", 3], low: ["Low", "--c3", 2], info: ["Info", "--ink-3", 1] };
VIEWS.threats = main => {
  main.innerHTML = `<div class="head"><h1>Threat map</h1><p>Heuristic detections, mapped to attack tactics. They flag patterns worth a look, not verdicts.</p><div class="grow"></div><span id="seg"></span></div>
    <div class="topo-stats" id="thstats"></div>
    <section class="panel"><div class="topo-tools"><span class="topo-hint">Each line runs from a device to the tactic it matches · a shield means the router or the DNS filter contained it · click a line or a device · thumb wheel or pinch to zoom</span></div>
      <div class="th-host" id="thhost"><svg id="thsvg" role="img" aria-label="Attack surface map"></svg><div class="tip th-tip" hidden></div></div>
      <div class="globe-legend">${Object.entries(SEV).map(([k, v]) => `<span><i class="sw" style="background:var(${v[1]})"></i>${v[0]}</span>`).join("")}<span><i class="th-shield-k">⛨</i>Contained</span></div></section>
    <section class="panel" style="margin-top:14px"><div class="ph"><h2>Tactics by device</h2><span class="sub">worst finding in each cell · click to filter</span><a class="right tlink" id="thclear" href="javascript:void 0" hidden>Show all</a></div><div id="thmatrix" class="th-matrix"></div></section>
    <section class="panel" style="margin-top:14px"><div class="ph"><h2>Findings</h2><span class="sub" id="thcount"></span></div><div id="thlist"></div></section>`;
  const svg = $("#thsvg", main), host = $("#thhost", main), tip = $(".th-tip", main);
  const zm = svgZoom(svg, host, { max: 6 });
  let F = [], filter = null, raf = 0;

  function map() {
    const W = Math.max(600, host.clientWidth), H = Math.round(Math.min(680, W * 0.64)), cx = W / 2, cy = H / 2 + 10;
    const R0 = Math.min(W, H) * 0.20, R1 = R0 + 34, R2 = R1 + 26, R3 = Math.min(W, H) / 2 - 36;   // local network, router wall, uplink wall, internet ring
    zm.base(0, 0, W, H); svg.style.height = H + "px";
    const devs = [...new Map(F.map(f => [f.device, f])).values()];
    const FZ = fencedKeys(), lan = devs.filter(d => !FZ.has(d.zone)), iot = devs.filter(d => FZ.has(d.zone));
    const pos = new Map();
    const place = (arr, a0, a1, rr) => arr.forEach((d, i) => { const a = a0 + (i + 0.5) / arr.length * (a1 - a0); pos.set(d.device, [cx + Math.cos(a) * rr, cy + Math.sin(a) * rr]); });
    place(lan, Math.PI * 0.62, Math.PI * 2.28, R0 * 0.62); place(iot, Math.PI * 0.30, Math.PI * 0.55, R0 * 0.68);
    const tacA = t => -Math.PI / 2 + (TACTICS.indexOf(t) + 0.5) / TACTICS.length * Math.PI * 2;
    let h = `<defs><radialGradient id="thglow"><stop offset="0" stop-color="var(--ok)" stop-opacity=".16"/><stop offset="1" stop-color="var(--ok)" stop-opacity="0"/></radialGradient></defs>
      <circle cx="${cx}" cy="${cy}" r="${R3}" class="th-net"/>`;
    TACTICS.forEach((t, i) => {             // tactic sectors on the internet ring
      const a0 = -Math.PI / 2 + i / TACTICS.length * Math.PI * 2, a1 = a0 + Math.PI * 2 / TACTICS.length, am = (a0 + a1) / 2;
      const hot = F.filter(f => f.tactic === t && !f.contained);
      const worst = hot.reduce((m, f) => Math.max(m, SEV[f.sev][2]), 0);
      const col = worst >= 4 ? "--crit" : worst === 3 ? "--warn" : worst ? "--c3" : "--ink-3";
      h += `<path d="M${cx + Math.cos(a0) * R3} ${cy + Math.sin(a0) * R3} A${R3} ${R3} 0 0 1 ${cx + Math.cos(a1) * R3} ${cy + Math.sin(a1) * R3}" class="th-sector" style="stroke:var(${col});opacity:${worst ? 0.9 : 0.25}"/>
        <line x1="${cx + Math.cos(a0) * (R2 + 8)}" y1="${cy + Math.sin(a0) * (R2 + 8)}" x2="${cx + Math.cos(a0) * (R3 + 6)}" y2="${cy + Math.sin(a0) * (R3 + 6)}" class="th-div"/>
        <text x="${cx + Math.cos(am) * (R3 + 18)}" y="${cy + Math.sin(am) * (R3 + 18) + 4}" text-anchor="${Math.cos(am) > 0.25 ? "start" : Math.cos(am) < -0.25 ? "end" : "middle"}" class="th-tac ${worst ? "hot" : ""}">${esc(t)}${hot.length ? ` · ${hot.length}` : ""}</text>`;
    });
    h += `<circle cx="${cx}" cy="${cy}" r="${R2}" class="th-wall uplink"/><circle cx="${cx}" cy="${cy}" r="${R1}" class="th-wall rtr"/>
      <text class="th-wl" x="${cx}" y="${cy - R2 - 6}" text-anchor="middle">${esc(cap(upName()))} · outer wall</text><text class="th-wl" x="${cx}" y="${cy - R1 + 14}" text-anchor="middle">${esc(cap(rtrName()))} · firewall and DNS redirect</text>
      <circle cx="${cx}" cy="${cy}" r="${R0}" fill="url(#thglow)"/><circle cx="${cx}" cy="${cy}" r="${R0}" class="th-home"/>
      <path d="M${cx + Math.cos(Math.PI * 0.28) * R0} ${cy + Math.sin(Math.PI * 0.28) * R0} A${R0} ${R0} 0 0 1 ${cx + Math.cos(Math.PI * 0.57) * R0} ${cy + Math.sin(Math.PI * 0.57) * R0}" class="th-iot"/>
      <text class="th-zone" x="${cx + Math.cos(Math.PI * 0.42) * (R0 - 12)}" y="${cy + Math.sin(Math.PI * 0.42) * (R0 - 12)}" text-anchor="middle">Fenced</text>`;
    // vectors, drawn weakest first
    const vec = F.map((f, i) => ({ f, i })).filter(v => pos.has(v.f.device)).sort((a, b) => SEV[a.f.sev][2] - SEV[b.f.sev][2]);
    for (const { f, i } of vec) {
      const [x0, y0] = pos.get(f.device), a = tacA(f.tactic) + ((i * 0.618) % 1 - 0.5) * 0.3;
      const stopR = f.contained ? R1 : f.tactic === "Lateral movement" ? R0 * 0.3 : R3 - 4;
      const x1 = cx + Math.cos(a) * stopR, y1 = cy + Math.sin(a) * stopR, mx = (x0 + x1) / 2 + (cy - (y0 + y1) / 2) * 0.12, my = (y0 + y1) / 2 + ((x0 + x1) / 2 - cx) * 0.12;
      const w = 1.2 + Math.min(4, Math.log10(1 + f.count) * 1.4), dim = filter && !(filter.device === f.device && (!filter.tactic || filter.tactic === f.tactic));
      h += `<g class="th-vec sev-${f.sev}${f.contained ? " cont" : ""}${dim ? " dim" : ""}" data-i="${i}"><path d="M${x0} ${y0} Q${mx} ${my} ${x1} ${y1}" style="stroke:var(${SEV[f.sev][1]});stroke-width:${w.toFixed(1)}"/>
        <path class="th-hit" d="M${x0} ${y0} Q${mx} ${my} ${x1} ${y1}"/>${f.contained ? `<text x="${x1}" y="${y1 + 4}" text-anchor="middle" class="th-shield">⛨</text>` : `<circle cx="${x1}" cy="${y1}" r="${w + 1.5}" style="fill:var(${SEV[f.sev][1]})"/>`}</g>`;
    }
    for (const d of devs) {
      const [x, y] = pos.get(d.device), worst = F.filter(f => f.device === d.device && !f.contained).reduce((m, f) => Math.max(m, SEV[f.sev][2]), 0);
      h += `<g class="th-dev" data-dev="${esc(d.device)}"><circle cx="${x}" cy="${y}" r="7" style="fill:var(${worst >= 4 ? "--crit" : worst === 3 ? "--warn" : worst ? "--c3" : "--ok"})"/>
        <text x="${x}" y="${y + (y > cy ? 20 : -12)}" text-anchor="middle" class="th-dn">${esc(d.device)}</text></g>`;
    }
    svg.innerHTML = h;
    svg.querySelectorAll(".th-vec").forEach(g => {
      const f = F[+g.dataset.i];
      g.onmouseenter = e => { tip.innerHTML = `<div class="t">${esc(f.tactic)} · ${SEV[f.sev][0]}${f.contained ? " · contained" : ""}</div><div class="r"><strong>${esc(f.title)}</strong></div><div class="r">Device<b>${esc(f.device)}</b></div><div class="r">Seen<b>${f.count.toLocaleString("en-GB")}×</b></div>${f.evidence.slice(0, 3).map(x => `<div class="t mono">${esc(x)}</div>`).join("")}`; tip.hidden = false; placeT(e); };
      g.onmousemove = placeT; g.onmouseleave = () => tip.hidden = true;
      g.onclick = () => { filter = { device: f.device, tactic: f.tactic }; render(); document.getElementById("thf-" + F.indexOf(f))?.scrollIntoView({ behavior: "smooth", block: "center" }); };
    });
    svg.querySelectorAll(".th-dev").forEach(g => g.onclick = () => { filter = filter && filter.device === g.dataset.dev && !filter.tactic ? null : { device: g.dataset.dev }; render(); });
  }
  const placeT = e => { tip.style.left = Math.min(Math.max(e.clientX, 150), innerWidth - 150) + "px"; tip.style.top = e.clientY + "px"; };
  function matrix() {
    const devs = [...new Set(F.map(f => f.device))];
    const used = TACTICS.filter(t => F.some(f => f.tactic === t));
    $("#thmatrix", main).innerHTML = `<table class="thm"><thead><tr><th></th>${used.map(t => `<th>${esc(t)}</th>`).join("")}</tr></thead><tbody>${devs.map(d => `<tr><th>${esc(d)}</th>${used.map(t => {
      const fs = F.filter(f => f.device === d && f.tactic === t);
      if (!fs.length) return `<td></td>`;
      const w = fs.reduce((m, f) => SEV[f.sev][2] > SEV[m.sev][2] ? f : m), all = fs.every(f => f.contained);
      return `<td><button class="thc sev-${w.sev}${all ? " cont" : ""}${filter && filter.device === d && filter.tactic === t ? " on" : ""}" data-d="${esc(d)}" data-t="${esc(t)}" title="${esc(fs.map(f => f.title).join("; "))}">${all ? "⛨ " : ""}${fs.length}</button></td>`;
    }).join("")}</tr>`).join("")}</tbody></table>`;
    main.querySelectorAll(".thc").forEach(b => b.onclick = () => { filter = filter && filter.device === b.dataset.d && filter.tactic === b.dataset.t ? null : { device: b.dataset.d, tactic: b.dataset.t }; render(); });
    $("#thclear", main).hidden = !filter; $("#thclear", main).onclick = () => { filter = null; render(); };
  }
  function list() {
    const show = F.map((f, i) => ({ f, i })).filter(({ f }) => !filter || (f.device === filter.device && (!filter.tactic || f.tactic === filter.tactic)));
    $("#thcount", main).textContent = `${show.length} of ${F.length}`;
    $("#thlist", main).innerHTML = show.map(({ f, i }) => `<article class="thf sev-${f.sev}${f.contained ? " cont" : ""}" id="thf-${i}">
      <div class="thf-h"><span class="sevchip sev-${f.sev}">${SEV[f.sev][0]}</span><span class="thf-t">${esc(f.tactic)}</span>${f.contained ? `<span class="contchip">⛨ Contained</span>` : ""}<b>${esc(f.title)}</b><span class="thf-d">${esc(f.device)}</span><span class="thf-n">${f.count.toLocaleString("en-GB")}×</span></div>
      <div class="thf-b"><div class="thf-ev">${f.evidence.map(x => `<code>${esc(x)}</code>`).join("")}</div><p>${esc(f.advice)}</p>${f.first ? `<div class="muted">First ${esc(stamp(f.first))} · last ${esc(stamp(f.last))}</div>` : ""}</div></article>`).join("") || `<p class="muted">Nothing matches.</p>`;
  }
  function stats() {
    const open = F.filter(f => !f.contained), c = s => open.filter(f => f.sev === s).length;
    const W8 = { critical: 40, high: 20, medium: 8, low: 2, info: 0 };      // open findings only: contained ones do not count
    const score = Math.round(100 * (1 - Math.exp(-open.reduce((t, f) => t + W8[f.sev], 0) / 90))), sc = score >= 60 ? "crit" : score >= 30 ? "warn" : "ok";
    $("#thstats", main).innerHTML =
      tile4("Risk score", `${score}<small> / 100</small>`, score >= 60 ? "several things need a look" : score >= 30 ? "some things are worth a look" : "quiet", sc) +
      tile4("Open findings", open.length, `${c("critical") + c("high")} high · ${c("medium")} medium · ${c("low")} low`, c("critical") + c("high") ? "crit" : "warn") +
      tile4("Contained", F.length - open.length, "caught by the router or the DNS filter", "ok") +
      tile4("Devices involved", new Set(open.map(f => f.device)).size, `across ${new Set(open.map(f => f.tactic)).size} tactics`, "fence");
  }
  const render = () => { map(); matrix(); list(); };
  let data = null;
  async function load(range) {
    let b = null;
    try { [data, b] = await Promise.all([api(`api/threats?range=${range}`), api(`api/beacons?range=${range === "1h" ? "6h" : range}`).catch(() => null)]); } catch { return; }
    const nice = f => f.mac ? groupKey(f.mac, f.device, f.vendor).name : f.device;
    F = data.findings.map(f => ({ ...f, device: nice(f) }));
    if (b) for (const p of b.pairs) {                                  // unexplained regular timers to the outside
      if (!p.external || p.regular < 0.6 || explainTimer(p)) continue;
      F.push({ sev: p.regular >= 0.85 && p.n >= 20 ? "medium" : "low", tactic: "Command and control", title: `Regular timer to ${p.host || p.dst}`, src: p.src, device: p.mac ? groupKey(p.mac, p.device, "").name : p.device,
        zone: zoneKeyOf({ ip: p.src }), count: p.n, first: p.first, last: p.last,
        evidence: [`every ${fmtGap(p.median)}, ${Math.round(p.regular * 100)}% regular, ${p.proto}/${p.port}`, `${p.dst}${p.org ? " · " + p.org : ""}${p.cc ? " · " + p.cc : ""}`],
        advice: "A steady beat to one address can be an app's heartbeat or a control channel. Open the Beacon finder for its full rhythm." });
    }
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    F.sort((a, b) => (a.contained - b.contained) || order[a.sev] - order[b.sev] || b.count - a.count);
    stats(); render();
  }
  const seg = rangeSeg("threats", ["1h", "24h", "7d"], "24h", r => { seg.value = r; load(r); });
  $("#seg", main).replaceWith(seg.node);
  let lastW = 0;
  const ro = new ResizeObserver(() => { const w = host.clientWidth; if (F.length && Math.abs(w - lastW) > 20) { lastW = w; map(); } }); ro.observe(host);
  load(seg.value);
  const iv = setInterval(() => load(seg.value), 120000);
  return () => { cancelAnimationFrame(raf); clearInterval(iv); ro.disconnect(); };
};

/* ---------------------------------------------------------------- story mode
   A hands-free tour for a spare screen: full screen, no sidebar, each view in turn with a
   live caption read from its own tiles. Space pauses, arrows step, Esc leaves. */
const STORY_STEPS = [
  { v: "now", s: 18, t: "The internet link, live" },
  { v: "health", s: 22, t: "How each machine is doing" },
  { v: "topology", s: 22, t: "Every device on its real link", act: [[9, () => document.querySelector(".node.n-dev")?.dispatchEvent(new MouseEvent("click", { bubbles: true }))]] },
  { v: "traffic", s: 20, t: "What the traffic is" },
  { v: "globe", s: 30, t: "Where the data goes", act: [[10, () => document.querySelector(".gc")?.click()], [22, () => document.querySelector("#gclear")?.click()]] },
  { v: "flows", s: 20, t: "Who sends what, where" },
  { v: "datamap", s: 18, t: "Every byte, as area", act: [[9, () => document.querySelector(".dm-box")?.dispatchEvent(new MouseEvent("click", { bubbles: true }))]] },
  { v: "constellation", s: 20, t: "Devices and the companies they talk to" },
  { v: "passports", s: 18, t: "Every device at a glance" },
  { v: "skyline", s: 24, t: "Who used the network, and when", act: [[9, () => document.querySelector("#sv-top")?.click()], [16, () => document.querySelector("#sv-iso")?.click()]] },
  { v: "air", s: 18, t: "Wi-Fi health" },
  { v: "privacy", s: 20, t: "Who chases ads and trackers" },
  { v: "namespace", s: 22, t: "Every name the network looks up", act: [[10, () => document.querySelector(".ns-item")?.click()]] },
  { v: "firsts", s: 18, t: "Names seen for the first time" },
  { v: "dnsspeed", s: 18, t: "How fast names are answered" },
  { v: "senders", s: 18, t: "Who sends data out" },
  { v: "timeline", s: 20, t: "What happened, in order" },
  { v: "beacons", s: 20, t: "Anything calling home on a timer" },
  { v: "threats", s: 26, t: "Threat map" },
  { v: "dpi", s: 22, t: "What the traffic really is, and who is on a VPN" },
  { v: "isp", s: 22, t: "What the ISP sees" },
  { v: "tunnel", s: 22, t: "Everything inside the VPN tunnel", vpn: true },
  { v: "vpncost", s: 18, t: "What the VPN costs", vpn: true },
  { v: "bloat", s: 22, t: "Bufferbloat: delay when the line is full" },
  { v: "ports", s: 16, t: "Every service in use" },
];
const STORY = { on: false, i: 0, t0: 0, paused: false, timers: [], raf: 0, idle: 0 };
function storyEl() {
  let el = document.getElementById("story");
  if (!el) {
    el = document.createElement("div"); el.id = "story";
    el.innerHTML = `<div class="st-cap"><div class="st-step" id="st-step"></div><div class="st-title" id="st-title"></div><div class="st-ins" id="st-ins"></div></div>
      <div class="st-side"><div class="st-clock" id="st-clock"></div><div class="st-ctl"><button id="st-prev" aria-label="Previous">‹</button><button id="st-pause" aria-label="Pause">❚❚</button><button id="st-next" aria-label="Next">›</button><button id="st-exit" aria-label="Leave story mode">✕</button></div></div>
      <div class="st-bar"><i id="st-prog"></i></div><div class="st-dots" id="st-dots"></div>`;
    document.body.appendChild(el);
    $("#st-prev", el).onclick = () => storyGo(STORY.i - 1, -1);
    $("#st-next", el).onclick = () => storyGo(STORY.i + 1);
    $("#st-pause", el).onclick = () => storyPause();
    $("#st-exit", el).onclick = () => storyStop();
  }
  return el;
}
function storyStart() {
  STORY.on = true; document.body.classList.add("kiosk"); storyEl().hidden = false;
  try { document.documentElement.requestFullscreen?.().catch(() => {}); } catch { /* not allowed without a click */ }
  storyGo(0);
  const tick = () => {
    if (!STORY.on) return;
    const st = STORY_STEPS[STORY.i], el = storyEl();
    const p = STORY.paused ? STORY.pausedAt : (performance.now() - STORY.t0) / 1000;
    $("#st-prog", el).style.width = Math.min(100, p / st.s * 100) + "%";
    $("#st-clock", el).textContent = `${locTime(Date.now() / 1000)} ${TZL}`;
    if (!STORY.paused && p >= st.s) storyGo(STORY.i + 1);
    document.body.classList.toggle("st-idle", performance.now() - STORY.idle > 3000);
    STORY.raf = requestAnimationFrame(tick);
  };
  cancelAnimationFrame(STORY.raf); STORY.raf = requestAnimationFrame(tick);
}
function storyGo(i, dir = 1) {
  const n = STORY_STEPS.length;
  i = (i + n) % n;
  for (let k = 0; k < n && STORY_STEPS[i].vpn && !vpnEnabled(); k++) i = (i + (dir < 0 ? -1 : 1) + n) % n;   // VPN steps only when the VPN is enabled
  STORY.i = i; STORY.t0 = performance.now(); STORY.paused = false;
  STORY.timers.forEach(clearTimeout); STORY.timers = [];
  const st = STORY_STEPS[STORY.i], el = storyEl();
  $("#st-pause", el).textContent = "❚❚";
  $("#st-step", el).textContent = `${STORY.i + 1} of ${STORY_STEPS.length}`;
  $("#st-title", el).textContent = st.t;
  $("#st-ins", el).textContent = "";
  $("#st-dots", el).innerHTML = STORY_STEPS.map((s, j) => `<i class="${j === STORY.i ? "on" : ""}" title="${esc(s.t)}"></i>`).join("");
  STORY.expect = st.v; location.hash = "#/" + st.v;          // route() stops Story mode on any other page change
  for (const [sec, fn] of st.act || []) STORY.timers.push(setTimeout(() => { try { fn(); } catch { /* the view may have changed */ } }, sec * 1000));
  // a live insight read from the view's own tiles, changing every few seconds
  const tiles = () => {
    const ts = [...document.querySelectorAll("#view .tstat")].map(t => `${t.querySelector(".k")?.textContent || ""}: ${t.querySelector(".v")?.textContent || ""} · ${t.querySelector(".s")?.textContent || ""}`).filter(x => x.length > 8);
    if (ts.length) return ts;
    const ro = [...document.querySelectorAll("#view .readout")].map(r => r.textContent.replace(/\s+/g, " ").trim()).filter(Boolean);     // the Now page: live readouts
    return ro.length ? ro : [document.querySelector("#view .head p")?.textContent || ""].filter(Boolean);
  };
  let k = 0;
  const show = () => { const ts = tiles(); if (ts.length) { const ins = $("#st-ins", el); ins.classList.remove("in"); void ins.offsetWidth; ins.textContent = ts[k++ % ts.length]; ins.classList.add("in"); } };
  for (let s = 3; s < st.s; s += 5) STORY.timers.push(setTimeout(show, s * 1000));
}
function storyPause() { STORY.paused = !STORY.paused; if (STORY.paused) STORY.pausedAt = (performance.now() - STORY.t0) / 1000; else STORY.t0 = performance.now() - STORY.pausedAt * 1000; $("#st-pause").textContent = STORY.paused ? "▶" : "❚❚"; }
function storyStop(home = true) {
  STORY.on = false; STORY.timers.forEach(clearTimeout); cancelAnimationFrame(STORY.raf);
  document.body.classList.remove("kiosk", "st-idle"); const el = document.getElementById("story"); if (el) el.hidden = true;
  try { if (document.fullscreenElement) document.exitFullscreen(); } catch { /* ignore */ }
  if (home) location.hash = "#/now";
}
addEventListener("keydown", e => {
  if (!STORY.on) return;
  if (e.key === "Escape") storyStop(); else if (e.key === " ") { e.preventDefault(); storyPause(); } else if (e.key === "ArrowRight") storyGo(STORY.i + 1); else if (e.key === "ArrowLeft") storyGo(STORY.i - 1, -1);
});
addEventListener("pointermove", () => { STORY.idle = performance.now(); });
VIEWS.story = main => { main.innerHTML = ""; setTimeout(storyStart, 0); };

/* ---------------------------------------------------------------- fingerprints (DPI lite) and live VPN status
   Short captures on the router are fingerprinted on the collector: first-byte signatures (TLS and its server
   name, QUIC, WireGuard, OpenVPN, IPsec, STUN, SSH ...) and behaviour from packet sizes and timing.
   The top strip says, per device and right now, whether its traffic is inside a VPN tunnel. */
const FP_COL = {
  "TLS": "#2F5BEA", "TLS (session already running)": "#6887F2", "QUIC": "#0E8C7E", "QUIC (session already running)": "#1FA593",
  "WireGuard": "#C0362C", "Tailscale (WireGuard)": "#C4692D", "Tailscale disco": "#D4773E", "OpenVPN (UDP)": "#A01F4B", "OpenVPN (TCP)": "#A01F4B",
  "IPsec (IKEv2)": "#7A1F1F", "IPsec (ESP in UDP)": "#7A1F1F", "IPsec (ESP)": "#7A1F1F", "WireGuard (by port)": "#C0362C", "Tor (likely)": "#4B0082",
  "STUN": "#8A4FD1", "DTLS": "#A274E0", "SSH": "#3E8E5A", "HTTP (unencrypted)": "#E0B23A", "HTTP (inside the house)": "#C9B27A", "HTTP (local)": "#C9B27A", "DNS (unencrypted)": "#7A828D",
  "NTP": "#9AA1AB", "Local discovery": "#B5BAC2", "Unknown encrypted": "#5B2A86", "Unknown": "#8B929C", "Unidentified": "#C5C9CF",
};
const fpCol = l => FP_COL[l] || "#8B929C";
const VPN_ST = {
  vpn: ["On VPN", "ok", "🛡"], leak: ["VPN, but leaking", "crit", "⚠"], direct: ["Not on VPN", "", "○"], maybe: ["Possibly VPN", "warn", "◐"],
};
/* Capture points: one per zone (its bridge, from zone.iface, else "br-" + key) and the router's internet side. */
function captureIfaces() {
  const s = site();
  return [...s.zones.map(z => ({ iface: z.iface || "br-" + z.key, name: z.name })), { iface: s.router.wan_iface || "wan", name: "the internet side" }];
}
VIEWS.dpi = main => {
  main.innerHTML = `<div class="head"><h1>Fingerprints</h1><p>What the traffic really is, from its first bytes and its rhythm. Captures are short, metadata only, and never stored.</p></div>
    <section class="panel vpn-strip"><div class="ph"><h2>VPN right now</h2><span class="sub" id="vpnsub"></span><span class="right muted" id="vpnlive"></span></div><div id="vpncards" class="vpn-cards"></div></section>
    <div class="topo-stats" id="fpstats" style="margin-top:14px"></div>
    <section class="panel"><div class="topo-tools">
        ${captureIfaces().map(c => `<button class="mplay" data-if="${esc(c.iface)}">⏺ Capture ${esc(c.name)}</button>`).join("")}
        <span class="fp-prog" id="fpprog" hidden><i></i></span><span class="topo-hint" id="fpmeta"></span></div>
      <div class="grid g2">
        <div><div class="ph"><h2>Size against jitter</h2><span class="sub">each circle is one flow · protocols gather in their own places</span></div><div class="fp-host" id="fphost"><svg id="fpsvg" role="img" aria-label="Flows by packet size and jitter"></svg><div class="tip fp-tip" hidden></div></div></div>
        <div><div class="ph"><h2>What was seen</h2><span class="sub" id="fpmixsub"></span></div><div id="fpmix"></div></div>
      </div></section>
    <section class="panel" style="margin-top:14px"><div class="ph"><h2>Flows, with their rhythm</h2><span class="sub">each bar is a packet: up from the device above the line, down below · click a row for the evidence</span>
      <input class="search" type="search" id="fpq" placeholder="Filter" aria-label="Filter flows" style="margin-left:auto"></div><div id="fplist"></div></section>`;
  const svg = $("#fpsvg", main), host = $("#fphost", main), tip = $(".fp-tip", main);
  const zm = svgZoom(svg, host, { max: 8 });
  let data = null, run = null, q = "", open = null, tick = 0;

  function vpnCards(list) {
    $("#vpncards", main).innerHTML = list.map(v => {
      const [lab, cls, ic] = VPN_ST[v.status];
      const t = v.tunnels[0];
      const nm = v.mac ? groupKey(v.mac, v.name, v.vendor).name : v.name;
      const alarm = v.expected && (v.status === "direct" || v.status === "leak");
      return `<div class="vpn-card st-${v.status}${alarm ? " alarm" : ""}">
        <div class="vc-top"><span class="vc-ic">${ic}</span><b>${esc(nm)}</b>
          <label class="vc-exp" title="Warn me when this device is not on a VPN"><input type="checkbox" data-mac="${esc(v.mac)}" ${v.expected ? "checked" : ""} ${v.mac ? "" : "disabled"}> needs VPN</label></div>
        <div class="vc-st ${cls}">${alarm ? "Should be on VPN, is not" : lab}</div>
        <div class="vc-d">${t ? `${esc(t.provider || "")} · ${esc(v.tunnels.map(x => x.label).filter((x, i, a) => a.indexOf(x) === i).join(" + "))}${t.guess ? " (by behaviour)" : ""}<br>to ${esc(t.remote)}:${t.rport}/${t.proto} since ${locTime(t.since)} ${TZL}` : `${v.direct} direct ${v.direct === 1 ? "destination" : "destinations"} now`}</div>
        ${v.leaks && v.leaks.length ? `<div class="vc-l">Outside the tunnel: ${v.leaks.map(l => `${esc(l.to)}${l.org ? " (" + esc(shortOrg(l.org)) + ")" : ""} ${l.share}%`).join(", ")}</div>` : ""}
        <div class="vc-f">DNS via the DNS filter: ${v.dns_10min} in 10 min${v.status !== "direct" && v.dns_10min === 0 ? " (quiet, as a VPN would make it)" : ""}</div></div>`;
    }).join("") || `<p class="muted">No device is talking to the internet right now.</p>`;
    main.querySelectorAll(".vc-exp input").forEach(b => b.onchange = async () => { await post("api/vpn/expect", { mac: b.dataset.mac, on: b.checked }); loadVpn(); });
    const on = list.filter(v => v.status === "vpn").length, leak = list.filter(v => v.status === "leak").length;
    $("#vpnsub", main).textContent = `${on} on a VPN · ${leak} leaking · ${list.length - on - leak} direct`;
  }
  function scatter(flows) {
    const W = Math.max(300, host.clientWidth), H = 330, L = 44, R = 12, T = 12, B = 34;   // drawn at real size: axis text never shrinks
    zm.base(0, 0, W, H); svg.style.height = H + "px";
    const fs = flows.filter(f => f.jitter_ms != null && f.pkts >= 4);
    const x = s => L + Math.min(1, s / 1500) * (W - L - R);
    const y = j => T + (1 - Math.min(1, Math.log10(1 + j) / Math.log10(1 + 10000))) * (H - T - B);
    const maxP = Math.max(1, ...fs.map(f => f.pkts));
    let h = "";
    for (const j of [1, 10, 100, 1000, 10000]) h += `<line x1="${L}" x2="${W - R}" y1="${y(j)}" y2="${y(j)}" class="bc-grid"/><text x="${L - 6}" y="${y(j) + 4}" text-anchor="end" class="bc-ax">${j >= 1000 ? j / 1000 + " s" : j + " ms"}</text>`;
    for (const s of [0, 300, 600, 900, 1200, 1500]) h += `<line x1="${x(s)}" x2="${x(s)}" y1="${T}" y2="${H - B}" class="bc-grid"/><text x="${x(s)}" y="${H - B + 15}" text-anchor="middle" class="bc-ax">${s}</text>`;
    h += `<text x="${L + (W - L - R) / 2}" y="${H - 3}" text-anchor="middle" class="bc-at">Average packet size (bytes)</text><text transform="translate(12 ${T + (H - T - B) / 2}) rotate(-90)" text-anchor="middle" class="bc-at">Jitter</text>`;
    fs.forEach((f, i) => { h += `<circle class="fp-dot${f.tunnel ? " tun" : ""}" data-i="${flows.indexOf(f)}" cx="${x(f.mean_size).toFixed(1)}" cy="${y(f.jitter_ms).toFixed(1)}" r="${(3 + 11 * Math.sqrt(f.pkts / maxP)).toFixed(1)}" fill="${fpCol(f.label)}"/>`; });
    svg.innerHTML = h;
    svg.querySelectorAll(".fp-dot").forEach(c => {
      const f = flows[+c.dataset.i];
      c.onmouseenter = e => { tip.innerHTML = tipFlow(f); tip.hidden = false; placeTip(e); };
      c.onmousemove = placeTip; c.onmouseleave = () => tip.hidden = true;
      c.onclick = () => { open = f; list(); document.getElementById("fpr-" + run.flows.indexOf(f))?.scrollIntoView({ behavior: "smooth", block: "center" }); };
    });
  }
  const placeTip = e => { tip.style.left = Math.min(Math.max(e.clientX, 150), innerWidth - 150) + "px"; tip.style.top = e.clientY + "px"; };
  const devName = f => f.mac ? groupKey(f.mac, f.device, f.vendor).name : f.device;
  function tipFlow(f) {
    return `<div class="t">${esc(devName(f))} → ${esc(f.rname || f.remote)}${f.cc ? " " + flagOf(f.cc) : ""}</div><div class="r"><strong>${esc(f.label)}</strong></div>
      <div class="r">Behaviour<b>${esc(f.behaviour)}</b></div><div class="r">Packets<b>${f.pkts} (${f.pkts_up} up, ${f.pkts_dn} down)</b></div>
      <div class="r">Average size<b>${f.mean_size} B</b></div><div class="r">Jitter<b>${f.jitter_ms != null ? f.jitter_ms + " ms" : "–"}</b></div>
      ${f.evidence.slice(0, 2).map(e => `<div class="t">${esc(e)}</div>`).join("")}`;
  }
  function wave(f, w = 220, h = 30) {
    const tr = f.trace || [];
    if (!tr.length) return "";
    const t1 = Math.max(0.001, tr[tr.length - 1][0]), mx = 1500;
    return `<svg class="fp-wave" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none"><line x1="0" x2="${w}" y1="${h / 2}" y2="${h / 2}" class="fp-axis"/>${tr.map(([t, s]) => {
      const X = (t / t1) * (w - 2), hh = Math.max(1, Math.min(1, Math.abs(s) / mx) * (h / 2 - 1));
      return `<rect x="${X.toFixed(1)}" y="${s > 0 ? h / 2 - hh : h / 2}" width="1.3" height="${hh.toFixed(1)}" class="${s > 0 ? "up" : "dn"}"/>`;
    }).join("")}</svg>`;
  }
  function list() {
    if (!run) return;
    const fs = run.flows.filter(f => f.pkts >= 2 && (!q || `${f.device} ${f.label} ${f.rname} ${f.remote} ${f.org} ${f.service || ""}`.toLowerCase().includes(q)));
    $("#fplist", main).innerHTML = `<div class="fp-rows">${fs.slice(0, 150).map(f => { const i = run.flows.indexOf(f); return `<div class="fp-row${open === f ? " open" : ""}${f.tunnel ? " tun" : ""}" id="fpr-${i}" data-i="${i}">
      <span class="fp-lab" style="--c:${fpCol(f.label)}">${esc(f.label)}</span>
      <span class="fp-who"><b>${esc(devName(f))}</b> → ${esc(f.rname || f.remote)}${f.cc ? " " + flagOf(f.cc) : ""}<small>${f.proto}/${f.rport}${f.org ? " · " + esc(shortOrg(f.org)) : ""}</small></span>
      <span class="fp-chips">${f.service ? `<i class="chip pr">${esc(f.service)}</i>` : ""}${f.tunnel ? `<i class="chip tn">tunnel${f.provider ? ": " + esc(f.provider) : ""}</i>` : ""}${f.ech ? `<i class="chip">ECH</i>` : ""}${f.pq ? `<i class="chip">post-quantum</i>` : ""}<i class="chip bh">${esc(f.behaviour)}</i></span>
      ${wave(f)}<span class="fp-n">${f.pkts} pk${f.jitter_ms != null ? ` · ${f.jitter_ms} ms` : ""}</span>
      ${open === f ? `<div class="fp-ev">${f.evidence.map(e => `<code>${esc(e)}</code>`).join("")}${f.alpn && f.alpn.length ? `<code>ALPN ${esc(f.alpn.join(", "))}</code>` : ""}<code>${f.lan}:${f.lport} → ${f.remote}:${f.rport}</code><code>${f.bytes_up} B up · ${f.bytes_dn} B down · ${f.dur} s · ${f.pps} packets/s</code>${f.cv != null ? `<code>beat regularity (lower is steadier): ${f.cv}</code>` : ""}</div>` : ""}</div>`; }).join("")}</div>`;
    main.querySelectorAll(".fp-row").forEach(r => r.onclick = () => { const f = run.flows[+r.dataset.i]; open = open === f ? null : f; list(); });
  }
  function mix() {
    const c = new Map(); run.flows.forEach(f => c.set(f.label, (c.get(f.label) || 0) + f.pkts));
    const tot = [...c.values()].reduce((a, b) => a + b, 0) || 1;
    $("#fpmixsub", main).textContent = `${run.n} flows, ${run.pkts.toLocaleString("en-GB")} packets in ${run.secs} s on ${(captureIfaces().find(c => c.iface === run.iface) || { name: run.iface }).name}`;
    $("#fpmix", main).innerHTML = [...c].sort((a, b) => b[1] - a[1]).map(([l, n]) => `<div class="fp-mix"><span><i class="sw" style="background:${fpCol(l)}"></i>${esc(l)}</span><i class="bar" style="width:${(100 * n / tot).toFixed(1)}%;background:${fpCol(l)}"></i><b>${(100 * n / tot).toFixed(n / tot < 0.01 ? 1 : 0)}%</b></div>`).join("");
  }
  function stats() {
    const fs = run.flows.filter(f => !f.inside), tot = fs.reduce((a, f) => a + f.pkts, 0) || 1;   // internet traffic only
    const ident = fs.filter(f => f.conf >= 0.6).reduce((a, f) => a + f.pkts, 0), enc = fs.filter(f => f.encrypted).reduce((a, f) => a + f.pkts, 0);
    $("#fpstats", main).innerHTML =
      tile4("Identified", `${Math.round(100 * ident / tot)}<small>%</small>`, "of internet packets matched a signature or strong hint") +
      tile4("Encrypted", `${Math.round(100 * enc / tot)}<small>%</small>`, "of internet packets in encrypted protocols", "ok") +
      tile4("Tunnels", fs.filter(f => f.tunnel).length, esc(fs.filter(f => f.tunnel).map(f => devName(f) + ": " + (f.provider || f.label)).slice(0, 2).join(" · ")) || "no VPN or tunnel in this capture", "ug") +
      tile4("Unencrypted to the internet", fs.filter(f => f.label.startsWith("HTTP")).length, "plain HTTP flows leaving the network", "warn");
  }
  async function loadVpn() {
    try { const v = await api("api/vpn"); vpnCards(v.vpn); $("#vpnlive", main).textContent = `live · ${locTime(v.now)} ${TZL} · last capture ${v.last_capture ? ago(v.last_capture) : "none yet"}`; } catch { /* keep the last view */ }
  }
  async function load() {
    try { data = await api("api/dpi"); } catch { return; }
    vpnCards(data.vpn);
    run = data.runs[0] || null;
    $("#fpmeta", main).textContent = data.error ? `Last capture failed: ${data.error}` : run ? `Last capture ${stamp(run.ts)} · automatic every ${Math.round(data.every / 60)} min, taking the zones in turn` : "No capture yet. The first automatic one runs shortly after start.";
    if (run) { stats(); mix(); scatter(run.flows); list(); }
  }
  main.querySelectorAll("[data-if]").forEach(b => b.onclick = async () => {
    const r = await post("api/dpi/capture", { iface: b.dataset.if, secs: 12 });
    if (!r.ok) { $("#fpmeta", main).textContent = r.error; return; }
    const p = $("#fpprog", main); p.hidden = false; const bar = p.querySelector("i"), t0 = Date.now();
    const iv = setInterval(() => { const k = Math.min(1, (Date.now() - t0) / 15000); bar.style.width = k * 100 + "%"; if (k >= 1) { clearInterval(iv); p.hidden = true; load(); } }, 200);
  });
  $("#fpq", main).oninput = e => { q = e.target.value.toLowerCase(); list(); };
  load();
  const iv1 = setInterval(loadVpn, 10000), iv2 = setInterval(load, 60000);
  return () => { clearInterval(iv1); clearInterval(iv2); };
};

/* ---------------------------------------------------------------- live VPN indicator (sidebar, every page) */
async function vpnIndicator() {
  const el = document.getElementById("vpnind");
  if (!el) return;
  let v; try { v = (await api("api/vpn")).vpn; } catch { return; }
  const nm = x => x.mac ? groupKey(x.mac, x.name, x.vendor).name : x.name;
  const on = v.filter(x => x.status === "vpn"), leak = v.filter(x => x.status === "leak"), miss = v.filter(x => x.expected && x.status === "direct");
  el.hidden = !(on.length || leak.length || miss.length);
  el.className = "vpnind" + (leak.length || miss.length ? " bad" : "");
  el.innerHTML = [
    ...miss.map(x => `<span>⚠ ${esc(nm(x))}: not on VPN</span>`),
    ...leak.map(x => `<span>⚠ ${esc(nm(x))}: VPN leaking</span>`),
    ...on.map(x => `<span>🛡 ${esc(nm(x))}: ${esc((x.tunnels[0] || {}).provider || "VPN")}</span>`),
  ].join("");
}
vpnIndicator(); setInterval(vpnIndicator, 20000);

/* ---------------------------------------------------------------- what the internet provider sees
   A handshake-only look at the router's internet side: the view from outside the network. Every outgoing
   connection is sorted by what the ISP can read. When the VPN is enabled, its switch is shown here and
   the page compares a look with the VPN off against one with it on. */
const ISP_SEEN = {
  leak: ["Plain DNS leaking", "--crit", "They read the name you looked up"],
  full: ["Whole address readable", "--crit", "Unencrypted web: every word"],
  name: ["Site name readable", "--warn", "The name travels in the open"],
  address: ["Address and owner only", "--c3", "They see which company, not which page"],
  hidden: ["Name hidden (ECH)", "--ok", "Encrypted Client Hello"],
  "dns-encrypted": ["Encrypted DNS", "--ok", "They see you use it, not what you ask"],
  vpn: ["Inside the VPN", "--ok", "One tunnel to the VPN server, nothing inside visible"],
};
VIEWS.isp = main => {
  main.innerHTML = `<div class="head"><h1>What the ISP sees</h1><p>The view from outside your network: what ${esc(ispName())} can read, and what stays hidden.</p></div>
    <section class="panel vpn-switch" id="vsw" ${vpnEnabled() ? "" : "hidden"}></section>
    <div class="topo-stats" id="ispstats" style="margin-top:14px"></div>
    <section class="panel isp-delta" id="ispdelta" style="margin-top:14px" ${vpnEnabled() ? "" : "hidden"}></section>
    <section class="panel" style="margin-top:14px"><div class="topo-tools"><button class="mplay" id="isplook">👁 Look through the ISP's eyes (20 s)</button><span class="fp-prog" id="ispprog" hidden><i></i></span><span class="topo-hint" id="ispmeta"></span></div>
      <div class="isp-legend">${Object.entries(ISP_SEEN).map(([k, v]) => `<span><i style="background:var(${v[1]})"></i>${v[0]}</span>`).join("")}</div>
      <div id="isplist"></div></section>
    <section class="panel" style="margin-top:14px"><div class="ph"><h2>How it works, and what else gives you away</h2></div><div id="ispnotes" class="isp-notes"></div></section>`;
  let data = null, sw = null, busy = false;
  const nm = i => i.mac ? groupKey(i.mac, i.device, i.vendor).name : i.device;
  function dnsLine(d) {                     // where the DNS filter's own questions go while the VPN is on or off
    if (!d) return "";
    if (d.have === "partial") return `DNS: <b class="crit-t">redirect only half in place</b>, lookups may bypass the tunnel`;
    if (d.want !== d.have) return `DNS: <b class="warn-t">settling</b>, switching to ${d.want === "tunnel" ? "the tunnel" : "direct"}`;
    if (d.have === "tunnel") return d.vpn_resolver ? `DNS: <b>inside the tunnel</b>, through ${esc(vpnLabel())}` : `DNS: <b class="crit-t">tunnel resolver not running</b>, lookups will fail`;
    return `DNS: straight out through ${esc(ispName())}`;
  }
  function switchPanel() {
    if (!vpnEnabled() || (sw && sw.enabled === false)) { $("#vsw", main).hidden = true; return; }
    const s = sw && sw.switch || {}, ip = sw && sw.ip, on = s.on, up = s.up;
    const hs = s.handshake ? Math.max(0, s.now - s.handshake) : null;
    $("#vsw", main).innerHTML = `<div class="vs-row">
      <button class="vs-toggle ${on ? "on" : ""}" id="vstog" ${busy || (sw && sw.busy) || (sw && sw.can_switch === false) ? "disabled" : ""} title="${sw && sw.can_switch === false ? "Switching is off: set actions.vpn_switch in config.json" : ""}" aria-pressed="${!!on}"><i></i></button>
      <div class="vs-txt"><b>${esc(vpnLabel())} for the whole network: ${busy || (sw && sw.busy) ? "switching…" : on ? (up ? "ON" : "ON, tunnel not up") : "OFF"}</b>
        <span>${esc(sw ? sw.profile : "")}</span>
        <span>${on && hs != null ? `last handshake ${hs} s ago · ` : ""}Your address on the internet: <b>${ip ? esc(ip.ip) : "?"}</b>${ip && ip.cc ? " " + flagOf(ip.cc) : ""}${ip && ip.org ? " · " + esc(shortOrg(ip.org)) : ""}</span>
        <span>${dnsLine(s.dns)}</span></div>
      <div class="vs-last">${sw && sw.last ? `Last switch: ${esc(sw.last.result)} at ${locTime(sw.last.ts)} ${TZL}` : ""}</div></div>`;
    $("#vstog", main).onclick = async () => {
      busy = true; switchPanel();
      await post("api/vpnswitch", { on: !on });
      const t0 = Date.now();
      const poll = setInterval(async () => { sw = await api("api/vpnswitch").catch(() => sw); if (!sw.busy || Date.now() - t0 > 90000) { clearInterval(poll); busy = false; switchPanel(); } }, 3000);
    };
  }
  function delta() {
    if (!vpnEnabled()) return;
    const b = data.by_vpn || {}, off = b.off, on = b.on;
    const col = (r, title) => r ? `<div class="dl-col"><h3>${title}</h3><div class="dl-when">${stamp(r.ts)}</div>
        <div class="dl-big"><b>${(r.names || []).length}</b> site names the ISP could read</div>
        <div class="dl-big"><b>${(r.orgs || []).length}</b> companies they could see you talk to</div>
        <div class="dl-bars">${Object.entries(ISP_SEEN).map(([k, v]) => { const n = (r.counts || {})[k] || 0; return n ? `<div class="dl-bar"><span><i style="background:var(${v[1]})"></i>${v[0]}</span><b>${n}</b></div>` : ""; }).join("")}</div>
        <div class="dl-names">${(r.names || []).slice(0, 18).map(n => `<code>${esc(n)}</code>`).join("") || `<span class="muted">none</span>`}</div></div>`
      : `<div class="dl-col empty"><h3>${title}</h3><p class="muted">No look taken yet with the VPN ${title.includes("off") ? "off" : "on"}. ${title.includes("off") ? "Switch it off" : "Switch it on"} and press "Look through the ISP's eyes".</p></div>`;
    $("#ispdelta", main).innerHTML = `<div class="ph"><h2>The difference a VPN makes</h2><span class="sub">what the ISP could read, VPN off against VPN on</span></div>
      <div class="dl-grid">${col(off, "VPN off")}<div class="dl-arrow">→</div>${col(on, "VPN on")}</div>`;
  }
  function stats() {
    const r = data.run;
    if (!r) { $("#ispstats", main).innerHTML = ""; return; }
    const c = r.counts || {}, tot = r.n || 1, readable = (c.name || 0) + (c.full || 0) + (c.leak || 0);
    $("#ispstats", main).innerHTML =
      tile4("Readable to the ISP", `${Math.round(100 * readable / tot)}<small>%</small>`, `${readable} of ${r.n} connections show a site name`, readable ? "warn" : "ok") +
      tile4("Hidden", `${Math.round(100 * ((c.hidden || 0) + (c.vpn || 0) + (c["dns-encrypted"] || 0)) / tot)}<small>%</small>`, "names hidden by ECH, the VPN or encrypted DNS", "ok") +
      tile4("Your DNS", c.leak ? "LEAKING" : "Encrypted", c.leak ? "plain DNS left the network" : "they cannot see what you look up", c.leak ? "crit" : "ok") +
      tile4("Plain web addresses", c.full || 0, c.full ? "full addresses readable, see the red rows" : "none in this look", c.full ? "crit" : "ok");
  }
  function list() {
    const r = data.run;
    $("#ispmeta", main).textContent = data.error ? data.error : r ? `Last look ${stamp(r.ts)} · ${r.secs} s · VPN ${r.vpn ? "on" : "off"} · ${r.n} connections` : "No look yet. Press the button.";
    if (!r) { $("#isplist", main).innerHTML = ""; return; }
    const grp = new Map();                     // identical rows (same device, verdict and name) become one row with a count
    for (const i of r.items) { const k = [nm(i), i.seen, i.name || i.org || i.dst, i.dport].join("|"); const g = grp.get(k); if (g) g.n++; else grp.set(k, { ...i, n: 1 }); }
    $("#isplist", main).innerHTML = `<div class="isp-rows"><div class="isp-h"><span>Inside your network</span><span></span><span>What the ISP sees</span></div>${[...grp.values()].map(i => {
      const [lab, col, sub] = ISP_SEEN[i.seen];
      const clear = ["leak", "full", "name"].includes(i.seen);
      const theirs = i.seen === "full" ? `${i.method || "GET"} http://${esc(i.name)}${esc(i.path || "")}${i.query ? "?…" : ""}` : clear ? esc(i.name) : i.seen === "vpn" ? "VPN server" : esc(i.org ? shortOrg(i.org) : i.dst);
      return `<div class="isp-row s-${i.seen}"><span class="isp-in"><b>${esc(nm(i))}</b>${esc(i.inside_name || i.name || i.dst)}</span>
        <span class="isp-wall" style="--c:var(${col})"></span>
        <span class="isp-out"><em class="${clear ? "clear" : "blur"}">${theirs}${i.n > 1 ? ` <b class="isp-n">×${i.n}</b>` : ""}</em><small>${esc(i.dst)}${i.cc ? " " + flagOf(i.cc) : ""} · ${i.proto}/${i.dport} · ${esc(i.why)}</small></span></div>`;
    }).join("")}</div>`;
  }
  function notes() {
    const r = data.run, t = r ? r.ttl || {} : {};
    $("#ispnotes", main).innerHTML = `
      <p><b>Your DNS.</b> ${esc(data.dns_path || "")} ${sw && sw.switch && sw.switch.dns && sw.switch.dns.have === "tunnel" ? "With the VPN on, those questions travel inside the tunnel, so the ISP cannot even see which resolver you use." : "If the resolver is reached over an encrypted protocol, the ISP sees that traffic and nothing of what you ask."}</p>
      <p><b>Site names in handshakes.</b> When a browser opens a secure connection it says the site's name in the open (the "server name"), unless both sides support Encrypted Client Hello. That is why most names are still readable, even though every page is encrypted.</p>
      <p><b>QUIC is not a hiding place.</b> HTTP/3 looks fully encrypted, but its first packet is sealed with a key anyone can work out from the packet itself. This page does exactly that, the same way an internet provider can.</p>
      <p><b>What your packets say about your devices.</b> Every system starts packets with a set "time to live". Behind the router in this look: ${Object.entries(t).map(([k, v]) => `${esc(k)} ${v}×`).join(", ") || "none seen"}. Counting and timing tricks like this let a provider estimate how many and which kinds of devices you have, even behind one address.</p>
      ${vpnEnabled() ? `<p><b>With the VPN on</b> the ISP sees one steady stream to the VPN server and the amount of data, at what times. The VPN provider sees what the ISP used to see; the trust moves, it does not disappear.</p>` : ""}`;
  }
  async function load() {
    try { [data, sw] = await Promise.all([api("api/isp"), vpnEnabled() ? api("api/vpnswitch") : null]); } catch { return; }
    switchPanel(); delta(); stats(); list(); notes();
  }
  $("#isplook", main).onclick = async () => {
    const r = await post("api/isp/capture", { secs: 20 });
    if (!r.ok) { $("#ispmeta", main).textContent = r.error; return; }
    const p = $("#ispprog", main); p.hidden = false; const bar = p.querySelector("i"), t0 = Date.now();
    const iv = setInterval(() => { const k = Math.min(1, (Date.now() - t0) / 26000); bar.style.width = k * 100 + "%"; if (k >= 1) { clearInterval(iv); p.hidden = true; load(); } }, 250);
  };
  load();
  const iv = setInterval(async () => { if (!vpnEnabled()) return; sw = await api("api/vpnswitch").catch(() => sw); if (!busy) switchPanel(); }, 15000);
  return () => clearInterval(iv);
};

/* ---------------------------------------------------------------- the VPN tunnel
   Everything that leaves the network, and whether it went through the router's VPN. Each local device sends
   its live connections along a strand into the router. Tunnel traffic carries on inside the pipe to the VPN
   server, anything that goes straight out through the ISP peels off in red, and traffic that never reaches
   the internet loops back in grey. The router's connection table says which way each one went. */
const TU_MOTION = !matchMedia("(prefers-reduced-motion: reduce)").matches;
VIEWS.tunnel = main => {
  main.innerHTML = `<div class="head"><h1>Tunnel</h1><p>Everything that leaves the network, and whether it goes through ${esc(vpnLabel())}.</p><div class="grow"></div><span id="seg"></span></div>
    <div class="topo-stats" id="tustats"></div>
    <section class="panel"><div class="ph"><h2>The pipe</h2><span class="sub" id="tusub"></span></div>
      <div class="tu-host" id="tuhost"><svg id="tusvg" role="img" aria-label="Local devices sending their connections through the router into the VPN tunnel"></svg><div class="tip tu-tip" hidden></div></div>
      <div class="globe-legend"><span><i class="sw" style="background:var(--c4)"></i>Through the tunnel</span><span><i class="sw" style="background:var(--crit)"></i>Straight out through ${esc(ispName())}</span><span><i class="sw" style="background:var(--ink-3)"></i>Stays on the local network</span><span class="muted">Moving dots follow each device's live connections</span></div></section>
    <section class="panel" style="margin-top:14px"><div class="ph"><h2>Tunnel over time</h2><span class="sub">data through the tunnel, and the share of internet connections inside the tunnel</span></div><div id="tuhist" class="tu-hist"></div></section>
    <div class="tu-cols">
      <section class="panel"><div class="ph"><h2>Going around the tunnel</h2><span class="sub">live connections that reached the internet outside the tunnel</span></div><div id="tuaround"></div></section>
      <section class="panel"><div class="ph"><h2>Staying local</h2><span class="sub">never reaches the internet</span></div><div id="tuhome"></div></section>
    </div>`;
  const svg = $("#tusvg", main), host = $("#tuhost", main), tip = $(".tu-tip", main);
  let d = null, raf = 0, parts = [], routes = [], hot = null, lastT = 0;
  const ns = "http://www.w3.org/2000/svg";

  function stats() {
    const st = d.status || {}, on = st.on, up = st.up, it = (st.n_tunnel || 0) + (st.n_direct || 0);
    const pct = it ? Math.round(100 * (st.n_tunnel || 0) / it) : 0, ex = d.exit || {}, ep = d.endpoint || {};
    const dns = st.dns ? (st.dns.ok && st.dns.have === "tunnel" ? "DNS inside it" : st.dns.have === "direct" ? "DNS direct" : "DNS not settled") : "";
    $("#tustats", main).innerHTML =
      tile4("Tunnel", on ? (up ? "Up" : "Down") : "Off",
        on ? `handshake ${st.hs_age ?? "?"} s ago · ${ep.place ? esc(ep.place.city) : esc(vpnLabel())} · ${dns}` : `${esc(vpnLabel())} is switched off`, on ? (up ? "ok" : "crit") : "warn") +
      tile4("Inside the tunnel", on ? `${pct}<small>%</small>` : "0<small>%</small>", `${st.n_tunnel || 0} of ${it} internet connections`, on && pct === 100 ? "ok" : "warn") +
      tile4("Around it", st.n_direct || 0, (st.n_direct || 0) ? "reached the internet through the ISP directly" : "nothing leaves outside the tunnel", on && st.n_direct ? "crit" : "ok") +
      tile4("The internet sees you as", `<span class="tu-ip">${esc(ex.ip || "?")}</span>`, `${ex.cc ? flagOf(ex.cc) + " " : ""}${esc(shortOrg(ex.org || ""))}${on ? " · VPN exit" : " · your ISP line"}`, "fence");
    $("#tusub", main).textContent = on ? `VPN server ${ep.ip || "?"}:${ep.port || ""}${ep.place ? " in " + ep.place.city : ""}` : "The VPN is off: the pipe is empty";
  }

  function draw() {
    cancelAnimationFrame(raf);
    const devs = d.devices.filter(x => x.tunnel + x.direct + x.local > 0).slice(0, 14);
    const W = 1000, rowH = 46, H = Math.max(380, devs.length * rowH + 90), cy = H / 2;
    const st = d.status || {}, on = !!st.on, up = on && st.up;
    const FX = 440, FW = 118, PX0 = FX + FW / 2 + 10, PX1 = 850, PR = 34, EX = 912;
    const maxN = Math.max(1, ...devs.map(x => x.tunnel + x.direct + x.local));
    const y0 = cy - (devs.length - 1) * rowH / 2;
    const ep = d.endpoint || {}, ex = d.exit || {};
    let h = `<defs><linearGradient id="tuPipe" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="var(--c4)" stop-opacity=".30"/><stop offset=".5" stop-color="var(--c4)" stop-opacity=".12"/><stop offset="1" stop-color="var(--c4)" stop-opacity=".30"/></linearGradient></defs>`;
    // the pipe to the VPN server
    h += `<rect class="tu-pipe${on ? "" : " off"}${on && !up ? " down" : ""}" x="${PX0}" y="${cy - PR}" width="${PX1 - PX0}" height="${PR * 2}" rx="${PR}"/>`;
    if (up) h += `<line class="tu-flowline" x1="${PX0 + 20}" x2="${PX1 - 20}" y1="${cy}" y2="${cy}"/>`;
    h += `<text class="tu-pipe-l" x="${(PX0 + PX1) / 2}" y="${cy - PR - 10}">${on ? (up ? "Tunnel to the VPN server · encrypted" : "Tunnel down: the kill switch holds traffic") : "Tunnel off"}</text>`;
    // far end: the VPN server, and the ISP for anything that goes around
    h += `<g class="tu-end${on ? "" : " off"}"><circle cx="${EX}" cy="${cy}" r="40"/><text x="${EX}" y="${cy - 4}" class="tu-end-t">${esc(vpnLabel())}</text><text x="${EX}" y="${cy + 14}" class="tu-end-s">${esc(ep.place ? ep.place.city : "server")}</text></g>`;
    h += `<text class="tu-exit" x="${EX}" y="${cy + 62}">${on && ex.ip ? `seen as ${esc(ex.ip)} ${ex.cc ? flagOf(ex.cc) : ""}` : ""}</text>`;
    const VY = H - 36;
    h += `<g class="tu-vf"><rect x="${EX - 62}" y="${VY - 18}" width="124" height="36" rx="18"/><text x="${EX}" y="${VY + 5}">${esc(ispName())} direct</text></g>`;
    // the router
    h += `<g class="tu-rtr"><rect x="${FX - FW / 2}" y="${cy - 30}" width="${FW}" height="60" rx="12"/><text x="${FX}" y="${cy - 4}" class="tu-fl-t">${esc(cap(rtrName()))}</text><text x="${FX}" y="${cy + 15}" class="tu-fl-s">kill switch ${on ? "on" : "idle"}</text></g>`;
    // loop for local traffic
    h += `<path class="tu-home" d="M${FX - 20} ${cy + 30} C ${FX - 20} ${cy + 110}, ${FX + 60} ${cy + 110}, ${FX + 30} ${cy + 30}"/><text class="tu-home-l" x="${FX + 20}" y="${cy + 112}">stays local</text>`;
    // routes after the router, one per egress
    const after = {
      tunnel: `M${FX + FW / 2} ${cy} L${PX1 - 6} ${cy} L${EX - 40} ${cy}`,
      direct: `M${FX + FW / 2} ${cy + 18} C ${FX + 200} ${cy + 40}, ${EX - 160} ${VY}, ${EX - 62} ${VY}`,
      local: `M${FX + 30} ${cy + 30} C ${FX + 60} ${cy + 110}, ${FX - 20} ${cy + 110}, ${FX - 20} ${cy + 30}`,
    };
    if (d.around.length) h += `<path class="tu-direct" d="${after.direct}"/>`;
    // devices and their strands into the router
    devs.forEach((x, i) => {
      const y = y0 + i * rowH, n = x.tunnel + x.direct + x.local, w = 1.2 + 4 * Math.sqrt(n / maxN);
      const cls = x.direct ? "d" : x.tunnel ? "t" : "l";
      h += `<path class="tu-strand s-${cls}" data-i="${i}" id="tus${i}" d="M252 ${y} C ${FX - 150} ${y}, ${FX - 130} ${cy}, ${FX - FW / 2} ${cy}" style="stroke-width:${w.toFixed(1)}"/>`;
      h += `<g class="tu-dev" data-i="${i}" tabindex="0" role="button" aria-label="${esc(x.name)}: ${x.tunnel} through the tunnel, ${x.direct} direct, ${x.local} local"><circle cx="246" cy="${y}" r="6" class="s-${cls}"/>
        <text x="232" y="${y - 3}" class="tu-dn">${esc(x.name)}</text><text x="232" y="${y + 13}" class="tu-dc">${[x.tunnel ? `${x.tunnel} tunnel` : "", x.direct ? `${x.direct} direct` : "", x.local ? `${x.local} local` : ""].filter(Boolean).join(" · ")}</text></g>`;
    });
    h += `<path id="tuA-tunnel" d="${after.tunnel}" class="tu-guide"/><path id="tuA-direct" d="${after.direct}" class="tu-guide"/><path id="tuA-local" d="${after.local}" class="tu-guide"/><g id="tudots"></g>`;
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    svg.innerHTML = h;
    routes = devs.map((x, i) => ({ x, strand: $(`#tus${i}`, svg) }));
    const A = { tunnel: $("#tuA-tunnel", svg), direct: $("#tuA-direct", svg), local: $("#tuA-local", svg) };
    const L = Object.fromEntries(Object.entries(A).map(([k, p]) => [k, p.getTotalLength()]));
    routes.forEach(r => { r.len = r.strand.getTotalLength(); });
    const dots = $("#tudots", svg);
    parts = [];
    const spawn = (r, t0) => {
      const x = r.x, n = x.tunnel + x.direct + x.local, u = Math.random() * n;
      const eg = u < x.tunnel ? "tunnel" : u < x.tunnel + x.direct ? "direct" : "local";
      const c = document.createElementNS(ns, "circle");
      c.setAttribute("r", eg === "tunnel" ? 3.2 : 3.6);
      c.setAttribute("class", "tu-dot e-" + eg);
      dots.appendChild(c);
      parts.push({ r, eg, c, t: t0, v: 0.10 + Math.random() * 0.05, L2: L[eg], P2: A[eg] });
    };
    // each device keeps a number of dots in flight that follows its live connections
    for (const r of routes) { const k = Math.max(1, Math.round(2 + 6 * Math.sqrt((r.x.tunnel + r.x.direct + r.x.local) / maxN))); for (let j = 0; j < k; j++) spawn(r, Math.random()); }
    const place = p => {
      const tot = p.r.len + p.L2, s = p.t * tot;
      const pt = s < p.r.len ? p.r.strand.getPointAtLength(s) : p.P2.getPointAtLength(Math.min(p.L2, s - p.r.len));
      p.c.setAttribute("cx", pt.x.toFixed(1)); p.c.setAttribute("cy", pt.y.toFixed(1));
      p.c.style.opacity = hot == null || hot === p.r ? 1 : 0.15;
    };
    const tick = t => {
      const dt = lastT ? Math.min(0.05, (t - lastT) / 1000) : 0; lastT = t;
      for (const p of parts) {
        const speed = p.eg === "tunnel" && !up ? 0 : p.v;         // a down tunnel with the kill switch holds traffic at the router
        p.t += dt * speed;
        if (p.t >= 1) { p.t = 0; const x = p.r.x, n = x.tunnel + x.direct + x.local, u = Math.random() * n;
          p.eg = u < x.tunnel ? "tunnel" : u < x.tunnel + x.direct ? "direct" : "local"; p.L2 = L[p.eg]; p.P2 = A[p.eg]; p.c.setAttribute("class", "tu-dot e-" + p.eg); }
        if (p.eg === "tunnel" && !up && p.t * (p.r.len + p.L2) > p.r.len) p.t = (p.r.len - 2) / (p.r.len + p.L2);
        place(p);
      }
      raf = requestAnimationFrame(tick);
    };
    if (TU_MOTION) raf = requestAnimationFrame(tick); else parts.forEach(place);
    svg.querySelectorAll(".tu-dev, .tu-strand").forEach(g => {
      const r = routes[+g.dataset.i];
      g.addEventListener("pointerenter", e => { hot = r; svg.classList.add("tu-focus"); routes.forEach(q => q.strand.classList.toggle("hot", q === r)); showTip(e, r.x); if (!TU_MOTION) parts.forEach(place); });
      g.addEventListener("pointermove", e => showTip(e, r.x));
      g.addEventListener("pointerleave", () => { hot = null; svg.classList.remove("tu-focus"); routes.forEach(q => q.strand.classList.remove("hot")); tip.hidden = true; if (!TU_MOTION) parts.forEach(place); });
      g.addEventListener("click", () => { if (r.x.mac) location.hash = `#/devices/${encodeURIComponent(r.x.mac)}`; });
    });
  }
  function showTip(e, x) {
    tip.hidden = false;
    tip.innerHTML = `<div class="t">${esc(x.name)}</div><div class="r"><span>Through the tunnel</span><b>${x.tunnel}</b></div><div class="r"><span>Straight out</span><b>${x.direct}</b></div><div class="r"><span>Stays local</span><b>${x.local}</b></div><div class="r muted"><span>${esc(x.ip)}</span><span>click to open</span></div>`;
    const b = host.getBoundingClientRect();
    tip.style.left = Math.min(Math.max(e.clientX - b.left, 120), b.width - 120) + "px"; tip.style.top = (e.clientY - b.top) + "px";
  }

  function history() {
    const box = $("#tuhist", main), W = Math.max(320, box.clientWidth), H = 190, L = 58, R = 12, T = 12, B = 44;
    const rows = d.history, span = d.span, t1 = d.now, t0 = t1 - span;
    if (rows.length < 2) { box.innerHTML = `<p class="muted">Collecting: the first minutes of tunnel history appear here shortly (sampling started ${rows.length ? stamp(rows[0][0]) : "just now"}).</p>`; return; }
    const x = t => L + (t - t0) / span * (W - L - R);
    const maxB = Math.max(1e5, ...rows.map(r => Math.max(r[4] || 0, r[5] || 0)));
    const y = v => T + (1 - v / maxB) * (H - T - B - 20);
    const gap = 150;
    const area = k => { let p = "", prev = null; for (const r of rows) { if (r[k] == null) { prev = null; continue; } const X = x(r[0]).toFixed(1), Y = y(r[k]).toFixed(1); p += (prev && r[0] - prev < gap ? "L" : "M") + X + " " + Y; prev = r[0]; } return p; };
    let h = "";
    for (const f of [0, 0.5, 1]) h += `<line x1="${L}" x2="${W - R}" y1="${y(maxB * f)}" y2="${y(maxB * f)}" class="bc-grid"/><text x="${L - 6}" y="${y(maxB * f) + 4}" text-anchor="end" class="bc-ax">${bitsText(maxB * f)}</text>`;
    h += `<path d="${area(4)}" class="tu-rx"/><path d="${area(5)}" class="tu-tx"/>`;
    // coverage strip: each minute coloured by the share inside the tunnel; red when the tunnel was down
    const SY = H - B + 2, bw = Math.max(1, (W - L - R) / (span / 60));
    for (const r of rows) {
      const [ts, on, upm, hs, , , nt, nd] = r, it = nt + nd;
      const cls = !on ? "off" : !upm || (hs != null && hs > 180) ? "bad" : it && nd ? "part" : "full";
      h += `<rect x="${x(ts).toFixed(1)}" y="${SY}" width="${bw.toFixed(2)}" height="12" class="tu-cov ${cls}"><title>${locTime(ts)} · ${!on ? "VPN off" : cls === "bad" ? "tunnel down or stale handshake" : it ? Math.round(100 * nt / it) + "% inside the tunnel" : "no internet connections"}</title></rect>`;
    }
    h += `<text x="${L - 6}" y="${SY + 10}" text-anchor="end" class="bc-ax">inside</text>`;
    const ticks = 6;
    for (let i = 0; i <= ticks; i++) { const t = t0 + span * i / ticks; h += `<text x="${x(t)}" y="${H - 8}" text-anchor="middle" class="bc-ax">${span > 86400 ? dayOf(t) : locTime(t)}</text>`; }
    h += `<line class="tu-cursor" x1="0" x2="0" y1="${T}" y2="${SY + 12}" hidden/>`;
    box.innerHTML = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Data through the VPN tunnel over time">${h}</svg><div class="tip tu-htip" hidden></div>
      <div class="globe-legend"><span><i class="sw" style="background:var(--c4)"></i>Down through the tunnel</span><span><i class="sw" style="background:var(--up)"></i>Up through the tunnel</span><span><i class="sw tu-sw-part"></i>Some connections went around</span><span><i class="sw" style="background:var(--crit)"></i>Tunnel down or stale</span><span><i class="sw" style="background:var(--rule)"></i>VPN off</span></div>`;
    const hs = box.querySelector("svg"), ht = box.querySelector(".tu-htip"), cur = box.querySelector(".tu-cursor");
    hs.addEventListener("pointermove", e => {
      const b = hs.getBoundingClientRect(), px = (e.clientX - b.left) / b.width * W;
      if (px < L || px > W - R) { ht.hidden = true; cur.setAttribute("hidden", ""); return; }
      const t = t0 + (px - L) / (W - L - R) * span;
      let best = rows[0]; for (const r of rows) if (Math.abs(r[0] - t) < Math.abs(best[0] - t)) best = r;
      const [ts, on, upm, hsa, rx, tx, nt, nd, nl] = best;
      cur.removeAttribute("hidden"); cur.setAttribute("x1", x(ts)); cur.setAttribute("x2", x(ts));
      ht.hidden = false;
      ht.innerHTML = `<div class="t">${locTime(ts)} ${TZL}</div>${on ? `<div class="r"><span>Down through tunnel</span><b>${rx == null ? "–" : bitsText(rx)}</b></div><div class="r"><span>Up through tunnel</span><b>${tx == null ? "–" : bitsText(tx)}</b></div><div class="r"><span>Inside / around / local</span><b>${nt} / ${nd} / ${nl}</b></div><div class="r"><span>Last handshake</span><b>${hsa == null ? "–" : hsa + " s"}</b></div>` : `<div class="r"><span>VPN</span><b>off</b></div>`}`;
      ht.style.left = Math.min(Math.max(e.clientX - box.getBoundingClientRect().left, 110), box.clientWidth - 110) + "px"; ht.style.top = (e.clientY - box.getBoundingClientRect().top) + "px";
    });
    hs.addEventListener("pointerleave", () => { ht.hidden = true; cur.setAttribute("hidden", ""); });
  }

  function lists() {
    const on = d.status && d.status.on;
    $("#tuaround", main).innerHTML = d.around.length ? `<div class="tu-list">${d.around.map(a => `<div class="tu-row"><b>${esc(a.device)}</b><span>→ ${esc(a.name || shortOrg(a.org) || a.dst)} ${a.cc ? flagOf(a.cc) : ""}</span><small>${esc(a.dst)} · ${a.proto}/${a.dport} · ${locTime(a.last)}</small></div>`).join("")}</div>`
      : `<p class="tu-ok">${on ? "✓ Nothing is going around the tunnel. Every internet connection from the network is inside it." : "The VPN is off, so every internet connection goes straight out through the ISP."}</p>`;
    $("#tuhome", main).innerHTML = d.home.length ? `<div class="tu-list">${d.home.map(a => `<div class="tu-row"><b>${esc(a.device)}</b><span>→ ${esc(a.dst_name)}</span><small>${a.proto}/${a.dport}${a.n > 1 ? ` · ×${a.n}` : ""}</small></div>`).join("")}</div>` : `<p class="muted">No local connections right now.</p>`;
  }

  async function load(range) {
    try { d = await api(`api/tunnel?range=${range}`); } catch { return; }
    stats(); draw(); history(); lists();
  }
  const seg = rangeSeg("tunnel", ["1h", "6h", "24h", "7d"], "6h", r => { seg.value = r; load(r); });
  $("#seg", main).replaceWith(seg.node);
  load(seg.value);
  const iv = setInterval(() => load(seg.value), 20000);
  let roW = 0;
  const ro = new ResizeObserver(([en]) => { const w = en.contentRect.width; if (d && Math.abs(w - roW) > 20) { roW = w; history(); } }); ro.observe($("#tuhist", main));
  return () => { clearInterval(iv); cancelAnimationFrame(raf); ro.disconnect(); };
};

/* ---------------------------------------------------------------- device passports
   One card per device, laid side by side: when it is busy (a day of 15-minute slots coloured by what it was
   doing), what it uses most, how many companies and countries it talks to, how it is connected, and whether
   its connections are inside the router's VPN tunnel. Built from the other pages' data feeds. */
VIEWS.passports = main => {
  main.innerHTML = `<div class="head"><h1>Device passports</h1><p>Every device on one page: when it is busy, what it uses, and who it talks to.</p><div class="grow"></div><span id="pfilt"></span><span id="seg"></span></div>
    <div class="globe-legend pp-legend"><span><i class="sw pp-sw-night"></i>Night, 00:00 to 06:00 local</span><span class="muted">Bar height = data in that slot (square root, so quiet times stay visible) · colour = what it was doing · click a card to open the device</span></div>
    <div class="pp-grid" id="ppgrid"><div class="pp-card pp-skel"></div><div class="pp-card pp-skel"></div><div class="pp-card pp-skel"></div></div>`;
  let data = null, filt = store.get("pp.filter", "All");
  const fseg = document.createElement("div"); fseg.className = "seg"; fseg.setAttribute("role", "group"); fseg.setAttribute("aria-label", "Which devices");
  for (const o of ["All", "Main", "Fenced zones"]) { const b = document.createElement("button"); b.textContent = o; b.setAttribute("aria-pressed", o === filt);
    b.onclick = () => { filt = o; store.set("pp.filter", o); fseg.querySelectorAll("button").forEach(x => x.setAttribute("aria-pressed", x === b)); draw(); }; fseg.appendChild(b); }
  $("#pfilt", main).replaceWith(fseg);

  function build() {
    const [dv, sk, geo, tu] = data, g = new Map();
    for (const x of dv.devices) {
      const k = groupKey(x.mac, x.name, x.vendor);
      const e = g.get(k.key) || g.set(k.key, { key: k.key, name: k.name, macs: [], ips: [], vendor: x.vendor, down: 0, up: 0, first: x.first_seen, last: x.last_seen, link: x.link, known: true, slots: new Map(), apps: new Map(), orgs: new Set(), ccs: new Map(), tun: null }).get(k.key);
      e.macs.push(x.mac); if (x.ip) e.ips.push(x.ip); e.down += x.down || 0; e.up += x.up || 0;
      e.first = Math.min(e.first || x.first_seen, x.first_seen || e.first); e.last = Math.max(e.last || 0, x.last_seen || 0);
      if (!e.link && x.link) e.link = x.link; if (!x.known) e.known = false;
    }
    const byMac = new Map(); for (const e of g.values()) for (const m of e.macs) byMac.set(m, e);
    for (const [t, mac, dn, u, top] of sk.cells) {
      const e = byMac.get(mac); if (!e) continue;
      const s = e.slots.get(t) || e.slots.set(t, { b: 0, top: null, tb: 0 }).get(t);
      s.b += dn + u; if (top && dn + u > s.tb) { s.tb = dn + u; s.top = top; }
      if (top) e.apps.set(top, (e.apps.get(top) || 0) + dn + u);
    }
    for (const x of geo.dests) for (const [m, b] of Object.entries(x.macs || {})) { const e = byMac.get(m); if (!e) continue; if (x.org) e.orgs.add(x.org); if (x.cc) e.ccs.set(x.cc, (e.ccs.get(x.cc) || 0) + (b || 0)); }
    const tunByIp = new Map((tu.devices || []).map(x => [x.ip, x]));
    for (const e of g.values()) for (const ip of e.ips) { const x = tunByIp.get(ip); if (x) e.tun = e.tun ? { tunnel: e.tun.tunnel + x.tunnel, direct: e.tun.direct + x.direct, local: e.tun.local + x.local } : { ...x }; }
    return { list: [...g.values()].filter(e => e.down + e.up > 0).sort((a, b) => (b.down + b.up) - (a.down + a.up)), sk, vpnOn: tu.status && tu.status.on };
  }

  function linkText(l) {
    if (!l) return "";
    if (l.kind === "wifi") return `Wi-Fi ${esc(l.band || "")}${l.signal != null ? ` · ${l.signal} dBm` : ""}`;
    if (l.kind === "wired") return `Wired${l.speed ? " · " + esc(String(l.speed)) : ""}${isMultigig(l) ? " · multi-gig" : ""}`;
    return esc(l.kind || "");
  }
  function rhythm(e, sk) {
    const b = sk.bucket, n = Math.max(1, Math.round((sk.t1 - sk.t0) / b)), W = 300, H = 46;
    const vals = Array.from({ length: n }, (_, i) => e.slots.get(sk.t0 + i * b));
    const max = Math.max(1, ...vals.map(v => v ? v.b : 0)), bw = W / n;
    let h = "";
    for (let i = 0; i < n; i++) { const t = sk.t0 + i * b; if (locHour(t) < 6) h += `<rect x="${(i * bw).toFixed(2)}" y="0" width="${(bw + 0.3).toFixed(2)}" height="${H}" class="pp-night"/>`; }
    vals.forEach((v, i) => {
      if (!v || !v.b) return;
      const hh = Math.max(1.5, Math.sqrt(v.b / max) * (H - 2)), c = clsObj(v.top ? classOf(v.top) : "Unclassified").color;
      h += `<rect x="${(i * bw + bw * 0.12).toFixed(2)}" y="${(H - hh).toFixed(1)}" width="${Math.max(0.8, bw * 0.76).toFixed(2)}" height="${hh.toFixed(1)}" rx="${Math.min(1.5, bw / 3).toFixed(1)}" fill="${c}"><title>${locTime(sk.t0 + i * b)} · ${bytes(v.b)}${v.top ? " · " + esc(v.top) : ""}</title></rect>`;
    });
    const marks = [0, 0.25, 0.5, 0.75].map(f => `<span style="left:${f * 100}%">${sk.bucket >= 3600 ? dayOf(sk.t0 + f * (sk.t1 - sk.t0)) : locTime(sk.t0 + f * (sk.t1 - sk.t0))}</span>`).join("");
    return `<svg class="pp-rh" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="Activity of ${esc(e.name)} over time">${h}</svg><div class="pp-axis">${marks}<span style="right:0">now</span></div>`;
  }

  function draw() {
    if (!data) return;
    const { list, sk, vpnOn } = build();
    const shown = list.filter(e => filt === "All" || (filt === "Fenced zones") === e.ips.some(isFencedIp));
    const maxT = Math.max(1, ...list.map(e => e.down + e.up));
    $("#ppgrid", main).innerHTML = shown.map(e => {
      const tot = e.down + e.up, apps = [...e.apps.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3), appT = Math.max(1, ...apps.map(a => a[1]));
      const ccs = [...e.ccs.entries()].sort((a, b) => b[1] - a[1]), iot = e.ips.some(isFencedIp);
      const badges = [
        iot ? `<span class="pp-b fence">fenced zone</span>` : "",
        e.macs.length > 1 ? `<span class="pp-b">dual-homed</span>` : "",
        !e.known ? `<span class="pp-b crit">new device</span>` : "",
        e.tun ? (e.tun.direct ? `<span class="pp-b crit">${e.tun.direct} outside the tunnel</span>` : e.tun.tunnel ? `<span class="pp-b tun">inside the VPN tunnel</span>` : "") : (vpnOn ? `<span class="pp-b muted">idle</span>` : ""),
      ].join("");
      return `<article class="pp-card" data-mac="${esc(e.macs[0])}" tabindex="0" role="button" aria-label="Open ${esc(e.name)}">
        <header><span class="pp-ini" style="--c:${apps[0] ? clsObj(classOf(apps[0][0])).color : "var(--ink-3)"}">${esc((e.name || "?").trim().charAt(0).toUpperCase())}</span>
          <div class="pp-id"><h3>${esc(e.name)}</h3><small>${esc(e.ips.join(" · ") || "")}${e.vendor && e.vendor !== "Private address" ? " · " + esc(e.vendor) : ""}</small></div>
          <span class="pp-link">${linkText(e.link)}</span></header>
        <div class="pp-rhw">${rhythm(e, sk)}</div>
        <div class="pp-stats">
          <div><span>Data</span><b>${bytes(tot)}</b><i class="pp-bar"><i style="width:${(100 * tot / maxT).toFixed(1)}%"></i></i></div>
          <div><span>Companies</span><b>${e.orgs.size}</b></div>
          <div><span>Countries</span><b class="pp-flags">${ccs.slice(0, 5).map(c => flagOf(c[0])).join("")}${ccs.length > 5 ? `<small> +${ccs.length - 5}</small>` : ccs.length ? "" : "–"}</b></div>
        </div>
        <div class="pp-apps">${apps.map(([a, v]) => { const c = clsObj(classOf(a)); return `<div class="pp-app"><span><i style="background:${c.color}"></i>${esc(a)}</span><i class="pp-abar"><i style="width:${(100 * v / appT).toFixed(1)}%;background:${c.color}"></i></i><b>${bytes(v)}</b></div>`; }).join("") || `<p class="muted">No app names seen yet.</p>`}</div>
        <footer>${badges}<span class="pp-seen">seen ${stamp(e.last)}</span></footer></article>`;
    }).join("") || `<p class="muted">No devices with traffic in this period.</p>`;
    main.querySelectorAll(".pp-card[data-mac]").forEach(c => { const go = () => location.hash = `#/devices/${encodeURIComponent(c.dataset.mac)}`; c.onclick = go; c.onkeydown = ev => { if (ev.key === "Enter") go(); }; });
  }
  async function load(range) {
    try { data = await Promise.all([api(`api/devices?range=${range}`), api(`api/skyline?range=${range}`), api(`api/geo?range=${range}`), api("api/tunnel?range=1h")]); } catch { return; }
    draw();
  }
  const seg = rangeSeg("passports", ["24h", "7d"], "24h", r => { seg.value = r; load(r); });
  $("#seg", main).replaceWith(seg.node);
  load(seg.value);
  const iv = setInterval(() => load(seg.value), 120000);
  return () => clearInterval(iv);
};

/* ---------------------------------------------------------------- data map
   Every byte as area (a squarified treemap). Big boxes are devices, the tiles inside are the apps they used,
   coloured by traffic class. Click a box to open it full size; the path above takes you back. "By app" turns
   it round: apps outside, the devices that used them inside. */
function squarify(items, x, y, w, h) {
  const out = [], total = items.reduce((a, b) => a + b.v, 0);
  if (!total || w <= 0 || h <= 0) return out;
  const scale = w * h / total, rest = items.map(i => ({ ...i, a: i.v * scale }));
  const worst = (row, side) => { const s = row.reduce((a, b) => a + b.a, 0), mx = Math.max(...row.map(r => r.a)), mn = Math.min(...row.map(r => r.a)); return Math.max(side * side * mx / (s * s), s * s / (side * side * mn)); };
  let X = x, Y = y, Wd = w, Ht = h;
  while (rest.length) {
    const side = Math.min(Wd, Ht), row = [rest.shift()];
    while (rest.length && worst([...row, rest[0]], side) <= worst(row, side)) row.push(rest.shift());
    const s = row.reduce((a, b) => a + b.a, 0);
    if (Wd >= Ht) { const cw = s / Ht; let yy = Y; for (const r of row) { const rh = r.a / cw; out.push({ ...r, x: X, y: yy, w: cw, h: rh }); yy += rh; } X += cw; Wd -= cw; }
    else { const rh = s / Wd; let xx = X; for (const r of row) { const cw = r.a / rh; out.push({ ...r, x: xx, y: Y, w: cw, h: rh }); xx += cw; } Y += rh; Ht -= rh; }
  }
  return out;
}
VIEWS.datamap = main => {
  main.innerHTML = `<div class="head"><h1>Data map</h1><p>Every byte as area. Boxes are devices, the tiles inside are the apps they used.</p><div class="grow"></div><span id="dmode"></span><span id="seg"></span></div>
    <div class="topo-stats" id="dmstats"></div>
    <section class="panel"><div class="ph"><h2 id="dmcrumb">All devices</h2><span class="sub">click a box to open it · Escape or the path above goes back</span></div>
      <div class="dm-host" id="dmhost"><svg id="dmsvg" role="img" aria-label="Treemap of data use"></svg><div class="tip dm-tip" hidden></div></div>
      <div class="globe-legend" id="dmlegend"></div></section>`;
  const svg = $("#dmsvg", main), host = $("#dmhost", main), tip = $(".dm-tip", main);
  let apps = [], focus = null, mode = store.get("dm.mode", "By device");
  const mseg = document.createElement("div"); mseg.className = "seg"; mseg.setAttribute("role", "group"); mseg.setAttribute("aria-label", "Arrange by");
  for (const o of ["By device", "By app"]) { const b = document.createElement("button"); b.textContent = o; b.setAttribute("aria-pressed", o === mode);
    b.onclick = () => { mode = o; focus = null; store.set("dm.mode", o); mseg.querySelectorAll("button").forEach(x => x.setAttribute("aria-pressed", x === b)); draw(); }; mseg.appendChild(b); }
  $("#dmode", main).replaceWith(mseg);

  function tree() {
    const outer = new Map();
    for (const a of apps) {
      const cls = clsObj(classOf(a.name));
      for (const u of a.users || []) {
        if (!u.bytes) continue;
        const [ok, ik, iname] = mode === "By device" ? [u.name, a.name, a.name] : [a.name, u.name, u.name];
        const o = outer.get(ok) || outer.set(ok, { name: ok, v: 0, kids: new Map(), cls: mode === "By app" ? cls : null }).get(ok);
        o.v += u.bytes;
        const k = o.kids.get(ik) || o.kids.set(ik, { name: iname, v: 0, cls }).get(ik);
        k.v += u.bytes;
      }
    }
    return [...outer.values()].map(o => {
      let kids = [...o.kids.values()].sort((a, b) => b.v - a.v);
      if (kids.length > 24) { const rest = kids.slice(23); kids = kids.slice(0, 23); kids.push({ name: `${rest.length} more`, v: rest.reduce((s, k) => s + k.v, 0), cls: { name: "Other", color: cssVar("--ink-3") }, more: true }); }
      return { ...o, kids };
    }).sort((a, b) => b.v - a.v);
  }
  function draw() {
    const t = tree(), all = t.reduce((s, o) => s + o.v, 0);
    const W = Math.max(320, host.clientWidth), H = Math.max(420, Math.min(680, Math.round(W * 0.56)));
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`); svg.style.height = H + "px";
    const top = focus ? t.filter(o => o.name === focus) : t;
    $("#dmcrumb", main).innerHTML = focus ? `<a href="#" id="dmback">${mode === "By device" ? "All devices" : "All apps"}</a> › ${esc(focus)}` : (mode === "By device" ? "All devices" : "All apps");
    const ob = $("#dmback", main); if (ob) ob.onclick = ev => { ev.preventDefault(); focus = null; draw(); };
    let h = "";
    const boxes = squarify(top.map(o => ({ ...o })), 0, 0, W, H);
    boxes.forEach((o, oi) => {
      const pad = 3, head = o.h > 46 && o.w > 70 ? 22 : 0;
      const frame = `<rect class="dm-box" x="${o.x + 1}" y="${o.y + 1}" width="${Math.max(0, o.w - 2)}" height="${Math.max(0, o.h - 2)}" rx="6" data-o="${oi}"/>`;
      h += frame;
      if (head) h += `<text class="dm-head" x="${o.x + 9}" y="${o.y + 16}" data-o="${oi}">${esc(clip(o.name, o.w / 7.6))} <tspan class="dm-hv">${bytes(o.v)} · ${Math.round(100 * o.v / all)}%</tspan></text>`;
      const kids = squarify(o.kids, o.x + pad + 1, o.y + head + pad, o.w - 2 * pad - 2, o.h - head - 2 * pad - 1);
      kids.forEach(k => {
        const c = mode === "By device" ? k.cls.color : shade(o.cls.color, 0.75 + 0.5 * (k.v / o.v));
        h += `<rect class="dm-tile" x="${(k.x + 1).toFixed(1)}" y="${(k.y + 1).toFixed(1)}" width="${Math.max(0, k.w - 2).toFixed(1)}" height="${Math.max(0, k.h - 2).toFixed(1)}" rx="3" fill="${c}" data-o="${oi}" data-k="${esc(k.name)}"/>`;
        if (k.w > 58 && k.h > 30) h += `<text class="dm-lab" x="${k.x + 7}" y="${k.y + 18}" pointer-events="none">${esc(clip(k.name, k.w / 7.4))}</text>${k.h > 46 ? `<text class="dm-val" x="${k.x + 7}" y="${k.y + 35}" pointer-events="none">${bytes(k.v)}</text>` : ""}`;
      });
    });
    svg.innerHTML = h;
    const legendCls = new Map(); for (const o of t) for (const k of o.kids) if (k.cls) legendCls.set(k.cls.name, k.cls.color);
    $("#dmlegend", main).innerHTML = [...legendCls.entries()].slice(0, 12).map(([n, c]) => `<span><i class="sw" style="background:${c}"></i>${esc(n)}</span>`).join("");
    const biggest = t[0], topApp = (() => { const m = new Map(); for (const a of apps) m.set(a.name, (m.get(a.name) || 0) + (a.down || 0) + (a.up || 0)); return [...m.entries()].sort((a, b) => b[1] - a[1])[0]; })();
    $("#dmstats", main).innerHTML =
      tile4("All data", bytes(all), `${t.length} ${mode === "By device" ? "devices" : "apps"} in this period`) +
      tile4(mode === "By device" ? "Biggest user" : "Biggest app", biggest ? esc(biggest.name) : "–", biggest ? `${bytes(biggest.v)} · ${Math.round(100 * biggest.v / all)}% of everything` : "", "ug") +
      tile4("Top app overall", topApp ? esc(topApp[0]) : "–", topApp ? bytes(topApp[1]) : "", "ok") +
      tile4("Under 1% each", `${t.filter(o => o.v < all * 0.01).length}`, `${mode === "By device" ? "devices" : "apps"} too small to label`, "fence");
    svg.querySelectorAll("[data-o]").forEach(el => {
      const o = boxes[+el.dataset.o];
      el.addEventListener("pointermove", e => {
        const k = el.dataset.k ? o.kids.find(x => x.name === el.dataset.k) : null;
        tip.hidden = false;
        tip.innerHTML = `<div class="t">${esc(k ? k.name : o.name)}</div>${k ? `<div class="r"><span>${esc(o.name)}</span><b>${bytes(k.v)}</b></div><div class="r"><span>Share of ${esc(o.name)}</span><b>${Math.round(100 * k.v / o.v)}%</b></div>` : ""}<div class="r"><span>${k ? "Share of all" : "Total"}</span><b>${k ? Math.round(1000 * k.v / all) / 10 + "%" : bytes(o.v)}</b></div>${!focus ? `<div class="r muted"><span>click to open ${esc(o.name)}</span></div>` : ""}`;
        const b = host.getBoundingClientRect();
        tip.style.left = Math.min(Math.max(e.clientX - b.left, 120), b.width - 120) + "px"; tip.style.top = (e.clientY - b.top) + "px";
      });
      el.addEventListener("pointerleave", () => { tip.hidden = true; });
      el.addEventListener("click", () => { if (!focus) { focus = o.name; tip.hidden = true; draw(); } });
    });
  }
  const clip = (s, n) => (s = String(s), s.length > Math.max(3, Math.floor(n)) ? s.slice(0, Math.max(2, Math.floor(n) - 1)) + "…" : s);
  const esc_ = e => { if (e.key === "Escape" && focus) { focus = null; draw(); } };
  addEventListener("keydown", esc_);
  async function load(range) { let d; try { d = await api(`api/apps?range=${range}`); } catch { return; } apps = d.apps || []; draw(); }
  const seg = rangeSeg("datamap", ["1h", "6h", "24h", "7d"], "24h", r => { seg.value = r; focus = null; load(r); });
  $("#seg", main).replaceWith(seg.node);
  load(seg.value);
  const iv = setInterval(() => load(seg.value), 120000);
  let roW = 0;
  const ro = new ResizeObserver(([en]) => { const w = en.contentRect.width; if (apps.length && Math.abs(w - roW) > 20) { roW = w; draw(); } }); ro.observe(host);
  return () => { clearInterval(iv); ro.disconnect(); removeEventListener("keydown", esc_); };
};

/* ---------------------------------------------------------------- what the VPN costs
   The delay and loss the router's VPN tunnel adds, from the latency checks the collector runs every minute,
   split by whether the VPN was on at that minute. Targets the payload marks "local" (the router, the
   uplink) are the control: the tunnel should not change them. */
VIEWS.vpncost = main => {
  main.innerHTML = `<div class="head"><h1>VPN cost</h1><p>What ${esc(vpnLabel())} adds in delay and loss, measured every minute. Targets on the local side act as the control.</p><div class="grow"></div><span id="seg"></span></div>
    <div class="topo-stats" id="vcstats"></div>
    <section class="panel"><div class="ph"><h2>Delay, VPN off against on</h2><span class="sub">each dot is one minute's typical round trip · box = middle half · bar = median · log scale</span></div><div id="vcrows" class="vc-rows"></div>
      <div class="globe-legend"><span><i class="sw" style="background:var(--down)"></i>VPN off</span><span><i class="sw" style="background:var(--c4)"></i>VPN on</span></div></section>
    <section class="panel" style="margin-top:14px"><div class="ph"><h2>Over time</h2><span class="sub">purple bands: VPN on</span></div><div id="vcline" class="tu-hist"></div></section>
    <section class="panel" style="margin-top:14px"><div class="ph"><h2>What this means</h2></div><div id="vcsum" class="isp-notes"></div></section>`;
  let d = null;
  const COLS = ["--up", "--c3", "--c4", "--down"];
  const inetT = () => Object.keys(d.targets).filter(t => !d.targets[t].local);
  const localT = () => Object.keys(d.targets).filter(t => d.targets[t].local);
  const ms = v => v == null ? "–" : v < 10 ? v.toFixed(1) + " ms" : Math.round(v) + " ms";
  const pct = v => v == null ? "–" : (v < 1 ? v.toFixed(1) : Math.round(v)) + "%";
  function stats() {
    const T = d.targets, [n1, n2] = inetT(), q9 = T[n1] || {}, cf = T[n2] || {};
    const dl = x => x.on && x.off ? x.on.med - x.off.med : null;
    const sign = v => v == null ? "–" : `${v >= 0 ? "+" : "−"}${Math.abs(v) < 10 ? Math.abs(v).toFixed(1) : Math.round(Math.abs(v))}<small> ms</small>`;
    const lossOn = inetT().map(t => T[t].loss_on).filter(v => v != null), lossOff = inetT().map(t => T[t].loss_off).filter(v => v != null);
    const avg = a => a.length ? a.reduce((s, v) => s + v, 0) / a.length : null;
    $("#vcstats", main).innerHTML =
      tile4(`Extra delay to ${esc(n1 || "the internet")}`, sign(dl(q9)), `${ms(q9.off && q9.off.med)} off · ${ms(q9.on && q9.on.med)} on`, (dl(q9) ?? 0) > 15 ? "warn" : "ok") +
      tile4(`Extra delay to ${esc(n2 || "a second target")}`, sign(dl(cf)), `${ms(cf.off && cf.off.med)} off · ${ms(cf.on && cf.on.med)} on`, (dl(cf) ?? 0) > 15 ? "warn" : "ok") +
      tile4("Ping loss", `${pct(avg(lossOn))}<small> on</small>`, `${pct(avg(lossOff))} with the VPN off (internet targets)`, (avg(lossOn) ?? 0) > 5 ? "warn" : "ok") +
      tile4("VPN on", `${Math.round(100 * d.on_share)}<small>%</small>`, `of this period · ${(d.on_share * d.span / 3600).toFixed(1)} hours`, "fence");
  }
  function rows() {
    const box = $("#vcrows", main), W = Math.max(360, box.clientWidth), L = 150, R = 110, rowH = 30;
    const lo = 0.5, hi = 300, x = v => L + (Math.log10(Math.max(lo, Math.min(hi, v))) - Math.log10(lo)) / (Math.log10(hi) - Math.log10(lo)) * (W - L - R);
    const tg = [...inetT(), ...localT()];
    const H = tg.length * rowH * 2 + tg.length * 14 + 34;
    let h = "", y = 8;
    for (const v of [1, 2, 5, 10, 20, 50, 100, 200]) h += `<line x1="${x(v)}" x2="${x(v)}" y1="0" y2="${H - 26}" class="bc-grid"/><text x="${x(v)}" y="${H - 8}" text-anchor="middle" class="bc-ax">${v} ms</text>`;
    let seed = 1; const rnd = () => ((seed = (seed * 16807) % 2147483647) / 2147483647);
    for (const t of tg) {
      const T = d.targets[t];
      h += `<text x="10" y="${y + rowH}" class="vc-name">${esc(t)}</text><text x="10" y="${y + rowH + 17}" class="vc-sub">${T.local ? "on the local side" : "on the internet"}</text>`;
      for (const [k, col] of [["off", "--down"], ["on", "--c4"]]) {
        const st = T[k], sm = T["samples_" + k] || [], cy = y + rowH / 2 + 2;
        for (const v of sm) h += `<circle cx="${(x(v) + (rnd() - 0.5) * 2).toFixed(1)}" cy="${(cy + (rnd() - 0.5) * (rowH - 12)).toFixed(1)}" r="1.9" fill="var(${col})" opacity=".32"/>`;
        if (st) {
          h += `<rect x="${x(st.p25)}" y="${cy - 8}" width="${Math.max(1.5, x(st.p75) - x(st.p25))}" height="16" rx="3" fill="none" stroke="var(${col})" stroke-width="1.5"/>`;
          h += `<line x1="${x(st.med)}" x2="${x(st.med)}" y1="${cy - 11}" y2="${cy + 11}" stroke="var(${col})" stroke-width="3" stroke-linecap="round"/>`;
          h += `<text x="${W - R + 10}" y="${cy + 5}" class="vc-val" fill="var(${col})">${k === "on" ? "on " : "off "}${ms(st.med)}</text>`;
        } else h += `<text x="${W - R + 10}" y="${cy + 5}" class="vc-val muted">${k}: no data</text>`;
        y += rowH;
      }
      h += `<line x1="10" x2="${W - 10}" y1="${y + 6}" y2="${y + 6}" class="vc-sep"/>`;
      y += 14;
    }
    box.innerHTML = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Round-trip delay to each target with the VPN off and on">${h}</svg>`;
  }
  function line() {
    const box = $("#vcline", main), W = Math.max(360, box.clientWidth), H = 220, L = 52, R = 12, T = 10, B = 28;
    const t1 = d.now, t0 = t1 - d.span, x = t => L + (t - t0) / d.span * (W - L - R);
    const shown = inetT().slice(0, COLS.length), net = d.series.filter(s => shown.includes(s[1]));
    const mx = Math.max(30, Math.min(300, ...net.map(s => s[2]).sort((a, b) => a - b).slice(-Math.ceil(net.length * 0.02) - 1, -Math.ceil(net.length * 0.02) || undefined)));
    const y = v => T + (1 - Math.min(v, mx) / mx) * (H - T - B);
    let h = "";
    for (const p of d.periods) if (p[2]) h += `<rect x="${x(Math.max(t0, p[0]))}" y="${T}" width="${Math.max(1, x(p[1]) - x(Math.max(t0, p[0])))}" height="${H - T - B}" class="vc-band"/>`;
    for (const f of [0, 0.5, 1]) h += `<line x1="${L}" x2="${W - R}" y1="${y(mx * f)}" y2="${y(mx * f)}" class="bc-grid"/><text x="${L - 6}" y="${y(mx * f) + 4}" text-anchor="end" class="bc-ax">${Math.round(mx * f)} ms</text>`;
    for (const [ti, tg] of shown.entries()) {
      let p = "", prev = 0;
      for (const s of net) if (s[1] === tg) { p += (s[0] - prev > 180 ? "M" : "L") + x(s[0]).toFixed(1) + " " + y(s[2]).toFixed(1); prev = s[0]; }
      h += `<path d="${p}" fill="none" stroke="var(${COLS[ti]})" stroke-width="1.5" opacity=".9"/>`;
    }
    for (let i = 0; i <= 6; i++) { const t = t0 + d.span * i / 6; h += `<text x="${x(t)}" y="${H - 8}" text-anchor="middle" class="bc-ax">${d.span > 86400 ? dayOf(t) : locTime(t)}</text>`; }
    box.innerHTML = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Round trip to the internet targets over time, VPN periods shaded">${h}</svg>
      <div class="globe-legend">${shown.map((t, i) => `<span><i class="sw" style="background:var(${COLS[i]})"></i>${esc(t)}</span>`).join("")}<span><i class="sw vc-sw-band"></i>VPN on</span></div>`;
  }
  function summary() {
    const T = d.targets, [n1, n2] = inetT(), [l1] = localT(), q9 = T[n1], cf = T[n2], fb = T[l1];
    const dl = x => x && x.on && x.off ? x.on.med - x.off.med : null;
    const p = [];
    if (dl(q9) != null) p.push(`<p><b>Delay.</b> With the VPN on, a round trip to ${esc(n1)} takes ${ms(q9.on.med)} against ${ms(q9.off.med)} without it, ${dl(q9) >= 0 ? "about " + ms(dl(q9)) + " more" : "no more"}. Every packet now travels to the VPN server first. ${cf && dl(cf) != null ? `${esc(n2)} costs ${ms(Math.abs(dl(cf)))} ${dl(cf) >= 0 ? "extra" : "less"}.` : ""} People notice delay from roughly 100 ms; video calls stay comfortable below about 150 ms.</p>`);
    else p.push(`<p><b>Not enough data yet.</b> This page needs minutes with the VPN both off and on in the chosen period.</p>`);
    if (fb && dl(fb) != null) p.push(`<p><b>The control.</b> ${esc(l1)} answers in ${ms(fb.on.med)} with the VPN on and ${ms(fb.off.med)} with it off. It is on the local side, so the tunnel should not touch it. If it does not move, the extra delay above really is the tunnel.</p>`);
    const lo = [cf && cf.loss_on, q9 && q9.loss_on].filter(v => v != null);
    if (lo.length && Math.max(...lo) > 3) p.push(`<p><b>Ping loss.</b> With the VPN on, ${pct(Math.max(...lo))} of pings to the internet get no answer, against under ${pct(Math.max((cf && cf.loss_off) || 0, (q9 && q9.loss_off) || 0) || 1)} without it. VPN servers often give ping the lowest priority, so this can overstate real loss for web and video traffic. If pages or calls stutter with the VPN on, this is the first number to watch.</p>`);
    if (d.peak_down && d.peak_down.on != null && d.peak_down.off != null) p.push(`<p><b>Speed.</b> The busiest minutes reached ${bitsText(d.peak_down.off)} with the VPN off and ${bitsText(d.peak_down.on)} with it on. That reflects what the network was doing, not the line's limit; a proper speed comparison needs a test run both ways.</p>`);
    $("#vcsum", main).innerHTML = p.join("");
  }
  async function load(range) {
    try { d = await api(`api/vpncost?range=${range}`); } catch { return; }
    stats(); rows(); line(); summary();
  }
  const seg = rangeSeg("vpncost", ["6h", "24h", "7d", "30d"], "24h", r => { seg.value = r; load(r); });
  $("#seg", main).replaceWith(seg.node);
  load(seg.value);
  const iv = setInterval(() => load(seg.value), 60000);
  let roW = 0;
  const ro = new ResizeObserver(([en]) => { const w = en.contentRect.width; if (d && Math.abs(w - roW) > 20) { roW = w; rows(); line(); } }); ro.observe($("#vcrows", main));
  return () => { clearInterval(iv); ro.disconnect(); };
};

/* ---------------------------------------------------------------- DNS names: shared helpers
   The part of a name its owner registered ("apple.com", "bbc.co.uk"), used to group hosts by company. */
const SLD2 = new Set("co.uk org.uk ac.uk gov.uk me.uk ltd.uk plc.uk net.uk nhs.uk com.au net.au org.au co.nz co.jp ne.jp or.jp com.br com.cn com.tw co.kr co.in com.mx com.tr co.za com.sg com.hk com.ar co.il".split(" "));
function regDomain(h) {
  const p = String(h).toLowerCase().replace(/\.$/, "").split(".");
  if (p.length <= 2) return p.join(".");
  if (/\.(in-addr|ip6)\.arpa$/.test(h.toLowerCase())) return p.slice(-2).join(".");   // every reverse lookup is one group
  return SLD2.has(p.slice(-2).join(".")) ? p.slice(-3).join(".") : p.slice(-2).join(".");
}
const hostCls = h => clsObj(classify({ host: h }));

/* ---------------------------------------------------------------- first sightings
   Every name the network asked for the first time since the DNS log began, placed on a timeline with one
   lane per device. New names are normal, but a burst from one device, or a name nobody expects, is worth a look. */
VIEWS.firsts = main => {
  main.innerHTML = `<div class="head"><h1>First sightings</h1><p>Every name the network asked for the first time. A burst from one device, or a name nobody expects, is worth a look.</p><div class="grow"></div><span id="seg"></span></div>
    <div class="topo-stats" id="fsstats"></div>
    <section class="panel"><div class="ph"><h2>When each device met something new</h2><span class="sub" id="fssub"></span></div>
      <div class="fs-host" id="fshost"><div id="fschart"></div><div class="tip fs-tip" hidden></div></div>
      <div class="globe-legend"><span><i class="sw" style="background:var(--crit)"></i>Blocked by the DNS filter on first sight</span><span><i class="sw fs-sw-learn"></i>Netmon's first day: everything looks new</span><span class="muted">Colour = kind of service · hover a dot for the name</span></div></section>
    <section class="panel" style="margin-top:14px"><div class="ph"><h2>New names by company</h2><span class="sub">grouped by the part of the name the owner registered</span></div><div id="fslist" class="fs-list"></div></section>`;
  let d = null;
  function draw() {
    const nw = d.new, box = $("#fschart", main), W = Math.max(380, box.clientWidth), t1 = d.now, t0 = t1 - d.span;
    const learnEnd = (d.history_start || t0) + 86400;
    const byDev = new Map(); for (const n of nw) byDev.set(n.who, (byDev.get(n.who) || 0) + 1);
    const devs = [...byDev.entries()].sort((a, b) => b[1] - a[1]).map(e => e[0]).slice(0, 14);
    const L = 200, R = 14, top = 70, lane = 30, H = top + devs.length * lane + 30;
    const x = t => L + (t - t0) / d.span * (W - L - R);
    let h = "";
    if (learnEnd > t0) h += `<rect x="${x(Math.max(t0, d.history_start || t0))}" y="0" width="${Math.max(0, x(Math.min(t1, learnEnd)) - x(Math.max(t0, d.history_start || t0)))}" height="${H - 24}" class="fs-learn"/>`;
    // hourly count of new names above the lanes
    const bw = d.span > 86400 * 2 ? 21600 : 3600, bins = new Map();
    for (const n of nw) { const b = Math.floor(n.t / bw) * bw; bins.set(b, (bins.get(b) || 0) + 1); }
    const mb = Math.max(1, ...bins.values());
    for (const [b, c] of bins) h += `<rect x="${x(b).toFixed(1)}" y="${(top - 12 - (c / mb) * 48).toFixed(1)}" width="${Math.max(1, x(b + bw) - x(b) - 1).toFixed(1)}" height="${((c / mb) * 48).toFixed(1)}" rx="1.5" class="fs-bin"><title>${locTime(b)}: ${c} new names</title></rect>`;
    h += `<text x="${L - 10}" y="${top - 16}" text-anchor="end" class="bc-ax">new names per ${bw === 3600 ? "hour" : "6 hours"}</text>`;
    devs.forEach((dv, i) => { const y = top + i * lane + lane / 2; h += `<line x1="${L}" x2="${W - R}" y1="${y}" y2="${y}" class="bc-grid"/><text x="${L - 10}" y="${y + 5}" text-anchor="end" class="fs-dev">${esc(dv.length > 26 ? dv.slice(0, 25) + "…" : dv)}</text>`; });
    const lanes = new Map(devs.map((v, i) => [v, i]));
    let seed = 7; const rnd = () => ((seed = (seed * 16807) % 2147483647) / 2147483647);
    nw.forEach((n, i) => {
      const li = lanes.get(n.who); if (li == null) return;
      const y = top + li * lane + lane / 2 + (rnd() - 0.5) * (lane - 12), c = hostCls(n.domain).color;
      h += `<circle cx="${x(n.t).toFixed(1)}" cy="${y.toFixed(1)}" r="${n.blocked ? 4 : 3.4}" fill="${n.blocked ? "var(--crit)" : c}" class="fs-dot${n.blocked ? " bl" : ""}" data-i="${i}"/>`;
    });
    for (let i = 0; i <= 6; i++) { const t = t0 + d.span * i / 6; h += `<text x="${x(t)}" y="${H - 6}" text-anchor="middle" class="bc-ax">${d.span > 86400 ? dayOf(t) : locTime(t)}</text>`; }
    box.innerHTML = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Timeline of names looked up for the first time, one lane per device">${h}</svg>`;
    const tip = $(".fs-tip", main), host = $("#fshost", main);
    box.querySelector("svg").addEventListener("pointermove", e => {
      const el = e.target.closest(".fs-dot"); if (!el) { tip.hidden = true; return; }
      const n = nw[+el.dataset.i]; tip.hidden = false;
      tip.innerHTML = `<div class="t">${esc(n.domain)}</div><div class="r"><span>First asked by</span><b>${esc(n.who)}</b></div><div class="r"><span>When</span><b>${locTime(n.t)} ${TZL}</b></div><div class="r"><span>Company</span><b>${esc(regDomain(n.domain))}</b></div><div class="r"><span>DNS filter</span><b>${n.blocked ? "blocked" : "answered"}</b></div>`;
      const b = host.getBoundingClientRect(); tip.style.left = Math.min(Math.max(e.clientX - b.left, 130), b.width - 130) + "px"; tip.style.top = (e.clientY - b.top) + "px";
    });
    box.querySelector("svg").addEventListener("pointerleave", () => { tip.hidden = true; });
    const learning = d.history_start && t1 - d.history_start < 86400 * 2;
    $("#fssub", main).textContent = learning ? `The DNS log began ${stamp(d.history_start)}; until a day has passed, much of this is simply the first time Netmon saw it` : `${nw.length} new names in this period`;
  }
  function stats() {
    const nw = d.new, hr = nw.filter(n => n.t >= d.now - 3600).length, bl = nw.filter(n => n.blocked).length;
    const hrs = Math.max(1, (d.now - Math.max(d.now - d.span, d.history_start || 0)) / 3600), avgHr = nw.length / hrs, busy = hr > 20 && hr > 2 * avgHr;
    const byDev = new Map(); for (const n of nw) byDev.set(n.who, (byDev.get(n.who) || 0) + 1);
    const top = [...byDev.entries()].sort((a, b) => b[1] - a[1])[0];
    $("#fsstats", main).innerHTML =
      tile4("New names", nw.length.toLocaleString("en-GB"), `first seen in this period, out of ${d.domains.length.toLocaleString("en-GB")} asked for`) +
      tile4("In the last hour", hr, `${busy ? "more than twice" : "about"} the usual ${Math.round(avgHr)} an hour`, busy ? "warn" : "ok") +
      tile4("Most curious device", top ? esc(top[0]) : "–", top ? `${top[1]} of the new names` : "", "ug") +
      tile4("Blocked on first sight", `${nw.length ? Math.round(100 * bl / nw.length) : 0}<small>%</small>`, `${bl} new names were ads or trackers`, "fence");
  }
  function list() {
    const g = new Map();
    for (const n of d.new) { const k = regDomain(n.domain); const e = g.get(k) || g.set(k, { k, names: [], who: new Set(), bl: 0, t: n.t }).get(k); e.names.push(n.domain); e.who.add(n.who); if (n.blocked) e.bl++; e.t = Math.max(e.t, n.t); }
    const rows = [...g.values()].sort((a, b) => b.names.length - a.names.length).slice(0, 60);
    $("#fslist", main).innerHTML = rows.map(e => `<div class="fs-row"><div class="fs-co"><i style="background:${hostCls(e.k).color}"></i><b>${esc(e.k)}</b><span>${e.names.length} new${e.bl ? ` · <em class="crit-t">${e.bl} blocked</em>` : ""}</span><small>${esc([...e.who].slice(0, 3).join(", "))}${e.who.size > 3 ? ` +${e.who.size - 3}` : ""}</small></div>
      <div class="fs-names">${e.names.slice(0, 8).map(n => `<code>${esc(n)}</code>`).join("")}${e.names.length > 8 ? `<span class="muted">+${e.names.length - 8} more</span>` : ""}</div></div>`).join("") || `<p class="muted">No new names in this period.</p>`;
  }
  async function load(range) { try { d = await api(`api/names?range=${range}`); } catch { return; } stats(); draw(); list(); }
  const seg = rangeSeg("firsts", ["6h", "24h", "7d"], "24h", r => { seg.value = r; load(r); });
  $("#seg", main).replaceWith(seg.node);
  load(seg.value);
  const iv = setInterval(() => load(seg.value), 120000);
  let roW = 0;
  const ro = new ResizeObserver(([en]) => { const w = en.contentRect.width; if (d && Math.abs(w - roW) > 20) { roW = w; draw(); } }); ro.observe($("#fschart", main));
  return () => { clearInterval(iv); ro.disconnect(); };
};

/* ---------------------------------------------------------------- name space
   Every name looked up, as a zoomable sunburst of the internet's address book: endings (.com, .de) in the
   middle, then the names their owners registered, then the individual hosts. Arc size = lookups (or number of
   names). A red rim marks the share the DNS filter blocked. Click an arc to zoom in, the centre to go back. */
VIEWS.namespace = main => {
  main.innerHTML = `<div class="head"><h1>Name space</h1><p>Every name the network looked up, as a map: endings in the middle, then who registered them, then their hosts. Red marks what the DNS filter blocked.</p><div class="grow"></div><span id="nsby"></span><span id="seg"></span></div>
    <div class="topo-stats" id="nsstats"></div>
    <section class="panel"><div class="ns-wrap"><div class="ns-host" id="nshost"><svg id="nssvg" role="img" aria-label="Sunburst of looked-up names"></svg><div class="tip ns-tip" hidden></div></div>
      <div class="ns-side" id="nsside"></div></div>
      <div class="globe-legend"><span><i class="sw" style="background:var(--crit)"></i>Blocked share (rim)</span><span class="muted">Colour = kind of service · click an arc to zoom in, the centre to go back</span></div></section>`;
  const svg = $("#nssvg", main), host = $("#nshost", main), tip = $(".ns-tip", main);
  let d = null, root = null, focus = null, by = store.get("ns.by", "Lookups"), anim = 0, view = { a0: 0, a1: 1, depth: 0 };
  const bseg = document.createElement("div"); bseg.className = "seg"; bseg.setAttribute("role", "group"); bseg.setAttribute("aria-label", "Size arcs by");
  for (const o of ["Lookups", "Names"]) { const b = document.createElement("button"); b.textContent = o; b.setAttribute("aria-pressed", o === by);
    b.onclick = () => { by = o; store.set("ns.by", o); bseg.querySelectorAll("button").forEach(x => x.setAttribute("aria-pressed", x === b)); build(); focus = root; view = { a0: 0, a1: 1, depth: 0 }; render(); side(); }; bseg.appendChild(b); }
  $("#nsby", main).replaceWith(bseg);

  function build() {
    root = { name: "all names", kids: new Map(), v: 0, n: 0, b: 0, depth: 0 };
    for (const [dom, n, b] of d.domains) {
      const reg = regDomain(dom), tld = reg.includes(".") ? reg.slice(reg.indexOf(".") + 1) : reg;
      const w = by === "Lookups" ? n : 1;
      let node = root; node.v += w; node.n += n; node.b += b;
      for (const [key, depth] of [["." + tld, 1], [reg, 2], [dom, 3]]) {
        if (depth === 3 && dom === reg) break;
        let k = node.kids.get(key);
        if (!k) { k = { name: key, kids: new Map(), v: 0, n: 0, b: 0, depth, parent: node }; node.kids.set(key, k); }
        k.v += w; k.n += n; k.b += b; node = k;
      }
    }
    const lay = (nd, a0, a1) => { nd.a0 = a0; nd.a1 = a1; let a = a0; const kids = [...nd.kids.values()].sort((x, y) => y.v - x.v); nd.list = kids; for (const k of kids) { const a2 = a + (a1 - a0) * k.v / nd.v; lay(k, a, a2); a = a2; } };
    lay(root, 0, 1);
    focus = root;
  }
  const colorOf = nd => nd.depth === 1 ? cssVar("--ink-3") : hostCls(nd.depth === 2 ? nd.name : regDomain(nd.name)).color;
  function render() {
    const S = Math.min(640, Math.max(300, host.clientWidth)), R = S / 2 - 6, ring = R / 3.6;
    svg.setAttribute("viewBox", `${-S / 2} ${-S / 2} ${S} ${S}`); svg.style.height = S + "px";
    const span = view.a1 - view.a0, ang = a => ((a - view.a0) / span) * Math.PI * 2 - Math.PI / 2;
    const arc = (a0, a1, r0, r1) => {
      const t0 = ang(a0), t1 = ang(a1), big = t1 - t0 > Math.PI ? 1 : 0;
      if (t1 - t0 >= Math.PI * 2 - 1e-6) return `M${r1} 0A${r1} ${r1} 0 1 1 ${-r1} 0A${r1} ${r1} 0 1 1 ${r1} 0M${r0} 0A${r0} ${r0} 0 1 0 ${-r0} 0A${r0} ${r0} 0 1 0 ${r0} 0Z`;
      const p = (t, r) => `${(Math.cos(t) * r).toFixed(2)} ${(Math.sin(t) * r).toFixed(2)}`;
      return `M${p(t0, r1)}A${r1} ${r1} 0 ${big} 1 ${p(t1, r1)}L${p(t1, r0)}A${r0} ${r0} 0 ${big} 0 ${p(t0, r0)}Z`;
    };
    let h = "", idx = [];
    const walk = nd => {
      for (const k of nd.list) {
        const rel = k.depth - view.depth; if (rel < 1 || rel > 3) { if (rel < 1) walk(k); continue; }
        if (k.a1 <= view.a0 || k.a0 >= view.a1) continue;
        const a0 = Math.max(k.a0, view.a0), a1 = Math.min(k.a1, view.a1);
        if ((a1 - a0) / span < 0.0015) continue;
        const r0 = ring * 0.55 + (rel - 1) * ring + 1, r1 = r0 + ring - 2, c = colorOf(k);
        idx.push(k);
        h += `<path d="${arc(a0, a1, r0, r1)}" fill="${rel === 3 ? shade(c, 1.25) : c}" class="ns-arc d${rel}" data-i="${idx.length - 1}"/>`;
        if (k.b) { const bs = Math.min(1, k.b / k.n); h += `<path d="${arc(a0, a0 + (a1 - a0) * bs, r1 - 3.5, r1)}" class="ns-block" pointer-events="none"/>`; }
        const mid = (ang(a0) + ang(a1)) / 2, arcLen = (ang(a1) - ang(a0)) * (r0 + r1) / 2;
        if (arcLen > 15 && ring > 40) {
          const rr = (r0 + r1) / 2, deg = mid * 180 / Math.PI, flip = deg > 90 && deg < 270;
          const maxc = Math.floor((ring - 10) / 7.2), nm = k.name.length > maxc ? k.name.slice(0, Math.max(3, maxc - 1)) + "…" : k.name;
          h += `<text class="ns-lab" transform="rotate(${deg.toFixed(1)}) translate(${rr.toFixed(1)} 0) rotate(${flip ? 180 : 0})" text-anchor="middle" dy="4" pointer-events="none">${esc(nm)}</text>`;
        }
        if (rel < 3) walk(k);
      }
    };
    walk(root);
    const f = focus;
    h += `<circle r="${ring * 0.55 - 3}" class="ns-core"/><text class="ns-c1" y="-6" text-anchor="middle">${esc(f === root ? "All names" : f.name)}</text><text class="ns-c2" y="14" text-anchor="middle">${f.n.toLocaleString("en-GB")} lookups</text>${f !== root ? `<text class="ns-c3" y="32" text-anchor="middle">click to go back</text>` : ""}`;
    svg.innerHTML = h;
    svg._idx = idx;
  }
  function zoomTo(nd) {
    cancelAnimationFrame(anim);
    const from = { ...view }, to = { a0: nd.a0, a1: nd.a1, depth: nd.depth }, t0 = performance.now();
    focus = nd; side();
    const step = t => { const k = Math.min(1, (t - t0) / 520), e = 1 - Math.pow(1 - k, 3);
      view = { a0: from.a0 + (to.a0 - from.a0) * e, a1: from.a1 + (to.a1 - from.a1) * e, depth: e < 0.5 ? from.depth : to.depth };
      render(); if (k < 1) anim = requestAnimationFrame(step); };
    anim = requestAnimationFrame(step);
  }
  svg.addEventListener("click", e => {
    const el = e.target.closest(".ns-arc");
    if (el) { const k = svg._idx[+el.dataset.i]; if (k.kids.size) zoomTo(k); return; }
    if (e.target.closest(".ns-core, .ns-c1, .ns-c2, .ns-c3") && focus !== root) zoomTo(focus.parent || root);
  });
  svg.addEventListener("pointermove", e => {
    const el = e.target.closest(".ns-arc"); if (!el) { tip.hidden = true; return; }
    const k = svg._idx[+el.dataset.i]; tip.hidden = false;
    const kind = k.depth === 1 ? "ending" : k.depth === 2 ? "registered name" : "host";
    tip.innerHTML = `<div class="t">${esc(k.name)}</div><div class="r"><span>${kind}</span><b>${k.n.toLocaleString("en-GB")} lookups</b></div>${k.depth < 3 ? `<div class="r"><span>names inside</span><b>${countLeaves(k)}</b></div>` : ""}<div class="r"><span>blocked</span><b>${k.b ? Math.round(100 * k.b / k.n) + "%" : "none"}</b></div>`;
    const b = host.getBoundingClientRect(); tip.style.left = Math.min(Math.max(e.clientX - b.left, 120), b.width - 120) + "px"; tip.style.top = (e.clientY - b.top) + "px";
  });
  svg.addEventListener("pointerleave", () => { tip.hidden = true; });
  const countLeaves = nd => nd.kids.size ? [...nd.kids.values()].reduce((s, k) => s + countLeaves(k), 0) : 1;
  function side() {
    const f = focus, kids = f.list.slice(0, 14), mx = Math.max(1, ...kids.map(k => k.n));
    $("#nsside", main).innerHTML = `<h3>${esc(f === root ? "Biggest endings" : f.name)}</h3><p class="muted">${f === root ? "Click one to open it" : `${f.n.toLocaleString("en-GB")} lookups · ${countLeaves(f)} names${f.b ? ` · ${Math.round(100 * f.b / f.n)}% blocked` : ""}`}</p>
      <div class="ns-list">${kids.map((k, i) => `<button class="ns-item" data-i="${i}"><span><i style="background:${colorOf(k)}"></i>${esc(k.name)}</span><i class="pp-abar"><i style="width:${(100 * k.n / mx).toFixed(1)}%;background:${colorOf(k)}"></i></i><b>${k.n.toLocaleString("en-GB")}${k.b ? ` <em class="crit-t">${Math.round(100 * k.b / k.n)}%</em>` : ""}</b></button>`).join("")}</div>
      ${f !== root ? `<button class="mplay ns-up">← Back to ${esc(f.parent === root ? "all names" : f.parent.name)}</button>` : ""}`;
    $("#nsside", main).querySelectorAll(".ns-item").forEach(b => b.onclick = () => { const k = kids[+b.dataset.i]; if (k.kids.size) zoomTo(k); });
    const up = $(".ns-up", main); if (up) up.onclick = () => zoomTo(f.parent || root);
  }
  function stats() {
    const regs = new Map(); for (const [dom, n, b] of d.domains) { const r = regDomain(dom); const e = regs.get(r) || regs.set(r, { n: 0, hosts: 0, b: 0 }).get(r); e.n += n; e.hosts++; e.b += b; }
    const sprawl = [...regs.entries()].filter(e => !e[0].endsWith(".arpa")).sort((a, b) => b[1].hosts - a[1].hosts)[0], tot = d.domains.reduce((s, x) => s + x[1], 0), bl = d.domains.reduce((s, x) => s + x[2], 0);
    const tracker = [...regs.entries()].filter(e => e[1].b).sort((a, b) => b[1].b - a[1].b)[0];
    $("#nsstats", main).innerHTML =
      tile4("Names looked up", d.domains.length.toLocaleString("en-GB"), `${tot.toLocaleString("en-GB")} lookups · ${regs.size.toLocaleString("en-GB")} registered names`) +
      tile4("Biggest sprawl", sprawl ? esc(sprawl[0]) : "–", sprawl ? `${sprawl[1].hosts} different host names` : "", "ug") +
      tile4("Blocked", `${tot ? Math.round(100 * bl / tot) : 0}<small>%</small>`, `${bl.toLocaleString("en-GB")} lookups stopped by the DNS filter`, "crit") +
      tile4("Most blocked", tracker ? esc(tracker[0]) : "–", tracker ? `${tracker[1].b.toLocaleString("en-GB")} blocked lookups` : "nothing blocked", "fence");
  }
  async function load(range) {
    try { d = await api(`api/names?range=${range}`); } catch { return; }
    const keep = focus && focus !== root ? focus.name : null;
    build(); stats();
    if (keep) { const find = nd => nd.name === keep ? nd : [...nd.kids.values()].map(find).find(Boolean); const nd = find(root); if (nd) { focus = nd; view = { a0: nd.a0, a1: nd.a1, depth: nd.depth }; } else view = { a0: 0, a1: 1, depth: 0 }; }
    else view = { a0: 0, a1: 1, depth: 0 };
    render(); side();
  }
  const seg = rangeSeg("namespace", ["1h", "6h", "24h", "7d"], "24h", r => { seg.value = r; focus = null; load(r); });
  $("#seg", main).replaceWith(seg.node);
  load(seg.value);
  const iv = setInterval(() => load(seg.value), 180000);
  let roW = 0;
  const ro = new ResizeObserver(([en]) => { const w = en.contentRect.width; if (d && Math.abs(w - roW) > 20) { roW = w; render(); } }); ro.observe(host);
  return () => { clearInterval(iv); ro.disconnect(); cancelAnimationFrame(anim); };
};

/* ---------------------------------------------------------------- machine health
   One card per machine: what needs attention in plain English first, then disk, memory, heat, battery,
   network, pending updates and security settings, with small trend lines. Below, a patch matrix across all
   machines. Everything is read-only: the reporters list updates, they never install them. */
const MH_SEV = ["ok", "warn", "crit"];
function mhSpark(pts, { w = 120, h = 26, lo = null, hi = null, col = "var(--down)" } = {}) {
  if (!pts || pts.length < 6) return "";                    // a trend needs about half an hour of reports
  const vs = pts.map(p => p[1]), mn = lo ?? Math.min(...vs), mx = hi ?? Math.max(...vs), t0 = pts[0][0], t1 = pts[pts.length - 1][0] || t0 + 1;
  const x = t => ((t - t0) / Math.max(1, t1 - t0) * w).toFixed(1), y = v => (h - 2 - (v - mn) / Math.max(1e-9, mx - mn) * (h - 4)).toFixed(1);
  return `<svg class="mh-spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-hidden="true"><path d="${pts.map((p, i) => (i ? "L" : "M") + x(p[0]) + " " + y(p[1])).join("")}" fill="none" stroke="${col}" stroke-width="1.6" vector-effect="non-scaling-stroke"/></svg>`;
}
const mhGB = kb => kb >= 1073741824 ? (kb / 1073741824).toFixed(1) + " TB" : kb >= 1048576 ? (kb / 1048576).toFixed(kb >= 10485760 ? 0 : 1) + " GB" : Math.round(kb / 1024) + " MB";
const mhDur = s => s >= 86400 ? `${Math.floor(s / 86400)} d ${Math.floor(s % 86400 / 3600)} h` : s >= 3600 ? `${Math.floor(s / 3600)} h ${Math.floor(s % 3600 / 60)} min` : `${Math.max(1, Math.round(s / 60))} min`;
const mhAgo = s => s < 90 ? "just now" : s < 5400 ? `${Math.round(s / 60)} min ago` : s < 172800 ? `${Math.round(s / 3600)} h ago` : `${Math.round(s / 86400)} days ago`;
/* Friendly names for mount points: the macOS data volume, the root disk, macOS external volumes, OpenWrt flash. */
const mhMount = m => /^\/System\/Volumes\/Data$/.test(m) ? "Internal disk" : m === "/" ? "System disk" : /^\/Volumes\//.test(m) ? m.replace(/^\/Volumes\//, "") : m === "/overlay" ? "Flash storage" : m;

VIEWS.health = main => {
  main.innerHTML = `<div class="head"><h1>Machine health</h1><p>Disk, memory, heat, updates and security settings for each machine. Read-only: updates are listed, never installed.</p><div class="grow"></div><span id="seg"></span></div>
    <div class="topo-stats" id="mhstats"></div>
    <div class="mh-grid" id="mhgrid"><div class="pp-card pp-skel"></div><div class="pp-card pp-skel"></div></div>
    <section class="panel" style="margin-top:14px"><div class="ph"><h2>Patch matrix</h2><span class="sub">what each machine is waiting for · counts come from each machine's own update lists</span></div><div class="tscroll" id="mhpatch"></div></section>`;
  let d = null;
  function stats() {
    const ms = d.machines, rep = ms.filter(m => m.facts && m.age < 900), att = ms.filter(m => (m.findings || []).some(f => f[0] > 0));
    const upd = ms.reduce((s, m) => s + (m.facts ? m.facts.upd_os.length + m.facts.pkgs.reduce((a, p) => a + (p.security || 0), 0) : 0), 0);
    const sec = ms.reduce((s, m) => s + (m.findings || []).filter(f => f[1] === "security").length, 0);
    const crit = ms.some(m => (m.findings || []).some(f => f[0] === 2));
    $("#mhstats", main).innerHTML =
      tile4("Machines reporting", `${rep.length}<small> of ${ms.length}</small>`, ms.filter(m => !m.facts).map(m => m.name).join(", ") ? `not yet: ${esc(ms.filter(m => !m.facts).map(m => m.name).join(", "))}` : "all reporting", rep.length === ms.length ? "ok" : "fence") +
      tile4("Need attention", att.length, att.length ? esc(att.map(m => m.name).join(", ")) : "nothing needs a look", crit ? "crit" : att.length ? "warn" : "ok") +
      tile4("Updates waiting", upd, "system updates and security patches", upd ? "warn" : "ok") +
      tile4("Security settings", sec ? `${sec}<small> to check</small>` : "✓", sec ? "encryption, firewall and similar" : "all as they should be", sec ? "warn" : "ok");
  }
  function card(m) {
    const f = m.facts;
    if (!f) {
      return `<article class="mh-card off"><header><i class="mh-dot off"></i><div><h3>${esc(m.name)}</h3><small>${m.on_demand ? "switched off · runs on demand" : "no report yet"}</small></div></header>
        <p class="muted">${esc(m.note || (m.installer ? "Waiting for the one-line installer on this machine." : "No report has arrived yet."))}</p>
        ${m.installer ? `<div class="mh-install"><p>On this machine, open a terminal and paste this line. It installs a read-only reporter in the current account (no admin rights) and can be removed with one command.</p>
          <div class="mh-cmd"><code id="mhcmd">curl -s "${esc(location.origin)}/api/health/installer?m=${encodeURIComponent(m.id)}" | sh</code><button class="mplay" id="mhcopy">Copy</button></div>
          <p class="muted">The link works once, and only from the address configured for this machine.</p></div>` : ""}</article>`;
    }
    const fnd = m.findings || [], sev = fnd.length ? Math.max(...fnd.map(x => x[0])) : 0, stale = m.age > 900;
    const hist = m.history || {}, mem = f.mem || {}, sw = f.swap || {};
    const memPct = mem.total_kb ? 100 - 100 * mem.avail_kb / mem.total_kb : null;
    const bar = (pct, cls = "") => `<i class="mh-bar ${cls}"><i style="width:${Math.max(0, Math.min(100, pct)).toFixed(1)}%"></i></i>`;
    const lvl = (p, w, c) => p >= c ? "crit" : p >= w ? "warn" : "";
    const disks = f.disks.filter(x => !["ram", "iso9660"].includes(x.fs)).map(x => {
      const tot = x.used_kb + x.avail_kb, pct = tot ? 100 * x.used_kb / tot : 0, full = (m.full_in_days || {})[x.mount];
      return `<div class="mh-row"><span>${esc(mhMount(x.mount))}</span>${bar(pct, lvl(pct, 85, 95))}<b>${pct.toFixed(0)}%</b><small>${mhGB(x.avail_kb)} free${full && full < 180 ? ` · full in ~${Math.round(full)} days` : ""}</small>${mhSpark(hist["disk:" + x.mount], { lo: 0, hi: 100, col: "var(--up)" })}</div>`;
    }).join("") + f.pools.map(p => `<div class="mh-row"><span>ZFS ${esc(p.name)}</span>${bar(100 * p.alloc / p.size, p.health !== "ONLINE" ? "crit" : lvl(100 * p.alloc / p.size, 85, 95))}<b>${Math.round(100 * p.alloc / p.size)}%</b><small>${esc(p.health)} · ${mhGB(p.free / 1024)} free</small></div>`).join("");
    const temps = [...f.temps].sort((a, b) => b.c - a.c).slice(0, 4).map(t => `<span class="mh-chip ${t.c >= 85 ? "crit" : t.c >= 75 ? "warn" : ""}">${esc(t.label.replace(/^cpu-thermal$/, "CPU"))} ${t.c.toFixed(0)} °C</span>`).join("");
    const b = f.batt;
    const po = f.posture || {}, P = [];
    const chip = (ok, label, title) => P.push(`<span class="mh-p ${ok === true ? "ok" : ok === false ? "bad" : "info"}" title="${esc(title || "")}">${ok === true ? "✓" : ok === false ? "✗" : "•"} ${label}</span>`);
    if (po.filevault) chip(/On/.test(po.filevault), "FileVault", po.filevault);
    if (po.firewall) chip(/enabled/.test(po.firewall), "Firewall", po.firewall);
    if (po.sip) chip(/enabled/.test(po.sip), "SIP", po.sip);
    if (po.gatekeeper) chip(/enabled/.test(po.gatekeeper), "Gatekeeper", po.gatekeeper);
    if (po.auto_security) chip(po.auto_security === "1" ? true : po.auto_security === "0" ? false : null, "Auto security fixes");
    if (po.auto_macos) chip(po.auto_macos === "1" ? true : null, "Auto macOS updates", po.auto_macos === "1" ? "on" : "off: updates wait for a click");
    if (po.remote_login) chip(null, `Remote login ${po.remote_login}`);
    if (po.screen_sharing) chip(null, `Screen sharing ${po.screen_sharing}`);
    if (po.unattended_upgrades) chip(po.unattended_upgrades === "installed", "Automatic security updates");
    if (po.ssh_password_auth) chip(po.ssh_password_auth === "off", "SSH password login off");
    if (po.vpn_kill_switch) chip(po.vpn_kill_switch === "1", "VPN kill switch");
    if (po.doh_block) chip(!/^0 /.test(po.doh_block), `DoH block (${esc(po.doh_block)})`);
    const upd = [...f.upd_os.map(u => `<div class="mh-u"><b>${esc(u.label)}</b>${u.restart ? `<span class="mh-chip warn">restart</span>` : ""}</div>`),
      ...f.pkgs.map(p => `<div class="mh-u"><b>${p.count} ${esc(p.kind)} package${p.count === 1 ? "" : "s"}</b>${p.security ? `<span class="mh-chip crit">${p.security} security</span>` : ""}<small>${p.names.slice(0, 6).map(esc).join(", ")}${p.names.length > 6 ? "…" : ""}${p.lists_ts ? ` · lists from ${mhAgo(d.now - p.lists_ts)}` : ""}</small></div>`),
      f.reboot ? `<div class="mh-u"><b>Restart needed</b><small>${esc(f.reboot)}</small></div>` : "",
      ...f.vers.map(v => `<div class="mh-u"><small>${esc(v)}</small></div>`)].join("");
    const bk = f.backup ? `Time Machine ${mhAgo(d.now - f.backup)}` : "";
    return `<article class="mh-card s-${stale ? "stale" : MH_SEV[sev]}">
      <header><i class="mh-dot ${stale ? "off" : MH_SEV[sev]}"></i><div><h3>${esc(m.name)}</h3><small>${esc(f.os || "")}${f.model ? " · " + esc(f.model) : ""}</small></div>
        <span class="mh-meta">${stale ? `<b class="warn-t">last report ${mhAgo(m.age)}</b>` : `reported ${mhAgo(m.age)}`}<br>up ${f.uptime ? mhDur(f.uptime) : "?"}${bk ? " · " + bk : ""}</span></header>
      <div class="mh-find">${fnd.length ? fnd.map(x => `<div class="mh-f ${MH_SEV[x[0]]}"><i></i><span>${esc(x[2])}</span></div>`).join("") : `<div class="mh-f ok"><i></i><span>All good.</span></div>`}</div>
      <div class="mh-sec"><h4>Storage</h4>${disks || `<p class="muted">No disks reported.</p>`}</div>
      <div class="mh-sec mh-two">
        <div><h4>Memory</h4>${memPct != null ? `<div class="mh-row"><span>In use</span>${bar(memPct, mem.pressure === "critical" ? "crit" : mem.pressure === "warning" ? "warn" : "")}<b>${memPct.toFixed(0)}%</b><small>of ${mhGB(mem.total_kb)}${mem.pressure ? ` · pressure ${esc(mem.pressure)}` : ""}</small>${mhSpark(hist.mem_used_pct, { lo: 0, hi: 100, col: "var(--c4)" })}</div>` : ""}
          ${sw.total_kb ? `<div class="mh-row"><span>Swap</span>${bar(100 * sw.used_kb / sw.total_kb, lvl(100 * sw.used_kb / sw.total_kb, 75, 95))}<b>${Math.round(100 * sw.used_kb / sw.total_kb)}%</b><small>${mhGB(sw.used_kb)} of ${mhGB(sw.total_kb)}</small></div>` : ""}
          ${f.load ? `<div class="mh-row"><span>Load</span>${bar(100 * f.load[0] / Math.max(1, f.cpus || 1), lvl(100 * f.load[0] / Math.max(1, f.cpus || 1), 80, 100))}<b>${f.load[0].toFixed(2)}</b><small>${f.cpus || "?"} cores</small>${mhSpark(hist.load1, { lo: 0, col: "var(--c3)" })}</div>` : ""}</div>
        <div><h4>Heat and power</h4><div class="mh-chips">${temps || `<span class="muted">No temperature sensors readable without admin rights.</span>`}${f.therm && f.therm.cpu_speed_limit && f.therm.cpu_speed_limit !== "100" ? `<span class="mh-chip warn">CPU slowed to ${esc(f.therm.cpu_speed_limit)}%</span>` : f.therm && f.therm.warning === "none" ? `<span class="mh-chip">no thermal warning</span>` : ""}</div>
          ${b ? `<div class="mh-row"><span>Battery</span>${bar(b.health_pct || 0, (b.health_pct || 100) < 80 ? "warn" : "")}<b>${b.health_pct != null ? Math.round(b.health_pct) + "%" : "?"}</b><small>health · ${b.cycles} cycles · ${b.temp_c != null ? b.temp_c.toFixed(0) + " °C" : ""} · ${esc(b.power || "")}</small>${mhSpark(hist.batt_temp, { col: "var(--up)" })}</div>` : ""}
          ${f.smart.length ? `<div class="mh-chips">${f.smart.map(s => `<span class="mh-chip ${/verified|passed|ok/i.test(s.status) ? "" : "crit"}">disk ${esc(s.disk)}: ${esc(s.status || "?")}</span>`).join("")}</div>` : ""}
          <h4 style="margin-top:10px">Network</h4><div class="mh-row"><span>Now</span><b class="mh-net">↓ ${m.rx_bps != null ? bitsText(m.rx_bps) : "–"} · ↑ ${m.tx_bps != null ? bitsText(m.tx_bps) : "–"}</b>${mhSpark(hist.rx_bps, { lo: 0, col: "var(--down)" })}</div>
          <small class="muted">${esc(f.addrs.map(a => a.ip).filter(Boolean).join(" · "))}</small></div></div>
      <div class="mh-sec"><h4>Updates</h4>${upd || `<p class="mh-okline">✓ Nothing waiting.</p>`}</div>
      <div class="mh-sec"><h4>Security settings</h4><div class="mh-chips">${P.join("") || `<span class="muted">Not reported for this kind of machine.</span>`}</div></div>
    </article>`;
  }
  function patch() {
    const rows = d.machines.filter(m => m.facts).map(m => {
      const f = m.facts, po = f.posture || {};
      const pk = f.pkgs.map(p => `${p.count} ${esc(p.kind)}${p.security ? ` (<b class="crit-t">${p.security} security</b>)` : ""}`).join(", ") || "–";
      const auto = po.auto_security ? (po.auto_security === "1" ? "security fixes on" : "security fixes OFF") + (po.auto_macos ? (po.auto_macos === "1" ? ", macOS auto" : ", macOS manual") : "") : po.unattended_upgrades ? (po.unattended_upgrades === "installed" ? "unattended-upgrades" : "none") : "–";
      const lists = f.pkgs.filter(p => p.lists_ts).map(p => mhAgo(d.now - p.lists_ts)).join(", ") || "–";
      return `<tr><td><b>${esc(m.name)}</b></td><td>${esc(f.os || "")}</td><td>${f.upd_os.length ? f.upd_os.map(u => esc(u.label)).join("<br>") : "✓ none"}</td><td>${pk}</td><td>${f.reboot || f.upd_os.some(u => u.restart) ? `<b class="warn-t">yes</b>` : "no"}</td><td>${auto}</td><td>${lists}</td></tr>`;
    }).join("");
    $("#mhpatch", main).innerHTML = `<table class="mh-table"><thead><tr><th>Machine</th><th>System</th><th>System updates waiting</th><th>Packages out of date</th><th>Restart needed</th><th>Automatic updates</th><th>Lists checked</th></tr></thead><tbody>${rows}</tbody></table>`;
  }
  function draw() {
    stats();
    const order = m => !m.facts ? 3 : -Math.max(0, ...(m.findings || []).map(f => f[0]));
    $("#mhgrid", main).innerHTML = [...d.machines].sort((a, b) => order(a) - order(b)).map(card).join("");
    patch();
    const cp = $("#mhcopy", main);
    if (cp) cp.onclick = async () => { const t = $("#mhcmd", main).textContent; try { await navigator.clipboard.writeText(t); cp.textContent = "Copied"; } catch { const r = document.createRange(); r.selectNodeContents($("#mhcmd", main)); getSelection().removeAllRanges(); getSelection().addRange(r); cp.textContent = "Selected: press ⌘C"; } };
  }
  async function load(range) { try { d = await api(`api/health?range=${range}`); } catch { return; } draw(); }
  const seg = rangeSeg("health", ["6h", "24h", "7d", "30d"], "24h", r => { seg.value = r; load(r); });
  $("#seg", main).replaceWith(seg.node);
  load(seg.value);
  const iv = setInterval(() => load(seg.value), 60000);
  return () => clearInterval(iv);
};

/* ---------------------------------------------------------------- sidebar: your own order
   Drag a page up or down (into another group too). The order is kept on the collector, so every browser and device
   shows the same menu; this browser keeps a copy only so the menu is right at once while the collector answers. Alt with the
   arrow keys moves the focused page. "Reset menu order" in the footer puts the original order back.
   Group headings travel with the order as markers, so pages added later land next to their default neighbour. */
function navTokens(nav) { return [...nav.children].map(el => el.matches(".nav-h") ? "h:" + el.textContent.trim() : el.dataset.view).filter(Boolean); }
function navApply(nav, order) {
  const byTok = new Map([...nav.children].map(el => [el.matches(".nav-h") ? "h:" + el.textContent.trim() : el.dataset.view, el]));
  const def = NAV_DEFAULT, seen = new Set(), out = [];
  for (const t of order) if (byTok.has(t) && !seen.has(t)) { out.push(t); seen.add(t); }
  def.forEach((t, i) => {                                     // anything new since the order was saved: after its default neighbour
    if (seen.has(t) || !byTok.has(t)) return;
    let k = i - 1; while (k >= 0 && !seen.has(def[k])) k--;
    const at = k < 0 ? 0 : out.indexOf(def[k]) + 1;
    out.splice(at, 0, t); seen.add(t);
  });
  for (const t of out) nav.appendChild(byTok.get(t));
}
let NAV_DEFAULT = [];
function navInit() {
  const nav = document.querySelector(".nav"); if (!nav) return;
  NAV_DEFAULT = navTokens(nav);
  let custom = store.get("nav.order", null);
  if (Array.isArray(custom)) navApply(nav, custom);
  api("api/navorder").then(d => {                            // the collector's copy wins
    custom = Array.isArray(d.order) ? d.order : null;
    if (custom) { store.set("nav.order", custom); navApply(nav, custom); }
    else { try { localStorage.removeItem("netmon.nav.order"); } catch { /* private window */ } navApply(nav, NAV_DEFAULT); }
    sync();
  }).catch(() => {});
  const foot = document.querySelector(".side-foot");
  const reset = document.createElement("button");
  reset.className = "nav-reset"; reset.type = "button"; reset.textContent = "Reset menu order";
  const sync = () => { reset.hidden = !custom; };
  reset.onclick = () => { custom = null; try { localStorage.removeItem("netmon.nav.order"); } catch { /* private window */ } navApply(nav, NAV_DEFAULT); sync(); post("api/navorder", { order: null }).catch(() => {}); };
  foot && foot.prepend(reset); sync();
  const save = () => { custom = navTokens(nav); store.set("nav.order", custom); sync(); post("api/navorder", { order: custom }).catch(() => {}); };
  let dragging = null;
  const clear = () => nav.querySelectorAll(".drop-before, .drop-after").forEach(e => e.classList.remove("drop-before", "drop-after"));
  nav.querySelectorAll("a[data-view]").forEach(a => {
    a.draggable = true;
    a.title = a.title || "Drag to reorder the menu";
    a.addEventListener("dragstart", e => { dragging = a; a.classList.add("dragging"); e.dataTransfer.effectAllowed = "move"; e.dataTransfer.setData("text/plain", a.dataset.view); });
    a.addEventListener("dragend", () => { a.classList.remove("dragging"); dragging = null; clear(); });
    a.addEventListener("keydown", e => {
      if (!e.altKey || (e.key !== "ArrowUp" && e.key !== "ArrowDown")) return;
      e.preventDefault();
      const sib = e.key === "ArrowUp" ? a.previousElementSibling : a.nextElementSibling;
      if (!sib) return;
      if (e.key === "ArrowUp") nav.insertBefore(a, sib); else nav.insertBefore(sib, a);
      a.focus(); save();
    });
  });
  nav.addEventListener("dragover", e => {
    if (!dragging) return;
    const t = e.target.closest(".nav > a, .nav > .nav-h"); if (!t || t === dragging) return;
    e.preventDefault(); e.dataTransfer.dropEffect = "move";
    const r = t.getBoundingClientRect(), after = e.clientY > r.top + r.height / 2 && !t.matches(".nav-h");
    clear(); t.classList.add(after ? "drop-after" : "drop-before");
    // near the top or bottom edge of the menu, scroll it so long lists can be crossed
    const nr = nav.getBoundingClientRect();
    if (e.clientY < nr.top + 28) nav.scrollTop -= 12; else if (e.clientY > nr.bottom - 28) nav.scrollTop += 12;
  });
  nav.addEventListener("drop", e => {
    if (!dragging) return;
    const t = nav.querySelector(".drop-before, .drop-after"); if (!t) return;
    e.preventDefault();
    if (t.classList.contains("drop-after")) t.after(dragging); else t.before(dragging);
    clear(); save();
  });
  nav.addEventListener("dragleave", e => { if (!nav.contains(e.relatedTarget)) clear(); });
}
navInit();

/* ---------------------------------------------------------------- bufferbloat
   How much delay builds up when the line is busy, and which packets are lost. One dot per minute: how busy the
   download was against how long a ping to the first internet target took, split at fix_ts (the moment the
   payload marks as a shaping change; 0 when there is none). Then each of the router's CAKE shapers with its
   tiers, queue delay and intended drops, and the two kinds of loss side by side. A button runs a 20-second
   load test from the collector and grades it. */
const BL_TIN = { "Bulk": "--ink-3", "Best Effort": "--down", "Best effort": "--down", "Video": "--c4", "Voice": "--c3" };
/* The first latency target that is neither the router nor the uplink. */
const inetTarget = names => names.find(n => n !== rtrName() && n !== upName()) || names[0];
VIEWS.bloat = main => {
  main.innerHTML = `<div class="head"><h1>Bufferbloat</h1><p>How much delay builds up when the line is busy, and which packets get lost. A healthy line adds almost nothing when full.</p><div class="grow"></div><span id="seg"></span></div>
    <div class="topo-stats" id="blstats"></div>
    <section class="panel"><div class="ph"><h2>Delay against load</h2><span class="sub">one dot per minute: how busy the download was, and how long a ping to the internet took</span></div>
      <div class="bl-host" id="blsc"></div>
      <div class="globe-legend"><span><i class="sw" style="background:var(--crit)"></i>Before the marked shaping change</span><span><i class="sw" style="background:var(--ok)"></i>After it</span><span class="muted">A flat line is good: the busier the line, the more a bloated one climbs</span></div></section>
    <section class="panel" style="margin-top:14px"><div class="ph"><h2>The shapers</h2><span class="sub">traffic per tier, and the packets each shaper dropped on purpose to keep its queue short</span></div>
      <div class="bl-grid" id="blq"></div>
      <div class="globe-legend"><span><i class="sw" style="background:var(--c4)"></i>Video</span><span><i class="sw" style="background:var(--down)"></i>Best effort</span><span><i class="sw" style="background:var(--c3)"></i>Voice</span><span><i class="sw" style="background:var(--ink-3)"></i>Bulk</span><span><i class="sw bl-sw-drop"></i>Dropped on purpose</span></div></section>
    <section class="panel" style="margin-top:14px"><div class="ph"><h2>Lost packets, told apart</h2><span class="sub">pings that never came back (bad) against drops the shaper chose (good: they keep delay low)</span></div><div id="blloss"></div></section>
    <section class="panel" style="margin-top:14px"><div class="ph"><h2>Load test</h2><span class="sub">20 seconds of full load from the collector, with a ping every fifth of a second</span></div>
      <div class="topo-tools"><button class="mplay" id="bltest">Run a 20-second test</button><span class="topo-hint" id="blmsg">Everyone on the network shares the line during the test.</span></div><div class="tscroll" id="bltests"></div></section>`;
  let d = null, poll = 0;
  const mb = v => v >= 10 ? Math.round(v) : v.toFixed(1);
  const fixTs = () => d.fix_ts || 0;
  const inetName = () => d.ref_target || inetTarget([...new Set(d.latency.map(r => r[1]))]);
  function stats() {
    const after = d.scatter.filter(s => s[0] >= fixTs()), idle = after.filter(s => s[1] < 2).map(s => s[3]).sort((a, b) => a - b);
    const im = idle.length ? idle[idle.length >> 1] : 21;
    const busy = after.filter(s => s[1] > 20).map(s => s[3]).sort((a, b) => a - b), bp = busy.length ? busy[Math.floor(.9 * (busy.length - 1))] : null;
    const t = d.tests[0], hr = d.now - 3600;
    const lossRows = d.latency.filter(r => r[0] >= hr && r[1] === inetName()), loss = lossRows.length ? lossRows.reduce((s, r) => s + (r[4] || 0), 0) / lossRows.length : 0;
    let dropped = 0, bytes = 0;
    for (const [ts, dev, tin, b, dr] of d.minutes) if (ts >= hr) { dropped += dr; bytes += b; }
    const g = t && t.grade ? t.grade : bp != null ? gradeOf(bp - im) : "?";
    $("#blstats", main).innerHTML =
      tile4("Grade", `<span class="bl-grade g-${g.replace("+", "p")}">${g}</span>`, t && t.grade ? `last test ${stamp(t.ts)}` : "from busy minutes since the shaping change", /A/.test(g) ? "ok" : /B|C/.test(g) ? "warn" : "crit") +
      tile4("Added delay when busy", bp != null ? `${Math.max(0, bp - im).toFixed(0)}<small> ms</small>` : "–", bp != null ? `${busy.length} busy minutes · idle ${im.toFixed(0)} ms` : "no busy minutes yet", bp == null || bp - im < 30 ? "ok" : "warn") +
      tile4("Dropped on purpose", dropped.toLocaleString("en-GB"), `packets in the last hour · ${bytes ? bitsText(bytes * 8 / 3600) : "0 bit/s"} average`, "fence") +
      tile4("Pings lost", `${loss.toFixed(1)}<small>%</small>`, `to ${esc(inetName() || "the internet")} in the last hour`, loss > 2 ? "warn" : "ok");
  }
  const gradeOf = a => a < 5 ? "A+" : a < 30 ? "A" : a < 60 ? "B" : a < 200 ? "C" : a < 400 ? "D" : "F";
  function scatter() {
    const box = $("#blsc", main), W = Math.max(360, box.clientWidth), H = 300, L = 54, R = 16, T = 12, B = 40;
    const pts = d.scatter, mx = Math.max(10, ...pts.map(p => p[1])), my = Math.min(700, Math.max(80, ...pts.map(p => p[3])));
    const x = v => L + v / mx * (W - L - R), y = v => T + (1 - Math.min(v, my) / my) * (H - T - B);
    let h = "";
    for (let i = 0; i <= 4; i++) { const v = my * i / 4; h += `<line x1="${L}" x2="${W - R}" y1="${y(v)}" y2="${y(v)}" class="bc-grid"/><text x="${L - 6}" y="${y(v) + 4}" text-anchor="end" class="bc-ax">${Math.round(v)} ms</text>`; }
    for (let i = 0; i <= 5; i++) { const v = mx * i / 5; h += `<text x="${x(v)}" y="${H - 20}" text-anchor="middle" class="bc-ax">${mb(v)}</text>`; }
    h += `<text x="${(L + W - R) / 2}" y="${H - 4}" text-anchor="middle" class="bc-ax">download in that minute, Mbit/s</text>`;
    pts.forEach((p, i) => h += `<circle cx="${x(p[1]).toFixed(1)}" cy="${y(p[3]).toFixed(1)}" r="${p[5] > 0 ? 4.2 : 3.2}" class="bl-dot ${p[0] < fixTs() ? "pre" : "post"}${p[5] > 0 ? " lossy" : ""}" data-i="${i}"/>`);
    box.innerHTML = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Ping delay against download load, one dot per minute">${h}</svg><div class="tip bl-tip" hidden></div>`;
    const svg = box.querySelector("svg"), tip = box.querySelector(".bl-tip");
    svg.addEventListener("pointermove", e => {
      const el = e.target.closest(".bl-dot"); if (!el) { tip.hidden = true; return; }
      const p = pts[+el.dataset.i]; tip.hidden = false;
      tip.innerHTML = `<div class="t">${locTime(p[0])} ${TZL}${fixTs() ? ` · ${p[0] < fixTs() ? "before the change" : "after the change"}` : ""}</div><div class="r"><span>Download</span><b>${mb(p[1])} Mbit/s</b></div><div class="r"><span>Upload</span><b>${mb(p[2])} Mbit/s</b></div><div class="r"><span>Ping, typical</span><b>${p[3].toFixed(0)} ms</b></div><div class="r"><span>Ping, worst</span><b>${p[4] != null ? p[4].toFixed(0) + " ms" : "–"}</b></div><div class="r"><span>Lost</span><b>${(p[5] || 0).toFixed(0)}%</b></div>`;
      const b = box.getBoundingClientRect(); tip.style.left = Math.min(Math.max(e.clientX - b.left, 110), b.width - 110) + "px"; tip.style.top = (e.clientY - b.top) + "px";
    });
    svg.addEventListener("pointerleave", () => { tip.hidden = true; });
  }
  function queues() {
    const t1 = d.now, t0 = t1 - d.span, by = {};
    for (const [ts, dev, tin, b, dr, mk, av, pk] of d.minutes) {
      const e = by[dev] || (by[dev] = new Map()); const m = e.get(ts) || e.set(ts, { tins: [], drops: 0, marks: 0, pk: 0 }).get(ts);
      m.tins[tin] = b * 8 / 60; m.drops += dr; m.marks += mk; m.pk = Math.max(m.pk, pk || 0);
    }
    const lastLive = d.live[d.live.length - 1] || { devs: {} };
    const devs = [...new Set([...Object.keys(d.current || {}), ...Object.keys(by)])].sort();
    $("#blq", main).innerHTML = devs.map(dev => {
      const cur = d.current[dev] || {}, names = cur.names || ["Bulk", "Best Effort", "Video", "Voice"], mins = [...(by[dev] || new Map()).entries()].sort((a, b) => a[0] - b[0]);
      const lv = lastLive.devs[dev], rate = lv ? lv.tins.reduce((s, t) => s + t[0], 0) * 8 / (lv.dt || 10) : null;
      const qd = lv ? Math.max(0, ...lv.tins.map(t => t[3] || 0)) / 1000 : null, vid = lv ? (lv.tins[2] || [0])[0] * 8 / (lv.dt || 10) : 0;
      const W = 460, H = 120, DH = 26, bw = cur.bw || 1, x = t => (t - t0) / d.span * W;
      const ymax = Math.max(bw, ...mins.map(([, m]) => m.tins.reduce((s, v) => s + (v || 0), 0))), y = v => H - v / ymax * (H - 6);
      let h = `<line x1="0" x2="${W}" y1="${y(bw)}" y2="${y(bw)}" class="bl-cap"/>`;
      const bwpx = Math.max(1, W / (d.span / 60));
      for (const [ts, m] of mins) {
        let acc = 0;
        [1, 0, 3, 2].forEach(ti => { const v = m.tins[ti] || 0; if (!v) return; const y0 = y(acc), y1 = y(acc + v); acc += v;
          h += `<rect x="${x(ts).toFixed(1)}" y="${y1.toFixed(1)}" width="${bwpx.toFixed(2)}" height="${Math.max(.5, y0 - y1).toFixed(1)}" fill="var(${BL_TIN[names[ti]] || "--ink-3"})"/>`; });
      }
      const md = Math.max(1, ...mins.map(([, m]) => m.drops));
      for (const [ts, m] of mins) if (m.drops) h += `<rect x="${x(ts).toFixed(1)}" y="${(H + 6 + DH - m.drops / md * DH).toFixed(1)}" width="${bwpx.toFixed(2)}" height="${(m.drops / md * DH).toFixed(1)}" class="bl-drop"><title>${locTime(ts)}: ${m.drops} dropped, ${m.marks} marked, worst queue ${(m.pk / 1000).toFixed(1)} ms</title></rect>`;
      return `<div class="bl-card"><div class="bl-h"><b>${esc(d.devs[dev] || dev)}</b><span>limit ${mb(bw / 1e6)} Mbit/s (dashed line)${rate != null ? " · " : ""}${rate != null ? `${mb(rate / 1e6)} Mbit/s now` : ""}${qd != null ? ` · queue ${qd < 1 ? "under 1" : qd.toFixed(1)} ms` : ""}${vid > 1000 ? ` · Video ${mb(vid / 1e6)} Mbit/s` : ""}</span></div>
        <svg viewBox="0 0 ${W} ${H + DH + 10}" preserveAspectRatio="none" class="bl-q" role="img" aria-label="${esc(d.devs[dev] || dev)} over time">${h}</svg>
        <div class="bl-foot"><span>${locTime(t0)}</span><span class="muted">drops per minute below</span><span>now</span></div></div>`;
    }).join("") || `<p class="muted">Collecting: the first minutes appear shortly.</p>`;
  }
  function loss() {
    const box = $("#blloss", main), W = Math.max(360, box.clientWidth), L = 110, R = 12, t1 = d.now, t0 = t1 - d.span, x = t => L + (t - t0) / d.span * (W - L - R);
    const bwpx = Math.max(1, (W - L - R) / (d.span / 60)), rowH = 44;
    const rows = [[inetName(), `Pings to ${inetName()} with no answer`, "--crit"], [upName(), `Pings to ${upName()} with no answer`, "--warn"]];
    let h = "", y0 = 6;
    for (const [tg, label, col] of rows) {
      h += `<text x="0" y="${y0 + 16}" class="bl-rl">${label.replace(" with no answer", "")}</text><text x="0" y="${y0 + 31}" class="bc-ax">no answer, % per minute</text><line x1="${L}" x2="${W - R}" y1="${y0 + rowH - 6}" y2="${y0 + rowH - 6}" class="bc-grid"/>`;
      for (const r of d.latency) if (r[1] === tg && r[4] > 0) h += `<rect x="${x(r[0]).toFixed(1)}" y="${(y0 + rowH - 6 - r[4] / 100 * (rowH - 10)).toFixed(1)}" width="${bwpx.toFixed(2)}" height="${(r[4] / 100 * (rowH - 10)).toFixed(1)}" fill="var(${col})"><title>${locTime(r[0])}: ${r[4].toFixed(0)}% lost to ${tg}</title></rect>`;
      y0 += rowH;
    }
    const dm = new Map(); for (const [ts, , , , dr] of d.minutes) dm.set(ts, (dm.get(ts) || 0) + dr);
    const mxd = Math.max(1, ...dm.values());
    h += `<text x="0" y="${y0 + 16}" class="bl-rl">Shaper drops</text><text x="0" y="${y0 + 31}" class="bc-ax">on purpose, per minute</text><line x1="${L}" x2="${W - R}" y1="${y0 + rowH - 6}" y2="${y0 + rowH - 6}" class="bc-grid"/>`;
    for (const [ts, dr] of dm) if (dr) h += `<rect x="${x(ts).toFixed(1)}" y="${(y0 + rowH - 6 - dr / mxd * (rowH - 10)).toFixed(1)}" width="${bwpx.toFixed(2)}" height="${(dr / mxd * (rowH - 10)).toFixed(1)}" class="bl-drop"><title>${locTime(ts)}: ${dr} packets dropped on purpose</title></rect>`;
    y0 += rowH;
    for (let i = 0; i <= 6; i++) { const t = t0 + d.span * i / 6; h += `<text x="${x(t)}" y="${y0 + 12}" text-anchor="middle" class="bc-ax">${d.span > 86400 ? dayOf(t) : locTime(t)}</text>`; }
    if (fixTs() > t0) h += `<line x1="${x(fixTs())}" x2="${x(fixTs())}" y1="0" y2="${y0}" class="bl-fix"/><text x="${x(fixTs()) + 4}" y="10" class="bc-ax">change</text>`;
    box.innerHTML = `<svg viewBox="0 0 ${W} ${y0 + 18}" role="img" aria-label="Lost pings and shaper drops over time">${h}</svg>
      <p class="muted bl-note">A shaper drop tells one busy download to slow down, so everyone else's packets never wait. A lost ping is a packet that should have arrived and did not. The first should rise under load; the second should stay near zero.</p>`;
  }
  function tests() {
    const rows = d.tests.map(t => t.error ? `<tr><td>${stamp(t.ts)}</td><td colspan="8" class="crit-t">${esc(t.error)}</td></tr>` :
      `<tr><td>${stamp(t.ts)}</td><td>${t.vpn ? "VPN on" : "direct"}</td><td>${mb(t.down_mbps)}</td><td>${mb(t.up_mbps)}</td><td>${t.idle_ms != null ? t.idle_ms.toFixed(0) : "–"}</td><td>${t.load_p90_ms != null ? t.load_p90_ms.toFixed(0) : "–"}</td><td><b>${t.added_ms != null ? Math.max(0, t.added_ms).toFixed(0) : "–"}</b></td><td>${t.lost}</td><td><span class="bl-grade sm g-${String(t.grade).replace("+", "p")}">${esc(t.grade)}</span></td></tr>`).join("");
    $("#bltests", main).innerHTML = rows ? `<table class="mh-table"><thead><tr><th>When</th><th>VPN</th><th>Down Mbit/s</th><th>Up Mbit/s</th><th>Idle ms</th><th>Busy ms (90%)</th><th>Added ms</th><th>Pings lost</th><th>Grade</th></tr></thead><tbody>${rows}</tbody></table>` : `<p class="muted">No test yet. The grade uses the delay added under load: A+ under 5 ms, A under 30, B under 60, C under 200, D under 400, F above.</p>`;
    const b = $("#bltest", main); b.hidden = d.load_test === false; b.disabled = !!d.busy; b.textContent = d.busy ? "Testing… about 30 seconds" : "Run a 20-second test";
    if (d.load_test === false) $("#blmsg", main).textContent = "The load test is off. Set actions.load_test in config.json to allow it.";
  }
  function draw() { stats(); scatter(); queues(); loss(); tests(); }
  $("#bltest", main).onclick = async () => {
    const r = await post("api/bloat/test", {}).catch(() => ({ ok: false, error: "no answer" }));
    $("#blmsg", main).textContent = r.ok ? "Running: the line is flat out for 20 seconds." : (r.error || "could not start");
    clearInterval(poll); poll = setInterval(async () => { await load(seg.value); if (!d.busy) { clearInterval(poll); $("#blmsg", main).textContent = "Done."; } }, 4000);
    await load(seg.value);
  };
  async function load(range) { try { d = await api(`api/bloat?range=${range}`); } catch { return; } draw(); }
  const seg = rangeSeg("bloat", ["6h", "24h", "7d"], "6h", r => { seg.value = r; load(r); });
  $("#seg", main).replaceWith(seg.node);
  load(seg.value);
  const iv = setInterval(() => load(seg.value), 30000);
  let roW = 0;
  const ro = new ResizeObserver(([en]) => { const w = en.contentRect.width; if (d && Math.abs(w - roW) > 20) { roW = w; scatter(); loss(); } }); ro.observe($("#blsc", main));
  return () => { clearInterval(iv); clearInterval(poll); ro.disconnect(); };
};

/* ---------------------------------------------------------------- DNS speed
   How long the network waits for names. Cached and blocked answers come from the DNS filter itself in about
   0 ms; the rest go to the upstream resolver (inside the VPN tunnel while the VPN is on). */
VIEWS.dnsspeed = main => {
  main.innerHTML = `<div class="head"><h1>DNS speed</h1><p>How long the network waits for a name to turn into an address. Every web page starts with a few of these.</p><div class="grow"></div><span id="seg"></span></div>
    <div class="topo-stats" id="dsstats"></div>
    <section class="panel"><div class="ph"><h2>How long lookups take</h2><span class="sub">only lookups the DNS filter had to ask outside for · log scale</span></div><div id="dshist" class="tu-hist"></div></section>
    <section class="panel" style="margin-top:14px"><div class="ph"><h2>Over time</h2><span class="sub">typical and slowest-tenth lookup time per hour; purple bands: VPN on</span></div><div id="dsline" class="tu-hist"></div><div id="dsmix" class="tu-hist" style="margin-top:6px"></div></section>
    <div class="tu-cols"><section class="panel"><div class="ph"><h2>Slowest names</h2><span class="sub">asked at least 3 times</span></div><div id="dsslow"></div></section>
      <section class="panel"><div class="ph"><h2>Who asks</h2><span class="sub">lookups, answered from cache, blocked</span></div><div id="dsclients"></div></section></div>`;
  let d = null;
  const ms = v => v == null ? "–" : v >= 1000 ? (v / 1000).toFixed(1) + " s" : Math.round(v) + " ms";
  function stats() {
    const s = d.stats, tot = d.clients.reduce((a, c) => a + c[2], 0), cached = d.clients.reduce((a, c) => a + c[3], 0);
    $("#dsstats", main).innerHTML =
      tile4("Typical lookup", ms(s.med), `when the DNS filter must ask outside · ${s.n.toLocaleString("en-GB")} such lookups`, s.med > 80 ? "warn" : "ok") +
      tile4("Slowest tenth", ms(s.p90), `and the slowest hundredth ${ms(s.p99)}`, s.p90 > 300 ? "warn" : "ok") +
      tile4("Over a second", (s.over1s || 0).toLocaleString("en-GB"), `lookups · worst ${ms(s.max)}`, s.over1s > 50 ? "warn" : "fence") +
      tile4("Answered instantly", `${tot ? Math.round(100 * cached / tot) : 0}<small>%</small>`, "from the DNS filter's memory, no wait at all", "ok");
  }
  function hist() {
    const box = $("#dshist", main), W = Math.max(360, box.clientWidth), H = 200, L = 50, R = 12, T = 10, B = 36;
    const n = d.hist.length, bw = (W - L - R) / n, mx = Math.max(1, ...d.hist);
    const y = v => T + (1 - v / mx) * (H - T - B);
    const edge = i => i === 0 ? 0 : d.edges[i - 1];
    let h = "";
    d.hist.forEach((c, i) => { if (!c) return; const lo = edge(i), col = lo >= 1000 ? "--crit" : lo >= 181 ? "--warn" : "--ok";
      h += `<rect x="${(L + i * bw + 1).toFixed(1)}" y="${y(c).toFixed(1)}" width="${Math.max(1, bw - 2).toFixed(1)}" height="${(H - B - y(c)).toFixed(1)}" rx="2" fill="var(${col})"><title>${ms(lo)} to ${ms(d.edges[i] ?? lo * 1.41)}: ${c} lookups</title></rect>`; });
    for (const v of [1, 10, 100, 1000, 10000]) { const i = d.edges.findIndex(e => e >= v); if (i >= 0) h += `<text x="${L + (i + 1) * bw}" y="${H - 18}" text-anchor="middle" class="bc-ax">${ms(v)}</text>`; }
    for (const [v, lab] of [[d.stats.med, "typical"], [d.stats.p90, "slowest tenth"]]) if (v != null) { const i = d.edges.findIndex(e => e >= v); const x = L + (i + .5) * bw; h += `<line x1="${x}" x2="${x}" y1="${T}" y2="${H - B}" class="bl-fix"/><text x="${x + 4}" y="${T + 12}" class="bc-ax">${lab} ${ms(v)}</text>`; }
    h += `<text x="${L}" y="${H - 2}" class="bc-ax">time to answer →</text>`;
    box.innerHTML = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="How long lookups take">${h}</svg>`;
  }
  function line() {
    const W = Math.max(360, $("#dsline", main).clientWidth), H = 170, L = 50, R = 12, T = 10, B = 26, t1 = d.now, t0 = t1 - d.span;
    const x = t => L + (t - t0) / d.span * (W - L - R), rows = d.hours, mx = Math.max(100, ...rows.map(r => Math.min(3000, r[3] || 0)));
    const y = v => T + (1 - Math.min(v, mx) / mx) * (H - T - B);
    let h = "";
    for (const p of d.periods) if (p[2]) h += `<rect x="${x(Math.max(t0, p[0]))}" y="${T}" width="${Math.max(1, x(p[1]) - x(Math.max(t0, p[0])))}" height="${H - T - B}" class="vc-band"/>`;
    for (const f of [0, .5, 1]) h += `<line x1="${L}" x2="${W - R}" y1="${y(mx * f)}" y2="${y(mx * f)}" class="bc-grid"/><text x="${L - 6}" y="${y(mx * f) + 4}" text-anchor="end" class="bc-ax">${ms(mx * f)}</text>`;
    const path = k => rows.filter(r => r[k] != null).map((r, i) => (i ? "L" : "M") + x(r[0] + d.bucket / 2).toFixed(1) + " " + y(r[k]).toFixed(1)).join("");
    h += `<path d="${path(3)}" fill="none" stroke="var(--warn)" stroke-width="1.8"/><path d="${path(2)}" fill="none" stroke="var(--ok)" stroke-width="2.2"/>`;
    for (let i = 0; i <= 6; i++) { const t = t0 + d.span * i / 6; h += `<text x="${x(t)}" y="${H - 6}" text-anchor="middle" class="bc-ax">${d.span > 86400 ? dayOf(t) : locTime(t)}</text>`; }
    $("#dsline", main).innerHTML = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Lookup time over time">${h}</svg><div class="globe-legend"><span><i class="sw" style="background:var(--ok)"></i>Typical</span><span><i class="sw" style="background:var(--warn)"></i>Slowest tenth</span><span><i class="sw vc-sw-band"></i>VPN on</span></div>`;
    const Hm = 90, mm = Math.max(1, ...d.mix.map(r => r[1] + r[2] + r[3])), bwp = Math.max(1, (W - L - R) / (d.span / d.bucket) - 1);
    let g = "";
    for (const [t, c, f, b] of d.mix) { let acc = 0; for (const [v, col] of [[c, "--ok"], [f, "--down"], [b, "--crit"]]) { const hh = v / mm * (Hm - 16); g += `<rect x="${x(t).toFixed(1)}" y="${(Hm - 16 - acc - hh).toFixed(1)}" width="${bwp.toFixed(1)}" height="${hh.toFixed(1)}" fill="var(${col})" opacity=".8"><title>${locTime(t)}: ${c} from cache, ${f} asked outside, ${b} blocked</title></rect>`; acc += hh; } }
    g += `<text x="${L - 6}" y="12" text-anchor="end" class="bc-ax">${mm}</text><text x="${L - 6}" y="${Hm - 16}" text-anchor="end" class="bc-ax">0</text>`;
    $("#dsmix", main).innerHTML = `<svg viewBox="0 0 ${W} ${Hm}" role="img" aria-label="Lookups per hour by how they were answered">${g}</svg><div class="globe-legend"><span><i class="sw" style="background:var(--ok)"></i>From cache (instant)</span><span><i class="sw" style="background:var(--down)"></i>Asked outside</span><span><i class="sw" style="background:var(--crit)"></i>Blocked</span><span class="muted">lookups per ${d.bucket === 3600 ? "hour" : "6 hours"}</span></div>`;
  }
  function lists() {
    $("#dsslow", main).innerHTML = d.slow.length ? `<div class="tu-list">${d.slow.map(s => `<div class="tu-row"><b>${ms(s[2])}</b><span>${esc(s[0])}</span><small>typical · worst ${ms(s[3])} · ${s[1]} lookups</small></div>`).join("")}</div>` : `<p class="muted">Nothing slow.</p>`;
    $("#dsclients", main).innerHTML = `<table class="mh-table" style="min-width:0"><thead><tr><th>Device</th><th>Lookups</th><th>From cache</th><th>Blocked</th><th>Typical wait</th></tr></thead><tbody>${d.clients.map(c => `<tr><td>${esc(c[0])}</td><td>${c[2].toLocaleString("en-GB")}</td><td>${Math.round(100 * c[3] / Math.max(1, c[2]))}%</td><td>${Math.round(100 * c[5] / Math.max(1, c[2]))}%</td><td>${ms(c[6])}</td></tr>`).join("")}</tbody></table>`;
  }
  async function load(range) { try { d = await api(`api/dnsspeed?range=${range}`); } catch { return; } stats(); hist(); line(); lists(); }
  const seg = rangeSeg("dnsspeed", ["6h", "24h", "7d"], "24h", r => { seg.value = r; load(r); });
  $("#seg", main).replaceWith(seg.node);
  load(seg.value);
  const iv = setInterval(() => load(seg.value), 120000);
  let roW = 0; const ro = new ResizeObserver(([en]) => { const w = en.contentRect.width; if (d && Math.abs(w - roW) > 20) { roW = w; hist(); line(); } }); ro.observe($("#dshist", main));
  return () => { clearInterval(iv); ro.disconnect(); };
};

/* ---------------------------------------------------------------- timeline
   What happened, in order: VPN switches, checks turning red or green, new devices and apps, machine-health
   installs and load tests. Lanes above for the shape of the day, a plain list below, newest first. */
const TL_LANES = [["vpn", "VPN"], ["check", "Checks"], ["device", "New devices"], ["app", "New apps"], ["health", "Machines"], ["test", "Load tests"]];
VIEWS.timeline = main => {
  main.innerHTML = `<div class="head"><h1>Timeline</h1><p>Everything Netmon noticed, in order. Hover a mark for the detail; the list below reads newest first.</p><div class="grow"></div><span id="seg"></span></div>
    <div class="topo-stats" id="tlstats"></div>
    <section class="panel"><div class="tl-host" id="tlhost"><div id="tllanes"></div><div class="tip tl-tip" hidden></div></div></section>
    <section class="panel" style="margin-top:14px"><div class="ph"><h2>What happened</h2><span class="sub">newest first · times in local time and UTC</span></div><div id="tllist" class="tl-list"></div></section>`;
  let d = null;
  const col = e => e[1] === "vpn" ? (e[3] ? "--c4" : "--ink-3") : e[1] === "check" ? (e[3] === 2 ? "--crit" : e[3] === 1 ? "--warn" : "--ok") : e[1] === "device" ? "--warn" : e[1] === "app" ? "--down" : e[1] === "test" ? (e[3] ? "--ok" : "--warn") : "--c3";
  function lanes() {
    const box = $("#tllanes", main), W = Math.max(360, box.clientWidth), L = 110, R = 14, lh = 34, H = TL_LANES.length * lh + 30, t1 = d.now, t0 = t1 - d.span;
    const x = t => L + (t - t0) / d.span * (W - L - R);
    let h = "";
    TL_LANES.forEach(([k, lab], i) => { const y = i * lh + lh / 2; h += `<line x1="${L}" x2="${W - R}" y1="${y}" y2="${y}" class="bc-grid"/><text x="${L - 10}" y="${y + 5}" text-anchor="end" class="fs-dev">${lab}</text>`; });
    let on = null;                                                   // VPN on periods as a band in the VPN lane
    for (const e of d.events.filter(e => e[1] === "vpn")) { if (e[3] && on == null) on = e[0]; else if (!e[3] && on != null) { h += `<rect x="${x(Math.max(t0, on))}" y="${lh / 2 - 7}" width="${Math.max(2, x(e[0]) - x(Math.max(t0, on)))}" height="14" rx="4" class="tl-vpnband"/>`; on = null; } }
    if (on != null) h += `<rect x="${x(Math.max(t0, on))}" y="${lh / 2 - 7}" width="${Math.max(2, x(t1) - x(Math.max(t0, on)))}" height="14" rx="4" class="tl-vpnband"/>`;
    d.events.forEach((e, i) => { const li = TL_LANES.findIndex(l => l[0] === e[1]); if (li < 0) return;
      h += `<circle cx="${x(e[0]).toFixed(1)}" cy="${li * lh + lh / 2}" r="${e[1] === "app" ? 3.5 : 5.5}" fill="var(${col(e)})" class="tl-mark" data-i="${i}"/>`; });
    for (let i = 0; i <= 6; i++) { const t = t0 + d.span * i / 6; h += `<text x="${x(t)}" y="${H - 8}" text-anchor="middle" class="bc-ax">${d.span > 86400 ? dayOf(t) : locTime(t)}</text>`; }
    box.innerHTML = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Events over time in lanes">${h}</svg>`;
    const svg = box.querySelector("svg"), tip = $(".tl-tip", main), host = $("#tlhost", main);
    svg.addEventListener("pointermove", ev => { const el = ev.target.closest(".tl-mark"); if (!el) { tip.hidden = true; return; } const e = d.events[+el.dataset.i]; tip.hidden = false;
      tip.innerHTML = `<div class="t">${stamp(e[0])}</div><div class="r"><span>${esc(e[4])}</span></div>`; const b = host.getBoundingClientRect(); tip.style.left = Math.min(Math.max(ev.clientX - b.left, 150), b.width - 150) + "px"; tip.style.top = (ev.clientY - b.top) + "px"; });
    svg.addEventListener("pointerleave", () => { tip.hidden = true; });
  }
  function list() {
    const byDay = new Map();
    for (const e of [...d.events].reverse()) { const k = dayOf(e[0]); byDay.has(k) || byDay.set(k, []); byDay.get(k).push(e); }
    const kind = { vpn: "VPN", check: "Check", device: "Device", app: "App", health: "Machine", test: "Test" };
    $("#tllist", main).innerHTML = [...byDay.entries()].map(([day, es]) => `<h3 class="tl-day">${esc(day)}</h3>${es.map(e => `<div class="tl-row"><span class="tl-t">${stamp(e[0])}</span><span class="tl-k" style="--c:var(${col(e)})">${kind[e[1]] || esc(e[1])}</span><span class="tl-x">${esc(e[4])}</span></div>`).join("")}`).join("") || `<p class="muted">Nothing happened in this period.</p>`;
  }
  function stats() {
    const c = k => d.events.filter(e => e[1] === k).length, red = d.checks_now.filter(x => x[2] > 0);
    $("#tlstats", main).innerHTML =
      tile4("Events", d.events.length, "in this period") +
      tile4("VPN switches", c("vpn"), d.events.filter(e => e[1] === "vpn").slice(-1).map(e => `last: ${e[3] ? "on" : "off"} ${stamp(e[0])}`)[0] || "none", "fence") +
      tile4("New on the network", `${c("device")}<small> devices</small> · ${c("app")}<small> apps</small>`, "first seen in this period", c("device") ? "warn" : "ok") +
      tile4("Checks not green now", red.length, red.length ? esc(red.map(x => x[1]).join(", ")) : "all green", red.length ? "warn" : "ok");
  }
  async function load(range) { try { d = await api(`api/timeline?range=${range}`); } catch { return; } stats(); lanes(); list(); }
  const seg = rangeSeg("timeline", ["6h", "24h", "7d", "30d"], "24h", r => { seg.value = r; load(r); });
  $("#seg", main).replaceWith(seg.node);
  load(seg.value);
  const iv = setInterval(() => load(seg.value), 60000);
  let roW = 0; const ro = new ResizeObserver(([en]) => { const w = en.contentRect.width; if (d && Math.abs(w - roW) > 20) { roW = w; lanes(); } }); ro.observe($("#tllanes", main));
  return () => { clearInterval(iv); ro.disconnect(); };
};

/* ---------------------------------------------------------------- senders
   Download against upload for every device, as a butterfly on a shared log scale. Most devices take far more
   than they send; anything that sends more than it receives (cameras, backups, or something leaking) is
   flagged. Click a device for the places it sends most to (estimated from each destination's traffic). */
VIEWS.senders = main => {
  main.innerHTML = `<div class="head"><h1>Senders</h1><p>What each device takes in, against what it sends out. Anything that sends more than it receives is worth a look.</p><div class="grow"></div><span id="seg"></span></div>
    <div class="topo-stats" id="snstats"></div>
    <section class="panel"><div class="ph"><h2>In and out, per device</h2><span class="sub">left: downloaded · right: uploaded · log scale, so small senders stay visible · click a device</span></div><div id="snfly" class="tl-host"></div></section>
    <section class="panel" style="margin-top:14px" id="sndet" hidden></section>`;
  let dv = null, geo = null, sel = null;
  const rows = () => {
    const g = new Map();
    for (const x of dv.devices) { const k = groupKey(x.mac, x.name, x.vendor); const e = g.get(k.key) || g.set(k.key, { name: k.name, macs: [], down: 0, up: 0, iot: false }).get(k.key); e.macs.push(x.mac); e.down += x.down || 0; e.up += x.up || 0; if (isFencedIp(x.ip)) e.iot = true; }
    return [...g.values()].filter(e => e.down + e.up > 0).sort((a, b) => b.up - a.up);
  };
  function draw() {
    const rs = rows(), box = $("#snfly", main), W = Math.max(380, box.clientWidth), C = W / 2, NW = 170, rh = 30, H = rs.length * rh + 34;
    const lmax = Math.log10(Math.max(1e6, ...rs.map(r => Math.max(r.down, r.up)))), lmin = 4;        // 10 kB .. biggest
    const sc = v => v <= 1e4 ? 0 : (Math.log10(v) - lmin) / (lmax - lmin) * (C - NW / 2 - 12);
    let h = "";
    for (let p = 5; p <= Math.ceil(lmax); p++) { const o = sc(10 ** p); if (o <= 0 || o > C - NW / 2 - 28) continue; for (const s of [-1, 1]) h += `<line x1="${C + s * (NW / 2 + o)}" x2="${C + s * (NW / 2 + o)}" y1="0" y2="${H - 24}" class="bc-grid"/>`;
      h += `<text x="${C - NW / 2 - o}" y="${H - 8}" text-anchor="middle" class="bc-ax">${bytes(10 ** p)}</text><text x="${C + NW / 2 + o}" y="${H - 8}" text-anchor="middle" class="bc-ax">${bytes(10 ** p)}</text>`; }
    rs.forEach((r, i) => {
      const y = i * rh + 4, flag = r.up > r.down;
      h += `<g class="sn-row${sel === i ? " sel" : ""}" data-i="${i}" tabindex="0" role="button" aria-label="${esc(r.name)}: ${bytes(r.down)} in, ${bytes(r.up)} out">
        <rect x="0" y="${y - 2}" width="${W}" height="${rh}" class="sn-hit"/>
        <rect x="${C - NW / 2 - sc(r.down)}" y="${y + 4}" width="${sc(r.down)}" height="${rh - 12}" rx="3" fill="var(--down)"/>
        <rect x="${C + NW / 2}" y="${y + 4}" width="${sc(r.up)}" height="${rh - 12}" rx="3" fill="var(${flag ? "--crit" : "--up"})"/>
        <text x="${C}" y="${y + rh / 2 + 3}" text-anchor="middle" class="sn-name">${esc(r.name.length > 22 ? r.name.slice(0, 21) + "…" : r.name)}</text>
        ${C - NW / 2 - sc(r.down) > 64 ? `<text x="${C - NW / 2 - sc(r.down) - 6}" y="${y + rh / 2 + 3}" text-anchor="end" class="bc-ax">${bytes(r.down)}</text>` : `<text x="${C - NW / 2 - sc(r.down) + 6}" y="${y + rh / 2 + 3}" class="sn-in">${bytes(r.down)}</text>`}
        <text x="${C + NW / 2 + sc(r.up) + 6}" y="${y + rh / 2 + 3}" class="bc-ax">${bytes(r.up)}${flag ? " · sends more than it gets" : ""}</text></g>`;
    });
    h += `<text x="${C - NW / 2 - 6}" y="${H - 22}" text-anchor="end" class="fs-dev">← downloaded</text><text x="${C + NW / 2 + 6}" y="${H - 22}" class="fs-dev">uploaded →</text>`;
    box.innerHTML = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Download against upload per device">${h}</svg>`;
    box.querySelectorAll(".sn-row").forEach(g => { const go = () => { sel = +g.dataset.i; draw(); detail(rs[sel]); }; g.onclick = go; g.onkeydown = e => { if (e.key === "Enter") go(); }; });
    const tu = rs.reduce((s, r) => s + r.up, 0), td = rs.reduce((s, r) => s + r.down, 0), fl = rs.filter(r => r.up > r.down);
    $("#snstats", main).innerHTML =
      tile4("Sent out", bytes(tu), `against ${bytes(td)} taken in`, "fence") +
      tile4("Biggest sender", rs[0] ? esc(rs[0].name) : "–", rs[0] ? `${bytes(rs[0].up)} sent` : "", "ug") +
      tile4("Sends more than it gets", fl.length, fl.length ? esc(fl.map(r => r.name).join(", ")) : "no device", fl.length ? "warn" : "ok") +
      tile4("Out of every 100 bytes", `${td + tu ? Math.round(100 * tu / (td + tu)) : 0}<small> go out</small>`, "the rest come in");
  }
  function detail(r) {
    const box = $("#sndet", main); box.hidden = false;
    const macs = new Set(r.macs), list = [];
    for (const x of geo.dests) { const mb = Object.entries(x.macs || {}).filter(([m]) => macs.has(m)).reduce((s, [, b]) => s + b, 0); if (!mb) continue; const all = (x.down || 0) + (x.up || 0) || 1; list.push({ ...x, est: (x.up || 0) * mb / all }); }
    list.sort((a, b) => b.est - a.est);
    box.innerHTML = `<div class="ph"><h2>Where ${esc(r.name)} sends</h2><span class="sub">estimated from each destination's traffic · ${bytes(r.up)} out in total</span></div>
      <div class="tu-list">${list.slice(0, 15).map(x => `<div class="tu-row"><b>${bytes(x.est)}</b><span>${esc(x.host || shortOrg(x.org) || x.ip)} ${x.cc ? flagOf(x.cc) : ""}</span><small>${esc(x.ip)} · ${esc(shortOrg(x.org || ""))}</small></div>`).join("") || `<p class="muted">No outside destinations recorded.</p>`}</div>`;
  }
  async function load(range) { try { [dv, geo] = await Promise.all([api(`api/devices?range=${range}`), api(`api/geo?range=${range}`)]); } catch { return; } sel = null; $("#sndet", main).hidden = true; draw(); }
  const seg = rangeSeg("senders", ["6h", "24h", "7d"], "24h", r => { seg.value = r; load(r); });
  $("#seg", main).replaceWith(seg.node);
  load(seg.value);
  const iv = setInterval(() => load(seg.value), 120000);
  let roW = 0; const ro = new ResizeObserver(([en]) => { const w = en.contentRect.width; if (dv && Math.abs(w - roW) > 20) { roW = w; draw(); } }); ro.observe($("#snfly", main));
  return () => { clearInterval(iv); ro.disconnect(); };
};

/* ---------------------------------------------------------------- self-test
   The self-test (selftest/) runs every 15 minutes on the collector and checks Netmon, the router and the network
   without anyone watching. This page shows its latest run, its history and each test's last 24 runs. */
const SELF_IX = { PASS: 0, WARN: 1, FAIL: 2, SKIP: 3 };
const SELF_LABEL = { PASS: "Pass", WARN: "Warning", FAIL: "Fail", SKIP: "Skipped" };
const SELF_CLS = { PASS: "p", WARN: "w", FAIL: "f", SKIP: "s" };
const selfPill = s => `<span class="pill s${SELF_IX[s]}">${ICON[SELF_IX[s]]}${SELF_LABEL[s]}</span>`;

VIEWS.selftest = main => {
  main.innerHTML = `<div class="head st-head"><h1>Self-test</h1><p>Every 15 minutes the collector tests Netmon, the router and the network by itself. A confirmed failure sends an alert when mail is configured.</p>
      <div class="grow"></div><span id="stseg"></span><button class="btn primary" id="strun">Run now</button></div>
    <div class="topo-stats" id="ststats"></div>
    <section class="panel" style="margin-bottom:14px"><div class="ph"><h2>Recent runs</h2><span class="sub" id="stsub"></span>
      <span class="right st-key"><span><i class="f"></i>failed</span><span><i class="w"></i>warnings</span><span><i class="p"></i>all passed</span></span></div>
      <div id="strip" class="st-runs"></div></section>
    <div id="stgroups"></div>`;
  let d = null, open = new Set(), lastTs = 0;
  const seg = rangeSeg("selftest", ["Problems first", "Problems only"], "Problems first", v => { seg.value = v; draw(); }, "Which tests to show");
  $("#stseg", main).replaceWith(seg.node);

  function runs() {
    const rs = d.runs || [], box = $("#strip", main);
    if (!rs.length) { box.innerHTML = `<p class="muted">No runs recorded yet.</p>`; return; }
    const W = Math.max(320, box.clientWidth), H = 96, n = Math.max(rs.length, 24), bw = W / n, top = Math.max(4, ...rs.map(r => r[3] + r[4]));
    const y = v => H - 22 - v / top * (H - 34);
    let h = "";
    rs.forEach((r, i) => {
      const [ts, secs, p, w, f, s, how] = r, x = i * bw + 1, cw = Math.max(2, bw - 2);
      const tip = `${stamp(ts)}: ${p} passed, ${w} warnings, ${f} failed, ${s} skipped, ${Math.round(secs)} s${how === "button" ? " (Run now)" : ""}`;
      h += `<g><title>${esc(tip)}</title><rect x="${x}" y="0" width="${cw}" height="${H - 18}" fill="transparent"/>`;
      if (f + w === 0) h += `<rect x="${x}" y="${H - 26}" width="${cw}" height="4" rx="1.5" class="st-p"/>`;
      if (w) h += `<rect x="${x}" y="${y(f + w)}" width="${cw}" height="${y(f) - y(f + w) - (f ? 1 : 0)}" rx="1.5" class="st-w"/>`;
      if (f) h += `<rect x="${x}" y="${y(f)}" width="${cw}" height="${H - 22 - y(f)}" rx="1.5" class="st-f"/>`;
      h += `</g>`;
    });
    h += `<line x1="0" x2="${W}" y1="${H - 21}" y2="${H - 21}" class="bc-grid"/>`;
    h += `<text x="0" y="${H - 4}" class="bc-ax">${esc(stamp(rs[0][0]))}</text>`;
    if (rs.length > 1 && rs.length * bw > 360) h += `<text x="${rs.length * bw}" y="${H - 4}" text-anchor="end" class="bc-ax">${esc(stamp(rs[rs.length - 1][0]))}</text>`;
    h += `<text x="${W}" y="12" text-anchor="end" class="bc-ax">${top} tests</text>`;
    box.innerHTML = `<svg viewBox="0 0 ${W} ${H}" height="${H}" role="img" aria-label="Warnings and failures in each of the last ${rs.length} runs">${h}</svg>`;
    $("#stsub", main).textContent = `last ${rs.length} run${rs.length > 1 ? "s" : ""}, height shows how many tests did not pass`;
  }

  function draw() {
    const L = d.latest;
    if (!L) { $("#stgroups", main).innerHTML = `<section class="panel"><p class="muted">The self-test has not run yet. It starts within 15 minutes, or press Run now.</p></section>`; runs(); return; }
    const c = L.counts, age = Date.now() / 1000 - L.ts, stale = age > 2700;
    const hardFail = L.results.filter(r => r.hard === "FAIL").length;
    $("#ststats", main).innerHTML =
      tile4("Last run", d.running ? "Running" : ago(L.ts), `${stamp(L.ts)} · took ${Math.round(L.secs)} s`, stale ? "crit" : "ok") +
      tile4("Passed", `${c.pass}<small> of ${L.results.length}</small>`, `${c.skip} skipped`, "ok") +
      tile4("Warnings", c.warn, c.warn ? "shown on this page, no email" : "none", c.warn ? "warn" : "ok") +
      tile4("Failed", c.fail, hardFail ? `${hardFail} confirmed, alert sent` : c.fail ? "waiting for a second run to confirm" : "none", c.fail ? "crit" : "ok");
    const only = seg.value === "Problems only", order = { FAIL: 0, WARN: 1, SKIP: 2, PASS: 3 };
    const strip = d.strip || {};
    $("#stgroups", main).innerHTML = L.layers.map(ly => {
      let rs = L.results.filter(r => r.layer === ly.id);
      const n = { PASS: 0, WARN: 0, FAIL: 0, SKIP: 0 }; rs.forEach(r => n[r.status]++);
      rs = rs.slice().sort((a, b) => order[a.status] - order[b.status]);
      if (only) rs = rs.filter(r => r.status === "FAIL" || r.status === "WARN");
      if (!rs.length && only) return "";
      return `<section class="panel check-group"><div class="ph"><h2>${esc(ly.title)}</h2><span class="sub">${esc(ly.about)}</span>
          <span class="right sub">${n.PASS} passed${n.WARN ? ` · ${n.WARN} warnings` : ""}${n.FAIL ? ` · ${n.FAIL} failed` : ""}${n.SKIP ? ` · ${n.SKIP} skipped` : ""}</span></div>
        ${rs.map(r => {
          const hist = (strip[r.id] || []).slice(-24);
          return `<div class="st-row" data-id="${esc(r.id)}" tabindex="0" role="button" aria-expanded="${open.has(r.id)}">
            <div>${selfPill(r.status)}</div>
            <div><div class="title"><span data-verbatim>${esc(r.title)}</span><span class="st-kind" title="${r.kind === "heuristic" ? "Judges whether numbers look normal; no exact answer exists" : "An exact answer is known and must come back"}">${r.kind === "heuristic" ? "Heuristic" : "Deterministic"}</span>${r.urgent ? `<span class="st-kind">Alerts at once</span>` : ""}</div>
              <div class="out" data-verbatim>${esc(r.detail)}</div></div>
            <div class="when">${r.status === "PASS" ? "" : `${SELF_LABEL[r.status]} for ${r.streak > 1 ? `${r.streak} runs` : "1 run"}`}
              <div class="st-mini" aria-label="Last ${hist.length} runs">${hist.map(([ts, s]) => `<i class="${SELF_CLS[s]}" title="${esc(stamp(ts))}: ${SELF_LABEL[s]}"></i>`).join("")}</div></div>
            ${open.has(r.id) ? `<div class="st-hist" data-verbatim id="sth-${esc(r.id).replace(/[^a-z0-9-]/gi, "_")}">Loading history</div>` : ""}
          </div>`;
        }).join("") || `<p class="muted">Nothing to show.</p>`}</section>`;
    }).join("") || `<section class="panel"><p class="muted">No warnings or failures in the latest run.</p></section>`;
    main.querySelectorAll(".st-row").forEach(el => {
      const go = () => { const id = el.dataset.id; open.has(id) ? open.delete(id) : open.add(id); draw(); if (open.has(id)) history(id); };
      el.onclick = go; el.onkeydown = e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); go(); } };
    });
    open.forEach(id => history(id));
    runs();
  }

  async function history(id) {
    let h; try { h = await api(`api/selftest?id=${encodeURIComponent(id)}`); } catch { return; }
    const box = $(`#sth-${id.replace(/[^a-z0-9-]/gi, "_")}`, main); if (!box) return;
    const rows = []; let prev = null;
    for (const [ts, st, det] of h.history || []) { const k = st + det.replace(/\d+/g, "#"); if (k !== prev) rows.push([ts, st, det]); prev = k; }
    box.innerHTML = `<div class="st-hl">${rows.slice(0, 12).map(([ts, st, det]) => `<div>${selfPill(st)} <span class="when">${esc(stamp(ts))}</span> ${esc(det)}</div>`).join("")}</div>`;
  }

  async function load() {
    try { d = await api("api/selftest"); } catch { return; }
    const btn = $("#strun", main);
    if (d.running || d.queued) { btn.disabled = true; btn.textContent = d.running ? "Running" : "Starting"; }
    else { btn.disabled = false; btn.textContent = "Run now"; }
    if (d.latest && d.latest.ts !== lastTs) { lastTs = d.latest.ts; }
    draw();
  }
  $("#strun", main).onclick = async () => {
    const b = $("#strun", main); b.disabled = true; b.textContent = "Starting";
    try { await post("api/selftest/run", {}); } catch { /* shown by the next load */ }
    setTimeout(load, 3000);
  };
  load();
  const iv = setInterval(load, 10000);
  let roW = 0; const ro = new ResizeObserver(([en]) => { const w = en.contentRect.width; if (d && Math.abs(w - roW) > 20) { roW = w; runs(); } }); ro.observe($("#strip", main));
  return () => { clearInterval(iv); ro.disconnect(); };
};

/* ---------------------------------------------------------------- encryption
   Bytes per protection class from Netify's protocol for every record; where the plain text went, and which
   connections knock without ever being answered, from the connection table. */
const CR_CLS = [["enc", "Encrypted", "var(--c3)"], ["house", "Housekeeping", "var(--unknown)"], ["plain", "Plain text", "var(--up)"], ["unk", "Not recognised", "var(--rule)"]];
const crPct = (v, t) => !t ? "0" : v / t >= .9995 && v < t ? "99.9" : v / t < .001 && v > 0 ? "<0.1" : (100 * v / t).toFixed(v / t > .1 && v / t < .9 ? 0 : 1).replace(/\.0$/, "");
VIEWS.crypto = main => {
  main.innerHTML = `<div class="head"><h1>Encryption</h1><p>How much of each device's traffic is sealed, what still travels as plain text and why, and what keeps knocking without an answer.</p><div class="grow"></div><span id="seg"></span></div>
    <div class="topo-stats" id="crstats"></div>
    <section class="panel"><div class="ph"><h2>Each device's traffic by protection</h2><span class="sub">share of bytes, from the protocol the router recognised</span></div>
      <div class="legend cr-legend">${CR_CLS.map(([k, n, c]) => `<span><i class="swatch" style="background:${c}"></i>${n}</span>`).join("")}</div><div id="crdev" class="cr-devs"></div></section>
    <div class="tu-cols">
      <section class="panel"><div class="ph"><h2>Plain text, and why</h2><span class="sub">unencrypted connections to named places</span></div><div id="crplain"></div></section>
      <section class="panel"><div class="ph"><h2>Knocking, never answered</h2><span class="sub">tried at least 3 times, no reply ever came</span></div><div id="crknock"></div></section>
    </div>
    <section class="panel" style="margin-top:14px"><div class="ph"><h2>Protocols</h2><span class="sub">everything the router recognised, largest first</span></div><div id="crproto" class="cr-protos"></div></section>`;
  let d = null;
  const col = Object.fromEntries(CR_CLS.map(([k, , c]) => [k, c])), lab = Object.fromEntries(CR_CLS.map(([k, n]) => [k, n]));
  const scopeName = { internet: "on the internet", home: "on the local network", tailnet: "on the overlay network", elsewhere: "on another network" };
  function knockHint(k) {
    if (k.scope === "tailnet") return `${esc((k.host || k.ip).split(".")[0])} is on the overlay network and did not answer: it may be switched off.`;
    if (k.scope === "elsewhere") return "An address from another network, perhaps remembered from a previous Wi-Fi.";
    if (k.scope === "internet" && k.port === 443) return "The site did not answer in time. Through a VPN, bursts of new connections can wait: many VPN servers limit how many they accept per second.";
    return "No reply came back.";
  }
  function draw() {
    const T = d.totals, all = CR_CLS.reduce((s, [k]) => s + (T[k] || 0), 0);
    const look = d.plain.filter(p => p.verdict === "look"), tries = d.knock.reduce((s, k) => s + k.tries, 0);
    $("#crstats", main).innerHTML =
      tile4("Encrypted", `${crPct(T.enc, all)}<small>%</small>`, `${bytes(T.enc)} of ${bytes(all)}`, "ok") +
      tile4("Plain text", bytes(T.plain), `${d.plain.length} destination${d.plain.length === 1 ? "" : "s"} · ${look.length} worth a look`, look.length ? "warn" : "ok") +
      tile4("Housekeeping", bytes(T.house), "speed tests, pings, clock and call setup", "") +
      tile4("Never answered", tries, d.knock[0] ? `most: ${esc(d.knock[0].device)} → ${esc((d.knock[0].host || d.knock[0].ip).split(".")[0])}` : "nothing knocking", tries ? "warn" : "ok");
    $("#crdev", main).innerHTML = d.devices.map(v => {
      const segs = CR_CLS.filter(([k]) => v[k] > 0).map(([k]) => {
        const w = Math.max(v[k] / v.total * 100, v[k] > 0 && k !== "enc" ? .6 : 0);
        return `<i style="width:${w.toFixed(2)}%;background:${col[k]}" title="${esc(lab[k])}: ${bytes(v[k])} (${crPct(v[k], v.total)}%)"></i>`;
      }).join("");
      const notes = CR_CLS.filter(([k]) => k !== "enc" && v[k] > 0).map(([k]) => `${lab[k].toLowerCase()} ${bytes(v[k])}`).join(" · ");
      return `<div class="cr-row"><div class="cr-name"><b>${esc(v.name)}</b><small>${bytes(v.total)} · ${crPct(v.enc, v.total)}% encrypted</small></div>
        <div class="cr-bar" role="img" aria-label="${esc(v.name)}: ${crPct(v.enc, v.total)} percent encrypted">${segs}</div>
        <div class="cr-note">${notes || "all encrypted"} <span class="muted">· ${v.protos.slice(0, 3).map(p => esc(p[0])).join(", ")}</span></div></div>`;
    }).join("") || `<p class="muted">No traffic recorded in this period.</p>`;
    $("#crplain", main).innerHTML = d.plain.length ? `<div class="cr-list">${d.plain.slice(0, 30).map(p => `<div class="cr-item">
        <span class="pill s${p.verdict === "look" ? 1 : 0}">${ICON[p.verdict === "look" ? 1 : 0]}${p.verdict === "look" ? "Look" : "Fine"}</span>
        <div><div><b>${esc(p.device)}</b> → ${esc(p.host || p.ip)}</div>
          <div class="muted">${esc(p.service)} · ${p.conns} connection${p.conns === 1 ? "" : "s"} · ${esc(scopeName[p.scope] || p.scope)} · last ${ago(p.last)}</div>
          <div>${esc(p.why)}</div></div></div>`).join("")}</div>` : `<p class="muted">No plain-text connections in this period.</p>`;
    $("#crknock", main).innerHTML = d.knock.length ? `<div class="cr-list">${d.knock.slice(0, 20).map(k => `<div class="cr-item">
        <b class="cr-tries">${k.tries}</b>
        <div><div><b>${esc(k.device)}</b> → ${esc(k.host || k.ip)}</div>
          <div class="muted">${esc(k.services.join(" and "))} · ${esc(scopeName[k.scope] || k.scope)} · ${stamp(k.first)} to ${stamp(k.last)}</div>
          <div>${knockHint(k)}</div></div></div>`).join("")}</div>` : `<p class="muted">Nothing is knocking without an answer.</p>`;
    const pmax = Math.max(1, ...d.protos.map(p => p[2]));
    $("#crproto", main).innerHTML = d.protos.map(([p, c, b]) => `<div class="cr-prow"><span><i class="swatch" style="background:${col[c]}"></i>${esc(p)}</span>
      <div class="cr-ptrack"><i style="width:${Math.max(.4, Math.log10(1 + b) / Math.log10(1 + pmax) * 100).toFixed(1)}%;background:${col[c]}"></i></div><b>${bytes(b)}</b><small>${esc(lab[c])}</small></div>`).join("");
  }
  async function load(range) { try { d = await api(`api/crypto?range=${range}`); } catch { return; } draw(); }
  const seg = rangeSeg("crypto", ["6h", "24h", "7d"], "24h", r => { seg.value = r; load(r); });
  $("#seg", main).replaceWith(seg.node);
  load(seg.value);
  const iv = setInterval(() => load(seg.value), 120000);
  return () => clearInterval(iv);
};

/* ---------------------------------------------------------------- rhythm
   The last 24 hours as a clock face, midnight at the top, local time. Outer bars: link speed per 10 minutes.
   Teal line: DNS lookups. Inner rings: the busiest devices, darker when they moved more data. */
VIEWS.rhythm = main => {
  main.innerHTML = `<div class="head"><h1>Rhythm</h1><p>The network's last 24 hours as a clock, midnight at the top, local time. When it wakes, works and sleeps.</p></div>
    <div class="rh-grid"><section class="panel rh-clock"><div id="rhc" class="rh-host"></div></section>
      <div class="rh-side"><div class="rh-tiles" id="rhstats"></div>
        <section class="panel"><div class="ph"><h2>How to read it</h2></div><div id="rhkey" class="rh-key"></div></section></div></div>`;
  let d = null;
  const F_HM = new Intl.DateTimeFormat("en-GB", { timeZone: TZ, hour: "2-digit", minute: "2-digit" });
  const ukMin = ts => { const [h, m] = F_HM.format(new Date(ts * 1000)).split(":").map(Number); return h * 60 + m; };
  function draw() {
    const host = $("#rhc", main), S = Math.max(420, Math.min(760, host.clientWidth)), C = S / 2;
    const rs = d.series, devs = d.devices, nd = devs.length;
    const R0 = C * .30, ringW = Math.min(14, (C * .30) / Math.max(1, nd)), RD = R0 + nd * ringW + 10, RB = C * .74, RMAX = C - 34;
    const ang = ts => (ukMin(ts) / 1440) * 2 * Math.PI - Math.PI / 2;
    const P = (a, r) => [C + r * Math.cos(a), C + r * Math.sin(a)];
    const arc = (a0, a1, r0, r1) => { const [x0, y0] = P(a0, r1), [x1, y1] = P(a1, r1), [x2, y2] = P(a1, r0), [x3, y3] = P(a0, r0), big = a1 - a0 > Math.PI ? 1 : 0;
      return `M${x0.toFixed(1)} ${y0.toFixed(1)}A${r1} ${r1} 0 ${big} 1 ${x1.toFixed(1)} ${y1.toFixed(1)}L${x2.toFixed(1)} ${y2.toFixed(1)}A${r0} ${r0} 0 ${big} 0 ${x3.toFixed(1)} ${y3.toFixed(1)}Z`; };
    const step = 2 * Math.PI / 144, gap = .004;
    const bmax = Math.max(1e6, ...rs.map(r => r[1] || 0)), sc = v => Math.sqrt(Math.max(0, v || 0) / bmax) * (RMAX - RB);
    const dmax = Math.max(1, ...rs.map(r => r[3]));
    let h = "";
    for (let hr = 0; hr < 24; hr++) { const a = hr / 24 * 2 * Math.PI - Math.PI / 2, [x0, y0] = P(a, R0 - 6), [x1, y1] = P(a, RMAX + 4);
      h += `<line x1="${x0.toFixed(1)}" y1="${y0.toFixed(1)}" x2="${x1.toFixed(1)}" y2="${y1.toFixed(1)}" class="rh-hr${hr % 6 ? "" : " q"}"/>`;
      if (hr % 3 === 0) { const [tx, ty] = P(a, RMAX + 18); h += `<text x="${tx.toFixed(1)}" y="${(ty + 5).toFixed(1)}" text-anchor="middle" class="rh-hl">${String(hr).padStart(2, "0")}</text>`; } }
    for (const [a, b, on] of d.periods) if (on) { const a0 = ang(a), a1 = a0 + Math.min(2 * Math.PI - .001, (b - a) / 86400 * 2 * Math.PI);
      h += `<path d="${arc(a0, a1, RMAX + 2, RMAX + 7)}" class="rh-vpn"><title>VPN on ${esc(stamp(a))} to ${esc(stamp(b))}</title></path>`; }
    devs.forEach((v, i) => { const r0 = R0 + i * ringW, r1 = r0 + ringW - 2, vm = Math.max(...v.slots) || 1;
      v.slots.forEach((b, j) => { if (!b) return; const a0 = ang(rs[j][0]); const t = Math.max(.12, Math.log10(1 + b) / Math.log10(1 + vm));
        h += `<path d="${arc(a0 + gap, a0 + step - gap, r0, r1)}" style="fill:color-mix(in srgb, var(--down) ${Math.round(t * 100)}%, var(--panel-2))"/>`; }); });
    rs.forEach(r => { const a0 = ang(r[0]) + gap, a1 = a0 + step - 2 * gap;
      if (r[1] != null) h += `<path d="${arc(a0, a1, RB, RB + Math.max(1, sc(r[1])))}" class="rh-dn"/>`;
      if (r[2] != null) h += `<path d="${arc(a0, a1, RB - Math.max(1, sc(r[2]) * .5), RB - 1)}" class="rh-up"/>`; });
    const pts = rs.map(r => P(ang(r[0]) + step / 2, RD + (RB - 12 - RD) * r[3] / dmax));
    let line = "", prev = null;
    rs.forEach((r, i) => { const brk = !prev || r[0] - prev > 900; line += `${brk ? "M" : "L"}${pts[i][0].toFixed(1)} ${pts[i][1].toFixed(1)}`; prev = r[0]; });
    h += `<path d="${line}" class="rh-dns"/>`;
    const an = ang(d.now), [hx, hy] = P(an, RMAX + 6), [hx0, hy0] = P(an, R0 - 10);
    h += `<line x1="${hx0.toFixed(1)}" y1="${hy0.toFixed(1)}" x2="${hx.toFixed(1)}" y2="${hy.toFixed(1)}" class="rh-now"/>`;
    h += `<text x="${C}" y="${C - 8}" text-anchor="middle" class="rh-time">${locTime(d.now)}</text><text x="${C}" y="${C + 16}" text-anchor="middle" class="rh-sub">local now</text>`;
    host.innerHTML = `<svg viewBox="0 0 ${S} ${S}" width="${S}" height="${S}" role="img" aria-label="The last 24 hours as a clock: link speed, DNS lookups and device activity">${h}</svg><div class="tip" hidden></div>`;
    const svg = host.querySelector("svg"), tip = host.querySelector(".tip");
    svg.onpointermove = e => {
      const b = svg.getBoundingClientRect(), x = (e.clientX - b.left) * S / b.width - C, y = (e.clientY - b.top) * S / b.height - C, r = Math.hypot(x, y);
      if (r < R0 - 10 || r > RMAX + 10) { tip.hidden = true; return; }
      const m = ((Math.atan2(y, x) + Math.PI / 2 + 2 * Math.PI) % (2 * Math.PI)) / (2 * Math.PI) * 1440;
      const row = rs.find(q => { const u = ukMin(q[0]); return m >= u && m < u + 10; }); if (!row) { tip.hidden = true; return; }
      const j = rs.indexOf(row), on = devs.filter(v => v.slots[j] > 200000).map(v => v.name);
      tip.hidden = false; tip.style.left = `${e.clientX - host.getBoundingClientRect().left}px`; tip.style.top = `${e.clientY - host.getBoundingClientRect().top}px`;
      tip.innerHTML = `<div class="t">${locTime(row[0])} to ${locTime(row[0] + 600)} ${TZL}</div><div class="r"><span>Download</span><b>${row[1] == null ? "–" : bitsText(row[1])}</b></div>
        <div class="r"><span>Upload</span><b>${row[2] == null ? "–" : bitsText(row[2])}</b></div><div class="r"><span>DNS lookups</span><b>${row[3]}</b></div>
        <div class="r"><span>Busy</span><b>${on.length ? esc(on.slice(0, 3).join(", ")) + (on.length > 3 ? ` +${on.length - 3}` : "") : "none"}</b></div>`;
    };
    svg.onpointerleave = () => { tip.hidden = true; };
    const withV = rs.filter(r => r[1] != null), busiest = withV.reduce((a, r) => !a || r[1] > a[1] ? r : a, null);
    const hours = Array.from({ length: 24 }, () => [0, 0]); withV.forEach(r => { const hh = Math.floor(ukMin(r[0]) / 60); hours[hh][0] += r[1] + r[2]; hours[hh][1]++; });
    const avg = hours.map((x, i) => [i, x[1] ? x[0] / x[1] : null]).filter(x => x[1] != null), quiet = avg.reduce((a, x) => !a || x[1] < a[1] ? x : a, null);
    const awake = rs.reduce((a, r) => !a || r[4] > a[4] ? r : a, null), dnsTot = rs.reduce((s, r) => s + r[3], 0);
    $("#rhstats", main).innerHTML =
      tile4("Busiest 10 minutes", busiest ? `${locTime(busiest[0])}<small> ${TZL}</small>` : "–", busiest ? `${bitsText(busiest[1])} down on average` : "", "") +
      tile4("Quietest hour", quiet ? `${String(quiet[0]).padStart(2, "0")}:00<small> ${TZL}</small>` : "–", quiet ? `${bitsText(quiet[1])} in and out` : "", "ok") +
      tile4("Most devices busy", awake ? awake[4] : "–", awake ? `at ${locTime(awake[0])} ${TZL}` : "", "ug") +
      tile4("DNS lookups", dnsTot.toLocaleString("en-GB"), `in ${Math.round((withV.length || rs.length) / 6)} hours recorded`, "");
    $("#rhkey", main).innerHTML = `<div class="rh-k"><i class="sw" style="background:var(--down)"></i><span><b>Outer bars</b>: download speed, each 10 minutes. Orange bars inside them: upload.</span></div>
      <div class="rh-k"><i class="sw ln" style="background:var(--c3)"></i><span><b>Teal line</b>: DNS lookups, further out when busier.</span></div>
      ${vpnEnabled() ? `<div class="rh-k"><i class="sw" style="background:var(--c4)"></i><span><b>Purple rim</b>: the VPN was on.</span></div>` : ""}
      <div class="rh-k"><i class="sw" style="background:color-mix(in srgb, var(--down) 60%, var(--panel-2))"></i><span><b>Rings</b>, from the centre out:</span></div>
      <ol class="rh-devs">${devs.map(v => `<li>${esc(v.name)} <small>${bytes(v.total)}</small></li>`).join("")}</ol>
      <p class="muted">The hand is now. Just behind it, the clock shows yesterday at the same time.${withV.length && withV[0][0] - rs[0][0] > 1800 ? ` Speed records start at ${locTime(withV[0][0])} ${TZL} yesterday; the gap before that is empty, not quiet.` : ""}</p>`;
  }
  async function load() { try { d = await api("api/rhythm"); } catch { return; } draw(); }
  load();
  const iv = setInterval(load, 120000);
  let roW = 0; const ro = new ResizeObserver(([en]) => { const w = en.contentRect.width; if (d && Math.abs(w - roW) > 20) { roW = w; draw(); } }); ro.observe($("#rhc", main));
  return () => { clearInterval(iv); ro.disconnect(); };
};

/* ---------------------------------------------------------------- companies
   Which companies each device looks up, from its DNS lookups. Rows are companies, columns are devices. */
const kfmt = n => n >= 10000 ? Math.round(n / 1000) + "k" : n >= 1000 ? (n / 1000).toFixed(1) + "k" : String(n);
VIEWS.companies = main => {
  main.innerHTML = `<div class="head"><h1>Companies</h1><p>Which companies each device looks up, from its DNS lookups. Darker squares mean more lookups; the red strip is the share the DNS filter blocked.</p><div class="grow"></div><span id="seg"></span></div>
    <div class="topo-stats" id="cmstats"></div>
    <section class="panel"><div class="ph"><h2>Lookups by company and device</h2><span class="sub">hover a square for the names behind it</span></div><div id="cmgrid" class="cm-host"></div></section>
    <section class="panel" style="margin-top:14px"><div class="ph"><h2>Everyone else</h2><span class="sub">the most looked-up names that belong to none of the companies above</span></div><div id="cmother" class="cm-other"></div></section>`;
  let d = null;
  function draw() {
    const comps = d.companies, devs = d.devices, cells = new Map(d.cells.map(c => [c[1] + "|" + c[0], c]));
    const blk = comps.reduce((s, c) => s + c[2], 0), mostB = comps.filter(c => c[0] !== "Everyone else").sort((a, b) => b[2] - a[2])[0];
    const fully = comps.filter(c => c[0] !== "Everyone else" && c[1] >= 20 && c[2] >= .99 * c[1]);
    $("#cmstats", main).innerHTML =
      tile4("Lookups", kfmt(d.total), `by ${devs.length} devices`, "") +
      tile4("Most asked for", esc(comps[0] ? comps[0][0] : "–"), comps[0] ? `${kfmt(comps[0][1])} lookups, ${Math.round(100 * comps[0][1] / d.total)}% of all` : "", "ug") +
      tile4("Blocked by the DNS filter", `${Math.round(100 * blk / Math.max(1, d.total))}<small>%</small>`, `${kfmt(blk)} lookups never answered`, "ok") +
      tile4("Blocked completely", fully.length ? esc(fully.map(c => c[0]).join(", ")) : "none", fully.length ? "every lookup stopped" : "no company blocked outright", fully.length ? "ok" : "");
    const vmax = Math.max(1, ...d.cells.map(c => c[2]));
    const head = `<div class="cm-row cm-head" style="--n:${devs.length}"><div></div>${devs.map(([n]) => `<div class="cm-dev" title="${esc(n)}">${esc(n)}</div>`).join("")}<div class="cm-tot">All devices</div></div>`;
    const body = comps.map(([c, n, b], ci) => `<div class="cm-row" style="--n:${devs.length}"><div class="cm-co"><b>${esc(c)}</b></div>${devs.map((dv, di) => {
        const x = cells.get(ci + "|" + di);
        if (!x) return `<div class="cm-cell empty"></div>`;
        const t = Math.max(.1, Math.log10(1 + x[2]) / Math.log10(1 + vmax)), dark = t > .55;
        return `<div class="cm-cell${dark ? " dark" : ""}" style="background:color-mix(in srgb, var(--down) ${Math.round(t * 100)}%, var(--panel-2))" data-c="${ci}" data-d="${di}">
          <span>${kfmt(x[2])}</span>${x[3] ? `<i style="width:${(100 * x[3] / x[2]).toFixed(1)}%"></i>` : ""}</div>`;
      }).join("")}<div class="cm-tot"><b>${kfmt(n)}</b><small>${b ? `${Math.round(100 * b / n)}% blocked` : "none blocked"}</small></div></div>`).join("");
    $("#cmgrid", main).innerHTML = `<div class="cm-table">${head}${body}</div><div class="tip" hidden></div>`;
    const host = $("#cmgrid", main), tip = host.querySelector(".tip");
    host.querySelectorAll(".cm-cell[data-c]").forEach(el => {
      el.onpointerenter = () => {
        const x = cells.get(el.dataset.c + "|" + el.dataset.d), r = el.getBoundingClientRect(), hb = host.getBoundingClientRect();
        tip.hidden = false; tip.style.left = `${r.left - hb.left + r.width / 2 + host.scrollLeft}px`; tip.style.top = `${r.top - hb.top}px`;
        tip.innerHTML = `<div class="t">${esc(devs[x[0]][0])} → ${esc(comps[x[1]][0])}</div><div class="r"><span>Lookups</span><b>${x[2].toLocaleString("en-GB")}</b></div>
          <div class="r"><span>Blocked</span><b>${x[3].toLocaleString("en-GB")}</b></div>${x[4].map(([dm, k]) => `<div class="r"><span>${esc(dm)}</span><b>${k}</b></div>`).join("")}`;
      };
      el.onpointerleave = () => { tip.hidden = true; };
    });
    $("#cmother", main).innerHTML = d.other_top.map(([dm, n]) => `<div class="cm-o"><span>${esc(dm)}</span><b>${n.toLocaleString("en-GB")}</b></div>`).join("") || `<p class="muted">Nothing else.</p>`;
  }
  async function load(range) { try { d = await api(`api/companies?range=${range}`); } catch { return; } draw(); }
  const seg = rangeSeg("companies", ["6h", "24h", "7d"], "24h", r => { seg.value = r; load(r); });
  $("#seg", main).replaceWith(seg.node);
  load(seg.value);
  const iv = setInterval(() => load(seg.value), 120000);
  return () => clearInterval(iv);
};

/* ---------------------------------------------------------------- pulse
   Every minute of the last 24 hours as a strip per ping target, like a barcode: darker is slower, red ticks are lost pings. */
VIEWS.pulse = main => {
  main.innerHTML = `<div class="head"><h1>Pulse</h1><p>Every minute of the last 24 hours, one strip per ping target. Darker means a slower round trip; red ticks mark lost pings.</p></div>
    <section class="panel"><div class="ph"><h2>Round trip, minute by minute</h2><span class="sub" id="pssub"></span><span class="right" id="pskey"></span></div><div id="pshost" class="ps-host"></div></section>
    <div class="topo-stats" id="psstats" style="margin-top:14px"></div>`;
  let d = null;
  const LO = .5, HI = 200, lg = v => Math.max(0, Math.min(1, Math.log(v / LO) / Math.log(HI / LO)));
  const rgb = v => { const m = getComputedStyle(document.documentElement).getPropertyValue(v).trim(), h = m.replace("#", "");
    return h.length === 6 ? [0, 2, 4].map(i => parseInt(h.slice(i, i + 2), 16)) : [128, 128, 128]; };
  function draw() {
    const host = $("#pshost", main), W = Math.max(480, host.clientWidth), LW = 150, PW = W - LW - 8, SH = 34, GAP = 12;
    const tgts = d.targets, t0 = d.t0, t1 = d.now, x = ts => LW + (ts - t0) / (t1 - t0) * PW, H = 26 + tgts.length * (SH + GAP) + 26;
    const lo = rgb("--panel-2"), hi = rgb("--down"), crit = rgb("--crit"), vpn = rgb("--c4"), dpr = devicePixelRatio || 1;
    host.innerHTML = `<canvas width="${W * dpr}" height="${H * dpr}" style="width:${W}px;height:${H}px" role="img" aria-label="Round trip per minute for ${tgts.length} targets over 24 hours"></canvas><div class="ps-cross" hidden></div><div class="tip" hidden></div>`;
    const cv = host.querySelector("canvas"), g = cv.getContext("2d"); g.scale(dpr, dpr);
    const css = getComputedStyle(main), ink3 = css.getPropertyValue("--ink-3").trim() || "#7A828D", ink = css.getPropertyValue("--ink").trim() || "#111";
    g.font = `13px ${getComputedStyle(document.body).fontFamily}`;
    for (const [a, b, on] of d.periods) if (on) { g.fillStyle = `rgba(${vpn},.8)`; g.fillRect(x(Math.max(a, t0)), 10, Math.max(1, x(b) - x(Math.max(a, t0))), 5); }
    g.fillStyle = ink3; g.textAlign = "right"; g.fillText("VPN on", LW - 10, 17);
    const colW = Math.max(1, PW / 1440 + .5);
    tgts.forEach((t, i) => {
      const y = 26 + i * (SH + GAP), rows = d.series[t] || [];
      g.fillStyle = `rgb(${lo})`; g.fillRect(LW, y, PW, SH);
      for (const [ts, med, hiR, loss] of rows) {
        if (med == null) { g.fillStyle = `rgb(${crit})`; g.fillRect(x(ts), y, colW, SH); continue; }
        const k = .15 + .85 * lg(med); g.fillStyle = `rgb(${lo.map((c, j) => Math.round(c + (hi[j] - c) * k))})`; g.fillRect(x(ts), y, colW, SH);
        if (loss > 0) { g.fillStyle = `rgb(${crit})`; g.fillRect(x(ts), y - 5, colW, 4); }
      }
      const last = rows.filter(r => r[0] > t1 - 3600), meds = last.map(r => r[1]).filter(v => v != null).sort((a, b) => a - b), lost = last.reduce((s, r) => s + r[3], 0) / Math.max(1, last.length);
      g.textAlign = "left"; g.fillStyle = ink; g.font = `600 14px ${getComputedStyle(document.body).fontFamily}`; g.fillText(t, 0, y + 14);
      g.fillStyle = ink3; g.font = `13px ${getComputedStyle(document.body).fontFamily}`;
      g.fillText(meds.length ? `${meds[meds.length >> 1].toFixed(meds[meds.length >> 1] < 10 ? 1 : 0)} ms · ${lost.toFixed(0)}% lost` : "no replies", 0, y + 30);
    });
    g.fillStyle = ink3; g.textAlign = "center";
    const F = new Intl.DateTimeFormat("en-GB", { timeZone: TZ, hour: "2-digit" });
    for (let ts = Math.ceil(t0 / 3600) * 3600; ts < t1; ts += 3600) { const hh = +F.format(new Date(ts * 1000)); if (hh % 3) continue;
      g.fillRect(x(ts), H - 24, 1, 5); g.fillText(`${String(hh).padStart(2, "0")}:00`, x(ts), H - 6); }
    if (d.fix_ts > t0) { g.strokeStyle = ink; g.setLineDash([3, 3]); g.beginPath(); g.moveTo(x(d.fix_ts) + .5, 20); g.lineTo(x(d.fix_ts) + .5, H - 26); g.stroke(); g.setLineDash([]);
      g.textAlign = "left"; g.fillStyle = ink; g.fillText(`ping fix ${locTime(d.fix_ts)}`, Math.min(x(d.fix_ts) + 4, W - 110), 17); }
    const cross = host.querySelector(".ps-cross"), tip = host.querySelector(".tip");
    cv.onpointermove = e => {
      const b = cv.getBoundingClientRect(), px = e.clientX - b.left; if (px < LW || px > LW + PW) { cross.hidden = tip.hidden = true; return; }
      const ts = t0 + (px - LW) / PW * (t1 - t0), m = Math.floor(ts / 60) * 60;
      cross.hidden = false; cross.style.left = `${px}px`; cross.style.height = `${H - 46}px`;
      tip.hidden = false; tip.style.left = `${px}px`; tip.style.top = `${e.clientY - b.top}px`;
      tip.innerHTML = `<div class="t">${locTime(m)} ${TZL}</div>` + tgts.map(t => { const r = (d.series[t] || []).find(q => q[0] === m);
        return `<div class="r"><span>${esc(t)}</span><b>${!r ? "–" : r[1] == null ? "no reply" : r[1].toFixed(r[1] < 10 ? 1 : 0) + " ms"}${r && r[3] ? ` · ${r[3]}% lost` : ""}</b></div>`; }).join("");
    };
    cv.onpointerleave = () => { cross.hidden = tip.hidden = true; };
    $("#pskey", main).innerHTML = `<span class="ps-grad"><span>${LO} ms</span><i></i><span>${HI} ms</span></span>`;
    $("#pssub", main).textContent = "log scale of colour";
    const all = tgts.map(t => { const rows = (d.series[t] || []).filter(r => r[0] >= d.fix_ts); const lost = rows.filter(r => r[3] > 0).length;
      const before = (d.series[t] || []).filter(r => r[0] < d.fix_ts && r[0] > d.fix_ts - 3 * 3600), lb = before.filter(r => r[3] > 0).length;
      return [t, rows.length, lost, before.length, lb]; });
    $("#psstats", main).innerHTML = all.map(([t, n, l, nb, lb]) => tile4(esc(t), `${n ? (100 * l / n).toFixed(1) : "–"}<small>% of minutes lost a ping</small>`,
      `since the ${locTime(d.fix_ts)} fix; ${nb ? (100 * lb / nb).toFixed(0) : "–"}% in the 3 hours before`, l / Math.max(1, n) > .05 ? "warn" : "ok")).join("");
  }
  async function load() { try { d = await api("api/pulse"); } catch { return; } draw(); }
  load();
  const iv = setInterval(load, 60000);
  let roW = 0; const ro = new ResizeObserver(([en]) => { const w = en.contentRect.width; if (d && Math.abs(w - roW) > 20) { roW = w; draw(); } }); ro.observe($("#pshost", main));
  return () => { clearInterval(iv); ro.disconnect(); };
};

/* ---------------------------------------------------------------- router */
function route() {
  const [, view = "now", arg] = (location.hash || "#/now").split("/");
  const name = VIEWS[view] ? view : "now";
  // any page change that is not Story mode's own next step ends Story mode
  if (STORY.on && name !== "story" && name !== STORY.expect) storyStop(false);
  if (teardown) { try { teardown(); } catch { /* ignore */ } teardown = null; }
  document.querySelectorAll(".nav a").forEach(a => a.dataset.view === name ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current"));
  const host = $("#view");
  host.classList.remove("enter"); void host.offsetWidth; host.classList.add("enter");
  // each page gets a fresh box, so a reply that arrives after the reader has moved on writes into the old,
  // detached box and leaves the new page alone
  const main = document.createElement("div");
  main.className = "view-page";
  host.replaceChildren(main);
  const r = VPN_VIEWS.has(name) && !vpnEnabled()
    ? (main.innerHTML = `<div class="head"><h1>VPN</h1><p>The VPN is not enabled for this site. Set "vpn": {"enabled": true} in config.json to use this page.</p></div>`, null)
    : VIEWS[name](main, arg);
  teardown = typeof r === "function" ? r : null;
  document.title = name === "now" ? "Netmon" : `${main.querySelector("h1")?.textContent || name} · Netmon`;
}
/* Pages that only make sense with the router's VPN; they stay hidden while NOW.site.vpn.enabled is false. */
const VPN_VIEWS = new Set(["tunnel", "vpncost"]);
addEventListener("hashchange", route);
startLive();
loadVpnInfo(); setInterval(loadVpnInfo, 60000);
route();

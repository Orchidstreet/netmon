// SPDX-License-Identifier: AGPL-3.0-or-later
// webcheck: opens every netmon page in a real WebKit browser and reports what it finds. Part of the self-test.
// Read-only: the page is loaded with every non-GET request blocked, so no button can change anything.
// macOS only. Build: swiftc -O -o webcheck webcheck.swift
//
//   webcheck <base-url> <view,view,...> [width] [height] [container-selector]
// Each view is opened as <base-url>#/<view>. The container selector (default #view) names the element that
// holds the page's content; the audit reads text, headings and charts inside it.
// Prints one JSON object per view on stdout, then {"done":true}.
import Cocoa
import WebKit

let args = CommandLine.arguments
guard args.count >= 3 else { FileHandle.standardError.write("usage: webcheck <base-url> <views> [width] [height]\n".data(using: .utf8)!); exit(2) }
let base = args[1]
let views = args[2].split(separator: ",").map(String.init)
let width = args.count > 3 ? Double(args[3]) ?? 1440 : 1440
let height = args.count > 4 ? Double(args[4]) ?? 900 : 900
let container = args.count > 5 ? args[5] : "#view"
let containerJS = String(data: try! JSONSerialization.data(withJSONObject: [container]), encoding: .utf8)!

// Injected before any page script runs: collects errors, counts requests in flight, blocks writes,
// and keeps drawing going while the page is hidden (the window is off screen).
let boot = """
(() => {
  const st = window.__st = { errors: [], bad: [], blocked: 0, pending: 0, lastNet: Date.now() };
  const note = (k, s) => { if (st[k].length < 40) st[k].push(String(s).slice(0, 300)); };
  addEventListener('error', e => note('errors', (e.message || 'error') + ' @' + String(e.filename || '').split('/').pop() + ':' + (e.lineno || 0)));
  addEventListener('unhandledrejection', e => note('errors', 'promise: ' + (e.reason && e.reason.message || e.reason)));
  const ce = console.error.bind(console); console.error = (...a) => { note('errors', 'console: ' + a.map(String).join(' ')); ce(...a); };
  const of = window.fetch.bind(window);
  window.fetch = (u, o) => {
    const m = String(o && o.method || 'GET').toUpperCase();
    if (m !== 'GET' && m !== 'HEAD') { st.blocked++; return Promise.reject(new Error('self-test blocks writes')); }
    st.pending++; st.lastNet = Date.now();
    return of(u, o).then(r => { if (!r.ok) note('bad', String(u) + ' ' + r.status); return r; },
                         e => { note('bad', String(u) + ' ' + e); throw e; })
      .finally(() => { st.pending--; st.lastNet = Date.now(); });
  };
  const raf = window.requestAnimationFrame.bind(window);
  window.requestAnimationFrame = cb => document.hidden ? setTimeout(() => cb(performance.now()), 16) : raf(cb);
})();
"""

// Run after each page settles. Measures what a reader would see.
let audit = """
(() => {
  const st = window.__st, main = document.querySelector(\(containerJS)[0]);
  const vis = el => { const r = el.getBoundingClientRect(); if (r.width < 1 || r.height < 1) return false;
    const cs = getComputedStyle(el); return cs.visibility !== 'hidden' && cs.display !== 'none' && +cs.opacity !== 0; };
  const txt = (main && main.innerText) || '';
  // text quoted verbatim (the Self-test page repeats test details) is left out of the junk search
  const clean = main ? main.cloneNode(true) : null;
  if (clean) clean.querySelectorAll('[data-verbatim]').forEach(e => e.remove());
  const parts = []; if (clean) { const w = document.createTreeWalker(clean, NodeFilter.SHOW_TEXT); while (w.nextNode()) parts.push(w.currentNode.textContent); }
  const junk = (parts.join(' ').match(/\\b(undefined|NaN|Invalid Date|Infinity)\\b|\\[object Object\\]/g) || []);
  let tiny = 0; const tinyEx = [];
  let clipped = 0; const clipEx = [];
  for (const el of main ? main.querySelectorAll('*') : []) {
    const own = [...el.childNodes].some(n => n.nodeType === 3 && n.textContent.trim());
    if (!own || !vis(el)) continue;
    let fs = parseFloat(getComputedStyle(el).fontSize) || 0;
    if (el instanceof SVGElement && el.getScreenCTM) { const m = el.getScreenCTM(); if (m) fs *= Math.hypot(m.a, m.b); }
    if (fs && fs < 11.5) { tiny++; if (tinyEx.length < 5) tinyEx.push(el.textContent.trim().slice(0, 40) + ' (' + fs.toFixed(1) + 'px)'); }
    if (!(el instanceof SVGElement)) {
      const cs = getComputedStyle(el);
      if (cs.overflowX !== 'visible' && cs.overflowX !== 'auto' && cs.overflowX !== 'scroll' && el.scrollWidth > el.clientWidth + 2) {
        clipped++; if (clipEx.length < 5) clipEx.push(el.textContent.trim().slice(0, 40));
      }
    }
  }
  const q = s => main ? main.querySelectorAll(s).length : 0;
  let ink = null;                                   // share of a canvas that is drawn on (0 = blank)
  const cv = main && main.querySelector('canvas');
  if (cv && cv.width && cv.height) {
    try { const c = cv.getContext('2d');
      if (c) { const d = c.getImageData(0, 0, cv.width, cv.height).data; let n = 0, t = 0;
        for (let i = 3; i < d.length; i += 4 * 97) { t++; if (d[i] > 0) n++; } ink = t ? +(n / t).toFixed(3) : 0; }
    } catch (e) { ink = -1; }
  }
  return JSON.stringify({
    hidden: document.hidden, h1: (main && main.querySelector('h1') || {}).textContent || '',
    text_len: txt.length, junk: [...new Set(junk)].slice(0, 5), tiny, tiny_ex: tinyEx, clipped, clip_ex: clipEx,
    page_overflow: Math.max(0, document.scrollingElement.scrollWidth - innerWidth),
    marks: q('svg path, svg rect, svg circle, svg line, svg polyline, svg polygon'), svg_text: q('svg text'),
    rows: q('tr, li, .row, .tu-row'), canvas: q('canvas'), ink, panels: q('.panel'),
    empty_msgs: [...(main ? main.querySelectorAll('.muted, .empty, p') : [])].map(e => e.textContent.trim()).filter(t => /^no (data|traffic|devices|records?)|nothing (recorded|yet)|failed|error/i.test(t)).slice(0, 5),
    errors: st.errors, bad: st.bad, blocked: st.blocked, title: document.title
  });
})()
"""

final class Runner: NSObject, WKNavigationDelegate {
    let web: WKWebView
    var queue: [String]
    var current = ""
    var started = Date()
    var loaded = false

    init(views: [String]) {
        let cfg = WKWebViewConfiguration()
        cfg.websiteDataStore = .nonPersistent()             // fresh each run: no stored menu order or cached files
        cfg.userContentController.addUserScript(WKUserScript(source: boot, injectionTime: .atDocumentStart, forMainFrameOnly: true))
        for k in ["hiddenPageDOMTimerThrottlingEnabled", "pageVisibilityBasedProcessSuppressionEnabled"] {
            if cfg.preferences.responds(to: NSSelectorFromString("_set" + k.prefix(1).uppercased() + k.dropFirst() + ":")) {
                cfg.preferences.setValue(false, forKey: k)
            }
        }
        web = WKWebView(frame: NSRect(x: 0, y: 0, width: width, height: height), configuration: cfg)
        queue = views
        super.init()
        web.navigationDelegate = self
    }

    func start() {
        let win = NSWindow(contentRect: NSRect(x: -30000, y: -30000, width: width, height: height),
                           styleMask: [.borderless], backing: .buffered, defer: false)
        win.contentView = web
        win.ignoresMouseEvents = true
        win.orderBack(nil)
        current = queue.removeFirst()
        started = Date()
        web.load(URLRequest(url: URL(string: base + "#/" + current)!))
    }

    func webView(_ w: WKWebView, didFinish n: WKNavigation!) { if !loaded { loaded = true; settle() } }
    func webView(_ w: WKWebView, didFail n: WKNavigation!, withError e: Error) { emit(["view": current, "load_error": e.localizedDescription]); finish() }
    func webView(_ w: WKWebView, didFailProvisionalNavigation n: WKNavigation!, withError e: Error) { emit(["view": current, "load_error": e.localizedDescription]); finish() }

    // Wait until no request has been in flight for 1.2 s (at least 2.5 s, at most 20 s), then audit.
    func settle() {
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
            self.web.evaluateJavaScript("JSON.stringify([window.__st ? window.__st.pending : -1, window.__st ? Date.now() - window.__st.lastNet : 0])") { r, _ in
                let s = (r as? String) ?? "[0,99999]"
                let a = (try? JSONSerialization.jsonObject(with: Data(s.utf8))) as? [Int] ?? [0, 99999]
                let age = Date().timeIntervalSince(self.started)
                if age > 20 || (age > 2.5 && a[0] <= 0 && a[1] > 1200) { self.measure(age) } else { self.settle() }
            }
        }
    }

    func measure(_ secs: Double) {
        web.evaluateJavaScript(audit) { r, err in
            var o: [String: Any] = ["view": self.current, "secs": (secs * 10).rounded() / 10]
            if let s = r as? String, let j = (try? JSONSerialization.jsonObject(with: Data(s.utf8))) as? [String: Any] {
                o.merge(j) { a, _ in a }
            } else { o["audit_error"] = err?.localizedDescription ?? "no result" }
            self.emit(o)
            self.next()
        }
    }

    func next() {
        guard !queue.isEmpty else { return finish() }
        current = queue.removeFirst()
        started = Date()
        // Same page, new view: reset the per-view error lists, then change the address like a click on the menu.
        web.evaluateJavaScript("window.__st.errors=[];window.__st.bad=[];window.__st.blocked=0;location.hash='#/\(current)';0") { _, _ in self.settle() }
    }

    func emit(_ o: [String: Any]) {
        if let d = try? JSONSerialization.data(withJSONObject: o), let s = String(data: d, encoding: .utf8) { print(s); fflush(stdout) }
    }

    func finish() { print("{\"done\":true}"); fflush(stdout); exit(0) }
}

let app = NSApplication.shared
app.setActivationPolicy(.prohibited)
let runner = Runner(views: views)
DispatchQueue.main.asyncAfter(deadline: .now() + 600) { FileHandle.standardError.write("webcheck: gave up after 10 minutes\n".data(using: .utf8)!); exit(3) }
runner.start()
app.run()

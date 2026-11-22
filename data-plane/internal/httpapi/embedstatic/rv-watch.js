// Onshore page watcher. Reports which scripts load on this page, including ones
// added after it loads. It sends script addresses without their query strings, and reads
// nothing else: no form fields, no cookies, no page text.
(function () {
  "use strict";
  var me = document.currentScript;
  var key = me && me.getAttribute("data-page");
  if (!key || !window.fetch) return;
  var endpoint = new URL(me.src).origin + "/control/v1/page-protection/report/" + encodeURIComponent(key);
  var seen = Object.create(null), queue = [], timer = null;
  function flush() {
    timer = null;
    if (!queue.length) return;
    var body = JSON.stringify({ page: location.origin, scripts: queue.splice(0, 100) });
    if (!(navigator.sendBeacon && navigator.sendBeacon(endpoint, new Blob([body], { type: "text/plain" })))) {
      fetch(endpoint, { method: "POST", body: body, mode: "no-cors", keepalive: true, credentials: "omit", headers: { "content-type": "text/plain" } }).catch(function () {});
    }
    if (queue.length) timer = setTimeout(flush, 1000);
  }
  function note(url) {
    if (!url) return;
    var u;
    try { u = new URL(url, location.href); } catch (e) { return; }
    if (u.protocol !== "http:" && u.protocol !== "https:") return;
    var clean = u.origin + u.pathname;
    if (seen[clean] || clean === me.src.split(/[?#]/)[0]) return;
    seen[clean] = 1;
    queue.push(clean);
    if (!timer) timer = setTimeout(flush, 500);
  }
  function sweep() { for (var i = 0; i < document.scripts.length; i++) note(document.scripts[i].src); }
  sweep();
  if (window.PerformanceObserver) {
    try {
      new PerformanceObserver(function (list) {
        list.getEntries().forEach(function (e) { if (e.initiatorType === "script") note(e.name); });
      }).observe({ type: "resource", buffered: true });
    } catch (e) { /* older browsers still get the sweep and the observer below */ }
  }
  if (window.MutationObserver) {
    new MutationObserver(function (changes) {
      changes.forEach(function (c) {
        c.addedNodes.forEach(function (n) { if (n.tagName === "SCRIPT") note(n.src); });
      });
    }).observe(document.documentElement, { childList: true, subtree: true });
  }
  window.addEventListener("load", sweep);
  window.addEventListener("pagehide", flush);
})();

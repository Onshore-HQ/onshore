// Onshore secure components. Load this from your own install:
//   <script src="https://vault.example.ng/embed/rv.js"></script>
// Your page never receives what a person types, or a revealed value.
(function (global) {
  "use strict";
  var script = document.currentScript;
  var BASE = script && script.src ? new URL(script.src).origin : null;

  function Component(kind, opts) {
    if (!opts || !opts.vault || !opts.clientToken) throw new Error("vault and clientToken are required");
    var base = opts.baseUrl ? new URL(opts.baseUrl).origin : BASE;
    if (!base) throw new Error("baseUrl is required when this script is not loaded from the vault");
    var listeners = {};
    var frame = null;
    var pending = null;
    var self = this;

    function emit(name, data) { (listeners[name] || []).forEach(function (fn) { fn(data); }); }

    function onMessage(e) {
      if (!frame || e.source !== frame.contentWindow || e.origin !== base || !e.data || e.data.rv !== 1) return;
      var m = e.data;
      if (m.type === "resize") { frame.style.height = m.height + "px"; return; }
      if (m.type === "complete" && pending) { pending.resolve(m.tokens); pending = null; }
      if (m.type === "invalid" && pending) { var inv = new Error("validation_failed"); inv.fields = m.fields; pending.reject(inv); pending = null; }
      if (m.type === "error" && pending) { pending.reject(new Error(m.code)); pending = null; }
      emit(m.type, m);
    }

    this.on = function (name, fn) { (listeners[name] = listeners[name] || []).push(fn); return self; };

    this.mount = function (target) {
      var host = typeof target === "string" ? document.querySelector(target) : target;
      if (!host) throw new Error("mount target not found");
      frame = document.createElement("iframe");
      frame.src = base + "/embed/frame/" + encodeURIComponent(opts.vault);
      frame.title = kind === "collect" ? "Secure form" : "Secure value";
      frame.setAttribute("sandbox", "allow-scripts allow-same-origin");
      frame.setAttribute("referrerpolicy", "no-referrer");
      frame.style.cssText = "border:0;width:100%;display:block;height:" + (opts.height || 60) + "px";
      window.addEventListener("message", onMessage);
      frame.addEventListener("load", function () {
        // The token goes by message, not in the URL, so that it stays out of logs.
        frame.contentWindow.postMessage({ rv: 1, type: "init", clientToken: opts.clientToken, labels: opts.labels || {}, theme: opts.theme || {}, hideAfter: opts.hideAfter }, base);
      });
      host.appendChild(frame);
      return self;
    };

    this.unmount = function () {
      window.removeEventListener("message", onMessage);
      if (frame && frame.parentNode) frame.parentNode.removeChild(frame);
      frame = null;
    };

    if (kind === "collect") {
      // Resolves with { field: token }. Rejects with err.fields on a format problem, and
      // the frame shows the person what to fix.
      this.submit = function () {
        return new Promise(function (resolve, reject) {
          if (!frame) return reject(new Error("not mounted"));
          if (pending) return reject(new Error("already submitting"));
          pending = { resolve: resolve, reject: reject };
          frame.contentWindow.postMessage({ rv: 1, type: "submit" }, base);
        });
      };
    }
  }

  global.Onshore = {
    collect: function (opts) { return new Component("collect", opts); },
    reveal: function (opts) { return new Component("reveal", opts); },
  };
})(window);

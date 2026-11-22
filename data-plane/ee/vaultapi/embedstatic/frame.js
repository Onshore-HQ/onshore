// Runs inside the frame, on the vault's own origin. The host page can talk to it, but it
// cannot read it: nothing a person types, and no revealed value, ever leaves this window.
(function () {
  "use strict";
  var root = document.getElementById("root");
  var parentOrigin = null;
  var clientToken = null;
  var kind = null;
  var labels = {};
  var inputs = {};
  var busy = false;

  var MESSAGES = {
    required: "This is required.",
    validation_failed: "Check this value.",
    invalid_client_token: "This form has expired. Please reload the page.",
    origin_not_allowed: "This page is not allowed to use this component.",
    policy_denied: "You do not have access to this.",
    rate_limited: "Too many attempts. Please wait a minute.",
  };
  var KEYBOARDS = { bvn: "numeric", nin: "numeric", ng_11_digit_id: "numeric", nuban: "numeric", phone_ng: "tel", email: "email" };

  function send(msg) {
    if (parentOrigin) window.parent.postMessage(Object.assign({ rv: 1 }, msg), parentOrigin);
    resize();
  }
  function resize() {
    if (parentOrigin) window.parent.postMessage({ rv: 1, type: "resize", height: document.documentElement.scrollHeight }, parentOrigin);
  }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }
  function post(path, body) {
    return fetch(path, { method: "POST", headers: { "content-type": "application/json" }, credentials: "omit", cache: "no-store", body: JSON.stringify(body) }).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (data) { return { ok: res.ok, status: res.status, data: data }; });
    });
  }
  function fail(code, publicError) {
    root.textContent = "";
    root.appendChild(el("div", "error", MESSAGES[code] || "This could not be completed."));
    if (publicError !== false) send({ type: "error", code: code });
  }

  // Styling is a short list of checked values. Free-form CSS could read what is typed,
  // through attribute selectors and background requests.
  var COLOR = /^(#[0-9a-fA-F]{3,8}|[a-zA-Z]{3,20}|rgba?\([0-9., %]{5,30}\))$/;
  var PIXELS = /^[0-9]{1,2}px$/;
  var THEME = { color: COLOR, muted: COLOR, background: COLOR, inputBackground: COLOR, border: COLOR, accent: COLOR, error: COLOR, radius: PIXELS, fontSize: PIXELS };
  var THEME_VARS = { color: "--rv-color", muted: "--rv-muted", background: "--rv-background", inputBackground: "--rv-input-background", border: "--rv-border", accent: "--rv-accent", error: "--rv-error", radius: "--rv-radius", fontSize: "--rv-font-size" };
  function applyTheme(theme) {
    if (!theme || typeof theme !== "object") return;
    Object.keys(THEME).forEach(function (k) {
      if (typeof theme[k] === "string" && THEME[k].test(theme[k])) document.documentElement.style.setProperty(THEME_VARS[k], theme[k]);
    });
    if (theme.font === "serif" || theme.font === "mono") document.body.classList.add("font-" + theme.font);
  }

  function renderCollect(fields) {
    root.textContent = "";
    fields.forEach(function (f) {
      var label = el("label");
      label.appendChild(document.createTextNode(typeof labels[f.name] === "string" ? labels[f.name] : f.name));
      var input = el("input");
      input.type = "text";
      input.name = "rv-" + f.name;
      input.autocomplete = "off";
      input.spellcheck = false;
      input.setAttribute("autocapitalize", "off");
      input.setAttribute("autocorrect", "off");
      input.inputMode = KEYBOARDS[f.data_type] || "text";
      input.addEventListener("input", function () {
        input.removeAttribute("aria-invalid");
        var p = label.querySelector(".problem");
        if (p) p.remove();
        var complete = Object.keys(inputs).every(function (n) { return inputs[n].value.trim() !== ""; });
        // Whether it is filled in, and nothing about what it says.
        send({ type: "change", complete: complete });
      });
      input.addEventListener("keydown", function (e) {
        if (e.key === "Enter") { e.preventDefault(); send({ type: "enter" }); }
      });
      label.appendChild(input);
      root.appendChild(label);
      inputs[f.name] = input;
    });
    send({ type: "ready" });
  }

  function submit() {
    if (kind !== "collect" || busy) return;
    busy = true;
    var values = {};
    Object.keys(inputs).forEach(function (n) { values[n] = inputs[n].value; });
    post("/embed/v1/collect", { client_token: clientToken, parent_origin: parentOrigin, values: values }).then(function (r) {
      busy = false;
      if (r.ok) {
        Object.keys(inputs).forEach(function (n) { inputs[n].value = ""; inputs[n].disabled = true; });
        send({ type: "complete", tokens: r.data.tokens });
        return;
      }
      var code = (r.data.error && r.data.error.code) || "error";
      if (code === "validation_failed" && r.data.error.fields) {
        r.data.error.fields.forEach(function (p) {
          var input = inputs[p.field];
          if (!input) return;
          input.setAttribute("aria-invalid", "true");
          var label = input.parentNode;
          if (!label.querySelector(".problem")) label.appendChild(el("span", "problem", MESSAGES[p.code] || MESSAGES.validation_failed));
        });
        send({ type: "invalid", fields: r.data.error.fields.map(function (p) { return p.field; }) });
        return;
      }
      fail(code);
    }).catch(function () { busy = false; fail("network"); });
  }

  function reveal(hideAfter) {
    post("/embed/v1/reveal", { client_token: clientToken, parent_origin: parentOrigin }).then(function (r) {
      if (!r.ok) { fail((r.data.error && r.data.error.code) || "error"); return; }
      root.textContent = "";
      var decisions = [];
      (r.data.results || []).forEach(function (item, i) {
        var row = el("div", "value");
        var name = labels[i];
        if (typeof name === "string") row.appendChild(el("b", "", name));
        if (item.error) {
          row.appendChild(el("span", "error", MESSAGES[item.error.code] || "Not available."));
          decisions.push(item.error.code);
        } else {
          row.appendChild(el("span", "", item.value));
          decisions.push(item.decision);
        }
        root.appendChild(row);
      });
      // Which decision was made, for the host's UI. Never the value.
      send({ type: "revealed", decisions: decisions });
      var seconds = typeof hideAfter === "number" && hideAfter > 0 && hideAfter <= 300 ? hideAfter : 30;
      setTimeout(function () {
        root.textContent = "";
        root.appendChild(el("div", "note", "Hidden again."));
        send({ type: "hidden" });
      }, seconds * 1000);
    }).catch(function () { fail("network"); });
  }

  window.addEventListener("message", function (e) {
    // Only the page directly above this frame, and after init only from the same origin.
    if (e.source !== window.parent || !e.data || e.data.rv !== 1) return;
    if (parentOrigin && e.origin !== parentOrigin) return;
    if (e.data.type === "init" && !clientToken) {
      parentOrigin = e.origin;
      clientToken = String(e.data.clientToken || "");
      labels = e.data.labels && typeof e.data.labels === "object" ? e.data.labels : {};
      applyTheme(e.data.theme);
      post("/embed/v1/describe", { client_token: clientToken, parent_origin: parentOrigin }).then(function (r) {
        if (!r.ok) { fail((r.data.error && r.data.error.code) || "error"); return; }
        kind = r.data.kind;
        if (kind === "collect") renderCollect(r.data.fields);
        else if (kind === "reveal") reveal(e.data.hideAfter);
        else fail("error");
      }).catch(function () { fail("network"); });
      return;
    }
    if (e.data.type === "submit") submit();
  });
})();

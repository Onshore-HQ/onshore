// A local stand-in for the four foreign tools, so that the whole demo runs without any account.
// Every page says so. For recording, put real accounts in demo/.env and this stops being used.
import http from "node:http";
import zlib from "node:zlib";
import pg from "pg";

const PORT = Number(process.env.PORT ?? 4200);
const analytics = new pg.Pool({ connectionString: process.env.LOCAL_ANALYTICS_URL ?? "postgres://analytics:analytics-demo-only@127.0.0.1:55434/analytics", max: 2 });
const logs = [], errors = [], ai = [];
const push = (list, item, cap = 1500) => { list.unshift({ at: new Date().toISOString(), ...item }); if (list.length > cap) list.length = cap; };
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
const mark = (s) => esc(s).replace(/tok_[a-z0-9_]+|\[[A-Z_]+_\d+\]/g, (m) => `<b class="t">${m}</b>`).replace(/(?<![\w-])\d{10,11}(?!\d)/g, (m) => `<b class="r">${m}</b>`);

const page = (title, body) => `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>${esc(title)}</title><style>
body{margin:0;background:#111217;color:#ccccdc;font:14px/1.5 Inter,system-ui,sans-serif}header{display:flex;gap:18px;align-items:center;padding:10px 16px;background:#181b1f;border-bottom:1px solid #2c3235}
header b{color:#fff}a{color:#6e9fff;text-decoration:none}.note{background:#3d2f0b;color:#f2cc0c;padding:6px 16px;font-size:13px}main{padding:16px}
table{width:100%;border-collapse:collapse;font:13px/1.6 ui-monospace,Menlo,monospace}td,th{border-bottom:1px solid #22252b;padding:5px 8px;text-align:left;vertical-align:top;word-break:break-word}th{color:#8e8e8e;font-weight:500}
.r{color:#ff7383;font-weight:600}.t{color:#73bf69;font-weight:600}.big{font-size:22px;color:#fff;font-weight:500;margin:0 0 4px}.card{background:#181b1f;border:1px solid #2c3235;border-radius:4px;padding:14px;margin-bottom:12px}
pre{white-space:pre-wrap;word-break:break-word;font:13px/1.6 ui-monospace,Menlo,monospace;margin:0}.g{display:grid;gap:12px;grid-template-columns:1fr 1fr}.m{color:#8e8e8e;font-size:12px}</style>
<header><b>Offshore tools</b><a href=/logs>Logs</a><a href=/errors>Errors</a><a href=/ai>AI provider</a><a href=/analytics>Analytics database</a><span class=m style=margin-left:auto>Region: outside Nigeria</span></header>
<div class=note>Local stand-in, not the real tool. It shows exactly what arrived. For recording, add real accounts to demo/.env. Synthetic data, fictional company.</div>
<main>${body}</main><script>setTimeout(()=>{if(!document.hidden&&!window.getSelection().toString())location.reload()},${title.includes("Analytics") ? 5000 : 2500})</script>`;

const body = (req) => new Promise((res) => { const c = []; req.on("data", (d) => c.push(d)); req.on("end", () => { let b = Buffer.concat(c); try { if (req.headers["content-encoding"] === "gzip") b = zlib.gunzipSync(b); } catch {} res(b); }); });
const send = (s, code, text, type = "text/html; charset=utf-8") => { s.writeHead(code, { "content-type": type }); s.end(text); };

function attrValue(v) { return v?.stringValue ?? v?.intValue ?? v?.boolValue ?? v?.doubleValue ?? (v?.kvlistValue ? JSON.stringify(v.kvlistValue) : ""); }

http.createServer(async (req, s) => {
  const url = new URL(req.url, "http://x");
  const p = url.pathname;
  if (req.method === "POST" && p.endsWith("/v1/logs")) {
    const b = await body(req);
    try {
      const j = JSON.parse(b.toString());
      for (const r of j.resourceLogs ?? []) {
        const service = (r.resource?.attributes ?? []).find((a) => a.key === "service.name")?.value?.stringValue ?? "";
        for (const sl of r.scopeLogs ?? []) for (const l of sl.logRecords ?? []) push(logs, { service, line: attrValue(l.body), level: l.severityText ?? "" });
      }
    } catch { push(logs, { service: "?", line: "(a batch that was not JSON)" }); }
    return send(s, 200, "{}", "application/json");
  }
  if (req.method === "POST" && /\/api\/\d+\/envelope/.test(p)) {
    const b = (await body(req)).toString().split("\n");
    for (let i = 0; i < b.length - 1; i++) {
      try {
        const head = JSON.parse(b[i]);
        if (head.type === "event") { const e = JSON.parse(b[i + 1]); const x = e.exception?.values?.[0]; push(errors, { title: x?.type ?? "Error", message: x?.value ?? e.message, extra: e.extra ?? {}, service: e.server_name ?? "" }); }
      } catch {}
    }
    return send(s, 200, "{}", "application/json");
  }
  if (req.method === "POST" && p.endsWith("/chat/completions")) {
    const j = JSON.parse((await body(req)).toString());
    const text = (j.messages ?? []).map((m) => `${m.role}: ${typeof m.content === "string" ? m.content : JSON.stringify(m.content)}`).join("\n\n");
    const user = [...(j.messages ?? [])].reverse().find((m) => m.role === "user")?.content ?? "";
    const acct = String(user).match(/\[(?!BVN|NG_11|NIN|AMOUNT)[A-Z0-9_]+_\d+\]|tok_nuban_\w+|\b\d{10}\b/)?.[0];
    const bvn = text.match(/\[(?:BVN|NG_11_DIGIT_ID)_\d+\]|tok_bvn_\w+|\b\d{11}\b/)?.[0];
    const reply = `Sorry about that. I can see the failed transfer${acct ? ` to ${acct}` : ""}${bvn ? `, and I have matched your profile using BVN ${bvn}` : ""}. Your money is safe, and it should be back in your wallet within 24 hours.`;
    push(ai, { received: text, sent: reply, model: j.model });
    return send(s, 200, JSON.stringify({ id: "chatcmpl-sim", object: "chat.completion", model: j.model, choices: [{ index: 0, finish_reason: "stop", message: { role: "assistant", content: reply } }], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } }), "application/json");
  }
  if (p === "/api/counts") return send(s, 200, JSON.stringify({ logs: logs.length, errors: errors.length, ai: ai.length }), "application/json");
  if (p === "/api/clear" && req.method === "POST") { logs.length = 0; errors.length = 0; ai.length = 0; return send(s, 200, "{}", "application/json"); }
  if (p === "/api/latest") return send(s, 200, JSON.stringify({ log: logs[0], error: errors[0], ai: ai[0] }), "application/json");
  if (p === "/" || p === "/logs") {
    const q = url.searchParams.get("q") ?? "";
    const rows = logs.filter((l) => !q || l.line.includes(q)).slice(0, 120).map((l) => `<tr><td class=m style=white-space:nowrap>${esc(l.at.slice(11, 19))}</td><td>${esc(l.service)}</td><td>${mark(l.line)}</td></tr>`).join("");
    return send(s, 200, page("Logs", `<p class=big>Explore: raw logs</p><p class=m>service="lagoon-pay"</p><table><tr><th>Time</th><th>Service</th><th>Line</th></tr>${rows || "<tr><td colspan=3>No lines yet.</td></tr>"}</table>`));
  }
  if (p === "/errors") {
    const rows = errors.slice(0, 40).map((e) => `<div class=card><p class=big>${esc(e.title)}</p><pre>${mark(e.message)}</pre><p class=m>${esc(e.at)}</p>${Object.keys(e.extra).length ? `<pre class=m>${mark(JSON.stringify(e.extra, null, 1))}</pre>` : ""}</div>`).join("");
    return send(s, 200, page("Errors", `<p class=big>Issues</p>${rows || "<p>No errors yet.</p>"}`));
  }
  if (p === "/ai") {
    const rows = ai.slice(0, 12).map((a) => `<div class=card><div class=g><div><p class=m>What the provider received</p><pre>${mark(a.received)}</pre></div><div><p class=m>What the provider replied</p><pre>${mark(a.sent)}</pre></div></div></div>`).join("");
    return send(s, 200, page("AI provider", `<p class=big>Requests received</p>${rows || "<p>No requests yet.</p>"}`));
  }
  if (p === "/analytics") {
    let html = "<p>The analytics copy has not run yet.</p>";
    try {
      const r = await analytics.query(`SELECT customer_ref, full_name, bvn, account_number, phone, copied_at FROM analytics.customers ORDER BY customer_ref LIMIT 60`);
      const n = await analytics.query(`SELECT count(*) FROM analytics.customers`);
      if (r.rows.length) html = `<p class=m>${n.rows[0].count} rows, analytics.customers</p><table><tr>${r.fields.map((f) => `<th>${f.name}</th>`).join("")}</tr>${r.rows.map((x) => `<tr>${r.fields.map((f) => `<td>${mark(x[f.name] instanceof Date ? x[f.name].toISOString().slice(0, 19) : x[f.name])}</td>`).join("")}</tr>`).join("")}</table>`;
    } catch {}
    return send(s, 200, page("Analytics database", `<p class=big>Table editor: analytics.customers</p>${html}`));
  }
  send(s, 404, "not found", "text/plain");
}).listen(PORT, "127.0.0.1", () => console.log(`offshore stand-in on http://localhost:${PORT}`));

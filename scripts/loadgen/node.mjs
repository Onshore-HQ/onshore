// The same load as main.go through the Node SDK, in one process or several.
// Usage: node node.mjs <cfg.json> <path to sdks/node/dist/index.js> [processes]
import { fork } from "node:child_process";
import fs from "node:fs";
const [cfgPath, sdk, procsArg] = process.argv.slice(2);
const procs = Number(procsArg ?? 1);
const cfg = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
const secs = 5;
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
const steps = [["tokenize", 1], ["tokenize", 10], ["tokenize", 40], ["detokenize", 1], ["detokenize", 10], ["detokenize", 40]];
if (process.env.RV_LOAD_WORKER) {
  const { VaultClient } = await import(sdk);
  const c = new VaultClient({ baseUrl: "https://localhost:8443", serviceAccountId: cfg.sa, keyId: cfg.kid, privateKey: cfg.seed });
  let n = (Date.now() % 1000000) * 1000 + process.pid * 7;
  const batch = () => Array.from({ length: 10 }, () => ({ field: "phone", value: `0903${String(n++ % 10000000).padStart(7, "0")}` }));
  const toks = (await c.tokenize(cfg.vault, batch())).map((r) => r.token);
  process.on("message", async ({ name, conc }) => {
    const lat = []; let failed = 0; const stop = Date.now() + secs * 1000;
    await Promise.all(Array.from({ length: conc }, async () => {
      while (Date.now() < stop) {
        const s = performance.now();
        try { await (name === "tokenize" ? c.tokenize(cfg.vault, batch()) : c.detokenize(cfg.vault, toks, "load test")); lat.push(performance.now() - s); } catch { failed++; }
      }
    }));
    process.send({ lat, failed });
  });
  process.send({ ready: true });
} else {
  const workers = Array.from({ length: procs }, () => fork(process.argv[1], process.argv.slice(2), { env: { ...process.env, RV_LOAD_WORKER: "1" } }));
  await Promise.all(workers.map((w) => new Promise((r) => w.once("message", r))));
  for (const [name, total] of steps) {
    const conc = Math.max(1, Math.round(total / procs));
    const out = await Promise.all(workers.map((w) => new Promise((r) => { w.once("message", r); w.send({ name, conc }); })));
    const lat = out.flatMap((o) => o.lat).sort((a, b) => a - b);
    const failed = out.reduce((a, o) => a + o.failed, 0);
    console.log(`${name.padEnd(10)} conc=${String(conc * procs).padEnd(3)} ${(lat.length / secs).toFixed(0).padStart(6)} batches/s  p50=${(lat[lat.length >> 1] ?? 0).toFixed(1).padStart(7)} ms  p95=${(lat[Math.floor(lat.length * 0.95)] ?? 0).toFixed(1).padStart(7)} ms  failed=${failed}`);
  }
  workers.forEach((w) => w.kill());
}

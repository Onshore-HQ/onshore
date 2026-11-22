import { db } from "./db";
import { state } from "./config";
import { error, info } from "./log";
import { reportTransferFailure } from "./errors";
import { backend, FIELDS, isToken, staff, tokenizeOne } from "./onshore";

const money = (n: number) => `₦${n.toLocaleString("en-NG")}`;
const atSource = () => state().config.tokenize_at_source;
const maybe = async (field: string, value: string, ref: string) => (atSource() && !isToken(value) ? tokenizeOne(field, value, ref) : value);
const loanId = () => `LGN-LN-${String(Math.floor(Math.random() * 1e8)).padStart(8, "0")}`;

export async function signup(b: { fullName: string; phone: string; email: string; dob: string; city?: string; bvn: string; nin?: string; ref?: string }) {
  const ref = b.ref ?? `LGN-C-${String(90000 + Math.floor(Math.random() * 9999))}`;
  await info(`POST /api/signup payload=${JSON.stringify(b)}`);
  const c = await db.customer.create({ data: {
    ref, fullName: await maybe(FIELDS.fullName, b.fullName, ref), phone: await maybe(FIELDS.phone, b.phone, ref), email: await maybe(FIELDS.email, b.email, ref), dob: b.dob, city: b.city ?? "Lagos",
    bvn: await maybe(FIELDS.bvn, b.bvn, ref), nin: b.nin ? await maybe(FIELDS.nin, b.nin, ref) : "", tokenized: atSource(),
  } });
  return c;
}

export async function linkAccount(customerId: number, bank: string, nuban: string) {
  const c = await db.customer.findUniqueOrThrow({ where: { id: customerId } });
  await info(`POST /api/accounts payload=${JSON.stringify({ customer: c.ref, bank, account_number: nuban })}`);
  return db.account.create({ data: { customerId, bank, nuban: await maybe(FIELDS.nuban, nuban, c.ref), last4: nuban.slice(-4), balance: 150000 + Math.floor(Math.random() * 900000) } });
}

export async function transfer(customerId: number, b: { bank: string; account: string; name: string; amount: number; narration: string; fail?: boolean }) {
  const c = await db.customer.findUniqueOrThrow({ where: { id: customerId } });
  await info(`POST /api/transfers payload=${JSON.stringify({ customer: c.ref, bvn: c.bvn, to_bank: b.bank, to_account: b.account, to_name: b.name, amount: b.amount, narration: b.narration })}`);
  const failed = b.fail ?? Math.random() < 0.03;
  const t = await db.transfer.create({ data: { customerId, toBank: b.bank, toAccount: await maybe(FIELDS.nuban, b.account, c.ref), toName: b.name, amount: b.amount, narration: b.narration, status: failed ? "failed" : "success" } });
  if (failed) {
    await error(`transfer failed customer=${c.ref} account=${b.account} amount=${b.amount}`);
    reportTransferFailure(b.account, b.amount, c.ref);
  }
  return t;
}

export async function applyLoan(customerId: number, b: { amount: number; tenor: number; income: number; employer: string }) {
  const c = await db.customer.findUniqueOrThrow({ where: { id: customerId } });
  const loanRef = loanId();
  await info(`POST /api/loans payload=${JSON.stringify({ customer: c.ref, loan_id: loanRef, bvn: c.bvn, ...b })}`);
  return db.loan.create({ data: { loanRef, customerId, ...b, status: "in review" } });
}

/** The third deliberate mistake: the whole conversation and the profile go to the model as context. */
export async function chat(customerId: number, message: string) {
  const { config, onshore } = state();
  const c = await db.customer.findUniqueOrThrow({ where: { id: customerId }, include: { accounts: true, transfers: { orderBy: { createdAt: "desc" }, take: 5 } } });
  await db.chatMessage.create({ data: { customerId, role: "user", content: message } });
  const history = await db.chatMessage.findMany({ where: { customerId }, orderBy: { createdAt: "asc" }, take: 12 });
  const profile = `Customer profile: name ${c.fullName}, BVN ${c.bvn}, phone ${c.phone}, accounts ${c.accounts.map((a) => `${a.bank} ${a.nuban}`).join(", ")}. Last transfers: ${c.transfers.map((t) => `${money(t.amount)} to ${t.toAccount} (${t.status})`).join("; ") || "none"}.`;
  const messages = [{ role: "system", content: `You are Lagoon Pay's support assistant. Be brief and kind. ${profile}` }, ...history.map((h) => ({ role: h.role, content: h.content }))];
  await info(`chat request customer=${c.ref} message=${JSON.stringify(message)}`);
  const via = config.ai_gateway && onshore;
  const base = via ? `${onshore.base}/ai/${onshore.ai_route}/v1` : (process.env.OPENAI_BASE_URL || "http://127.0.0.1:4200/v1");
  const headers: Record<string, string> = { "content-type": "application/json", authorization: `Bearer ${process.env.OPENAI_API_KEY || "stand-in"}` };
  if (via) {
    headers["x-rv-route-key"] = onshore.ai_route_key;
    headers["x-rv-purpose"] = "Support chat";
    // A caller the policy allows to see plain values gets them back; the provider never does.
    const { c: sdk } = backend();
    headers["x-rv-caller-token"] = await (sdk as unknown as { bearer(): Promise<string> }).bearer();
  }
  const res = await fetch(`${base}/chat/completions`, { method: "POST", headers, body: JSON.stringify({ model: process.env.OPENAI_MODEL || "gpt-test", messages }) });
  const j = (await res.json()) as { choices?: { message?: { content?: string } }[]; error?: { message?: string } };
  const reply = j.choices?.[0]?.message?.content ?? `Sorry, the assistant is unavailable right now. (${j.error?.message ?? res.status})`;
  await db.chatMessage.create({ data: { customerId, role: "assistant", content: reply } });
  return reply;
}

/** The fourth deliberate mistake: a nightly job copies the customers table to a database in Europe. */
export async function analyticsCopy() {
  const pg = (await import("pg")).default;
  const { onshore } = state();
  const url = process.env.ANALYTICS_DATABASE_URL || "postgres://analytics:analytics-demo-only@127.0.0.1:55434/analytics";
  const client = new pg.Client({ connectionString: url });
  await client.connect();
  try {
    const rows = await db.customer.findMany({ include: { accounts: { take: 1 } }, orderBy: { id: "asc" } });
    const lines = rows.map((r) => ({ customer_ref: r.ref, full_name: r.fullName, bvn: r.bvn, account_number: r.accounts[0]?.nuban ?? "", phone: r.phone }));
    // After the fix the same job first has its batch checked, so the flow has evidence.
    let check: unknown = null;
    if (onshore?.flows.analytics && state().config.mode === "on") {
      const { checkFlow } = await import("./onshore");
      check = await checkFlow(onshore.flows.analytics, lines.slice(0, 200).map((l) => `${l.full_name} bvn=${l.bvn} account=${l.account_number} phone=${l.phone}`).join("\n"));
    }
    await client.query(`CREATE SCHEMA IF NOT EXISTS analytics; CREATE TABLE IF NOT EXISTS analytics.customers (customer_ref text PRIMARY KEY, full_name text, bvn text, account_number text, phone text, copied_at timestamptz); TRUNCATE analytics.customers`);
    for (let i = 0; i < lines.length; i += 200) {
      const chunk = lines.slice(i, i + 200);
      const values = chunk.flatMap((l) => [l.customer_ref, l.full_name, l.bvn, l.account_number, l.phone]);
      await client.query(`INSERT INTO analytics.customers (customer_ref,full_name,bvn,account_number,phone,copied_at) VALUES ${chunk.map((_, n) => `($${n * 5 + 1},$${n * 5 + 2},$${n * 5 + 3},$${n * 5 + 4},$${n * 5 + 5},now())`).join(",")}`, values);
    }
    await info(`analytics copy finished rows=${lines.length}`);
    return { rows: lines.length, check };
  } finally { await client.end(); }
}

/** Turning on tokenize-at-source also replaces what is already stored, as a real migration would. */
export async function tokenizeExisting() {
  const { c: sdk, onshore } = backend();
  const list = await db.customer.findMany({ where: { tokenized: false }, include: { accounts: true } });
  for (const c of list) {
    const items = [{ field: FIELDS.bvn, value: c.bvn }, ...(c.nin ? [{ field: FIELDS.nin, value: c.nin }] : []), { field: FIELDS.phone, value: c.phone }, { field: FIELDS.email, value: c.email }, { field: FIELDS.fullName, value: c.fullName }, ...c.accounts.map((a) => ({ field: FIELDS.nuban, value: a.nuban }))].map((x) => ({ ...x, subject_ref: c.ref }));
    const out = await sdk.tokenize(onshore.vault, items);
    const tok = (i: number) => { const t = out[i]?.token; if (!t) throw new Error(`refused for ${c.ref}: ${JSON.stringify(out[i]?.error)}`); return t; };
    let n = 0;
    const bvn = tok(n++); const nin = c.nin ? tok(n++) : ""; const phone = tok(n++); const email = tok(n++); const fullName = tok(n++);
    await db.customer.update({ where: { id: c.id }, data: { bvn, nin, phone, email, fullName, tokenized: true } });
    for (const a of c.accounts) await db.account.update({ where: { id: a.id }, data: { nuban: tok(n++) } });
  }
  return { customers: list.length };
}

export async function reveal(role: string, token: string, purpose: string) {
  const { c, onshore, label } = staff(role);
  try {
    const [r] = await c.detokenize(onshore.vault, [token], purpose);
    return { who: label, decision: r?.decision ?? "denied", value: r?.value ?? null, policy: r?.policy ?? null };
  } catch (e) {
    const err = e as { code?: string; status?: number; message?: string; policy?: string };
    return { who: label, decision: "denied", value: null, code: err.code ?? "denied", message: err.message, policy: err.policy ?? null };
  }
}

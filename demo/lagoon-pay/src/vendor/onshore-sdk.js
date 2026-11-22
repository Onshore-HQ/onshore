import crypto from "node:crypto";
export class VaultError extends Error {
    status;
    code;
    policy;
    requestId;
    constructor(status, code, message, policy, requestId) {
        super(message);
        this.status = status;
        this.code = code;
        this.policy = policy;
        this.requestId = requestId;
        this.name = "VaultError";
    }
}
const BATCH = 500;
const PKCS8 = Buffer.from("302e020100300506032b657004220420", "hex");
const b64u = (v) => Buffer.from(v).toString("base64url");
/**
 * Checks a webhook from Onshore. Pass the body exactly as received, before any
 * JSON parsing, and the `x-rv-signature` header. During a secret rotation the header
 * holds two signatures, and either one is enough.
 */
export function verifyWebhook(secret, rawBody, signatureHeader, opts = {}) {
    const parts = (signatureHeader ?? "").split(",").map((p) => p.split("=", 2));
    const at = Number(parts.find(([k]) => k === "t")?.[1]);
    if (!Number.isInteger(at))
        return false;
    const now = opts.now ?? Math.floor(Date.now() / 1000);
    if (Math.abs(now - at) > (opts.toleranceSeconds ?? 300))
        return false;
    const want = crypto.createHmac("sha256", secret).update(`${at}.`).update(rawBody).digest();
    return parts.filter(([k]) => k === "v1").some(([, v]) => {
        const got = Buffer.from(v ?? "", "hex");
        return got.length === want.length && crypto.timingSafeEqual(got, want);
    });
}
export class VaultClient {
    opts;
    key;
    token = null;
    tokenExpiry = 0;
    fetchFn;
    maxAttempts;
    timeoutMs;
    constructor(opts) {
        this.opts = opts;
        this.key = crypto.createPrivateKey({ key: Buffer.concat([PKCS8, Buffer.from(opts.privateKey, "base64")]), format: "der", type: "pkcs8" });
        this.fetchFn = opts.fetch ?? fetch;
        this.maxAttempts = opts.maxAttempts ?? 4;
        this.timeoutMs = opts.timeoutMs ?? 10_000;
    }
    assertion() {
        const now = Math.floor(Date.now() / 1000);
        const head = b64u(JSON.stringify({ alg: "EdDSA", typ: "JWT", kid: this.opts.keyId }));
        const body = b64u(JSON.stringify({ iss: this.opts.serviceAccountId, sub: this.opts.serviceAccountId, aud: "onshore", jti: crypto.randomUUID(), iat: now, exp: now + 120 }));
        return `${head}.${body}.${b64u(crypto.sign(null, Buffer.from(`${head}.${body}`), this.key))}`;
    }
    async bearer() {
        if (this.token && Date.now() < this.tokenExpiry - 60_000)
            return this.token;
        const r = await this.raw("POST", "/v1/auth/token", { assertion: this.assertion() }, null);
        this.token = r.access_token;
        this.tokenExpiry = Date.now() + r.expires_in * 1000;
        return this.token;
    }
    async raw(method, path, body, token, headers = {}) {
        let last;
        for (let attempt = 0; attempt < this.maxAttempts; attempt++) {
            if (attempt > 0)
                await new Promise((r) => setTimeout(r, Math.min(2000, 100 * 2 ** attempt) * (0.5 + Math.random() / 2)));
            let resp;
            try {
                resp = await this.fetchFn(this.opts.baseUrl.replace(/\/$/, "") + path, {
                    method,
                    headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers },
                    body: body === undefined ? undefined : JSON.stringify(body),
                    signal: AbortSignal.timeout(this.timeoutMs),
                });
            }
            catch (e) {
                last = new VaultError(0, "network_error", e instanceof Error ? e.name : "request failed");
                continue;
            }
            const data = (await resp.json().catch(() => ({})));
            if (resp.ok)
                return data;
            const err = new VaultError(resp.status, data.error?.code ?? "error", data.error?.message ?? `status ${resp.status}`, data.error?.policy, data.request_id);
            if (resp.status === 401 && token) {
                this.token = null;
                throw err;
            }
            if (resp.status === 429 || resp.status >= 500) {
                last = err;
                continue;
            }
            throw err;
        }
        throw last;
    }
    async call(method, path, body, headers) {
        return this.raw(method, path, body, await this.bearer(), headers);
    }
    /** Stores values and returns tokens. Larger inputs are split into 500-item batches. */
    async tokenize(vault, items, opts = {}) {
        const out = [];
        for (let i = 0; i < items.length; i += BATCH) {
            const r = await this.call("POST", `/v1/vaults/${vault}/tokenize`, { items: items.slice(i, i + BATCH), continue_on_error: opts.continueOnError ?? false });
            for (const x of r.results)
                out.push({ ...x, index: x.index + i });
        }
        return out;
    }
    /**
     * Returns values as policy allows. Fails closed: when the vault cannot answer
     * this throws, and it never returns the token as if it were the value.
     */
    async detokenize(vault, tokens, purpose, opts = {}) {
        const out = [];
        for (let i = 0; i < tokens.length; i += BATCH) {
            const r = await this.call("POST", `/v1/vaults/${vault}/detokenize`, { items: tokens.slice(i, i + BATCH).map((token) => ({ token })), purpose, continue_on_error: opts.continueOnError ?? false });
            for (const x of r.results)
                out.push({ ...x, index: x.index + i });
        }
        return out;
    }
    async insertRecord(vault, fields, subjectRef) {
        return this.call("POST", `/v1/vaults/${vault}/records`, { fields, subject_ref: subjectRef });
    }
    /** Finds a token without revealing a value. Rate-limited on the server. */
    async lookup(vault, field, value) {
        return (await this.call("POST", `/v1/vaults/${vault}/lookup`, { field, value })).token;
    }
    /**
     * Mints a single-use token for a secure component in a browser. `collect` names fields;
     * `reveal` names tokens and needs a purpose. Call this from your server, never the browser.
     */
    async createClientToken(vault, opts) {
        return this.call("POST", `/v1/vaults/${vault}/client-tokens`, { kind: opts.kind, origin: opts.origin, fields: opts.fields, tokens: opts.tokens, purpose: opts.purpose, on_behalf_of: opts.onBehalfOf, subject_ref: opts.subjectRef, bind_ip: opts.bindIp, ttl_seconds: opts.ttlSeconds });
    }
    /** Custom entities apply when `vault` is named. `entities` limits to built-in or custom slugs. */
    /** Checks a batch before a job sends it somewhere Onshore cannot sit in the path. Only counts are kept. */
    async checkFlow(vault, flow, text) {
        return this.call("POST", `/v1/vaults/${vault}/flows/${flow}/check`, { text });
    }
    async detect(text, opts = {}) {
        return this.call("POST", "/v1/detect", { text, tokenize: opts.tokenize ?? false, vault: opts.vault, entities: opts.entities, include_shadow: opts.includeShadow });
    }
    /**
     * Runs a check in the country and returns only true or false, for example whether
     * a stored name matches one supplied. Needs the `compare` policy action.
     */
    async residentCheck(vault, token, check, arg, purpose) {
        return (await this.call("POST", `/v1/vaults/${vault}/resident/check`, { token, check, arg, purpose })).result;
    }
    async eraseSubject(vault, subjectId, purpose) {
        return this.call("DELETE", `/v1/vaults/${vault}/subjects/${subjectId}`, undefined, { "x-rv-purpose": purpose });
    }
}
